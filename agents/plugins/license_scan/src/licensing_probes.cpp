/**
 * licensing_probes.cpp — ProbeSpec engine, the v1 probe table, and the
 * default filesystem ProbeHost operations (SLE roadmap §5 PR1; ADR-0024 D2).
 *
 * Compiles on every OS: all platform I/O goes through ProbeHost, and the only
 * platform-conditional code here is the UTF-8 <-> std::filesystem::path
 * conversion (Windows paths are UTF-16 natively).
 *
 * Interpreters emit ONLY §3.2 closed-vocabulary values and never fabricate:
 * presence without licence evidence is status `unknown`; a parsed vendor
 * licence artefact (rarreg.key, FlexLM INCREMENT) may claim more.
 */

#include "licensing_probes.hpp"
#include "licensing_parsers.hpp"

#include <filesystem>
#include <fstream>
#include <system_error>

#ifdef _WIN32
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681, R17)
#endif

namespace yuzu::license_scan {

namespace fs = std::filesystem;

// ── path <-> UTF-8 (Windows paths are UTF-16 natively) ─────────────────────

namespace {

fs::path path_from_utf8(std::string_view s) {
#ifdef _WIN32
    return fs::path(yuzu::win::to_wide(s));
#else
    return fs::path(std::string(s));
#endif
}

std::string path_to_utf8(const fs::path& p) {
#ifdef _WIN32
    return yuzu::win::from_wide(p.c_str());
#else
    return p.string();
#endif
}

// Match one path segment against a pattern segment with `*` wildcards only.
// Case-insensitive on Windows (case-insensitive filesystem), sensitive
// elsewhere. Classic two-pointer star matcher — no recursion, bounded.
bool segment_match(std::string_view name, std::string_view pat) {
    const auto eq = [](char a, char b) {
#ifdef _WIN32
        const auto lo = [](char c) {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        };
        return lo(a) == lo(b);
#else
        return a == b;
#endif
    };
    std::size_t n = 0, p = 0;
    std::size_t star = std::string_view::npos, back = 0;
    while (n < name.size()) {
        if (p < pat.size() && (pat[p] == '*')) {
            star = p++;
            back = n;
        } else if (p < pat.size() && eq(pat[p], name[n])) {
            ++p;
            ++n;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            n = ++back;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*')
        ++p;
    return p == pat.size();
}

std::vector<std::string> split_segments(std::string_view pattern, std::string& root) {
    std::vector<std::string> segs;
    std::string cur;
    std::size_t i = 0;
    root.clear();
#ifdef _WIN32
    // Drive root "C:/" or "C:\"; UNC deliberately unsupported (no probe row
    // targets network paths, and globbing UNC would be an unbounded egress).
    if (pattern.size() >= 3 && pattern[1] == ':' && (pattern[2] == '/' || pattern[2] == '\\')) {
        root = std::string(pattern.substr(0, 2)) + "\\";
        i = 3;
    }
#else
    if (!pattern.empty() && pattern[0] == '/') {
        root = "/";
        i = 1;
    }
#endif
    for (; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if (c == '/' || c == '\\') {
            if (!cur.empty()) {
                segs.push_back(cur);
                cur.clear();
            }
        } else {
            cur += c;
        }
    }
    if (!cur.empty())
        segs.push_back(cur);
    return segs;
}

} // namespace

// ── default filesystem ProbeHost operations ─────────────────────────────────

std::vector<std::string> ProbeHost::glob(std::string_view pattern) {
    std::string root;
    const auto segs = split_segments(pattern, root);
    if (root.empty() || segs.empty())
        return {}; // relative globs are not a probe shape we support

    std::vector<fs::path> frontier{path_from_utf8(root)};
    constexpr std::size_t kMaxFrontier = 2048; // breadth bound
    for (const auto& seg : segs) {
        std::vector<fs::path> next;
        const bool has_wildcard = seg.find('*') != std::string::npos;
        for (const auto& dir : frontier) {
            if (!has_wildcard) {
                std::error_code ec;
                fs::path candidate = dir / path_from_utf8(seg);
                if (fs::exists(candidate, ec) && !ec)
                    next.push_back(std::move(candidate));
            } else {
                std::error_code ec;
                fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
                if (ec)
                    continue;
                for (const auto& entry : it) {
                    if (next.size() >= kMaxFrontier)
                        break;
                    const std::string name = path_to_utf8(entry.path().filename());
                    if (segment_match(name, seg))
                        next.push_back(entry.path());
                }
            }
            if (next.size() >= kMaxFrontier)
                break;
        }
        frontier = std::move(next);
        if (frontier.empty())
            return {};
    }

    std::vector<std::string> out;
    out.reserve(frontier.size() < kGlobMaxMatches ? frontier.size() : kGlobMaxMatches);
    for (const auto& p : frontier) {
        if (out.size() >= kGlobMaxMatches)
            break;
        out.push_back(path_to_utf8(p));
    }
    return out;
}

bool ProbeHost::file_exists(std::string_view path) {
    std::error_code ec;
    return fs::exists(path_from_utf8(path), ec) && !ec;
}

std::optional<std::string> ProbeHost::read_file_prefix(std::string_view path,
                                                       std::size_t max_bytes) {
    std::ifstream f(path_from_utf8(path), std::ios::binary);
    if (!f)
        return std::nullopt;
    std::string content(max_bytes, '\0');
    f.read(content.data(), static_cast<std::streamsize>(max_bytes));
    content.resize(static_cast<std::size_t>(f.gcount()));
    return content;
}

// ── interpreters ────────────────────────────────────────────────────────────

namespace {

std::string parent_dir_utf8(std::string_view path) {
    const auto pos = path.find_last_of("/\\");
    return pos == std::string_view::npos ? std::string{} : std::string(path.substr(0, pos));
}

std::string base_name_utf8(std::string_view path) {
    const auto pos = path.find_last_of("/\\");
    return std::string(pos == std::string_view::npos ? path : path.substr(pos + 1));
}

// SQL Server: enumerate installed instances from Instance Names\SQL
// (value = instance name -> instance id), then read each instance's
// Setup\Edition + Version. Express/Developer editions are free-of-charge
// proprietary builds -> freeware; paid editions stay unknown (the registry
// does not say volume vs retail).
void interpret_sql_server(ProbeHost& host, const ProbeSpec& spec, const std::string& matched,
                          std::vector<LicRecord>& out) {
    (void)spec;
    for (const auto& [instance, id] : host.reg_enum_str_values(matched)) {
        (void)instance;
        const std::string setup = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\" + id + "\\Setup";
        const std::string edition = host.reg_read_str(setup, "Edition").value_or("");
        const std::string version = host.reg_read_str(setup, "Version").value_or("");
        LicRecord r;
        r.product = edition.empty() ? "Microsoft SQL Server"
                                    : "Microsoft SQL Server (" + edition + ")";
        r.vendor = "Microsoft";
        r.version = version;
        const std::string lower_ed = parse_detail::to_lower(edition);
        r.license_type = (lower_ed.find("express") != std::string::npos ||
                          lower_ed.find("developer") != std::string::npos)
                             ? "freeware"
                             : "unknown";
        r.status = "unknown";
        r.source = "registry_probe";
        r.confidence = "probable";
        r.exe_hints = "sqlservr.exe";
        out.push_back(std::move(r));
    }
}

// Exchange: Setup key presence + best-effort version.
void interpret_exchange(ProbeHost& host, const ProbeSpec& spec, const std::string& matched,
                        std::vector<LicRecord>& out) {
    (void)spec;
    LicRecord r;
    r.product = "Microsoft Exchange Server";
    r.vendor = "Microsoft";
    r.version = host.reg_read_str(matched, "OwaVersion").value_or("");
    r.license_type = "unknown";
    r.status = "unknown";
    r.source = "registry_probe";
    r.confidence = "probable";
    out.push_back(std::move(r));
}

// VMware Workstation: License.ws.<ver>.* subkeys carry a Serial value. A
// present serial is a licence indicator (perpetual Workstation Pro keys);
// the serial itself is NEVER emitted — key_hint is its hash prefix.
void interpret_vmware(ProbeHost& host, const ProbeSpec& spec, const std::string& matched,
                      std::vector<LicRecord>& out) {
    (void)spec;
    bool any_license_key = false;
    for (const auto& sub : host.reg_enum_subkeys(matched)) {
        const std::string lower = parse_detail::to_lower(sub);
        if (lower.rfind("license.ws", 0) != 0)
            continue;
        any_license_key = true;
        const std::string serial = host.reg_read_str(matched + "\\" + sub, "Serial").value_or("");
        LicRecord r;
        r.product = "VMware Workstation";
        r.vendor = "VMware";
        // "License.ws.17.0.e5.202010" -> version "17.0".
        const auto tokens = [&] {
            std::vector<std::string> t;
            std::string cur;
            for (char c : sub) {
                if (c == '.') {
                    t.push_back(cur);
                    cur.clear();
                } else {
                    cur += c;
                }
            }
            t.push_back(cur);
            return t;
        }();
        if (tokens.size() >= 4)
            r.version = tokens[2] + "." + tokens[3];
        r.status = serial.empty() ? "unknown" : "licensed";
        r.license_type = serial.empty() ? "unknown" : "perpetual";
        r.key_hint = derive_key_hint("", serial);
        r.source = "registry_probe";
        r.confidence = "probable";
        r.exe_hints = "vmware.exe";
        out.push_back(std::move(r));
    }
    if (!any_license_key) {
        LicRecord r;
        r.product = "VMware Workstation";
        r.vendor = "VMware";
        r.status = "unknown";
        r.license_type = "unknown";
        r.source = "registry_probe";
        r.confidence = "heuristic";
        r.exe_hints = "vmware.exe";
        out.push_back(std::move(r));
    }
}

// WinRAR: unregistered installs run as a perpetual evaluation (trial);
// a rarreg.key beside the exe is the parsed retail licence artefact.
void interpret_winrar(ProbeHost& host, const ProbeSpec& spec, const std::string& matched,
                      std::vector<LicRecord>& out) {
    (void)spec;
    LicRecord r;
    r.product = "WinRAR";
    r.vendor = "win.rar GmbH";
    r.exe_hints = "winrar.exe";
    r.confidence = "probable";
    std::string exe = host.reg_read_str(matched, "exe64").value_or("");
    if (exe.empty())
        exe = host.reg_read_str(matched, "exe32").value_or("");
    if (exe.empty()) {
        r.status = "unknown";
        r.license_type = "unknown";
        r.source = "registry_probe";
        r.confidence = "heuristic";
        out.push_back(std::move(r));
        return;
    }
    const std::string install_dir = parent_dir_utf8(exe);
    const std::string key_file = install_dir + "\\rarreg.key";
    if (!install_dir.empty() && host.file_exists(key_file)) {
        r.status = "licensed";
        r.license_type = "retail";
        r.source = "license_file";
        const auto content = host.read_file_prefix(key_file, 4096);
        r.key_hint = derive_key_hint("", content.value_or(""));
    } else {
        r.status = "trial";
        r.license_type = "trial";
        r.source = "registry_probe";
    }
    out.push_back(std::move(r));
}

// FlexLM .lic: parse INCREMENT/FEATURE lines -> one record per feature.
// Expiry is authoritative (parsed vendor artefact); permanent -> perpetual,
// dated features stay license_type unknown (a term is not proof of a
// subscription model).
void interpret_flexlm(ProbeHost& host, const ProbeSpec& spec, const std::string& matched,
                      std::vector<LicRecord>& out) {
    (void)spec;
    const auto content = host.read_file_prefix(matched, 256 * 1024);
    if (!content)
        return;
    const std::string joined = join_flexlm_continuations(*content);
    const long long now = host.now_epoch();
    std::size_t pos = 0;
    while (pos < joined.size()) {
        std::size_t eol = joined.find('\n', pos);
        if (eol == std::string::npos)
            eol = joined.size();
        const std::string_view line(joined.data() + pos, eol - pos);
        pos = eol + 1;
        const auto inc = parse_flexlm_increment(line);
        if (!inc)
            continue;
        LicRecord r;
        r.product = inc->feature;
        r.vendor = inc->vendor_daemon;
        r.version = inc->version;
        r.expires_at = expiry_wire_from_epoch(inc->expiry_epoch);
        if (inc->expiry_epoch == 0) {
            r.status = "licensed";
            r.license_type = "perpetual";
        } else {
            r.status = inc->expiry_epoch >= now ? "licensed" : "expired";
            r.license_type = "unknown";
        }
        r.source = "license_file";
        r.confidence = "authoritative";
        out.push_back(std::move(r));
    }
}

// JetBrains per-user licence keys under <profile>/AppData/Roaming/JetBrains:
// <Product>/ holds <product>.key; <Product>/eval/ holds evaluation keys.
// The key bytes are NEVER emitted — key_hint is a hash prefix.
void interpret_jetbrains_key(ProbeHost& host, const ProbeSpec& spec, const std::string& matched,
                             std::vector<LicRecord>& out) {
    (void)spec;
    const std::string dir = parent_dir_utf8(matched);
    const std::string dir_name = base_name_utf8(dir);
    const bool is_eval = parse_detail::to_lower(dir_name) == "eval";
    const std::string product_dir = is_eval ? base_name_utf8(parent_dir_utf8(dir)) : dir_name;
    LicRecord r;
    r.product = product_dir.empty() ? "JetBrains IDE" : "JetBrains " + product_dir;
    r.vendor = "JetBrains";
    if (is_eval) {
        r.status = "trial";
        r.license_type = "trial";
    } else {
        r.status = "licensed";
        r.license_type = "subscription";
    }
    r.source = "license_file";
    r.confidence = "probable";
    const auto content = host.read_file_prefix(matched, 8192);
    r.key_hint = derive_key_hint("", content.value_or(""));
    out.push_back(std::move(r));
}

} // namespace

// ── the v1 table ────────────────────────────────────────────────────────────

const std::vector<ProbeSpec>& probe_spec_table() {
    // Row shorthand: {surface, platform, scope, kind, path, interpret,
    //                 product, vendor, license_type, source, confidence, exe_hints}.
    // Presence rows (interpret == nullptr) keep status `unknown` by design.
    static const std::vector<ProbeSpec> table = {
        // ── Windows, machine scope (roadmap surface table row 3) ────────────
        {"sql_server", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL", &interpret_sql_server,
         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr},
        {"exchange", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Microsoft\\ExchangeServer\\v15\\Setup", &interpret_exchange, nullptr, nullptr,
         nullptr, nullptr, nullptr, nullptr},
        {"visual_studio", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Microsoft\\VisualStudio\\Setup", nullptr, "Microsoft Visual Studio",
         "Microsoft", "unknown", "registry_probe", "heuristic", "devenv.exe"},
        {"autodesk_adsklicensing", Platform::windows_os, Scope::machine, ProbeKind::file_glob,
         "C:/ProgramData/Autodesk/AdskLicensingService/*", nullptr,
         "Autodesk (AdskLicensing service)", "Autodesk", "unknown", "heuristic", "heuristic",
         nullptr},
        {"veeam", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Veeam\\Veeam Backup and Replication", nullptr, "Veeam Backup & Replication",
         "Veeam", "unknown", "registry_probe", "probable", nullptr},
        {"acronis", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Acronis", nullptr, "Acronis (agent/suite)", "Acronis", "unknown",
         "registry_probe", "heuristic", nullptr},
        // AV suites — one presence row per vendor, one shared surface.
        {"av_suites", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\ESET\\ESET Security", nullptr, "ESET Security", "ESET", "unknown",
         "registry_probe", "heuristic", nullptr},
        {"av_suites", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\McAfee", nullptr, "McAfee (security suite)", "McAfee", "unknown",
         "registry_probe", "heuristic", nullptr},
        {"av_suites", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Symantec\\Symantec Endpoint Protection", nullptr,
         "Symantec Endpoint Protection", "Broadcom", "unknown", "registry_probe", "heuristic",
         nullptr},
        {"av_suites", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\KasperskyLab", nullptr, "Kaspersky (security suite)", "Kaspersky", "unknown",
         "registry_probe", "heuristic", nullptr},
        {"av_suites", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Sophos", nullptr, "Sophos (security suite)", "Sophos", "unknown",
         "registry_probe", "heuristic", nullptr},
        {"av_suites", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Bitdefender", nullptr, "Bitdefender (security suite)", "Bitdefender",
         "unknown", "registry_probe", "heuristic", nullptr},
        {"av_suites", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\Malwarebytes", nullptr, "Malwarebytes", "Malwarebytes", "unknown",
         "registry_probe", "heuristic", nullptr},
        {"vmware_workstation", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\VMware, Inc.\\VMware Workstation", &interpret_vmware, nullptr, nullptr,
         nullptr, nullptr, nullptr, nullptr},
        {"winrar", Platform::windows_os, Scope::machine, ProbeKind::registry_key,
         "SOFTWARE\\WinRAR", &interpret_winrar, nullptr, nullptr, nullptr, nullptr, nullptr,
         nullptr},
        // Open-source classification — presence of well-known OSS installs.
        {"open_source_classification", Platform::windows_os, Scope::machine,
         ProbeKind::registry_key, "SOFTWARE\\7-Zip", nullptr, "7-Zip", "Igor Pavlov",
         "open_source", "registry_probe", "heuristic", "7zfm.exe"},
        {"open_source_classification", Platform::windows_os, Scope::machine,
         ProbeKind::registry_key, "SOFTWARE\\Notepad++", nullptr, "Notepad++", "Notepad++ Team",
         "open_source", "registry_probe", "heuristic", "notepad++.exe"},
        {"open_source_classification", Platform::windows_os, Scope::machine,
         ProbeKind::registry_key, "SOFTWARE\\GitForWindows", nullptr, "Git for Windows",
         "The Git Development Community", "open_source", "registry_probe", "heuristic",
         "git.exe"},
        {"open_source_classification", Platform::windows_os, Scope::machine,
         ProbeKind::registry_key, "SOFTWARE\\VideoLAN\\VLC", nullptr, "VLC media player",
         "VideoLAN", "open_source", "registry_probe", "heuristic", "vlc.exe"},

        // ── Windows, user scope (probed inside each user hive; all rows share
        //    the per_user_hives surface — R15's availability token binds to it)
        {"per_user_hives", Platform::windows_os, Scope::user, ProbeKind::registry_key,
         "Software\\Microsoft\\VisualStudio\\Licenses", nullptr,
         "Microsoft Visual Studio (per-user licence)", "Microsoft", "unknown", "registry_probe",
         "heuristic", "devenv.exe"},
        {"per_user_hives", Platform::windows_os, Scope::user, ProbeKind::registry_key,
         "Software\\JavaSoft\\Prefs\\jetbrains", nullptr, "JetBrains IDE (per-user)",
         "JetBrains", "unknown", "registry_probe", "heuristic", nullptr},

        // ── Windows, user scope, profile files (JetBrains keys; the engine
        //    receives the glob already resolved to a profile by the caller) —
        //    kept here as interpreter-only rows: licensing_win.cpp invokes
        //    interpret_jetbrains_key per profile via jetbrains_key_interpreter().

        // ── Linux, machine scope: FlexLM .lic conventional dirs (surface
        //    table Linux row 3; authoritative expiry) ─────────────────────────
        {"flexlm_lic", Platform::linux_os, Scope::machine, ProbeKind::file_glob,
         "/opt/flexlm/*.lic", &interpret_flexlm, nullptr, nullptr, nullptr, nullptr, nullptr,
         nullptr},
        {"flexlm_lic", Platform::linux_os, Scope::machine, ProbeKind::file_glob,
         "/opt/flexlm/licenses/*.lic", &interpret_flexlm, nullptr, nullptr, nullptr, nullptr,
         nullptr, nullptr},
        {"flexlm_lic", Platform::linux_os, Scope::machine, ProbeKind::file_glob,
         "/usr/local/flexlm/licenses/*.lic", &interpret_flexlm, nullptr, nullptr, nullptr,
         nullptr, nullptr, nullptr},
        {"flexlm_lic", Platform::linux_os, Scope::machine, ProbeKind::file_glob,
         "/var/flexlm/*.lic", &interpret_flexlm, nullptr, nullptr, nullptr, nullptr, nullptr,
         nullptr},
        {"flexlm_lic", Platform::linux_os, Scope::machine, ProbeKind::file_glob,
         "/etc/flexlm/*.lic", &interpret_flexlm, nullptr, nullptr, nullptr, nullptr, nullptr,
         nullptr},
        {"flexlm_lic", Platform::linux_os, Scope::machine, ProbeKind::file_glob,
         "/usr/local/MATLAB/*/licenses/*.lic", &interpret_flexlm, nullptr, nullptr, nullptr,
         nullptr, nullptr, nullptr},
        {"flexlm_lic", Platform::linux_os, Scope::machine, ProbeKind::file_glob,
         "/usr/ansys_inc/shared_files/licensing/*.lic", &interpret_flexlm, nullptr, nullptr,
         nullptr, nullptr, nullptr, nullptr},

        // ── macOS, machine scope: vendor plists (surface table macOS row) ───
        {"vendor_plists", Platform::macos_os, Scope::machine, ProbeKind::file_glob,
         "/Library/Preferences/com.microsoft.office.licensingV2.plist", nullptr,
         "Microsoft Office (volume licence)", "Microsoft", "volume", "license_file", "probable",
         nullptr},
        {"vendor_plists", Platform::macos_os, Scope::machine, ProbeKind::file_glob,
         "/Library/Preferences/Parallels/*license*", nullptr, "Parallels Desktop", "Parallels",
         "unknown", "heuristic", "heuristic", nullptr},
    };
    return table;
}

/// Exposed so licensing_win.cpp can drive the per-profile JetBrains file scan
/// through the same interpreter the table rows use.
InterpretFn jetbrains_key_interpreter() { return &interpret_jetbrains_key; }

// ── engine ──────────────────────────────────────────────────────────────────

namespace {

void emit_presence_record(const ProbeSpec& spec, std::vector<LicRecord>& out) {
    LicRecord r;
    r.product = spec.product ? spec.product : "";
    r.vendor = spec.vendor ? spec.vendor : "";
    r.license_type = spec.license_type ? spec.license_type : "unknown";
    r.status = "unknown"; // presence alone never claims licence state
    r.source = spec.source ? spec.source : "heuristic";
    r.confidence = spec.confidence ? spec.confidence : "heuristic";
    r.exe_hints = spec.exe_hints ? spec.exe_hints : "";
    out.push_back(std::move(r));
}

} // namespace

void run_probe_specs(ProbeHost& host, Platform platform, Scope scope,
                     std::vector<LicRecord>& records, std::vector<ProbeOutcome>& outcomes) {
    // One aggregated outcome per unique surface, in first-appearance order.
    std::vector<ProbeOutcome> local;
    const auto surface_slot = [&local](const char* surface) -> ProbeOutcome& {
        for (auto& o : local) {
            if (o.surface == surface)
                return o;
        }
        local.push_back(ProbeOutcome{surface, true, 0, {}});
        return local.back();
    };

    for (const auto& spec : probe_spec_table()) {
        if (spec.platform != platform || spec.scope != scope)
            continue;
        auto& slot = surface_slot(spec.surface);
        const std::size_t before = records.size();
        if (spec.kind == ProbeKind::registry_key) {
            if (host.reg_key_exists(spec.path)) {
                if (spec.interpret)
                    spec.interpret(host, spec, spec.path, records);
                else
                    emit_presence_record(spec, records);
            }
        } else { // file_glob
            const auto matches = host.glob(spec.path);
            if (spec.interpret) {
                for (const auto& m : matches)
                    spec.interpret(host, spec, m, records);
            } else if (!matches.empty()) {
                emit_presence_record(spec, records); // one record per row, not per match
            }
        }
        slot.rows += records.size() - before;
    }

    for (auto& o : local)
        outcomes.push_back(std::move(o));
}

} // namespace yuzu::license_scan
