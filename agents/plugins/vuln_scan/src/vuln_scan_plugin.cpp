/**
 * vuln_scan_plugin.cpp — Host vulnerability scanning plugin for Yuzu
 *
 * Actions:
 *   "scan"        — Full scan (CVE + configuration checks).
 *   "cve_scan"    — CVE-only: match installed software against known CVEs.
 *   "config_scan" — Configuration/compliance checks only.
 *   "summary"     — Quick severity counts from a full scan.
 *
 * Output is pipe-delimited via write_output():
 *   <severity>|cve|<CVE-ID>: <description>|<product> <installed_ver> (fixed in <fixed_ver>)
 *   <severity>|config|<title>|<detail>
 *   UNREADABLE|config|<title>|<path>: <cause>   (a Linux file check that could not run; excluded from the issue tally)
 *   summary|<severity>|<count>   (CRITICAL..INFO, then UNREADABLE; TOTAL first)
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
#endif

#ifdef __APPLE__
#include <yuzu/agent/subprocess_runner.hpp>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

#include "config_checks.hpp"
#include "cve_rules.hpp"
#include "macos_software.hpp"

namespace {

// ── Subprocess helpers (Linux) ─────────────────────────────────────────────
// The macOS leg runs absolute-path argvs through the shared bounded runner (macos_run below).

#if defined(__linux__)
// One shell pipeline per call (package managers, firewall probes). Shares the RAII popen owner
// with config_checks.hpp (a std::bad_alloc mid-read still closes the pipe and reaps the child).
std::string run_command(const char* cmd, bool* exited_ok = nullptr) {
    return yuzu::vuln::detail::run_cmd(cmd, exited_ok);
}

bool command_exists(const char* cmd) {
    auto check = std::string("command -v ") + cmd + " >/dev/null 2>&1";
    return system(check.c_str()) == 0;
}
#endif

// ── App record ────────────────────────────────────────────────────────────

struct AppInfo {
    std::string name;
    std::string version;
};

// Case-insensitive substring match
bool icontains(std::string_view haystack, std::string_view needle) {
    if (needle.empty())
        return true;
    if (haystack.size() < needle.size())
        return false;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

// Replace invalid UTF-8 bytes with '?'
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            out += s[i + 3];
            i += 4;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

// Escape pipe characters in output values
std::string escape_pipes(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '|')
            out += "\\|";
        else
            out += c;
    }
    return out;
}

// ── Get installed apps (same approach as installed_apps plugin) ────────────

#ifdef _WIN32

// RAII closer for an HKEY -- releases the handle even if a value read throws
// (std::string allocation in reg_sz_to_utf8/to_wide). vuln_scan reads HKLM/HKCU
// directly, so unlike installed_apps it needs no hive load/unload guard.
struct HKeyCloser {
    HKEY h{};
    explicit HKeyCloser(HKEY k) : h(k) {}
    ~HKeyCloser() {
        if (h)
            RegCloseKey(h);
    }
    HKeyCloser(const HKeyCloser&) = delete;
    HKeyCloser& operator=(const HKeyCloser&) = delete;
};

void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::vector<AppInfo>& apps) {
    HKEY hkey{};
    // Reg*W + WideCharToMultiByte(CP_UTF8) so non-ASCII names (e.g. "Café")
    // survive intact -- the *A APIs return the system ANSI code page (cp1252),
    // which then fails UTF-8 validation downstream and corrupts the stored /
    // fleet-queryable software-inventory surface (#1662 / #1682).
    if (RegOpenKeyExW(root, yuzu::win::to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) != ERROR_SUCCESS) {
        return;
    }
    HKeyCloser hkey_guard{hkey};

    // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size. Bind the array
    // size and every reset to one constant so the byte-vs-count unit cannot skew --
    // the #1662 A->W conversion missed one reset site (gov Gate 3/4 BLOCKING).
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;

    while (RegEnumKeyExW(hkey, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
           ERROR_SUCCESS) {
        HKEY app_key{};
        if (RegOpenKeyExW(hkey, name_buf, 0, KEY_READ | extra_sam, &app_key) == ERROR_SUCCESS) {
            HKeyCloser app_guard{app_key};
            // Value names are compile-time wide literals -> no per-iteration to_wide
            // allocation in this hot loop (hundreds of apps x 3 reads), and the only
            // throwing call left is the post-read reg_sz_to_utf8, on which app_guard
            // still releases app_key (#1682 Gate-4 R4). buf is written as bytes and
            // read back through its declared wchar_t lvalue (LPBYTE is alignment-1).
            auto read_str = [&](const wchar_t* value_name) -> std::string {
                wchar_t buf[512]{};
                DWORD size = sizeof(buf); // size in BYTES
                DWORD type = 0;
                if (RegQueryValueExW(app_key, value_name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    if (type == REG_SZ && size >= sizeof(wchar_t)) {
                        return yuzu::win::reg_sz_to_utf8(buf, size);
                    }
                }
                return {};
            };

            auto display_name = read_str(L"DisplayName");
            if (!display_name.empty()) {
                auto sys_component = read_str(L"SystemComponent");
                if (sys_component != "1") {
                    auto version = read_str(L"DisplayVersion");
                    apps.push_back({std::move(display_name), std::move(version)});
                }
            }
            // app_guard closes app_key (also on the read_str throw path)
        }
        name_len = kNameBufLen;
    }
    // hkey_guard closes hkey
}

std::vector<AppInfo> get_installed_apps([[maybe_unused]] yuzu::vuln::CoverageState* cov = nullptr) {
    std::vector<AppInfo> apps;
    static const char* kUninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_64KEY, apps);
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_32KEY, apps);
    enumerate_uninstall_key(HKEY_CURRENT_USER, kUninstallKey, 0, apps);

    std::sort(apps.begin(), apps.end(), [](const AppInfo& a, const AppInfo& b) {
        return a.name < b.name || (a.name == b.name && a.version < b.version);
    });
    apps.erase(std::unique(apps.begin(), apps.end(),
                           [](const AppInfo& a, const AppInfo& b) {
                               return a.name == b.name && a.version == b.version;
                           }),
               apps.end());

    return apps;
}
#elif defined(__linux__)
std::vector<AppInfo> get_installed_apps([[maybe_unused]] yuzu::vuln::CoverageState* cov = nullptr) {
    std::vector<AppInfo> apps;

    if (command_exists("dpkg-query")) {
        auto out = run_command("dpkg-query -W -f='${Package}|${Version}|${Status}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("install ok installed") == std::string::npos)
                continue;
            std::istringstream ls(line);
            std::string name, version;
            std::getline(ls, name, '|');
            std::getline(ls, version, '|');
            apps.push_back({name, version});
        }
    } else if (command_exists("rpm")) {
        auto out =
            run_command("rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            auto sep = line.find('|');
            if (sep != std::string::npos) {
                apps.push_back({line.substr(0, sep), line.substr(sep + 1)});
            }
        }
    } else if (command_exists("pacman")) {
        auto out = run_command("pacman -Q 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                apps.push_back({line.substr(0, sp), line.substr(sp + 1)});
            }
        }
    } else if (command_exists("apk")) {
        // Alpine: `apk info -v` prints "<name>-<pkgver>-r<pkgrel>" per line.
        // pkgver/pkgrel never contain '-', so the last two '-'-delimited fields
        // are the version; everything before is the (possibly hyphenated) name.
        auto out = run_command("apk info -v 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                line.pop_back();
            auto rel_sep = line.rfind('-');
            if (rel_sep == std::string::npos || rel_sep == 0)
                continue;
            auto ver_sep = line.rfind('-', rel_sep - 1);
            if (ver_sep == std::string::npos || ver_sep == 0)
                continue;
            apps.push_back({line.substr(0, ver_sep), line.substr(ver_sep + 1)});
        }
    }

    return apps;
}
#elif defined(__APPLE__)
// Run one macOS command through the shared bounded runner (execve of argv[0], own process group,
// deadline, output cap). ok = ran to completion, exit 0, output not truncated.
yuzu::vuln::CommandRead macos_run(const yuzu::vuln::Argv& argv) {
    yuzu::agent::SubprocessOptions opts;
    opts.deadline = std::chrono::milliseconds(yuzu::vuln::kMacosCommandDeadlineMs);
    opts.output_cap_bytes = yuzu::vuln::kMacosCommandMaxOutput;
    opts.merge_stderr = false;
    const auto r = yuzu::agent::run_bounded_subprocess(argv, opts);
    yuzu::vuln::CommandRead out;
    out.out = r.output;
    out.ok = r.tool_ran && !r.timed_out && !r.output_truncated &&
             r.termination_reason == yuzu::agent::TerminationReason::exited && r.exit_code == 0;
    return out;
}

std::vector<AppInfo> get_installed_apps(yuzu::vuln::CoverageState* cov) {
    // One bounded run of an absolute-path argv (no shell, no PATH search): the output goes to the
    // pure parser, so a failed, timed-out, over-cap or empty run reads unreadable, never a clean 0.
    const auto r = macos_run(yuzu::vuln::kMacosSystemProfilerCmd);
    auto parsed = yuzu::vuln::parse_system_profiler_apps(r.out, r.ok);

    // Homebrew is deliberately NOT enumerated here (WP13c/C-2): the agent runs as root and a
    // Homebrew prefix is owned by the installing user, so exec'ing its `brew` script would run
    // a user-controlled file as root. Homebrew formulae and casks are listed by
    // pkg_inventory.packages (no subprocess); this plugin does not scan them.
    if (cov) {
        cov->macos_software = true;
        cov->sp_readable = parsed.readable;
    }

    std::vector<AppInfo> apps;
    apps.reserve(parsed.apps.size());
    for (auto& a : parsed.apps)
        apps.push_back({std::move(a.name), std::move(a.version)});
    return apps;
}
#else
std::vector<AppInfo> get_installed_apps([[maybe_unused]] yuzu::vuln::CoverageState* cov = nullptr) {
    return {};
}
#endif

// ── Scan results ──────────────────────────────────────────────────────────

struct Finding {
    std::string severity;
    std::string category; // "cve" or "config"
    std::string title;
    std::string detail;
};

// ── CVE scan ──────────────────────────────────────────────────────────────

std::vector<Finding> do_cve_scan_impl(yuzu::vuln::CoverageState* cov = nullptr) {
    std::vector<Finding> findings;
    auto apps = get_installed_apps(cov);

    for (const auto& rule : yuzu::vuln::kCveRules) {
        for (const auto& app : apps) {
            if (!icontains(app.name, rule.product))
                continue;
            if (app.version.empty())
                continue;

            // Check if installed version is below the fixed version
            if (yuzu::vuln::compare_versions(app.version, rule.affected_below) < 0) {
                findings.push_back(
                    {std::string(rule.severity), "cve",
                     std::format("{}: {}", rule.cve_id, rule.description),
                     std::format("{} {} (fixed in {})", app.name, app.version, rule.fixed_in)});
            }
        }
    }

    return findings;
}

// ── Config scan ───────────────────────────────────────────────────────────

std::vector<Finding> do_config_scan_impl(yuzu::vuln::CoverageState* cov = nullptr) {
    std::vector<Finding> findings;
    #ifdef __APPLE__
    auto checks = yuzu::vuln::run_all_config_checks(macos_run);
#else
    auto checks = yuzu::vuln::run_all_config_checks();
#endif
    if (cov && yuzu::vuln::any_config_unreadable(checks))
        cov->config_unreadable = true;

    for (const auto& check : checks) {
        // Report all checks (passed ones as INFO)
        findings.push_back(
            {std::string(check.severity), "config", std::string(check.title), check.detail});
    }

    return findings;
}

// ── Output helpers ────────────────────────────────────────────────────────

// Declare the run's coverage. The CONSTRAINED/PARTIAL status reaches the agent log only (the row
// models REST/MCP serve do not carry it), so the operator-visible half is the in-band rows below.
// No-op on Linux/Windows and on a macOS run that read everything it consumes.
void declare_coverage(yuzu::CommandContext& ctx, const yuzu::vuln::CoverageState& cov) {
    const auto token = yuzu::vuln::coverage_token(cov);
    if (!token.empty())
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              token);
}

// cve_scan / scan: `INFO|scan|Coverage|<note>` after the findings. NEVER used by inventory, whose
// rows feed server-side NVD matching and stay pure name|version pairs.
void emit_coverage_row(yuzu::CommandContext& ctx, const yuzu::vuln::CoverageState& cov) {
    const auto note = yuzu::vuln::coverage_note(cov);
    if (!note.empty())
        ctx.write_output(yuzu::vuln::coverage_row(note));
}

// summary: `summary|COVERAGE|<note>` (summary's own row shape).
void emit_coverage_summary_row(yuzu::CommandContext& ctx, const yuzu::vuln::CoverageState& cov) {
    const auto note = yuzu::vuln::coverage_note(cov);
    if (!note.empty())
        ctx.write_output(yuzu::vuln::coverage_summary_row(note));
}

void output_findings(yuzu::CommandContext& ctx, const std::vector<Finding>& findings) {
    if (findings.empty()) {
        ctx.write_output("INFO|scan|No vulnerabilities|No issues detected");
        return;
    }

    for (const auto& f : findings) {
        ctx.write_output(
            sanitize_utf8(std::format("{}|{}|{}|{}", f.severity, escape_pipes(f.category),
                                      escape_pipes(f.title), escape_pipes(f.detail))));
    }
}

void output_summary(yuzu::CommandContext& ctx, const std::vector<Finding>& findings) {
    std::vector<std::string> severities;
    severities.reserve(findings.size());
    for (const auto& f : findings)
        severities.push_back(f.severity);
    for (const auto& row : yuzu::vuln::summary_rows(severities))
        ctx.write_output(row);
}

// ── ABI4 capability declarations (#2204) ─────────────────────────────────
//
// One row per entry in actions() below, same names/order.
//   - scan/summary run BOTH do_cve_scan_impl (get_installed_apps) and
//     do_config_scan_impl (run_all_config_checks); cve_scan/inventory run
//     only get_installed_apps; config_scan runs only run_all_config_checks.
//   - Windows: get_installed_apps reads HKLM/HKCU Uninstall directly
//     (RegOpenKeyExW/RegEnumKeyExW/RegQueryValueExW); the Windows config
//     checks (config_checks.hpp #ifdef _WIN32 block) are registry reads too
//     — every leg native, in-process, rung 1.
//   - Linux: get_installed_apps shells out via popen to whichever package
//     manager is present (dpkg-query/rpm/pacman/apk); run_linux_checks mixes
//     native /proc + /etc/ssh/sshd_config reads with a popen firewall probe
//     (iptables/nft/ufw) — the leg is genuinely wired throughout, but the
//     firewall check's acquisition method is the worst (least-native) one
//     actually exercised, so rung 3.
//   - macOS: get_installed_apps and run_macos_checks run absolute-path argvs
//     (/usr/sbin/system_profiler, spctl, fdesetup, csrutil, socketfilterfw, systemsetup, defaults)
//     through yuzu::agent::run_bounded_subprocess — rung 2, with a 60 s deadline and an 8 MB cap.
//     The cross-platform risky-ports check still runs `ss || netstat` through popen, so the actions
//     that run config checks (scan, summary, config_scan) are rung 3; cve_scan/inventory are rung 2.
//     cve_scan/scan/summary/inventory are CONSTRAINED: Homebrew formulae and casks are never
//     scanned (see macos_software.hpp), and the same actions report CONSTRAINED + PARTIAL at run
//     time (declare_coverage) plus an in-band Coverage row (not inventory). config_scan reads no
//     software list and stays SUPPORTED; it reports CONSTRAINED only when a check's read failed.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        "scan",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(pkg-manager+iptables/nft/ufw)", nullptr},
        {YUZU_SUPPORT_CONSTRAINED, 3, "argv(system_profiler+security-checks)+popen(ss/netstat)",
         "Homebrew formulae and casks are not scanned"},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "cve_scan",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(dpkg-query/rpm/pacman/apk)", nullptr},
        {YUZU_SUPPORT_CONSTRAINED, 2, "argv(system_profiler)",
         "Homebrew formulae and casks are not scanned"},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "config_scan",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(iptables/nft/ufw)+procfs", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 3, "argv(spctl/fdesetup/csrutil/socketfilterfw/systemsetup/defaults)+popen(ss/netstat)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "summary",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(pkg-manager+iptables/nft/ufw)", nullptr},
        {YUZU_SUPPORT_CONSTRAINED, 3, "argv(system_profiler+security-checks)+popen(ss/netstat)",
         "Homebrew formulae and casks are not scanned"},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "inventory",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(dpkg-query/rpm/pacman/apk)", nullptr},
        {YUZU_SUPPORT_CONSTRAINED, 2, "argv(system_profiler)",
         "Homebrew formulae and casks are not scanned"},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
};

} // namespace

class VulnScanPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "vuln_scan"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Host vulnerability scanning — CVE matching and configuration compliance checks";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan",    "cve_scan",  "config_scan",
                                     "summary", "inventory", nullptr};
        return acts;
    }

    [[nodiscard]] const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    [[nodiscard]] size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                [[maybe_unused]] yuzu::Params params) override {

        if (action == "scan") {
            ctx.report_progress(0);
            yuzu::vuln::CoverageState cov;
            auto cve_findings = do_cve_scan_impl(&cov);
            ctx.report_progress(50);
            auto config_findings = do_config_scan_impl(&cov);
            ctx.report_progress(90);

            std::vector<Finding> all;
            all.reserve(cve_findings.size() + config_findings.size());
            all.insert(all.end(), cve_findings.begin(), cve_findings.end());
            all.insert(all.end(), config_findings.begin(), config_findings.end());

            output_findings(ctx, all);
            emit_coverage_row(ctx, cov);
            declare_coverage(ctx, cov);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "cve_scan") {
            ctx.report_progress(0);
            yuzu::vuln::CoverageState cov;
            auto findings = do_cve_scan_impl(&cov);
            output_findings(ctx, findings);
            emit_coverage_row(ctx, cov);
            declare_coverage(ctx, cov);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "config_scan") {
            ctx.report_progress(0);
            yuzu::vuln::CoverageState cov;
            auto findings = do_config_scan_impl(&cov);
            output_findings(ctx, findings);
            declare_coverage(ctx, cov);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "inventory") {
            // Return raw software inventory for server-side NVD matching.
            // Format: name|version (one per line, pipe-delimited). Status only, never a coverage
            // row: these rows are consumed as name|version pairs.
            yuzu::vuln::CoverageState cov;
            auto apps = get_installed_apps(&cov);
            for (const auto& app : apps) {
                ctx.write_output(std::format("{}|{}", escape_pipes(sanitize_utf8(app.name)),
                                             escape_pipes(sanitize_utf8(app.version))));
            }
            declare_coverage(ctx, cov);
            return 0;
        }

        if (action == "summary") {
            yuzu::vuln::CoverageState cov;
            auto cve_findings = do_cve_scan_impl(&cov);
            auto config_findings = do_config_scan_impl(&cov);

            std::vector<Finding> all;
            all.reserve(cve_findings.size() + config_findings.size());
            all.insert(all.end(), cve_findings.begin(), cve_findings.end());
            all.insert(all.end(), config_findings.begin(), config_findings.end());

            output_summary(ctx, all);
            emit_coverage_summary_row(ctx, cov);
            declare_coverage(ctx, cov);
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(VulnScanPlugin)
