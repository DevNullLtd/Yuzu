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
 *   summary|<severity>|<count>
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <format>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
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

namespace {

// ── Subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
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

std::vector<AppInfo> get_installed_apps() {
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
std::vector<AppInfo> get_installed_apps() {
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
std::vector<AppInfo> get_installed_apps() {
    std::vector<AppInfo> apps;

    auto out = run_command("system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null"
                           " | grep -E '^ {4}\\w|Version:'");
    if (!out.empty()) {
        std::istringstream ss(out);
        std::string line;
        std::string current_name;
        std::string current_version;
        while (std::getline(ss, line)) {
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            line = line.substr(start);

            if (line.find("Version:") == 0) {
                current_version = line.substr(line.find(':') + 2);
            } else if (!line.empty() && line.back() == ':') {
                if (!current_name.empty()) {
                    apps.push_back({current_name, current_version});
                }
                current_name = line.substr(0, line.size() - 1);
                current_version.clear();
            }
        }
        if (!current_name.empty()) {
            apps.push_back({current_name, current_version});
        }
    }

    // Also check Homebrew packages
    if (command_exists("brew")) {
        auto brew_out = run_command("brew list --versions 2>/dev/null");
        std::istringstream ss(brew_out);
        std::string line;
        while (std::getline(ss, line)) {
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                apps.push_back({line.substr(0, sp), line.substr(sp + 1)});
            }
        }
    }

    return apps;
}
#else
std::vector<AppInfo> get_installed_apps() {
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

std::vector<Finding> do_cve_scan_impl() {
    std::vector<Finding> findings;
    auto apps = get_installed_apps();

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

std::vector<Finding> do_config_scan_impl() {
    std::vector<Finding> findings;
    auto checks = yuzu::vuln::run_all_config_checks();

    for (const auto& check : checks) {
        // Report all checks (passed ones as INFO)
        findings.push_back(
            {std::string(check.severity), "config", std::string(check.title), check.detail});
    }

    return findings;
}

// ── Output helpers ────────────────────────────────────────────────────────

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
    std::map<std::string, int> counts;
    counts["CRITICAL"] = 0;
    counts["HIGH"] = 0;
    counts["MEDIUM"] = 0;
    counts["LOW"] = 0;
    counts["INFO"] = 0;

    for (const auto& f : findings) {
        counts[f.severity]++;
    }

    // Output total first
    int total = 0;
    int issues = 0;
    for (const auto& [sev, count] : counts) {
        total += count;
        if (sev != "INFO")
            issues += count;
    }

    ctx.write_output(std::format("summary|TOTAL|{} findings ({} issues)", total, issues));

    for (const auto& sev : {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}) {
        ctx.write_output(std::format("summary|{}|{}", sev, counts[sev]));
    }
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
//   - macOS: get_installed_apps shells out via popen (system_profiler,
//     optionally brew); run_macos_checks is almost entirely popen
//     (spctl/fdesetup/csrutil/socketfilterfw/systemsetup/defaults) — rung 3.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        "scan",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(pkg-manager+iptables/nft/ufw)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(system_profiler/brew+security-checks)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "cve_scan",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(dpkg-query/rpm/pacman/apk)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(system_profiler/brew)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "config_scan",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(iptables/nft/ufw)+procfs", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(spctl/fdesetup/csrutil/socketfilterfw)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "summary",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(pkg-manager+iptables/nft/ufw)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(system_profiler/brew+security-checks)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "inventory",
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(dpkg-query/rpm/pacman/apk)", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 3, "popen(system_profiler/brew)", nullptr},
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
            auto cve_findings = do_cve_scan_impl();
            ctx.report_progress(50);
            auto config_findings = do_config_scan_impl();
            ctx.report_progress(90);

            std::vector<Finding> all;
            all.reserve(cve_findings.size() + config_findings.size());
            all.insert(all.end(), cve_findings.begin(), cve_findings.end());
            all.insert(all.end(), config_findings.begin(), config_findings.end());

            output_findings(ctx, all);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "cve_scan") {
            ctx.report_progress(0);
            auto findings = do_cve_scan_impl();
            output_findings(ctx, findings);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "config_scan") {
            ctx.report_progress(0);
            auto findings = do_config_scan_impl();
            output_findings(ctx, findings);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "inventory") {
            // Return raw software inventory for server-side NVD matching.
            // Format: name|version (one per line, pipe-delimited)
            auto apps = get_installed_apps();
            for (const auto& app : apps) {
                ctx.write_output(std::format("{}|{}", escape_pipes(sanitize_utf8(app.name)),
                                             escape_pipes(sanitize_utf8(app.version))));
            }
            return 0;
        }

        if (action == "summary") {
            auto cve_findings = do_cve_scan_impl();
            auto config_findings = do_config_scan_impl();

            std::vector<Finding> all;
            all.reserve(cve_findings.size() + config_findings.size());
            all.insert(all.end(), cve_findings.begin(), cve_findings.end());
            all.insert(all.end(), config_findings.begin(), config_findings.end());

            output_summary(ctx, all);
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(VulnScanPlugin)
