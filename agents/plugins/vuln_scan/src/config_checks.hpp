#pragma once

#include <array>
#include <cerrno>
#include <cstdio>
#include <expected>
#include <functional>
#include <fstream>
#include <format>
#include <istream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "macos_software.hpp"

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
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

namespace yuzu::vuln {

struct ConfigCheckResult {
    std::string_view severity;
    std::string_view title;
    std::string detail;
    bool passed;
};

// ── Portable read results and pure decisions (#4961) ───────────────────────
//
// A read that FAILED must never look like a read that returned an empty or
// unexpected value: the former is "the check could not run" (UNREADABLE), the
// latter is a real finding. Readers return the value or the errno; the checks
// below are pure so every OS's unit suite exercises them.

using ReadResult = std::expected<std::string, int>;                // value or errno
using LinesResult = std::expected<std::vector<std::string>, int>;  // lines or errno

inline std::string errno_name(int e) {
    switch (e) {
    case EACCES: return "eacces";
    case EPERM: return "eperm";
    case ENOENT: return "enoent";
    case EIO: return "eio";
    case ENOTDIR: return "enotdir";
    case EISDIR: return "eisdir";
    default: return "errno_" + std::to_string(e);
    }
}

// badbit = an I/O fault mid-read (libstdc++ records a read() error as badbit with
// errno set). failbit+eofbit on a short or empty file is a VALUE (empty string)
// here; libc++ also reports a read fault that way, which is why
// aslr_check/suid_dumpable_check treat an empty /proc/sys value as a fault.
inline ReadResult read_value_from(std::istream& in) {
    std::string val;
    std::getline(in, val);
    if (in.bad())
        return std::unexpected(EIO);
    return val;
}

inline LinesResult read_lines_from(std::istream& in) {
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line))
        lines.push_back(line);
    if (in.bad())
        return std::unexpected(EIO);
    return lines;
}

// Pure summary output (one string per output line): the TOTAL row first, then
// one row per severity. UNREADABLE (the check could not run)
// is counted separately and is NOT an issue, nor is INFO.
inline std::vector<std::string> summary_rows(const std::vector<std::string>& severities) {
    static constexpr const char* kSeverities[] = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNREADABLE"};
    std::map<std::string, int> counts;
    for (const char* sev : kSeverities)
        counts[sev] = 0;
    for (const auto& s : severities)
        counts[s]++;

    int total = 0;
    int issues = 0;
    for (const auto& [sev, count] : counts) {
        total += count;
        if (sev != "INFO" && sev != "UNREADABLE")
            issues += count;
    }

    std::vector<std::string> rows;
    rows.push_back(std::format("summary|TOTAL|{} findings ({} issues)", total, issues));
    for (const char* sev : kSeverities)
        rows.push_back(std::format("summary|{}|{}", sev, counts[sev]));
    return rows;
}

namespace detail {

inline ConfigCheckResult unreadable(std::string_view title, std::string_view path, int err) {
    return {"UNREADABLE", title, std::string(path) + ": " + errno_name(err), false};
}

// Comment lines (first non-blank char '#') never count as a directive.
inline bool directive_present(const std::vector<std::string>& lines, std::string_view needle) {
    for (const auto& line : lines) {
        auto pos = line.find_first_not_of(" \t");
        if (pos != std::string::npos && line[pos] == '#')
            continue;
        if (line.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

inline constexpr std::string_view kAslrPath = "/proc/sys/kernel/randomize_va_space";
inline constexpr std::string_view kSuidPath = "/proc/sys/fs/suid_dumpable";
inline constexpr std::string_view kSshdConfigPath = "/etc/ssh/sshd_config";
inline constexpr std::string_view kMountsPath = "/proc/mounts";

// An absent sshd_config means no SSH server config to weaken -- not a finding.
inline ConfigCheckResult sshd_not_applicable(std::string_view title) {
    return {"INFO", title, std::string(kSshdConfigPath) + " not present; check not applicable",
            true};
}

} // namespace detail

inline ConfigCheckResult aslr_check(const ReadResult& r) {
    constexpr std::string_view title = "ASLR (Address Space Layout Randomization)";
    if (!r)
        return detail::unreadable(title, detail::kAslrPath, r.error());
    const auto& val = *r;
    // A /proc/sys value is never empty: an empty read is a fault the stream did not
    // flag (libc++ surfaces a read error as EOF, not badbit; a masked file reads
    // empty), never a value to judge.
    if (val.empty())
        return detail::unreadable(title, detail::kAslrPath, EIO);
    bool ok = !val.empty() && val[0] == '2';
    return {ok ? "INFO" : "HIGH", title,
            ok ? "Full randomization enabled (value=2)"
               : "Not fully enabled (value=" + val + ") - should be 2",
            ok};
}

inline ConfigCheckResult suid_dumpable_check(const ReadResult& r) {
    constexpr std::string_view title = "SUID Core Dumps";
    if (!r)
        return detail::unreadable(title, detail::kSuidPath, r.error());
    const auto& val = *r;
    if (val.empty())
        return detail::unreadable(title, detail::kSuidPath, EIO); // see aslr_check
    bool ok = !val.empty() && val[0] == '0';
    return {ok ? "INFO" : "MEDIUM", title,
            ok ? "Restricted (suid_dumpable=0)"
               : "Not restricted (suid_dumpable=" + val + ") - SUID programs may dump core",
            ok};
}

inline ConfigCheckResult ssh_root_login_check(const LinesResult& r) {
    constexpr std::string_view title = "SSH Root Login";
    if (!r) {
        if (r.error() == ENOENT)
            return detail::sshd_not_applicable(title);
        return detail::unreadable(title, detail::kSshdConfigPath, r.error());
    }
    // Explicit "no" wins; "yes" is insecure; neither -> default depends on
    // distro, so flag as a warning.
    if (detail::directive_present(*r, "PermitRootLogin no"))
        return {"INFO", title, "PermitRootLogin is set to no", true};
    if (detail::directive_present(*r, "PermitRootLogin yes"))
        return {"HIGH", title,
                "PermitRootLogin is set to yes - direct root access via SSH is enabled", false};
    return {"MEDIUM", title,
            "PermitRootLogin not explicitly set - may default to prohibit-password", false};
}

// nullopt when neither directive is present: no row is emitted (unchanged).
inline std::optional<ConfigCheckResult> ssh_password_auth_check(const LinesResult& r) {
    constexpr std::string_view title = "SSH Password Authentication";
    if (!r) {
        if (r.error() == ENOENT)
            return detail::sshd_not_applicable(title);
        return detail::unreadable(title, detail::kSshdConfigPath, r.error());
    }
    if (detail::directive_present(*r, "PasswordAuthentication no"))
        return ConfigCheckResult{"INFO", title, "Disabled - key-based auth only", true};
    if (detail::directive_present(*r, "PasswordAuthentication yes"))
        return ConfigCheckResult{"MEDIUM", title,
                                 "Enabled - consider using key-based authentication only", false};
    return std::nullopt;
}

// nullopt when /proc/mounts has no separate /tmp mount: no row is emitted (unchanged).
inline std::optional<ConfigCheckResult> tmp_noexec_check(const LinesResult& r) {
    constexpr std::string_view title = "/tmp noexec";
    if (!r)
        return detail::unreadable(title, detail::kMountsPath, r.error());
    for (const auto& line : *r) {
        if (line.find(" /tmp ") == std::string::npos)
            continue;
        const bool has_noexec = line.find("noexec") != std::string::npos;
        return ConfigCheckResult{
            has_noexec ? "INFO" : "MEDIUM", title,
            has_noexec ? "/tmp is mounted with noexec"
                       : "/tmp is not mounted with noexec - executables can run from /tmp",
            has_noexec};
    }
    return std::nullopt;
}

// ── Subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
namespace detail {

// popen with RAII ownership: an exception (std::bad_alloc while appending) between popen and the
// close still closes the FILE* and reaps the child. Move-less by design.
struct Pipe {
    FILE* f = nullptr;
    explicit Pipe(const char* cmd) : f(popen(cmd, "r")) {}
    Pipe(const Pipe&) = delete;
    Pipe& operator=(const Pipe&) = delete;
    // Returns pclose's status (-1 when never opened or already closed); nulls the handle.
    int close() {
        if (!f)
            return -1;
        FILE* p = f;
        f = nullptr;
        return pclose(p);
    }
    ~Pipe() { close(); }
};

// `exited_ok` (optional): the command started and exited 0.
inline std::string run_cmd(const char* cmd, bool* exited_ok = nullptr) {
    std::string result;
    std::array<char, 256> buf{};
    if (exited_ok)
        *exited_ok = false;
    Pipe pipe(cmd);
    if (!pipe.f)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.f)) {
        result += buf.data();
    }
    const int rc = pipe.close();
    if (exited_ok)
        *exited_ok = rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

// Open failure -> errno from open. A fault after open (badbit, libstdc++) -> the
// errno the kernel set during the read, else EIO. (libc++ reports a read fault as
// EOF; the /proc/sys checks close that in the pure layer.)
template <typename Reader>
inline auto read_file_with(const char* path, Reader reader)
    -> std::invoke_result_t<Reader, std::ifstream&> {
    std::ifstream f(path);
    if (!f.is_open())
        return std::unexpected(errno ? errno : EIO);
    errno = 0;
    auto r = reader(f);
    if (!r && errno != 0)
        return std::unexpected(errno);
    return r;
}

inline ReadResult read_proc_value(const char* path) {
    return read_file_with(path, [](std::istream& in) { return read_value_from(in); });
}

inline LinesResult read_lines(const char* path) {
    return read_file_with(path, [](std::istream& in) { return read_lines_from(in); });
}

} // namespace detail
#endif

// ── Windows config checks ──────────────────────────────────────────────────

#ifdef _WIN32
namespace detail {

inline std::string read_registry_string(HKEY root, const char* subkey, const char* value_name) {
    // Reg*W so a non-ASCII config value survives as UTF-8 rather than cp1252
    // mojibake when it lands in a stored vuln finding (#1662 / #1682). Widen the
    // names BEFORE opening so the only operation between open and RegCloseKey is the
    // non-allocating RegQueryValueExW; reg_sz_to_utf8 runs AFTER close, so a
    // std::bad_alloc cannot leak the HKEY (#1682 Gate-4 R1).
    const std::wstring wsubkey = yuzu::win::to_wide(subkey);
    const std::wstring wvalue = yuzu::win::to_wide(value_name);
    HKEY hkey{};
    if (RegOpenKeyExW(root, wsubkey.c_str(), 0, KEY_READ, &hkey) != ERROR_SUCCESS)
        return {};
    wchar_t buf[512]{};
    DWORD size = sizeof(buf); // size in BYTES; buf written as bytes, read back through
    DWORD type = 0;           // its declared wchar_t lvalue (LPBYTE is alignment-1)
    const LONG rc = RegQueryValueExW(hkey, wvalue.c_str(), nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hkey); // closed before the allocating convert -- no leak window
    if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) &&
        size >= sizeof(wchar_t)) {
        return yuzu::win::reg_sz_to_utf8(buf, size);
    }
    return {};
}

// Numeric read -- the value is a DWORD, never decoded into a string, so it carries
// no encoding and stays Reg*A (no cp1252 mojibake risk; #1682 audit).
inline DWORD read_registry_dword(HKEY root, const char* subkey, const char* value_name,
                                 DWORD default_val) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
        return default_val;
    DWORD val = 0;
    DWORD size = sizeof(val);
    DWORD type = 0;
    DWORD result = default_val;
    if (RegQueryValueExA(hkey, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size) ==
        ERROR_SUCCESS) {
        if (type == REG_DWORD)
            result = val;
    }
    RegCloseKey(hkey);
    return result;
}

} // namespace detail

inline std::vector<ConfigCheckResult> run_windows_checks() {
    std::vector<ConfigCheckResult> results;

    // UAC enabled
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA", 0);
        results.push_back(
            {val == 1 ? "INFO" : "HIGH", "UAC (User Account Control)",
             val == 1 ? "Enabled" : "Disabled - system is vulnerable to privilege escalation",
             val == 1});
    }

    // SMBv1 disabled
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "SMB1", 1); // default is enabled if key missing
        results.push_back(
            {val == 0 ? "INFO" : "CRITICAL", "SMBv1 Protocol",
             val == 0 ? "Disabled" : "Enabled - vulnerable to EternalBlue/WannaCry (MS17-010)",
             val == 0});
    }

    // Auto-logon disabled
    {
        auto val = detail::read_registry_string(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "AutoAdminLogon");
        bool disabled = val.empty() || val == "0";
        results.push_back(
            {disabled ? "INFO" : "HIGH", "Auto-Logon",
             disabled ? "Disabled" : "Enabled - credentials stored in plaintext in registry",
             disabled});
    }

    // RDP Network Level Authentication
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            "UserAuthentication", 0);
        auto rdp_enabled = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            "fDenyTSConnections", 1);
        if (rdp_enabled == 0) { // RDP is enabled
            results.push_back(
                {val == 1 ? "INFO" : "HIGH", "RDP Network Level Authentication",
                 val == 1 ? "Enabled" : "Disabled - RDP is exposed without pre-authentication",
                 val == 1});
        }
    }

    // Windows Defender real-time protection
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableRealtimeMonitoring", 0);
        results.push_back({val == 0 ? "INFO" : "HIGH", "Windows Defender Real-Time Protection",
                           val == 0 ? "Enabled" : "Disabled - no real-time malware protection",
                           val == 0});
    }

    // Firewall profiles
    {
        static const char* kProfiles[] = {"DomainProfile", "StandardProfile", "PublicProfile"};
        static const char* kNames[] = {"Domain", "Private", "Public"};
        for (int i = 0; i < 3; ++i) {
            auto subkey = std::string("SYSTEM\\CurrentControlSet\\Services\\"
                                      "SharedAccess\\Parameters\\FirewallPolicy\\") +
                          kProfiles[i];
            auto val = detail::read_registry_dword(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                                   "EnableFirewall", 0);
            results.push_back(
                {val == 1 ? "INFO" : "HIGH", "Windows Firewall",
                 std::string(kNames[i]) + " profile: " + (val == 1 ? "Enabled" : "Disabled"),
                 val == 1});
        }
    }

    return results;
}
#endif

// ── Linux config checks ───────────────────────────────────────────────────

#ifdef __linux__
inline std::vector<ConfigCheckResult> run_linux_checks() {
    std::vector<ConfigCheckResult> results;

    // SSH: sshd_config is read ONCE; both SSH checks decide from that read.
    {
        const auto sshd = detail::read_lines(detail::kSshdConfigPath.data());
        results.push_back(ssh_root_login_check(sshd));
        if (auto pw = ssh_password_auth_check(sshd))
            results.push_back(std::move(*pw));
    }

    results.push_back(aslr_check(detail::read_proc_value(detail::kAslrPath.data())));
    results.push_back(suid_dumpable_check(detail::read_proc_value(detail::kSuidPath.data())));

    if (auto t = tmp_noexec_check(detail::read_lines(detail::kMountsPath.data())))
        results.push_back(std::move(*t));

    // Firewall (iptables/nftables)
    {
        auto ipt = detail::run_cmd("iptables -L -n 2>/dev/null | wc -l");
        auto nft = detail::run_cmd("nft list ruleset 2>/dev/null | wc -l");
        auto ufw = detail::run_cmd("ufw status 2>/dev/null | head -1");

        bool has_rules = false;
        std::string detail_str;

        if (ufw.find("active") != std::string::npos) {
            has_rules = true;
            detail_str = "UFW firewall is active";
        } else {
            int ipt_lines = 0, nft_lines = 0;
            try {
                ipt_lines = std::stoi(ipt);
            } catch (...) {}
            try {
                nft_lines = std::stoi(nft);
            } catch (...) {}
            // iptables -L with no rules still shows ~8 lines (headers)
            has_rules = ipt_lines > 10 || nft_lines > 0;
            if (has_rules) {
                detail_str = "Firewall rules detected";
            } else {
                detail_str = "No firewall rules detected - host may be unprotected";
            }
        }

        results.push_back({has_rules ? "INFO" : "HIGH", "Firewall", detail_str, has_rules});
    }

    // World-writable directories in PATH
    // Uses stat() directly instead of shell commands to avoid injection.
    {
        const char* path_env = std::getenv("PATH");
        std::vector<std::string> writable;
        if (path_env) {
            std::istringstream ss(path_env);
            std::string dir;
            while (std::getline(ss, dir, ':')) {
                if (dir.empty())
                    continue;
                struct stat st{};
                if (stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    // Check if world-writable (other-write bit)
                    if (st.st_mode & S_IWOTH) {
                        writable.push_back(dir);
                    }
                }
            }
        }
        if (!writable.empty()) {
            std::string dirs;
            for (const auto& d : writable) {
                if (!dirs.empty())
                    dirs += ", ";
                dirs += d;
            }
            results.push_back({"HIGH", "World-Writable PATH Directories",
                               "World-writable directories found in PATH: " + dirs, false});
        }
    }

    return results;
}
#endif

// ── macOS config decisions (portable, pure) ────────────────────────────────
//
// What a verdict needs (every rule is exercised by tests/unit/test_vuln_macos_software.cpp):
//   - the tool's WHOLE trimmed output is judged, line by line, empty lines ignored;
//   - GOOD needs exactly ONE non-empty line that EQUALS the good text, from a run that exited 0;
//   - BAD is judged from any COMPLETED run (the exit code is not relied on) and WINS over any other
//     line, so contradictory or multi-line output can never read as good;
//   - ABSENT (the setting is not set) needs exactly one line equal to the absent text, from any
//     completed run (measured: `defaults read` exits 1 for an absent key);
//   - anything else (missing tool, cut-short run, empty output, a permission message, localized or
//     near-miss text such as "enabled (Custom Configuration).") is
//     `UNREADABLE|config|<check>|Unknown (read failed)`: never a verdict and never a pass.
//   A prefix match is never enough. The Firewall state digit must agree with the text.
//
// ONE TABLE: everything to correct from a real Mac capture lives in kMacosCheckSpecs below (expected
// lines, state digits, severities, details, the good-state exit-zero policy, stderr merging).
//
// MEASURED on ONE macOS 27.0.1 Apple Silicon host (13-15 NOT measured):
//   spctl --status               -> "assessments enabled", exit 0
//   fdesetup status              -> "FileVault is On.", exit 0
//   csrutil status               -> "System Integrity Protection status: enabled.", exit 0
//   socketfilterfw --getglobalstate -> "Firewall is disabled. (State = 0)", exit 0 (the DISABLED
//                                      state: the enabled line and its digit are NOT measured)
//   systemsetup -getremotelogin  -> "Remote Login: Off", exit 0 (run via sudo, not as the daemon)
//   defaults read <PATH form: /Library/Preferences/com.apple.SoftwareUpdate> AutomaticCheckEnabled
//                                -> "Error: Could not find key ... ." (key absent), exit 1
// UNMEASURED (a read whose text differs is UNREADABLE): the BARE-domain defaults text, a system plist
// at 0, 1, absent or shadowed by a per-user/managed value as the LaunchDaemon account, any tool's
// exit code in its BAD state, the enabled Firewall `State` digit ("12" below is accepted on Apple's
// documentation, unverified; the only measured pairing is disabled <-> 0), `systemsetup` as the
// launchd daemon, Full Disk Access / PPPC needs, and `system_profiler` under a non-English language.
// A digit that does not agree with the text reads UNREADABLE. The bare "Firewall is enabled." line
// (no State suffix) is ACCEPTED as good on purpose: the suffix is optional, and the line is still
// exact and single. The update-check setting is read twice (bare domain and path form) and the
// worse answer wins.

struct CommandRead {
    std::string out;
    bool ok = false;  // started, not cut short, exit status 0
    bool ran = false; // started and ran to completion (any exit status), not cut short
};

// Runs one pre-split argv (stderr merged into the captured text when `merge_stderr`) and reports
// the captured text and how the run ended.
using MacosReader = std::function<CommandRead(const Argv&, bool merge_stderr)>;

enum class MacosCheck { Gatekeeper, FileVault, Sip, Firewall, RemoteLogin, AutoUpdate };

struct MacosCheckSpec {
    MacosCheck check;
    std::string_view title;
    const Argv* argv;
    std::string_view good_line;     // whole trimmed line of the "good" state
    std::string_view bad_line;      // whole trimmed line of the "bad" state
    std::string_view good_digits;   // allowed " (State = <d>)" digits after good_line ("" = no suffix)
    std::string_view bad_digits;    // same for bad_line
    bool good_requires_exit_zero;   // a good verdict also needs exit 0 (true for every tool)
    std::string_view good_detail;
    std::string_view bad_severity;
    std::string_view bad_detail;
    bool merge_stderr;              // capture stderr too (only where the tool reports on stderr)
    std::string_view absent_line;   // whole line meaning "setting not set" ("" = none)
    std::string_view absent_detail; // INFO detail for the absent case
    const Argv* argv_alt;           // optional SECOND read of the same setting (nullptr = none); the
                                    // worse of the two answers wins (macos_check_result_dual)
};

inline const std::array<MacosCheckSpec, 6> kMacosCheckSpecs = {{
    {MacosCheck::Gatekeeper, "Gatekeeper", &kMacosSpctlCmd, "assessments enabled",
     "assessments disabled", "", "", true, "Enabled - only verified apps can run", "HIGH",
     "Disabled - unsigned apps can run without restriction", false, "", "", nullptr},
    {MacosCheck::FileVault, "FileVault Disk Encryption", &kMacosFdesetupCmd, "FileVault is On.",
     "FileVault is Off.", "", "", true, "Enabled", "HIGH", "Disabled - disk is not encrypted", false,
     "", "", nullptr},
    {MacosCheck::Sip, "System Integrity Protection (SIP)", &kMacosCsrutilCmd,
     "System Integrity Protection status: enabled.",
     "System Integrity Protection status: disabled.", "", "", true, "Enabled", "CRITICAL",
     "Disabled - system files are unprotected", false, "", "", nullptr},
    {MacosCheck::Firewall, "Application Firewall", &kMacosSocketfilterfwCmd, "Firewall is enabled.",
     "Firewall is disabled.", "12", "0", true, "Enabled", "MEDIUM", "Disabled", false, "", "", nullptr},
    {MacosCheck::RemoteLogin, "Remote Login (SSH)", &kMacosSystemsetupCmd, "Remote Login: Off",
     "Remote Login: On", "", "", true, "Disabled", "MEDIUM", "Enabled - SSH access is open", false,
     "", "", nullptr},
    // The key covers the update CHECK only, not installation: the title and detail say so. Read
    // twice (bare domain, then the /Library/Preferences path form); see kMacosDefaultsCmd.
    {MacosCheck::AutoUpdate, "Automatic update check", &kMacosDefaultsCmd, "1", "0", "", "", true,
     "Enabled (check only; install not assessed)", "MEDIUM",
     "Disabled - the update check is off; patches may be missed", true,
     "Error: Could not find key 'AutomaticCheckEnabled' in domain 'com.apple.SoftwareUpdate'.",
     "Automatic update check: not set (macOS default applies)", &kMacosDefaultsPathCmd},
}};

inline const MacosCheckSpec& macos_spec(MacosCheck c) {
    for (const auto& s : kMacosCheckSpecs)
        if (s.check == c)
            return s;
    return kMacosCheckSpecs[0]; // unreachable: every enumerator has a row
}

// `line` equals `text`, or `text` followed by exactly " (State = <d>)" with <d> one of `digits`.
inline bool macos_line_matches(std::string_view line, std::string_view text,
                               std::string_view digits) {
    if (line == text)
        return true;
    if (digits.empty() || !line.starts_with(text))
        return false;
    const std::string_view rest = line.substr(text.size());
    constexpr std::string_view kOpen = " (State = ";
    return rest.size() == kOpen.size() + 2 && rest.starts_with(kOpen) &&
           digits.find(rest[kOpen.size()]) != std::string_view::npos && rest.back() == ')';
}

inline ConfigCheckResult macos_check_result(MacosCheck check, const CommandRead& r) {
    const MacosCheckSpec& sp = macos_spec(check);
    const ConfigCheckResult unknown{"UNREADABLE", sp.title, std::string(kConfigUnknownDetail),
                                    false};
    if (!(r.ran || r.ok))
        return unknown; // never completed: nothing to judge

    // The whole output, trimmed per line, empty lines dropped.
    std::vector<std::string_view> lines;
    std::string_view rest = r.out;
    while (!rest.empty()) {
        const auto nl = rest.find('\n');
        const auto line = detail::trim(rest.substr(0, nl));
        if (!line.empty())
            lines.push_back(line);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
    }
    bool saw_bad = false;
    for (const auto l : lines)
        if (macos_line_matches(l, sp.bad_line, sp.bad_digits))
            saw_bad = true;
    if (saw_bad) // any bad line wins, from any completed run
        return {sp.bad_severity, sp.title, std::string(sp.bad_detail), false};
    if (lines.size() != 1)
        return unknown; // good and absent need exactly one line
    if (!sp.absent_line.empty() && lines[0] == sp.absent_line)
        return {"INFO", sp.title, std::string(sp.absent_detail), true};
    if (macos_line_matches(lines[0], sp.good_line, sp.good_digits) &&
        (r.ok || !sp.good_requires_exit_zero))
        return {"INFO", sp.title, std::string(sp.good_detail), true};
    return unknown;
}

// Combine two reads of the SAME setting. The worse answer wins: a bad verdict over UNREADABLE over
// INFO. INFO needs BOTH reads to be good-or-absent AND to agree (same detail): a good read paired
// with an absent read is a DISAGREEMENT and reads UNREADABLE, because the bare-domain read may
// cascade differently from the system plist or be shadowed by a per-user or managed value.
inline ConfigCheckResult macos_combine_reads(const ConfigCheckResult& a, const ConfigCheckResult& b) {
    const auto rank = [](const ConfigCheckResult& r) {
        return r.severity == "UNREADABLE" ? 2 : (r.passed ? 0 : 3);
    };
    const int ra = rank(a), rb = rank(b);
    if (ra == 3 || rb == 3)
        return ra >= rb ? a : b;
    if (ra == 2)
        return a;
    if (rb == 2)
        return b;
    if (a.detail != b.detail)
        return {"UNREADABLE", a.title, std::string(kConfigUnknownDetail), false};
    return a;
}

inline ConfigCheckResult macos_check_result_dual(MacosCheck check, const CommandRead& first,
                                                 const CommandRead& second) {
    return macos_combine_reads(macos_check_result(check, first), macos_check_result(check, second));
}

// True when any check could not be read (severity UNREADABLE). macOS callers only: Linux's file
// checks also use UNREADABLE and must not raise the macOS status token.
inline bool any_config_unreadable(const std::vector<ConfigCheckResult>& results) {
    for (const auto& r : results)
        if (r.severity == "UNREADABLE" && r.detail != kOpenPortUnavailableDetail)
            return true;
    return false;
}

// ── macOS config checks ───────────────────────────────────────────────────

// Runs every table row through `reader`; a null reader fails closed (every check UNREADABLE).
inline std::vector<ConfigCheckResult> run_macos_checks_table(const MacosReader& reader) {
    std::vector<ConfigCheckResult> out;
    for (const auto& sp : kMacosCheckSpecs) {
        const auto read = [&](const Argv& a) { return reader ? reader(a, sp.merge_stderr) : CommandRead{}; };
        out.push_back(sp.argv_alt ? macos_check_result_dual(sp.check, read(*sp.argv), read(*sp.argv_alt))
                                  : macos_check_result(sp.check, read(*sp.argv)));
    }
    return out;
}

#ifdef __APPLE__
// `reader` runs one argv through the bounded runner (supplied by the plugin, which links
// agent-core). A null reader fails closed: every check reads Unknown.
inline std::vector<ConfigCheckResult> run_macos_checks(const MacosReader& reader) {
    return run_macos_checks_table(reader);
}
#endif

// ── Cross-platform checks ─────────────────────────────────────────────────

inline std::vector<ConfigCheckResult> run_cross_platform_checks() {
    std::vector<ConfigCheckResult> results;

#ifdef __APPLE__
    // `ss` is not present on macOS and `netstat -tlnp` is not valid there, so no open-port check
    // runs. Absence of rows must not read as "no risky ports": report the check as UNREADABLE.
    // It is a standing unavailability, not a failed read, so any_config_unreadable() ignores it
    // (otherwise every Mac would report CONSTRAINED permanently); the row itself is the signal.
    results.push_back({"UNREADABLE", "Open Ports", std::string(kOpenPortUnavailableDetail), false});
#elif defined(__linux__)
    // Check for common risky ports listening on all interfaces
    auto listeners = detail::run_cmd("ss -tlnH 2>/dev/null || netstat -tlnp 2>/dev/null");
    if (!listeners.empty()) {
        static constexpr struct {
            int port;
            const char* name;
            const char* risk;
        } kRiskyPorts[] = {
            {21, "FTP", "Unencrypted file transfer"},
            {23, "Telnet", "Unencrypted remote access"},
            {445, "SMB", "File sharing - common attack vector"},
            {3389, "RDP", "Remote desktop - frequent brute force target"},
            {5900, "VNC", "Remote desktop - often unencrypted"},
        };

        for (const auto& rp : kRiskyPorts) {
            auto port_str = ":" + std::to_string(rp.port) + " ";
            auto any_bind = "0.0.0.0:" + std::to_string(rp.port);
            auto any6_bind = ":::" + std::to_string(rp.port);
            if (listeners.find(any_bind) != std::string::npos ||
                listeners.find(any6_bind) != std::string::npos) {
                results.push_back({"HIGH", "Open Port",
                                   std::string(rp.name) + " (port " + std::to_string(rp.port) +
                                       ") listening on all interfaces - " + rp.risk,
                                   false});
            }
        }
    }
#endif

#ifdef _WIN32
    // On Windows, check common risky ports via netstat
    // (simplified — real implementation would parse netstat output)
    // For now, skipped since Windows firewall check covers this area
#endif

    return results;
}

// ── Run all platform checks ───────────────────────────────────────────────

inline std::vector<ConfigCheckResult> run_all_config_checks([[maybe_unused]] const MacosReader& macos_reader = {}) {
    std::vector<ConfigCheckResult> results;

#ifdef _WIN32
    auto win = run_windows_checks();
    results.insert(results.end(), win.begin(), win.end());
#elif defined(__linux__)
    auto lin = run_linux_checks();
    results.insert(results.end(), lin.begin(), lin.end());
#elif defined(__APPLE__)
    auto mac = run_macos_checks(macos_reader);
    results.insert(results.end(), mac.begin(), mac.end());
#endif

    auto cross = run_cross_platform_checks();
    results.insert(results.end(), cross.begin(), cross.end());

    return results;
}

} // namespace yuzu::vuln
