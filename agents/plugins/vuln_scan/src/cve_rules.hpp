#pragma once

#include <array>
#include <limits>
#include <string_view>

namespace yuzu::vuln {

struct CveRule {
    std::string_view cve_id;
    std::string_view product;        // case-insensitive substring match on app name
    std::string_view affected_below; // versions below this are vulnerable
    std::string_view fixed_in;       // informational: version that fixed it
    std::string_view severity;       // CRITICAL, HIGH, MEDIUM, LOW
    std::string_view description;
};

/// True when a '.'/'-'-separated, all-digit segment of `v` has more digits than a long long holds
/// (more than 18 after leading zeros), so compare_versions would saturate it.
inline bool version_has_overflowing_segment(std::string_view v) {
    while (!v.empty()) {
        const auto pos = v.find_first_of(".-");
        std::string_view seg = pos == std::string_view::npos ? v : v.substr(0, pos);
        v = pos == std::string_view::npos ? std::string_view{} : v.substr(pos + 1);
        if (seg.find_first_not_of("0123456789") != std::string_view::npos)
            continue;
        const auto nz = seg.find_first_not_of('0');
        if (nz != std::string_view::npos && seg.size() - nz > 18)
            return true;
    }
    return false;
}

// ── Version comparison ─────────────────────────────────────────────────────
// Returns <0 if a<b, 0 if a==b, >0 if a>b.
// Splits on '.' and '-', compares each segment numerically where possible.

inline int compare_versions(std::string_view a, std::string_view b) {
    auto next_segment = [](std::string_view& s) -> std::string_view {
        if (s.empty())
            return {};
        auto pos = s.find_first_of(".-");
        std::string_view seg;
        if (pos == std::string_view::npos) {
            seg = s;
            s = {};
        } else {
            seg = s.substr(0, pos);
            s = s.substr(pos + 1);
        }
        return seg;
    };

    auto to_num = [](std::string_view seg) -> std::pair<bool, long long> {
        if (seg.empty())
            return {true, 0};
        // A segment too large for long long SATURATES (no signed overflow); such a version is not
        // orderable and callers that need a trustworthy answer test version_has_overflowing_segment().
        long long val = 0;
        bool saturated = false;
        for (char c : seg) {
            if (c < '0' || c > '9')
                return {false, 0};
            if (!saturated) {
                const int d = c - '0';
                if (val > ((std::numeric_limits<long long>::max)() - d) / 10)
                    saturated = true;
                else
                    val = val * 10 + d;
            }
        }
        return {true, saturated ? (std::numeric_limits<long long>::max)() : val};
    };

    std::string_view ra = a, rb = b;
    while (!ra.empty() || !rb.empty()) {
        auto sa = next_segment(ra);
        auto sb = next_segment(rb);

        auto [a_num, a_val] = to_num(sa);
        auto [b_num, b_val] = to_num(sb);

        if (a_num && b_num) {
            if (a_val != b_val)
                return (a_val < b_val) ? -1 : 1;
        } else {
            int cmp = sa.compare(sb);
            if (cmp != 0)
                return cmp;
        }
    }
    return 0;
}

// ── Bundled CVE rules ──────────────────────────────────────────────────────
// High-profile CVEs across common software. Updated with plugin releases.

inline constexpr std::array kCveRules = std::to_array<CveRule>({
    // OpenSSL
    {"CVE-2014-0160", "openssl", "1.0.1g", "1.0.1g", "CRITICAL",
     "Heartbleed: TLS heartbeat read overrun allows memory disclosure"},
    {"CVE-2022-3602", "openssl", "3.0.7", "3.0.7", "HIGH",
     "X.509 certificate verification buffer overrun"},
    {"CVE-2023-0286", "openssl", "3.0.8", "3.0.8", "HIGH",
     "X.400 address type confusion in X.509 GeneralName"},
    {"CVE-2024-5535", "openssl", "3.3.2", "3.3.2", "MEDIUM",
     "SSL_select_next_proto buffer overread"},

    // curl
    {"CVE-2023-38545", "curl", "8.4.0", "8.4.0", "CRITICAL", "SOCKS5 heap buffer overflow"},
    {"CVE-2023-38546", "curl", "8.4.0", "8.4.0", "LOW", "Cookie injection with none file"},
    {"CVE-2024-2398", "curl", "8.7.1", "8.7.1", "MEDIUM", "HTTP/2 push headers memory leak"},

    // sudo
    {"CVE-2021-3156", "sudo", "1.9.5p2", "1.9.5p2", "CRITICAL",
     "Baron Samedit: heap buffer overflow in sudoedit"},
    {"CVE-2023-22809", "sudo", "1.9.12p2", "1.9.12p2", "HIGH",
     "sudoedit arbitrary file write via user-provided path"},

    // polkit
    {"CVE-2021-4034", "polkit", "0.120", "0.120", "CRITICAL",
     "PwnKit: local privilege escalation via pkexec"},

    // Log4j (Java)
    {"CVE-2021-44228", "log4j", "2.17.0", "2.17.0", "CRITICAL",
     "Log4Shell: remote code execution via JNDI lookup"},
    {"CVE-2021-45046", "log4j", "2.17.0", "2.17.0", "CRITICAL",
     "Log4Shell bypass: incomplete fix in 2.15.0"},

    // Apache HTTP Server
    {"CVE-2021-41773", "apache", "2.4.50", "2.4.50", "CRITICAL",
     "Path traversal and file disclosure"},
    {"CVE-2023-25690", "apache", "2.4.56", "2.4.56", "CRITICAL",
     "HTTP request smuggling via mod_proxy"},

    // OpenSSH
    {"CVE-2024-6387", "openssh", "9.8", "9.8p1", "CRITICAL",
     "regreSSHion: unauthenticated remote code execution"},
    {"CVE-2023-38408", "openssh", "9.3p2", "9.3p2", "HIGH",
     "PKCS#11 provider remote code execution via ssh-agent"},

    // Python
    {"CVE-2023-24329", "python", "3.11.4", "3.11.4", "HIGH",
     "urllib.parse URL parsing bypass via leading whitespace"},
    {"CVE-2024-0450", "python", "3.12.2", "3.12.2", "MEDIUM",
     "zipfile quoted-overlap zipbomb protection bypass"},

    // Node.js
    {"CVE-2023-44487", "node", "20.8.1", "20.8.1", "HIGH", "HTTP/2 Rapid Reset denial of service"},
    {"CVE-2024-22019", "node", "20.11.1", "20.11.1", "HIGH",
     "Reading unprocessed HTTP request with unbounded chunk extension"},

    // Google Chrome
    {"CVE-2024-0519", "chrome", "120.0.6099.225", "120.0.6099.225", "HIGH",
     "V8 out-of-bounds memory access"},
    {"CVE-2024-4671", "chrome", "124.0.6367.202", "124.0.6367.202", "HIGH",
     "Visuals use-after-free"},

    // Mozilla Firefox
    {"CVE-2024-29944", "firefox", "124.0.1", "124.0.1", "CRITICAL",
     "Privileged JavaScript execution via event handler"},
    {"CVE-2024-9680", "firefox", "131.0.2", "131.0.2", "CRITICAL",
     "Animation timeline use-after-free"},

    // .NET Runtime
    {"CVE-2024-21319", "dotnet", "8.0.1", "8.0.1", "HIGH",
     "Denial of service via SignedCms degenerate certificates"},
    {"CVE-2024-38168", "dotnet", "8.0.8", "8.0.8", "HIGH", "ASP.NET Core denial of service"},

    // Java / OpenJDK
    {"CVE-2024-20918", "openjdk", "21.0.2", "21.0.2", "HIGH",
     "Hotspot array access bounds check bypass"},
    {"CVE-2024-20952", "openjdk", "21.0.2", "21.0.2", "HIGH",
     "Security manager bypass via Object serialization"},

    // Windows Print Spooler
    {"CVE-2021-34527", "windows", "10.0.19041.1083", "KB5004945", "CRITICAL",
     "PrintNightmare: RCE via Windows Print Spooler"},
    {"CVE-2021-1675", "windows", "10.0.19041.1052", "KB5003637", "CRITICAL",
     "Print Spooler privilege escalation"},

    // nginx
    {"CVE-2022-41741", "nginx", "1.23.2", "1.23.2", "HIGH", "mp4 module memory corruption"},
    {"CVE-2024-7347", "nginx", "1.27.1", "1.27.1", "MEDIUM", "Worker process crash in mp4 module"},

    // PostgreSQL
    {"CVE-2023-5868", "postgresql", "16.1", "16.1", "MEDIUM",
     "Memory disclosure in aggregate function calls"},
    {"CVE-2024-0985", "postgresql", "16.2", "16.2", "HIGH",
     "Non-owner REFRESH MATERIALIZED VIEW CONCURRENTLY executes as owner"},

    // Git
    {"CVE-2024-32002", "git", "2.45.1", "2.45.1", "CRITICAL",
     "RCE via crafted repositories with submodules"},
    {"CVE-2023-25652", "git", "2.40.1", "2.40.1", "HIGH",
     "git apply --reject writes outside worktree"},

    // 7-Zip
    {"CVE-2024-11477", "7-zip", "24.07", "24.07", "HIGH",
     "Zstandard decompression integer underflow RCE"},

    // WinRAR
    {"CVE-2023-38831", "winrar", "6.23", "6.23", "HIGH",
     "Code execution when opening crafted archive"},

    // PuTTY
    {"CVE-2024-31497", "putty", "0.81", "0.81", "CRITICAL",
     "NIST P-521 private key recovery from ECDSA signatures"},

    // PHP
    {"CVE-2024-4577", "php", "8.3.8", "8.3.8", "CRITICAL", "CGI argument injection on Windows"},
    {"CVE-2024-2756", "php", "8.3.4", "8.3.4", "MEDIUM", "Cookie __Host-/__Secure- prefix bypass"},
});

} // namespace yuzu::vuln
