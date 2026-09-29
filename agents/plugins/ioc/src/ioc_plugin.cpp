/**
 * ioc_plugin.cpp — Indicator of Compromise checking plugin for Yuzu
 *
 * Actions:
 *   "check" — Check IOCs against local endpoint state.
 *             Parameters (all optional, comma-separated):
 *               ip_addresses  — IPs to check against active connections
 *               domains       — domains to check against DNS cache
 *               file_hashes   — SHA-256 hashes to check against files on disk
 *               file_paths    — specific file paths to check existence
 *               ports         — ports to check for listening services
 *
 * Output is pipe-delimited via write_output():
 *   type|value|matched|detail
 *   ip|192.168.1.100|true|Active connection (pid 1234)
 *   hash|abc123...|false|No matching files
 *   domain|evil.com|false|Not in DNS cache
 *   file|C:\bad.exe|true|File exists (size: 1234 bytes)
 *   port|4444|true|Listening (pid 5678)
 *
 * Platform support:
 *   Windows — GetExtendedTcpTable/GetExtendedUdpTable, DnsGetCacheDataTable,
 *             GetFileAttributesExA
 *   Linux   — /proc/net/tcp, /proc/net/tcp6, /etc/hosts, stat()
 *   macOS   — libproc via agents/shared/macos_socket_walk.hpp, file system APIs
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <iphlpapi.h>
#include <windns.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#include <cstring>
#include <sys/stat.h>
#elif defined(__APPLE__)
#include <arpa/inet.h>
#include <cstring>
#include <sys/stat.h>
#include <macos_socket_walk.hpp>
#endif

namespace {

// ── String utilities ─────────────────────────────────────────────────────────

/// Split a comma-separated string into trimmed tokens.
std::vector<std::string> split_csv(std::string_view input) {
    std::vector<std::string> tokens;
    if (input.empty())
        return tokens;

    size_t start = 0;
    while (start < input.size()) {
        auto end = input.find(',', start);
        if (end == std::string_view::npos)
            end = input.size();

        auto token = input.substr(start, end - start);
        // Trim whitespace
        auto first = token.find_first_not_of(" \t\r\n");
        if (first != std::string_view::npos) {
            auto last = token.find_last_not_of(" \t\r\n");
            tokens.emplace_back(token.substr(first, last - first + 1));
        }
        start = end + 1;
    }
    return tokens;
}

/// Case-insensitive string equality.
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

/// Escape pipe characters in output values.
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

// ── Active connection record ─────────────────────────────────────────────────

struct ConnectionInfo {
    std::string local_addr;
    uint16_t local_port{};
    std::string remote_addr;
    uint16_t remote_port{};
    std::string state;
    uint32_t pid{};
};

// ── Connection enumeration ───────────────────────────────────────────────────

#ifdef _WIN32

std::vector<ConnectionInfo> get_connections() {
    std::vector<ConnectionInfo> conns;

    // --- TCP v4 ---
    {
        ULONG size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size > 0) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                                    0) == NO_ERROR) {
                auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    auto& row = table->table[i];
                    char local_buf[INET_ADDRSTRLEN]{};
                    char remote_buf[INET_ADDRSTRLEN]{};
                    struct in_addr la{}, ra{};
                    la.S_un.S_addr = row.dwLocalAddr;
                    ra.S_un.S_addr = row.dwRemoteAddr;
                    inet_ntop(AF_INET, &la, local_buf, sizeof(local_buf));
                    inet_ntop(AF_INET, &ra, remote_buf, sizeof(remote_buf));

                    std::string state_str;
                    switch (row.dwState) {
                    case MIB_TCP_STATE_LISTEN:
                        state_str = "LISTEN";
                        break;
                    case MIB_TCP_STATE_ESTAB:
                        state_str = "ESTABLISHED";
                        break;
                    case MIB_TCP_STATE_TIME_WAIT:
                        state_str = "TIME_WAIT";
                        break;
                    default:
                        state_str = "OTHER";
                        break;
                    }

                    conns.push_back({local_buf, ntohs(static_cast<uint16_t>(row.dwLocalPort)),
                                     remote_buf, ntohs(static_cast<uint16_t>(row.dwRemotePort)),
                                     std::move(state_str), row.dwOwningPid});
                }
            }
        }
    }

    // --- TCP v6 ---
    {
        ULONG size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size > 0) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL,
                                    0) == NO_ERROR) {
                auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    auto& row = table->table[i];
                    char local_buf[INET6_ADDRSTRLEN]{};
                    char remote_buf[INET6_ADDRSTRLEN]{};
                    inet_ntop(AF_INET6, &row.ucLocalAddr, local_buf, sizeof(local_buf));
                    inet_ntop(AF_INET6, &row.ucRemoteAddr, remote_buf, sizeof(remote_buf));

                    std::string state_str;
                    switch (row.dwState) {
                    case MIB_TCP_STATE_LISTEN:
                        state_str = "LISTEN";
                        break;
                    case MIB_TCP_STATE_ESTAB:
                        state_str = "ESTABLISHED";
                        break;
                    case MIB_TCP_STATE_TIME_WAIT:
                        state_str = "TIME_WAIT";
                        break;
                    default:
                        state_str = "OTHER";
                        break;
                    }

                    conns.push_back({local_buf, ntohs(static_cast<uint16_t>(row.dwLocalPort)),
                                     remote_buf, ntohs(static_cast<uint16_t>(row.dwRemotePort)),
                                     std::move(state_str), row.dwOwningPid});
                }
            }
        }
    }

    // --- UDP v4 ---
    {
        ULONG size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (size > 0) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) ==
                NO_ERROR) {
                auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    auto& row = table->table[i];
                    char local_buf[INET_ADDRSTRLEN]{};
                    struct in_addr la{};
                    la.S_un.S_addr = row.dwLocalAddr;
                    inet_ntop(AF_INET, &la, local_buf, sizeof(local_buf));

                    conns.push_back({local_buf, ntohs(static_cast<uint16_t>(row.dwLocalPort)), "*",
                                     0, "LISTEN", row.dwOwningPid});
                }
            }
        }
    }

    return conns;
}

#elif defined(__linux__)

/// Parse a hex IPv4 address from /proc/net/tcp format.
std::string parse_proc_ipv4(std::string_view hex_addr) {
    uint32_t addr = 0;
    std::from_chars(hex_addr.data(), hex_addr.data() + hex_addr.size(), addr, 16);
    struct in_addr in{};
    std::memcpy(&in, &addr, sizeof(addr));
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

/// Parse a hex IPv6 address from /proc/net/tcp6 format.
std::string parse_proc_ipv6(std::string_view hex_addr) {
    if (hex_addr.size() != 32)
        return "::";
    uint8_t bytes[16]{};
    // /proc stores each 32-bit word in host byte order
    for (int word = 0; word < 4; ++word) {
        for (int b = 0; b < 4; ++b) {
            auto offset = static_cast<size_t>(word * 8 + (3 - b) * 2);
            unsigned val = 0;
            std::from_chars(hex_addr.data() + offset, hex_addr.data() + offset + 2, val, 16);
            bytes[word * 4 + b] = static_cast<uint8_t>(val);
        }
    }
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, bytes, buf, sizeof(buf));
    return buf;
}

/// Parse hex port from /proc/net format.
uint16_t parse_proc_port(std::string_view hex_port) {
    unsigned val = 0;
    std::from_chars(hex_port.data(), hex_port.data() + hex_port.size(), val, 16);
    return static_cast<uint16_t>(val);
}

constexpr std::string_view tcp_state_str(int st) noexcept {
    switch (st) {
    case 0x0A:
        return "LISTEN";
    case 0x01:
        return "ESTABLISHED";
    case 0x06:
        return "TIME_WAIT";
    case 0x08:
        return "CLOSE_WAIT";
    default:
        return "OTHER";
    }
}

/// Parse /proc/net/tcp or /proc/net/tcp6 into connections.
void parse_proc_net(const char* path, bool ipv6, std::vector<ConnectionInfo>& conns) {
    std::ifstream f(path);
    if (!f.is_open())
        return;

    std::string line;
    std::getline(f, line); // skip header

    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string idx, local, remote, state_hex, tx_rx, tr_tm, retrnsmt, uid_str, timeout_str,
            inode_str;
        // Fields: sl local_address rem_address st tx_queue:rx_queue tr:tm->when
        //         retrnsmt uid timeout inode ...
        ss >> idx >> local >> remote >> state_hex;

        // Parse local address:port
        auto local_sep = local.find(':');
        auto remote_sep = remote.find(':');
        if (local_sep == std::string::npos || remote_sep == std::string::npos)
            continue;

        std::string local_addr = ipv6 ? parse_proc_ipv6(local.substr(0, local_sep))
                                      : parse_proc_ipv4(local.substr(0, local_sep));
        uint16_t local_port = parse_proc_port(local.substr(local_sep + 1));

        std::string remote_addr = ipv6 ? parse_proc_ipv6(remote.substr(0, remote_sep))
                                       : parse_proc_ipv4(remote.substr(0, remote_sep));
        uint16_t remote_port = parse_proc_port(remote.substr(remote_sep + 1));

        int state_val = 0;
        std::from_chars(state_hex.data(), state_hex.data() + state_hex.size(), state_val, 16);

        // Skip remaining fields to get uid (field 7, 0-indexed after idx)
        ss >> tx_rx >> tr_tm >> retrnsmt >> uid_str >> timeout_str >> inode_str;

        conns.push_back({
            std::move(local_addr), local_port, std::move(remote_addr), remote_port,
            std::string(tcp_state_str(state_val)),
            0 // PID not easily available from /proc/net/tcp
        });
    }
}

std::vector<ConnectionInfo> get_connections() {
    std::vector<ConnectionInfo> conns;
    parse_proc_net("/proc/net/tcp", false, conns);
    parse_proc_net("/proc/net/tcp6", true, conns);
    return conns;
}

#elif defined(__APPLE__)

std::vector<ConnectionInfo> get_connections() {
    std::vector<ConnectionInfo> conns;
    conns.reserve(32);

    for (const auto& s : yuzu::shared::walk_sockets(/*dedup=*/true)) {
        // TCP/TCP6 keep their real state; UDP is connectionless and carries no
        // meaningful state, so it stays empty (the walk's own convention) —
        // never a fabricated "LISTEN" the old lsof-parsing fallback used.
        conns.push_back({s.local_addr, s.local_port, s.remote_addr, s.remote_port, s.state,
                         static_cast<uint32_t>(s.pid)});
    }
    return conns;
}

#else

std::vector<ConnectionInfo> get_connections() {
    return {};
}

#endif

// ── DNS cache check (Windows-only) ──────────────────────────────────────────

#ifdef _WIN32

/// Opaque structure returned by DnsGetCacheDataTable (undocumented but stable).
struct DNS_CACHE_ENTRY {
    DNS_CACHE_ENTRY* pNext;
    PWSTR pszName;
    WORD wType;
    WORD wDataLength;
    DWORD dwFlags;
};

using DnsGetCacheDataTableFn = BOOL(WINAPI*)(DNS_CACHE_ENTRY**);

/// Query the Windows DNS resolver cache for a domain name.
bool check_dns_cache(std::string_view domain) {
    static auto fn = []() -> DnsGetCacheDataTableFn {
        HMODULE mod = LoadLibraryA("dnsapi.dll");
        if (!mod)
            return nullptr;
        return reinterpret_cast<DnsGetCacheDataTableFn>(
            GetProcAddress(mod, "DnsGetCacheDataTable"));
    }();

    if (!fn)
        return false;

    DNS_CACHE_ENTRY* head = nullptr;
    if (!fn(&head))
        return false;

    // Convert search domain to wide string for comparison
    // (#1681) shared size-based convert (NUL-excluded), identical to the prior inline;
    // empty/untranslatable -> {} preserves the old wide_len<=0 early-return.
    std::wstring wide_domain = yuzu::win::to_wide(domain);
    if (wide_domain.empty())
        return false;

    bool found = false;
    for (auto* entry = head; entry != nullptr; entry = entry->pNext) {
        if (entry->pszName && _wcsicmp(entry->pszName, wide_domain.c_str()) == 0) {
            found = true;
            break;
        }
    }

    return found;
}

#endif // _WIN32

// ── File existence and size check ────────────────────────────────────────────

struct FileCheckResult {
    bool exists{};
    uint64_t size{};
};

FileCheckResult check_file_path(std::string_view path) {
    std::error_code ec;
    auto status = std::filesystem::status(std::filesystem::path(path), ec);
    if (ec || !std::filesystem::exists(status)) {
        return {false, 0};
    }
    auto fsize = std::filesystem::file_size(std::filesystem::path(path), ec);
    if (ec)
        fsize = 0;
    return {true, fsize};
}

// ── SHA-256 file hash computation ────────────────────────────────────────────
//
// Minimal SHA-256 implementation for file hashing. This avoids pulling in
// OpenSSL or platform crypto just for one hash function in the plugin.

struct Sha256 {
    static constexpr std::array<uint32_t, 64> kK = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};

    uint32_t h_[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t block_[64]{};
    size_t block_len_{};
    uint64_t total_len_{};

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t gam0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t gam1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void process_block() {
        uint32_t w[64]{};
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block_[i * 4]) << 24) |
                   (static_cast<uint32_t>(block_[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block_[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block_[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = gam1(w[i - 2]) + w[i - 7] + gam0(w[i - 15]) + w[i - 16];
        }
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + sig1(e) + ch(e, f, g) + kK[i] + w[i];
            uint32_t t2 = sig0(a) + maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += hh;
    }

    void update(const uint8_t* data, size_t len) {
        total_len_ += len;
        for (size_t i = 0; i < len; ++i) {
            block_[block_len_++] = data[i];
            if (block_len_ == 64) {
                process_block();
                block_len_ = 0;
            }
        }
    }

    std::string finalize() {
        uint64_t bits = total_len_ * 8;
        block_[block_len_++] = 0x80;
        if (block_len_ > 56) {
            while (block_len_ < 64)
                block_[block_len_++] = 0;
            process_block();
            block_len_ = 0;
        }
        while (block_len_ < 56)
            block_[block_len_++] = 0;
        for (int i = 7; i >= 0; --i) {
            block_[block_len_++] = static_cast<uint8_t>(bits >> (i * 8));
        }
        process_block();

        std::string hex;
        hex.reserve(64);
        for (int i = 0; i < 8; ++i) {
            hex += std::format("{:08x}", h_[i]);
        }
        return hex;
    }
};

/// Compute SHA-256 hash of a file. Returns empty string on failure.
std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return {};

    Sha256 hasher;
    std::array<uint8_t, 8192> buf{};
    while (f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size())) ||
           f.gcount() > 0) {
        hasher.update(buf.data(), static_cast<size_t>(f.gcount()));
    }
    return hasher.finalize();
}

// ── IOC check implementations ────────────────────────────────────────────────

void check_ip_addresses(yuzu::CommandContext& ctx, const std::vector<std::string>& ips,
                        const std::vector<ConnectionInfo>& conns) {
    for (const auto& ip : ips) {
        bool found = false;
        std::string detail;

        for (const auto& conn : conns) {
            if (conn.remote_addr == ip || conn.local_addr == ip) {
                found = true;
                // conn.state is empty for UDP (connectionless — no fabricated "LISTEN");
                // drop the " - " separator rather than render a bare trailing dash.
                std::string state_suffix = conn.state.empty() ? std::string{} : " - " + conn.state;
                if (conn.pid > 0) {
                    detail = std::format("Active connection{} (pid {})", state_suffix, conn.pid);
                } else {
                    detail = std::format("Active connection{}", state_suffix);
                }
                break;
            }
        }

        if (!found)
            detail = "Not found in active connections";

        ctx.write_output(std::format("ip|{}|{}|{}", escape_pipes(ip), found ? "true" : "false",
                                     escape_pipes(detail)));
    }
}

void check_domains(yuzu::CommandContext& ctx, const std::vector<std::string>& domains) {
    for (const auto& domain : domains) {
#ifdef _WIN32
        bool found = check_dns_cache(domain);
        std::string detail = found ? "Found in DNS resolver cache" : "Not in DNS cache";
        ctx.write_output(std::format("domain|{}|{}|{}", escape_pipes(domain),
                                     found ? "true" : "false", escape_pipes(detail)));
#else
        // On Linux/macOS, DNS caching varies widely (systemd-resolved,
        // dnsmasq, mDNSResponder). Check /etc/hosts as a basic fallback.
        bool found = false;
        std::string detail;
        std::ifstream hosts("/etc/hosts");
        if (hosts.is_open()) {
            std::string line;
            while (std::getline(hosts, line)) {
                // Skip comments
                auto pos = line.find('#');
                if (pos != std::string::npos)
                    line = line.substr(0, pos);
                if (line.find(domain) != std::string::npos) {
                    found = true;
                    detail = "Found in /etc/hosts";
                    break;
                }
            }
        }
        if (!found)
            detail = "Not found in /etc/hosts (DNS cache not available)";

        ctx.write_output(std::format("domain|{}|{}|{}", escape_pipes(domain),
                                     found ? "true" : "false", escape_pipes(detail)));
#endif
    }
}

void check_file_hashes(yuzu::CommandContext& ctx, const std::vector<std::string>& hashes,
                       const std::vector<std::string>& search_paths) {
    // Build a set of paths to scan. If file_paths were provided, hash those.
    // Otherwise report that no target files were specified for hash matching.
    if (search_paths.empty()) {
        for (const auto& hash : hashes) {
            ctx.write_output(
                std::format("hash|{}|false|No target file paths specified for hash comparison",
                            escape_pipes(hash)));
        }
        return;
    }

    // Hash each target file and compare against the IOC hash list
    for (const auto& hash : hashes) {
        bool matched = false;
        std::string detail;

        // Normalize the search hash to lowercase
        std::string search_hash = hash;
        std::transform(search_hash.begin(), search_hash.end(), search_hash.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        for (const auto& path : search_paths) {
            auto file_hash = sha256_file(std::filesystem::path(path));
            if (file_hash.empty())
                continue;

            if (file_hash == search_hash) {
                matched = true;
                detail = std::format("Hash match in: {}", path);
                break;
            }
        }

        if (!matched)
            detail = "No matching files found";

        ctx.write_output(std::format("hash|{}|{}|{}", escape_pipes(hash),
                                     matched ? "true" : "false", escape_pipes(detail)));
    }
}

void check_file_paths(yuzu::CommandContext& ctx, const std::vector<std::string>& paths) {
    for (const auto& path : paths) {
        auto result = check_file_path(path);
        std::string detail;
        if (result.exists) {
            detail = std::format("File exists (size: {} bytes)", result.size);
        } else {
            detail = "File not found";
        }

        ctx.write_output(std::format("file|{}|{}|{}", escape_pipes(path),
                                     result.exists ? "true" : "false", escape_pipes(detail)));
    }
}

void check_ports(yuzu::CommandContext& ctx, const std::vector<std::string>& ports,
                 const std::vector<ConnectionInfo>& conns) {
    for (const auto& port_str : ports) {
        uint16_t target_port = 0;
        [[maybe_unused]] auto [ptr, ec] =
            std::from_chars(port_str.data(), port_str.data() + port_str.size(), target_port);
        if (ec != std::errc{}) {
            ctx.write_output(
                std::format("port|{}|false|Invalid port number", escape_pipes(port_str)));
            continue;
        }

        bool found = false;
        std::string detail;

        for (const auto& conn : conns) {
            // UDP rows carry an empty state (never a fabricated "LISTEN" — see
            // get_connections()/walk_sockets()): UDP is connectionless, so a row's mere
            // presence here already means a process is bound to that local port, the same
            // fact "LISTEN" records for TCP. Treat empty state as a match for that reason,
            // not as a wildcard — every other state string (TIME_WAIT, CLOSE_WAIT, ...)
            // still correctly fails to match.
            if (conn.local_port == target_port &&
                (conn.state.empty() || iequals(conn.state, "LISTEN") ||
                 iequals(conn.state, "ESTABLISHED"))) {
                found = true;
                if (conn.pid > 0) {
                    detail = std::format("Listening (pid {})", conn.pid);
                } else if (!conn.state.empty()) {
                    detail = std::format("{} on {}", conn.state, conn.local_addr);
                } else {
                    detail = std::format("Bound on {}", conn.local_addr);
                }
                break;
            }
        }

        if (!found)
            detail = "No listening service on this port";

        ctx.write_output(std::format("port|{}|{}|{}", escape_pipes(port_str),
                                     found ? "true" : "false", escape_pipes(detail)));
    }
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: GetExtendedTcpTable/GetExtendedUdpTable + DnsGetCacheDataTable +
// GetFileAttributesEx-family filesystem calls -- native Win32 APIs, rung 1.
// linux: /proc/net/tcp[6] parsing + /etc/hosts read + stat()-based
// filesystem checks -- native kernel-published surfaces, rung 1.
// macos: connection enumeration walks libproc via
// agents/shared/macos_socket_walk.hpp; domain/file checks stay native --
// rung 1 throughout.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"check",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 1, "procfs", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_SUPPORTED, 1, "libproc",
      "UDP rows carry an empty state (no fabricated \"LISTEN\") — a real UDP listener still "
      "matches a port check, but its detail text differs from a TCP match; a port shared by "
      "more than one process (SO_REUSEPORT, prefork) reports the pid of one arbitrarily-chosen "
      "owner in its match detail, not every owner"},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "iphlpapi_dnsapi", nullptr}},
};

} // namespace

// ── Plugin class ─────────────────────────────────────────────────────────────

class IocPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "ioc"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Indicator of Compromise checking — match IOCs against local endpoint state";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"check", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                [[maybe_unused]] yuzu::Params params) override {

        if (action != "check") {
            ctx.write_output(std::format("unknown action: {}", action));
            return 1;
        }

        ctx.report_progress(0);

        // Parse parameters
        auto ip_list = split_csv(params.get("ip_addresses"));
        auto domain_list = split_csv(params.get("domains"));
        auto hash_list = split_csv(params.get("file_hashes"));
        auto path_list = split_csv(params.get("file_paths"));
        auto port_list = split_csv(params.get("ports"));

        if (ip_list.empty() && domain_list.empty() && hash_list.empty() && path_list.empty() &&
            port_list.empty()) {
            ctx.write_output("error|none|false|No IOC parameters provided");
            return 1;
        }

        // Output header
        ctx.write_output("type|value|matched|detail");

        // Fetch connections once (shared by IP and port checks)
        std::vector<ConnectionInfo> conns;
        if (!ip_list.empty() || !port_list.empty()) {
            conns = get_connections();
        }

        ctx.report_progress(10);

        // Check IP addresses
        if (!ip_list.empty()) {
            check_ip_addresses(ctx, ip_list, conns);
        }
        ctx.report_progress(30);

        // Check domains (Windows: DNS cache; Linux/macOS: /etc/hosts)
        if (!domain_list.empty()) {
            check_domains(ctx, domain_list);
        }
        ctx.report_progress(50);

        // Check file hashes
        if (!hash_list.empty()) {
            check_file_hashes(ctx, hash_list, path_list);
        }
        ctx.report_progress(70);

        // Check file paths
        if (!path_list.empty()) {
            check_file_paths(ctx, path_list);
        }
        ctx.report_progress(90);

        // Check ports
        if (!port_list.empty()) {
            check_ports(ctx, port_list, conns);
        }
        ctx.report_progress(100);

        return 0;
    }
};

YUZU_PLUGIN_EXPORT(IocPlugin)
