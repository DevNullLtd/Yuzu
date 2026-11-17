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
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
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

// After the platform headers: local_path_policy.hpp pulls <windows.h> on Windows, which must follow
// <winsock2.h> (included above).
#include <bounded_file_hash.hpp> // regular-file-only, capped, deadline-bounded SHA-256 (F36)
#include <local_path_policy.hpp> // refuse UNC / device / network-mount paths before any open (F36/F65)

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
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
    bool refused{}; ///< the path was a network/device path and was never touched
    std::string refusal;
};

// A path is judged lexically BEFORE any filesystem call (F65): a UNC path makes a LocalSystem
// agent authenticate to the named host, and a path under a network mount can pin the worker on a
// dead server. A refused path is reported as refused (never as "not found": that would read as a
// clean absence) and the caller's path text is not echoed into the reason.
FileCheckResult check_file_path(std::string_view path) {
    if (const auto refusal = yuzu::shared::local_path::local_path_refusal(path);
        yuzu::shared::local_path::refused(refusal)) {
        return {false, 0, true, std::string{yuzu::shared::local_path::refusal_token(refusal)}};
    }
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
// A file named by the operator is hashed only if it is a REGULAR file, at most kMaxHashFileBytes
// long, within a wall-clock deadline (F36): the previous unbounded std::ifstream read blocked a
// command worker forever on a FIFO or device node and read arbitrarily large files. POSIX opens
// the leaf no-follow and non-blocking and fstats the DESCRIPTOR; Windows has already refused
// UNC/device/non-fixed-drive paths (check_file_path / hash_target's caller) and checks the file
// type and size before opening.
constexpr std::uint64_t kMaxHashFileBytes = 512ull * 1024 * 1024; // 512 MiB
constexpr std::size_t kMaxFilePaths = 64;
constexpr std::size_t kMaxFileHashes = 256;
constexpr auto kHashDeadline = std::chrono::seconds(60); // one budget for the whole action

yuzu::shared::BoundedHash hash_target(const std::filesystem::path& path,
                                      yuzu::shared::HashClock::time_point deadline) {
#ifndef _WIN32
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0)
        return {yuzu::shared::HashStatus::unreadable, {}};
    struct FdCloser {
        int fd;
        ~FdCloser() { ::close(fd); }
    } closer{fd};
    return yuzu::shared::hash_fd_regular(fd, kMaxHashFileBytes, deadline);
#else
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec)
        return {yuzu::shared::HashStatus::not_regular, {}};
    const auto size = std::filesystem::file_size(path, ec);
    if (ec)
        return {yuzu::shared::HashStatus::unreadable, {}};
    if (size > kMaxHashFileBytes)
        return {yuzu::shared::HashStatus::oversize, {}};
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return {yuzu::shared::HashStatus::unreadable, {}};
    return yuzu::shared::hash_stream_bounded(
        [&f](unsigned char* buf, std::size_t len) -> long long {
            f.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(len));
            if (f.bad())
                return -1;
            return static_cast<long long>(f.gcount());
        },
        kMaxHashFileBytes, deadline);
#endif
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

    // Hash each target file ONCE (not once per IOC hash), within one shared deadline, then compare
    // every IOC hash against the results. A refused (network/device) path, a non-regular or
    // oversized file and a timeout leave the path unhashed; the rows say how many were skipped
    // so "No matching files found" is never read as "every path was checked".
    const auto deadline = yuzu::shared::HashClock::now() + kHashDeadline;
    std::unordered_map<std::string, std::string> hash_of_path; // path -> sha256 (hashed only)
    std::size_t not_hashed = 0;
    for (const auto& path : search_paths) {
        if (hash_of_path.contains(path))
            continue;
        if (yuzu::shared::local_path::refused(yuzu::shared::local_path::local_path_refusal(path))) {
            ++not_hashed;
            continue;
        }
        auto r = hash_target(std::filesystem::path(path), deadline);
        if (r.status == yuzu::shared::HashStatus::ok)
            hash_of_path.emplace(path, std::move(r.hex));
        else
            ++not_hashed;
    }

    for (const auto& hash : hashes) {
        bool matched = false;
        std::string detail;

        // Normalize the search hash to lowercase
        std::string search_hash = hash;
        std::transform(search_hash.begin(), search_hash.end(), search_hash.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        for (const auto& path : search_paths) {
            const auto it = hash_of_path.find(path);
            if (it == hash_of_path.end())
                continue;
            if (it->second == search_hash) {
                matched = true;
                detail = std::format("Hash match in: {}", path);
                break;
            }
        }

        if (!matched) {
            detail = not_hashed == 0
                         ? std::string{"No matching files found"}
                         : std::format("No matching files found ({} path(s) not hashed: refused, "
                                       "not a regular file, too large or unreadable)",
                                       not_hashed);
        }

        ctx.write_output(std::format("hash|{}|{}|{}", escape_pipes(hash),
                                     matched ? "true" : "false", escape_pipes(detail)));
    }
}

void check_file_paths(yuzu::CommandContext& ctx, const std::vector<std::string>& paths) {
    for (const auto& path : paths) {
        auto result = check_file_path(path);
        std::string detail;
        if (result.refused) {
            detail = result.refusal;
        } else if (result.exists) {
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

        // Bound the file work an operator parameter can request (F36): each path is stat'ed and,
        // with file_hashes, read; each hash is compared against every path.
        if (path_list.size() > kMaxFilePaths || hash_list.size() > kMaxFileHashes) {
            ctx.write_output(std::format(
                "error|none|false|Too many file_paths ({}, max {}) or file_hashes ({}, max {})",
                path_list.size(), kMaxFilePaths, hash_list.size(), kMaxFileHashes));
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
