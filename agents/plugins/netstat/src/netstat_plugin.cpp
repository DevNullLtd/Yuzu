/**
 * netstat_plugin.cpp — Network connection enumeration plugin for Yuzu
 *
 * Actions:
 *   "netstat_list" — Enumerates active TCP/UDP connections and listening
 *                    sockets on the host, returning protocol, addresses,
 *                    ports, state, and owning PID.
 *   "attribution"  — Same enumeration, plus the owning process's name and
 *                    executable path (formerly the standalone `sockwho`
 *                    plugin, folded in here — #3403/roadmap D2). Emits
 *                    netstat_list's 7 columns as a prefix with
 *                    process_name/process_path appended (9 total); pid
 *                    stays in its netstat_list position (6th field after
 *                    proto), NOT sockwho's old 1st-column layout.
 *
 * Output is pipe-delimited, one connection per line via write_output():
 *   netstat_list: proto|local_addr|local_port|remote_addr|remote_port|state|pid
 *   attribution:  proto|local_addr|local_port|remote_addr|remote_port|state|pid|process_name|process_path
 *
 * Platform support:
 *   Linux   — /proc/net/{tcp,tcp6,udp,udp6} + /proc/[pid]/fd inode mapping
 *             (attribution additionally reads /proc/[pid]/{comm,exe})
 *   macOS   — libproc, via the shared agents/shared/macos_socket_walk.hpp
 *             walk (also used by network_diag/ioc; #3403 dedupe)
 *   Windows — IP Helper API (GetExtendedTcpTable, GetExtendedUdpTable)
 *             (attribution additionally resolves owning process via
 *             QueryFullProcessImageNameW, cached per PID)
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef __linux__
#include <arpa/inet.h>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <unistd.h>
#elif defined(__APPLE__)
#include <arpa/inet.h>

#include <macos_socket_walk.hpp> // shared libproc socket walk (#3403)
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

#include "netstat_parsers.hpp" // yuzu::netstat::escape_pipes -- pure, unit-tested (test_netstat_parsers.cpp)

namespace {

using yuzu::netstat::escape_pipes;

// -- Linux implementation -----------------------------------------------------
#ifdef __linux__

constexpr std::string_view tcp_state_str(int st) noexcept {
    switch (st) {
    case 0x01:
        return "ESTABLISHED";
    case 0x02:
        return "SYN_SENT";
    case 0x03:
        return "SYN_RECV";
    case 0x04:
        return "FIN_WAIT1";
    case 0x05:
        return "FIN_WAIT2";
    case 0x06:
        return "TIME_WAIT";
    case 0x07:
        return "CLOSE";
    case 0x08:
        return "CLOSE_WAIT";
    case 0x09:
        return "LAST_ACK";
    case 0x0A:
        return "LISTEN";
    case 0x0B:
        return "CLOSING";
    default:
        return "UNKNOWN";
    }
}

std::string parse_ipv4(std::string_view hex_addr) {
    uint32_t addr = 0;
    std::from_chars(hex_addr.data(), hex_addr.data() + hex_addr.size(), addr, 16);
    struct in_addr in{};
    std::memcpy(&in, &addr, sizeof(addr));
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

std::string parse_ipv6(std::string_view hex_addr) {
    struct in6_addr in6{};
    // Kernel prints four 32-bit words in host byte order, 8 hex chars each
    for (int i = 0; i < 4; ++i) {
        auto chunk = hex_addr.substr(static_cast<size_t>(i) * 8, 8);
        uint32_t word = 0;
        std::from_chars(chunk.data(), chunk.data() + chunk.size(), word, 16);
        std::memcpy(&in6.s6_addr[i * 4], &word, sizeof(word));
    }
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
    return buf;
}

uint16_t parse_hex_port(std::string_view hex) {
    unsigned int port = 0;
    std::from_chars(hex.data(), hex.data() + hex.size(), port, 16);
    return static_cast<uint16_t>(port);
}

// Scan /proc/[pid]/fd/ symlinks to build inode → PID mapping.
//
// Both DIR* streams are RAII-owned, same idiom as build_socket_and_proc_maps()
// below (adversarial-review gate-2 finding, #3403): allocating work
// (std::format, std::string construction, map insertion) runs between
// opendir() and the matching closedir(), so an exception there would
// otherwise skip the manual cleanup and leak the fd for the life of the
// agent (CLAUDE.md's non-RAII-manual-cleanup floor). This function predates
// that fix and was found to still carry the same raw opendir()/closedir()
// shape during this branch's governance gate-3 cpp-safety review -- fixed
// here to match its sibling rather than leaving one of the two /proc
// walkers unRAII'd in the same file.
std::unordered_map<uint64_t, int> build_inode_to_pid_map() {
    std::unordered_map<uint64_t, int> map;

    const std::unique_ptr<DIR, int (*)(DIR*)> proc_dir{opendir("/proc"), &closedir};
    if (!proc_dir)
        return map;

    struct dirent* proc_entry = nullptr;
    while ((proc_entry = readdir(proc_dir.get())) != nullptr) {
        int pid = 0;
        [[maybe_unused]] auto [ptr, ec] = std::from_chars(proc_entry->d_name,
                                         proc_entry->d_name + std::strlen(proc_entry->d_name), pid);
        if (ec != std::errc{} || pid <= 0)
            continue;

        std::string fd_path = std::format("/proc/{}/fd", pid);
        const std::unique_ptr<DIR, int (*)(DIR*)> fd_dir{opendir(fd_path.c_str()), &closedir};
        if (!fd_dir)
            continue;

        char link_buf[128];
        struct dirent* fd_entry = nullptr;
        while ((fd_entry = readdir(fd_dir.get())) != nullptr) {
            if (fd_entry->d_name[0] == '.')
                continue;

            std::string link_path = std::format("{}/{}", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path.c_str(), link_buf, sizeof(link_buf) - 1);
            if (len <= 0)
                continue;
            link_buf[len] = '\0';

            // Match "socket:[12345]"
            std::string_view sv(link_buf, static_cast<size_t>(len));
            if (!sv.starts_with("socket:["))
                continue;
            auto inode_sv = sv.substr(8, sv.size() - 9); // strip "socket:[" and "]"
            uint64_t inode = 0;
            std::from_chars(inode_sv.data(), inode_sv.data() + inode_sv.size(), inode);
            if (inode > 0)
                map.emplace(inode, pid);
        }
    }
    return map;
}

void parse_proc_net_file(const char* path, std::string_view proto,
                         const std::unordered_map<uint64_t, int>& inode_map,
                         yuzu::CommandContext& ctx, bool is_tcp, bool is_ipv6) {
    std::ifstream f(path);
    if (!f)
        return;

    std::string line;
    std::getline(f, line); // skip header

    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string sl, local, remote, state_hex;
        // Columns: sl local_address rem_address st ...
        if (!(iss >> sl >> local >> remote >> state_hex))
            continue;

        // Parse local address:port
        auto colon = local.rfind(':');
        if (colon == std::string::npos)
            continue;
        std::string local_addr = is_ipv6 ? parse_ipv6(std::string_view(local).substr(0, colon))
                                         : parse_ipv4(std::string_view(local).substr(0, colon));
        uint16_t local_port = parse_hex_port(std::string_view(local).substr(colon + 1));

        // Parse remote address:port
        auto rcolon = remote.rfind(':');
        if (rcolon == std::string::npos)
            continue;
        std::string remote_addr = is_ipv6 ? parse_ipv6(std::string_view(remote).substr(0, rcolon))
                                          : parse_ipv4(std::string_view(remote).substr(0, rcolon));
        uint16_t remote_port = parse_hex_port(std::string_view(remote).substr(rcolon + 1));

        // Parse state
        int state_val = 0;
        std::from_chars(state_hex.data(), state_hex.data() + state_hex.size(), state_val, 16);
        std::string_view state = is_tcp ? tcp_state_str(state_val) : std::string_view{};

        // Skip remaining columns to get to inode (column index 9, 0-based)
        std::string tok;
        // Already consumed 4 tokens (sl, local, remote, state).
        // Need to skip 5 more: tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout
        for (int i = 0; i < 5 && (iss >> tok); ++i) {}
        uint64_t inode = 0;
        if (iss >> inode) { /* got inode */
        }

        int pid = -1;
        if (inode > 0) {
            auto it = inode_map.find(inode);
            if (it != inode_map.end())
                pid = it->second;
        }

        ctx.write_output(std::format("{}|{}|{}|{}|{}|{}|{}", proto, local_addr, local_port,
                                     remote_addr, remote_port, state, pid));
    }
}

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    auto inode_map = build_inode_to_pid_map();

    parse_proc_net_file("/proc/net/tcp", "tcp", inode_map, ctx, true, false);
    parse_proc_net_file("/proc/net/tcp6", "tcp6", inode_map, ctx, true, true);
    parse_proc_net_file("/proc/net/udp", "udp", inode_map, ctx, false, false);
    parse_proc_net_file("/proc/net/udp6", "udp6", inode_map, ctx, false, true);
}

// -- attribution: /proc inode→pid + pid→process enrichment (ex-sockwho) -----

struct ProcInfo {
    std::string name;
    std::string path;
};

// Build two maps in a single /proc scan: inode → PID (socket resolution) and
// PID → ProcInfo (process name/path). Ported from sockwho_plugin.cpp's
// build_maps() — sockwho is retired, this is now netstat's own attribution
// enrichment path.
//
// Both DIR* streams are RAII-owned (adversarial-review gate-2 finding,
// #3403): allocating work (std::format, std::string construction, map
// insertion) runs between opendir() and the matching closedir(), so an
// exception there would previously skip the manual cleanup and leak the fd
// for the life of the agent (CLAUDE.md's non-RAII-manual-cleanup floor).
// Same idiom as tar_proc_perf.cpp's read_proc_counters().
void build_socket_and_proc_maps(std::unordered_map<uint64_t, int>& inode_map,
                                std::unordered_map<int, ProcInfo>& proc_map) {
    const std::unique_ptr<DIR, int (*)(DIR*)> proc_dir{opendir("/proc"), &closedir};
    if (!proc_dir)
        return;

    struct dirent* proc_entry = nullptr;
    while ((proc_entry = readdir(proc_dir.get())) != nullptr) {
        int pid = 0;
        [[maybe_unused]] auto [ptr, ec] = std::from_chars(proc_entry->d_name,
                                         proc_entry->d_name + std::strlen(proc_entry->d_name), pid);
        if (ec != std::errc{} || pid <= 0)
            continue;

        std::string proc_path = std::format("/proc/{}", pid);

        ProcInfo info;
        {
            std::ifstream comm_f(proc_path + "/comm");
            std::getline(comm_f, info.name);
        }
        {
            char link_buf[4096];
            ssize_t len =
                readlink((proc_path + "/exe").c_str(), link_buf, sizeof(link_buf) - 1);
            if (len > 0)
                info.path.assign(link_buf, static_cast<size_t>(len));
        }
        if (!info.name.empty())
            proc_map.emplace(pid, std::move(info));

        std::string fd_path = proc_path + "/fd";
        const std::unique_ptr<DIR, int (*)(DIR*)> fd_dir{opendir(fd_path.c_str()), &closedir};
        if (!fd_dir)
            continue;

        char link_buf[128];
        struct dirent* fd_entry = nullptr;
        while ((fd_entry = readdir(fd_dir.get())) != nullptr) {
            if (fd_entry->d_name[0] == '.')
                continue;
            std::string link_path = std::format("{}/{}", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path.c_str(), link_buf, sizeof(link_buf) - 1);
            if (len <= 0)
                continue;
            link_buf[len] = '\0';

            std::string_view sv(link_buf, static_cast<size_t>(len));
            if (!sv.starts_with("socket:["))
                continue;
            auto inode_sv = sv.substr(8, sv.size() - 9);
            uint64_t inode = 0;
            std::from_chars(inode_sv.data(), inode_sv.data() + inode_sv.size(), inode);
            if (inode > 0)
                inode_map.emplace(inode, pid);
        }
    }
}

void parse_proc_net_file_attributed(const char* path, std::string_view proto,
                                    const std::unordered_map<uint64_t, int>& inode_map,
                                    const std::unordered_map<int, ProcInfo>& proc_map,
                                    yuzu::CommandContext& ctx, bool is_tcp, bool is_ipv6) {
    std::ifstream f(path);
    if (!f)
        return;

    std::string line;
    std::getline(f, line); // skip header

    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string sl, local, remote, state_hex;
        if (!(iss >> sl >> local >> remote >> state_hex))
            continue;

        auto colon = local.rfind(':');
        if (colon == std::string::npos)
            continue;
        std::string local_addr = is_ipv6 ? parse_ipv6(std::string_view(local).substr(0, colon))
                                         : parse_ipv4(std::string_view(local).substr(0, colon));
        uint16_t local_port = parse_hex_port(std::string_view(local).substr(colon + 1));

        auto rcolon = remote.rfind(':');
        if (rcolon == std::string::npos)
            continue;
        std::string remote_addr = is_ipv6 ? parse_ipv6(std::string_view(remote).substr(0, rcolon))
                                          : parse_ipv4(std::string_view(remote).substr(0, rcolon));
        uint16_t remote_port = parse_hex_port(std::string_view(remote).substr(rcolon + 1));

        int state_val = 0;
        std::from_chars(state_hex.data(), state_hex.data() + state_hex.size(), state_val, 16);
        std::string_view state = is_tcp ? tcp_state_str(state_val) : std::string_view{};

        std::string tok;
        for (int i = 0; i < 5 && (iss >> tok); ++i) {}
        uint64_t inode = 0;
        if (iss >> inode) { /* got inode */
        }

        int pid = -1;
        std::string_view pname, ppath;
        if (inode > 0) {
            auto it = inode_map.find(inode);
            if (it != inode_map.end()) {
                pid = it->second;
                auto pit = proc_map.find(pid);
                if (pit != proc_map.end()) {
                    pname = pit->second.name;
                    ppath = pit->second.path;
                }
            }
        }

        ctx.write_output(std::format("{}|{}|{}|{}|{}|{}|{}|{}|{}", proto, local_addr, local_port,
                                     remote_addr, remote_port, state, pid, escape_pipes(pname),
                                     escape_pipes(ppath)));
    }
}

void enumerate_and_stream_attribution(yuzu::CommandContext& ctx) {
    std::unordered_map<uint64_t, int> inode_map;
    std::unordered_map<int, ProcInfo> proc_map;
    build_socket_and_proc_maps(inode_map, proc_map);

    parse_proc_net_file_attributed("/proc/net/tcp", "tcp", inode_map, proc_map, ctx, true, false);
    parse_proc_net_file_attributed("/proc/net/tcp6", "tcp6", inode_map, proc_map, ctx, true, true);
    parse_proc_net_file_attributed("/proc/net/udp", "udp", inode_map, proc_map, ctx, false, false);
    parse_proc_net_file_attributed("/proc/net/udp6", "udp6", inode_map, proc_map, ctx, false, true);
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

// netstat_list's own libproc walk now rides the shared header (#3403 dedupe)
// instead of an inline copy — byte-parity with the pre-migration output
// (dedup=true matches the removed inline walk's fork-dedup behaviour).
void enumerate_and_stream(yuzu::CommandContext& ctx) {
    for (const auto& s : yuzu::shared::walk_sockets(/*dedup=*/true)) {
        ctx.write_output(std::format("{}|{}|{}|{}|{}|{}|{}", s.proto, s.local_addr, s.local_port,
                                     s.remote_addr, s.remote_port, s.state,
                                     static_cast<int>(s.pid)));
    }
}

// attribution: the same shared walk, plus resolve_proc_name_path() per row
// (sourced from sockwho_plugin.cpp originally — see macos_socket_walk.hpp's
// file comment; sockwho itself is retired).
//
// dedup=true is deliberate here, not a leftover from copying
// enumerate_and_stream() above: it collapses a fork-shared socket (multiple
// processes holding the same fd) to a single owner row, intentionally
// matching netstat_list's dedup semantics (#3403) so the two actions agree
// on what "one socket" means. This differs from the retired sockwho
// plugin, which emitted one row per (pid,fd) — i.e. one row per holder of a
// shared socket, not one row per socket. That per-(pid,fd) shape was not
// preserved on purpose; do not "fix" this back to dedup=false to restore it.
void enumerate_and_stream_attribution(yuzu::CommandContext& ctx) {
    for (const auto& s : yuzu::shared::walk_sockets(/*dedup=*/true)) {
        std::string pname, ppath;
        if (auto resolved = yuzu::shared::resolve_proc_name_path(s.pid)) {
            pname = std::move(resolved->first);
            ppath = std::move(resolved->second);
        }
        ctx.write_output(std::format("{}|{}|{}|{}|{}|{}|{}|{}|{}", s.proto, s.local_addr,
                                     s.local_port, s.remote_addr, s.remote_port, s.state,
                                     static_cast<int>(s.pid), escape_pipes(pname),
                                     escape_pipes(ppath)));
    }
}

// -- Windows implementation ---------------------------------------------------
#elif defined(_WIN32)

constexpr std::string_view tcp_state_str_win(DWORD st) noexcept {
    switch (st) {
    case 1:
        return "CLOSED";
    case 2:
        return "LISTEN";
    case 3:
        return "SYN_SENT";
    case 4:
        return "SYN_RECV";
    case 5:
        return "ESTABLISHED";
    case 6:
        return "FIN_WAIT1";
    case 7:
        return "FIN_WAIT2";
    case 8:
        return "CLOSE_WAIT";
    case 9:
        return "CLOSING";
    case 10:
        return "LAST_ACK";
    case 11:
        return "TIME_WAIT";
    case 12:
        return "DELETE_TCB";
    default:
        return "UNKNOWN";
    }
}

std::string format_addr4(DWORD addr) {
    struct in_addr in{};
    in.s_addr = addr; // already in network byte order
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

std::string format_addr6(const void* addr) {
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return buf;
}

void emit_tcp4(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret =
            GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        ctx.write_output(std::format(
            "tcp|{}|{}|{}|{}|{}|{}", format_addr4(row.dwLocalAddr),
            ntohs(static_cast<u_short>(row.dwLocalPort)), format_addr4(row.dwRemoteAddr),
            ntohs(static_cast<u_short>(row.dwRemotePort)), tcp_state_str_win(row.dwState),
            static_cast<int>(row.dwOwningPid)));
    }
}

void emit_tcp6(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret =
            GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        ctx.write_output(std::format(
            "tcp6|{}|{}|{}|{}|{}|{}", format_addr6(row.ucLocalAddr),
            ntohs(static_cast<u_short>(row.dwLocalPort)), format_addr6(row.ucRemoteAddr),
            ntohs(static_cast<u_short>(row.dwRemotePort)), tcp_state_str_win(row.dwState),
            static_cast<int>(row.dwOwningPid)));
    }
}

void emit_udp4(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        ctx.write_output(std::format("udp|{}|{}|*|0||{}", format_addr4(row.dwLocalAddr),
                                     ntohs(static_cast<u_short>(row.dwLocalPort)),
                                     static_cast<int>(row.dwOwningPid)));
    }
}

void emit_udp6(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        ctx.write_output(std::format("udp6|{}|{}|*|0||{}", format_addr6(row.ucLocalAddr),
                                     ntohs(static_cast<u_short>(row.dwLocalPort)),
                                     static_cast<int>(row.dwOwningPid)));
    }
}

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    emit_tcp4(ctx);
    emit_tcp6(ctx);
    emit_udp4(ctx);
    emit_udp6(ctx);
}

// -- attribution: QueryFullProcessImageNameW enrichment (ex-sockwho) --------

struct ProcInfo {
    std::string name;
    std::string path;
};

using yuzu::win::from_wide;

// Single-owner RAII for a process HANDLE: CloseHandle runs on every scope
// exit, including an exception from from_wide/substr between acquire and
// release (adversarial-review gate-2 finding, #3403 — the prior manual
// CloseHandle could skip it). Same shape as processes_plugin.cpp's
// HandleGuard.
struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    explicit operator bool() const noexcept { return h && h != INVALID_HANDLE_VALUE; }
};

ProcInfo get_proc_info(DWORD pid) {
    ProcInfo info;
    HandleGuard hg(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hg)
        return info;

    wchar_t path_buf[MAX_PATH];
    DWORD path_len = MAX_PATH;
    if (QueryFullProcessImageNameW(hg.h, 0, path_buf, &path_len)) {
        info.path = from_wide(path_buf);
        auto slash = info.path.rfind('\\');
        if (slash != std::string::npos)
            info.name = info.path.substr(slash + 1);
        else
            info.name = info.path;
    }
    return info; // ~HandleGuard closes the handle on every path
}

const ProcInfo& lookup_proc(DWORD pid, std::unordered_map<DWORD, ProcInfo>& cache) {
    auto it = cache.find(pid);
    if (it != cache.end())
        return it->second;
    auto [inserted, ok] = cache.emplace(pid, get_proc_info(pid));
    return inserted->second;
}

void emit_tcp4_attributed(yuzu::CommandContext& ctx, std::unordered_map<DWORD, ProcInfo>& cache) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret =
            GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        auto& proc = lookup_proc(row.dwOwningPid, cache);
        ctx.write_output(std::format(
            "tcp|{}|{}|{}|{}|{}|{}|{}|{}", format_addr4(row.dwLocalAddr),
            ntohs(static_cast<u_short>(row.dwLocalPort)), format_addr4(row.dwRemoteAddr),
            ntohs(static_cast<u_short>(row.dwRemotePort)), tcp_state_str_win(row.dwState),
            static_cast<int>(row.dwOwningPid), escape_pipes(proc.name), escape_pipes(proc.path)));
    }
}

void emit_tcp6_attributed(yuzu::CommandContext& ctx, std::unordered_map<DWORD, ProcInfo>& cache) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret =
            GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        auto& proc = lookup_proc(row.dwOwningPid, cache);
        ctx.write_output(std::format(
            "tcp6|{}|{}|{}|{}|{}|{}|{}|{}", format_addr6(row.ucLocalAddr),
            ntohs(static_cast<u_short>(row.dwLocalPort)), format_addr6(row.ucRemoteAddr),
            ntohs(static_cast<u_short>(row.dwRemotePort)), tcp_state_str_win(row.dwState),
            static_cast<int>(row.dwOwningPid), escape_pipes(proc.name), escape_pipes(proc.path)));
    }
}

void emit_udp4_attributed(yuzu::CommandContext& ctx, std::unordered_map<DWORD, ProcInfo>& cache) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        auto& proc = lookup_proc(row.dwOwningPid, cache);
        ctx.write_output(std::format("udp|{}|{}|*|0||{}|{}|{}", format_addr4(row.dwLocalAddr),
                                     ntohs(static_cast<u_short>(row.dwLocalPort)),
                                     static_cast<int>(row.dwOwningPid), escape_pipes(proc.name),
                                     escape_pipes(proc.path)));
    }
}

void emit_udp6_attributed(yuzu::CommandContext& ctx, std::unordered_map<DWORD, ProcInfo>& cache) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        auto& proc = lookup_proc(row.dwOwningPid, cache);
        ctx.write_output(std::format("udp6|{}|{}|*|0||{}|{}|{}", format_addr6(row.ucLocalAddr),
                                     ntohs(static_cast<u_short>(row.dwLocalPort)),
                                     static_cast<int>(row.dwOwningPid), escape_pipes(proc.name),
                                     escape_pipes(proc.path)));
    }
}

void enumerate_and_stream_attribution(yuzu::CommandContext& ctx) {
    std::unordered_map<DWORD, ProcInfo> cache;
    emit_tcp4_attributed(ctx, cache);
    emit_tcp6_attributed(ctx, cache);
    emit_udp4_attributed(ctx, cache);
    emit_udp6_attributed(ctx, cache);
}

#endif // platform

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Two actions, both native in-process on every platform: Linux reads
// /proc/net/{tcp,tcp6,udp,udp6} + /proc/[pid]/fd directly (attribution also
// /proc/[pid]/{comm,exe}), macOS uses libproc via the shared
// macos_socket_walk.hpp, Windows uses the IP Helper API (attribution also
// QueryFullProcessImageNameW) — zero subprocesses anywhere (rung 1).
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "netstat_list",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/net/{tcp,udp}[6]", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "libproc", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "GetExtendedTcpTable/GetExtendedUdpTable", nullptr},
    },
    {
        /* .action      = */ "attribution",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/proc/net/* + /proc/[pid]/{comm,exe,fd}", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "libproc", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IP Helper API + QueryFullProcessImageNameW", nullptr},
    },
};

} // namespace

class NetstatPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "netstat"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates active network connections and listening sockets";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"netstat_list", "attribution", nullptr};
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
                yuzu::Params /*params*/) override {
        if (action == "netstat_list") {
            return do_list(ctx);
        }
        if (action == "attribution") {
            return do_attribution(ctx);
        }
        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
        enumerate_and_stream(ctx);
        return 0;
#else
        ctx.write_output("error: network enumeration not supported on this platform");
        return 1;
#endif
    }

    int do_attribution(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
        enumerate_and_stream_attribution(ctx);
        return 0;
#else
        ctx.write_output("error: network enumeration not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(NetstatPlugin)
