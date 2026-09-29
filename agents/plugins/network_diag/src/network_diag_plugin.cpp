/**
 * network_diag_plugin.cpp — Network diagnostics plugin for Yuzu
 *
 * Actions:
 *   "listening"   — List listening TCP ports.
 *   "connections"  — List established TCP connections.
 *
 * Output is pipe-delimited via write_output().
 *
 * Platform support:
 *   Linux   — /proc/net/tcp[6]
 *   macOS   — libproc via agents/shared/macos_socket_walk.hpp (rung 1)
 *   Windows — IP Helper API (GetExtendedTcpTable)
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <sstream>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <cstdlib>
#include <fstream>
#include <vector>
#endif

#ifdef __APPLE__
#include <macos_socket_walk.hpp>
#endif

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
#include <iphlpapi.h>
#include <vector>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

namespace {

#ifdef _WIN32

void list_listening_win(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER,
                            0) != NO_ERROR)
        return;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        struct in_addr addr{};
        addr.S_un.S_addr = row.dwLocalAddr;
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        auto port = ntohs(static_cast<u_short>(row.dwLocalPort));
        ctx.write_output(std::format("listen|tcp|{}|{}|{}", ip, port, row.dwOwningPid));
    }
}

void list_connections_win(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS,
                            0) != NO_ERROR)
        return;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB)
            continue;

        struct in_addr la{}, ra{};
        la.S_un.S_addr = row.dwLocalAddr;
        ra.S_un.S_addr = row.dwRemoteAddr;
        char lip[INET_ADDRSTRLEN]{}, rip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &la, lip, sizeof(lip));
        inet_ntop(AF_INET, &ra, rip, sizeof(rip));
        auto lport = ntohs(static_cast<u_short>(row.dwLocalPort));
        auto rport = ntohs(static_cast<u_short>(row.dwRemotePort));
        ctx.write_output(
            std::format("conn|tcp|{}|{}|{}|{}|{}", lip, lport, rip, rport, row.dwOwningPid));
    }
}

#elif defined(__linux__)

std::string hex_to_ip(const std::string& hex_addr) {
    if (hex_addr.length() == 8) {
        // IPv4
        unsigned long addr = std::strtoul(hex_addr.c_str(), nullptr, 16);
        return std::format("{}.{}.{}.{}", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
                           (addr >> 24) & 0xFF);
    }
    // IPv6 — simplified: return hex representation
    return hex_addr;
}

void parse_proc_tcp(yuzu::CommandContext& ctx, const char* path, const std::string& target_state,
                    bool is_listen) {
    std::ifstream f(path);
    if (!f.is_open())
        return;
    std::string line;
    std::getline(f, line); // skip header
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string idx, local, remote, state_hex;
        iss >> idx >> local >> remote >> state_hex;
        if (state_hex != target_state)
            continue;

        auto colon1 = local.find(':');
        auto colon2 = remote.find(':');
        if (colon1 == std::string::npos || colon2 == std::string::npos)
            continue;

        auto local_ip = hex_to_ip(local.substr(0, colon1));
        auto local_port = std::strtoul(local.substr(colon1 + 1).c_str(), nullptr, 16);
        auto remote_ip = hex_to_ip(remote.substr(0, colon2));
        auto remote_port = std::strtoul(remote.substr(colon2 + 1).c_str(), nullptr, 16);

        // Parse remaining fields to get inode (field 10 from start, 7 more after state)
        std::string tmp;
        // Fields after state: tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout, inode
        for (int i = 0; i < 6; ++i)
            iss >> tmp;
        std::string inode;
        iss >> inode;

        if (is_listen) {
            ctx.write_output(std::format("listen|tcp|{}|{}|{}", local_ip, local_port, inode));
        } else {
            ctx.write_output(std::format("conn|tcp|{}|{}|{}|{}|{}", local_ip, local_port, remote_ip,
                                         remote_port, inode));
        }
    }
}

#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// One action, native in-process on every platform: Windows reads the IP
// Helper API natively, Linux reads /proc/net/tcp[6] directly, macOS walks
// libproc via agents/shared/macos_socket_walk.hpp — zero subprocesses
// anywhere (rung 1).
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "listening",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/net/tcp[6]", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libproc",
         "a socket shared by more than one process (SO_REUSEPORT, prefork) surfaces under one "
         "arbitrarily-chosen owning PID, not one row per owner"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetExtendedTcpTable", nullptr},
    },
    {
        /* .action      = */ "connections",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/net/tcp[6]", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libproc",
         "a socket shared by more than one process (SO_REUSEPORT, prefork) surfaces under one "
         "arbitrarily-chosen owning PID, not one row per owner"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetExtendedTcpTable", nullptr},
    },
};

} // namespace

class NetworkDiagPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "network_diag"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Network diagnostics — listening ports and established connections";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"listening", "connections", nullptr};
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

        if (action == "listening") {
#ifdef _WIN32
            list_listening_win(ctx);
#elif defined(__linux__)
            parse_proc_tcp(ctx, "/proc/net/tcp", "0A", true);
            parse_proc_tcp(ctx, "/proc/net/tcp6", "0A", true);
#elif defined(__APPLE__)
            for (const auto& s : yuzu::shared::walk_sockets(/*dedup=*/true)) {
                if ((s.proto != "tcp" && s.proto != "tcp6") || s.state != "LISTEN")
                    continue;
                // lsof rendered an unbound wildcard address as "*" — preserve that
                // for byte-identical output against the pre-migration format.
                std::string addr =
                    (s.local_addr == "0.0.0.0" || s.local_addr == "::") ? "*" : s.local_addr;
                ctx.write_output(std::format("listen|tcp|{}|{}|{}", addr, s.local_port, s.pid));
            }
#endif
            return 0;
        }

        if (action == "connections") {
#ifdef _WIN32
            list_connections_win(ctx);
#elif defined(__linux__)
            parse_proc_tcp(ctx, "/proc/net/tcp", "01", false);
            parse_proc_tcp(ctx, "/proc/net/tcp6", "01", false);
#elif defined(__APPLE__)
            for (const auto& s : yuzu::shared::walk_sockets(/*dedup=*/true)) {
                if ((s.proto != "tcp" && s.proto != "tcp6") || s.state != "ESTABLISHED")
                    continue;
                ctx.write_output(std::format("conn|tcp|{}|{}|{}|{}|{}", s.local_addr, s.local_port,
                                             s.remote_addr, s.remote_port, s.pid));
            }
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(NetworkDiagPlugin)
