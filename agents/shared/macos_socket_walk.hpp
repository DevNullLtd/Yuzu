/**
 * macos_socket_walk.hpp — shared macOS socket enumeration (libproc walk).
 *
 * Hoisted from netstat_plugin.cpp's macOS enumerate_and_stream() — the
 * canonical, most complete copy of this walk in the tree (proc_listallpids +
 * proc_pidinfo(PROC_PIDLISTFDS) + proc_pidfdinfo(PROC_PIDFDSOCKETINFO), with
 * a fork-dedup step keyed on proto:local_addr:local_port:remote_addr:
 * remote_port) — so network_diag and ioc can migrate off their `lsof`
 * shell-outs onto rung 1 (ADR-3002) without a third hand-rolled copy.
 *
 * netstat_plugin.cpp and tar_network_collector.cpp's macOS enumerators now
 * both consume this header directly (#3403 dedupe, PR3.1-b) — the former
 * inline copies are gone, so this is the single macOS socket-walk
 * implementation in the tree. sockwho_plugin.cpp's own copy was retired
 * along with the plugin (folded into netstat's `attribution` action).
 *
 * resolve_proc_name_path() is sourced from the retired sockwho_plugin.cpp's
 * macOS proc_name/proc_pidpath pair (same ignore-return-value convention as
 * the source: a zero-initialized buffer that libproc left untouched reads as
 * "unresolved", not as an error to propagate).
 */
#pragma once

#ifdef __APPLE__

#include <arpa/inet.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::shared {

struct SocketInfo {
    pid_t pid{};
    std::string proto; // "tcp" | "tcp6" | "udp" | "udp6"
    std::string local_addr;
    uint16_t local_port{};
    std::string remote_addr;
    uint16_t remote_port{};
    std::string state; // TCP state name; empty for UDP (no meaningful state — never a
                        // fabricated "LISTEN")
};

namespace detail {

constexpr std::string_view socket_walk_tcp_state(int st) noexcept {
    // TSI_S_* constants from <netinet/tcp_fsm.h> (included via sys/proc_info.h)
    switch (st) {
    case 0:
        return "CLOSED";
    case 1:
        return "LISTEN";
    case 2:
        return "SYN_SENT";
    case 3:
        return "SYN_RECV";
    case 4:
        return "ESTABLISHED";
    case 5:
        return "CLOSE_WAIT";
    case 6:
        return "FIN_WAIT1";
    case 7:
        return "CLOSING";
    case 8:
        return "LAST_ACK";
    case 9:
        return "FIN_WAIT2";
    case 10:
        return "TIME_WAIT";
    default:
        return "UNKNOWN";
    }
}

inline std::string socket_walk_addr4(const struct in_addr& addr) {
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

inline std::string socket_walk_addr6(const struct in6_addr& addr) {
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return buf;
}

} // namespace detail

/**
 * Enumerate active TCP/UDP sockets on the host via libproc. When `dedup` is
 * true, a socket that appears under multiple PIDs (post-fork fd sharing)
 * collapses to one row, keyed on proto+local_addr+local_port+remote_addr+
 * remote_port (first PID encountered wins) — matches netstat_plugin.cpp's
 * existing behaviour. When false, every (pid, fd) hit is emitted, including
 * duplicates. Empty on failure (no processes enumerable).
 */
inline std::vector<SocketInfo> walk_sockets(bool dedup) {
    std::vector<SocketInfo> out;

    int pid_count = proc_listallpids(nullptr, 0);
    if (pid_count <= 0)
        return out;

    std::vector<pid_t> pids(static_cast<size_t>(pid_count) * 2); // over-allocate
    pid_count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
    if (pid_count <= 0)
        return out;
    pids.resize(static_cast<size_t>(pid_count));

    std::unordered_map<std::string, bool> seen;

    for (pid_t pid : pids) {
        int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (buf_size <= 0)
            continue;

        auto fd_count = static_cast<size_t>(buf_size) / sizeof(struct proc_fdinfo);
        std::vector<struct proc_fdinfo> fds(fd_count);
        int actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(),
                                  static_cast<int>(fds.size() * sizeof(struct proc_fdinfo)));
        if (actual <= 0)
            continue;
        fd_count = static_cast<size_t>(actual) / sizeof(struct proc_fdinfo);

        for (size_t i = 0; i < fd_count; ++i) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;

            struct socket_fdinfo si{};
            int si_size =
                proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
            if (si_size < static_cast<int>(sizeof(si)))
                continue;

            int family = si.psi.soi_family;
            if (family != AF_INET && family != AF_INET6)
                continue;

            int kind = si.psi.soi_kind;
            bool is_tcp = (kind == SOCKINFO_TCP);
            bool is_udp = (kind == SOCKINFO_IN);
            if (!is_tcp && !is_udp)
                continue;

            SocketInfo info;
            info.pid = pid;

            if (is_tcp) {
                auto& tcp = si.psi.soi_proto.pri_tcp;
                info.state = std::string(detail::socket_walk_tcp_state(tcp.tcpsi_state));

                if (family == AF_INET) {
                    info.proto = "tcp";
                    info.local_addr =
                        detail::socket_walk_addr4(tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4);
                    info.remote_addr =
                        detail::socket_walk_addr4(tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4);
                } else {
                    info.proto = "tcp6";
                    info.local_addr = detail::socket_walk_addr6(tcp.tcpsi_ini.insi_laddr.ina_6);
                    info.remote_addr = detail::socket_walk_addr6(tcp.tcpsi_ini.insi_faddr.ina_6);
                }
                info.local_port = ntohs(static_cast<uint16_t>(tcp.tcpsi_ini.insi_lport));
                info.remote_port = ntohs(static_cast<uint16_t>(tcp.tcpsi_ini.insi_fport));
            } else {
                auto& inp = si.psi.soi_proto.pri_in;
                // UDP is connectionless — info.state stays empty (default-constructed),
                // never a fabricated "LISTEN".
                if (family == AF_INET) {
                    info.proto = "udp";
                    info.local_addr = detail::socket_walk_addr4(inp.insi_laddr.ina_46.i46a_addr4);
                    info.remote_addr = "*";
                } else {
                    info.proto = "udp6";
                    info.local_addr = detail::socket_walk_addr6(inp.insi_laddr.ina_6);
                    info.remote_addr = "*";
                }
                info.local_port = ntohs(static_cast<uint16_t>(inp.insi_lport));
                info.remote_port = 0;
            }

            if (dedup) {
                auto key = info.proto + ":" + info.local_addr + ":" +
                           std::to_string(info.local_port) + ":" + info.remote_addr + ":" +
                           std::to_string(info.remote_port);
                if (seen.contains(key))
                    continue;
                seen.emplace(std::move(key), true);
            }

            out.push_back(std::move(info));
        }
    }

    return out;
}

/**
 * Resolve a PID's process name (16-char-truncated, from proc_name) and full
 * on-disk executable path (from proc_pidpath). Returns nullopt when libproc
 * resolves neither (permission denied, PID already exited) — never an
 * ambiguous pair of empty strings a caller might mistake for a real, empty
 * process identity.
 */
inline std::optional<std::pair<std::string, std::string>> resolve_proc_name_path(pid_t pid) {
    char name_buf[PROC_PIDPATHINFO_MAXSIZE]{};
    proc_name(pid, name_buf, sizeof(name_buf));
    std::string pname(name_buf);

    char path_buf[PROC_PIDPATHINFO_MAXSIZE]{};
    proc_pidpath(pid, path_buf, sizeof(path_buf));
    std::string ppath(path_buf);

    if (pname.empty() && ppath.empty())
        return std::nullopt;
    return std::make_pair(std::move(pname), std::move(ppath));
}

} // namespace yuzu::shared

#endif // __APPLE__
