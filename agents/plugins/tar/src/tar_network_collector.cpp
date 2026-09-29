/**
 * tar_network_collector.cpp -- Network connection enumeration for TAR plugin
 *
 * Enumerates active TCP/UDP connections and returns them as structured
 * NetConnection records for diff-based change detection.
 *
 * Platform support:
 *   Windows -- GetExtendedTcpTable + GetExtendedUdpTable (IP Helper API)
 *   Linux   -- /proc/net/{tcp,tcp6,udp,udp6} + /proc/[pid]/fd inode mapping
 *   macOS   -- libproc, via the shared agents/shared/macos_socket_walk.hpp
 *              walk (#3403 dedupe)
 */

#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <format>
#include <mutex>
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
// netqual (per-connection TCP_INFO via netlink SOCK_DIAG / INET_DIAG).
#include <algorithm>
#include <cerrno> // errno / EINTR in the recvmsg retry loop
#include <cstddef> // offsetof
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/tcp.h> // TCP_ESTABLISHED (NOT struct tcp_info — see linux_tcp_info.hpp)
#include <sys/socket.h>
#include <sys/time.h> // struct timeval (SO_RCVTIMEO)
// ABI-pinned tcp_info prefix — glibc 2.39's <netinet/tcp.h> lacks tcpi_segs_out
// and we can't add <linux/tcp.h> (it re-defines struct tcp_info, clashing with
// the <netinet/tcp.h> above that we need for TCP_ESTABLISHED).
#include "yuzu/agent/linux_tcp_info.hpp"
#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif
#elif defined(__APPLE__)
#include <macos_socket_walk.hpp> // shared libproc socket walk (#3403 dedupe)
// netqual (per-connection quality) + tcp lifecycle event stream (roadmap
// 2.2) — the plugin-owned NstatClient, reached via a registered pointer (see
// netqual_nstat_register_client in tar_collectors.hpp).
#include "tar_netqual_nstat.hpp"
#include <atomic>
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
// netqual (per-connection quality via TCP ESTATS — ADR-0020).
#include <tcpestats.h>
#include <atomic>
#include <cstring>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

// Need netdb.h for getnameinfo on POSIX (included via arpa/inet.h on some
// platforms but not all). Include it unconditionally for POSIX.
#if !defined(_WIN32)
#include <netdb.h>
#endif

namespace yuzu::tar {

// ── Reverse DNS resolution (all platforms) ──────────────────────────────────
//
// Resolved at collection time so TAR events store the hostname alongside the IP.
// Uses getnameinfo(NI_NAMEREQD) which performs a PTR lookup.
//
// Design:
//   - Result cache with TTL (1h positive, 5m negative). Avoids re-querying
//     the same IPs across successive TAR snapshots.
//   - Total time budget per snapshot (3 seconds). Once the budget is
//     exhausted, remaining uncached IPs get empty remote_host. This prevents
//     the TAR collector from stalling when many IPs have no PTR records
//     and the DNS server is slow.
//   - getnameinfo() is called synchronously (no std::async). The per-IP
//     cost is bounded by the system DNS resolver timeout (typically 5s on
//     Linux, configurable via resolv.conf). The total budget cap ensures
//     the aggregate cost is bounded regardless.
//   - Skip non-routable addresses: loopback, wildcard, link-local.

namespace {

constexpr int64_t kDnsPositiveTtlSeconds = 3600;   // 1 hour for resolved names
constexpr int64_t kDnsNegativeTtlSeconds = 300;     // 5 minutes for failed lookups
constexpr auto kDnsTotalBudget = std::chrono::seconds(3);

struct DnsCacheEntry {
    std::string host;     // empty = negative (no PTR record)
    int64_t expires_at;   // steady_clock seconds
};

std::mutex g_dns_cache_mtx;
std::unordered_map<std::string, DnsCacheEntry> g_dns_cache;

bool is_skip_address(const std::string& addr) {
    if (addr.empty() || addr == "*" || addr == "0.0.0.0" || addr == "::" ||
        addr == "127.0.0.1" || addr == "::1")
        return true;
    // Link-local: 169.254.x.x (IPv4), fe80::/10 (IPv6)
    if (addr.starts_with("169.254.") || addr.starts_with("fe80:"))
        return true;
    return false;
}

std::string getnameinfo_sync(const std::string& addr) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    struct addrinfo* ai = nullptr;
    if (getaddrinfo(addr.c_str(), nullptr, &hints, &ai) != 0 || !ai)
        return {};

    char host[NI_MAXHOST]{};
    int rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, host, sizeof(host),
                         nullptr, 0, NI_NAMEREQD);
    freeaddrinfo(ai);

    if (rc != 0)
        return {};
    return host;
}

int64_t steady_now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now().time_since_epoch())
               .count();
}

/// Resolve hostnames for a batch of connections, respecting the total
/// time budget. Connections are resolved in order; once the budget is
/// exhausted, remaining uncached IPs get empty remote_host.
void resolve_hostnames(std::vector<NetConnection>& connections) {
    auto deadline = std::chrono::steady_clock::now() + kDnsTotalBudget;

    for (auto& nc : connections) {
        if (is_skip_address(nc.remote_addr))
            continue;

        auto now = steady_now_seconds();

        // Check cache
        {
            std::lock_guard lock(g_dns_cache_mtx);
            auto it = g_dns_cache.find(nc.remote_addr);
            if (it != g_dns_cache.end() && it->second.expires_at > now) {
                nc.remote_host = it->second.host;
                continue;
            }
        }

        // Budget exhausted — skip remaining uncached IPs
        if (std::chrono::steady_clock::now() >= deadline) {
            spdlog::debug("TAR: DNS resolution budget exhausted, skipping remaining IPs");
            break;
        }

        // Synchronous resolve (bounded by system DNS timeout per IP,
        // aggregate bounded by kDnsTotalBudget)
        auto result = getnameinfo_sync(nc.remote_addr);

        // Cache with appropriate TTL
        int64_t ttl = result.empty() ? kDnsNegativeTtlSeconds : kDnsPositiveTtlSeconds;
        {
            std::lock_guard lock(g_dns_cache_mtx);
            g_dns_cache[nc.remote_addr] = DnsCacheEntry{result, steady_now_seconds() + ttl};
        }

        nc.remote_host = std::move(result);
    }
}

} // namespace

// -- Linux implementation -----------------------------------------------------
#ifdef __linux__

namespace {

constexpr std::string_view tcp_state_str(int st) noexcept {
    switch (st) {
    case 0x01: return "ESTABLISHED";
    case 0x02: return "SYN_SENT";
    case 0x03: return "SYN_RECV";
    case 0x04: return "FIN_WAIT1";
    case 0x05: return "FIN_WAIT2";
    case 0x06: return "TIME_WAIT";
    case 0x07: return "CLOSE";
    case 0x08: return "CLOSE_WAIT";
    case 0x09: return "LAST_ACK";
    case 0x0A: return "LISTEN";
    case 0x0B: return "CLOSING";
    default:   return "UNKNOWN";
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

std::unordered_map<uint64_t, uint32_t> build_inode_to_pid_map() {
    std::unordered_map<uint64_t, uint32_t> map;

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir)
        return map;

    struct dirent* proc_entry = nullptr;
    while ((proc_entry = readdir(proc_dir)) != nullptr) {
        int pid = 0;
        [[maybe_unused]] auto [ptr, ec] = std::from_chars(
            proc_entry->d_name,
            proc_entry->d_name + std::strlen(proc_entry->d_name), pid);
        if (ec != std::errc{} || pid <= 0)
            continue;

        std::string fd_path = std::format("/proc/{}/fd", pid);
        DIR* fd_dir = opendir(fd_path.c_str());
        if (!fd_dir)
            continue;

        char link_buf[128];
        struct dirent* fd_entry = nullptr;
        while ((fd_entry = readdir(fd_dir)) != nullptr) {
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
                map.emplace(inode, static_cast<uint32_t>(pid));
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
    return map;
}

void parse_proc_net_file(const char* path, std::string_view proto,
                         const std::unordered_map<uint64_t, uint32_t>& inode_map,
                         std::vector<NetConnection>& out, bool is_tcp, bool is_ipv6) {
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
        std::string local_addr = is_ipv6
            ? parse_ipv6(std::string_view(local).substr(0, colon))
            : parse_ipv4(std::string_view(local).substr(0, colon));
        uint16_t local_port = parse_hex_port(std::string_view(local).substr(colon + 1));

        auto rcolon = remote.rfind(':');
        if (rcolon == std::string::npos)
            continue;
        std::string remote_addr = is_ipv6
            ? parse_ipv6(std::string_view(remote).substr(0, rcolon))
            : parse_ipv4(std::string_view(remote).substr(0, rcolon));
        uint16_t remote_port = parse_hex_port(std::string_view(remote).substr(rcolon + 1));

        int state_val = 0;
        std::from_chars(state_hex.data(), state_hex.data() + state_hex.size(), state_val, 16);
        std::string state = is_tcp ? std::string{tcp_state_str(state_val)} : std::string{};

        // Skip remaining columns to get to inode (column index 9)
        std::string tok;
        for (int i = 0; i < 5 && (iss >> tok); ++i) {}
        uint64_t inode = 0;
        iss >> inode;

        uint32_t pid = 0;
        if (inode > 0) {
            auto it = inode_map.find(inode);
            if (it != inode_map.end())
                pid = it->second;
        }

        NetConnection nc;
        nc.proto = proto;
        nc.local_addr = std::move(local_addr);
        nc.local_port = local_port;
        nc.remote_addr = std::move(remote_addr);
        nc.remote_port = remote_port;
        nc.state = std::move(state);
        nc.pid = pid;
        out.push_back(std::move(nc));
    }
}

} // namespace

std::vector<NetConnection> enumerate_connections() {
    std::vector<NetConnection> result;
    auto inode_map = build_inode_to_pid_map();

    parse_proc_net_file("/proc/net/tcp",  "tcp",  inode_map, result, true,  false);
    parse_proc_net_file("/proc/net/tcp6", "tcp6", inode_map, result, true,  true);
    parse_proc_net_file("/proc/net/udp",  "udp",  inode_map, result, false, false);
    parse_proc_net_file("/proc/net/udp6", "udp6", inode_map, result, false, true);

    resolve_hostnames(result);
    return result;
}

// ── netqual: per-connection TCP_INFO via netlink INET_DIAG ────────────────────
// Mirrors the proven netlink mechanics in agents/core/src/net_quality_sampler.cpp
// (the same interface `ss -ti` uses — no packet capture, no CAP_NET_ADMIN), but
// extracts the per-connection 4-tuple + socket inode (→ owning process) rather
// than rolling up to a device aggregate. Bounded by SO_RCVTIMEO so a stalled
// dump degrades to a partial sample, never a hung collector.
namespace {

/// RAII owner for the netlink socket fd (no leak on any return).
struct NetlinkFd {
    int fd{-1};
    explicit NetlinkFd(int f) : fd(f) {}
    ~NetlinkFd() {
        if (fd >= 0)
            ::close(fd);
    }
    NetlinkFd(const NetlinkFd&) = delete;
    NetlinkFd& operator=(const NetlinkFd&) = delete;
};

bool nq_send_dump(int fd, uint8_t family) {
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } msg{};
    msg.nlh.nlmsg_len = sizeof(msg);
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.nlh.nlmsg_seq = family;
    msg.req.sdiag_family = family;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states = (1u << TCP_ESTABLISHED); // only conns with a live RTT
    msg.req.idiag_ext = (1u << (INET_DIAG_INFO - 1));
    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    struct iovec iov{&msg, sizeof(msg)};
    struct msghdr m{};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    return ::sendmsg(fd, &m, 0) > 0;
}

/// Owning-process image name from the socket inode's pid. /proc/[pid]/comm is
/// the image name only (kernel-truncated to 15 chars) — matches the procperf
/// "names only" privacy posture, never a command line. NOTE: unlike procperf's
/// parse_linux_pid_stat, the bytes are stored UNSANITIZED ('|'/control bytes
/// pass through) — same class as the process source's status Name:; hardening
/// all raw-comm consumers together is a tracked follow-up.
std::string nq_read_comm(uint32_t pid) {
    if (pid == 0)
        return {};
    std::ifstream f(std::format("/proc/{}/comm", pid));
    std::string name;
    std::getline(f, name);
    return name;
}

void nq_collect(int fd, uint8_t family,
                const std::unordered_map<uint64_t, uint32_t>& inode_pid,
                std::vector<TcpQualitySample>& out) {
    // alignas: the in-place nlmsghdr/inet_diag_msg/rtattr casts require
    // NLMSG_ALIGNTO alignment; tcp_info (8-aligned) is read via memcpy, not cast.
    alignas(NLMSG_ALIGNTO) char buf[16384];
    for (;;) {
        struct sockaddr_nl sa{};
        struct iovec iov{buf, sizeof(buf)};
        struct msghdr m{};
        m.msg_name = &sa;
        m.msg_namelen = sizeof(sa);
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd, &m, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return; // EAGAIN (SO_RCVTIMEO) or DONE — bounded, never wedged
        for (auto* h = reinterpret_cast<struct nlmsghdr*>(buf); NLMSG_OK(h, n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
                return;
            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY)
                continue;
            // Defence-in-depth: NLMSG_OK only guarantees the header fits, not the
            // inet_diag_msg body — a truncated/malformed message would tail-over-
            // read `diag` and make `rtalen` negative. Also discard any message left
            // over from the previous family's dump (a mid-dump SO_RCVTIMEO can leave
            // AF_INET replies queued when we send the AF_INET6 dump on the same
            // socket — they'd be misparsed as the wrong family).
            if (h->nlmsg_seq != family ||
                h->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
                continue;
            auto* diag = reinterpret_cast<struct inet_diag_msg*>(NLMSG_DATA(h));

            // Remote address (the connection's peer). inet_ntop is canonical, so
            // this matches the /proc-derived strings elsewhere.
            char ab[INET6_ADDRSTRLEN]{};
            std::string remote;
            if (family == AF_INET) {
                struct in_addr a{};
                std::memcpy(&a, &diag->id.idiag_dst[0], sizeof(a));
                if (inet_ntop(AF_INET, &a, ab, sizeof(ab)))
                    remote = ab;
            } else {
                struct in6_addr a6{};
                std::memcpy(&a6, diag->id.idiag_dst, sizeof(a6));
                if (inet_ntop(AF_INET6, &a6, ab, sizeof(ab)))
                    remote = ab;
            }

            // tcp_info attribute (defensive length check + memcpy into a local;
            // RTA_DATA is only 4-byte aligned but LinuxTcpInfo needs 8 — cast
            // would be alignment + strict-aliasing UB, memcpy moots both).
            int rtalen = static_cast<int>(h->nlmsg_len) -
                         static_cast<int>(NLMSG_LENGTH(sizeof(*diag)));
            auto* attr = reinterpret_cast<struct rtattr*>(diag + 1);
            yuzu::agent::LinuxTcpInfo ti{};
            bool have_info = false;
            for (; RTA_OK(attr, rtalen); attr = RTA_NEXT(attr, rtalen)) {
                if (attr->rta_type != INET_DIAG_INFO)
                    continue;
                if (RTA_PAYLOAD(attr) <
                    offsetof(yuzu::agent::LinuxTcpInfo, tcpi_segs_out) + sizeof(uint32_t))
                    continue;
                std::memcpy(&ti, RTA_DATA(attr),
                            std::min<std::size_t>(RTA_PAYLOAD(attr), sizeof ti));
                have_info = true;
            }
            if (!have_info)
                continue;

            TcpQualitySample s;
            s.proto = (family == AF_INET) ? "tcp" : "tcp6";
            s.remote_addr = std::move(remote);
            uint32_t pid = 0;
            if (auto it = inode_pid.find(diag->idiag_inode); it != inode_pid.end())
                pid = it->second;
            s.process_name = nq_read_comm(pid);
            s.rtt_us = ti.tcpi_rtt;
            s.rtt_var_us = ti.tcpi_rttvar;
            s.lost = ti.tcpi_lost;                 // instantaneous lost segments — gone within an RTT
            s.retrans = ti.tcpi_total_retrans;     // lifetime — context only
            s.segs_out = ti.tcpi_segs_out;         // lifetime — context / denominator
            s.ca_state = ti.tcpi_ca_state;         // 0=Open..4=Loss — holds across a recovery episode
            out.push_back(std::move(s));
        }
    }
}

} // namespace

std::vector<TcpQualitySample> collect_tcp_quality() {
    std::vector<TcpQualitySample> out;
    int raw = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (raw < 0)
        return out;
    NetlinkFd guard(raw);
    struct timeval tv{2, 0}; // 2 s — bound the recvmsg wait
    ::setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto inode_pid = build_inode_to_pid_map(); // inode → owning pid
    for (uint8_t fam : {AF_INET, AF_INET6})
        if (nq_send_dump(raw, fam))
            nq_collect(raw, fam, inode_pid, out);
    return out;
}

std::string_view netqual_effective_capture_method() { return "inetdiag"; }

// nstat (tar_netqual_nstat.hpp) is macOS-only; the plugin still calls
// netqual_nstat_register_client() unconditionally at init/shutdown (matching
// NstatClient's own "inert off-macOS" contract), so this TU needs a body on
// every platform it compiles for.
void netqual_nstat_register_client(NstatClient*) {}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

namespace {

// The plugin-owned NstatClient (roadmap 2.2), reached via
// netqual_nstat_register_client() — see tar_collectors.hpp for the ownership
// contract. Non-owning: set/cleared only by tar_plugin.cpp's init()/shutdown().
std::atomic<NstatClient*> g_nstat_client{nullptr};

} // namespace

void netqual_nstat_register_client(NstatClient* client) {
    g_nstat_client.store(client, std::memory_order_release);
}

// The libproc walk now rides the shared agents/shared/macos_socket_walk.hpp
// helper (#3403 dedupe, PR3.1-b) instead of an inline copy -- byte-parity
// with the pre-migration output (walk_sockets(dedup=true) matches the
// removed inline walk's fork-dedup behaviour: same key shape, first PID
// wins). Roadmap 2.2 makes nstat the PRIMARY tcp connection-lifecycle source
// when the plugin's NstatClient is running() and system_wide() -- that drain
// lives in tar_plugin.cpp's collect_fast tcp leg (mirrors the
// ES-stream-with-poll-fallback shape used for process_live), not here. This
// poll keeps its job unconditionally: it is the tcp lifecycle fallback/seed
// whenever nstat is not primary, the ONLY source for udp/udp6 (nstat's TCP
// provider has no UDP counterpart), and the full live snapshot
// fleet_snapshot reads directly.
std::vector<NetConnection> enumerate_connections() {
    std::vector<NetConnection> result;
    for (auto& s : yuzu::shared::walk_sockets(/*dedup=*/true)) {
        NetConnection nc;
        nc.proto = std::move(s.proto);
        nc.local_addr = std::move(s.local_addr);
        nc.local_port = s.local_port;
        nc.remote_addr = std::move(s.remote_addr);
        nc.remote_port = s.remote_port;
        nc.state = std::move(s.state);
        nc.pid = static_cast<uint32_t>(s.pid);
        result.push_back(std::move(nc));
    }

    resolve_hostnames(result);
    return result;
}

// netqual per-connection quality (roadmap 2.2): the plugin-owned NstatClient's
// live flow-table snapshot when it is running() AND system_wide() — an
// own-process-only session is real capture via nstat, just not COMPLETE
// capture, so it is deliberately withheld here rather than reported as a
// partial netqual sample (memo §3, "no silent partial capture"; mirrors the
// Windows ESTATS admin-only "records nothing" honesty at tar_netqual.hpp).
// {} when no client is registered (off, not yet started, or this build never
// wired one), the client isn't running (layout_mismatch or stop()ed), or it
// is scoped to own-process flows only.
std::vector<TcpQualitySample> collect_tcp_quality() {
    NstatClient* client = g_nstat_client.load(std::memory_order_acquire);
    // Also gate on !stalled() (UP-1): a reader that has gone silent past the
    // idle-fallback threshold is demoted to the poll for TCP lifecycle
    // (tar_plugin.cpp's nstat_primary includes !stalled()), so the quality
    // source must demote in lockstep rather than keep serving a stale snapshot.
    if (!client || !client->running() || !client->system_wide() || client->stalled())
        return {};
    return client->snapshot_quality();
}

// "nstat" only while the registered client is running(), system_wide(), has not
// self-failed to a layout_mismatch(), AND is not stalled() — running() already
// reflects a layout-mismatch shutdown (the reader thread stops itself), but the
// extra checks keep this honest even if that internal coupling changes. The
// !stalled() gate (UP-1) matches the lifecycle demotion: once the stream goes
// quiet past the idle threshold, the advertised method must fall to "none" in
// lockstep with the source, never advertise nstat while data comes from the
// poll. "none" in every other case: no client, not running, own-process scope,
// layout mismatch, or stalled — never a partial/misleading "nstat".
std::string_view netqual_effective_capture_method() {
    NstatClient* client = g_nstat_client.load(std::memory_order_acquire);
    if (client && client->running() && client->system_wide() && !client->layout_mismatch() &&
        !client->stalled())
        return "nstat";
    return "none";
}

// -- Windows implementation ---------------------------------------------------
#elif defined(_WIN32)

namespace {

constexpr std::string_view tcp_state_str_win(DWORD st) noexcept {
    switch (st) {
    case 1:  return "CLOSED";
    case 2:  return "LISTEN";
    case 3:  return "SYN_SENT";
    case 4:  return "SYN_RECV";
    case 5:  return "ESTABLISHED";
    case 6:  return "FIN_WAIT1";
    case 7:  return "FIN_WAIT2";
    case 8:  return "CLOSE_WAIT";
    case 9:  return "CLOSING";
    case 10: return "LAST_ACK";
    case 11: return "TIME_WAIT";
    case 12: return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

std::string format_win_addr4(DWORD addr) {
    struct in_addr in{};
    in.s_addr = addr;
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

std::string format_win_addr6(const void* addr) {
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return buf;
}

void collect_tcp4(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedTcpTable(buf.data(), &size, FALSE,
                                         AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
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
        NetConnection nc;
        nc.proto = "tcp";
        nc.local_addr = format_win_addr4(row.dwLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = format_win_addr4(row.dwRemoteAddr);
        nc.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        nc.state = tcp_state_str_win(row.dwState);
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

void collect_tcp6(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedTcpTable(buf.data(), &size, FALSE,
                                         AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
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
        NetConnection nc;
        nc.proto = "tcp6";
        nc.local_addr = format_win_addr6(row.ucLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = format_win_addr6(row.ucRemoteAddr);
        nc.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        nc.state = tcp_state_str_win(row.dwState);
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

void collect_udp4(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE,
                                         AF_INET, UDP_TABLE_OWNER_PID, 0);
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
        NetConnection nc;
        nc.proto = "udp";
        nc.local_addr = format_win_addr4(row.dwLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = "*";
        nc.remote_port = 0;
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

void collect_udp6(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE,
                                         AF_INET6, UDP_TABLE_OWNER_PID, 0);
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
        NetConnection nc;
        nc.proto = "udp6";
        nc.local_addr = format_win_addr6(row.ucLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = "*";
        nc.remote_port = 0;
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

// ── netqual: per-connection quality via TCP ESTATS (ADR-0020) ────────────────
// Extended stats are DISABLED per connection until SetPerTcp[6]ConnectionEStats
// enables them (admin-only; a non-elevated agent latches kDenied and netqual
// records nothing), and the ROD blocks are undefined until the Rw echo reads
// EnableCollection=TRUE. So the collector runs a two-tick protocol: enable +
// baseline-read on first sight, emit since-enable deltas on later ticks. Stats
// are NEVER disabled — since 1709 a disable can reset counters under other
// ESTATS consumers on the box (and vice versa: a foreign reset shows up here as
// a negative delta, which nq_delta_clamped degrades to 0 for one tick).

/// Per-tick bound on new Set...EStats enables, so a connection-storm tick costs
/// a bounded number of extra syscalls; the remainder enable on later ticks.
constexpr std::size_t kNetQualEnableCapPerTick = 128;
/// Bound on tracked connections (the per-tick emit cap is kNetQualTopN=50; this
/// is headroom so a degraded connection is found even on connection-heavy hosts).
constexpr std::size_t kNetQualMaxTracked = 2048;
/// If more than this many wall-clock seconds elapsed since the last sweep, every
/// surviving baseline is re-anchored (emits nothing this tick) instead of
/// differenced: a delta spanning a long gap — netqual disabled for hours, or the
/// host slept with connections surviving resume — would otherwise report the
/// whole gap's cumulative retransmits as ONE tick's `lost` (the current-loss
/// gauge) and sort those falsified rows to the top-N. Comfortably above the 60s
/// fast cadence, so a multi-minute gap means disable/sleep, not a slow tick.
/// Mirrors the #538 clean-baseline-on-re-enable contract Linux netqual gets for
/// free (it holds no cross-tick state).
constexpr std::int64_t kNetQualStaleSweepSeconds = 300;

/// Baseline + liveness state for one tracked connection.
struct NqTracked {
    NqWinCounters prev{};
    bool baselined{false}; // first successful ROD read happened; deltas valid
    uint64_t seen_tick{0};
};

std::mutex g_nq_mtx; // guards the statics below (collect_fast vs snapshot)
std::unordered_map<std::string, NqTracked> g_nq_tracked;
uint64_t g_nq_tick = 0;
std::int64_t g_nq_last_sweep_unix = 0; // wall-clock of the previous sweep (stale guard)

// Elevation gate: 0=unknown, 1=active, 2=denied. Token elevation is fixed for
// the process lifetime, so kDenied never re-arms (unlike the module ETW latch).
std::atomic<int> g_nq_gate{0};
constexpr int kNqGateActive = 1;
constexpr int kNqGateDenied = 2;

ULONG nq_set_estats(MIB_TCPROW& row, TCP_ESTATS_TYPE type, PUCHAR rw, ULONG rw_size) {
    return SetPerTcpConnectionEStats(&row, type, rw, 0, rw_size, 0);
}
ULONG nq_set_estats(MIB_TCP6ROW& row, TCP_ESTATS_TYPE type, PUCHAR rw, ULONG rw_size) {
    return SetPerTcp6ConnectionEStats(&row, type, rw, 0, rw_size, 0);
}
ULONG nq_get_estats(MIB_TCPROW& row, TCP_ESTATS_TYPE type, PUCHAR rw, ULONG rw_size, PUCHAR rod,
                    ULONG rod_size) {
    return GetPerTcpConnectionEStats(&row, type, rw, 0, rw_size, nullptr, 0, 0, rod, 0, rod_size);
}
ULONG nq_get_estats(MIB_TCP6ROW& row, TCP_ESTATS_TYPE type, PUCHAR rw, ULONG rw_size, PUCHAR rod,
                    ULONG rod_size) {
    return GetPerTcp6ConnectionEStats(&row, type, rw, 0, rw_size, nullptr, 0, 0, rod, 0, rod_size);
}

/// Enable Path + Data collection on one connection. ERROR_ACCESS_DENIED is the
/// caller's latch signal; any other failure just means this connection stays
/// un-baselined and is retried on a later tick.
template <typename Row>
ULONG nq_enable(Row& row) {
    TCP_ESTATS_PATH_RW_v0 path_rw{};
    path_rw.EnableCollection = TRUE;
    ULONG ret = nq_set_estats(row, TcpConnectionEstatsPath,
                              reinterpret_cast<PUCHAR>(&path_rw), sizeof(path_rw));
    if (ret != NO_ERROR)
        return ret;
    TCP_ESTATS_DATA_RW_v0 data_rw{};
    data_rw.EnableCollection = TRUE;
    return nq_set_estats(row, TcpConnectionEstatsData, reinterpret_cast<PUCHAR>(&data_rw),
                         sizeof(data_rw));
}

/// Read Path + Data RODs into plain counters. Returns NO_ERROR only when both
/// reads succeed AND both Rw echoes confirm collection is on — the RODs are
/// documented "meaningless random data" otherwise. ERROR_NOT_FOUND propagates
/// (connection closed between table read and here); a disabled Rw echo maps to
/// ERROR_INVALID_STATE so the caller re-enables.
template <typename Row>
ULONG nq_read(Row& row, NqWinCounters& out) {
    TCP_ESTATS_PATH_RW_v0 path_rw{};
    TCP_ESTATS_PATH_ROD_v0 path_rod{};
    ULONG ret = nq_get_estats(row, TcpConnectionEstatsPath, reinterpret_cast<PUCHAR>(&path_rw),
                              sizeof(path_rw), reinterpret_cast<PUCHAR>(&path_rod),
                              sizeof(path_rod));
    if (ret != NO_ERROR)
        return ret;
    TCP_ESTATS_DATA_RW_v0 data_rw{};
    TCP_ESTATS_DATA_ROD_v0 data_rod{};
    ret = nq_get_estats(row, TcpConnectionEstatsData, reinterpret_cast<PUCHAR>(&data_rw),
                        sizeof(data_rw), reinterpret_cast<PUCHAR>(&data_rod), sizeof(data_rod));
    if (ret != NO_ERROR)
        return ret;
    if (!path_rw.EnableCollection || !data_rw.EnableCollection)
        return ERROR_INVALID_STATE; // another consumer disabled us — re-enable

    out.smoothed_rtt_ms = path_rod.SmoothedRtt;
    out.rtt_var_ms = path_rod.RttVar;
    out.pkts_retrans = path_rod.PktsRetrans;
    out.timeouts = path_rod.Timeouts;
    out.fast_retran = path_rod.FastRetran;
    out.dup_acks_in = path_rod.DupAcksIn;
    out.ecn_signals = path_rod.EcnSignals;
    out.cur_timeout_count = path_rod.CurTimeoutCount;
    out.segs_out = static_cast<int64_t>(data_rod.SegsOut);
    return NO_ERROR;
}

/// Owning-process image basename from the connection's pid — same names-only
/// privacy posture as procperf (never a path, never a command line). Per-tick
/// cache: connection-heavy hosts share few distinct pids.
std::string nq_process_name(uint32_t pid, std::unordered_map<uint32_t, std::string>& cache) {
    if (pid == 0)
        return {};
    if (auto it = cache.find(pid); it != cache.end())
        return it->second;
    std::string name;
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        WCHAR path[MAX_PATH * 2];
        DWORD len = static_cast<DWORD>(std::size(path));
        if (::QueryFullProcessImageNameW(h, 0, path, &len)) {
            std::wstring_view wpath(path, len);
            const auto slash = wpath.find_last_of(L'\\');
            if (slash != std::wstring_view::npos)
                wpath.remove_prefix(slash + 1);
            name = yuzu::win::from_wide(wpath.data(), static_cast<int>(wpath.size()));
        }
        ::CloseHandle(h);
    }
    cache.emplace(pid, name);
    return name;
}

/// One connection's pass through the two-tick protocol. `enables` is the shared
/// per-tick Set budget. Returns false only on the ACCESS_DENIED latch signal.
template <typename Row>
bool nq_visit(Row& row, std::string key, const std::string& proto, std::string remote,
              uint32_t pid, std::size_t& enables,
              std::unordered_map<uint32_t, std::string>& name_cache,
              std::vector<TcpQualitySample>& out) {
    auto it = g_nq_tracked.find(key);
    if (it == g_nq_tracked.end()) {
        if (g_nq_tracked.size() >= kNetQualMaxTracked || enables >= kNetQualEnableCapPerTick)
            return true; // over budget — untracked this tick, retried later
        ++enables;
        const ULONG ret = nq_enable(row);
        if (ret == ERROR_ACCESS_DENIED)
            return false;
        if (ret != NO_ERROR)
            return true; // connection raced closed / transient — retry later
        NqTracked t;
        t.seen_tick = g_nq_tick;
        // Baseline read now: with a fresh enable the counters start ~0, but if
        // ANOTHER consumer already had stats on they are large — reading (not
        // assuming zero) keeps the first emitted delta honest either way.
        t.baselined = (nq_read(row, t.prev) == NO_ERROR);
        g_nq_tracked.emplace(std::move(key), std::move(t));
        return true; // enable tick emits nothing
    }

    it->second.seen_tick = g_nq_tick;
    NqWinCounters cur;
    const ULONG ret = nq_read(row, cur);
    if (ret == ERROR_NOT_FOUND) {
        g_nq_tracked.erase(it); // closed under us
        return true;
    }
    if (ret == ERROR_INVALID_STATE) {
        // Foreign disable: re-enable (budgeted) and re-baseline next tick.
        if (enables < kNetQualEnableCapPerTick) {
            ++enables;
            if (nq_enable(row) == ERROR_ACCESS_DENIED)
                return false;
        }
        it->second.baselined = false;
        return true;
    }
    if (ret != NO_ERROR)
        return true; // transient — keep baseline, skip this tick
    if (!it->second.baselined) {
        it->second.prev = cur; // first good read after (re-)enable — baseline only
        it->second.baselined = true;
        return true;
    }
    out.push_back(nq_win_build_sample(cur, it->second.prev, proto, std::move(remote),
                                      nq_process_name(pid, name_cache)));
    it->second.prev = cur;
    return true;
}

/// Fetch an OWNER_PID TCP table for `family`, retrying the documented
/// size-probe/fetch TOCTOU up to 3× on ERROR_INSUFFICIENT_BUFFER (the table can
/// grow between the size call and the fetch on a connection-churn host — the
/// same race the sibling collect_tcp4/6 loops guard). Returns true (buf filled,
/// possibly empty when the host has no connections of this family — a valid
/// result safe to prune against) or false (the family could NOT be read this
/// tick — the caller must skip pruning it, or a transient failure would erase
/// every still-live baseline and blank netqual for that family for many ticks).
bool nq_fetch_tcp_table(ULONG family, std::vector<BYTE>& buf) {
    buf.clear();
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return true; // no connections of this family — genuine empty, prune-safe
    buf.resize(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        const DWORD ret =
            GetExtendedTcpTable(buf.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR)
            return true;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size); // grew between probe and fetch — retry at the new size
            continue;
        }
        break; // hard failure — leave buf cleared, report unread
    }
    buf.clear();
    return false;
}

} // namespace

std::vector<NetConnection> enumerate_connections() {
    std::vector<NetConnection> result;
    collect_tcp4(result);
    collect_tcp6(result);
    collect_udp4(result);
    collect_udp6(result);

    resolve_hostnames(result);
    return result;
}

std::vector<TcpQualitySample> collect_tcp_quality() {
    std::vector<TcpQualitySample> out;
    if (g_nq_gate.load(std::memory_order_relaxed) == kNqGateDenied)
        return out; // non-elevated: latched for the process lifetime

    // Raw ESTABLISHED tables (OWNER_PID variants — the pid feeds process_name).
    // Fetched before the state lock (retry the size race, like the sibling
    // collectors); only the tracked-map work is serialized. v4_ok/v6_ok gate
    // the per-family prune below so a transient read failure does not wipe live
    // baselines.
    std::vector<BYTE> buf4, buf6;
    const bool v4_ok = nq_fetch_tcp_table(AF_INET, buf4);
    const bool v6_ok = nq_fetch_tcp_table(AF_INET6, buf6);

    std::lock_guard lock(g_nq_mtx);
    ++g_nq_tick;

    // Stale-gap guard: if too long elapsed since the last sweep (netqual was
    // disabled, or the host slept), re-anchor every surviving baseline so this
    // tick emits nothing rather than reporting the whole gap's retransmits as
    // one tick's current loss. Connections still established get re-baselined in
    // the visit loops; ones that vanished are pruned as usual.
    const std::int64_t now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count();
    if (g_nq_last_sweep_unix != 0 &&
        now_unix - g_nq_last_sweep_unix > kNetQualStaleSweepSeconds) {
        for (auto& [k, t] : g_nq_tracked)
            t.baselined = false;
    }
    g_nq_last_sweep_unix = now_unix;

    std::size_t enables = 0;
    std::unordered_map<uint32_t, std::string> name_cache;
    bool denied = false;

    if (!buf4.empty()) {
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf4.data());
        for (DWORD i = 0; i < table->dwNumEntries && !denied; ++i) {
            auto& r = table->table[i];
            if (r.dwState != MIB_TCP_STATE_ESTAB)
                continue;
            MIB_TCPROW row{};
            row.dwState = r.dwState;
            row.dwLocalAddr = r.dwLocalAddr;
            row.dwLocalPort = r.dwLocalPort;
            row.dwRemoteAddr = r.dwRemoteAddr;
            row.dwRemotePort = r.dwRemotePort;
            std::string remote = format_win_addr4(r.dwRemoteAddr);
            std::string key = nq_v4_key(format_win_addr4(r.dwLocalAddr),
                                        ntohs(static_cast<u_short>(r.dwLocalPort)), remote,
                                        ntohs(static_cast<u_short>(r.dwRemotePort)));
            denied = !nq_visit(row, std::move(key), "tcp", std::move(remote),
                               static_cast<uint32_t>(r.dwOwningPid), enables, name_cache, out);
        }
    }
    if (!buf6.empty()) {
        auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf6.data());
        for (DWORD i = 0; i < table->dwNumEntries && !denied; ++i) {
            auto& r = table->table[i];
            if (r.dwState != MIB_TCP_STATE_ESTAB)
                continue;
            MIB_TCP6ROW row{};
            row.State = static_cast<MIB_TCP_STATE>(r.dwState);
            std::memcpy(&row.LocalAddr, r.ucLocalAddr, sizeof(row.LocalAddr));
            row.dwLocalScopeId = r.dwLocalScopeId; // required, or link-local rows
            row.dwLocalPort = r.dwLocalPort;       // fail ERROR_NOT_FOUND
            std::memcpy(&row.RemoteAddr, r.ucRemoteAddr, sizeof(row.RemoteAddr));
            row.dwRemoteScopeId = r.dwRemoteScopeId;
            row.dwRemotePort = r.dwRemotePort;
            std::string remote = format_win_addr6(r.ucRemoteAddr);
            // Scope IDs are part of the key (see nq_v6_key): two link-local
            // connections can share address+port and differ only by zone.
            std::string key = nq_v6_key(format_win_addr6(r.ucLocalAddr), r.dwLocalScopeId,
                                        ntohs(static_cast<u_short>(r.dwLocalPort)), remote,
                                        r.dwRemoteScopeId,
                                        ntohs(static_cast<u_short>(r.dwRemotePort)));
            denied = !nq_visit(row, std::move(key), "tcp6", std::move(remote),
                               static_cast<uint32_t>(r.dwOwningPid), enables, name_cache, out);
        }
    }

    if (denied) {
        // One warn for the whole session — the status action carries the state
        // (netqual_capture_method=none) from here on.
        g_nq_gate.store(kNqGateDenied, std::memory_order_relaxed);
        spdlog::warn("TAR netqual: SetPerTcpConnectionEStats returned ACCESS_DENIED — "
                     "ESTATS needs an elevated agent; netqual records nothing this session");
        g_nq_tracked.clear();
        return {};
    }
    g_nq_gate.store(kNqGateActive, std::memory_order_relaxed);

    // Prune connections that left the ESTABLISHED table (stats die with the TCB;
    // nothing to disable — see the never-disable note above) — but ONLY for a
    // family whose table we actually read this tick. A family whose fetch failed
    // (v4_ok/v6_ok == false) is skipped: its entries keep their baselines and are
    // revisited next tick, instead of being wiped and re-enabled 128-at-a-time.
    std::erase_if(g_nq_tracked, [&](const auto& kv) {
        if (kv.second.seen_tick == g_nq_tick)
            return false; // observed this tick — keep
        return kv.first.starts_with("tcp6|") ? v6_ok : v4_ok;
    });
    return out;
}

std::string_view netqual_effective_capture_method() {
    // Tri-state, honestly: only claim "estats" once the elevation gate has
    // actually latched active. Until the first collect_fast tick tests it (or
    // when netqual is disabled), the gate is kNqGateUnknown and we report
    // "estats_pending" — NOT "estats" — so a non-elevated agent no longer
    // advertises "estats" for the first interval before flipping to "none".
    switch (g_nq_gate.load(std::memory_order_relaxed)) {
    case kNqGateDenied:
        return "none";
    case kNqGateActive:
        return "estats";
    default:
        return "estats_pending";
    }
}

// nstat (tar_netqual_nstat.hpp) is macOS-only — see the Linux definition's
// comment for why this TU still needs the symbol on every platform.
void netqual_nstat_register_client(NstatClient*) {}

#else
// Unsupported platform
std::vector<NetConnection> enumerate_connections() {
    return {};
}
std::vector<TcpQualitySample> collect_tcp_quality() {
    return {};
}
std::string_view netqual_effective_capture_method() { return "none"; }
void netqual_nstat_register_client(NstatClient*) {}
#endif

} // namespace yuzu::tar
