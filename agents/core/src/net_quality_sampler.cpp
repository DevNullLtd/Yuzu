/// @file net_quality_sampler.cpp
/// See net_quality_sampler.hpp. Linux reads per-connection TCP_INFO via netlink
/// SOCK_DIAG/INET_DIAG (proven to match `ss -ti`) + device throughput from
/// /proc/net/dev. Windows reads device throughput via GetIfTable2 and a
/// system-wide TCP retransmit rate via GetTcpStatisticsEx (RTT deferred — needs
/// ESTATS). macOS reads device throughput via NET_RT_IFLIST2 (retransmit + RTT
/// deferred — see the macOS block below). Other platforms return all-invalid.

#include "net_quality_sampler.hpp"

#include <type_traits>

// Pure helpers (median / throughput_bps / RetransWindow) are header-inline.

// ── Linux implementation ─────────────────────────────────────────────────────
#if defined(__linux__)

#include "yuzu/agent/linux_tcp_info.hpp" // ABI-pinned tcp_info (glibc-version-proof)

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // TCP_ESTABLISHED (NOT struct tcp_info — see linux_tcp_info.hpp)
#include <sys/socket.h>
#include <sys/time.h> // struct timeval (SO_RCVTIMEO)
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef> // offsetof
#include <cstdint>
#include <cstdio>
#include <cstdlib> // std::strtoull — /proc/net/dev field walk
#include <cstring>
#include <type_traits>
#include <vector>

#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif

namespace yuzu::agent::netq {

namespace {

/// RAII owner for the netlink socket fd (cpp-safety: no leak on any return).
struct FdGuard {
    int fd{-1};
    explicit FdGuard(int f) : fd(f) {}
    ~FdGuard() {
        if (fd >= 0)
            ::close(fd);
    }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
};
static_assert(!std::is_copy_constructible_v<FdGuard> && !std::is_move_constructible_v<FdGuard>,
              "FdGuard must be a non-copyable, non-movable scope owner");

/// RAII owner for the /proc/net/dev FILE* (twin of FdGuard — no manual fclose).
struct FileGuard {
    std::FILE* f{nullptr};
    explicit FileGuard(std::FILE* p) : f(p) {}
    ~FileGuard() {
        if (f)
            std::fclose(f);
    }
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;
};

bool send_dump(int fd, uint8_t family) {
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

// Cap on retained per-connection RTTs. The retrans/segs accumulators are scalar
// sums (no cap needed); only the RTT vector grows per-connection. We keep doubles
// for a single device-level median, so this can be far larger than TAR's
// kNetQualTopN=50 (which bounds persisted warehouse rows). 4096 established
// connections is already extraordinary, and the kernel returns them in arbitrary
// (hash) order, so a 4096-sample median stays an unbiased device aggregate while
// bounding memory at ~32 KiB on a pathological host.
constexpr std::size_t kMaxRttSamples = 4096;

// Accumulate per-connection RTT (ms) + retransmit/segment totals from one dump.
// `family` is the dump we issued (echoed back in nlmsg_seq) so leftover replies
// from the previous family's dump are discarded, not double-counted.
void collect(int fd, uint8_t family, std::vector<double>& rtts_ms, uint64_t& retrans,
             uint64_t& segs) {
    // alignas: the in-place nlmsghdr/inet_diag_msg/rtattr casts below require
    // NLMSG_ALIGNTO (4-byte) alignment; a bare char[] is only 1-aligned (UBSan
    // -fsanitize=alignment). tcp_info (8-aligned) is read via memcpy, not cast.
    alignas(NLMSG_ALIGNTO) char buf[16384];
    for (;;) {
        struct sockaddr_nl sa{};
        struct iovec iov{buf, sizeof(buf)};
        struct msghdr m{};
        m.msg_name = &sa;
        m.msg_namelen = sizeof(sa);
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        // Retry on EINTR (don't abandon a dump on a signal); a SO_RCVTIMEO
        // timeout returns EAGAIN -> n<0 -> we stop (bounded wait, never a
        // wedged heartbeat thread).
        ssize_t n;
        do {
            n = ::recvmsg(fd, &m, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return;
        for (auto* h = reinterpret_cast<struct nlmsghdr*>(buf); NLMSG_OK(h, n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
                return;
            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY)
                continue;
            // Full mirror of tar_network_collector.cpp's nq_collect guard:
            //  (1) nlmsg_seq != family — discard a reply left over from the
            //      previous family's dump (a mid-dump SO_RCVTIMEO can leave
            //      AF_INET replies queued when we send the AF_INET6 dump on the
            //      same socket); counting it again would double-count a conn.
            //  (2) nlmsg_len bound — NLMSG_OK guarantees the header fits, not the
            //      inet_diag_msg body; a truncated message would tail-over-read
            //      `diag` and make `rtalen` negative.
            if (h->nlmsg_seq != family ||
                h->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
                continue;
            auto* diag = reinterpret_cast<struct inet_diag_msg*>(NLMSG_DATA(h));
            int rtalen = static_cast<int>(h->nlmsg_len) -
                         static_cast<int>(NLMSG_LENGTH(sizeof(*diag)));
            auto* attr = reinterpret_cast<struct rtattr*>(diag + 1);
            for (; RTA_OK(attr, rtalen); attr = RTA_NEXT(attr, rtalen)) {
                if (attr->rta_type != INET_DIAG_INFO)
                    continue;
                // Defensive: the kernel's tcp_info may be shorter/longer than
                // our pinned prefix; only read the fields we need if present.
                if (RTA_PAYLOAD(attr) < offsetof(LinuxTcpInfo, tcpi_segs_out) +
                                            sizeof(uint32_t))
                    continue;
                // memcpy into a local, NOT a reinterpret_cast: RTA_DATA is only
                // 4-byte aligned but LinuxTcpInfo needs 8-byte alignment (it has
                // u64 members), and no real object of that type lives in `buf`.
                // The cast would be alignment + strict-aliasing UB; memcpy moots
                // both. Copy at most our struct size (kernel struct is larger).
                LinuxTcpInfo ti{};
                std::memcpy(&ti, RTA_DATA(attr),
                            std::min<std::size_t>(RTA_PAYLOAD(attr), sizeof ti));
                if (ti.tcpi_rtt > 0 && rtts_ms.size() < kMaxRttSamples)
                    rtts_ms.push_back(ti.tcpi_rtt / 1000.0); // tcpi_rtt is microseconds
                retrans += ti.tcpi_total_retrans;
                segs += ti.tcpi_segs_out;
            }
        }
    }
}

} // namespace

NetCounters read_net_counters() {
    // v1 throughput is a deliberately COARSE device aggregate: the sum of every
    // non-loopback interface's byte counters. On a host with stacked interfaces
    // (a bridge + its veth pairs, a VPN tun over a physical NIC, container
    // bridges) the same packet is counted on each layer it traverses, so this
    // over-counts — it is an upper bound on device traffic, not a wire-accurate
    // figure. We do NOT filter virtual interfaces by name: that heuristic is
    // fragile (naming varies across distros/orchestrators) and would wrongly drop
    // a VPN tun the operator cares about. Accurate per-interface / per-route
    // attribution is a later warehouse slice; the thin heartbeat fact stays an
    // honest coarse aggregate (see docs/user-manual/network.md "Throughput").
    NetCounters c;
    std::FILE* raw = std::fopen("/proc/net/dev", "re");
    if (!raw)
        return c; // invalid
    FileGuard fg(raw); // closes on every return path
    std::FILE* f = raw;
    char line[512];
    // Skip the two header lines.
    if (!std::fgets(line, sizeof(line), f) || !std::fgets(line, sizeof(line), f))
        return c;
    uint64_t rx_total = 0, tx_total = 0;
    while (std::fgets(line, sizeof(line), f)) {
        char* colon = std::strchr(line, ':');
        if (!colon)
            continue;
        // Interface name is before the colon (may be space-padded).
        char* name = line;
        while (*name == ' ')
            ++name;
        *colon = '\0';
        // Skip the loopback — it is not "the network", and dwarfs real traffic.
        if (std::strcmp(name, "lo") == 0)
            continue;
        // rx: bytes packets errs drop fifo frame compressed multicast | tx: bytes ...
        // 8 rx fields then tx bytes is field 9 overall. strtoull walk instead of
        // sscanf "%llu"x9 (glibc 2.38's __isoc23_sscanf redirect breaks older-glibc
        // hosts); like %llu, strtoull skips leading whitespace, and all 9 fields
        // must convert — matching the old `>= 9` (i.e. all-nine) conversion-count gate.
        const char* p = colon + 1;
        unsigned long long fields[9]{};
        bool ok = true;
        for (auto& fv : fields) {
            char* end{};
            fv = std::strtoull(p, &end, 10);
            if (end == p) {
                ok = false;
                break;
            }
            p = end;
        }
        if (ok) {
            rx_total += fields[0]; // rx bytes
            tx_total += fields[8]; // tx bytes
        }
    }
    c.valid = true;
    c.rx_bytes = rx_total;
    c.tx_bytes = tx_total;
    c.at = std::chrono::steady_clock::now();
    return c;
}

NetQualitySample sample_net_quality(const NetCounters& prev, const NetCounters& cur) {
    NetQualitySample s;

    // RTT + retransmit via netlink INET_DIAG (no delta needed).
    int raw = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (raw >= 0) {
        FdGuard guard(raw);
        // Bound the recvmsg wait so a stalled dump (kernel that never sends
        // NLMSG_DONE) can never wedge the heartbeat thread — it degrades to a
        // partial/empty sample (absent tags), not a hung agent.
        struct timeval tv{2, 0}; // 2 s
        ::setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        std::vector<double> rtts;
        uint64_t retrans = 0, segs = 0;
        for (uint8_t fam : {AF_INET, AF_INET6})
            if (send_dump(raw, fam))
                collect(raw, fam, rtts, retrans, segs);
        if (auto p50 = median(std::move(rtts))) {
            s.rtt_valid = true;
            s.rtt_p50_ms = *p50;
        }
        if (segs > 0) {
            // Raw cumulative device sums — the agent differences these across
            // heartbeats (RetransWindow) for the interval rate. NOT a ratio here:
            // the absolute Σretrans/Σsegs is the disproven, dilution-prone signal.
            s.retrans_valid = true;
            s.retrans_total = retrans;
            s.segs_out_total = segs;
        }
    }

    // Throughput from the interface-counter delta.
    if (auto bps = throughput_bps(prev, cur)) {
        s.throughput_valid = true;
        s.throughput_bps = *bps;
    }

    return s;
}

} // namespace yuzu::agent::netq

// ── Windows implementation ───────────────────────────────────────────────────
#elif defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h> // must precede windows.h; netioapi.h needs its typedefs + AF_INET*
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h> // GetTcpStatisticsEx / MIB_TCPSTATS
#include <netioapi.h> // GetIfTable2 / MIB_IF_TABLE2 / FreeMibTable (64-bit octets)
// clang-format on
#pragma comment(lib, "iphlpapi.lib") // GetTcpStatisticsEx / GetIfTable2 / FreeMibTable

namespace yuzu::agent::netq {

namespace {

// RAII for GetIfTable2's heap allocation — FreeMibTable on every return path.
// Single-owner like the Linux FdGuard/FileGuard: copy/move deleted so the raw
// pointer can never be duplicated into a double-FreeMibTable.
struct MibIfTableGuard {
    MIB_IF_TABLE2* t{nullptr};
    MibIfTableGuard() = default;
    MibIfTableGuard(const MibIfTableGuard&) = delete;
    MibIfTableGuard& operator=(const MibIfTableGuard&) = delete;
    ~MibIfTableGuard() {
        if (t)
            ::FreeMibTable(t);
    }
};
static_assert(!std::is_copy_constructible_v<MibIfTableGuard> &&
                  !std::is_move_constructible_v<MibIfTableGuard>,
              "MibIfTableGuard must be a single non-copyable, non-movable owner");

} // namespace

NetCounters read_net_counters() {
    // Coarse device aggregate: the sum of every non-loopback interface's 64-bit
    // octet counters (mirrors the Linux /proc/net/dev path and tar_perf.cpp's
    // read_network). Same over-counting caveat as Linux for stacked interfaces —
    // an upper bound, not wire-accurate (docs/user-manual/network.md "Throughput").
    NetCounters c;
    MibIfTableGuard g;
    if (::GetIfTable2(&g.t) != NO_ERROR || !g.t)
        return c; // invalid
    uint64_t rx_total = 0, tx_total = 0;
    for (ULONG i = 0; i < g.t->NumEntries; ++i) {
        const MIB_IF_ROW2& row = g.t->Table[i];
        if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK)
            continue; // loopback is not "the network" and dwarfs real traffic
        rx_total += row.InOctets;  // 64-bit — no wrap concern
        tx_total += row.OutOctets;
    }
    c.valid = true;
    c.rx_bytes = rx_total;
    c.tx_bytes = tx_total;
    c.at = std::chrono::steady_clock::now();
    return c;
}

NetQualitySample sample_net_quality(const NetCounters& prev, const NetCounters& cur) {
    NetQualitySample s;

    // Retransmit COUNTERS from the system-wide TCP MIB (GetTcpStatisticsEx),
    // summed over IPv4 + IPv6. Device-wide, since-boot cumulative counts; the
    // agent differences them across heartbeats (RetransWindow) for the interval
    // rate. NOT a ratio here.
    //
    // DIFFERENT POPULATION FROM LINUX — UNVALIDATED ON WINDOWS. Unlike the Linux
    // per-connection INET_DIAG sum, this MIB is the whole stack and CANNOT be
    // scoped by interface, so it INCLUDES loopback segments. The interval-delta
    // rate was validated under netem loss on Linux; the Windows counter is a
    // measurement-first signal whose separation-under-loss has NOT been
    // independently validated, and on a loopback-dominated host (e.g. a single-box
    // UAT rig) it dilutes toward ~0. Treat as a measurement, never a verdict.
    uint64_t retrans = 0, segs = 0;
    bool any = false;
    for (int fam : {AF_INET, AF_INET6}) {
        MIB_TCPSTATS st{};
        if (::GetTcpStatisticsEx(&st, fam) == NO_ERROR) {
            // dwRetransSegs / dwOutSegs are DWORD since-boot; a 32-bit wrap on a
            // long-running busy host gives cur<prev for that interval, which the
            // RetransWindow clamps to a zero contribution (never negative loss).
            retrans += st.dwRetransSegs;
            segs += st.dwOutSegs;
            any = true;
        }
    }
    if (any && segs > 0) {
        s.retrans_valid = true;
        s.retrans_total = retrans;
        s.segs_out_total = segs;
    }
    // RTT omitted on Windows in v1: per-connection smoothed RTT needs ESTATS
    // (GetPerTcpConnectionEStats — enable per connection + admin + overhead), a
    // deferred slice. rtt_valid stays false → the tag is absent, never 0.

    // Throughput from the interface-counter delta (the pure helper).
    if (auto bps = throughput_bps(prev, cur)) {
        s.throughput_valid = true;
        s.throughput_bps = *bps;
    }
    return s;
}

} // namespace yuzu::agent::netq

// ── macOS implementation (THROUGHPUT ONLY — retransmit + RTT deferred) ──────
#elif defined(__APPLE__)

#include <sys/sysctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace yuzu::agent::netq {

NetCounters read_net_counters() {
    // v1 throughput is a deliberately COARSE device aggregate — the sum of
    // every non-loopback interface's byte counters, read via the routing-socket
    // interface list (NET_RT_IFLIST2). This mirrors the Linux /proc/net/dev and
    // Windows GetIfTable2 paths, including the same over-counting caveat: on a
    // host with stacked interfaces (a bridge + its member NICs, a VPN utun over
    // a physical NIC) the same packet is counted on each layer it traverses, so
    // this is an upper bound on device traffic, not a wire-accurate figure (see
    // docs/user-manual/network.md "Throughput").
    NetCounters c;

    int mib[6] = {CTL_NET, AF_ROUTE, 0, 0, NET_RT_IFLIST2, 0}; // family 0 = all
    std::size_t needed = 0;
    if (::sysctl(mib, 6, nullptr, &needed, nullptr, 0) < 0 || needed == 0)
        return c; // invalid

    std::vector<char> buf(needed);
    if (::sysctl(mib, 6, buf.data(), &needed, nullptr, 0) < 0)
        return c; // invalid — no fd/heap handle to own, the vector frees itself

    uint64_t rx_total = 0, tx_total = 0;
    char* ptr = buf.data();
    std::size_t remaining = needed;
    // Walk the buffer message-by-message. This is a trusted kernel buffer, but
    // FULL BOUNDS CHECKS are still mandatory (PLAN-002): a truncated/short
    // final message or a zero ifm_msglen must never over-read the buffer,
    // spin forever, or be tolerated as "close enough" — any malformation
    // invalidates the whole sample rather than publishing a partial
    // aggregate as if it were complete.
    // Every routing-socket message type (if_msghdr, if_msghdr2, ifa_msghdr, …)
    // shares this exact leading prefix (see net/route.h / net/if.h). The
    // interface list interleaves RTM_IFINFO2 records with RTM_NEWADDR address
    // records whose total length is routinely SHORTER than sizeof(if_msghdr)
    // (if_msghdr embeds a full if_data), so the per-message minimum is this
    // prefix — requiring a full if_msghdr would misread a legitimate short
    // trailing address record as truncation and invalidate the whole sample.
    struct MsgPrefix {
        unsigned short msglen;
        unsigned char version;
        unsigned char type;
    };
    static_assert(sizeof(MsgPrefix) == 4);
    // Pin the mirrored layout to the SDK's real headers — if Apple ever moved
    // these fields, the walk would misparse silently without this.
    static_assert(offsetof(struct if_msghdr2, ifm_msglen) == offsetof(MsgPrefix, msglen) &&
                  offsetof(struct if_msghdr2, ifm_version) == offsetof(MsgPrefix, version) &&
                  offsetof(struct if_msghdr2, ifm_type) == offsetof(MsgPrefix, type));

    while (remaining > 0) {
        if (remaining < sizeof(MsgPrefix))
            return c; // truncated trailing header — not a successful walk

        // memcpy into a local, aligned object rather than reinterpret_cast
        // the raw kernel bytes: same discipline as the Linux tcp_info read
        // above — no real object of these types lives in `buf`, so a typed
        // cast would be alignment + strict-aliasing UB; memcpy moots both.
        MsgPrefix pfx{};
        std::memcpy(&pfx, ptr, sizeof(pfx));
        const std::size_t msglen = pfx.msglen;
        if (msglen < sizeof(MsgPrefix) || msglen > remaining)
            return c; // malformed/truncated — never advance by 0, never overrun

        if (pfx.type == RTM_IFINFO2) {
            // A short RTM_IFINFO2 IS the malformation the fail-whole-sample
            // contract above exists for (unlike a legitimately-short
            // RTM_NEWADDR, which the generic msglen check above already lets
            // through) — invalidate the whole sample rather than silently
            // skip a truncated interface record and publish a partial
            // aggregate as if it were complete.
            if (msglen < sizeof(struct if_msghdr2))
                return c; // invalid — truncated RTM_IFINFO2
            // Reject a routing-message ABI version we don't know how to lay
            // out as if_msghdr2 (prospective guard: a future kernel revision
            // could change the layout under a new RTM_VERSION without
            // changing msglen enough to be caught above).
            if (pfx.version != RTM_VERSION)
                return c; // invalid — unrecognized RTM_IFINFO2 layout version
            struct if_msghdr2 ifm2 {};
            std::memcpy(&ifm2, ptr, sizeof(ifm2));
            // Skip the loopback — it is not "the network", and dwarfs real
            // traffic (mirrors the Linux "lo" skip / Windows
            // IF_TYPE_SOFTWARE_LOOPBACK skip).
            if (!(ifm2.ifm_flags & IFF_LOOPBACK)) {
                // if_data64 fields — 64-bit, no wrap concern.
                rx_total += ifm2.ifm_data.ifi_ibytes;
                tx_total += ifm2.ifm_data.ifi_obytes;
            }
        }
        ptr += msglen;
        remaining -= msglen;
    }

    // Reached only when the walk consumed the entire buffer cleanly (no
    // malformed/truncated message forced an early, invalid return above) —
    // valid is set only after that successful, complete walk.
    c.valid = true;
    c.rx_bytes = rx_total;
    c.tx_bytes = tx_total;
    c.at = std::chrono::steady_clock::now();
    return c;
}

NetQualitySample sample_net_quality(const NetCounters& prev, const NetCounters& cur) {
    NetQualitySample s;

    // (a) Throughput from the interface-counter delta (the pure helper) — via
    // NET_RT_IFLIST2, measurement-first, same coarse over-counting caveat as
    // the Linux and Windows paths above.
    if (auto bps = throughput_bps(prev, cur)) {
        s.throughput_valid = true;
        s.throughput_bps = *bps;
    }

    // (b) Retransmit is DEFERRED on macOS in v1. The originally-planned source
    // (the global net.inet.tcp.stats OID, read for tcps_sndrexmitpack /
    // tcps_sndpack) is UNUSABLE: it reads back all-zero counters on current
    // macOS (verified 26.5.2 — every one of its 228 u32 fields is 0, matching
    // Apple's own `netstat -s -p tcp`), so `segs` would always be 0 and a
    // 'retransmit' claim would be false. We deliberately do not read that
    // OID. Retransmit defers to a per-flow source (the NetworkStatistics/
    // nstat client, roadmap 2.x).
    // s.retrans_valid stays false — absent, never a fabricated 0.

    // (c) RTT is deferred on macOS, exactly as on Windows in v1 — needs a
    // per-connection source. s.rtt_valid stays false — absent, never 0.

    return s;
}

} // namespace yuzu::agent::netq

#else // ── other platforms: all-invalid ────────────────────────────────────

namespace yuzu::agent::netq {

NetCounters read_net_counters() { return {}; }

NetQualitySample sample_net_quality(const NetCounters&, const NetCounters&) { return {}; }

} // namespace yuzu::agent::netq

#endif
