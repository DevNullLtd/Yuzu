/**
 * icmp_probe.hpp — shared unprivileged reachability probes
 * (ADR-3002, Decision 5: deepest-interpreter-invoked rung classification
 * applies to consumers; this header itself is rung 1, native, no interpreter).
 * Consumer today: discovery's ping sweep. wol's `check` action still spawns
 * the system `ping` binary via popen/run_command (rung 3, unmigrated as of
 * this writing — see wol_plugin.cpp's own "last shell-out of this shape"
 * comment, which tracks that migration as separate future work); do not
 * re-list it here as a current consumer until it actually calls into this
 * header.
 *
 * Hoisted VERBATIM from netprobe_plugin.cpp (behaviour identical; netprobe's
 * in-plugin copy is converged onto this header as a tracked follow-up) so
 * discovery's ping sweep can probe a host natively (rung 1) instead of
 * spawning `ping`:
 *
 *   IcmpSession — ICMP echo RTT. Windows: IcmpSendEcho (iphlpapi,
 *       unprivileged; whole-millisecond granularity by API design). POSIX:
 *       unprivileged SOCK_DGRAM ICMP "ping socket" (works out of the box on
 *       macOS; on Linux gated by net.ipv4.ping_group_range — a refused socket
 *       sets `permitted=false` so callers report an honest `not-permitted` /
 *       CONSTRAINED status, never a fake 100% loss).
 *   tcp_sample — TCP connect-time RTT for targets that drop ICMP (the
 *       pragmatic fallback; unprivileged everywhere).
 *   resolve_first / set_port — getaddrinfo helpers shared by both.
 *
 * IPv4-focused like the netprobe original (IPv6 is a tracked follow-up).
 * Header-only; no spawn, no interpreter — rung 1 by construction.
 */
#pragma once

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
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
// clang-format off
#include <iphlpapi.h>
#include <icmpapi.h> // after iphlpapi.h
// clang-format on
// Normally from <ipexport.h> via iphlpapi.h; defined defensively so the
// timeout-vs-send-failure split below cannot fail to compile on an SDK that
// does not surface it.
#ifndef IP_REQ_TIMED_OUT
#define IP_REQ_TIMED_OUT 11010L
#endif
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yuzu::shared {

// Move-only RAII owner for a getaddrinfo() result list -- zero-dependency
// (agents/shared leaf rule: no core/plugin type, just the platform socket
// headers this file already includes).
struct AddrInfoGuard {
    addrinfo* p{nullptr};
    AddrInfoGuard() = default;
    explicit AddrInfoGuard(addrinfo* ptr) : p(ptr) {}
    ~AddrInfoGuard() {
        if (p)
            ::freeaddrinfo(p);
    }
    AddrInfoGuard(const AddrInfoGuard&) = delete;
    AddrInfoGuard& operator=(const AddrInfoGuard&) = delete;
    AddrInfoGuard(AddrInfoGuard&& other) noexcept : p(other.p) { other.p = nullptr; }
    AddrInfoGuard& operator=(AddrInfoGuard&& other) noexcept {
        if (this != &other) {
            if (p)
                ::freeaddrinfo(p);
            p = other.p;
            other.p = nullptr;
        }
        return *this;
    }
};

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
inline void close_socket(SocketHandle s) { ::closesocket(s); }
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
inline void close_socket(SocketHandle s) { ::close(s); }
#endif

// Move-only RAII owner for a socket fd/SOCKET, same shape as wol_plugin.cpp's
// SocketGuard (that copy is plugin-local; this is the shared-leaf twin so
// icmp_probe.hpp's own socket acquisitions don't manually close).
struct SocketGuard {
    SocketHandle s{kInvalidSocket};
    SocketGuard() = default;
    explicit SocketGuard(SocketHandle sock) : s(sock) {}
    ~SocketGuard() {
        if (s != kInvalidSocket)
            close_socket(s);
    }
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    SocketGuard(SocketGuard&& other) noexcept : s(other.s) { other.s = kInvalidSocket; }
    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            if (s != kInvalidSocket)
                close_socket(s);
            s = other.s;
            other.s = kInvalidSocket;
        }
        return *this;
    }
    bool ok() const { return s != kInvalidSocket; }
};

inline double probe_elapsed_ms(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
        .count();
}

// One resolved address (first result of the requested family).
struct Resolved {
    sockaddr_storage addr{};
    int addr_len{0};
    int family{0};
};

// getaddrinfo wrapper: first result for `family` (AF_UNSPEC = first of any).
// nullopt on failure. The numeric-friendly hints make IP literals resolve
// without a DNS round-trip.
inline std::optional<Resolved> resolve_first(const std::string& target, int family) {
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* raw_res = nullptr;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &raw_res) != 0 || !raw_res)
        return std::nullopt;
    AddrInfoGuard res{raw_res};
    Resolved r;
    std::memcpy(&r.addr, res.p->ai_addr, res.p->ai_addrlen);
    r.addr_len = static_cast<int>(res.p->ai_addrlen);
    r.family = res.p->ai_family;
    return r;
}

inline void set_port(Resolved& r, int port) {
    if (r.family == AF_INET)
        reinterpret_cast<sockaddr_in*>(&r.addr)->sin_port =
            htons(static_cast<std::uint16_t>(port));
    else if (r.family == AF_INET6)
        reinterpret_cast<sockaddr_in6*>(&r.addr)->sin6_port =
            htons(static_cast<std::uint16_t>(port));
}

// ── TCP connect-time sample ──────────────────────────────────────────────────

// A TCP connect attempt can end three genuinely different ways, and
// collapsing them onto one std::optional<double> lost a distinction that
// matters: `rtt_ms` set means a real connect succeeded; `refused` means the
// destination's network stack actively answered with an RST (ECONNREFUSED /
// WSAECONNREFUSED) -- POSITIVE evidence the host is up and reachable, just
// with nothing listening on this port (common for a woken desktop with no
// service on kFallbackTcpPort, especially when ICMP is also blocked);
// neither set means a genuine timeout/no-response -- no evidence either way.
// A caller that only checks `rtt_ms` (the old contract) still gets identical
// behaviour for the connected case; `refused` is new information, not a
// behaviour change for existing has_value()-style checks.
struct TcpSampleResult {
    std::optional<double> rtt_ms;
    bool refused{false};
};

#ifdef _WIN32
inline TcpSampleResult tcp_sample(const Resolved& dst, int timeout_ms) {
    TcpSampleResult result;
    SocketGuard sock{::socket(dst.family, SOCK_STREAM, IPPROTO_TCP)};
    if (!sock.ok())
        return result;
    const SOCKET s = sock.s;
    u_long nonblock = 1;
    ::ioctlsocket(s, FIONBIO, &nonblock);
    const auto t0 = std::chrono::steady_clock::now();
    int rc = ::connect(s, reinterpret_cast<const sockaddr*>(&dst.addr), dst.addr_len);
    if (rc == 0) {
        result.rtt_ms = probe_elapsed_ms(t0);
        return result;
    }
    const int err = ::WSAGetLastError();
    if (err == WSAECONNREFUSED) {
        // Rare but possible: a synchronous refusal (e.g. loopback) with no
        // async wait needed at all.
        result.refused = true;
        return result;
    }
    if (err != WSAEWOULDBLOCK)
        return result;
    fd_set wfds, efds;
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(s, &wfds);
    FD_SET(s, &efds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    if (::select(0, nullptr, &wfds, &efds, &tv) <= 0)
        return result;
    // Windows signals an async connect failure (e.g. RST/refused) via the
    // EXCEPT set, not the WRITE set -- the write set alone (the old check)
    // never observed a refusal at all, so it read identically to a timeout.
    if (FD_ISSET(s, &wfds)) {
        int soerr = 0;
        int len = sizeof(soerr);
        if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &len) == 0 &&
            soerr == 0)
            result.rtt_ms = probe_elapsed_ms(t0);
        return result;
    }
    if (FD_ISSET(s, &efds)) {
        int soerr = 0;
        int len = sizeof(soerr);
        if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &len) == 0 &&
            soerr == WSAECONNREFUSED)
            result.refused = true;
    }
    return result;
}
#else
inline TcpSampleResult tcp_sample(const Resolved& dst, int timeout_ms) {
    TcpSampleResult result;
    SocketGuard sock{::socket(dst.family, SOCK_STREAM, IPPROTO_TCP)};
    if (!sock.ok())
        return result;
    const int s = sock.s;
    ::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL, 0) | O_NONBLOCK);
    const auto t0 = std::chrono::steady_clock::now();
    int rc = ::connect(s, reinterpret_cast<const sockaddr*>(&dst.addr),
                       static_cast<socklen_t>(dst.addr_len));
    if (rc == 0) {
        result.rtt_ms = probe_elapsed_ms(t0);
        return result;
    }
    if (errno == ECONNREFUSED) {
        // Rare but possible: a synchronous refusal (e.g. loopback) with no
        // async wait needed at all.
        result.refused = true;
        return result;
    }
    if (errno != EINPROGRESS)
        return result;
    // Poll for the connect to settle -- do not gate on `revents & POLLOUT`:
    // a failed async connect (e.g. RST/refused) is reported on some POSIX
    // implementations via POLLERR/POLLHUP rather than POLLOUT, and the old
    // POLLOUT-only gate silently treated that identically to a timeout
    // (never reaching the getsockopt below at all). Any wakeup here means
    // the connect settled one way or another; SO_ERROR tells us which.
    pollfd pfd{s, POLLOUT, 0};
    if (::poll(&pfd, 1, timeout_ms) <= 0)
        return result;
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if (::getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0) {
        if (soerr == 0)
            result.rtt_ms = probe_elapsed_ms(t0);
        else if (soerr == ECONNREFUSED)
            result.refused = true;
    }
    return result;
}
#endif

// ── Pure checksum ────────────────────────────────────────────────────────────

/**
 * RFC 1071 internet checksum. Portable and pure — Windows' IcmpSendEcho
 * computes its own checksum internally and never calls this, but keeping the
 * function (and its tests) on every leg means the framing helper below can be
 * portable too, and a checksum regression is caught wherever CI runs.
 */
inline std::uint16_t icmp_checksum(const unsigned char* data, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<std::uint32_t>(data[i]) << 8 | data[i + 1];
    if (len & 1)
        sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

// ── Probe outcome: "no answer" is NOT the same as "could not ask" ───────────

/**
 * Why a probe produced no RTT. The distinction is the whole point: an
 * untyped "nothing" makes a host that never received our packet
 * indistinguishable from a host that chose not to answer, and a sweep that
 * could not transmit at all then reports a confidently empty network.
 */
enum class ProbeFailure {
    None,           // nothing went wrong — see ProbeOutcome::replied/silent
    TransmitDenied, // send refused by policy (EACCES/EPERM, or a Windows send error)
    TransmitFailed, // send failed for a non-policy reason (ENETUNREACH, ENOBUFS, ...)
    ReceiveFailed,  // poll/recv errored — distinct from expiring the budget
};

struct ProbeOutcome {
    std::optional<double> rtt_ms{}; // engaged iff the host actually replied
    ProbeFailure failure{ProbeFailure::None};

    bool replied() const { return rtt_ms.has_value(); }
    // Transmitted fine, nothing came back within the budget — a genuinely
    // silent (or absent) host. The ONLY case a caller may read as "down".
    bool silent() const { return !rtt_ms.has_value() && failure == ProbeFailure::None; }
    // We never got the question out; the target's state is unknown, not down.
    bool transmit_blocked() const {
        return failure == ProbeFailure::TransmitDenied || failure == ProbeFailure::TransmitFailed;
    }
};

/**
 * Classify a failed send by its errno. Pure, so the mapping is unit-tested
 * even though the branch that consults it only runs when the kernel actually
 * refuses a transmission (which no unit host can be made to do without a
 * syscall seam — exercising the branch itself remains a tracked gap).
 *
 * EACCES/EPERM mean a policy said no; everything else is a transport problem.
 * Both are "we could not ask", never "the host is down" — the distinction that
 * keeps a blocked sweep from reporting a confidently empty network.
 */
inline ProbeFailure classify_transmit_errno(int err) {
    return (err == EACCES || err == EPERM) ? ProbeFailure::TransmitDenied
                                           : ProbeFailure::TransmitFailed;
}

/**
 * Classify a failed `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` by its errno,
 * returning the IcmpSession `permitted` value the caller should report. Pure,
 * so the mapping is unit-tested even though the branch that consults it only
 * runs on a POSIX host whose kernel actually refuses the socket (which no
 * unit host can be made to do without a syscall seam).
 *
 * EACCES/EPERM mean a policy said no — Linux's net.ipv4.ping_group_range
 * denied this (E)UID an unprivileged ICMP socket — so `permitted=false`,
 * which the caller classifies CONSTRAINED/icmp:ping_group_range.
 *
 * EPROTONOSUPPORT is a DIFFERENT failure mode: the kernel itself lacks
 * SOCK_DGRAM/IPPROTO_ICMP support, which no sysctl tuning fixes. It must NOT
 * be grouped with the policy denials above (colleague review of this PR) —
 * doing so reported it as CONSTRAINED/icmp:ping_group_range and would
 * misdirect an operator toward tuning a sysctl that isn't the cause. Left
 * `permitted=true` here (so IcmpSession::ok()==false), it classifies
 * UNAVAILABLE/icmp:socket_error instead, same as any other transport error.
 */
inline bool classify_socket_open_errno(int err) { return !(err == EACCES || err == EPERM); }

// ── Pure echo framing/matching (portable — compiled and tested on every leg) ──

constexpr std::size_t kEchoPacketLen = 32;

/**
 * Build an ICMP echo request (type 8 / code 0) carrying `seq`, with the
 * RFC-1071 checksum filled in. Pure: no socket, no platform header — so the
 * framing that the live path depends on is unit-tested on every leg,
 * including Windows where the send itself goes through IcmpSendEcho.
 */
inline std::array<unsigned char, kEchoPacketLen> build_echo_request(std::uint16_t seq) {
    std::array<unsigned char, kEchoPacketLen> pkt{};
    pkt[0] = 8; // echo request
    pkt[1] = 0; // code
    pkt[6] = static_cast<unsigned char>(seq >> 8);
    pkt[7] = static_cast<unsigned char>(seq & 0xFF);
    const char tag[] = "yuzu-net";
    for (std::size_t i = 0; i + 1 < sizeof(tag); ++i)
        pkt[8 + i] = static_cast<unsigned char>(tag[i]);
    const std::uint16_t ck = icmp_checksum(pkt.data(), pkt.size());
    pkt[2] = static_cast<unsigned char>(ck >> 8);
    pkt[3] = static_cast<unsigned char>(ck & 0xFF);
    return pkt;
}

/**
 * Does `buf` hold OUR echo reply — i.e. an ICMP echo reply (type 0) whose
 * sequence equals `expected_seq`?
 *
 * macOS delivers the IP header ahead of the ICMP message; Linux ping sockets
 * deliver the ICMP message alone. The leading nibble check distinguishes them.
 * Replies are matched on SEQUENCE only because Linux ping sockets rewrite the
 * ICMP id; the caller separately checks the source address.
 *
 * Pure and bounds-checked: a short or truncated buffer is "not our reply",
 * never an out-of-bounds read.
 */
inline bool match_echo_reply(const unsigned char* buf, std::size_t n, std::uint16_t expected_seq) {
    if (!buf)
        return false;
    std::size_t off = 0;
    if (n >= 20 && (buf[0] & 0xF0) == 0x40)
        off = static_cast<std::size_t>(buf[0] & 0x0F) * 4;
    if (n < off + 8)
        return false;
    if (buf[off] != 0) // 0 == echo reply; 8 would be someone else's request
        return false;
    const std::uint16_t got_seq =
        static_cast<std::uint16_t>(buf[off + 6] << 8 | buf[off + 7]);
    return got_seq == expected_seq;
}

// ── ICMP echo sample ─────────────────────────────────────────────────────────

#ifdef _WIN32
// IcmpSendEcho reports RoundTripTime in WHOLE milliseconds (a sub-ms LAN hop
// reads 0 — kept raw, never fudged; TCP sampling gives sub-ms fidelity).
struct IcmpSession {
    HANDLE h{INVALID_HANDLE_VALUE};
    IcmpSession() : h(::IcmpCreateFile()) {}
    ~IcmpSession() {
        if (h != INVALID_HANDLE_VALUE)
            ::IcmpCloseHandle(h);
    }
    IcmpSession(const IcmpSession&) = delete;
    IcmpSession& operator=(const IcmpSession&) = delete;
    bool ok() const { return h != INVALID_HANDLE_VALUE; }
    bool permitted{true}; // Windows ICMP is unprivileged; parity with POSIX

    ProbeOutcome sample(ULONG ipv4, int timeout_ms) {
        static const char payload[24] = "yuzu-netprobe-e1-sample";
        std::vector<unsigned char> reply(sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8);
        DWORD n = ::IcmpSendEcho(h, ipv4, const_cast<char*>(payload), sizeof(payload), nullptr,
                                 reply.data(), static_cast<DWORD>(reply.size()),
                                 static_cast<DWORD>(timeout_ms));
        if (n == 0) {
            // A zero return covers BOTH "nobody answered in time" and "the
            // request could not be issued". Only GetLastError separates them,
            // and conflating them is what lets a blocked sweep report an empty
            // network: IP_REQ_TIMED_OUT is a silent host, anything else means
            // we never got the question out.
            const DWORD err = ::GetLastError();
            if (err == IP_REQ_TIMED_OUT)
                return {};
            return {std::nullopt, ProbeFailure::TransmitFailed};
        }
        const auto* r = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
        if (r->Status != IP_SUCCESS)
            return {}; // unreachable/TTL-expired etc. — a real network answer, host not up
        ProbeOutcome out;
        out.rtt_ms = static_cast<double>(r->RoundTripTime);
        return out;
    }
};
#else
struct IcmpSession {
    int fd{-1};
    bool permitted{true};
    std::uint16_t seq{0};

    IcmpSession() {
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (fd < 0)
            permitted = classify_socket_open_errno(errno);
        // Randomize the starting sequence: on macOS concurrent ICMP dgram
        // sockets can see each other's echo replies, and two sessions both
        // counting from 0 could cross-match a reply (and record a bogus RTT).
        seq = static_cast<std::uint16_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFF);
    }
    ~IcmpSession() {
        if (fd >= 0)
            ::close(fd);
    }
    IcmpSession(const IcmpSession&) = delete;
    IcmpSession& operator=(const IcmpSession&) = delete;
    bool ok() const { return fd >= 0; }

    ProbeOutcome sample(const sockaddr_in& dst, int timeout_ms) {
        const std::uint16_t this_seq = ++seq;
        const auto pkt = build_echo_request(this_seq);

        const auto t0 = std::chrono::steady_clock::now();
        if (::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<const sockaddr*>(&dst),
                     sizeof(dst)) < 0) {
            // A refused SEND is not a silent host. A policy that allows the
            // socket but blocks transmission (seatbelt/SELinux/nftables) would
            // otherwise mark every target dead and let the caller report a
            // confidently empty network.
            return {std::nullopt, classify_transmit_errno(errno)};
        }

        // Drain until OUR echo reply (other ICMP traffic can share the
        // socket) or the timeout budget is spent.
        for (;;) {
            const int remaining = timeout_ms - static_cast<int>(probe_elapsed_ms(t0));
            if (remaining <= 0)
                return {}; // budget spent with the packet away — genuinely silent
            pollfd pfd{fd, POLLIN, 0};
            const int pr = ::poll(&pfd, 1, remaining);
            if (pr == 0)
                return {}; // timed out — silent
            if (pr < 0) {
                if (errno == EINTR)
                    continue; // not an error, just interrupted — keep waiting
                return {std::nullopt, ProbeFailure::ReceiveFailed};
            }
            unsigned char buf[512];
            sockaddr_in from{};
            socklen_t from_len = sizeof(from);
            const auto n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                      reinterpret_cast<sockaddr*>(&from), &from_len);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                return {std::nullopt, ProbeFailure::ReceiveFailed};
            }
            if (n == 0)
                continue;
            // recvfrom, not recv: matching on sequence alone would let any
            // host on the segment answer for another address. Require the
            // reply to come from the address we probed.
            if (from.sin_family == AF_INET &&
                from.sin_addr.s_addr != dst.sin_addr.s_addr)
                continue; // someone else's traffic — keep draining
            if (match_echo_reply(buf, static_cast<std::size_t>(n), this_seq)) {
                ProbeOutcome out;
                out.rtt_ms = probe_elapsed_ms(t0);
                return out;
            }
            // Someone else's reply / other ICMP — keep draining.
        }
    }
};
#endif

} // namespace yuzu::shared
