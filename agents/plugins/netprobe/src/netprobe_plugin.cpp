/**
 * netprobe_plugin.cpp — active network measurement (BRD E1,
 * docs/dex-brd-coverage.md): RTT / jitter / loss to operator-chosen targets
 * plus DNS resolution timing. Three actions:
 *
 *   icmp — ICMP echo RTT. Windows: IcmpSendEcho (iphlpapi, unprivileged;
 *          millisecond granularity by API design). POSIX: unprivileged
 *          SOCK_DGRAM ICMP "ping socket" (works out of the box on macOS;
 *          on Linux gated by net.ipv4.ping_group_range — when the socket is
 *          refused the row carries status `not-permitted` instead of a fake
 *          100% loss). IPv4 only in this slice (IPv6 is a tracked follow-up).
 *   tcp  — TCP connect-time RTT to target:port (default 443). Unprivileged
 *          everywhere; the pragmatic probe for targets that drop ICMP.
 *   dns  — getaddrinfo wall-time per name.
 *
 * Be kind to the network (fleet-scale): targets capped at 4 per invocation,
 * samples at 10, timeout at 3000 ms, fixed 200 ms inter-sample gap, strictly
 * sequential. Worst case ≈ 2 minutes; defaults (5 × 1000 ms) ≈ seconds.
 * Recurrence/trending is NOT this plugin's job — the server scheduler runs
 * the definition on an interval and the response store keeps the history.
 *
 * Output rows:
 *   rtt|<target>|<proto>|<sent>|<ok>|<min_ms>|<avg_ms>|<max_ms>|<jitter_ms>|<loss_pct>|<status>
 *   dns|<name>|<resolve_ms>|<status: ok | error:N | invalid-target>|<address count>
 * Timing fields are 1-decimal strings (the result-column system has no float
 * type; the DSL coerces float-strings for workflow conditions). Jitter is the
 * population stddev of successful samples (netprobe_stats.hpp, unit-tested).
 */

#include <yuzu/plugin.hpp>

#include "netprobe_stats.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <thread>
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

namespace {

using yuzu::netprobe::clamp_param;
using yuzu::netprobe::compute_stats;
using yuzu::netprobe::split_targets;
using yuzu::netprobe::sanitize_for_output;
using yuzu::netprobe::valid_probe_target;

constexpr std::size_t kMaxTargets = 4;
constexpr int kDefaultCount = 5, kMinCount = 1, kMaxCount = 10;
constexpr int kDefaultTimeoutMs = 1000, kMinTimeoutMs = 100, kMaxTimeoutMs = 3000;
constexpr int kDefaultPort = 443;
constexpr auto kInterSampleGap = std::chrono::milliseconds(200);

double elapsed_ms(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
        .count();
}

std::string fmt1(double v) { return std::format("{:.1f}", v); }

// One resolved address (first result of the requested family).
struct Resolved {
    sockaddr_storage addr{};
    int addr_len{0};
    int family{0};
};

// getaddrinfo wrapper: first result for `family` (AF_UNSPEC = first of any).
// nullopt on failure. The numeric-friendly hints make IP literals resolve
// without a DNS round-trip.
std::optional<Resolved> resolve_first(const std::string& target, int family) {
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &res) != 0 || !res)
        return std::nullopt;
    Resolved r;
    std::memcpy(&r.addr, res->ai_addr, res->ai_addrlen);
    r.addr_len = static_cast<int>(res->ai_addrlen);
    r.family = res->ai_family;
    freeaddrinfo(res);
    return r;
}

void set_port(Resolved& r, int port) {
    if (r.family == AF_INET)
        reinterpret_cast<sockaddr_in*>(&r.addr)->sin_port =
            htons(static_cast<std::uint16_t>(port));
    else if (r.family == AF_INET6)
        reinterpret_cast<sockaddr_in6*>(&r.addr)->sin6_port =
            htons(static_cast<std::uint16_t>(port));
}

// ── TCP connect-time sample ──────────────────────────────────────────────────

#ifdef _WIN32
std::optional<double> tcp_sample(const Resolved& dst, int timeout_ms) {
    SOCKET s = ::socket(dst.family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return std::nullopt;
    u_long nonblock = 1;
    ::ioctlsocket(s, FIONBIO, &nonblock);
    const auto t0 = std::chrono::steady_clock::now();
    int rc = ::connect(s, reinterpret_cast<const sockaddr*>(&dst.addr), dst.addr_len);
    std::optional<double> out;
    if (rc == 0) {
        out = elapsed_ms(t0);
    } else if (::WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wfds, efds;
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET(s, &wfds);
        FD_SET(s, &efds);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        if (::select(0, nullptr, &wfds, &efds, &tv) > 0 && FD_ISSET(s, &wfds)) {
            int soerr = 0;
            int len = sizeof(soerr);
            if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &len) ==
                    0 &&
                soerr == 0)
                out = elapsed_ms(t0);
        }
    }
    ::closesocket(s);
    return out;
}
#else
std::optional<double> tcp_sample(const Resolved& dst, int timeout_ms) {
    int s = ::socket(dst.family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
        return std::nullopt;
    ::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL, 0) | O_NONBLOCK);
    const auto t0 = std::chrono::steady_clock::now();
    int rc = ::connect(s, reinterpret_cast<const sockaddr*>(&dst.addr),
                       static_cast<socklen_t>(dst.addr_len));
    std::optional<double> out;
    if (rc == 0) {
        out = elapsed_ms(t0);
    } else if (errno == EINPROGRESS) {
        pollfd pfd{s, POLLOUT, 0};
        if (::poll(&pfd, 1, timeout_ms) > 0 && (pfd.revents & POLLOUT)) {
            int soerr = 0;
            socklen_t len = sizeof(soerr);
            if (::getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0 && soerr == 0)
                out = elapsed_ms(t0);
        }
    }
    ::close(s);
    return out;
}
#endif

// ── ICMP echo sample ─────────────────────────────────────────────────────────

#ifdef _WIN32
// IcmpSendEcho reports RoundTripTime in WHOLE milliseconds (a sub-ms LAN hop
// reads 0 — kept raw, never fudged; the tcp action gives sub-ms fidelity).
struct IcmpSession {
    HANDLE h{INVALID_HANDLE_VALUE};
    IcmpSession() : h(::IcmpCreateFile()) {}
    ~IcmpSession() {
        if (h != INVALID_HANDLE_VALUE)
            ::IcmpCloseHandle(h);
    }
    bool ok() const { return h != INVALID_HANDLE_VALUE; }

    std::optional<double> sample(ULONG ipv4, int timeout_ms) {
        static const char payload[24] = "yuzu-netprobe-e1-sample";
        std::vector<unsigned char> reply(sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8);
        DWORD n = ::IcmpSendEcho(h, ipv4, const_cast<char*>(payload), sizeof(payload), nullptr,
                                 reply.data(), static_cast<DWORD>(reply.size()),
                                 static_cast<DWORD>(timeout_ms));
        if (n == 0)
            return std::nullopt;
        const auto* r = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
        if (r->Status != IP_SUCCESS)
            return std::nullopt;
        return static_cast<double>(r->RoundTripTime);
    }
};
#else
// RFC 1071 internet checksum.
std::uint16_t icmp_checksum(const unsigned char* data, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<std::uint32_t>(data[i]) << 8 | data[i + 1];
    if (len & 1)
        sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

struct IcmpSession {
    int fd{-1};
    bool permitted{true};
    std::uint16_t seq{0};

    IcmpSession() {
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (fd < 0)
            permitted = !(errno == EACCES || errno == EPERM || errno == EPROTONOSUPPORT);
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
    bool ok() const { return fd >= 0; }

    std::optional<double> sample(const sockaddr_in& dst, int timeout_ms) {
        // Echo request: type 8 / code 0 / checksum / id / seq + 24-byte
        // payload. Linux ping sockets rewrite the id, so replies are matched
        // on SEQUENCE only.
        unsigned char pkt[32] = {8, 0, 0, 0, 0, 0, 0, 0, 'y', 'u', 'z', 'u', '-', 'n', 'e', 't'};
        const std::uint16_t this_seq = ++seq;
        pkt[6] = static_cast<unsigned char>(this_seq >> 8);
        pkt[7] = static_cast<unsigned char>(this_seq & 0xFF);
        const std::uint16_t ck = icmp_checksum(pkt, sizeof(pkt));
        pkt[2] = static_cast<unsigned char>(ck >> 8);
        pkt[3] = static_cast<unsigned char>(ck & 0xFF);

        const auto t0 = std::chrono::steady_clock::now();
        if (::sendto(fd, pkt, sizeof(pkt), 0, reinterpret_cast<const sockaddr*>(&dst),
                     sizeof(dst)) < 0)
            return std::nullopt;

        // Drain until OUR echo reply (other ICMP traffic can share the
        // socket) or the timeout budget is spent.
        for (;;) {
            const int remaining =
                timeout_ms - static_cast<int>(elapsed_ms(t0));
            if (remaining <= 0)
                return std::nullopt;
            pollfd pfd{fd, POLLIN, 0};
            if (::poll(&pfd, 1, remaining) <= 0)
                return std::nullopt;
            unsigned char buf[512];
            const auto n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0)
                return std::nullopt;
            // macOS delivers IP header + ICMP; Linux ping sockets deliver
            // ICMP only. Skip the IP header when one is present.
            std::size_t off = 0;
            if (n >= 20 && (buf[0] & 0xF0) == 0x40)
                off = static_cast<std::size_t>(buf[0] & 0x0F) * 4;
            if (static_cast<std::size_t>(n) < off + 8)
                continue;
            const bool is_reply = buf[off] == 0; // echo reply
            const std::uint16_t got_seq =
                static_cast<std::uint16_t>(buf[off + 6] << 8 | buf[off + 7]);
            if (is_reply && got_seq == this_seq)
                return elapsed_ms(t0);
            // Someone else's reply / other ICMP — keep draining.
        }
    }
};
#endif

// ── actions ──────────────────────────────────────────────────────────────────

struct RttRowWriter {
    yuzu::CommandContext& ctx;
    void write(const std::string& target, const std::string& proto,
               const yuzu::netprobe::ProbeStats& s, const std::string& status) const {
        ctx.write_output(std::format("rtt|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}", target, proto, s.sent,
                                     s.ok, fmt1(s.min_ms), fmt1(s.avg_ms), fmt1(s.max_ms),
                                     fmt1(s.jitter_ms), fmt1(s.loss_pct), status));
    }
    void write_empty(const std::string& target, const std::string& proto,
                     const std::string& status) const {
        write(target, proto, yuzu::netprobe::ProbeStats{}, status);
    }
};

std::vector<std::string> parse_targets_or_error(yuzu::CommandContext& ctx, yuzu::Params& params) {
    auto targets = split_targets(std::string(params.get("targets")), kMaxTargets);
    if (targets.empty())
        ctx.write_output("error|missing required parameter: targets (comma-separated, max 4)");
    return targets;
}

int do_icmp(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto targets = parse_targets_or_error(ctx, params);
    if (targets.empty())
        return 1;
    const int count = clamp_param(std::string(params.get("count")), kDefaultCount, kMinCount,
                                  kMaxCount);
    const int timeout_ms = clamp_param(std::string(params.get("timeout_ms")), kDefaultTimeoutMs,
                                       kMinTimeoutMs, kMaxTimeoutMs);
    RttRowWriter row{ctx};

    IcmpSession session;
    for (const auto& target : targets) {
        if (!valid_probe_target(target)) {
            row.write_empty(sanitize_for_output(target), "icmp", "invalid-target");
            continue;
        }
        if (!session.ok()) {
#ifndef _WIN32
            row.write_empty(target, "icmp",
                            session.permitted ? "error" : "not-permitted");
#else
            row.write_empty(target, "icmp", "error");
#endif
            continue;
        }
        auto dst = resolve_first(target, AF_INET); // IPv4 only this slice
        if (!dst) {
            row.write_empty(target, "icmp", "resolve-failed");
            continue;
        }
        std::vector<double> ok_ms;
        for (int i = 0; i < count; ++i) {
            if (i > 0)
                std::this_thread::sleep_for(kInterSampleGap);
#ifdef _WIN32
            const ULONG ipv4 = reinterpret_cast<sockaddr_in*>(&dst->addr)->sin_addr.s_addr;
            if (auto ms = session.sample(ipv4, timeout_ms))
                ok_ms.push_back(*ms);
#else
            const auto& sin = *reinterpret_cast<sockaddr_in*>(&dst->addr);
            if (auto ms = session.sample(sin, timeout_ms))
                ok_ms.push_back(*ms);
#endif
        }
        row.write(target, "icmp", compute_stats(count, ok_ms), "ok");
    }
    return 0;
}

int do_tcp(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto targets = parse_targets_or_error(ctx, params);
    if (targets.empty())
        return 1;
    const int count = clamp_param(std::string(params.get("count")), kDefaultCount, kMinCount,
                                  kMaxCount);
    const int timeout_ms = clamp_param(std::string(params.get("timeout_ms")), kDefaultTimeoutMs,
                                       kMinTimeoutMs, kMaxTimeoutMs);
    const int port = clamp_param(std::string(params.get("port")), kDefaultPort, 1, 65535);
    const std::string proto = std::format("tcp:{}", port);
    RttRowWriter row{ctx};

    for (const auto& target : targets) {
        if (!valid_probe_target(target)) {
            row.write_empty(sanitize_for_output(target), proto, "invalid-target");
            continue;
        }
        auto dst = resolve_first(target, AF_UNSPEC);
        if (!dst) {
            row.write_empty(target, proto, "resolve-failed");
            continue;
        }
        set_port(*dst, port);
        std::vector<double> ok_ms;
        for (int i = 0; i < count; ++i) {
            if (i > 0)
                std::this_thread::sleep_for(kInterSampleGap);
            if (auto ms = tcp_sample(*dst, timeout_ms))
                ok_ms.push_back(*ms);
        }
        row.write(target, proto, compute_stats(count, ok_ms), "ok");
    }
    return 0;
}

int do_dns(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto names = parse_targets_or_error(ctx, params);
    if (names.empty())
        return 1;
    for (const auto& name : names) {
        if (!valid_probe_target(name)) {
            ctx.write_output(std::format("dns|{}|0.0|invalid-target|0", sanitize_for_output(name)));
            continue;
        }
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        const auto t0 = std::chrono::steady_clock::now();
        const int rc = getaddrinfo(name.c_str(), nullptr, &hints, &res);
        const double ms = elapsed_ms(t0);
        int addresses = 0;
        for (const addrinfo* p = res; p; p = p->ai_next)
            ++addresses;
        if (res)
            freeaddrinfo(res);
        ctx.write_output(std::format("dns|{}|{}|{}|{}", name, fmt1(ms),
                                     rc == 0 ? std::string("ok") : std::format("error:{}", rc),
                                     addresses));
    }
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// All three actions are native, in-process socket work on every platform —
// zero subprocesses (rung 1). icmp on Linux depends on
// net.ipv4.ping_group_range admitting an unprivileged SOCK_DGRAM ICMP
// socket; when the kernel refuses it the row reports the honest
// `not-permitted` status rather than a fabricated 100% loss (IcmpSession's
// own comment), so that leg is CONSTRAINED rather than unconditionally
// SUPPORTED. macOS's ping-socket support "works out of the box" per this
// file's header comment.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "icmp",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "SOCK_DGRAM ICMP ping socket",
         "requires net.ipv4.ping_group_range to admit the process group; reports "
         "not-permitted otherwise"},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "SOCK_DGRAM ICMP ping socket", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "IcmpSendEcho", nullptr},
    },
    {
        /* .action      = */ "tcp",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "non-blocking connect() timing", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "non-blocking connect() timing", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "non-blocking connect() timing", nullptr},
    },
    {
        /* .action      = */ "dns",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "getaddrinfo", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "getaddrinfo", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "getaddrinfo", nullptr},
    },
};

} // namespace

class NetprobePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "netprobe"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Active network measurement: ICMP/TCP round-trip time, jitter, loss, and DNS "
               "resolution timing to operator-chosen targets";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"icmp", "tcp", "dns", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
#ifdef _WIN32
        // Self-sufficient Winsock init (refcounted) — the agent process has
        // Winsock up via gRPC, but a plugin must not rely on that implicitly.
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return std::unexpected(yuzu::PluginError{1, "WSAStartup failed"});
#endif
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "icmp")
            return do_icmp(ctx, params);
        if (action == "tcp")
            return do_tcp(ctx, params);
        if (action == "dns")
            return do_dns(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(NetprobePlugin)
