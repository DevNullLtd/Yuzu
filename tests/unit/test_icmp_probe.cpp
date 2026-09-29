// icmp_probe.hpp is wave-0 shared infrastructure (discovery's ping sweep,
// wol's `check` action, the latter not yet in this branch). This TU covers:
//   - the PURE surface, portable and run on every leg: the RFC-1071 checksum,
//     echo-request framing, echo-reply matching, transmit-errno
//     classification, ProbeOutcome semantics, and numeric-literal address
//     resolution (getaddrinfo on an IP literal resolves in-process, no DNS).
//   - the LIVE sample() path, POSIX-only and asserted as an HONESTY invariant
//     rather than as network success, so it is discriminating without being
//     host-policy dependent (see the loopback case at the bottom).
//
// The pure/live split is deliberate. /adversarial-review (Kimi F5, Codex
// CDX-2, found independently) proved the earlier version of this file
// false-green: mutating sample() to return nothing left the whole tag green,
// because no test reached it. CLAUDE.md makes "a false-green test offered as
// closure evidence for a blocking finding" a policy floor.
#include <catch2/catch_test_macros.hpp>

#include <icmp_probe.hpp>

#include <cstring>

using namespace yuzu::shared;

#ifdef _WIN32
// getaddrinfo (used by resolve_first below) is real Winsock and fails with
// WSANOTINITIALISED until WSAStartup runs -- unlike IcmpCreateFile (IP
// Helper API, a separate driver interface with no such requirement).
// Production callers (network_interfaces.cpp, cloud_identity.cpp) each own
// their own lazy WSAStartup; this TU owns its own the same way, once, before
// any TEST_CASE below runs.
namespace {
struct WinsockInit {
    WinsockInit() {
        WSADATA wsa;
        ::WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WinsockInit() { ::WSACleanup(); }
};
const WinsockInit kWinsockInit;
} // namespace
#endif

// icmp_checksum is now PORTABLE (it moved out of icmp_probe.hpp's POSIX
// branch so the framing helper could be portable too), so these run on every
// leg. Windows' IcmpSendEcho computes its own checksum internally and never
// calls this, but a regression here would still break the POSIX legs, and
// catching it wherever CI runs first is strictly better.

TEST_CASE("icmp_checksum: all-zero packet checksums to 0xFFFF (RFC 1071 identity)",
          "[agent][icmp_probe]") {
    unsigned char pkt[8] = {0};
    CHECK(icmp_checksum(pkt, sizeof(pkt)) == 0xFFFF);
}

TEST_CASE("icmp_checksum: a known byte pattern matches the hand-computed RFC 1071 sum",
          "[agent][icmp_probe]") {
    // Two 16-bit words: 0x0001 + 0xF203 = 0xF204; one's-complement -> 0x0DFB.
    unsigned char pkt[4] = {0x00, 0x01, 0xF2, 0x03};
    CHECK(icmp_checksum(pkt, sizeof(pkt)) == 0x0DFB);
}

TEST_CASE("icmp_checksum: an odd-length buffer pads the trailing byte high, not low",
          "[agent][icmp_probe]") {
    // A single 0xFF byte is summed as 0xFF00 (padded as the HIGH byte per
    // RFC 1071), not 0x00FF -- carry-fold to one's complement of 0xFF00.
    unsigned char pkt[1] = {0xFF};
    CHECK(icmp_checksum(pkt, sizeof(pkt)) == static_cast<std::uint16_t>(~0xFF00));
}

TEST_CASE("resolve_first: a numeric IPv4 literal resolves without any DNS round-trip",
          "[agent][icmp_probe]") {
    auto r = resolve_first("127.0.0.1", AF_INET);
    REQUIRE(r.has_value());
    CHECK(r->family == AF_INET);
    CHECK(r->addr_len == sizeof(sockaddr_in));
    const auto* sin = reinterpret_cast<const sockaddr_in*>(&r->addr);
    CHECK(sin->sin_family == AF_INET);
    unsigned char expected[4] = {127, 0, 0, 1};
    CHECK(std::memcmp(&sin->sin_addr, expected, 4) == 0);
}

TEST_CASE("resolve_first: a numeric IPv6 literal resolves without any DNS round-trip",
          "[agent][icmp_probe]") {
    auto r = resolve_first("::1", AF_INET6);
    REQUIRE(r.has_value());
    CHECK(r->family == AF_INET6);
    CHECK(r->addr_len == sizeof(sockaddr_in6));
}

// POSIX-only: verified on Windows (MSVC/the-rig) that WinSock's getaddrinfo
// resolves an empty node string to a wildcard/loopback address instead of
// failing EAI_NONAME the way glibc/libSystem's implementation does -- a real
// platform divergence, not a bug in resolve_first (it forwards getaddrinfo's
// own answer either way, and neither platform's answer triggers a DNS
// round-trip for an empty node).
#ifndef _WIN32
TEST_CASE("resolve_first: an empty target fails immediately (EAI_NONAME, no network I/O)",
          "[agent][icmp_probe]") {
    auto r = resolve_first("", AF_INET);
    CHECK_FALSE(r.has_value());
}
#endif

TEST_CASE("set_port: writes the port in network byte order for both address families",
          "[agent][icmp_probe]") {
    auto v4 = resolve_first("127.0.0.1", AF_INET);
    REQUIRE(v4.has_value());
    set_port(*v4, 8080);
    const auto* sin = reinterpret_cast<const sockaddr_in*>(&v4->addr);
    CHECK(sin->sin_port == htons(8080));

    auto v6 = resolve_first("::1", AF_INET6);
    REQUIRE(v6.has_value());
    set_port(*v6, 443);
    const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&v6->addr);
    CHECK(sin6->sin6_port == htons(443));
}

// ── Pure echo framing / reply matching ───────────────────────────────────────
// These carry the logic the live path depends on, and are portable, so the
// framing and matching are covered on every leg (including Windows, whose send
// goes through IcmpSendEcho). /adversarial-review found the previous suite
// false-green: mutating sample() to return nothing left [icmp_probe] fully
// green, because nothing here reached it.

TEST_CASE("build_echo_request: frames a type-8 echo request carrying the sequence",
          "[agent][icmp_probe]") {
    const auto pkt = build_echo_request(0xBEEF);
    REQUIRE(pkt.size() == kEchoPacketLen);
    CHECK(pkt[0] == 8); // echo REQUEST, not reply — a type-0 here never elicits a response
    CHECK(pkt[1] == 0);
    CHECK(pkt[6] == 0xBE); // sequence, network byte order
    CHECK(pkt[7] == 0xEF);
}

TEST_CASE("build_echo_request: the checksum it writes actually validates",
          "[agent][icmp_probe]") {
    // Recomputing over a packet whose checksum field is populated must yield 0
    // (RFC 1071's self-validating property). A packet with a wrong or missing
    // checksum is silently dropped by the peer, so the sweep would report every
    // host down — with no local error to notice.
    auto pkt = build_echo_request(0x1234);
    CHECK(icmp_checksum(pkt.data(), pkt.size()) == 0);
    // And the field is genuinely populated, not left zero.
    CHECK((pkt[2] != 0 || pkt[3] != 0));
}

TEST_CASE("build_echo_request: distinct sequences produce distinct packets",
          "[agent][icmp_probe]") {
    const auto a = build_echo_request(1);
    const auto b = build_echo_request(2);
    CHECK(a != b);
}

TEST_CASE("match_echo_reply: accepts our reply, bare ICMP (Linux ping-socket shape)",
          "[agent][icmp_probe]") {
    unsigned char reply[8] = {0, 0, 0, 0, 0, 0, 0x12, 0x34};
    CHECK(match_echo_reply(reply, sizeof(reply), 0x1234));
}

TEST_CASE("match_echo_reply: accepts our reply behind an IP header (macOS shape)",
          "[agent][icmp_probe]") {
    // 0x45 == IPv4, IHL 5 -> a 20-byte header the matcher must skip.
    unsigned char reply[28] = {};
    reply[0] = 0x45;
    reply[20] = 0;    // echo reply
    reply[26] = 0xAB; // sequence
    reply[27] = 0xCD;
    CHECK(match_echo_reply(reply, sizeof(reply), 0xABCD));
    // A matcher that ignored IHL and read a fixed offset fails this:
    unsigned char long_hdr[32] = {};
    long_hdr[0] = 0x46; // IHL 6 -> 24-byte header
    long_hdr[24] = 0;
    long_hdr[30] = 0xAB;
    long_hdr[31] = 0xCD;
    CHECK(match_echo_reply(long_hdr, sizeof(long_hdr), 0xABCD));
}

TEST_CASE("match_echo_reply: rejects a different sequence", "[agent][icmp_probe]") {
    // The cross-matching guard: another probe's late reply must not be
    // credited to the host currently being probed.
    unsigned char reply[8] = {0, 0, 0, 0, 0, 0, 0x12, 0x34};
    CHECK_FALSE(match_echo_reply(reply, sizeof(reply), 0x9999));
}

TEST_CASE("match_echo_reply: rejects a non-echo-reply ICMP type", "[agent][icmp_probe]") {
    // Type 8 is an echo REQUEST (our own packet looped back, or another host
    // probing us). Accepting it would report any host that pings us as alive.
    unsigned char request[8] = {8, 0, 0, 0, 0, 0, 0x12, 0x34};
    CHECK_FALSE(match_echo_reply(request, sizeof(request), 0x1234));
    unsigned char unreachable[8] = {3, 0, 0, 0, 0, 0, 0x12, 0x34};
    CHECK_FALSE(match_echo_reply(unreachable, sizeof(unreachable), 0x1234));
}

TEST_CASE("match_echo_reply: short and null buffers are rejected, never read past",
          "[agent][icmp_probe]") {
    unsigned char reply[8] = {0, 0, 0, 0, 0, 0, 0x12, 0x34};
    CHECK_FALSE(match_echo_reply(nullptr, 8, 0x1234));
    CHECK_FALSE(match_echo_reply(reply, 0, 0x1234));
    CHECK_FALSE(match_echo_reply(reply, 7, 0x1234)); // one byte short of a sequence
    // An IP header claiming more bytes than the buffer holds.
    unsigned char truncated[22] = {};
    truncated[0] = 0x45; // 20-byte header, but only 2 bytes of ICMP follow
    CHECK_FALSE(match_echo_reply(truncated, sizeof(truncated), 0x1234));
}

// ── ProbeOutcome semantics ───────────────────────────────────────────────────

TEST_CASE("ProbeOutcome: 'could not ask' is never reported as 'host is down'",
          "[agent][icmp_probe]") {
    // The distinction the whole typed-outcome change exists for.
    ProbeOutcome silent;
    CHECK(silent.silent());
    CHECK_FALSE(silent.replied());
    CHECK_FALSE(silent.transmit_blocked());

    ProbeOutcome denied{std::nullopt, ProbeFailure::TransmitDenied};
    CHECK(denied.transmit_blocked());
    CHECK_FALSE(denied.silent()); // must NOT read as a down host
    CHECK_FALSE(denied.replied());

    ProbeOutcome failed{std::nullopt, ProbeFailure::TransmitFailed};
    CHECK(failed.transmit_blocked());
    CHECK_FALSE(failed.silent());

    ProbeOutcome recv_err{std::nullopt, ProbeFailure::ReceiveFailed};
    CHECK_FALSE(recv_err.silent()); // an errored receive is not a silent host
    CHECK_FALSE(recv_err.transmit_blocked()); // but the packet did go out

    ProbeOutcome up;
    up.rtt_ms = 1.5;
    CHECK(up.replied());
    CHECK_FALSE(up.silent());
    CHECK_FALSE(up.transmit_blocked());
}

TEST_CASE("classify_transmit_errno: a policy refusal is distinguished from a transport fault",
          "[agent][icmp_probe]") {
    // Both are "we could not ask" — but an operator acts differently on
    // "policy blocked this agent" than on "the network buffer was full", so
    // the two must not collapse into one reason.
    CHECK(classify_transmit_errno(EACCES) == ProbeFailure::TransmitDenied);
    CHECK(classify_transmit_errno(EPERM) == ProbeFailure::TransmitDenied);
    CHECK(classify_transmit_errno(ENETUNREACH) == ProbeFailure::TransmitFailed);
    CHECK(classify_transmit_errno(ENOBUFS) == ProbeFailure::TransmitFailed);
    CHECK(classify_transmit_errno(EHOSTUNREACH) == ProbeFailure::TransmitFailed);
    // Neither classification may ever be ProbeFailure::None — that is the
    // value that would make a blocked send read as a silent host.
    CHECK(classify_transmit_errno(EACCES) != ProbeFailure::None);
    CHECK(classify_transmit_errno(ENETUNREACH) != ProbeFailure::None);
}

TEST_CASE("classify_socket_open_errno: a ping_group_range policy denial is distinguished from "
          "a kernel that lacks ICMP socket support (colleague-review should-fix)",
          "[agent][icmp_probe]") {
    // EACCES/EPERM: Linux's net.ipv4.ping_group_range refused this (E)UID an
    // unprivileged ICMP socket — a policy denial, permitted=false, which the
    // caller (discovery_scan_plan.hpp's classify_icmp_session) maps to
    // CONSTRAINED/icmp:ping_group_range.
    CHECK_FALSE(classify_socket_open_errno(EACCES));
    CHECK_FALSE(classify_socket_open_errno(EPERM));

    // EPROTONOSUPPORT: the kernel itself lacks SOCK_DGRAM/IPPROTO_ICMP
    // support — no sysctl fixes that. Before this fix it was grouped with
    // the policy denials above and misreported as CONSTRAINED/
    // icmp:ping_group_range, misdirecting an operator toward tuning a
    // sysctl that was never the cause. It must come back permitted=true (so
    // IcmpSession::ok()==false) so the caller instead maps it to
    // UNAVAILABLE/icmp:socket_error, distinct from EACCES/EPERM above.
    CHECK(classify_socket_open_errno(EPROTONOSUPPORT));

    // Any other transport-ish errno is likewise not a policy denial.
    CHECK(classify_socket_open_errno(ENOBUFS));
}

TEST_CASE("IcmpSession: construction lands in a state the honest-degrade path handles",
          "[agent][icmp_probe]") {
    // DELIBERATELY NOT a live capability assertion. An earlier cut asserted
    // CHECK(session.ok()) && CHECK(session.permitted) unconditionally, which
    // makes the unit suite depend on host kernel policy: on a Linux host whose
    // net.ipv4.ping_group_range excludes the agent's gid -- the exact
    // deployment state this plugin's CONSTRAINED/PARTIAL degrade exists to
    // support, and a plausible CI runner config -- the constructor correctly
    // sets fd<0/permitted=false and both CHECKs would fail. A supported
    // runtime state must never turn a unit leg red.
    //
    // What IS environment-independent, and is what discovery's degrade branch
    // actually reads: a usable session never reports itself unpermitted, so
    // ok() implies permitted. The three states the plugin switches on are
    // therefore exactly {ok && permitted}, {!ok && !permitted} (denied ->
    // CONSTRAINED), {!ok && permitted} (socket error -> UNAVAILABLE).
    IcmpSession session;
    if (session.ok())
        CHECK(session.permitted);
    else
        SUCCEED("no unprivileged ICMP socket on this host — the honest-degrade "
                "state, asserted by the pure classifier tests instead");
}

#ifndef _WIN32
TEST_CASE("IcmpSession::sample: loopback is never reported as a silent host",
          "[agent][icmp_probe]") {
    // This is the test that closes the false-green: it actually calls sample().
    //
    // It is still environment-independent, because it asserts the HONESTY
    // invariant rather than network success. 127.0.0.1 always answers its own
    // echo unless the platform refused to transmit, so exactly one of two
    // things may be true:
    //   - we got a reply (with a sane RTT inside the budget), or
    //   - transmission was blocked, and sample() SAYS so.
    // What must never happen is `silent()` — "the packet went out and loopback
    // chose not to answer" is not a real state, and reporting it is precisely
    // how a policy-blocked sweep becomes a confidently empty network.
    //
    // Mutating sample() to return an untyped nothing (the /adversarial-review
    // mutation that previously left this tag green) now fails here.
    IcmpSession session;
    if (!session.ok()) {
        SUCCEED("no unprivileged ICMP socket on this host — nothing to sample");
        return;
    }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr) == 1);

    const auto outcome = session.sample(dst, 1000);
    CHECK_FALSE(outcome.silent());
    CHECK(outcome.replied() != outcome.transmit_blocked()); // exactly one holds
    if (outcome.replied()) {
        CHECK(*outcome.rtt_ms >= 0.0);
        CHECK(*outcome.rtt_ms <= 1000.0);
    }
}

TEST_CASE("IcmpSession::sample: consecutive probes use fresh sequences",
          "[agent][icmp_probe]") {
    // A fixed sequence would let one probe's reply satisfy the next, so a
    // dead host following a live one could read as alive.
    IcmpSession session;
    if (!session.ok()) {
        SUCCEED("no unprivileged ICMP socket on this host");
        return;
    }
    const std::uint16_t before = session.seq;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr) == 1);
    (void)session.sample(dst, 500);
    (void)session.sample(dst, 500);
    CHECK(static_cast<std::uint16_t>(session.seq - before) == 2);
}
#endif // !_WIN32
