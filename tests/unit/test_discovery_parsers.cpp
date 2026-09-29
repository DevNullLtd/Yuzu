/**
 * test_discovery_parsers.cpp — parse_proc_net_arp + format_mac48
 * (discovery_parsers.hpp, Wave-2 PR2.1 WP-C).
 *
 * Portable and unguarded — both are pure header-only text handling (no
 * ifstream, no platform dependency), so this TU carries no platform guard and
 * runs on every leg, macOS included. That is deliberate for format_mac48: its
 * only production caller is the _WIN32 ARP leg, so testing it here is the one
 * part of the Windows path that can be verified off-Windows.
 */
#include "discovery_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::discovery::parse_proc_net_arp;

TEST_CASE("parse_proc_net_arp parses the real captured /proc/net/arp table",
         "[agent][discovery_parsers]") {
    // Real capture (captured 2026-08-14T20:07:03Z via docker — pre-migration
    // fixtures per ADR-3002:688-694): the two-line table section of
    // ~/.claude/wave2-prestage/fixtures/linux/proc_net_arp.out (manifest.txt
    // line "proc_net_arp.out|rc=0|cmd=docker debian:bookworm-slim ping
    // gateway then cat /proc/net/arp"); the file's leading "bash: line 5: ip:
    // command not found" and "=== ... ===" section banners are capture-
    // harness noise, not fixture data, and are excluded here.
    constexpr std::string_view kRealCapture = R"(IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         8e:2a:cd:00:41:28     *        eth0
)";

    const auto entries = parse_proc_net_arp(kRealCapture);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "172.17.0.1");
    CHECK(entries[0].mac == "8e:2a:cd:00:41:28");
}

TEST_CASE("parse_proc_net_arp returns empty on a header-only table",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kHeaderOnly =
        "IP address       HW type     Flags       HW address            Mask     Device\n";
    CHECK(parse_proc_net_arp(kHeaderOnly).empty());
}

TEST_CASE("parse_proc_net_arp returns empty on blank input", "[agent][discovery_parsers]") {
    CHECK(parse_proc_net_arp("").empty());
    CHECK(parse_proc_net_arp("\n\n").empty());
}

TEST_CASE("parse_proc_net_arp drops an all-zero MAC", "[agent][discovery_parsers]") {
    constexpr std::string_view kAllZero =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.50     0x1         0x2         00:00:00:00:00:00     *        eth0\n";
    CHECK(parse_proc_net_arp(kAllZero).empty());
}

TEST_CASE("parse_proc_net_arp drops an entry without the ATF_COM complete bit",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kIncomplete =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        "192.168.1.52     0x1         0x4         aa:bb:cc:dd:ee:ff     *        eth0\n";
    // Neither row has bit 0x2 set (0x0 and 0x4) — both dropped, even though
    // the second has a real-looking, non-zero MAC.
    CHECK(parse_proc_net_arp(kIncomplete).empty());
}

TEST_CASE("parse_proc_net_arp keeps a row whose flags carry ATF_COM plus extra bits",
         "[agent][discovery_parsers]") {
    // 0x6 == ATF_COM|ATF_PERM: a permanent, complete entry. The test above
    // proves flags WITHOUT 0x2 are dropped; this proves the check is a
    // BITMASK test and not an equality test -- a parser written
    // `flags == kAtfCom` passes every other case in this file and drops
    // every permanent ARP entry on a real host.
    constexpr std::string_view kCompletePermanent =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.95     0x1         0x6         aa:bb:cc:dd:ee:ff     *        eth0\n";
    const auto entries = parse_proc_net_arp(kCompletePermanent);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.95");
    CHECK(entries[0].mac == "aa:bb:cc:dd:ee:ff");
}

TEST_CASE("parse_proc_net_arp drops a non-Ethernet hardware type",
         "[agent][discovery_parsers]") {
    // hwtype 0x6 (IEEE 802 / token ring family) is complete and has a
    // real-looking MAC, but the old `arp -n` parser required hwtype
    // "ether" — preserve that selectivity: non-Ethernet rows are dropped
    // even when otherwise well-formed and "complete".
    constexpr std::string_view kNonEthernet =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.90     0x6         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
    CHECK(parse_proc_net_arp(kNonEthernet).empty());
}

TEST_CASE("parse_proc_net_arp drops a truncated row missing Mask/Device",
         "[agent][discovery_parsers]") {
    // Only 4 of the 6 kernel columns present — a truncated capture, not a
    // real /proc/net/arp row. Must be skipped, not misread as complete.
    constexpr std::string_view kTruncated =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.91     0x1         0x2         aa:bb:cc:dd:ee:ff\n";
    CHECK(parse_proc_net_arp(kTruncated).empty());
}

TEST_CASE("parse_proc_net_arp tolerates ragged/collapsed whitespace",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kRagged =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "  192.168.1.60 \t 0x1  0x2 aa:bb:cc:dd:ee:ff\t*   eth0  \n";
    const auto entries = parse_proc_net_arp(kRagged);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.60");
    CHECK(entries[0].mac == "aa:bb:cc:dd:ee:ff");
}

TEST_CASE("parse_proc_net_arp tolerates short/malformed lines without crashing",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kShortLines =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.61\n"
        "192.168.1.62     0x1\n"
        "192.168.1.63     0x1         0x2         aa:bb:cc:dd:ee:00     *        eth0\n";
    const auto entries = parse_proc_net_arp(kShortLines);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.63");
}

TEST_CASE("parse_proc_net_arp tolerates CRLF line endings", "[agent][discovery_parsers]") {
    constexpr std::string_view kCrlf =
        "IP address       HW type     Flags       HW address            Mask     Device\r\n"
        "192.168.1.70     0x1         0x2         aa:bb:cc:11:22:33     *        eth0\r\n";
    const auto entries = parse_proc_net_arp(kCrlf);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.70");
    CHECK(entries[0].mac == "aa:bb:cc:11:22:33");
}

TEST_CASE("parse_proc_net_arp tolerates a missing header line",
         "[agent][discovery_parsers]") {
    // No "IP address ..." header row at all — the first line is real data
    // and must not be mistaken for (and dropped as) a header.
    constexpr std::string_view kNoHeader =
        "192.168.1.80     0x1         0x2         aa:bb:cc:44:55:66     *        eth0\n";
    const auto entries = parse_proc_net_arp(kNoHeader);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.80");
    CHECK(entries[0].mac == "aa:bb:cc:44:55:66");
}

// ── format_mac48 (Windows leg's MAC formatter, portable + tested everywhere) ──

TEST_CASE("format_mac48 emits lowercase colon-separated hex with zero padding",
         "[agent][discovery_parsers]") {
    // Zero-padding is the discriminating part: a formatter losing the leading
    // zero of 0x00/0x0a yields "0:17:88:a6:b2:13", which no longer matches the
    // MACs the Linux and macOS legs emit for the same host.
    const unsigned char addr[6] = {0x00, 0x17, 0x88, 0xa6, 0xb2, 0x13};
    CHECK(yuzu::discovery::format_mac48(addr) == "00:17:88:a6:b2:13");
    CHECK(yuzu::discovery::format_mac48(addr).size() == 17);
}

TEST_CASE("format_mac48 lowercases the high hex digits", "[agent][discovery_parsers]") {
    // Upper-case output ("AA:BB:...") would silently break MAC equality against
    // the /proc/net/arp and sysctl legs, which are lowercase.
    const unsigned char addr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    CHECK(yuzu::discovery::format_mac48(addr) == "aa:bb:cc:dd:ee:ff");
}

TEST_CASE("format_mac48 handles the all-zero and all-ones extremes",
         "[agent][discovery_parsers]") {
    const unsigned char zero[6] = {0, 0, 0, 0, 0, 0};
    // The all-zero MAC is formatted faithfully; DROPPING it is the parser's
    // job (see the all-zero case above), not the formatter's.
    CHECK(yuzu::discovery::format_mac48(zero) == "00:00:00:00:00:00");
    const unsigned char bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    CHECK(yuzu::discovery::format_mac48(bcast) == "ff:ff:ff:ff:ff:ff");
}

// ── is_resolved_arp_row (Windows leg's per-row filter, portable + tested
//    everywhere; #3249) ───────────────────────────────────────────────────
// Extracted from the impure GetIpNetTable2-calling loop in
// discovery_plugin.cpp, which is genuinely Windows-only and unbuildable on
// this Mac. The predicate itself takes plain ints (see discovery_parsers.hpp
// for why) so it is fixture-tested here against literal state/length values
// without ever calling GetIpNetTable2 — the actual Windows call site wiring
// (static_cast<int>(row.State), the static_asserts pinning these mirror
// values against the real NL_NEIGHBOR_STATE enum) is macOS-unverifiable and
// stays that way; only this predicate is proven off-Windows.

TEST_CASE("is_resolved_arp_row accepts every resolved/reachable-ish state with a full MAC",
         "[agent][discovery_parsers]") {
    using yuzu::discovery::is_resolved_arp_row;
    using yuzu::discovery::kNlnsDelay;
    using yuzu::discovery::kNlnsPermanent;
    using yuzu::discovery::kNlnsProbe;
    using yuzu::discovery::kNlnsReachable;
    using yuzu::discovery::kNlnsStale;

    // One assertion per accepted state, not a loop over a vector — a state
    // dropped from the switch by a future edit fails its own named line.
    CHECK(is_resolved_arp_row(kNlnsReachable, 6));
    CHECK(is_resolved_arp_row(kNlnsStale, 6));
    CHECK(is_resolved_arp_row(kNlnsDelay, 6));
    CHECK(is_resolved_arp_row(kNlnsProbe, 6));
    CHECK(is_resolved_arp_row(kNlnsPermanent, 6));
}

TEST_CASE("is_resolved_arp_row rejects Unreachable and Incomplete regardless of length",
         "[agent][discovery_parsers]") {
    using yuzu::discovery::is_resolved_arp_row;
    using yuzu::discovery::kNlnsIncomplete;
    using yuzu::discovery::kNlnsUnreachable;

    // A no-answer-yet probe can still carry a stale/zero-length physical
    // address; the state check must reject it before length is even
    // considered — a predicate that only checks length would wrongly accept
    // an Incomplete row with a leftover 6-byte address from a prior lease.
    CHECK_FALSE(is_resolved_arp_row(kNlnsUnreachable, 6));
    CHECK_FALSE(is_resolved_arp_row(kNlnsIncomplete, 6));
    CHECK_FALSE(is_resolved_arp_row(kNlnsUnreachable, 0));
}

TEST_CASE("is_resolved_arp_row rejects an unrecognised/out-of-range state",
         "[agent][discovery_parsers]") {
    using yuzu::discovery::is_resolved_arp_row;
    using yuzu::discovery::kNlnsMaximum;
    // A value the enum has never defined (a hypothetical future SDK state,
    // or corrupt/garbage input) must fail closed via the `default:` branch,
    // not be silently accepted.
    CHECK_FALSE(is_resolved_arp_row(/*state=*/99, /*phys_len=*/6));
    CHECK_FALSE(is_resolved_arp_row(/*state=*/-1, /*phys_len=*/6));
    // kNlnsMaximum is NL_NEIGHBOR_STATE's own published sentinel/bound value,
    // not a real neighbour state — reject it explicitly rather than relying
    // only on the mirror-value pin test below to notice a switch that
    // accidentally grew a `case kNlnsMaximum:` arm.
    CHECK_FALSE(is_resolved_arp_row(kNlnsMaximum, 6));
}

TEST_CASE("is_resolved_arp_row rejects a short physical address on an otherwise-resolved row",
         "[agent][discovery_parsers]") {
    using yuzu::discovery::is_resolved_arp_row;
    using yuzu::discovery::kNlnsReachable;

    // < 6 bytes: not a full Ethernet MAC (e.g. a still-resolving or
    // non-Ethernet link-layer address) — must be rejected even though the
    // state itself is Reachable.
    CHECK_FALSE(is_resolved_arp_row(kNlnsReachable, 5));
    CHECK_FALSE(is_resolved_arp_row(kNlnsReachable, 0));
    // Boundary: exactly 6 is the minimum accepted, and longer (e.g. a
    // hypothetical 8-byte FireWire EUI-64) is not rejected on length alone.
    CHECK(is_resolved_arp_row(kNlnsReachable, 6));
    CHECK(is_resolved_arp_row(kNlnsReachable, 8));
}

TEST_CASE("is_resolved_arp_row: the state mirror values match NL_NEIGHBOR_STATE's documented ABI",
         "[agent][discovery_parsers]") {
    // Pins the numeric values discovery_plugin.cpp's _WIN32 static_asserts
    // also pin against the real enum — a divergence here would silently
    // make every test above assert against the wrong integers.
    CHECK(yuzu::discovery::kNlnsUnreachable == 0);
    CHECK(yuzu::discovery::kNlnsIncomplete == 1);
    CHECK(yuzu::discovery::kNlnsProbe == 2);
    CHECK(yuzu::discovery::kNlnsDelay == 3);
    CHECK(yuzu::discovery::kNlnsStale == 4);
    CHECK(yuzu::discovery::kNlnsReachable == 5);
    CHECK(yuzu::discovery::kNlnsPermanent == 6);
    CHECK(yuzu::discovery::kNlnsMaximum == 7);
}
