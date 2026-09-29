/**
 * test_tar_arp.cpp -- Unit tests for the `arp` capture source's non-Windows
 * legs (tar_arp_collector.cpp / tar_arp_parsers.hpp).
 *
 * The impure I/O (reading /proc/net/arp, the macOS NET_RT_FLAGS sysctl) is
 * platform-gated and NOT exercised here -- no test spawns a process or
 * touches a real /proc file. Coverage rides entirely on the PURE parsers,
 * fed fixture text/records, so it compiles and runs on every OS:
 *   - parse_proc_net_arp(): a real /proc/net/arp capture (below), plus
 *     synthetic malformed lines and a cap-truncation fixture appended to it.
 *   - arp_entry_from_route_record() (__APPLE__ only): route_sysctl_arp.hpp's
 *     own binary rt_msghdr parser is ITS tested concern
 *     (tests/unit/test_route_sysctl_arp.cpp); this only covers the thin
 *     {ip, mac} -> ArpEntry mapping layer this package adds on top, fed
 *     constructed records.
 *   - classify_arp_collection() / should_warn_ratelimited(): the
 *     failed-fetch, kernel-truncated-read, and over-cap warn decisions the
 *     macOS leg of enumerate_arp() makes, extracted to pure functions so
 *     they're directly assertable against fixture facts instead of only
 *     reachable through a live sysctl call.
 */

#include "tar_arp_parsers.hpp"
#include "tar_collectors.hpp" // yuzu::tar::enumerate_arp (Finding 4 live smoke test, __APPLE__ only)

#ifdef __APPLE__
#include <route_sysctl_arp.hpp>
#endif

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <sstream>
#include <string>
#include <vector>

using namespace yuzu::tar;

namespace {

// Real capture: `docker run --rm --cap-add=NET_ADMIN alpine:3.20 sh -c '...'`
// on this host (captured 2026-08-24; Docker Desktop for Mac's Linux VM,
// kernel "7.0.12-linuxkit #1 SMP PREEMPT ... aarch64", Alpine 3.20.10
// container). `cat /proc/net/arp` output preserved verbatim below (the
// column spacing is the kernel's arp_seq_show() padding, not reformatted).
//
// Three real neighbour states produced in that one run:
//   - `ping -c 2 -W 1 172.17.0.1` (the container's default gateway) once
//     -> resolved, dynamic (Flags 0x2 = ATF_COM)
//   - `ip neigh add 172.17.0.250 lladdr 02:42:ac:11:00:fa dev eth0 nud
//     permanent` -> resolved AND permanent (Flags 0x6 = ATF_PERM|ATF_COM)
//   - `ping -c 1 -W 1 172.17.0.253` (unused address on the same /16,
//     one shot, no reply) -> the kernel created the ARP request row before
//     any reply came back: unresolved, incomplete (Flags 0x0, all-zero MAC)
const std::string kRealProcNetArp =
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "172.17.0.1       0x1         0x2         ca:1a:64:cc:91:b6     *        eth0\n"
    "172.17.0.253     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    "172.17.0.250     0x1         0x6         02:42:ac:11:00:fa     *        eth0\n";

} // namespace

TEST_CASE("parse_proc_net_arp decodes the real captured /proc/net/arp text",
          "[tar][arp][parse]") {
    const auto parsed = parse_proc_net_arp(kRealProcNetArp);
    CHECK_FALSE(parsed.truncated);
    CHECK_FALSE(parsed.malformed); // BR4-005: a clean real capture is not malformed
    REQUIRE(parsed.entries.size() == 3);

    // Header row consumed, not emitted as a (malformed) entry.
    CHECK(parsed.entries[0].ip_address == "172.17.0.1");
    CHECK(parsed.entries[0].mac_address == "ca:1a:64:cc:91:b6");
    CHECK(parsed.entries[0].iface == "eth0");
    CHECK(parsed.entries[0].entry_type == "dynamic"); // ATF_COM only

    // Incomplete row (Flags 0x0, all-zero MAC) is KEPT, not dropped --
    // parity with the Windows leg reporting NlnsIncomplete rows rather than
    // skipping them.
    CHECK(parsed.entries[1].ip_address == "172.17.0.253");
    CHECK(parsed.entries[1].mac_address == "00:00:00:00:00:00");
    CHECK(parsed.entries[1].entry_type == "incomplete");

    // ATF_PERM (0x4) takes priority over ATF_COM even though both bits are
    // set (0x6 = 0x4|0x2): a static entry with a resolved MAC must read as
    // "static", not "dynamic".
    CHECK(parsed.entries[2].ip_address == "172.17.0.250");
    CHECK(parsed.entries[2].mac_address == "02:42:ac:11:00:fa");
    CHECK(parsed.entries[2].entry_type == "static");
}

TEST_CASE("parse_proc_net_arp flags malformed lines but keeps the valid rows around them for "
          "diagnostics -- BR4-005 (round 4)",
          "[tar][arp][parse]") {
    // BR4-005: a malformed row used to be silently skipped with no signal
    // that the table might be missing a real binding -- indistinguishable
    // from a genuinely smaller, complete table once diffed. The parser
    // still decodes every valid row around the junk (so a caller can log
    // what it saw), but now also sets `malformed`; it is the CALLER
    // (enumerate_arp(), tar_arp_collector.cpp) that turns that flag into an
    // IncompleteCaptureError throw rather than diffing/persisting the
    // subset as complete.
    const std::string text = kRealProcNetArp +
                              "too few columns\n"                                    // < 6 tokens
                              "\n"                                                    // blank line
                              "172.17.0.99 0x1 not_a_flag 00:00:00:00:00:00 * eth0\n" // Flags unparseable
                              "172.17.0.100 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n";      // valid, after the junk

    const auto parsed = parse_proc_net_arp(text);
    CHECK_FALSE(parsed.truncated);
    CHECK(parsed.malformed);
    // 3 real rows + the one trailing valid row; the 2 malformed lines are
    // dropped from `entries` (blank lines are not malformed at all — the
    // parser's own header/blank-skip runs before the malformed checks) but
    // don't stop the walk — the valid rows around them still decode.
    REQUIRE(parsed.entries.size() == 4);
    CHECK(parsed.entries[3].ip_address == "172.17.0.100");
    CHECK(parsed.entries[3].mac_address == "aa:bb:cc:dd:ee:ff");
    CHECK(parsed.entries[3].entry_type == "dynamic");
}

TEST_CASE("parse_proc_net_arp: a blank line alone does not set malformed -- BR4-005 (round 4)",
          "[tar][arp][parse]") {
    // Blank lines are ordinary formatting, not a missing binding — must not
    // trip the same incomplete-capture signal a real malformed row does.
    const auto parsed = parse_proc_net_arp(kRealProcNetArp + "\n\n");
    CHECK_FALSE(parsed.malformed);
    REQUIRE(parsed.entries.size() == 3);
}

TEST_CASE("parse_proc_net_arp caps at kArpEntryCap and sets truncated, using the named constant",
          "[tar][arp][parse]") {
    // kArpEntryCap + 1 synthetic rows appended to the real capture: proves
    // the parser's default cap argument is the SHARED tar_collectors.hpp
    // constant (never a hard-coded literal here), and that entries already
    // parsed before the cap (the 3 real rows) come back first, in order.
    std::ostringstream text;
    text << kRealProcNetArp;
    for (std::size_t i = 0; i < kArpEntryCap + 1; ++i)
        text << "10.0.0.99 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n";

    const auto parsed = parse_proc_net_arp(text.str());
    CHECK(parsed.truncated);
    REQUIRE(parsed.entries.size() == kArpEntryCap);
    CHECK(parsed.entries[0].ip_address == "172.17.0.1"); // real rows parsed first, kept
    CHECK(parsed.entries[1].ip_address == "172.17.0.253");
    CHECK(parsed.entries[2].ip_address == "172.17.0.250");
    CHECK(parsed.entries[3].ip_address == "10.0.0.99"); // synthetic rows fill the rest
}

TEST_CASE("parse_proc_net_arp: an under-cap table is not reported as truncated",
          "[tar][arp][parse]") {
    // Feeding a cap smaller than the real fixture's 3 rows still must not
    // mark a WHOLE, complete-under-that-cap table as partial; only feed a
    // custom cap here to prove the parameter is honoured independent of the
    // default -- the default-argument path is covered by the cap test above.
    const auto parsed = parse_proc_net_arp(kRealProcNetArp, /*cap=*/10);
    CHECK_FALSE(parsed.truncated);
    CHECK(parsed.entries.size() == 3);
}

// ── classify_arp_collection / should_warn_ratelimited ───────────────────────
//
// The macOS leg of enumerate_arp() (tar_arp_collector.cpp) makes three warn
// decisions from a fetch/parse result -- failed fetch, a kernel-truncated
// read, and an entry count over kArpEntryCap -- previously embedded directly
// in that impure function and untested. These fixture-fed cases exercise
// the extracted pure classify_arp_collection()/should_warn_ratelimited()
// functions directly; no sysctl call, process spawn, or sleep involved.

TEST_CASE("classify_arp_collection: a failed fetch reports fetch_failed and nothing else",
          "[tar][arp][classify]") {
    // parse_truncated/record_count are irrelevant once the fetch itself
    // failed -- pass values that would otherwise trip truncated/capped to
    // prove fetch_failed short-circuits them.
    const auto status = classify_arp_collection(/*fetch_ok=*/false, /*parse_truncated=*/true,
                                                  /*record_count=*/9999, /*cap=*/10);
    CHECK(status.fetch_failed);
    CHECK_FALSE(status.parse_truncated);
    CHECK_FALSE(status.capped);
}

TEST_CASE("classify_arp_collection: a successful, whole, under-cap read is clean",
          "[tar][arp][classify]") {
    const auto status = classify_arp_collection(/*fetch_ok=*/true, /*parse_truncated=*/false,
                                                  /*record_count=*/5, /*cap=*/10);
    CHECK_FALSE(status.fetch_failed);
    CHECK_FALSE(status.parse_truncated);
    CHECK_FALSE(status.capped);
}

TEST_CASE("classify_arp_collection: a kernel-truncated read is reported independent of the cap",
          "[tar][arp][classify]") {
    const auto status = classify_arp_collection(/*fetch_ok=*/true, /*parse_truncated=*/true,
                                                  /*record_count=*/5, /*cap=*/10);
    CHECK_FALSE(status.fetch_failed);
    CHECK(status.parse_truncated);
    CHECK_FALSE(status.capped); // 5 records, cap 10 -- under cap even though truncated
}

TEST_CASE("classify_arp_collection: a record count over the cap is capped",
          "[tar][arp][classify]") {
    const auto status = classify_arp_collection(/*fetch_ok=*/true, /*parse_truncated=*/false,
                                                  /*record_count=*/11, /*cap=*/10);
    CHECK_FALSE(status.fetch_failed);
    CHECK_FALSE(status.parse_truncated);
    CHECK(status.capped);
}

TEST_CASE("classify_arp_collection: a record count exactly at the cap is NOT capped",
          "[tar][arp][classify]") {
    // No entry was actually omitted at an exact match -- "capped" means a
    // valid entry was omitted, not merely that the count reached the cap.
    const auto status = classify_arp_collection(/*fetch_ok=*/true, /*parse_truncated=*/false,
                                                  /*record_count=*/10, /*cap=*/10);
    CHECK_FALSE(status.capped);
}

TEST_CASE("should_warn_ratelimited: warns only on the transition into true",
          "[tar][arp][classify]") {
    CHECK(should_warn_ratelimited(/*condition=*/true, /*previously_latched=*/false));
    CHECK_FALSE(should_warn_ratelimited(/*condition=*/true, /*previously_latched=*/true));
}

TEST_CASE("should_warn_ratelimited: never warns while the condition is false",
          "[tar][arp][classify]") {
    CHECK_FALSE(should_warn_ratelimited(/*condition=*/false, /*previously_latched=*/false));
    CHECK_FALSE(should_warn_ratelimited(/*condition=*/false, /*previously_latched=*/true));
}

TEST_CASE("should_warn_ratelimited: the latch clears and can warn again on the next occurrence",
          "[tar][arp][classify]") {
    // Simulates the collector's own exchange() sequence across three calls:
    // condition begins true (warn), clears (no warn, latch resets), then
    // returns true again -- the latch clearing must let it warn again
    // rather than staying suppressed forever.
    bool latched = false;
    CHECK(should_warn_ratelimited(true, latched));
    latched = true; // collector's exchange(true) after the warn above

    CHECK_FALSE(should_warn_ratelimited(false, latched));
    latched = false; // collector's exchange(false) once the condition clears

    CHECK(should_warn_ratelimited(true, latched));
}

#ifdef __APPLE__

TEST_CASE("arp_entry_from_route_record maps a route_sysctl_arp.hpp record onto ArpEntry",
          "[tar][arp][macos]") {
    // route_sysctl_arp.hpp's own binary rt_msghdr parser is exercised in
    // tests/unit/test_route_sysctl_arp.cpp; this covers only the thin
    // mapping layer this package adds on top of its already-decoded output.
    const yuzu::shared::ArpRecord rec{"192.168.1.50", "aa:bb:cc:dd:ee:ff"};
    const ArpEntry e = arp_entry_from_route_record(rec);

    CHECK(e.ip_address == "192.168.1.50");
    CHECK(e.mac_address == "aa:bb:cc:dd:ee:ff");
    // Constrained source: NET_RT_FLAGS/RTF_LLINFO distinguishes neither
    // static/permanent nor dynamic/stale/probe entries the way
    // GetIpNetTable2's NL_NEIGHBOR_STATE or /proc/net/arp's Flags column
    // do, so "unknown" is the honest token rather than a fabricated guess.
    CHECK(e.entry_type == "unknown");
    // yuzu::shared::ArpRecord carries no interface field for this mapping
    // to read.
    CHECK(e.iface.empty());
}

TEST_CASE("arp_entry_from_route_record maps every record independently, order preserved",
          "[tar][arp][macos]") {
    const std::vector<yuzu::shared::ArpRecord> records{
        {"10.0.0.1", "00:11:22:33:44:55"},
        {"10.0.0.2", "aa:aa:aa:aa:aa:aa"},
    };
    std::vector<ArpEntry> mapped;
    mapped.reserve(records.size());
    for (const auto& rec : records)
        mapped.push_back(arp_entry_from_route_record(rec));

    REQUIRE(mapped.size() == 2);
    CHECK(mapped[0].ip_address == "10.0.0.1");
    CHECK(mapped[0].mac_address == "00:11:22:33:44:55");
    CHECK(mapped[1].ip_address == "10.0.0.2");
    CHECK(mapped[1].mac_address == "aa:aa:aa:aa:aa:aa");
}

// ── enumerate_arp(): real macOS route-sysctl leg (Finding 4) ────────────────
//
// Everything above exercises only the pure parsers/mappers. No test called
// the real enumerate_arp() itself, so a regression in the native
// NET_RT_FLAGS/RTF_LLINFO sysctl leg (tar_arp_collector.cpp's __APPLE__
// branch) -- a wrong sysctl MIB, a broken rt_msghdr walk, a mishandled ENOMEM
// retry -- would still pass every test in this file. This is a live-host
// smoke test: it calls the REAL enumerate_arp() against this machine's
// actual kernel ARP/neighbour table and asserts only that it returns without
// throwing and the shape is sane -- no timing assumption, no process spawn,
// no network access (a route sysctl is a local kernel query, not a network
// call). This is the established exception in this codebase for real-OS-
// primitive verification (see this file's own header note on why the
// syscall itself isn't otherwise exercised, and tar_mapdrive.cpp's
// getfsstat-adjacent precedent) -- kept intentionally minimal so it stays
// fast and non-flaky regardless of what's actually in the host's ARP table
// at test time (empty is a legitimate, common result on a quiet host).
TEST_CASE("enumerate_arp (macOS route-sysctl leg): runs against the live "
          "host without throwing, entries are internally consistent",
          "[tar][arp][live]") {
    std::vector<ArpEntry> entries;
    REQUIRE_NOTHROW(entries = enumerate_arp());

    for (const auto& e : entries) {
        // macOS leg fixes entry_type == "unknown" and iface == "" (see
        // arp_entry_from_route_record above) -- a real capture must match
        // that contract, and every entry must carry at least an IP.
        CHECK_FALSE(e.ip_address.empty());
        CHECK(e.entry_type == "unknown");
        CHECK(e.iface.empty());
    }
}

#endif // __APPLE__
