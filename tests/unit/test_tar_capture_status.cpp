/**
 * test_tar_capture_status.cpp -- fixture-fed tests for
 * tar_capture_status.hpp's classify_subprocess_capture(), the pure predicate
 * that decides whether a bounded-subprocess capture is complete enough to
 * diff/persist as authoritative TAR state (BR-001), and for
 * collect_or_retain(), the collect-or-retain seam every TAR snapshot-diff
 * source (service, mapdrive, arp) applies on top of that decision.
 *
 * No test here spawns a process, sleeps, or touches the network -- every
 * case feeds fixed tool_ran/timed_out/output_truncated/exit_code values
 * straight to the pure classifier, exactly the fields SubprocessResult
 * carries at runtime (agents/core/include/yuzu/agent/subprocess_runner.hpp),
 * or feeds collect_or_retain a fixture lambda that returns or throws on
 * demand in place of a real enumerate_arp()/enumerate_mapdrive() syscall.
 *
 * This suite exists specifically because the prior TAR test suites (BR-005,
 * round 1) exercised only parsed lines/blobs and never these SubprocessResult
 * status fields -- letting a partial-capture-persisted-as-complete bug pass
 * the whole green TAR suite. Every state SubprocessResult can report is
 * covered here: a clean complete run, spawn failure, deadline, output-cap
 * truncation, and non-zero exit -- both with the default zero_exit_required
 * policy and with it explicitly relaxed for a command whose documented
 * success path is legitimately non-zero.
 *
 * The "composed with compute_arp_events/compute_mapdrive_events" cases below
 * close the round-2 gap (BR-003): round 1 fixed the collect-or-retain
 * mechanism for service/mapdrive but never composed it through baseline
 * advancement in a test, so a native collector (ARP's three platform legs,
 * macOS getfsstat) could still fail to apply the SAME contract and pass
 * every existing suite -- exactly what happened (BR-001/BR-002). These
 * cases call the REAL production functions -- collect_or_retain and
 * compute_arp_events/compute_mapdrive_events, not a re-implementation --
 * across three simulated ticks (complete / incomplete / complete-again)
 * against a plain in-test "stored baseline" variable standing in for
 * db_->get_state/set_state, and assert the exact skip/retain/recover
 * behaviour: an incomplete tick computes NO events and never touches the
 * baseline, and the next complete tick then diffs against the RETAINED
 * (not reset) baseline.
 *
 * Round 3 additions close three more gaps found after Windows/Linux mapdrive
 * cap paths were found still silently truncating (B3-001) and the Windows
 * ARP cap check was found off-by-one (B3-004): would_exceed_cap is the
 * shared, platform-neutral cap-before-push decision every capped collector
 * loop now applies (exercised directly here since the Windows-only loops
 * that call it cannot run on this host -- B3-005); collect_or_retain now
 * catches only the dedicated IncompleteCaptureError type, not bare
 * std::exception, so a real allocation/programming failure is no longer
 * misreported as ordinary capture incompleteness (B3-003); and
 * snapshot_result_line is the `snapshot` action's honesty decision, tested
 * here as the action-level regression for B3-002.
 *
 * Round 4 additions close two more gaps found in round-4 review:
 * is_unexpected_enumeration_status is the shared, platform-neutral
 * "is this status one of the documented non-failure outcomes" decision the
 * Windows mapdrive WNet/NetSessionEnum legs now apply before throwing
 * IncompleteCaptureError, in place of the previous bare `rc != NO_ERROR`
 * checks that conflated unexpected failures with normal completion
 * (BR4-003) -- exercised directly here since those Windows-only call sites
 * cannot run on this host. snapshot_phase_outcome is the `snapshot`
 * action's SECOND honesty decision: it folds collect_fast_impl/
 * collect_slow_impl/do_collect_software's own return codes (an ordinary
 * persistence failure, not just a collect_or_retain skip) into the same
 * response, tested here as the action-level regression for BR4-001.
 */

#include "tar_capture_status.hpp"
#include "tar_collectors.hpp" // ArpEntry/ArpEvent, MapDriveEntry/MapDriveEvent, compute_arp_events, compute_mapdrive_events

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <vector>

using namespace yuzu::tar;

TEST_CASE("classify_subprocess_capture: a clean completed run is complete", "[tar_capture_status]") {
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/0);
    CHECK(status.complete);
    CHECK(status.reason.empty());
}

TEST_CASE("classify_subprocess_capture: spawn failure is incomplete", "[tar_capture_status]") {
    // Mirrors SubprocessResult's own contract: tool_ran=false means exec
    // itself never positively succeeded (missing binary, not executable,
    // etc) -- termination_reason == spawn_error at the runner level.
    auto status = classify_subprocess_capture(/*tool_ran=*/false, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/-1);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "spawn failed");
}

TEST_CASE("classify_subprocess_capture: a deadline kill is incomplete even if the child produced output",
          "[tar_capture_status]") {
    // A killed child can still have tool_ran=true (it ran and emitted some
    // output before being killed) -- timed_out is what actually disqualifies
    // it, exactly as subprocess_runner.hpp documents callers MUST check.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/true,
                                              /*output_truncated=*/false, /*exit_code=*/-1);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "deadline/cancelled");
}

TEST_CASE("classify_subprocess_capture: output-cap truncation is incomplete even on a clean exit",
          "[tar_capture_status]") {
    // The child can exit 0 and still have output_truncated=true if it wrote
    // past the byte cap before exiting -- the captured lines/output only
    // reflect what was captured before the cap, per SubprocessResult's own
    // contract, so this must not be treated as a genuine empty/short result.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/true, /*exit_code=*/0);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "output capped");
}

TEST_CASE("classify_subprocess_capture: non-zero exit is incomplete when zero-exit is required",
          "[tar_capture_status]") {
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/1);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "exit code 1");
}

TEST_CASE("classify_subprocess_capture: non-zero exit is tolerated when the caller opts out",
          "[tar_capture_status]") {
    // Precedent: this repo has been bitten by treating a documented
    // success-with-nonzero-exit tool (dnf check-update exits 100) as a
    // failure. No current TAR call site needs this today (systemctl,
    // launchctl, smbstatus, wevtutil, journalctl all verified/documented to
    // exit 0 on success -- see the call sites), but the escape hatch itself
    // must work correctly for the day one does.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/100,
                                              /*zero_exit_required=*/false);
    CHECK(status.complete);
    CHECK(status.reason.empty());
}

TEST_CASE("classify_subprocess_capture: timed_out takes priority over a reported exit code",
          "[tar_capture_status]") {
    // A deadline-killed child never reports a real exit_code (subprocess_runner.hpp
    // leaves it at the -1 sentinel) -- but even if a future runner change ever
    // reported one alongside timed_out=true, timed_out must still win: the
    // capture is not authoritative regardless of what exit_code says.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/true,
                                              /*output_truncated=*/false, /*exit_code=*/0);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "deadline/cancelled");
}

// ── collect_or_retain ────────────────────────────────────────────────────────

TEST_CASE("collect_or_retain: a successful collector's value is returned in current",
          "[tar_capture_status][collect_or_retain]") {
    auto res = collect_or_retain([]() -> std::vector<int> { return {1, 2, 3}; });
    REQUIRE(res.current);
    CHECK(*res.current == std::vector<int>{1, 2, 3});
    CHECK(res.skip_reason.empty());
}

TEST_CASE("collect_or_retain: a throwing collector yields no current and captures what()",
          "[tar_capture_status][collect_or_retain]") {
    auto res = collect_or_retain([]() -> std::vector<int> {
        throw IncompleteCaptureError("TAR: fixture incomplete capture");
    });
    CHECK_FALSE(res.current);
    CHECK(res.skip_reason == "TAR: fixture incomplete capture");
}

// round 3, B3-003: collect_or_retain now catches ONLY IncompleteCaptureError,
// not bare std::exception -- a real programming/allocation failure (modelled
// here by std::logic_error; the collector's `throw std::bad_alloc{}` would
// hit the identical path) must propagate OUT of collect_or_retain rather
// than being silently reinterpreted as ordinary capture incompleteness and
// swallowed. This is the exact defect B3-003 named: the previous bare
// `catch (const std::exception&)` could not tell "this capture legitimately
// didn't complete" apart from "an allocation just failed mid-collector".
TEST_CASE("collect_or_retain: a non-IncompleteCaptureError exception is NOT caught -- it "
          "propagates",
          "[tar_capture_status][collect_or_retain]") {
    REQUIRE_THROWS_AS(collect_or_retain([]() -> std::vector<int> {
                          throw std::logic_error("not a capture-incompleteness signal");
                      }),
                      std::logic_error);
}

// ── collect_or_retain composed with compute_arp_events / compute_mapdrive_events
// (BR-003) ────────────────────────────────────────────────────────────────────
//
// Each case below mirrors the EXACT composition at its tar_plugin.cpp call
// site (collect_fast_impl's arp leg / collect_slow_impl's mapdrive leg):
// `auto res = collect_or_retain(collector); if (res.current) { diff + advance
// stored_baseline; }` -- stored_baseline stands in for the
// db_->get_state/set_state pair a real tick reads/writes.

TEST_CASE("collect_or_retain + compute_arp_events: an incomplete tick emits no events and "
          "never touches the baseline; the next complete tick diffs against the RETAINED "
          "baseline and recovers cleanly",
          "[tar_capture_status][collect_or_retain][orchestration][arp]") {
    const ArpEntry a{.iface = "eth0",
                     .ip_address = "10.0.0.1",
                     .mac_address = "aa:aa:aa:aa:aa:aa",
                     .entry_type = "dynamic"};
    const ArpEntry b{.iface = "eth0",
                     .ip_address = "10.0.0.2",
                     .mac_address = "bb:bb:bb:bb:bb:bb",
                     .entry_type = "dynamic"};
    const ArpEntry c{.iface = "eth0",
                     .ip_address = "10.0.0.3",
                     .mac_address = "cc:cc:cc:cc:cc:cc",
                     .entry_type = "dynamic"};

    std::vector<ArpEntry> stored_baseline{a, b}; // seeded from a prior complete tick

    // Tick 1: complete capture, one genuine new neighbour (c) -- one
    // "appeared" event, baseline advances to {a, b, c}.
    {
        auto res = collect_or_retain([&]() -> std::vector<ArpEntry> { return {a, b, c}; });
        REQUIRE(res.current);
        auto events = compute_arp_events(stored_baseline, *res.current, /*timestamp=*/1000,
                                         /*snapshot_id=*/1);
        REQUIRE(events.size() == 1);
        CHECK(events[0].action == "appeared");
        CHECK(events[0].ip_address == "10.0.0.3");
        stored_baseline = *res.current;
    }
    REQUIRE(stored_baseline.size() == 3);

    // Tick 2: the collector throws -- the exact shape enumerate_arp() now
    // raises on a failed read, a kernel-truncated parse, or the entry cap
    // (BR-001). res.current is empty, so per the production `if (current)`
    // guard this mirrors, NEITHER compute_arp_events NOR a baseline write
    // may run for this tick -- nothing in this block performs either.
    {
        auto res = collect_or_retain([&]() -> std::vector<ArpEntry> {
            throw IncompleteCaptureError("TAR: arp entry cap 4096 reached");
        });
        REQUIRE_FALSE(res.current);
        CHECK(res.skip_reason == "TAR: arp entry cap 4096 reached");
    }
    // The baseline from the last COMPLETE tick is untouched -- still exactly
    // {a, b, c}, not {} and not a partial read.
    REQUIRE(stored_baseline.size() == 3);
    CHECK(stored_baseline[2].ip_address == "10.0.0.3");

    // Tick 3 (recovery): a complete read of the SAME table -- no real
    // topology change since tick 1. Diffing against the RETAINED baseline
    // must produce ZERO events. This is the assertion that actually
    // falsifies BR-001: had tick 2 replaced the baseline with {} (the
    // pre-fix behaviour), this diff would instead report three spurious
    // "appeared" events.
    {
        auto res = collect_or_retain([&]() -> std::vector<ArpEntry> { return {a, b, c}; });
        REQUIRE(res.current);
        auto events = compute_arp_events(stored_baseline, *res.current, /*timestamp=*/3000,
                                         /*snapshot_id=*/3);
        CHECK(events.empty());
        stored_baseline = *res.current;
    }
}

TEST_CASE("collect_or_retain + compute_mapdrive_events: an incomplete getfsstat tick emits no "
          "events and never touches the baseline; the next complete tick recovers cleanly",
          "[tar_capture_status][collect_or_retain][orchestration][mapdrive]") {
    const MapDriveEntry m1{.direction = "outbound",
                           .local_mount = "/Volumes/share1",
                           .remote_path = "//fileserver/share1",
                           .remote_host = "fileserver",
                           .username = "",
                           .provider = "SMB"};
    const MapDriveEntry m2{.direction = "outbound",
                           .local_mount = "/Volumes/share2",
                           .remote_path = "//fileserver/share2",
                           .remote_host = "fileserver",
                           .username = "",
                           .provider = "SMB"};
    const MapDriveEntry m3{.direction = "outbound",
                           .local_mount = "/Volumes/share3",
                           .remote_path = "//fileserver/share3",
                           .remote_host = "fileserver",
                           .username = "",
                           .provider = "NFS"};

    std::vector<MapDriveEntry> stored_baseline{m1, m2}; // seeded from a prior complete tick

    // Tick 1: complete capture, one new mount (m3) mounted since the baseline.
    {
        auto res = collect_or_retain([&]() -> std::vector<MapDriveEntry> { return {m1, m2, m3}; });
        REQUIRE(res.current);
        auto events = compute_mapdrive_events(stored_baseline, *res.current, /*timestamp=*/1000,
                                              /*snapshot_id=*/1);
        REQUIRE(events.size() == 1);
        CHECK(events[0].action == "appeared");
        CHECK(events[0].local_mount == "/Volumes/share3");
        stored_baseline = *res.current;
    }
    REQUIRE(stored_baseline.size() == 3);

    // Tick 2: getfsstat failed (or the live snapshot exceeded the entry cap
    // -- BR-002). res.current is empty; neither the diff nor a baseline
    // write may run.
    {
        auto res = collect_or_retain([&]() -> std::vector<MapDriveEntry> {
            throw IncompleteCaptureError("TAR: getfsstat failed");
        });
        REQUIRE_FALSE(res.current);
        CHECK(res.skip_reason == "TAR: getfsstat failed");
    }
    // Baseline from the last COMPLETE tick is untouched -- still {m1, m2, m3},
    // not {} (which would otherwise record all three mounts as `removed`).
    REQUIRE(stored_baseline.size() == 3);
    CHECK(stored_baseline[2].local_mount == "/Volumes/share3");

    // Tick 3 (recovery): a complete read of the SAME mount table diffed
    // against the RETAINED baseline must produce ZERO events -- had tick 2
    // instead replaced the baseline with {}, this diff would report three
    // spurious "appeared" events (the exact BR-002 scenario: "stores every
    // mount as removed... stores them all as appeared on recovery").
    {
        auto res = collect_or_retain([&]() -> std::vector<MapDriveEntry> { return {m1, m2, m3}; });
        REQUIRE(res.current);
        auto events = compute_mapdrive_events(stored_baseline, *res.current, /*timestamp=*/3000,
                                              /*snapshot_id=*/3);
        CHECK(events.empty());
        stored_baseline = *res.current;
    }
}

// ── would_exceed_cap (round 3, B3-004/B3-005) ───────────────────────────────
//
// The single decision every capped collector loop must apply BEFORE
// appending a candidate row. Pure and compiled on every platform, unlike the
// #ifdef-gated Windows ARP / Windows mapdrive (WNet outbound,
// NetSessionEnum inbound) loops that now call it -- so this exact boundary
// is exercised directly here, even though this host cannot run those loops'
// surrounding Win32 I/O.

TEST_CASE("would_exceed_cap: false below the cap, true at and above it",
          "[tar_capture_status][cap]") {
    CHECK_FALSE(would_exceed_cap(0, 3));
    CHECK_FALSE(would_exceed_cap(2, 3));
    CHECK(would_exceed_cap(3, 3));  // AT the cap -- one more would exceed it
    CHECK(would_exceed_cap(4, 3));
}

TEST_CASE("would_exceed_cap drives a check-before-push loop correctly at the exact-cap "
          "boundary -- B3-004 regression",
          "[tar_capture_status][cap]") {
    // Simulates the fixed collector loop shape (Windows ARP's push loop,
    // Windows mapdrive's enum_wnet_outbound/collect_sessions): test capacity
    // BEFORE constructing/appending the candidate, so only a genuine
    // (cap+1)-th candidate establishes truncation. The pre-fix shape
    // (push, THEN check size >= cap) declared an EXACT-cap table truncated,
    // discarding a complete snapshot forever -- this is the case that
    // regression covers.
    auto simulate = [](std::size_t candidates, std::size_t cap) {
        std::vector<int> out;
        bool truncated = false;
        for (std::size_t i = 0; i < candidates; ++i) {
            if (would_exceed_cap(out.size(), cap)) {
                truncated = true;
                break;
            }
            out.push_back(static_cast<int>(i));
        }
        return std::pair{out.size(), truncated};
    };

    // Exactly `cap` candidates: every one fits -- must NOT be truncated.
    auto [size_exact, trunc_exact] = simulate(/*candidates=*/3, /*cap=*/3);
    CHECK(size_exact == 3);
    CHECK_FALSE(trunc_exact);

    // cap+1 candidates: the (cap+1)-th is refused -- truncated, and the kept
    // size is still exactly the cap (nothing beyond it was appended).
    auto [size_over, trunc_over] = simulate(/*candidates=*/4, /*cap=*/3);
    CHECK(size_over == 3);
    CHECK(trunc_over);

    // Well under cap: never truncated.
    auto [size_under, trunc_under] = simulate(/*candidates=*/1, /*cap=*/3);
    CHECK(size_under == 1);
    CHECK_FALSE(trunc_under);
}

// ── snapshot_result_line (round 3, B3-002) ──────────────────────────────────
//
// do_snapshot's (tar_plugin.cpp) sole honesty decision: given the names of
// every enabled source collect_or_retain skipped this pass, produce the
// exact response line the `snapshot` action writes. Previously the action
// unconditionally wrote "tar|snapshot|complete" even when arp/service/
// mapdrive was classified incomplete and silently skipped; this is the
// action-level regression test for that defect, exercised through the real
// production function (not a re-implementation) without standing up a live
// TarPlugin/CommandContext/database.

TEST_CASE("snapshot_result_line: no skipped sources reports complete",
          "[tar_capture_status][snapshot]") {
    CHECK(snapshot_result_line({}) == "tar|snapshot|complete");
}

TEST_CASE("snapshot_result_line: one skipped source reports partial with its name",
          "[tar_capture_status][snapshot]") {
    CHECK(snapshot_result_line({"arp"}) == "tar|snapshot|partial|arp");
}

TEST_CASE("snapshot_result_line: multiple skipped sources are comma-joined, order preserved",
          "[tar_capture_status][snapshot]") {
    CHECK(snapshot_result_line({"arp", "service", "mapdrive"}) ==
          "tar|snapshot|partial|arp,service,mapdrive");
}

// ── is_unexpected_enumeration_status (BR4-003, round 4) ─────────────────────
//
// tar_mapdrive_collector.cpp's Windows legs (enum_wnet_outbound,
// enum_netsession_inbound) previously conflated any unexpected WNet/
// NetSessionEnum status with normal enumeration completion -- a bare
// `if (rc != NO_ERROR) break/return` treated a transient provider/transport
// failure the same as "table exhausted, zero more rows", letting a partial
// outbound/inbound map set silently replace the last complete baseline.
// This predicate is the exact decision those call sites now apply before
// throwing IncompleteCaptureError; it's exercised here with plain integer
// status codes standing in for the real WNetOpenEnumW / WNetEnumResourceW /
// NetSessionEnum results those Windows-only (_WIN32-gated, uncompiled on
// this host) call sites would produce -- open failure, mid-enumeration
// failure, and session-enumeration failure are the three BR4-003 explicitly
// calls out, and each is one of the cases below.

TEST_CASE("is_unexpected_enumeration_status: WNetOpenEnumW open failure",
          "[tar_capture_status][enumeration]") {
    constexpr unsigned long kNoError = 0;
    constexpr unsigned long kErrorNotConnected = 2250; // real WNet transport failure code
    // Clean open: NO_ERROR is the only acceptable status at this call site.
    CHECK_FALSE(is_unexpected_enumeration_status(kNoError, {kNoError}));
    // Open failure: any other status must NOT be treated as a benign
    // "no connected resources" empty result.
    CHECK(is_unexpected_enumeration_status(kErrorNotConnected, {kNoError}));
}

TEST_CASE("is_unexpected_enumeration_status: WNetEnumResourceW mid-enumeration failure",
          "[tar_capture_status][enumeration]") {
    constexpr unsigned long kNoError = 0;
    constexpr unsigned long kErrorNoMoreItems = 259;
    constexpr unsigned long kErrorNetworkBusy = 54; // real mid-enumeration transport failure
    // NO_ERROR (more rows this page) and ERROR_NO_MORE_ITEMS (genuinely
    // exhausted) are both acceptable outcomes at this call site.
    CHECK_FALSE(is_unexpected_enumeration_status(kNoError, {kNoError, kErrorNoMoreItems}));
    CHECK_FALSE(is_unexpected_enumeration_status(kErrorNoMoreItems, {kNoError, kErrorNoMoreItems}));
    // Any other status mid-enumeration is an unexpected failure, not a
    // documented "table exhausted" terminal code.
    CHECK(is_unexpected_enumeration_status(kErrorNetworkBusy, {kNoError, kErrorNoMoreItems}));
}

TEST_CASE("is_unexpected_enumeration_status: NetSessionEnum session-enumeration failure",
          "[tar_capture_status][enumeration]") {
    constexpr unsigned long kNerrSuccess = 0;
    constexpr unsigned long kErrorAccessDenied = 5;   // handled separately by the caller
    constexpr unsigned long kErrorInvalidLevel = 124; // real unexpected session-enum failure
    // A clean NetSessionEnum page is acceptable at this call site.
    CHECK_FALSE(is_unexpected_enumeration_status(kNerrSuccess, {kNerrSuccess}));
    // ERROR_ACCESS_DENIED is NOT in the acceptable set here deliberately --
    // the caller (enum_netsession_inbound) checks and handles it BEFORE
    // reaching this predicate, as its own documented constrained-empty
    // outcome, so it is exercised as "unexpected" from this predicate's own
    // narrow point of view.
    CHECK(is_unexpected_enumeration_status(kErrorAccessDenied, {kNerrSuccess}));
    // A genuinely unexpected session-enumeration failure.
    CHECK(is_unexpected_enumeration_status(kErrorInvalidLevel, {kNerrSuccess}));
}

// ── snapshot_phase_outcome (BR4-001, round 4) ────────────────────────────────
//
// do_snapshot's (tar_plugin.cpp) SECOND honesty decision: fold the three
// per-phase return codes collect_fast_impl/collect_slow_impl/
// do_collect_software produce into the phase names added to
// skipped_sources and the action's own return code. Previously those three
// return values were discarded (bare expression statements), so an
// ordinary persistence failure inside any of them -- injected here as a
// fixture return code standing in for db_->insert_*_events() returning
// false -- still produced "tar|snapshot|complete" / rc 0. TarPlugin is
// translation-unit-local (tar_plugin.cpp) and cannot be constructed from
// tests/unit/*.cpp, so this is the real production aggregation function
// do_snapshot calls, exercised directly with fixture return codes standing
// in for a failed collect_fast_impl/collect_slow_impl/do_collect_software
// call (e.g. from an injected failing database write) rather than a
// re-implementation.

TEST_CASE("snapshot_phase_outcome: all phases succeed reports no failures, rc 0",
          "[tar_capture_status][snapshot]") {
    const auto out = snapshot_phase_outcome(/*fast_rc=*/0, /*slow_rc=*/0, /*software_rc=*/0);
    CHECK(out.failed_phases.empty());
    CHECK(out.return_code == 0);
}

TEST_CASE("snapshot_phase_outcome: a failed collect_fast_impl (e.g. injected insert failure) "
          "is reported and fails the action",
          "[tar_capture_status][snapshot]") {
    const auto out = snapshot_phase_outcome(/*fast_rc=*/1, /*slow_rc=*/0, /*software_rc=*/0);
    REQUIRE(out.failed_phases.size() == 1);
    CHECK(out.failed_phases[0] == "collect_fast");
    CHECK(out.return_code == 1);
}

TEST_CASE("snapshot_phase_outcome: a failed collect_slow_impl (e.g. the BR4-001 service-insert "
          "scenario) is reported and fails the action",
          "[tar_capture_status][snapshot]") {
    const auto out = snapshot_phase_outcome(/*fast_rc=*/0, /*slow_rc=*/1, /*software_rc=*/0);
    REQUIRE(out.failed_phases.size() == 1);
    CHECK(out.failed_phases[0] == "collect_slow");
    CHECK(out.return_code == 1);
}

TEST_CASE("snapshot_phase_outcome: a failed do_collect_software is reported and fails the "
          "action",
          "[tar_capture_status][snapshot]") {
    const auto out = snapshot_phase_outcome(/*fast_rc=*/0, /*slow_rc=*/0, /*software_rc=*/1);
    REQUIRE(out.failed_phases.size() == 1);
    CHECK(out.failed_phases[0] == "software");
    CHECK(out.return_code == 1);
}

TEST_CASE("snapshot_phase_outcome: multiple failed phases are all reported, call order "
          "preserved, and compose with snapshot_result_line",
          "[tar_capture_status][snapshot]") {
    const auto out = snapshot_phase_outcome(/*fast_rc=*/1, /*slow_rc=*/1, /*software_rc=*/1);
    REQUIRE(out.failed_phases.size() == 3);
    CHECK(out.failed_phases[0] == "collect_fast");
    CHECK(out.failed_phases[1] == "collect_slow");
    CHECK(out.failed_phases[2] == "software");
    CHECK(out.return_code == 1);

    // Composed exactly as do_snapshot composes it: an arp precollection
    // skip (collect_or_retain path) PLUS a phase failure both surface in
    // the one response line an operator/agentic consumer reads.
    std::vector<std::string> skipped_sources{"arp"};
    skipped_sources.insert(skipped_sources.end(), out.failed_phases.begin(),
                           out.failed_phases.end());
    CHECK(snapshot_result_line(skipped_sources) ==
          "tar|snapshot|partial|arp,collect_fast,collect_slow,software");
}

// ── snapshot_phase_outcome: has_earlier_skips (round 5, adversarial-review) ──
//
// A collect_or_retain skip (arp/service/mapdrive) leaves every phase rc at 0
// -- it is not a persistence failure, so fast_rc/slow_rc/software_rc alone
// cannot see it. Previously the action's own return code came ONLY from
// those three integers, so a forced snapshot that silently retained one of
// those sources' stale baseline still reported rc 0 -- a clean SUCCESS at
// the wire level -- even though the text line said "partial". A generic/
// MCP/automation consumer reading only the return code (not the text line)
// could not tell. has_earlier_skips closes that gap.

TEST_CASE("snapshot_phase_outcome: no phase failures and no earlier skips reports rc 0",
          "[tar_capture_status][snapshot]") {
    const auto out =
        snapshot_phase_outcome(/*fast_rc=*/0, /*slow_rc=*/0, /*software_rc=*/0,
                               /*has_earlier_skips=*/false);
    CHECK(out.failed_phases.empty());
    CHECK(out.return_code == 0);
}

TEST_CASE("snapshot_phase_outcome: an earlier collect_or_retain skip (e.g. arp) with all three "
          "phase rcs clean still fails the action -- a partial snapshot must never report "
          "success at the return-code level",
          "[tar_capture_status][snapshot]") {
    const auto out =
        snapshot_phase_outcome(/*fast_rc=*/0, /*slow_rc=*/0, /*software_rc=*/0,
                               /*has_earlier_skips=*/true);
    CHECK(out.failed_phases.empty()); // no NEW phase failure -- the skip predates this call
    CHECK(out.return_code == 1);      // but the action-level result is still non-zero
}

TEST_CASE("snapshot_phase_outcome: an earlier skip composes with a genuine phase failure -- "
          "still exactly one failing return code, and the failed_phases list is unaffected",
          "[tar_capture_status][snapshot]") {
    const auto out =
        snapshot_phase_outcome(/*fast_rc=*/1, /*slow_rc=*/0, /*software_rc=*/0,
                               /*has_earlier_skips=*/true);
    REQUIRE(out.failed_phases.size() == 1);
    CHECK(out.failed_phases[0] == "collect_fast");
    CHECK(out.return_code == 1);
}
