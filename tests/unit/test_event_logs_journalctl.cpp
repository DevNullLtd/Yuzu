/**
 * test_event_logs_journalctl.cpp -- Wave-4 PR4.2 adversarial-review
 * remediation. Fixture tests for the pure Linux rung-2 fallback classifier
 * (event_logs_journalctl.hpp).
 *
 * This file exists because the equivalent decision previously lived inline in
 * event_logs_plugin.cpp's anonymous namespace, where nothing could reach it --
 * and it shipped two successive honesty holes there: first no exit-code check
 * at all (a nonzero journalctl read as "no events"), then an `exited &&
 * exit_code != 0` guard that still missed a signal-killed child. Both are
 * pinned below.
 *
 * Runs on EVERY host: the classifier is pure and depends only on the
 * SubprocessResult value type, exactly like test_event_logs_macos.cpp's
 * coverage of the macOS `log show` classifier.
 */
#include <catch2/catch_test_macros.hpp>

#include <iterator> // std::size (enum/table binding static_assert)

#include "../../agents/plugins/event_logs/src/event_logs_journalctl.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

using namespace yuzu::event_logs_journalctl;
using yuzu::agent::SubprocessResult;
using yuzu::agent::TerminationReason;

namespace {

// A journalctl run that completed normally with rows.
SubprocessResult ok_result() {
    SubprocessResult r;
    r.tool_ran = true;
    r.exit_code = 0;
    r.timed_out = false;
    r.termination_reason = TerminationReason::exited;
    r.lines = {"2026-08-24T09:15:02+0100 host unit[12]: something happened"};
    return r;
}

} // namespace

TEST_CASE("classify_journalctl_result: a clean exit is ok", "[event_logs][journalctl]") {
    auto c = classify_journalctl_result(ok_result());
    CHECK(c.outcome == FallbackOutcome::ok);
    CHECK(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: an empty clean exit is still ok, not a failure",
          "[event_logs][journalctl]") {
    // A host genuinely free of matching entries. This is the ONE case where
    // "no events found" is the truth, and it must stay distinguishable from
    // every failure below.
    auto r = ok_result();
    r.lines.clear();
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::ok);
    CHECK(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: journalctl absent is unavailable",
          "[event_logs][journalctl]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.exit_code = -1;
    r.termination_reason = TerminationReason::spawn_error;
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::unavailable);
    CHECK_FALSE(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: a nonzero exit is unavailable, never clean-empty",
          "[event_logs][journalctl]") {
    // The first honesty hole: no journal files, or an ACL denial for a process
    // outside the systemd-journal group. journalctl exits nonzero with no
    // stdout; the pre-remediation code emitted "No error events found" rc 0.
    //
    // This mapping is only SAFE because the query leg no longer passes
    // `--grep`: verified against a live journald (systemd 257), a `--grep` that
    // matches nothing also exits 1, so with --grep in play this same rule would
    // report every ordinary empty search as an acquisition failure. The filter
    // is applied in-process instead, and `-p err` on an empty result exits 0
    // (also verified), so a nonzero exit here is unambiguously a failure.
    auto r = ok_result();
    r.lines.clear();
    r.exit_code = 1;
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::unavailable);
    CHECK_FALSE(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: a byte-cap truncation is constrained, not a clean ok",
          "[event_logs][journalctl]") {
    // The runner's output byte cap is independent of max_lines and the
    // deadline, so a child can exit cleanly having had its capture cut short —
    // a few very large entries (a kernel oops, a unit dump) reach the cap well
    // inside 500 lines. Reporting that as ok emits partial rows as a complete
    // result with no way for the caller to tell. The macOS sibling classifier
    // checks the same flag; the two must not disagree.
    auto r = ok_result();
    r.output_truncated = true;
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::constrained);
    CHECK_FALSE(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: a signal-killed child is unavailable, never clean-empty",
          "[event_logs][journalctl]") {
    // The SECOND honesty hole, and the reason this classifier is a tested pure
    // function rather than an inline branch. The kernel OOM killer SIGKILLs
    // journalctl on a memory-pressured host (or it crashes): tool_ran stays
    // true, timed_out stays false, exit_code keeps the -1 sentinel, and
    // termination_reason is `signaled`. A guard written as
    // `exited && exit_code != 0` is FALSE here, so the run fell through to the
    // clean "no events" sentinel and told the operator the host was healthy.
    auto r = ok_result();
    r.lines.clear();
    r.exit_code = -1;
    r.timed_out = false;
    r.termination_reason = TerminationReason::signaled;
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::unavailable);
    CHECK_FALSE(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: a line_limit stop is a clean bounded ok",
          "[event_logs][journalctl]") {
    // stop_after_max_lines is set on this call, so a busy host is killed at the
    // cap: exit_code keeps the -1 sentinel by contract while timed_out stays
    // false. Classifying on exit_code alone would report every busy host as
    // unavailable -- the defect this PR fixed on the macOS classifier.
    auto r = ok_result();
    r.exit_code = -1;
    r.timed_out = false;
    r.termination_reason = TerminationReason::line_limit;
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::ok);
    CHECK(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: a deadline stop is constrained, not unavailable",
          "[event_logs][journalctl]") {
    auto r = ok_result();
    r.exit_code = -1;
    r.timed_out = true;
    r.termination_reason = TerminationReason::deadline;
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::constrained);
    CHECK_FALSE(c.reason.empty());
}

TEST_CASE("classify_journalctl_result: a cancelled run is constrained",
          "[event_logs][journalctl]") {
    auto r = ok_result();
    r.exit_code = -1;
    r.timed_out = true;
    r.termination_reason = TerminationReason::cancelled;
    auto c = classify_journalctl_result(r);
    CHECK(c.outcome == FallbackOutcome::constrained);
}

TEST_CASE("classify_journalctl_result: line_limit wins over a stale nonzero exit code",
          "[event_logs][journalctl]") {
    // Ordering pin: the deliberate bound is decided BEFORE any exit-code
    // reasoning, so reordering the classifier fails here.
    auto r = ok_result();
    r.exit_code = 143; // SIGTERM-shaped, as a kill can leave behind
    r.timed_out = false;
    r.termination_reason = TerminationReason::line_limit;
    CHECK(classify_journalctl_result(r).outcome == FallbackOutcome::ok);
}

TEST_CASE("classify_journalctl_result: every reachable termination reason is decided",
          "[event_logs][journalctl]") {
    // Whole-contract sweep: no reachable state may fall through to a silent
    // ok-with-no-rows that an operator would read as "this host is healthy".
    struct Case {
        TerminationReason reason;
        int exit_code;
        bool timed_out;
        bool tool_ran;
        FallbackOutcome expected;
    };
    const Case cases[] = {
        {TerminationReason::spawn_error, -1, false, false, FallbackOutcome::unavailable},
        {TerminationReason::exited, 0, false, true, FallbackOutcome::ok},
        {TerminationReason::exited, 1, false, true, FallbackOutcome::unavailable},
        {TerminationReason::signaled, -1, false, true, FallbackOutcome::unavailable},
        {TerminationReason::deadline, -1, true, true, FallbackOutcome::constrained},
        {TerminationReason::cancelled, -1, true, true, FallbackOutcome::constrained},
        {TerminationReason::line_limit, -1, false, true, FallbackOutcome::ok},
    };
    // Binds the table to the enum: a 7th TerminationReason would otherwise be
    // added upstream, fall through the classifier's if-chain to the exit-code
    // branch, and escape this sweep silently. `line_limit` and `spawn_error`
    // are the last two enumerators, so this also pins that nothing was
    // appended after them without updating the cases above.
    static_assert(static_cast<int>(TerminationReason::spawn_error) == 5,
                  "TerminationReason gained an enumerator — add it to `cases` above and "
                  "give classify_journalctl_result an explicit arm for it.");
    static_assert(std::size(cases) == 7, "one case per reachable state, exited counted twice");
    for (const auto& c : cases) {
        SubprocessResult r;
        r.tool_ran = c.tool_ran;
        r.exit_code = c.exit_code;
        r.timed_out = c.timed_out;
        r.termination_reason = c.reason;
        CHECK(classify_journalctl_result(r).outcome == c.expected);
    }
}
