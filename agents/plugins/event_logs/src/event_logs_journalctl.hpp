#pragma once

// event_logs_journalctl.hpp -- pure outcome classifier for the Linux rung-2
// `journalctl` argv fallback (Wave-4 PR4.2).
//
// Deliberately the same shape as event_logs_macos.hpp's
// classify_log_show_result: a free function over a SubprocessResult, no I/O of
// its own, so every reachable (termination_reason, exit_code, timed_out)
// combination is fixture-testable on every host. The Linux leg previously made
// this decision inline in event_logs_plugin.cpp's anonymous namespace, where it
// could not be tested -- and an untested inline version shipped two successive
// honesty holes (a missing exit-code check, then a missing signal check) before
// this header existed. The classifier is the tested part; the shell just emits
// what it returns.

#include <string_view>

#include <yuzu/agent/subprocess_runner.hpp>

namespace yuzu::event_logs_journalctl {

enum class FallbackOutcome {
    ok,          // Ran to completion, or stopped at the deliberate line cap.
                 // result.lines (possibly empty) is the whole honest picture.
    constrained, // Deadline/cancel: what was collected is real but incomplete.
    unavailable, // Never ran, died on a signal, or exited nonzero -- the event
                 // data is UNKNOWN and must never be reported as "no events".
};

// `outcome == ok` carries an empty reason; the other two carry sentinel text.
struct FallbackClassification {
    FallbackOutcome outcome = FallbackOutcome::ok;
    std::string_view reason;
};

// Order is load-bearing; see each comment.
inline FallbackClassification
classify_journalctl_result(const yuzu::agent::SubprocessResult& result) {
    // exec never got off the ground (journalctl absent on a non-systemd image).
    if (!result.tool_ran)
        return {FallbackOutcome::unavailable, "journalctl did not run"};

    // A stop_after_max_lines stop is the runner's DELIBERATE clean bound: it
    // kills the child at the cap, so exit_code keeps the -1 kill sentinel and
    // termination_reason is line_limit while timed_out stays false. This must
    // be tested BEFORE any exit-code or signal reasoning, or every busy host
    // (more matching lines than the cap) reports a false failure -- the same
    // defect the macOS classifier carried until this PR fixed it.
    if (result.termination_reason == yuzu::agent::TerminationReason::line_limit)
        return {FallbackOutcome::ok, {}};

    // deadline and cancelled both surface as timed_out with exit_code -1.
    if (result.timed_out)
        return {FallbackOutcome::constrained, "journalctl timed out (partial result)"};

    // A child that died from a signal it received ITSELF -- the kernel OOM
    // killer on a memory-pressured host, or a journalctl crash -- reports
    // termination_reason `signaled`, exit_code -1, timed_out false, tool_ran
    // true. A guard written as `exited && exit_code != 0` misses exactly this
    // state and the run reads as a clean empty log. Checked explicitly rather
    // than relying on the -1 sentinel so the intent survives the next edit.
    if (result.termination_reason == yuzu::agent::TerminationReason::signaled)
        return {FallbackOutcome::unavailable, "journalctl was killed by a signal"};


    // Ran and reported a real problem: no journal files, an ACL denial for a
    // process outside the systemd-journal group, an unsupported argument.
    if (result.exit_code != 0)
        return {FallbackOutcome::unavailable, "journalctl exited with an error"};

    // Checked AFTER the exit code, matching the macOS sibling's order: a run
    // that BOTH failed and was cut short is unavailable (the data is unknown),
    // not merely constrained (real-but-partial). The byte cap is independent of
    // max_lines and the deadline, so a child can exit cleanly having had its
    // capture cut short — a few very large entries reach 1 MB well inside the
    // line window — and those partial rows must not read as a complete result.
    if (result.output_truncated)
        return {FallbackOutcome::constrained, "journalctl output was truncated (partial result)"};

    return {FallbackOutcome::ok, {}};
}

} // namespace yuzu::event_logs_journalctl
