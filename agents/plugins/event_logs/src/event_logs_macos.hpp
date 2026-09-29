#pragma once

// event_logs_macos.hpp -- pure `log show` SubprocessResult -> (rows, rc)
// decision for the event_logs plugin's macOS "errors" and "query" actions
// (BR-08).
//
// event_logs_plugin.cpp's macOS branches previously checked ONLY
// result.timed_out before falling back to "result.lines.empty() -> rc-0
// none found" -- so a `log show` that never ran (missing from PATH), exited
// non-zero, or hit the internal output-truncation cap was silently reported
// as an honest empty search, indistinguishable from a genuine one.
//
// decide_log_show_output() is the single decision point both actions'
// macOS branches call: given an already-captured yuzu::agent::SubprocessResult
// plus the action's row prefix ("error"/"event") and its clean-empty message
// text, it returns the EXACT output rows to emit (already formatted in the
// plugin's existing pipe-delimited shape) and the return code -- the plugin
// shell does nothing but call this and emit what it returns.
//
// Never spawns a process -- the plugin owns the run_bounded_subprocess call
// and hands this header the already-captured result, so the decision is
// fixture-testable on every CI host without a macOS box or the real `log`
// binary.

#include "event_logs_parsers.hpp" // truncate_field, kMessageDisplayCap

#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::event_logs_macos {

namespace parsers = yuzu::event_logs_parsers;

// EX_NOPERM (sysexits.h): "you did not have sufficient permission to perform
// the operation." Empirically confirmed (darwin-guardian investigation,
// PR #3578) as the exit code `log show` returns when it cannot open the
// local unified-log data store at all -- distinct from a TCC/Full-Disk-
// Access redaction (which still succeeds, just with `<private>` fields).
// A differential probe on the CI host proved the axis is PRIVILEGE TIER, not
// FDA: a root headless daemon opens the store and returns real rows (exit 0);
// the identical predicate as the non-root, non-login-session CI service
// account gets EX_NOPERM every time, even with every FDA grant tried. A real
// login session (interactive or GUI) also opens the store, which is why this
// never reproduces on a developer's own Mac.
constexpr int kLogShowExitNoPerm = 77;

enum class LogShowOutcome {
    ok,                      // Completed normally; result.lines (possibly
                             // empty) is the whole honest picture -- callers
                             // may report rc 0.
    timed_out,               // Wall-clock deadline elapsed before `log show`
                             // finished.
    store_permission_denied, // `log show` ran and exited EX_NOPERM (77) --
                             // this process's privilege tier (non-root,
                             // no login session) cannot open the local log
                             // data store at all. NOT a code defect and NOT
                             // an FDA gap -- see docs/darwin-compat.md. The
                             // production agent runs as a root LaunchDaemon,
                             // so this never occurs there.
    unavailable,             // `log show` never ran, exited non-zero for some
                             // other reason, or its captured output was
                             // truncated -- distinguishable from a genuine
                             // empty search, never folded into it.
};

// `outcome == ok` carries an empty `reason`; `timed_out`/`unavailable`
// carry the sentinel-row message text appended after any partial lines.
struct LogShowClassification {
    LogShowOutcome outcome = LogShowOutcome::ok;
    std::string_view reason;
};

inline LogShowClassification
classify_log_show_result(const yuzu::agent::SubprocessResult& result) {
    if (result.timed_out)
        return {LogShowOutcome::timed_out, "log show timed out before completing"};

    // !tool_ran means exec() itself never got off the ground (log missing
    // from PATH, etc) -- an honest "unknown", never a fabricated empty
    // search.
    if (!result.tool_ran)
        return {LogShowOutcome::unavailable, "log show did not run"};

    // A stop_after_max_lines stop is the runner's documented DELIBERATE
    // clean bound (TerminationReason::line_limit -- "a clean bounded stop,
    // not a failure"): the child is killed after the cap, so exit_code
    // stays the -1 kill sentinel even though the collected lines are
    // exactly the bounded result the caller asked for. Classify it ok
    // BEFORE the exit-code check -- otherwise any Mac with more matching
    // log lines than the cap (the common case on a busy box) reports a
    // false "unavailable" + rc 1. Found by the Wave-4 PR4.2 action-
    // dispatch-level test driving the real plugin on real hardware.
    if (result.termination_reason == yuzu::agent::TerminationReason::line_limit)
        return {LogShowOutcome::ok, {}};

    // EX_NOPERM specifically means the log data store itself could not be
    // opened by this process's privilege tier -- distinguished from other
    // nonzero exits (bad predicate, etc) so callers can tell "this
    // environment structurally cannot do this" apart from "log show broke."
    if (result.exit_code == kLogShowExitNoPerm) {
        return {LogShowOutcome::store_permission_denied,
                "log show could not open the local log store (requires root or a "
                "login session -- see docs/darwin-compat.md)"};
    }

    // log show ran and reported some other real problem (bad predicate,
    // etc) -- a nonzero exit is never silently treated as "no matches".
    if (result.exit_code != 0)
        return {LogShowOutcome::unavailable, "log show exited with an error"};

    // Capture hit the internal sanity cap before log show finished --
    // whatever was collected is real, but incomplete, so it must not be
    // reported as the whole (possibly empty) picture.
    if (result.output_truncated)
        return {LogShowOutcome::unavailable, "log show output was truncated"};

    return {LogShowOutcome::ok, {}};
}

// The full row/rc decision both macOS branches emit unmodified.
struct LogShowDecision {
    std::vector<std::string> rows;
    int rc = 0;
};

// Formats one raw `log show --style compact` line into the plugin's
// "<row_prefix>|timestamp|process|message" shape (message capped at 200
// chars). Falls back to "<row_prefix>|line|-|line" when the compact
// double-space columns aren't present. Identical logic previously lived
// twice (do_errors' emit_error_line / do_query's emit_event_line) --
// row_prefix is the only thing that ever differed between them.
//
// timestamp/process/message are all attacker-influenceable (log show emits
// arbitrary process names and message text verbatim from whatever process
// wrote the entry) -- each is escaped via safe_output_field so a hostile
// '|' or embedded CR/LF can never inject an extra column or row into this
// pipe-delimited output. Escaping happens after the 200-char message cap
// (not before): capping the raw text first keeps the cap boundary from
// ever landing mid-escape-sequence, which would otherwise break the
// server's parity-based unescaper.
inline std::string format_log_show_line(std::string_view row_prefix, const std::string& line) {
    auto first_space = line.find("  ");
    if (first_space == std::string::npos) {
        auto safe_line = yuzu::util::safe_output_field(line);
        return std::format("{}|{}|-|{}", row_prefix, safe_line, safe_line);
    }

    auto timestamp = line.substr(0, first_space);
    auto rest = line.substr(first_space + 2);
    auto second_space = rest.find("  ");
    std::string process = "-";
    std::string message = rest;
    if (second_space != std::string::npos) {
        process = rest.substr(0, second_space);
        message = rest.substr(second_space + 2);
    }
    // Shared UTF-8-boundary-safe cap, not a raw substr: `log show` messages are
    // arbitrary UTF-8 and a byte cut can split a multi-byte character, which the
    // server's Postgres response store rejects — losing the whole result rather
    // than one character. The Windows and Linux rows go through the same helper;
    // one diff must not ship two answers to the same question.
    message = parsers::truncate_field(message, parsers::kMessageDisplayCap);
    return std::format("{}|{}|{}|{}", row_prefix, yuzu::util::safe_output_field(timestamp),
                        yuzu::util::safe_output_field(process),
                        yuzu::util::safe_output_field(message));
}

// The single SubprocessResult -> (rows, rc) decision for both macOS
// branches ("errors" passes row_prefix "error" + its "No error events
// found" message; "query" passes "event" + "No matching events found").
// Covers every case:
//   (a) timed_out              -> partial lines, then an honest timeout row, rc 1
//   (b) store_permission_denied -> partial lines, then an honest
//       "permission_denied" row, rc 1 (EX_NOPERM -- privilege-tier gap,
//       never occurs under the production root LaunchDaemon)
//   (c) unavailable            -> partial lines, then an honest unavailable
//       row, rc 1 (!tool_ran / other nonzero exit_code / output_truncated)
//   (d) ok + no lines          -> the clean-empty row, rc 0
//   (e) ok + lines             -> the formatted lines, rc 0
// The plugin shell's job is reduced to calling this and emitting what it
// returns -- it makes no rows/rc decision of its own.
inline LogShowDecision decide_log_show_output(const yuzu::agent::SubprocessResult& result,
                                               std::string_view row_prefix,
                                               std::string_view empty_message) {
    LogShowDecision decision;

    auto classification = classify_log_show_result(result);
    if (classification.outcome != LogShowOutcome::ok) {
        // Never masquerade a timeout, a missing/failing `log show`, or a
        // truncated capture as an empty success: emit whatever partial
        // lines were collected, then an honest incomplete-query row in the
        // same 4-column shape.
        for (const auto& line : result.lines)
            decision.rows.push_back(format_log_show_line(row_prefix, line));
        const char* tag;
        switch (classification.outcome) {
        case LogShowOutcome::timed_out:
            tag = "timeout";
            break;
        case LogShowOutcome::store_permission_denied:
            // Distinct, greppable tag (not folded into "unavailable") so a
            // caller -- the plugin's own action-dispatch test, in
            // particular -- can tell a privilege-tier environment gap apart
            // from a genuine acquisition regression without re-parsing
            // free-text reasons.
            tag = "permission_denied";
            break;
        default:
            tag = "unavailable";
            break;
        }
        decision.rows.push_back(
            std::format("{}|{}|-|{}", row_prefix, tag, classification.reason));
        decision.rc = 1;
        return decision;
    }

    if (result.lines.empty()) {
        decision.rows.push_back(std::format("{}|none|-|{}", row_prefix, empty_message));
        decision.rc = 0;
        return decision;
    }

    for (const auto& line : result.lines)
        decision.rows.push_back(format_log_show_line(row_prefix, line));
    decision.rc = 0;
    return decision;
}

} // namespace yuzu::event_logs_macos
