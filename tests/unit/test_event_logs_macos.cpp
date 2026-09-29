/**
 * test_event_logs_macos.cpp -- pure fixture vectors for
 * event_logs_macos.hpp's classify_log_show_result() and
 * decide_log_show_output() (BR-08).
 *
 * decide_log_show_output() is the single source of truth for the
 * SubprocessResult -> (rows, rc) decision both macOS branches
 * (event_logs_plugin.cpp's do_errors/do_query) call unmodified -- these
 * fixtures assert its rows+rc directly, covering the same honest-failure
 * cases classify_log_show_result() classifies.
 *
 * All fixtures are injected yuzu::agent::SubprocessResult values -- no real
 * `log show` (or any process) is ever spawned, so this runs on every CI
 * host regardless of platform.
 */

#include <catch2/catch_test_macros.hpp>

#include "event_logs_macos.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <cstddef>
#include <format>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::event_logs_macos;
using yuzu::agent::SubprocessResult;

namespace {

// Mirrors the server's parity-based pipe-delimited splitter locally (no
// server code linked into this pure-fixture test binary, no process
// spawned): splits on a '|' only when it is preceded by an EVEN number of
// consecutive backslashes -- an ODD run means the '|' is escaped data, not
// a column separator (see yuzu::util::safe_output_field's doc comment).
std::vector<std::string> split_pipe_delimited(const std::string& row) {
    std::vector<std::string> fields;
    std::string current;
    std::size_t backslash_run = 0;
    for (char c : row) {
        if (c == '\\') {
            current += c;
            ++backslash_run;
        } else if (c == '|' && backslash_run % 2 == 0) {
            fields.push_back(current);
            current.clear();
            backslash_run = 0;
        } else {
            current += c;
            backslash_run = 0;
        }
    }
    fields.push_back(current);
    return fields;
}

// Inverts yuzu::util::escape_pipes: "\|" -> "|" and "\\" -> "\", scanned
// left to right.
std::string unescape_field(const std::string& field) {
    std::string out;
    for (std::size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 1 < field.size() &&
            (field[i + 1] == '\\' || field[i + 1] == '|')) {
            out += field[i + 1];
            ++i;
        } else {
            out += field[i];
        }
    }
    return out;
}

} // namespace

TEST_CASE("classify_log_show_result: a clean run with no matches is honest ok",
         "[event_logs][macos]") {
    // log show ran to completion, exited 0, found nothing to report.
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {};

    auto classification = classify_log_show_result(result);
    CHECK(classification.outcome == LogShowOutcome::ok);
    CHECK(classification.reason.empty());
}

TEST_CASE("classify_log_show_result: a clean run with matches is honest ok",
         "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  something happened"};

    auto classification = classify_log_show_result(result);
    CHECK(classification.outcome == LogShowOutcome::ok);
    CHECK(classification.reason.empty());
}

TEST_CASE("classify_log_show_result: timed_out wins regardless of other fields, partial lines kept",
         "[event_logs][macos]") {
    // A killed child can still have tool_ran=true and captured partial
    // output -- timed_out must still be reported as a timeout, not folded
    // into ok or unavailable.
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = -1;
    result.timed_out = true;
    result.output_truncated = false;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  partial line before the deadline"};

    auto classification = classify_log_show_result(result);
    CHECK(classification.outcome == LogShowOutcome::timed_out);
    CHECK(classification.reason == "log show timed out before completing");
    // Partial lines are the caller's responsibility to flush; this
    // classifier never drops or mutates them.
    REQUIRE(result.lines.size() == 1);
}

TEST_CASE("classify_log_show_result: tool_ran=false is honest unavailable, never rc-0 none found",
         "[event_logs][macos]") {
    // exec() itself failed (log missing from PATH) -- must never be
    // reported as an empty search.
    SubprocessResult result;
    result.tool_ran = false;
    result.exit_code = -1;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {};

    auto classification = classify_log_show_result(result);
    CHECK(classification.outcome == LogShowOutcome::unavailable);
    CHECK(classification.reason == "log show did not run");
}

TEST_CASE("classify_log_show_result: a nonzero exit is honest unavailable, never rc-0 none found",
         "[event_logs][macos]") {
    // log show ran and reported a real problem (bad predicate, permission
    // denial, etc) -- lines.empty() here must not be mistaken for "no
    // matches".
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 1;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {};

    auto classification = classify_log_show_result(result);
    CHECK(classification.outcome == LogShowOutcome::unavailable);
    CHECK(classification.reason == "log show exited with an error");
}

TEST_CASE("classify_log_show_result: a line_limit stop is a clean bounded ok, not unavailable",
         "[event_logs][macos]") {
    // stop_after_max_lines fired: the runner killed the child DELIBERATELY
    // after collecting exactly the requested cap, so exit_code stays the -1
    // kill sentinel by SubprocessResult's contract ("NEVER fabricated to 0
    // for a signal-killed child") while timed_out and output_truncated stay
    // false. This is the runner's documented clean bound -- before the
    // Wave-4 PR4.2 fix it fell through to the exit_code!=0 branch and every
    // busy Mac (more matching lines than the cap) reported a false
    // "unavailable" + rc 1. Found by the action-dispatch-level test driving
    // the real plugin on real hardware.
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = -1;
    result.timed_out = false;
    result.output_truncated = false;
    result.termination_reason = yuzu::agent::TerminationReason::line_limit;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  line 1 of the requested cap",
                    "2026-07-20 12:00:01  kernel[0]  line 2 of the requested cap"};

    auto classification = classify_log_show_result(result);
    CHECK(classification.outcome == LogShowOutcome::ok);
    CHECK(classification.reason.empty());
}

TEST_CASE("decide_log_show_output: a line_limit stop emits its capped lines, rc 0",
         "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = -1;
    result.timed_out = false;
    result.output_truncated = false;
    result.termination_reason = yuzu::agent::TerminationReason::line_limit;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  first capped line",
                    "2026-07-20 12:00:01  syslogd[55]  second capped line"};

    for (auto [prefix, empty_message] :
         {std::pair{"error", "No error events found"},
          std::pair{"event", "No matching events found"}}) {
        auto decision = decide_log_show_output(result, prefix, empty_message);
        CHECK(decision.rc == 0);
        REQUIRE(decision.rows.size() == 2);
        CHECK(decision.rows[0] ==
              std::format("{}|2026-07-20 12:00:00|kernel[0]|first capped line", prefix));
        CHECK(decision.rows[1] ==
              std::format("{}|2026-07-20 12:00:01|syslogd[55]|second capped line", prefix));
    }
}

TEST_CASE("classify_log_show_result: output_truncated is honest unavailable even with lines/exit 0",
         "[event_logs][macos]") {
    // Capture hit the internal sanity cap before log show finished -- the
    // lines collected so far are real but incomplete, so this must not be
    // reported as the whole (possibly empty) picture.
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = true;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  line before the truncation cap"};

    auto classification = classify_log_show_result(result);
    CHECK(classification.outcome == LogShowOutcome::unavailable);
    CHECK(classification.reason == "log show output was truncated");
    REQUIRE(result.lines.size() == 1);
}

// ── decide_log_show_output: the plugin-facing rows/rc decision ────────────
//
// Every case below is exercised for BOTH the "errors" row shape
// (row_prefix "error", empty message "No error events found") and the
// "query" row shape (row_prefix "event", empty message "No matching events
// found") -- the two macOS branches' only difference.

TEST_CASE("decide_log_show_output: clean empty result is the honest none-found row, rc 0",
         "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {};

    auto errors_decision = decide_log_show_output(result, "error", "No error events found");
    CHECK(errors_decision.rc == 0);
    REQUIRE(errors_decision.rows.size() == 1);
    CHECK(errors_decision.rows[0] == "error|none|-|No error events found");

    auto query_decision = decide_log_show_output(result, "event", "No matching events found");
    CHECK(query_decision.rc == 0);
    REQUIRE(query_decision.rows.size() == 1);
    CHECK(query_decision.rows[0] == "event|none|-|No matching events found");
}

TEST_CASE("decide_log_show_output: normal results are formatted lines, rc 0",
         "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  something happened",
                     "2026-07-20 12:00:05  loginwindow[42]  a second line"};

    auto decision = decide_log_show_output(result, "error", "No error events found");
    CHECK(decision.rc == 0);
    REQUIRE(decision.rows.size() == 2);
    CHECK(decision.rows[0] == "error|2026-07-20 12:00:00|kernel[0]|something happened");
    CHECK(decision.rows[1] == "error|2026-07-20 12:00:05|loginwindow[42]|a second line");
}

TEST_CASE("decide_log_show_output: a line without the compact double-space columns falls back "
          "to line|-|line",
          "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {"unstructured-single-column-line"};

    auto decision = decide_log_show_output(result, "event", "No matching events found");
    CHECK(decision.rc == 0);
    REQUIRE(decision.rows.size() == 1);
    CHECK(decision.rows[0] == "event|unstructured-single-column-line|-|unstructured-single-column-line");
}

TEST_CASE("decide_log_show_output: timed_out flushes partial lines then an honest timeout row, "
          "rc nonzero",
          "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = -1;
    result.timed_out = true;
    result.output_truncated = false;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  partial line before the deadline"};

    auto errors_decision = decide_log_show_output(result, "error", "No error events found");
    CHECK(errors_decision.rc != 0);
    REQUIRE(errors_decision.rows.size() == 2);
    CHECK(errors_decision.rows[0] ==
          "error|2026-07-20 12:00:00|kernel[0]|partial line before the deadline");
    CHECK(errors_decision.rows[1] == "error|timeout|-|log show timed out before completing");

    auto query_decision = decide_log_show_output(result, "event", "No matching events found");
    CHECK(query_decision.rc != 0);
    REQUIRE(query_decision.rows.size() == 2);
    CHECK(query_decision.rows[0] ==
          "event|2026-07-20 12:00:00|kernel[0]|partial line before the deadline");
    CHECK(query_decision.rows[1] == "event|timeout|-|log show timed out before completing");
}

TEST_CASE("decide_log_show_output: tool_ran=false is an honest unavailable row, never rc-0 "
          "none-found",
          "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = false;
    result.exit_code = -1;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {};

    auto decision = decide_log_show_output(result, "error", "No error events found");
    CHECK(decision.rc != 0);
    REQUIRE(decision.rows.size() == 1);
    CHECK(decision.rows[0] == "error|unavailable|-|log show did not run");
}

TEST_CASE("decide_log_show_output: nonzero exit_code is an honest unavailable row, never rc-0 "
          "none-found",
          "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 1;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {};

    auto decision = decide_log_show_output(result, "event", "No matching events found");
    CHECK(decision.rc != 0);
    REQUIRE(decision.rows.size() == 1);
    CHECK(decision.rows[0] == "event|unavailable|-|log show exited with an error");
}

TEST_CASE("decide_log_show_output: output_truncated flushes partial lines then an honest "
          "unavailable row, rc nonzero",
          "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = true;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  line before the truncation cap"};

    auto decision = decide_log_show_output(result, "error", "No error events found");
    CHECK(decision.rc != 0);
    REQUIRE(decision.rows.size() == 2);
    CHECK(decision.rows[0] ==
          "error|2026-07-20 12:00:00|kernel[0]|line before the truncation cap");
    CHECK(decision.rows[1] == "error|unavailable|-|log show output was truncated");
}

TEST_CASE("decide_log_show_output: an overlong message is capped at 200 characters",
         "[event_logs][macos]") {
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = false;
    std::string long_message(250, 'x');
    result.lines = {"2026-07-20 12:00:00  kernel[0]  " + long_message};

    auto decision = decide_log_show_output(result, "error", "No error events found");
    CHECK(decision.rc == 0);
    REQUIRE(decision.rows.size() == 1);
    CHECK(decision.rows[0] == "error|2026-07-20 12:00:00|kernel[0]|" + long_message.substr(0, 200));
}

TEST_CASE("decide_log_show_output: a message containing '|' and '\\' stays inside a single "
          "message field after escaping (K-3)",
          "[event_logs][macos]") {
    // log show emits process names/messages verbatim from whatever wrote
    // the entry -- a hostile '|' or '\' in the message must never inject
    // an extra pipe-delimited column or corrupt a downstream split.
    SubprocessResult result;
    result.tool_ran = true;
    result.exit_code = 0;
    result.timed_out = false;
    result.output_truncated = false;
    result.lines = {"2026-07-20 12:00:00  kernel[0]  message|with\\backslash and pipe"};

    auto decision = decide_log_show_output(result, "error", "No error events found");
    CHECK(decision.rc == 0);
    REQUIRE(decision.rows.size() == 1);

    // Mirror the server's split locally instead of asserting a literal
    // escaped string, so the fixture stays honest about what matters: the
    // row still has exactly 4 columns and an embedded '|' never bleeds into
    // a neighbouring column. safe_output_field is intentionally lossy on a
    // literal backslash (folds '\' -> '/', a framing-safety choice that
    // needs no shared-decoder change), so the message's pipe survives while
    // its backslash is folded -- assert exactly that.
    auto fields = split_pipe_delimited(decision.rows[0]);
    REQUIRE(fields.size() == 4);
    CHECK(fields[0] == "error");
    CHECK(fields[1] == "2026-07-20 12:00:00");
    CHECK(fields[2] == "kernel[0]");
    CHECK(unescape_field(fields[3]) == "message|with/backslash and pipe");
}
