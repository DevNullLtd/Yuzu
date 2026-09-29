/**
 * test_content_dist_exec_parsers.cpp — pure-parser coverage for
 * `content_dist`'s `execute_staged` action (content_dist_exec_parsers.hpp),
 * the decision layer around the plugin's cross-platform migration onto
 * yuzu::agent::run_bounded_subprocess (deleting the plugin's private
 * OS-specific direct-argv spawn helpers).
 *
 * Fixture-constructed yuzu::agent::SubprocessResult values only — no
 * process spawns, no OS calls, no sleeps. The runner's own spawn/reap
 * machinery is covered by test_subprocess_runner.cpp; this file pins only
 * the two pure decisions content_dist owns: which SubprocessOptions
 * `execute_staged` runs with (build_execution_options), and how a completed
 * run's SubprocessResult maps onto the status|/exit_code|/output| wire
 * lines the plugin's deleted spawn paths used to produce directly
 * (map_execution_result).
 */
#include "content_dist_exec_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::content_dist::exec;
using yuzu::agent::SubprocessResult;
using yuzu::agent::TerminationReason;

// ── build_execution_options ──────────────────────────────────────────────

TEST_CASE("build_execution_options sets the fixed deadline/grace/merge/output-cap quad",
         "[agent][content_dist][exec]") {
    auto opts = build_execution_options(/*is_linux=*/false, /*is_windows=*/false);
    // BR-002 (whole-branch review): 30 MINUTES, not 30 seconds -- the
    // deleted pre-migration paths ran a staged installer to completion
    // unbounded on both platforms (see build_execution_options' own
    // rationale comment); 30 minutes is the deliberately generous bound
    // that replaces "no bound" without reintroducing it.
    CHECK(opts.deadline == std::chrono::minutes(30));
    // Mutating-site grace (ADR-3002): a deadline/cancel kill sends SIGTERM
    // first and waits this long for a voluntary exit before the hard kill,
    // instead of an immediate SIGKILL mid-transaction.
    CHECK(opts.soft_terminate_grace == std::chrono::seconds(30));
    CHECK(opts.merge_stderr);
    CHECK(opts.output_cap_bytes == 16u * 1024 * 1024);
}

TEST_CASE("build_execution_options enables exec_verify only when is_linux is true",
         "[agent][content_dist][exec]") {
    auto linux_opts = build_execution_options(true, false);
    CHECK(linux_opts.exec_verify.enabled);

    auto non_linux_opts = build_execution_options(false, false);
    CHECK_FALSE(non_linux_opts.exec_verify.enabled);
}

TEST_CASE("build_execution_options leaves require_root_owned false on every platform",
         "[agent][content_dist][exec]") {
    // Deliberate: the staging dir is agent-owned 0700, not root -- see the
    // header's own rationale comment. require_root_owned=true would
    // spawn_error every staged file on a rootless agent.
    CHECK_FALSE(build_execution_options(true, false).exec_verify.require_root_owned);
    CHECK_FALSE(build_execution_options(false, false).exec_verify.require_root_owned);
}

TEST_CASE("build_execution_options never sets expected_size -- that is the caller's job",
         "[agent][content_dist][exec]") {
    auto opts = build_execution_options(true, false);
    CHECK_FALSE(opts.exec_verify.expected_size.has_value());
}

// BR4-007 (whole-branch review round 4): the deleted Windows launcher passed
// CREATE_NO_WINDOW to CreateProcessW; this pins that build_execution_options
// restores it ONLY when is_windows is true, and never on a non-Windows
// build combination -- the OS effect itself is unobservable from macOS (the
// flag only affects Windows CreateProcessW creation flags), but the OPTION
// SELECTION build_execution_options makes is a pure decision this header
// already exposes, so it is fully testable here regardless of host OS.
TEST_CASE("build_execution_options sets no_window true only when is_windows is true (BR4-007)",
         "[agent][content_dist][exec][no_window]") {
    CHECK(build_execution_options(/*is_linux=*/false, /*is_windows=*/true).no_window);
    CHECK_FALSE(build_execution_options(/*is_linux=*/false, /*is_windows=*/false).no_window);
    CHECK_FALSE(build_execution_options(/*is_linux=*/true, /*is_windows=*/false).no_window);
}

// ── map_execution_result: exited ─────────────────────────────────────────

TEST_CASE("map_execution_result: exited with rc==0 reports status|ok", "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 0;
    r.output = "all good\n";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "ok");
    CHECK(wire.exit_code == 0);
    CHECK(wire.output == "all good\n");
}

TEST_CASE("map_execution_result: exited with nonzero rc reports status|error",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 42;
    r.output = "boom";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == 42);
    CHECK(wire.output == "boom");
}

TEST_CASE("map_execution_result: exited with empty output produces an empty output field",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 0;
    r.output = "";

    auto wire = map_execution_result(r);
    // Empty here signals the call site to omit the output| line entirely --
    // matches the deleted code's `if (!output.empty())` guard.
    CHECK(wire.output.empty());
}

// ── map_execution_result: output_truncated ───────────────────────────────

TEST_CASE("map_execution_result: output_truncated appends the truncation notice",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 0;
    r.output = "partial output";
    r.output_truncated = true;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "ok");
    CHECK(wire.output == "partial output\n[output truncated at 16 MiB]");
}

// ── map_execution_result: deadline / cancelled ───────────────────────────

TEST_CASE("map_execution_result: deadline reports status|error, exit_code|-1, and a "
         "termination notice appended to captured output",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::deadline;
    r.exit_code = -1;
    r.timed_out = true;
    r.output = "partial output before kill";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "partial output before kill\n[terminated: deadline exceeded]");
}

TEST_CASE("map_execution_result: cancelled reports its own distinct annotation, not "
         "\"deadline exceeded\" (BR-006)",
         "[agent][content_dist][exec]") {
    // Pre-fix, this branch collapsed cancelled into the literal text
    // "deadline exceeded" -- a consumer reading the output text (as
    // opposed to the BR-001 typed result-status seam) would pick the wrong
    // retry/escalation reason for an agent-shutdown cancel vs a real
    // timeout.
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::cancelled;
    r.exit_code = -1;
    r.timed_out = true;
    r.output = "";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "\n[terminated: cancelled]");
}

TEST_CASE("map_execution_result: a cancelled run that was ALSO truncated at the byte cap "
         "reports both facts, not just one (BR-006)",
         "[agent][content_dist][exec]") {
    // Pre-fix, this branch returned before ever checking output_truncated,
    // so a run that was both cut short at 16 MiB AND then cancelled/killed
    // lost the truncation fact entirely -- a consumer could parse the
    // partial output as complete.
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::deadline;
    r.exit_code = -1;
    r.timed_out = true;
    r.output_truncated = true;
    r.output = "partial output before kill";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.output == "partial output before kill\n[output truncated at 16 MiB]"
                         "\n[terminated: deadline exceeded]");
}

TEST_CASE("map_execution_result: a pre-armed cancel that fires before exec is confirmed "
         "still reports cancelled, not spawn failed",
         "[agent][content_dist][exec]") {
    // subprocess_runner.cpp: when a pre-armed cancel (or a very tight
    // deadline) kills the child on its very first poll, tool_ran can still
    // be false (exec was never positively confirmed) while
    // termination_reason is correctly cancelled/deadline, not spawn_error.
    // deadline/cancelled MUST be checked before tool_ran or this legitimate
    // combination gets misreported as "spawn failed (errno 0: Success)".
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::cancelled;
    r.exit_code = -1;
    r.timed_out = true;
    r.spawn_errno = 0;
    r.output = "";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "\n[terminated: cancelled]");
}

TEST_CASE("map_execution_result: a pre-armed deadline kill with tool_ran==false maps the "
         "same way",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::deadline;
    r.exit_code = -1;
    r.timed_out = true;
    r.spawn_errno = 0;
    r.output = "";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "\n[terminated: deadline exceeded]");
}

// ── map_execution_result: spawn_error ────────────────────────────────────

TEST_CASE("map_execution_result: spawn_error (tool_ran==false) reports the errno and strerror",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::spawn_error;
    r.exit_code = -1;
    r.spawn_errno = ENOENT;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output.find("spawn failed (errno " + std::to_string(ENOENT) + ":") == 0);
}

TEST_CASE("map_execution_result: spawn_error with spawn_errno==0 (BR-005, e.g. a Windows "
         "CreateProcessW/setup failure) never claims a fabricated 'Success'",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::spawn_error;
    r.exit_code = -1;
    r.spawn_errno = 0; // documented "non-POSIX/no-report failure path" value

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "spawn failed (OS error unavailable)");
    // The self-contradictory text this fix removes must never appear.
    CHECK(wire.output.find("Success") == std::string::npos);
    CHECK(wire.output.find("errno 0") == std::string::npos);
}

TEST_CASE("map_execution_result: spawn_error from a B6 exec_verify rejection (EACCES) maps "
         "the same way as any other spawn failure",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::spawn_error;
    r.exit_code = -1;
    r.spawn_errno = EACCES;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output.find("spawn failed (errno " + std::to_string(EACCES) + ":") == 0);
}

TEST_CASE("map_execution_result: tool_ran==false takes priority over a non-kill "
         "termination_reason",
         "[agent][content_dist][exec]") {
    // A spawn_error result should never fall into the exited branch even if
    // termination_reason were somehow left stale -- tool_ran is the
    // authoritative signal for "exec never confirmed" (subprocess_runner.hpp)
    // once deadline/cancelled (checked first -- see the two pre-armed-kill
    // test cases above) have been ruled out.
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::exited; // deliberately inconsistent
    r.exit_code = 0;
    r.spawn_errno = ENOENT;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.output.find("spawn failed") == 0);
}

// ── map_execution_result: signaled (residual case) ───────────────────────

TEST_CASE("map_execution_result: signaled reports status|error with the runner's -1 sentinel",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::signaled;
    r.exit_code = -1;
    r.output = "crashed";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "crashed");
}

// ── is_shebang_payload (CDX-002) ──────────────────────────────────────────

TEST_CASE("is_shebang_payload: a genuine shebang prefix is true", "[agent][content_dist][exec]") {
    CHECK(is_shebang_payload("#!/bin/sh\n"));
    CHECK(is_shebang_payload("#!/usr/bin/env python3\n"));
}

TEST_CASE("is_shebang_payload: a bare '#' is false", "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload("#"));
}

TEST_CASE("is_shebang_payload: '#' followed by a non-'!' byte is false",
         "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload("#x"));
}

TEST_CASE("is_shebang_payload: ELF magic is false", "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload("\x7f" "ELF"));
}

// ── is_safe_arg / split_args (BR-006: moved from content_dist_plugin.cpp's
// anonymous namespace so they are unit-testable as pure functions) ─────────

TEST_CASE("is_safe_arg: ordinary argument bytes are accepted", "[agent][content_dist][exec]") {
    CHECK(is_safe_arg("--verbose"));
    CHECK(is_safe_arg("/opt/vendor/install.sh"));
    CHECK(is_safe_arg("key=value"));
    CHECK(is_safe_arg(""));
}

TEST_CASE("is_safe_arg: every documented shell metacharacter is refused",
         "[agent][content_dist][exec]") {
    for (char c : std::string_view{";&|`$(){}<>!~^'\"#*?[]\n\r"}) {
        CHECK_FALSE(is_safe_arg(std::string(1, c)));
        CHECK_FALSE(is_safe_arg("prefix" + std::string(1, c) + "suffix"));
    }
}

TEST_CASE("split_args: splits on runs of spaces/tabs, no shell quoting", "[agent][content_dist][exec]") {
    CHECK(split_args("") == std::vector<std::string>{});
    CHECK(split_args("one") == std::vector<std::string>{"one"});
    CHECK(split_args("one two") == std::vector<std::string>{"one", "two"});
    CHECK(split_args("  one   two  ") == std::vector<std::string>{"one", "two"});
    CHECK(split_args("one\ttwo") == std::vector<std::string>{"one", "two"});
    // No shell word-splitting semantics -- a quoted token is NOT preserved
    // as one argument.
    CHECK(split_args("\"one two\"") == std::vector<std::string>{"\"one", "two\""});
}

TEST_CASE("is_shebang_payload: empty input is false", "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload(""));
}

// ── inherit_parent_env (legacy full-environment preservation, every OS) ────
// The deleted OS-specific launchers on BOTH platforms inherited the agent's
// full parent environment -- Windows via lpEnvironment=nullptr to
// CreateProcessW, POSIX via execvp() without ever replacing `environ` (BR-001,
// whole-branch review round 2: an earlier version of this file's comment
// claimed POSIX was unaffected, which was wrong -- see
// build_execution_options' own rationale comment). These pin that the
// migrated options builder preserves that on EVERY platform combination,
// unconditionally -- inherit_parent_env is no longer an is_windows-gated
// flag.
TEST_CASE("build_execution_options sets inherit_parent_env unconditionally, on every platform "
          "combination (BR-001)",
          "[agent][content_dist][exec]") {
    CHECK(build_execution_options(/*is_linux=*/false, /*is_windows=*/true).inherit_parent_env);
    CHECK(build_execution_options(/*is_linux=*/false, /*is_windows=*/false).inherit_parent_env);
    CHECK(build_execution_options(/*is_linux=*/true, /*is_windows=*/false).inherit_parent_env);
}

TEST_CASE("build_execution_options keeps exec_verify Linux-only while inherit_parent_env stays "
          "unconditional (BR-001)",
          "[agent][content_dist][exec]") {
    // Linux gets the fd-exec verification (and, since BR-001, inherit_parent_env
    // too -- it is no longer Windows-exclusive); non-Linux never gets fd-exec
    // (it fails closed there) but still gets inherit_parent_env.
    auto lin = build_execution_options(/*is_linux=*/true, /*is_windows=*/false);
    auto win = build_execution_options(/*is_linux=*/false, /*is_windows=*/true);
    CHECK(lin.exec_verify.enabled);
    CHECK(lin.inherit_parent_env);
    CHECK_FALSE(win.exec_verify.enabled);
    CHECK(win.inherit_parent_env);
}
