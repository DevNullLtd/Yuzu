/**
 * test_shutdown_join_order.cpp -- #3495 regression guard: ServerImpl::stop()
 * must call agent_server_->Shutdown(deadline) BEFORE joining any background
 * thread that can be blocked inside AgentRegistry::send_to() ->
 * stream->Write() (policy evaluation, pre-flight runner, quarantine
 * containment reconciler, schedule tick).
 *
 * WHY THIS GUARD EXISTS. All four of those threads synchronously call into
 * a gRPC stream write with no bound of its own -- it can stall indefinitely
 * on an HTTP/2 flow-control window. `agent_server_->Shutdown(deadline)` is
 * the ONLY thing in `stop()` that forcibly cancels such a write. Before
 * #3495, Shutdown(deadline) ran AFTER the joins, so a thread blocked
 * inside a write had no path to unblock: a normal SIGTERM had no in-process
 * timed escalation for this case, so `stop()` could hang until an external
 * SIGKILL (e.g. Kubernetes' post-grace-period kill) arrived, losing the
 * final audit/evidence rows for whatever was in flight and skipping every
 * later teardown step. Found via governance #3495 (chaos-injector HIGH +
 * codex external tie-break, 2026-08-24) on the same shape #3042 and #3007
 * already document for other components. The original #3495 fix covered
 * only three of the four threads (missed `policy_eval_thread_`, which
 * dispatches through the identical shared `command_dispatch_fn` closure) --
 * caught in this PR's own Gate 3 governance re-review, closed in the same
 * PR rather than deferred. This test now covers all four so a future
 * regression on any one of them fails loudly, not silently like the
 * original miss did.
 *
 * MECHANISM -- no hand-copied line numbers. This test opens server.cpp (via
 * `YUZU_SERVER_SRC_DIR`, injected by tests/meson.build) AT TEST RUN TIME and
 * locates, by literal substring, the single call sites for:
 *   - `agent_server_->Shutdown(deadline)`
 *   - `policy_eval_thread_.join()`
 *   - `preflight_runner_thread_.join()`
 *   - `quarantine_reconcile_thread_.join()`
 *   - `schedule_tick_thread_.join()`
 *   - `heartbeat_ingestion_->set_quarantine_reconcile_fn(nullptr)`
 * then asserts Shutdown's line number is strictly BEFORE each of the four
 * joins', and strictly BEFORE the fn-null wait's (re-verifying the #3495
 * acceptance criterion that this wait's already-bounded shape must not
 * regress to unbounded when the reorder lands).
 *
 * Same technique and same rationale as test_store_wiring_order.cpp's #3261
 * guard: `ServerImpl` is not unit-constructible (see test_default_certs.cpp),
 * so a source-scan is the only thing that catches an ordering regression in
 * a function this large without standing up a live gRPC server and
 * deliberately stalling a stream write (issue #3495's own suggested-scope
 * item 6 notes that would need an integration or TSan-assisted test, not a
 * unit test -- this guard covers the ordering property directly instead;
 * governance Gate 3 cpp-safety, 2026-08-30, recommended a follow-up issue
 * for that runtime-level coverage rather than adding it to this PR).
 *
 * WHAT THIS SCAN DOES NOT CATCH: that Shutdown's 5s deadline is itself
 * sufficient in practice, that the join actually completes once cancellation
 * lands, or any change to whichever OTHER statements sit between these call
 * sites. It proves relative source order only -- exactly the property that
 * regressed once already (the joins predate Shutdown's call site by ~150
 * lines before this fix), and that a fourth caller of the same shared
 * dispatch closure can be missed even by a reviewer looking directly at this
 * function (the original #3495 PR's own diff touched this exact area and
 * still missed policy_eval_thread_).
 *
 * WHAT THIS SCAN DELIBERATELY DOES NOT DO: assert that command_dispatch_fn
 * has exactly four production consumers, or catch a FIFTH one added later
 * with its join placed correctly relative to the others but still by
 * coincidence rather than by any enforced rule. There is no compile-time or
 * test-time chokepoint tying "joins command_dispatch_fn" to "joins after
 * Shutdown(deadline)" -- Gate 3 architect flagged this absence explicitly
 * (2026-08-30) as a standing risk for the next thread added to this
 * closure's caller list, not something this PR's scope closes.
 */

#include <catch2/catch_test_macros.hpp>

#include "shutdown_drain_rules.hpp"

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "source_scan.hpp"

namespace {

using yuzu::test::source_scan::count_occurrences;
using yuzu::test::source_scan::occurrence_lines;
using yuzu::test::source_scan::require_one_line;
using yuzu::test::source_scan::stripped_source;

// Runs of whitespace collapsed to one space, ends trimmed: a reflow of the scanned text must not
// move a pin, a rewritten token must.
std::string collapse_ws(std::string_view in) {
    std::string out;
    bool pending_space = false;
    for (const char c : in) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            pending_space = !out.empty();
            continue;
        }
        if (pending_space)
            out.push_back(' ');
        pending_space = false;
        out.push_back(c);
    }
    return out;
}

// Offset of the ')' matching the '(' at `open`, or npos. The scanned spans hold no string literal
// containing a parenthesis.
std::size_t matching_paren(std::string_view text, std::size_t open) {
    int depth = 0;
    for (std::size_t i = open; i < text.size(); ++i) {
        if (text[i] == '(')
            ++depth;
        else if (text[i] == ')' && --depth == 0)
            return i;
    }
    return std::string_view::npos;
}

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

constexpr std::string_view kDrainCountDecl =
    "const int workflow_runs = workflow_engine_ ? workflow_engine_->in_flight_runs() : 0;";
constexpr std::string_view kDrainRuleCall = "shutdown_drain::keep_draining_for_work(";
constexpr std::string_view kShouldStopCall = "workflow_engine_->set_should_stop(";
constexpr std::string_view kStopBranch =
    "if (stop_requested_.load(std::memory_order_acquire)) return "
    "yuzu::server::WorkflowStopLevel::kStop;";
constexpr std::string_view kDrainBranch =
    "if (draining_.load(std::memory_order_acquire)) return "
    "yuzu::server::WorkflowStopLevel::kDraining;";
constexpr std::string_view kNoneReturn = "return yuzu::server::WorkflowStopLevel::kNone;";

// Every defect in how ServerImpl::stop() feeds the workflow engine's in-process run count into the
// drain, and how the engine learns of the shutdown; empty when clean. A pure function of the
// (comment-stripped) text so the mutation cases below can prove each pin fails when its line is
// removed or rewritten. A scan that ignores the call's arguments or its result, or the position of
// the read, is the false green this exists to prevent (qe2-4).
std::vector<std::string> drain_wiring_problems(const std::string& text) {
    std::vector<std::string> out;
    const auto sole = [&](std::string_view needle) -> std::size_t {
        if (count_occurrences(text, needle) != 1) {
            out.push_back("expected exactly one '" + std::string(needle) + "', found " +
                          std::to_string(count_occurrences(text, needle)));
            return std::string::npos;
        }
        return text.find(needle);
    };
    const std::size_t draining_at = sole("draining_.store(true, std::memory_order_release)");
    const std::size_t count_at = sole("workflow_engine_->in_flight_runs()");
    const std::size_t rule_at = sole(kDrainRuleCall);
    const std::size_t stop_at = sole("stop_requested_.store(true, std::memory_order_release)");
    const std::size_t should_stop_at = sole(kShouldStopCall);
    if (draining_at != std::string::npos && count_at != std::string::npos &&
        rule_at != std::string::npos && stop_at != std::string::npos) {
        if (!(draining_at < count_at && count_at < rule_at && rule_at < stop_at))
            out.push_back("order must be draining_ store, run count read, keep_draining_for_work, "
                          "stop_requested_ store");
        // The count is read INSIDE the drain loop, every tick: the `for (;;)` opening the loop that
        // holds the rule call must come before the read. A hoisted read freezes the count.
        const std::size_t loop_at = text.rfind("for (;;)", rule_at);
        if (loop_at == std::string::npos || loop_at < draining_at)
            out.push_back("no drain loop (`for (;;)`) between the draining_ store and the rule call");
        else if (count_at < loop_at)
            out.push_back("the workflow run count is read above the drain loop, not inside it");
        else if (text.find(kDrainCountDecl) == std::string::npos)
            out.push_back("the run count is not bound as `const int workflow_runs = ...`");
        // The call: its last two arguments are the tracker count then the engine count, it is the
        // condition of `if (!...) break;`, so neither a constant nor a dropped result survives.
        const std::size_t open = rule_at + kDrainRuleCall.size() - 1;
        const std::size_t close = matching_paren(text, open);
        if (close == std::string::npos) {
            out.push_back("unbalanced keep_draining_for_work( call");
        } else {
            const std::string call = collapse_ws(text.substr(rule_at, close + 1 - rule_at));
            if (call != "shutdown_drain::keep_draining_for_work(elapsed, min_grace, running, workflow_runs)")
                out.push_back("keep_draining_for_work must read `(elapsed, min_grace, running, "
                              "workflow_runs)`, found `" + call + "`");
            const std::string before = collapse_ws(text.substr(0, rule_at));
            if (!ends_with(before, "if (!"))
                out.push_back("keep_draining_for_work must be the negated condition of an `if (!...)`");
            const std::string after = collapse_ws(text.substr(close + 1, 48));
            if (!starts_with(after, ") break;"))
                out.push_back("the `if (!keep_draining_for_work(...))` must `break;` directly");
            // The progress log fires for an engine run too, so an operator sees what holds the drain.
            const std::string tail = collapse_ws(text.substr(close, stop_at - close));
            if (tail.find("if (running > 0 || workflow_runs > 0) {") == std::string::npos)
                out.push_back("the `if (running > 0 || workflow_runs > 0)` log branch is missing");
        }
    }
    if (should_stop_at != std::string::npos) {
        const std::size_t open = should_stop_at + kShouldStopCall.size() - 1;
        const std::size_t close = matching_paren(text, open);
        if (close == std::string::npos) {
            out.push_back("unbalanced set_should_stop( call");
        } else {
            const std::string arg = collapse_ws(text.substr(open + 1, close - open - 1));
            const std::size_t stop_branch = arg.find(kStopBranch);
            const std::size_t drain_branch = arg.find(kDrainBranch);
            const std::size_t none_return = arg.rfind(kNoneReturn);
            if (!starts_with(arg, "[this] {"))
                out.push_back("set_should_stop must take a `[this]` lambda");
            if (stop_branch == std::string::npos)
                out.push_back("set_should_stop lambda lacks `stop_requested_ -> kStop`");
            if (drain_branch == std::string::npos)
                out.push_back("set_should_stop lambda lacks `draining_ -> kDraining`");
            if (stop_branch != std::string::npos && drain_branch != std::string::npos &&
                !(stop_branch < drain_branch))
                out.push_back("set_should_stop must test stop_requested_ before draining_ (stop wins)");
            if (drain_branch != std::string::npos &&
                (none_return == std::string::npos || none_return < drain_branch))
                out.push_back("set_should_stop lambda must end by returning kNone");
        }
    }
    return out;
}

// `text` with the sole occurrence of `from` replaced; fails loudly when the anchor is not sole, so a
// mutation that silently did nothing cannot pass for a proof.
std::string mutated(const std::string& text, std::string_view from, std::string_view to) {
    INFO("mutation anchor: " << from);
    REQUIRE(count_occurrences(text, from) == 1);
    std::string out = text;
    out.replace(out.find(from), from.size(), to);
    return out;
}

} // namespace

TEST_CASE("server.cpp: agent_server_->Shutdown(deadline) runs before the policy-eval/"
          "pre-flight/quarantine/schedule joins and the heartbeat fn-null wait (#3495)",
          "[shutdown_order]") {
    const std::string& text = stripped_source("server.cpp");

    const int shutdown_line = require_one_line(text, "agent_server_->Shutdown(deadline)",
                                               "agent_server_->Shutdown(deadline)");
    const int policy_eval_join_line =
        require_one_line(text, "policy_eval_thread_.join()", "policy_eval_thread_.join()");
    const int preflight_join_line = require_one_line(
        text, "preflight_runner_thread_.join()", "preflight_runner_thread_.join()");
    const int quarantine_join_line = require_one_line(
        text, "quarantine_reconcile_thread_.join()", "quarantine_reconcile_thread_.join()");
    const int schedule_join_line =
        require_one_line(text, "schedule_tick_thread_.join()", "schedule_tick_thread_.join()");
    const int fn_null_wait_line =
        require_one_line(text, "heartbeat_ingestion_->set_quarantine_reconcile_fn(nullptr)",
                         "heartbeat_ingestion_->set_quarantine_reconcile_fn(nullptr)");

    INFO("Shutdown(deadline) at server.cpp:" << shutdown_line);

    INFO("policy_eval_thread_.join() at server.cpp:" << policy_eval_join_line);
    CHECK(shutdown_line < policy_eval_join_line);

    INFO("preflight_runner_thread_.join() at server.cpp:" << preflight_join_line);
    CHECK(shutdown_line < preflight_join_line);

    INFO("quarantine_reconcile_thread_.join() at server.cpp:" << quarantine_join_line);
    CHECK(shutdown_line < quarantine_join_line);

    INFO("schedule_tick_thread_.join() at server.cpp:" << schedule_join_line);
    CHECK(shutdown_line < schedule_join_line);

    // #3495 acceptance criterion: the fn-null wait's already-bounded shape
    // (Shutdown's deadline plus whatever store-call timeout was already in
    // flight) must not regress to unbounded -- it stays sequenced after
    // Shutdown regardless of where the four joins above land relative to it.
    INFO("heartbeat_ingestion_->set_quarantine_reconcile_fn(nullptr) at server.cpp:"
         << fn_null_wait_line);
    CHECK(shutdown_line < fn_null_wait_line);
}

/**
 * Governance Gate 6 (sre SHOULD-2, feat/split-a4-schedule-seam, ADR-0031
 * WS-A4 seventh family) -- refined TWICE during the same governance run
 * before landing on the actual invariant, both corrections worth recording:
 *
 * (1) Gate 3 cpp-safety corrected the citation: `web_server_->stop()`
 *     (server.cpp:~9090) only closes the listening socket; it does NOT
 *     itself join anything. The actual drain guarantee -- that every
 *     in-flight httplib `ThreadPool` task has finished -- comes from
 *     `httplib::Server::listen()`'s internal `task_queue->shutdown()`,
 *     which unblocks `web_thread_.join()`. That join is the real
 *     synchronization point.
 *
 * (2) Gate 7 (writing this test) then found `ScheduleEngine::stop()` itself
 *     is a NO-OP (schedule_engine.cpp: "No engine-side resources to stop:
 *     the poller thread ... is owned by ServerImpl ... joined before the
 *     stores") -- it does not invalidate `query_schedules_checked`'s
 *     callability, so asserting `web_thread_.join()` precedes
 *     `schedule_engine_->stop()` is not a real safety requirement, and an
 *     earlier draft of this test asserted it anyway and failed against the
 *     live source (`schedule_engine_->stop()` at server.cpp:9247 genuinely
 *     runs BEFORE `web_thread_.join()` at :9317 today -- harmless, because
 *     `stop()` does nothing). The ONLY call that actually invalidates the
 *     borrow is `schedule_engine_.reset()` (destruction), which this test
 *     pins alone.
 *
 * `LocalScheduleApi` (schedule_api_local.hpp) holds a BORROWED
 * `ScheduleEngine&` and is now reachable from THREE HTTP/MCP-facing call
 * sites (the dashboard fragment, REST v1, and MCP `list_schedules`) via one
 * shared `schedule_api` instance, instead of just the pre-existing
 * background `ScheduleRunner`. That borrow is safe only because
 * `web_thread_.join()` -- which cannot return until every such task has
 * exited -- runs strictly BEFORE `schedule_engine_.reset()`, which would
 * otherwise leave the borrow dangling. `schedule_api_local.hpp`'s own
 * lifetime-contract doc comment states this ordering as load-bearing; this
 * test pins it the same way the guard above pins #3495's, so a future
 * reorder in `stop()` fails loudly here instead of silently reopening a UAF
 * window for all three schedule-read surfaces.
 *
 * Same source-scan technique as the #3495 guard above -- see its doc comment
 * for the rationale (`ServerImpl` is not unit-constructible) and its stated
 * limits (proves relative source order only, not that the drain actually
 * completes in practice).
 */
TEST_CASE("server.cpp: web_thread_.join() runs before schedule_engine_.reset() "
          "(ADR-0031 WS-A4 schedule seam)",
          "[shutdown_order]") {
    const std::string& text = stripped_source("server.cpp");

    const int web_join_line = require_one_line(text, "web_thread_.join()", "web_thread_.join()");
    const int schedule_engine_reset_line =
        require_one_line(text, "schedule_engine_.reset()", "schedule_engine_.reset()");

    INFO("web_thread_.join() at server.cpp:" << web_join_line);
    INFO("schedule_engine_.reset() at server.cpp:" << schedule_engine_reset_line);
    CHECK(web_join_line < schedule_engine_reset_line);
}

/**
 * #2146: the shutdown drain waits for workflow runs in flight. The pure rule is in
 * shutdown_drain_rules.hpp; the loop that feeds it lives in ServerImpl::stop(), which is not
 * unit-constructible, so the wiring is pinned by scan: the engine's in-process counter is read
 * INSIDE the drain loop (after draining_ is set, before stop_requested_ is), and what it reads
 * feeds keep_draining_for_work. Reading a table count instead, or computing the wait without it,
 * fails here.
 */
TEST_CASE("server.cpp: the drain loop waits on the workflow engine's in-process run count, between "
          "draining_ and stop_requested_ (#2146)",
          "[shutdown_order][shutdown_drain]") {
    const std::string& text = stripped_source("server.cpp");
    const auto problems = drain_wiring_problems(text);
    for (const auto& p : problems)
        UNSCOPED_INFO(p);
    CHECK(problems.empty());
}

// Each survivor the quality-engineer listed (qe2-4), plus the neighbours the same scan must stop:
// every mutation starts from the real source and must produce at least one problem.
TEST_CASE("server.cpp: the drain wiring scan fails against each mutation of the wiring (#2146)",
          "[shutdown_order][shutdown_drain]") {
    const std::string& text = stripped_source("server.cpp");
    REQUIRE(drain_wiring_problems(text).empty());

    const std::string call_head = "if (!shutdown_drain::keep_draining_for_work(";
    const std::string call_tail = "workflow_runs))";
    const std::string log_cond = "if (running > 0 || workflow_runs > 0) {";
    const std::string loop_head = "for (;;) {\n                const auto elapsed = steady_clock::now() - drain_start;";

    struct Case {
        const char* name;
        std::string text;
    };
    // The hoist: the declaration line leaves the loop and lands above it.
    std::string hoisted = mutated(text, kDrainCountDecl, "");
    hoisted = mutated(hoisted, loop_head, std::string(kDrainCountDecl) + "\n            " + loop_head);
    const std::vector<Case> cases = {
        {"count argument replaced by 0", mutated(text, call_tail, "0))")},
        {"tracker count passed twice", mutated(text, "min_grace, running,", "min_grace, running, running,")},
        {"result ignored", mutated(mutated(text, call_head, "(void)shutdown_drain::keep_draining_for_work("),
                                   call_tail, "workflow_runs);")},
        {"negation dropped", mutated(text, call_head, "if (shutdown_drain::keep_draining_for_work(")},
        {"no break on the result", mutated(text, "workflow_runs))\n                    break;",
                                           "workflow_runs)) {}")},
        {"count read hoisted above the loop", hoisted},
        {"log branch no longer sees the engine count", mutated(text, log_cond, "if (running > 0) {")},
        {"log branch removed", mutated(text, log_cond, "if (false) {")},
        {"set_should_stop assigned something else",
         mutated(text, kShouldStopCall, "workflow_engine_->set_unrelated(")},
        {"set_should_stop lambda never reports a stop",
         mutated(text, "WorkflowStopLevel::kStop;", "WorkflowStopLevel::kDraining;")},
        {"set_should_stop lambda never reports a drain",
         mutated(text, "WorkflowStopLevel::kDraining;\n                    return yuzu::server::WorkflowStopLevel::kNone;",
                 "WorkflowStopLevel::kNone;\n                    return yuzu::server::WorkflowStopLevel::kNone;")},
        {"draining wins over stop",
         mutated(mutated(mutated(text, "if (stop_requested_.load(std::memory_order_acquire))\n"
                                       "                        return yuzu::server::WorkflowStopLevel::kStop;",
                                 "@@STOP@@"),
                         "if (draining_.load(std::memory_order_acquire))\n"
                         "                        return yuzu::server::WorkflowStopLevel::kDraining;",
                         "if (stop_requested_.load(std::memory_order_acquire))\n"
                         "                        return yuzu::server::WorkflowStopLevel::kStop;"),
                 "@@STOP@@",
                 "if (draining_.load(std::memory_order_acquire))\n"
                 "                        return yuzu::server::WorkflowStopLevel::kDraining;")},
    };
    for (const auto& c : cases) {
        INFO("mutation: " << c.name);
        CHECK_FALSE(drain_wiring_problems(c.text).empty());
    }
}

TEST_CASE("shutdown_drain: a workflow run in flight extends the wait, and the SAME cap releases it",
          "[shutdown_drain]") {
    using namespace std::chrono_literals;
    using yuzu::server::shutdown_drain::keep_draining_for_work;
    using yuzu::server::shutdown_drain::kExecutionDrainCap;
    // Nothing in the tracker, no grace: only the engine's own run count holds the drain.
    CHECK_FALSE(keep_draining_for_work(0s, 0s, 0, 0));
    CHECK(keep_draining_for_work(0s, 0s, 0, 1));
    CHECK(keep_draining_for_work(kExecutionDrainCap - 1s, 0s, 0, 3));
    // The cap bounds it exactly as it bounds a tracked execution: a run still going at the cap is
    // stopped by stop_requested_, not waited for.
    CHECK_FALSE(keep_draining_for_work(kExecutionDrainCap, 0s, 0, 1));
    CHECK_FALSE(keep_draining_for_work(kExecutionDrainCap + 5s, 0s, 4, 4));
    // A tracked execution alone, and the minimum grace, behave as before.
    CHECK(keep_draining_for_work(1s, 0s, 2, 0));
    CHECK(keep_draining_for_work(5s, 10s, 0, 0));
    CHECK_FALSE(keep_draining_for_work(10s, 10s, 0, 0));
}

// require_one_line fails loudly on zero or on more than one occurrence (uniqueness kept
// from the pattern version). The failure itself is a Catch2 REQUIRE, so the count it
// tests is pinned directly through occurrence_lines.
TEST_CASE("occurrence_lines: zero and two occurrences are not a sole match "
          "and a sole match reports its line",
          "[shutdown_order]") {
    CHECK(occurrence_lines("a\nb\n", "x()").empty());
    CHECK(occurrence_lines("a\nx()\nb\n", "x()") == std::vector<int>{2});
    CHECK(occurrence_lines("x()\nb\nx()\n", "x()") == std::vector<int>{1, 3});
    // A needle is a literal: the pattern metacharacters in a call site are plain text.
    CHECK(occurrence_lines("a.join() ajoin()", ".join()") == std::vector<int>{1});
}
