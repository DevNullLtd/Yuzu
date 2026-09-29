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
 * locates, by regex, the single call sites for:
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

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') -- see the server_test_exe cpp_args block."
#endif

namespace {

namespace fs = std::filesystem;

std::string read_server_cpp() {
    const fs::path path = fs::path(YUZU_SERVER_SRC_DIR) / "server.cpp";
    REQUIRE(fs::is_regular_file(path));
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.is_open());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int line_of(const std::string& text, std::size_t pos) {
    return static_cast<int>(std::count(
               text.begin(), text.begin() + static_cast<std::string::difference_type>(pos), '\n')) +
           1;
}

std::string strip_line_comments(const std::string& text) {
    static const std::regex re(R"(//[^\n]*)");
    return std::regex_replace(text, re, "");
}

// Returns the line number of the SOLE match, failing loudly (rather than
// returning an empty optional, or silently picking the first of several) if
// the pattern is found zero or more-than-one times -- a vacuous pass here
// would be worse than a hard failure, since it would mean the scan itself
// broke, not that the ordering is fine. Uniqueness matters as much as
// presence (governance Gate 2, security-guardian): a future second call site
// matching the same pattern earlier in the file (e.g. a hoisted helper)
// would otherwise satisfy every ordering check below while the real
// `stop()` order silently regressed.
int require_one_line(const std::string& text, const std::regex& re, const char* label) {
    INFO("looking for: " << label);
    std::vector<int> lines;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re); it != std::sregex_iterator();
         ++it)
        lines.push_back(line_of(text, static_cast<std::size_t>(it->position(0))));
    REQUIRE(lines.size() == 1);
    return lines[0];
}

} // namespace

TEST_CASE("server.cpp: agent_server_->Shutdown(deadline) runs before the policy-eval/"
          "pre-flight/quarantine/schedule joins and the heartbeat fn-null wait (#3495)",
          "[shutdown_order]") {
    const std::string text = strip_line_comments(read_server_cpp());

    const int shutdown_line =
        require_one_line(text, std::regex(R"(agent_server_->Shutdown\(deadline\))"),
                          "agent_server_->Shutdown(deadline)");
    const int policy_eval_join_line = require_one_line(
        text, std::regex(R"(policy_eval_thread_\.join\(\))"), "policy_eval_thread_.join()");
    const int preflight_join_line = require_one_line(
        text, std::regex(R"(preflight_runner_thread_\.join\(\))"), "preflight_runner_thread_.join()");
    const int quarantine_join_line =
        require_one_line(text, std::regex(R"(quarantine_reconcile_thread_\.join\(\))"),
                          "quarantine_reconcile_thread_.join()");
    const int schedule_join_line = require_one_line(
        text, std::regex(R"(schedule_tick_thread_\.join\(\))"), "schedule_tick_thread_.join()");
    const int fn_null_wait_line =
        require_one_line(text, std::regex(R"(heartbeat_ingestion_->set_quarantine_reconcile_fn\(nullptr\))"),
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
    const std::string text = strip_line_comments(read_server_cpp());

    const int web_join_line =
        require_one_line(text, std::regex(R"(web_thread_\.join\(\))"), "web_thread_.join()");
    const int schedule_engine_reset_line = require_one_line(
        text, std::regex(R"(schedule_engine_\.reset\(\))"), "schedule_engine_.reset()");

    INFO("web_thread_.join() at server.cpp:" << web_join_line);
    INFO("schedule_engine_.reset() at server.cpp:" << schedule_engine_reset_line);
    CHECK(web_join_line < schedule_engine_reset_line);
}
