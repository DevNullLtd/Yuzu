/**
 * test_execution_tracker.cpp — Unit tests for ExecutionTracker
 *
 * Covers: create, get, query filters, agent status transitions, summary,
 *         refresh_counts, parent-child hierarchy, rerun, mark cancelled.
 */

#include "execution_tracker.hpp"
#include "execution_event_bus.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_execution_tracker_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <latch>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;

// ── Helpers ─────────────────────────────────────────────────────────────────

static Execution make_execution(const std::string& definition_id = "def-001",
                                const std::string& scope = "ostype = 'windows'",
                                const std::string& dispatched_by = "admin") {
    Execution exec;
    exec.definition_id = definition_id;
    exec.scope_expression = scope;
    exec.dispatched_by = dispatched_by;
    exec.status = "running";
    return exec;
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: construction migrates and opens the store",
          "[pg][execution_tracker][db]") {
    // The fixture's own constructor already REQUIREs is_open() — this test
    // exists so a construction failure surfaces here by name rather than as
    // an opaque fixture assertion inside the first unrelated test that
    // happens to run.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    REQUIRE(tracker_bundle->is_open());
}

// ── Create Execution ───────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: create execution", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto result = tracker.create_execution(make_execution());
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ExecutionTracker: create execution with parameter_values", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.parameter_values = R"({"timeout": 30, "force": true})";
    auto result = tracker.create_execution(exec);
    REQUIRE(result.has_value());

    auto fetched = tracker.get_execution(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->parameter_values == exec.parameter_values);
}

// ── Get Execution ──────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: get execution", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto result =
        tracker.create_execution(make_execution("def-hostname", "ostype = 'windows'", "operator1"));
    REQUIRE(result.has_value());

    auto exec = tracker.get_execution(*result);
    REQUIRE(exec.has_value());
    CHECK(exec->definition_id == "def-hostname");
    CHECK(exec->scope_expression == "ostype = 'windows'");
    CHECK(exec->dispatched_by == "operator1");
    CHECK(exec->status == "running");
}

TEST_CASE("ExecutionTracker: get nonexistent returns empty", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto result = tracker.get_execution("nonexistent-id");
    CHECK(!result.has_value());
}

// ── Query with Filters ─────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: query all executions", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    tracker.create_execution(make_execution("def-1"));
    tracker.create_execution(make_execution("def-2"));
    tracker.create_execution(make_execution("def-3"));

    auto results = tracker.query_executions();
    REQUIRE(results.size() == 3);
}

TEST_CASE("ExecutionTracker: query by definition_id", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    tracker.create_execution(make_execution("def-alpha"));
    tracker.create_execution(make_execution("def-beta"));
    tracker.create_execution(make_execution("def-alpha"));

    ExecutionQuery q;
    q.definition_id = "def-alpha";
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("ExecutionTracker: query by status", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id1_result = tracker.create_execution(make_execution());
    auto id2_result = tracker.create_execution(make_execution());
    REQUIRE(id1_result.has_value());
    REQUIRE(id2_result.has_value());
    REQUIRE(tracker.mark_cancelled(*id1_result, "admin"));

    ExecutionQuery q;
    q.status = "cancelled";
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].id == *id1_result);
}

TEST_CASE("ExecutionTracker: query with limit", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    for (int i = 0; i < 10; ++i) {
        tracker.create_execution(make_execution("def-" + std::to_string(i)));
    }

    ExecutionQuery q;
    q.limit = 5;
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 5);
}

// ── #3789: query_executions_checked / SQL scope pushdown ──────────────────

TEST_CASE("ExecutionTracker: query_executions_checked with no scope matches query_executions",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    REQUIRE(tracker.create_execution(make_execution("def-a")).has_value());
    REQUIRE(tracker.create_execution(make_execution("def-b")).has_value());

    auto checked = tracker.query_executions_checked(ExecutionQuery{}, std::nullopt);
    REQUIRE(checked.has_value());
    CHECK(checked->size() == 2);
}

TEST_CASE("ExecutionTracker: query_executions_checked scope admits the owner's own "
          "dispatch before any agent has responded",
          "[pg][execution_tracker]") {
    // #3789 finding: agent_exec_status is response-arrival seeded, so a
    // just-dispatched execution has zero status rows. Without the owner
    // disjunct, this execution would be invisible to its own dispatcher
    // under an engaged scope.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution("def-owner", "scope", "bob"));
    REQUIRE(id.has_value());

    ExecutionListScope scope;
    scope.owner = "bob";
    // visible_agents deliberately empty — no agent has reported yet.
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    REQUIRE(checked->size() == 1);
    CHECK((*checked)[0].id == *id);
}

TEST_CASE("ExecutionTracker: query_executions_checked scope admits via a visible "
          "agent's status row even when the caller is not the dispatcher",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution("def-teammate", "scope", "alice"));
    REQUIRE(id.has_value());
    AgentExecStatus as;
    as.agent_id = "bob-agent";
    as.status = "success";
    tracker.update_agent_status(*id, as);

    ExecutionListScope scope;
    scope.owner = "bob"; // not the dispatcher
    scope.visible_agents = {"bob-agent"};
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    REQUIRE(checked->size() == 1);
    CHECK((*checked)[0].id == *id);
}

TEST_CASE("ExecutionTracker: query_executions_checked scope excludes an execution "
          "neither dispatched by the owner nor reported by a visible agent",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution("def-hidden", "scope", "alice"));
    REQUIRE(id.has_value());
    AgentExecStatus as;
    as.agent_id = "alice-agent";
    as.status = "success";
    tracker.update_agent_status(*id, as);

    ExecutionListScope scope;
    scope.owner = "bob";
    scope.visible_agents = {"bob-agent"}; // does not include alice-agent
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    CHECK(checked->empty());
}

TEST_CASE("ExecutionTracker: query_executions_checked engaged-empty scope (no owner, "
          "no visible agents) excludes every row",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;
    REQUIRE(tracker.create_execution(make_execution()).has_value());

    ExecutionListScope scope; // owner empty, visible_agents empty
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    CHECK(checked->empty());
}

TEST_CASE("ExecutionTracker: query_executions_checked scope pushdown respects "
          "LIMIT ordering (INV-3) — a hidden newer execution must not consume the "
          "page while an older visible one exists",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Older, visible (dispatched by bob).
    Execution visible_exec = make_execution("def-visible", "scope", "bob");
    visible_exec.dispatched_at = 1000;
    REQUIRE(tracker.create_execution(visible_exec).has_value());
    // Newer, hidden (dispatched by someone else, no visible-agent row).
    Execution hidden_exec = make_execution("def-hidden", "scope", "alice");
    hidden_exec.dispatched_at = 2000;
    REQUIRE(tracker.create_execution(hidden_exec).has_value());

    ExecutionListScope scope;
    scope.owner = "bob";
    ExecutionQuery q;
    q.limit = 1; // if the scope were applied AFTER LIMIT, the hidden newer
                 // row would consume the only slot and the visible one
                 // would never be returned.
    auto checked = tracker.query_executions_checked(q, scope);
    REQUIRE(checked.has_value());
    REQUIRE(checked->size() == 1);
    CHECK((*checked)[0].definition_id == "def-visible");
}

TEST_CASE("ExecutionTracker: get_execution_checked distinguishes absent from present",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto absent = tracker.get_execution_checked("no-such-execution");
    REQUIRE(absent.has_value()); // not degraded
    CHECK_FALSE(absent->has_value()); // genuinely absent

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    auto present = tracker.get_execution_checked(*id);
    REQUIRE(present.has_value());
    REQUIRE(present->has_value());
    CHECK((*present)->id == *id);
}

TEST_CASE("ExecutionTracker: get_agent_statuses_for_executions_checked groups by "
          "execution id and short-circuits on empty input without degrading",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_a = tracker.create_execution(make_execution("def-a"));
    auto id_b = tracker.create_execution(make_execution("def-b"));
    REQUIRE(id_a.has_value());
    REQUIRE(id_b.has_value());
    AgentExecStatus a1;
    a1.agent_id = "agent-1";
    a1.status = "success";
    tracker.update_agent_status(*id_a, a1);

    auto checked = tracker.get_agent_statuses_for_executions_checked({*id_a, *id_b});
    REQUIRE(checked.has_value());
    CHECK(checked->at(*id_a).size() == 1);
    CHECK(checked->find(*id_b) == checked->end()); // no rows -> no key, not degrade

    auto empty_result = tracker.get_agent_statuses_for_executions_checked({});
    REQUIRE(empty_result.has_value());
    CHECK(empty_result->empty());
}

TEST_CASE("ExecutionTracker: get_children_checked distinguishes genuinely-no-children "
          "from a degraded read",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    auto checked = tracker.get_children_checked(*id, std::nullopt);
    REQUIRE(checked.has_value());       // not degraded
    CHECK(checked->children.empty());   // genuinely no children
    CHECK_FALSE(checked->truncated);
}

// ── Update Agent Status ────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: update_agent_status dispatched -> running -> success",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    // dispatched
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "dispatched";
    as.dispatched_at = 1000;
    tracker.update_agent_status(*id_result, as);

    // running (first response)
    as.status = "running";
    as.first_response_at = 1001;
    tracker.update_agent_status(*id_result, as);

    // success (terminal)
    as.status = "success";
    as.completed_at = 1002;
    as.exit_code = 0;
    tracker.update_agent_status(*id_result, as);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "success");
    CHECK(statuses[0].exit_code == 0);
}

TEST_CASE("ExecutionTracker: a stale 'running' update arriving AFTER a terminal status does not "
          "regress the row (CHAOS-TTL-1 keepalive hardening)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // security-guardian finding on the CHAOS-TTL-1 agent-core keepalive: the
    // keepalive thread's periodic snapshot-then-write of in_flight_ids_ has
    // no re-check against a command that completes mid-sweep — an ordinary
    // race, no attacker required — so a stale keepalive 'running' response
    // can legitimately arrive at the server strictly AFTER the command's own
    // real terminal response. Without this guard, the unconditional
    // ON CONFLICT upsert would flip an already-terminal row back to
    // status='running', completed_at=0, silently corrupting the executions
    // drawer / SSE / per-agent KPI surface with no self-healing signal ever
    // arriving afterward (agents do not re-send a terminal status).
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus terminal;
    terminal.agent_id = "agent-1";
    terminal.status = "success";
    terminal.dispatched_at = 1000;
    terminal.first_response_at = 1001;
    terminal.completed_at = 1002;
    terminal.exit_code = 0;
    tracker.update_agent_status(*id_result, terminal);

    // A stale keepalive ping, reordered to arrive strictly after the
    // terminal write — same shape as ExecutionTracker::renew_concurrency_
    // claim's caller (notify_exec_tracker's RUNNING case), different
    // (larger, nonzero) exit_code/error_detail to prove these columns are
    // untouched too, not just `status`.
    AgentExecStatus stale_running;
    stale_running.agent_id = "agent-1";
    stale_running.status = "running";
    stale_running.first_response_at = 1050; // later than the real one — must NOT move it either
    stale_running.completed_at = 0;
    stale_running.exit_code = 99;
    stale_running.error_detail = "should never be visible";
    tracker.update_agent_status(*id_result, stale_running);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "success");
    CHECK(statuses[0].completed_at == 1002);
    CHECK(statuses[0].exit_code == 0);
    CHECK(statuses[0].error_detail.empty());
    // first_response_at's own "only fill if zero" rule already protects this
    // column independently of the terminal guard — confirm both hold together.
    CHECK(statuses[0].first_response_at == 1001);

    // A genuine SECOND terminal write (e.g. HA WS-0 redelivery) still applies
    // normally — the guard is scoped to 'running' overwriting terminal, not
    // to terminal-vs-terminal.
    AgentExecStatus second_terminal;
    second_terminal.agent_id = "agent-1";
    second_terminal.status = "failure";
    second_terminal.completed_at = 2000;
    second_terminal.exit_code = 1;
    second_terminal.error_detail = "redelivered as failure";
    tracker.update_agent_status(*id_result, second_terminal);

    auto restatuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(restatuses.size() == 1);
    CHECK(restatuses[0].status == "failure");
    CHECK(restatuses[0].completed_at == 2000);
    CHECK(restatuses[0].error_detail == "redelivered as failure");
}

TEST_CASE("ExecutionTracker: update_agent_status failure with error_detail",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "failure";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 1;
    as.error_detail = "plugin timeout";
    tracker.update_agent_status(*id_result, as);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "failure");
    CHECK(statuses[0].exit_code == 1);
    CHECK(statuses[0].error_detail == "plugin timeout");
}

TEST_CASE("ExecutionTracker: get_agent_statuses multiple agents", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    for (int i = 0; i < 4; ++i) {
        AgentExecStatus as;
        as.agent_id = "agent-" + std::to_string(i);
        as.status = (i < 3) ? "success" : "failure";
        as.dispatched_at = 1000;
        as.completed_at = 1005;
        as.exit_code = (i < 3) ? 0 : 1;
        tracker.update_agent_status(*id_result, as);
    }

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 4);
}

TEST_CASE("ExecutionTracker: update_agent_status on unknown execution_id is a no-op",
          "[pg][execution_tracker][issue872]") {
    // Out-of-band dispatches that bypass the workflow-routes create path
    // (CLI / direct gRPC / re-mapped command_id) can reach
    // update_agent_status with an execution_id that has no row in the
    // `executions` table. The mutator must tolerate this — no crash, no
    // SQL constraint violation. The chained refresh_counts must likewise
    // return cleanly when there is nothing to aggregate.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    AgentExecStatus as;
    as.agent_id = "agent-ghost";
    as.status = "success";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 0;
    // Must not throw, must not abort the test process.
    tracker.update_agent_status("exec-does-not-exist", as);

    // No parent execution row was created; querying it returns empty.
    auto fetched = tracker.get_execution("exec-does-not-exist");
    CHECK_FALSE(fetched.has_value());

    // The agent_exec_status schema has NO foreign-key constraint on
    // execution_id (no `FOREIGN KEY(execution_id) REFERENCES executions(id)`
    // at execution_tracker.cpp lines 105-115), so the orphan row IS written.
    // Pin this as the canonical behaviour — if a future migration adds FK
    // enforcement (so the upsert silently no-ops or sqlite3_step returns
    // SQLITE_CONSTRAINT), this test will flip to size==0 and force a
    // conscious decision about the new contract. Without an explicit size
    // assertion the test would silently pass on either path, masking the
    // schema regression.
    auto statuses = tracker.get_agent_statuses("exec-does-not-exist");
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-ghost");
    CHECK(statuses[0].status == "success");
}

TEST_CASE("ExecutionTracker: update_agent_status alone advances parent aggregates "
          "(chain invariant)",
          "[pg][execution_tracker][issue872]") {
    // UAT 2026-05-06 fix 18e8766 chained refresh_counts inside
    // update_agent_status so callers no longer need an explicit refresh.
    // The `test_rest_api_t2.cpp` cleanup in PR #1068 dropped 7 redundant
    // explicit calls based on this chain. If a future refactor breaks the
    // chain (e.g. moves refresh behind a flag or an async queue),
    // test_rest_api_t2.cpp's lower-bound assertions (>= 2) would still
    // pass with stale aggregates — only the workflow_routes terminal-
    // threshold test would bite. This case pins the chain at the mutator
    // itself so any chain-break fails ONE focused test with a clear name.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.agents_targeted = 1;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 0;
    // Single call, no explicit refresh_counts. The chain inside
    // update_agent_status MUST recompute aggregates and advance status.
    tracker.update_agent_status(*id_result, as);

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_responded == 1);
    CHECK(summary.agents_success == 1);
    CHECK(summary.agents_failure == 0);
}

// ── Summary ────────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: get_summary", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.agents_targeted = 4;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.id == *id_result);
    CHECK(summary.agents_targeted == 4);
}

TEST_CASE("ExecutionTracker: summary after refresh_counts", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.agents_targeted = 3;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());

    // Add agent statuses
    AgentExecStatus s1;
    s1.agent_id = "a1";
    s1.status = "success";
    tracker.update_agent_status(*id_result, s1);

    AgentExecStatus s2;
    s2.agent_id = "a2";
    s2.status = "success";
    tracker.update_agent_status(*id_result, s2);

    AgentExecStatus s3;
    s3.agent_id = "a3";
    s3.status = "failure";
    s3.exit_code = 1;
    tracker.update_agent_status(*id_result, s3);

    // Refresh aggregate counts from agent_exec_status rows
    tracker.refresh_counts(*id_result);

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_responded == 3);
    CHECK(summary.agents_success == 2);
    CHECK(summary.agents_failure == 1);
    CHECK(summary.progress_pct > 0);
}

TEST_CASE("ExecutionTracker: refresh_counts retries and recovers from transient row-lock "
          "contention instead of wedging the execution (governance adversarial review "
          "2026-08-31, CHAOS-01)",
          "[pg][execution_tracker][chaos]") {
    // Reproduces UP-1: the pre-migration SQLite recursive_mutex blocked
    // UNBOUNDEDLY on contention (never dropped an update, only queued); the
    // Postgres port's bounded lock_timeout can cancel a queued
    // refresh_counts call instead, and pre-fix that failure was silent and
    // final — the execution stayed "running" forever. This test proves the
    // fix's single retry recovers once the contending transaction releases,
    // which it reliably does well inside a real lock_timeout window.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::execution_tracker_pg_template);

    // lock_timeout wide enough to be robust to CI scheduling jitter
    // (governance PR review, 2026-08-31, Doomgoose: the original 100ms/150ms
    // pair left only a ~50ms margin on each side, and a mutant that broke the
    // retry was observed to false-green under a loaded run). Attempt 2 gets
    // its OWN fresh lock_timeout window starting when attempt 1 fails
    // (~kLockTimeout after t=0), so the safe range for the release delay is
    // strictly between kLockTimeout and 2*kLockTimeout — kReleaseDelay sits
    // centered in that range with a wide (150ms) margin on both sides.
    constexpr auto kLockTimeout = std::chrono::milliseconds{300};
    constexpr auto kReleaseDelay = std::chrono::milliseconds{450};
    yuzu::server::pg::PgPool store_pool{
        {.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = static_cast<int>(kLockTimeout.count())}};
    REQUIRE(store_pool.valid());
    ExecutionTracker tracker{store_pool};
    REQUIRE(tracker.is_open());

    auto exec = make_execution();
    exec.agents_targeted = 1;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());
    const std::string execution_id = *id_result;

    // A second, independent connection holds an exclusive row lock on the
    // execution for longer than store_pool's lock_timeout, so the FIRST
    // refresh_counts attempt (chained inside update_agent_status) is
    // guaranteed to be cancelled and abandoned.
    yuzu::server::pg::PgPool locker_pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(locker_pool.valid());
    auto locker_lease = locker_pool.try_acquire_for(std::chrono::milliseconds{2000});
    REQUIRE(locker_lease);
    auto begin = pg::exec_params(locker_lease.get(), "BEGIN", std::vector<std::string>{});
    REQUIRE(begin.status() == PGRES_COMMAND_OK);
    auto lock = pg::exec_params(
        locker_lease.get(), "SELECT 1 FROM execution_tracker.executions WHERE id=$1 FOR UPDATE",
        std::vector<std::string>{execution_id});
    REQUIRE(lock.status() == PGRES_TUPLES_OK);

    // Releases the lock partway through the store's retry window — well
    // after kLockTimeout has already cancelled attempt 1, well before a
    // human would notice anything.
    std::thread releaser([&] {
        std::this_thread::sleep_for(kReleaseDelay);
        auto rollback =
            pg::exec_params(locker_lease.get(), "ROLLBACK", std::vector<std::string>{});
        CHECK(rollback.status() == PGRES_COMMAND_OK);
    });

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 0;
    auto before = std::chrono::steady_clock::now();
    tracker.update_agent_status(execution_id, as);
    auto elapsed = std::chrono::steady_clock::now() - before;

    releaser.join();

    // Proves attempt 1 actually got cancelled rather than the test passing
    // by luck (e.g. the lock happening to already be free) — the call must
    // have blocked for at least one full lock_timeout window before the
    // retry could succeed. No log-capture seam exists in this file, so a
    // coarse wall-clock floor is the cheapest reliable proof (governance PR
    // review, 2026-08-31, Doomgoose: "never asserts attempt 1 was
    // cancelled").
    CHECK(elapsed >= kLockTimeout);

    // Pre-fix: this would be stuck at "running" with stale (zero) aggregate
    // counts — attempt 1 was cancelled and nothing ever retried it.
    auto summary = tracker.get_summary(execution_id);
    CHECK(summary.agents_responded == 1);
    CHECK(summary.agents_success == 1);
    auto row = tracker.get_execution(execution_id);
    REQUIRE(row.has_value());
    CHECK(row->status == "succeeded");
}

// ── Parent-Child Hierarchy ─────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: parent-child relationship", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    Execution child = make_execution();
    child.parent_id = *parent_result;
    auto child_result = tracker.create_execution(child);
    REQUIRE(child_result.has_value());

    auto children = tracker.get_children(*parent_result);
    REQUIRE(children.size() == 1);
    CHECK(children[0].parent_id == *parent_result);
}

TEST_CASE("ExecutionTracker: multiple children", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    for (int i = 0; i < 3; ++i) {
        Execution child = make_execution();
        child.parent_id = *parent_result;
        tracker.create_execution(child);
    }

    auto children = tracker.get_children(*parent_result);
    REQUIRE(children.size() == 3);
}

TEST_CASE("ExecutionTracker: get_children empty for execution without children",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    auto children = tracker.get_children(*id_result);
    CHECK(children.empty());
}

// #2146 A2-R1 governance re-review (blocking): get_children_checked's query
// had NO LIMIT at all before this fix -- kExecutionChildrenCap
// (execution_tracker.cpp) queries one row PAST the cap so a parent with
// EXACTLY the cap's worth of children is never misreported as truncated
// (same +1-row sentinel idiom as ScheduleEngine::query_schedules_checked's
// own boundary tests, test_schedule_engine.cpp). Unrestricted (nullopt)
// scope -- the cap value dropped 500->100 in the #2146 A2-R1 Gate 8
// re-review (Astra opinion: ScheduleEngine's fixed no-param kScheduleListCap
// is the closer analogue), but the RAW, unscoped shape this test exercises
// is otherwise unchanged.
TEST_CASE("ExecutionTracker: get_children_checked at exactly the cap is not "
          "misreported as truncated (#2146 A2-R1 boundary)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    for (int i = 0; i < 100; ++i) {
        Execution child = make_execution("def-child-" + std::to_string(i));
        child.parent_id = *parent_result;
        REQUIRE(tracker.create_execution(child).has_value());
    }

    auto checked = tracker.get_children_checked(*parent_result, std::nullopt);
    REQUIRE(checked.has_value());
    CHECK(checked->children.size() == 100);
    CHECK_FALSE(checked->truncated);
}

// Sibling of the exact-cap test above: one child OVER the cap must come back
// capped at 100 rows WITH result.truncated == true -- the honest signal REST
// v1, the legacy route, and MCP all surface as result_truncated_by_cap.
// Before this fix there was no cap at all, so this scenario could not be
// distinguished from "the parent genuinely has 101 children" either --
// worse, an unbounded read.
TEST_CASE("ExecutionTracker: get_children_checked truncates and flags a parent one "
          "over the cap (#2146 A2-R1 boundary)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    for (int i = 0; i < 101; ++i) {
        Execution child = make_execution("def-child-" + std::to_string(i));
        child.parent_id = *parent_result;
        REQUIRE(tracker.create_execution(child).has_value());
    }

    auto checked = tracker.get_children_checked(*parent_result, std::nullopt);
    REQUIRE(checked.has_value());
    CHECK(checked->children.size() == 100);
    CHECK(checked->truncated);
}

// #2146 A2-R1 Gate 8 re-review fix: the exact bug this fold closes -- the
// cap used to apply to the RAW row set BEFORE the caller-side confinement
// filter, so a caller's own visible child could be displaced entirely out
// of the capped window by invisible siblings dispatched more recently
// (dispatched_at DESC). 105 invisible children (dispatched strictly AFTER
// the visible one, so they occupy the top of the DESC-ordered window) plus
// one visible child; a confined scope naming only the visible child's
// dispatcher must still return it, and truncated must be false (the
// caller's OWN visible row set -- one row -- is nowhere near the cap).
TEST_CASE("ExecutionTracker: get_children_checked pushes the scope into SQL "
          "before the cap -- an invisible sibling cannot displace a visible "
          "child out of the capped window (#2146 A2-R1 Gate 8 fix)",
          "[pg][execution_tracker][security]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    Execution visible_child = make_execution("def-visible", "", "someone-else");
    visible_child.parent_id = *parent_result;
    visible_child.dispatched_at = 1000;
    auto visible_id = tracker.create_execution(visible_child);
    REQUIRE(visible_id.has_value());
    AgentExecStatus visible_status;
    visible_status.agent_id = "agent-visible";
    visible_status.status = "success";
    tracker.update_agent_status(*visible_id, visible_status);

    for (int i = 0; i < 105; ++i) {
        Execution invisible_child = make_execution("def-invisible-" + std::to_string(i), "",
                                                    "someone-else");
        invisible_child.parent_id = *parent_result;
        // Strictly newer than the visible child -> every one of these sorts
        // ahead of it in the dispatched_at DESC window the old, unscoped cap
        // used to apply.
        invisible_child.dispatched_at = 2000 + i;
        auto invisible_id = tracker.create_execution(invisible_child);
        REQUIRE(invisible_id.has_value());
        AgentExecStatus invisible_status;
        invisible_status.agent_id = "agent-invisible-" + std::to_string(i);
        invisible_status.status = "success";
        tracker.update_agent_status(*invisible_id, invisible_status);
    }

    yuzu::server::ExecutionListScope scope;
    scope.owner = "nobody-owns-these"; // not the dispatcher of any child here
    scope.visible_agents = {"agent-visible"};

    auto checked = tracker.get_children_checked(*parent_result, scope);
    REQUIRE(checked.has_value());
    REQUIRE(checked->children.size() == 1);
    CHECK(checked->children[0].id == *visible_id);
    CHECK_FALSE(checked->truncated);
}

// At-cap boundary for the SCOPED (visible) count, not the raw count: exactly
// 100 vs 101 children visible to the caller, each mixed in among invisible
// siblings so the boundary genuinely exercises the scoped SQL path rather
// than degenerating into the unscoped test above.
TEST_CASE("ExecutionTracker: get_children_checked's cap boundary is the "
          "caller's VISIBLE child count -- not the raw row count "
          "(#2146 A2-R1 Gate 8 fix)",
          "[pg][execution_tracker][security]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto make_visible_batch = [&](const std::string& parent_id, int count) {
        for (int i = 0; i < count; ++i) {
            Execution child = make_execution("def-vis-" + std::to_string(i), "", "someone-else");
            child.parent_id = parent_id;
            child.dispatched_at = 1000 + i;
            auto id = tracker.create_execution(child);
            REQUIRE(id.has_value());
            AgentExecStatus s;
            s.agent_id = "agent-visible";
            s.status = "success";
            tracker.update_agent_status(*id, s);
        }
    };
    auto make_invisible_batch = [&](const std::string& parent_id, int count) {
        for (int i = 0; i < count; ++i) {
            Execution child = make_execution("def-inv-" + std::to_string(i), "", "someone-else");
            child.parent_id = parent_id;
            child.dispatched_at = 5000 + i;
            auto id = tracker.create_execution(child);
            REQUIRE(id.has_value());
            AgentExecStatus s;
            s.agent_id = "agent-invisible-" + std::to_string(i);
            s.status = "success";
            tracker.update_agent_status(*id, s);
        }
    };

    yuzu::server::ExecutionListScope scope;
    scope.owner = "nobody-owns-these";
    scope.visible_agents = {"agent-visible"};

    SECTION("exactly 100 visible children, plus invisible noise, is not truncated") {
        auto parent_result = tracker.create_execution(make_execution());
        REQUIRE(parent_result.has_value());
        make_visible_batch(*parent_result, 100);
        make_invisible_batch(*parent_result, 20);

        auto checked = tracker.get_children_checked(*parent_result, scope);
        REQUIRE(checked.has_value());
        CHECK(checked->children.size() == 100);
        CHECK_FALSE(checked->truncated);
    }

    SECTION("101 visible children, plus invisible noise, is truncated at 100") {
        auto parent_result = tracker.create_execution(make_execution());
        REQUIRE(parent_result.has_value());
        make_visible_batch(*parent_result, 101);
        make_invisible_batch(*parent_result, 20);

        auto checked = tracker.get_children_checked(*parent_result, scope);
        REQUIRE(checked.has_value());
        CHECK(checked->children.size() == 100);
        CHECK(checked->truncated);
    }
}

// #2146 A2-R1 Gate 8 review round: a migration adding a supporting index on
// executions(parent_id) was authored and then removed before this PR merged
// (adversarial review found it a docs/postgres-store-playbook.md
// non-transactional-migration policy-floor violation on an already-non-empty
// table -- see execution_tracker.cpp's trailing comment inside kMigrations,
// after the v5 entry, and #4624). get_children_checked's query is therefore
// a deliberate, disclosed sequential scan today; the test below pins its
// statement_timeout bound instead of an index-presence assertion.

// #2146 A2-R1 Gate 8 fix: get_children_checked's query ran under the pool's
// 30s default statement_timeout, vastly exceeding the ~1.5s acquire budget
// every other reader of this shared pool assumes (rbac_store included). Hold
// an ACCESS EXCLUSIVE lock on `executions` from a SEPARATE side connection
// (never the tracker's own pool, so the tracker stays "open" and this is a
// genuine single-statement stall, not a pool/connection outage) and confirm
// get_children_checked returns degraded (nullopt) at roughly the SET LOCAL
// statement_timeout (~1.5s), never blocking anywhere near the pool's 30s
// default or the connection-level 10s lock_timeout (pg_pool.hpp) -- both of
// which are strictly larger, so the SET LOCAL override must be the one that
// actually fires.
TEST_CASE("ExecutionTracker: get_children_checked's statement_timeout fires "
          "well under the pool's 30s default (#2146 A2-R1 Gate 8 fix)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    pg::PgConn locker{PQconnectdb(tracker_bundle.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        pg::PgResult begin = pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{});
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        pg::PgResult lock = pg::exec_params(
            locker.get(), "LOCK TABLE execution_tracker.executions IN ACCESS EXCLUSIVE MODE",
            std::vector<std::string>{});
        REQUIRE(lock.status() == PGRES_COMMAND_OK);
    }

    const auto t0 = std::chrono::steady_clock::now();
    auto checked = tracker.get_children_checked(*parent_result, std::nullopt);
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    // Release the lock regardless of the assertion outcome below.
    pg::PgResult rollback =
        pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{});
    (void)rollback;

    CHECK_FALSE(checked.has_value());
    CHECK(elapsed < std::chrono::seconds(8));
}

// ── Rerun ──────────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: create_rerun all agents", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    // Simulate agent statuses
    AgentExecStatus s1;
    s1.agent_id = "a1";
    s1.status = "success";
    tracker.update_agent_status(*id_result, s1);

    AgentExecStatus s2;
    s2.agent_id = "a2";
    s2.status = "failure";
    s2.exit_code = 1;
    tracker.update_agent_status(*id_result, s2);

    auto rerun_result = tracker.create_rerun(*id_result, "admin", false);
    REQUIRE(rerun_result.has_value());

    auto rerun = tracker.get_execution(*rerun_result);
    REQUIRE(rerun.has_value());
    CHECK(rerun->rerun_of == *id_result);
    CHECK(rerun->definition_id == "def-001");
}

TEST_CASE("ExecutionTracker: create_rerun failed_only", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus s1;
    s1.agent_id = "a1";
    s1.status = "success";
    tracker.update_agent_status(*id_result, s1);

    AgentExecStatus s2;
    s2.agent_id = "a2";
    s2.status = "failure";
    s2.exit_code = 1;
    tracker.update_agent_status(*id_result, s2);

    AgentExecStatus s3;
    s3.agent_id = "a3";
    s3.status = "failure";
    s3.exit_code = 2;
    tracker.update_agent_status(*id_result, s3);

    auto rerun_result = tracker.create_rerun(*id_result, "admin", true);
    REQUIRE(rerun_result.has_value());

    auto rerun = tracker.get_execution(*rerun_result);
    REQUIRE(rerun.has_value());
    CHECK(rerun->rerun_of == *id_result);
}

TEST_CASE("ExecutionTracker: create_rerun nonexistent fails", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto rerun_result = tracker.create_rerun("nonexistent-id", "admin", false);
    CHECK(!rerun_result.has_value());
}

// ── Mark Cancelled ─────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: mark_cancelled", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    CHECK(tracker.mark_cancelled(*id_result, "admin"));

    auto exec = tracker.get_execution(*id_result);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");
    CHECK(exec->completed_at > 0);
}

TEST_CASE("ExecutionTracker: mark_cancelled sets completed_at", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    auto before = tracker.get_execution(*id_result);
    REQUIRE(before.has_value());
    CHECK(before->completed_at == 0);

    CHECK(tracker.mark_cancelled(*id_result, "operator1"));

    auto after = tracker.get_execution(*id_result);
    REQUIRE(after.has_value());
    CHECK(after->completed_at > 0);
}

// ── CC-07 typed plugin result status (PR1.1 finding F11) ───────────────────
//
// update_agent_status binds plugin_result_status into agent_exec_status and
// get_agent_statuses reads it back, but no test set it to anything but the
// 0/UNDECLARED default — so binding a literal 0, or dropping the column from
// the ON CONFLICT update list, would have left the suite green while the
// executions drawer silently lost every plugin-reported status. Values mirror
// YuzuResultStatus in sdk/include/yuzu/plugin.h (4 = CONSTRAINED, 2 =
// UNAVAILABLE), chosen distinct from exit_code so a crossed bind is caught.

TEST_CASE("ExecutionTracker: plugin_result_status round-trips through update/get (CC-07)",
          "[pg][execution_tracker][cc07]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus s;
    s.agent_id = "agent-1";
    s.status = "success";
    s.exit_code = 0;
    s.plugin_result_status = 4; // CONSTRAINED
    tracker.update_agent_status(*id_result, s);

    // An agent whose plugin reported nothing stays honestly undeclared.
    AgentExecStatus silent;
    silent.agent_id = "agent-2";
    silent.status = "success";
    tracker.update_agent_status(*id_result, silent);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 2);
    int seen = 0;
    for (const auto& st : statuses) {
        if (st.agent_id == "agent-1") {
            CHECK(st.plugin_result_status == 4);
            ++seen;
        } else if (st.agent_id == "agent-2") {
            CHECK(st.plugin_result_status == 0);
            ++seen;
        }
    }
    CHECK(seen == 2);
}

TEST_CASE("ExecutionTracker: a later frame overwrites the typed status via ON CONFLICT (CC-07)",
          "[pg][execution_tracker][cc07]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus running;
    running.agent_id = "agent-1";
    running.status = "running";
    running.plugin_result_status = 0; // nothing reported yet
    tracker.update_agent_status(*id_result, running);

    AgentExecStatus terminal;
    terminal.agent_id = "agent-1";
    terminal.status = "failure";
    terminal.exit_code = 1;
    terminal.plugin_result_status = 2; // UNAVAILABLE
    tracker.update_agent_status(*id_result, terminal);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "failure");
    CHECK(statuses[0].plugin_result_status == 2);
}

TEST_CASE("ExecutionTracker: a store bound to an unreachable pool degrades every method, "
          "never crashes",
          "[execution_tracker]") {
    // A store that never opened, ported to Postgres (ADR-0065): an unreachable
    // port fails construction's own connect attempt deterministically
    // (test_engine_principal_store.cpp's #2456 precedent) — no live database
    // needed, so this test carries no [pg] tag. Mirrors
    // test_approval_manager.cpp's equivalent closed-store coverage.
    pg::PgPool unreachable{{.conninfo = "host=127.0.0.1 port=1 dbname=yuzu connect_timeout=1",
                            .size = 1,
                            .connect_timeout_s = 1}};
    REQUIRE(unreachable.valid()); // conninfo parses; the host is just unreachable
    ExecutionTracker closed(unreachable);
    REQUIRE(!closed.is_open());

    CHECK(closed.query_executions(ExecutionQuery{}).empty());
    CHECK_FALSE(closed.get_execution("exec-1").has_value());
    CHECK(closed.get_summary("exec-1").id == "exec-1"); // id echoed, everything else defaulted
    CHECK(closed.get_agent_statuses("exec-1").empty());

    // #3789: the checked twins must fail closed (nullopt/unexpected), not
    // collapse to the plain methods' empty-on-degrade shape — a caller that
    // drops rows or writes `denied` audit rows off these results must be
    // able to tell "degraded" from "genuinely nothing here".
    CHECK_FALSE(closed.query_executions_checked(ExecutionQuery{}).has_value());
    auto exec_checked = closed.get_execution_checked("exec-1");
    REQUIRE_FALSE(exec_checked.has_value());
    CHECK(exec_checked.error() == "execution tracker not open");
    CHECK_FALSE(closed.get_children_checked("exec-1", std::nullopt).has_value());
    CHECK_FALSE(
        closed.get_agent_statuses_for_executions_checked({"exec-1"}).has_value());
    // Engaged-empty still short-circuits on a closed store — zero requested
    // ids is a success-empty outcome, not a degrade, regardless of whether
    // the store could otherwise serve the request.
    auto empty_ids_result = closed.get_agent_statuses_for_executions_checked({});
    REQUIRE(empty_ids_result.has_value());
    CHECK(empty_ids_result->empty());

    auto created = closed.create_execution(make_execution());
    REQUIRE_FALSE(created.has_value());
    CHECK(created.error() == "database not open");

    // Mutations on a closed store are no-ops, not crashes — and the two
    // that report success/failure (governance PR review, 2026-08-31) must
    // honestly report failure rather than silently claiming success.
    AgentExecStatus status;
    status.agent_id = "agent-1";
    status.status = "running";
    closed.update_agent_status("exec-1", status);
    closed.refresh_counts("exec-1");
    CHECK_FALSE(closed.mark_cancelled("exec-1", "tester"));
    CHECK_FALSE(closed.set_agents_targeted("exec-1", 1));
}

// "v2 probe stamps straight through..."/"v2 probe does not silently skip
// v1's CREATE INDEX..."/"v2 probe refuses to stamp when only SOME of v1's
// indexes are present" (UP-12/A-5/D4(a)/CDX-P1-04) are DELETED, not ported
// (ADR-0065) — they pinned SQLite-era migration-probe logic (a hand-rolled
// pre-migration check reconciling a partially-hand-surgeried schema against
// schema_meta before running MigrationRunner) that has no equivalent once
// the v1+v2 ladder folds into one PG v1 DDL created fresh on an empty
// schema: there is no "column pre-exists but the index doesn't" state a
// fresh Postgres schema can ever be in. See test_approval_manager.cpp's
// equivalent deletions for the same reasoning applied to that store's own
// SQLite migration-ladder-specific tests.

// ── Command <-> execution correlation (HA WS-1(1b), ADR-2002 section 5) ────
//
// WS-9 failover scenario: proves the cross-instance property this migration
// exists to deliver — a mapping written through one ExecutionTracker
// instance (dispatch, "replica A") is resolvable through a SEPARATE
// ExecutionTracker instance pointed at the same database ("replica B").
// The former in-process map could never pass this: it was populated only
// in the writer's own process memory.

TEST_CASE("ExecutionTracker: record/lookup command_execution round-trips",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    CHECK_FALSE(tracker_bundle->lookup_execution_id("cmd-unknown").has_value());

    REQUIRE(tracker_bundle->record_command_execution("cmd-1", "exec-1"));
    auto looked_up = tracker_bundle->lookup_execution_id("cmd-1");
    REQUIRE(looked_up.has_value());
    CHECK(*looked_up == "exec-1");

    // Last-write-wins on a repeated command_id (mirrors the former map's
    // operator[]= semantics).
    REQUIRE(tracker_bundle->record_command_execution("cmd-1", "exec-2"));
    looked_up = tracker_bundle->lookup_execution_id("cmd-1");
    REQUIRE(looked_up.has_value());
    CHECK(*looked_up == "exec-2");

    // Empty execution_id deletes the mapping (the former map's explicit-
    // clear branch).
    REQUIRE(tracker_bundle->record_command_execution("cmd-1", ""));
    CHECK_FALSE(tracker_bundle->lookup_execution_id("cmd-1").has_value());
}

TEST_CASE("ExecutionTracker: lookup is non-destructive across a multi-agent "
          "fan-out (HF-1)",
          "[pg][execution_tracker]") {
    // One command_id dispatched to N agents; each sends its own terminal
    // response against the SAME command_id. A lookup must never consume the
    // mapping, or agents 2..N would find nothing to stamp.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    REQUIRE(tracker_bundle->record_command_execution("cmd-fanout", "exec-fanout"));

    for (int i = 0; i < 5; ++i) {
        auto looked_up = tracker_bundle->lookup_execution_id("cmd-fanout");
        REQUIRE(looked_up.has_value());
        CHECK(*looked_up == "exec-fanout");
    }
}

TEST_CASE("ExecutionTracker: a command_execution mapping written on one "
          "instance resolves on a SEPARATE instance against the same "
          "database (WS-9 failover scenario)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle; // "replica A" — dispatches

    REQUIRE(tracker_bundle->record_command_execution("cmd-cross-replica", "exec-cross-replica"));

    // "replica B" — a second pool AND a second ExecutionTracker instance
    // against the SAME database, sharing no process memory with A. The
    // in-process map this migration replaces could never resolve this: it
    // was populated only in A's own memory.
    pg::PgPool pool_b{{.conninfo = tracker_bundle.dsn(), .size = 2}};
    ExecutionTracker tracker_b{pool_b};
    REQUIRE(tracker_b.is_open());

    auto looked_up = tracker_b.lookup_execution_id("cmd-cross-replica");
    REQUIRE(looked_up.has_value());
    CHECK(*looked_up == "exec-cross-replica");
}

TEST_CASE("ExecutionTracker: a store bound to an unreachable pool degrades "
          "command_execution methods without crashing",
          "[execution_tracker]") {
    pg::PgPool unreachable{{.conninfo = "host=127.0.0.1 port=1 dbname=yuzu connect_timeout=1",
                            .size = 1,
                            .connect_timeout_s = 1}};
    ExecutionTracker closed(unreachable);
    REQUIRE(!closed.is_open());

    CHECK_FALSE(closed.record_command_execution("cmd-1", "exec-1")); // no-op, not a crash
    CHECK_FALSE(closed.lookup_execution_id("cmd-1").has_value());
    auto reaped = closed.reap_command_execution_mappings();
    REQUIRE_FALSE(reaped.has_value());
    CHECK(reaped.error() == "execution tracker not open");
}

TEST_CASE("ExecutionTracker: reap_command_execution_mappings deletes only "
          "aged-out rows, is capped, and is clock-guarded",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    REQUIRE(tracker_bundle->record_command_execution("cmd-fresh", "exec-fresh"));
    REQUIRE(tracker_bundle->lookup_execution_id("cmd-fresh").has_value());

    // First pass: no anchor yet, nothing aged out (the fresh row's
    // created_at is "now", far inside the 24h retention window) — proceeds
    // (missing-anchor PROCEED decision) but deletes 0 rows.
    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK(first->deleted == 0);
    CHECK_FALSE(first->clock_anomaly);
    CHECK(tracker_bundle->lookup_execution_id("cmd-fresh").has_value());

    // Directly age the row past the retention window by rewriting
    // created_at through a second connection on the same pool (the public
    // API has no "backdate" hook by design — this is the test-only path,
    // mirroring how test_session_store.cpp pokes session_meta directly).
    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.command_execution SET created_at = created_at - 90000 "
            "WHERE command_id = 'cmd-fresh'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    } // lease released here, before the reap below acquires its own

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 1);
    CHECK_FALSE(second->clock_anomaly);
    CHECK_FALSE(tracker_bundle->lookup_execution_id("cmd-fresh").has_value());
}

TEST_CASE("ExecutionTracker: reap declines on an implausibly-forward "
          "anchor gap (forward-skew decline)",
          "[pg][execution_tracker]") {
    // Governance Gate 4/5/6 finding (consistency-auditor + chaos-injector
    // CH-4): the forward/backward anomaly-decline branches were previously
    // untested for this reap, unlike SessionStore's equivalent guard.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    // Establish a real anchor via one ordinary pass.
    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    // Rewrite the persisted anchor to look implausibly far in the PAST
    // relative to the real DB clock — from the next pass's point of view,
    // now_s reads as far ahead of the anchor, exactly the forward-skew
    // shape a poisoned or stale anchor produces.
    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "(value::bigint - 200000)::text WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on a backward-stepped clock "
          "(backward-anomaly decline)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    // Rewrite the persisted anchor to look far in the FUTURE relative to
    // the real DB clock — the next pass's now_s reads as BEHIND the
    // anchor, the backward-clock-movement shape (a rewound host clock, or
    // an earlier forward-skewed pass that poisoned the anchor).
    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "(value::bigint + 200000)::text WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on an unparseable persisted "
          "anchor (adversarial review Blocker, PR #3780)",
          "[pg][execution_tracker]") {
    // CLAUDE.md's clock-guarded-retention part 3: "SANITISE that reading
    // (ahead-of-now / negative / unparseable = anomaly, never a quiet
    // reset)". A bad migration, a manual reap_meta repair, or storage
    // corruption can write anything into this plain key/value table — the
    // parse must REJECT junk, never silently truncate/coerce it via an
    // unchecked strtoll (the finding this test locks: `to_i64`'s prior
    // zero-validation parse would have accepted "123junk" as 123, with no
    // rejection and no counted anomaly).
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = '123junk' "
            "WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on a negative persisted anchor "
          "(adversarial review Blocker, PR #3780)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(),
                                   "UPDATE execution_tracker.reap_meta SET value = '-1' "
                                   "WHERE key = 'cmd_exec_reap_anchor'",
                                   std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on an overflowed persisted "
          "anchor (adversarial review Blocker, PR #3780)",
          "[pg][execution_tracker]") {
    // A value strtoll cannot represent (beyond int64_t range) must be
    // rejected via the errno==ERANGE check, not wrapped/clamped by
    // static_cast<int64_t> on an already-saturated `long long`.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "'99999999999999999999999999' WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap does not overflow on a legitimately-parsed "
          "INT64_MAX anchor (adversarial review Blocker round 2, PR #3780)",
          "[pg][execution_tracker]") {
    // Distinct from the "overflowed" test above: that one exercises a
    // string strtoll cannot even PARSE (rejected by parse_reap_i64 itself,
    // via errno==ERANGE). THIS value parses cleanly and is >= 0, so it
    // passes parse_reap_i64 -- the residual defect was in the CONSUMING
    // arithmetic (`anchor + kMaxPlausibleSkewSecs`), not the parse. Under
    // UBSan this specific value reproduces "signed integer overflow:
    // 9223372036854775807 + 86400 cannot be represented in type 'long
    // int'" against the pre-fix comparison. The fixed comparison
    // (`now_s - anchor > kMaxPlausibleSkewSecs`, both operands already
    // non-negative) must decline this as a forward-skew anomaly without
    // invoking UB.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "'9223372036854775807' WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: the four non-tracked correlation-id VALUES "
          "round-trip opaquely through the PG-backed store",
          "[pg][execution_tracker]") {
    // Governance Gate 4 consistency-auditor finding / chaos-injector CH-5,
    // corrected per Gate 8 quality-engineer re-review: polchk-/bundle-/
    // preflight-/deployment- are minted as the execution_id VALUE (by
    // PolicyEvaluator/BundleOrchestrator/PreflightRunner/the deployment
    // engine), never as the command_id KEY — the ORIGINAL version of this
    // test looked up an unwritten prefixed STRING AS A KEY, which is
    // vacuously nullopt for any string and proved nothing (a false-green
    // policy-floor finding, caught before merge). The real property: the
    // store must treat these values as opaque data, storing and returning
    // them byte-for-byte under an ordinary command_id key — the
    // PREFIX-SKIP decision itself lives in AgentServiceImpl::
    // notify_exec_tracker (see the companion test in
    // test_agent_service_impl.cpp), not in the store.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    for (const std::string execution_id :
         {"polchk-abc123", "bundle-def456", "preflight-run1-check2", "deployment-xyz-stage"}) {
        CAPTURE(execution_id);
        const std::string command_id = "plugin-cmd-" + execution_id;
        REQUIRE(tracker_bundle->record_command_execution(command_id, execution_id));
        auto looked_up = tracker_bundle->lookup_execution_id(command_id);
        REQUIRE(looked_up.has_value());
        CHECK(*looked_up == execution_id);
    }
}

// ── Per-device concurrency claims (ADR-1007) ────────────────────────────────

TEST_CASE("ExecutionTracker: claim_concurrency_slots wins an uncontested claim",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto claimed = tracker.claim_concurrency_slots("def-conc-1", "exec-1", "cmd-test-1", {"agent-a", "agent-b"},
                                                    /*expires_at=*/9999999999);
    CHECK(claimed.size() == 2);
    CHECK(std::find(claimed.begin(), claimed.end(), "agent-a") != claimed.end());
    CHECK(std::find(claimed.begin(), claimed.end(), "agent-b") != claimed.end());
}

TEST_CASE("ExecutionTracker: claim_concurrency_slots refuses an agent already claimed for the "
          "SAME definition_id",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto first =
        tracker.claim_concurrency_slots("def-conc-2", "exec-1", "cmd-test-2", {"agent-a"}, 9999999999);
    REQUIRE(first.size() == 1);

    // Same definition, same agent, a DIFFERENT execution — this is exactly
    // the same-device-double-dispatch scenario the whole mechanism exists
    // to prevent. The partial unique index (ux_concurrency_claims_open), not
    // any timing, is what makes this deterministic — a plain sequential
    // second call already exercises the constraint that a real concurrent
    // race would also hit; see the dedicated race test below for genuine
    // thread contention on the same claim.
    auto second =
        tracker.claim_concurrency_slots("def-conc-2", "exec-2", "cmd-test-3", {"agent-a"}, 9999999999);
    CHECK(second.empty());
}

TEST_CASE("ExecutionTracker: claim_concurrency_slots does NOT block a DIFFERENT definition_id "
          "on the same agent",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Real duplicate-(plugin,action) definitions exist in shipped content
    // (antivirus/status, filesystem/replace, filesystem/get_version_info) —
    // the claim is keyed on definition_id, never (plugin,action), and this
    // proves two DIFFERENT definitions never cross-block each other even
    // when they would resolve to the same agent plugin call.
    auto first = tracker.claim_concurrency_slots("def-conc-A", "exec-1", "cmd-test-4", {"agent-a"}, 9999999999);
    auto second =
        tracker.claim_concurrency_slots("def-conc-B", "exec-2", "cmd-test-5", {"agent-a"}, 9999999999);
    CHECK(first.size() == 1);
    CHECK(second.size() == 1);
}

TEST_CASE("ExecutionTracker: two threads racing the SAME (definition_id, agent_id) — exactly "
          "one wins",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Genuine concurrent contention (not just the sequential-call proof
    // above) — the pool hands each thread its own connection, and the
    // partial unique index is what actually serializes the two INSERTs.
    // Gate 3 quality-engineer SHOULD: correctness here holds regardless of
    // true overlap (a single atomic INSERT...ON CONFLICT can't leak a
    // second winner even if the two calls happen to run sequentially), but
    // a rendezvous barrier makes this an actual concurrency stress test
    // rather than a restatement of the sequential proof above — both
    // threads submit at the same instant instead of whichever the OS
    // scheduler happens to run first.
    std::latch start_gate{2};
    std::atomic<int> won{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&] {
            start_gate.arrive_and_wait();
            auto claimed = tracker.claim_concurrency_slots("def-conc-race", "exec-race", "cmd-test-6",
                                                            {"agent-race"}, 9999999999);
            if (!claimed.empty())
                won.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads)
        t.join();
    CHECK(won.load() == 1);
}

TEST_CASE("ExecutionTracker: release_concurrency_claim frees the slot for a new claim",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto first =
        tracker.claim_concurrency_slots("def-conc-3", "exec-1", "cmd-test-7", {"agent-a"}, 9999999999);
    REQUIRE(first.size() == 1);
    tracker.release_concurrency_claim("def-conc-3", "exec-1", "agent-a");

    auto second =
        tracker.claim_concurrency_slots("def-conc-3", "exec-2", "cmd-test-8", {"agent-a"}, 9999999999);
    CHECK(second.size() == 1);
}

TEST_CASE("ExecutionTracker: release_concurrency_claim/s do NOT cross-release a different "
          "definition's open claim when execution_id collides (Gate 2 security-guardian "
          "finding, PR #3784 fix round)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // Every workflow-step dispatch (workflow_routes.cpp) shares the literal
    // empty string as execution_id across EVERY definition it dispatches
    // (CONSIST-2/sec-M2, pending real correlation) — so two DIFFERENT
    // per-device definitions can each hold a genuinely open claim on the
    // same agent under the SAME (empty) execution_id at the same time.
    // Releasing/renewing by (execution_id, agent_id) alone would therefore
    // touch BOTH definitions' rows on a release meant for only one —
    // reopening the exact double-dispatch race this feature exists to
    // prevent for whichever definition's claim got released early.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    const std::string shared_exec_id; // the empty-string collision, verbatim

    auto claim_x =
        tracker.claim_concurrency_slots("def-conc-collide-x", shared_exec_id, "cmd-test-9", {"agent-a"},
                                        9999999999);
    REQUIRE(claim_x.size() == 1);
    auto claim_y =
        tracker.claim_concurrency_slots("def-conc-collide-y", shared_exec_id, "cmd-test-10", {"agent-a"},
                                        9999999999);
    REQUIRE(claim_y.size() == 1); // different definition_id — NOT blocked by X's claim

    // Release Y's claim only. X must stay open.
    tracker.release_concurrency_claim("def-conc-collide-y", shared_exec_id, "agent-a");

    auto x_still_open = tracker.claim_concurrency_slots("def-conc-collide-x", "exec-other", "cmd-test-11",
                                                         {"agent-a"}, 9999999999);
    CHECK(x_still_open.empty()); // still held by the original claim — NOT released

    auto y_now_free = tracker.claim_concurrency_slots("def-conc-collide-y", "exec-other", "cmd-test-12",
                                                       {"agent-a"}, 9999999999);
    REQUIRE(y_now_free.size() == 1); // Y's release worked correctly
    // Release this probe claim too, or the batched re-claim below (a
    // DIFFERENT execution_id) legitimately fails — Y would still be held.
    tracker.release_concurrency_claim("def-conc-collide-y", "exec-other", "agent-a");

    // Batched sibling: re-claim Y, then release it via release_concurrency_claims
    // alongside an id that was never claimed at all — same collision shape.
    auto claim_y2 = tracker.claim_concurrency_slots("def-conc-collide-y", shared_exec_id, "cmd-test-13",
                                                     {"agent-a"}, 9999999999);
    REQUIRE(claim_y2.size() == 1);
    tracker.release_concurrency_claims("def-conc-collide-y", shared_exec_id, {"agent-a"});

    auto x_still_open2 = tracker.claim_concurrency_slots("def-conc-collide-x", "exec-other2", "cmd-test-14",
                                                          {"agent-a"}, 9999999999);
    CHECK(x_still_open2.empty()); // X's claim survives the batched release too
}

TEST_CASE("ExecutionTracker: renew_concurrency_claim does NOT touch a different definition's "
          "open claim when execution_id collides (Gate 3 quality-engineer finding, PR #3784 "
          "fix round)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // Sibling gap to the release_concurrency_claim/s test above — renew_concurrency_claim
    // shares the identical unscoped-match hazard (fixed with the identical definition_id
    // parameter, same fix round) but had no direct regression test of its own; the only
    // test that reaches it (the CHAOS-TTL-1 renewal test) uses a single definition_id, so
    // it cannot detect a dropped/misordered definition_id filter in renew's WHERE clause.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    const std::string shared_exec_id; // the empty-string collision, verbatim
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();

    // X claims with a short TTL (about to expire); Y claims with a long one.
    auto claim_x = tracker.claim_concurrency_slots("def-conc-renew-x", shared_exec_id, "cmd-test-15",
                                                    {"agent-a"}, /*expires_at=*/now + 2);
    REQUIRE(claim_x.size() == 1);
    auto claim_y = tracker.claim_concurrency_slots("def-conc-renew-y", shared_exec_id, "cmd-test-16",
                                                    {"agent-a"}, /*expires_at=*/now + 2);
    REQUIRE(claim_y.size() == 1); // different definition_id — NOT blocked by X's claim

    // Renew ONLY Y. If renew_concurrency_claim's WHERE clause lost its
    // definition_id scoping, this UPDATE would touch BOTH rows (same
    // execution_id, same agent_id) and X's claim would be renewed too —
    // silently reopening this fix's own hazard on the renewal side.
    tracker.renew_concurrency_claim("def-conc-renew-y", shared_exec_id, "agent-a");

    // Prime the reconciler anchor, then advance past X's ORIGINAL (unrenewed)
    // expiry. X must be force-released; Y must NOT be — proving the renewal
    // only ever touched Y's row.
    REQUIRE(tracker.reconcile_stale_concurrency_claims(now) == 0);
    auto released = tracker.reconcile_stale_concurrency_claims(now + 5);
    CHECK(released == 1); // only X's claim was past its (unrenewed) expiry

    auto x_free = tracker.claim_concurrency_slots("def-conc-renew-x", "exec-other", "cmd-test-17",
                                                   {"agent-a"}, 9999999999);
    CHECK(x_free.size() == 1); // X force-released — never renewed by Y's call

    auto y_still_open = tracker.claim_concurrency_slots("def-conc-renew-y", "exec-other", "cmd-test-18",
                                                         {"agent-a"}, 9999999999);
    CHECK(y_still_open.empty()); // Y's claim survived — it WAS correctly renewed
}

TEST_CASE("ExecutionTracker: update_agent_status releases the claim on a terminal status, NOT "
          "on 'running'",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec_id = tracker.create_execution(make_execution("def-conc-4"));
    REQUIRE(exec_id.has_value());
    auto first =
        tracker.claim_concurrency_slots("def-conc-4", *exec_id, "cmd-test-19", {"agent-a"}, 9999999999);
    REQUIRE(first.size() == 1);

    AgentExecStatus running;
    running.agent_id = "agent-a";
    running.status = "running";
    tracker.update_agent_status(*exec_id, running);

    // Still held — 'running' is not terminal.
    auto still_busy =
        tracker.claim_concurrency_slots("def-conc-4", "exec-other", "cmd-test-20", {"agent-a"}, 9999999999);
    CHECK(still_busy.empty());

    AgentExecStatus success;
    success.agent_id = "agent-a";
    success.status = "success";
    tracker.update_agent_status(*exec_id, success);

    // Released now.
    auto now_free =
        tracker.claim_concurrency_slots("def-conc-4", "exec-other", "cmd-test-21", {"agent-a"}, 9999999999);
    CHECK(now_free.size() == 1);
}

TEST_CASE("ExecutionTracker: mark_cancelled does NOT release open claims — cancel is server "
          "bookkeeping only, the agent may still be executing",
          "[pg][execution_tracker][concurrency]") {
    // ADR-1007 correctness fix (Gate 4 unhappy-path UP-1): there is no
    // gRPC cancel/kill RPC to the agent, so releasing the claim here would
    // let a duplicate dispatch land on a still-executing agent — the exact
    // race per-device enforcement exists to prevent. Claims release only
    // via a genuine terminal agent response or the stale-claim reconciler.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec_id = tracker.create_execution(make_execution("def-conc-5"));
    REQUIRE(exec_id.has_value());
    auto claimed = tracker.claim_concurrency_slots("def-conc-5", *exec_id, "cmd-test-22",
                                                    {"agent-a", "agent-b"}, 9999999999);
    REQUIRE(claimed.size() == 2);

    REQUIRE(tracker.mark_cancelled(*exec_id, "tester"));

    // Still held — cancelling server-side bookkeeping proves nothing about
    // whether the agent actually stopped.
    auto still_a =
        tracker.claim_concurrency_slots("def-conc-5", "exec-other", "cmd-test-23", {"agent-a"}, 9999999999);
    auto still_b =
        tracker.claim_concurrency_slots("def-conc-5", "exec-other", "cmd-test-24", {"agent-b"}, 9999999999);
    CHECK(still_a.empty());
    CHECK(still_b.empty());

    // A genuine terminal response DOES release it, cancel notwithstanding.
    AgentExecStatus done;
    done.agent_id = "agent-a";
    done.status = "success";
    tracker.update_agent_status(*exec_id, done);
    CHECK(tracker.claim_concurrency_slots("def-conc-5", "exec-other", "cmd-test-25", {"agent-a"}, 9999999999)
              .size() == 1);
}

TEST_CASE("ExecutionTracker: reconcile_stale_concurrency_claims force-releases a claim past its "
          "own expires_at",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    const int64_t now = 2000000000;
    // Prime the persisted anchor first — a reconcile pass with an expired
    // claim but NO prior anchor correctly declines as Anomaly::NoAnchor
    // (audit_retention_rules.hpp's documented behavior: a fresh process
    // with something already expired and no comparison point must not
    // assume its own clock is trustworthy). This priming call has nothing
    // expired yet, so it short-circuits to None and just stamps the anchor.
    REQUIRE(tracker.reconcile_stale_concurrency_claims(now) == 0);

    auto claimed =
        tracker.claim_concurrency_slots("def-conc-6", "exec-1", "cmd-test-26", {"agent-a"}, /*expires_at=*/now - 100);
    REQUIRE(claimed.size() == 1);

    // Still open pre-reconcile.
    CHECK(tracker.claim_concurrency_slots("def-conc-6", "exec-other", "cmd-test-27", {"agent-a"}, now + 100)
              .empty());

    auto released = tracker.reconcile_stale_concurrency_claims(now);
    CHECK(released == 1);

    // Free after reconcile.
    CHECK(tracker.claim_concurrency_slots("def-conc-6", "exec-other", "cmd-test-28", {"agent-a"}, now + 100)
              .size() == 1);
}

TEST_CASE("ExecutionTracker: a 'running' status renews the claim's expires_at, so the reconciler "
          "does not force-release a still-progressing execution (CHAOS-TTL-1)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // Gate 5 chaos finding, PR #3784 fix round (CHAOS-TTL-1): a flat TTL
    // with no renewal force-releases a claim for a command that legitimately
    // runs longer than one TTL window, admitting a genuine concurrent
    // second dispatch. This test proves the SERVER-SIDE renewal mechanism
    // given a 'running' update; the RELIABLE real-world trigger for that
    // update — the agent-core keepalive thread, independent of plugin
    // cooperation — is proven separately in
    // test_agent_service_impl.cpp's "__keepalive__" test and agent-side in
    // agents/core/src/agent.cpp. See ADR-1007's "CLOSED (agent-core
    // keepalive)" section for the full closure story, including why
    // plugin-cooperation signals (output-buffer auto-flush,
    // yuzu_ctx_report_progress) were tried and found unreliable first.
    // renew_concurrency_claim uses real wall-clock time internally
    // (now_epoch()), unlike claim_concurrency_slots/reconcile_stale_
    // concurrency_claims elsewhere in this file which take a caller-supplied
    // synthetic `now` — so this test anchors on real time throughout rather
    // than the far-future 2000000000 constant used above.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    const int64_t now0 = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    REQUIRE(tracker.reconcile_stale_concurrency_claims(now0) == 0); // prime the anchor

    auto exec_id = tracker.create_execution(make_execution("def-conc-ttl-renew"));
    REQUIRE(exec_id.has_value());
    auto claimed = tracker.claim_concurrency_slots("def-conc-ttl-renew", *exec_id, "cmd-test-29", {"agent-a"},
                                                    /*expires_at=*/now0 + 2);
    REQUIRE(claimed.size() == 1);

    AgentExecStatus progress;
    progress.agent_id = "agent-a";
    progress.status = "running";
    tracker.update_agent_status(*exec_id, progress); // renews to ~now0 + kConcurrencyClaimDefaultTtlSeconds

    // Walk `now` forward in steps well under the reconciler's own 1h
    // big-step anomaly floor (kConcurrencyReconcileBigStepFloorSeconds) —
    // a single jump straight to ~now0+3600 would itself look like a clock
    // anomaly and decline instead of force-releasing, which would prove
    // nothing about the renewal.
    //
    // Past the ORIGINAL expires_at (now0+2) but nowhere near the renewed
    // one (~now0+3600) — must NOT force-release.
    CHECK(tracker.reconcile_stale_concurrency_claims(now0 + 5) == 0);
    CHECK(tracker.claim_concurrency_slots("def-conc-ttl-renew", "exec-other", "cmd-test-30", {"agent-a"},
                                          now0 + 100)
              .empty());
    CHECK(tracker.reconcile_stale_concurrency_claims(now0 + 1800) == 0);
    CHECK(tracker.claim_concurrency_slots("def-conc-ttl-renew", "exec-other", "cmd-test-31", {"agent-a"},
                                          now0 + 100)
              .empty());
    CHECK(tracker.reconcile_stale_concurrency_claims(now0 + 3200) == 0);
    CHECK(tracker.claim_concurrency_slots("def-conc-ttl-renew", "exec-other", "cmd-test-32", {"agent-a"},
                                          now0 + 100)
              .empty());

    // Past the RENEWED expires_at too — the reconciler still eventually
    // reclaims a claim with no further progress signal at all.
    CHECK(tracker.reconcile_stale_concurrency_claims(now0 + 3700) == 1);
    CHECK(tracker.claim_concurrency_slots("def-conc-ttl-renew", "exec-other", "cmd-test-33", {"agent-a"},
                                          now0 + 100)
              .size() == 1);
}

TEST_CASE("ExecutionTracker: release_concurrency_claim_by_command / "
          "renew_concurrency_claim_by_command restore claim release/renewal when the "
          "execution_id correlation is lost (UP-1, unhappy-path Gate 4 finding, PR #3784 "
          "fix round)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // These *_by_command methods are the fallback notify_exec_tracker falls
    // back to whenever it can't resolve execution_id via the PG-backed
    // command_id -> execution_id correlation table (HA WS-1(1b),
    // ExecutionTracker::lookup_execution_id) -- genuinely, today: a
    // workflow-step dispatch (execution_id is always empty for those,
    // CONSIST-2/sec-M2), a correlation-table write/read degrade, or the
    // correlation table's own 24h-window entry aging out from under a
    // legitimately still-running command (reap_command_execution_mappings).
    // command_id alone (no definition_id scoping) is a safe match key
    // because command_id is minted fresh per dispatch
    // (plugin + "-" + random_bytes(16), server.cpp) and can never collide
    // the way the empty-string execution_id does for workflow-step
    // dispatch.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    const int64_t now0 = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    REQUIRE(tracker.reconcile_stale_concurrency_claims(now0) == 0); // prime the anchor

    auto claimed = tracker.claim_concurrency_slots("def-conc-by-cmd", "exec-lost", "cmd-restart-1",
                                                    {"agent-a"}, /*expires_at=*/now0 + 2);
    REQUIRE(claimed.size() == 1);

    // Renew purely by (command_id, agent_id) — as notify_exec_tracker's
    // fallback does on a post-restart keepalive it can no longer resolve
    // to an execution_id. Must extend well past the original short TTL.
    tracker.renew_concurrency_claim_by_command("cmd-restart-1", "agent-a");
    CHECK(tracker.reconcile_stale_concurrency_claims(now0 + 5) == 0); // past original TTL, not renewed one
    CHECK(tracker.claim_concurrency_slots("def-conc-by-cmd", "exec-other", "cmd-test-34", {"agent-a"},
                                          now0 + 100)
              .empty()); // still held — the renewal worked

    // A DIFFERENT command_id/agent must not be touched by either call —
    // scoping sanity, even though command_id is generated globally-unique
    // in production.
    auto unrelated = tracker.claim_concurrency_slots("def-conc-by-cmd-2", "exec-other-2",
                                                      "cmd-unrelated", {"agent-b"}, now0 + 2);
    REQUIRE(unrelated.size() == 1);
    tracker.release_concurrency_claim_by_command("cmd-restart-1", "agent-a");
    CHECK(tracker.claim_concurrency_slots("def-conc-by-cmd-2", "exec-other-3", "cmd-test-35",
                                          {"agent-b"}, now0 + 100)
              .empty()); // agent-b's claim under a different command_id survives untouched

    // Release purely by (command_id, agent_id) — as notify_exec_tracker's
    // fallback does on a post-restart terminal response. The original
    // claim must now be free.
    CHECK(tracker.claim_concurrency_slots("def-conc-by-cmd", "exec-other-4", "cmd-test-36", {"agent-a"},
                                          now0 + 100)
              .size() == 1);

    // No-op sanity: a command_id/agent_id pair with no open claim at all
    // (ordinary out-of-band dispatch that never took one) must not error
    // or touch anything.
    tracker.release_concurrency_claim_by_command("cmd-never-claimed", "agent-z");
    tracker.renew_concurrency_claim_by_command("cmd-never-claimed", "agent-z");
}

TEST_CASE("ExecutionTracker: release_concurrency_claim_by_command discriminates by command_id "
          "for the SAME agent, not just by agent_id (Fable adversarial-review finding, PR #3784 "
          "fix round)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // The by-command match key is (command_id, agent_id) — sibling tests
    // proved the agent_id half; this proves the command_id half. A SINGLE
    // agent legitimately holds two open claims for two different
    // definitions at once (per-device enforcement is per-definition, not a
    // global agent lock) — releasing one by its command_id must not touch
    // the other.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto claim_1 = tracker.claim_concurrency_slots("def-conc-by-cmd-disc-1", "exec-1",
                                                    "cmd-disc-1", {"agent-shared"}, 9999999999);
    REQUIRE(claim_1.size() == 1);
    auto claim_2 = tracker.claim_concurrency_slots("def-conc-by-cmd-disc-2", "exec-2",
                                                    "cmd-disc-2", {"agent-shared"}, 9999999999);
    REQUIRE(claim_2.size() == 1); // different definition_id — not blocked by claim_1

    tracker.release_concurrency_claim_by_command("cmd-disc-1", "agent-shared");

    CHECK(tracker.claim_concurrency_slots("def-conc-by-cmd-disc-1", "exec-other", "cmd-probe-1",
                                          {"agent-shared"}, 9999999999)
              .size() == 1); // claim_1 released
    CHECK(tracker.claim_concurrency_slots("def-conc-by-cmd-disc-2", "exec-other", "cmd-probe-2",
                                          {"agent-shared"}, 9999999999)
              .empty()); // claim_2 untouched — still held
}

TEST_CASE("ExecutionTracker: claim_concurrency_slots fails a candidate CLOSED on a "
          "(command_id, agent_id) reuse, rather than silently taking a second claim (Sol/Fable "
          "adversarial-review finding, PR #3784 fix round)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // command_id is minted fresh per dispatch (128 random bits,
    // server.cpp) and no legitimate caller reuses one — but that was
    // previously an assumption, not a schema guarantee. This proves the
    // NEW `ux_concurrency_claims_command` unique index actually enforces
    // it: a second INSERT reusing the same (command_id, agent_id), even
    // for a DIFFERENT definition_id/execution_id, must be excluded from
    // `RETURNING` (fail closed) rather than silently succeeding — which
    // would otherwise let a later single-command_id release/renew touch
    // two unrelated definitions' claims at once.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto first = tracker.claim_concurrency_slots("def-conc-reuse-1", "exec-1", "cmd-reused",
                                                  {"agent-a"}, 9999999999);
    REQUIRE(first.size() == 1);

    // Same command_id, same agent_id, but a DIFFERENT definition_id/
    // execution_id — must NOT win a second claim.
    auto second = tracker.claim_concurrency_slots("def-conc-reuse-2", "exec-2", "cmd-reused",
                                                   {"agent-a"}, 9999999999);
    CHECK(second.empty());

    // The first claim is unaffected by the failed second attempt.
    CHECK(tracker.claim_concurrency_slots("def-conc-reuse-1", "exec-other", "cmd-reuse-probe",
                                          {"agent-a"}, 9999999999)
              .empty()); // still held by the original claim
}

TEST_CASE("ExecutionTracker: update_agent_status gates release/renew on the ACTUALLY-PERSISTED "
          "status, not the caller-supplied one — a stale reordered 'running' does not renew a "
          "claim whose row is already terminal (UP-2, unhappy-path Gate 4 finding, PR #3784 fix "
          "round)",
          "[pg][execution_tracker][concurrency][adr1007]") {
    // upsert_agent_status_once's sticky-terminal CASE (CHAOS-TTL-1
    // hardening) keeps agent_exec_status.status terminal when a stale
    // 'running' write arrives after a real terminal one — but the OUTER
    // release/renew decision used to branch on the caller's literal
    // s.status ("running") instead of what was actually persisted. This
    // proves the decision now follows the persisted value: a stale
    // 'running' delivered for an execution_id whose row is already
    // terminal must take the RELEASE branch (a no-op/self-heal on an
    // already-released claim), never the RENEW branch (which would
    // wrongly extend a claim that has nothing left to renew for).
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec_id = tracker.create_execution(make_execution("def-conc-stale-running"));
    REQUIRE(exec_id.has_value());

    auto claimed = tracker.claim_concurrency_slots("def-conc-stale-running", *exec_id, "cmd-test-37",
                                                    {"agent-a"}, 9999999999);
    REQUIRE(claimed.size() == 1);

    AgentExecStatus success;
    success.agent_id = "agent-a";
    success.status = "success";
    tracker.update_agent_status(*exec_id, success);
    // Terminal write releases the claim — confirmed free.
    REQUIRE(tracker.claim_concurrency_slots("def-conc-stale-running", "exec-other", "cmd-test-38",
                                            {"agent-a"}, 9999999999)
                .size() == 1);
    // Release the probe claim so the SAME execution_id can be re-claimed
    // below without the earlier fix's cross-definition-leak guard tests'
    // pattern getting in the way.
    tracker.release_concurrency_claim("def-conc-stale-running", "exec-other", "agent-a");

    // Re-claim under the SAME (already-terminal) execution_id with a short
    // TTL — standing in for a claim a stale 'running' for this execution_id
    // could reach via the (execution_id, agent_id) match key, so the test
    // can observe which branch the decision actually takes.
    const int64_t now0 = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    auto reclaimed = tracker.claim_concurrency_slots("def-conc-stale-running", *exec_id, "cmd-test-2",
                                                      {"agent-a"}, /*expires_at=*/now0 + 3600);
    REQUIRE(reclaimed.size() == 1);

    // The stale, reordered 'running' — agent_exec_status[*exec_id] is
    // ALREADY 'success' (sticky CASE keeps it there; this write is a no-op
    // on the row itself). The pre-fix code branched on this literal
    // "running" and would have called renew_concurrency_claim, leaving the
    // re-claimed row open with an extended expires_at. The fix must
    // instead see the persisted 'success' and call release_concurrency_claim.
    AgentExecStatus stale_running;
    stale_running.agent_id = "agent-a";
    stale_running.status = "running";
    tracker.update_agent_status(*exec_id, stale_running);

    // Proves RELEASE, not RENEW, ran: the re-claimed row is free again.
    CHECK(tracker.claim_concurrency_slots("def-conc-stale-running", "exec-other-2", "cmd-test-39",
                                          {"agent-a"}, 9999999999)
              .size() == 1);
}

TEST_CASE("ExecutionTracker: reconcile_stale_concurrency_claims declines on a backward clock "
          "jump",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    const int64_t now1 = 2000000000;
    // First pass just stamps the persisted anchor at now1 — no open claims
    // yet, so the release count is 0 regardless.
    CHECK(tracker.reconcile_stale_concurrency_claims(now1) == 0);

    // BEFORE the persisted anchor, and past the big-step floor (1h) — a
    // sub-floor drift (ordinary NTP correction) must NOT trigger this; only
    // a jump exceeding the floor does (moved_at_least is direction-agnostic).
    const int64_t now2 = now1 - 7200;
    auto claimed = tracker.claim_concurrency_slots("def-conc-7", "exec-1", "cmd-test-40", {"agent-a"},
                                                    /*expires_at=*/now2 - 100);
    REQUIRE(claimed.size() == 1);

    // A pass whose `now` has moved past the floor from the persisted anchor
    // — in either direction — must DECLINE (release nothing), even though
    // this claim is nominally past its own expires_at relative to now2.
    CHECK(tracker.reconcile_stale_concurrency_claims(now2) == 0);

    // Still held — the decline means the claim was NOT force-released.
    CHECK(tracker.claim_concurrency_slots("def-conc-7", "exec-2", "cmd-test-41", {"agent-a"}, now1 + 100)
              .empty());
}

TEST_CASE("ExecutionTracker: reconcile_stale_concurrency_claims declines on the very first pass "
          "when something is already expired and there is no prior anchor",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // No priming call — this IS the first-ever pass against this store,
    // exactly the boot-with-an-already-wrong-clock scenario
    // audit_retention_rules.hpp's Anomaly::NoAnchor exists for (#2579's
    // fix, adopted here via the shared classify() rather than reimplemented).
    const int64_t now = 2000000000;
    auto claimed =
        tracker.claim_concurrency_slots("def-conc-8", "exec-1", "cmd-test-42", {"agent-a"}, /*expires_at=*/now - 100);
    REQUIRE(claimed.size() == 1);

    CHECK(tracker.reconcile_stale_concurrency_claims(now) == 0); // declined, not released
    CHECK(tracker.claim_concurrency_slots("def-conc-8", "exec-other", "cmd-test-43", {"agent-a"}, now + 100)
              .empty()); // still held

    // The SECOND pass now has a comparison point (the anchor the first
    // pass stamped) and proceeds normally.
    CHECK(tracker.reconcile_stale_concurrency_claims(now) == 1);
    CHECK(tracker.claim_concurrency_slots("def-conc-8", "exec-other", "cmd-test-44", {"agent-a"}, now + 100)
              .size() == 1);
}

TEST_CASE("ExecutionTracker: reconcile_stale_concurrency_claims caps the number released per "
          "pass",
          "[pg][execution_tracker][concurrency]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Below the cap (5000) — this only proves the cap parameter is wired,
    // not that 5000+ claims behave correctly (that volume is unrealistic
    // for this table and not worth the test runtime); see the reconciler's
    // own doc comment for the "generous headroom, not a routine limit"
    // rationale.
    const int64_t now = 2000000000;
    REQUIRE(tracker.reconcile_stale_concurrency_claims(now) == 0); // prime the anchor
    for (int i = 0; i < 10; ++i) {
        auto claimed = tracker.claim_concurrency_slots(
            "def-conc-cap", "exec-" + std::to_string(i), "cmd-test-45",
            {"agent-" + std::to_string(i)}, now - 100);
        REQUIRE(claimed.size() == 1);
    }
    CHECK(tracker.reconcile_stale_concurrency_claims(now) == 10);
}

// ── HA WS-2a: durable event outbox (ADR-2002 §5) ─────────────────────────────

namespace {
struct OutboxRow {
    long long event_id{0};
    std::string execution_id;
    std::string event_type;
    std::string data;
    bool is_terminal{false};
    long long created_at{0};
    unsigned long long w_xid{0};   // WS-2a-2 settle-horizon xid8
    std::string origin_replica;    // WS-2a-2 skip-own stamp
};

// Reads event_outbox rows for one execution, oldest event_id first, over a
// fresh lease on the given pool (the public API has no outbox read yet — no
// consumer until WS-2a-2).
std::vector<OutboxRow> fetch_outbox(pg::PgPool& pool, const std::string& execution_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT event_id, execution_id, event_type, data, is_terminal, created_at, "
        "       w_xid::text, origin_replica "
        "FROM execution_tracker.event_outbox WHERE execution_id=$1 ORDER BY event_id",
        std::vector<std::string>{execution_id});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    std::vector<OutboxRow> rows;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        OutboxRow row;
        row.event_id = std::strtoll(PQgetvalue(r.get(), i, 0), nullptr, 10);
        row.execution_id = PQgetvalue(r.get(), i, 1);
        row.event_type = PQgetvalue(r.get(), i, 2);
        row.data = PQgetvalue(r.get(), i, 3);
        row.is_terminal = std::string(PQgetvalue(r.get(), i, 4)) == "t";
        row.created_at = std::strtoll(PQgetvalue(r.get(), i, 5), nullptr, 10);
        row.w_xid = std::strtoull(PQgetvalue(r.get(), i, 6), nullptr, 10);
        row.origin_replica = PQgetvalue(r.get(), i, 7);
        rows.push_back(std::move(row));
    }
    return rows;
}

// Simulates ANOTHER replica durably appending an event: a direct autocommit
// INSERT with an explicit foreign origin_replica (so this replica's poll does
// not skip it) and the w_xid column DEFAULT filling in the insert txn's xid.
// Returns the durable event_id the poll must re-publish under.
std::uint64_t insert_other_replica_event(pg::PgPool& pool, const std::string& execution_id,
                                         const std::string& origin, const std::string& event_type,
                                         const std::string& data, bool is_terminal = false) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO execution_tracker.event_outbox "
        "(execution_id, event_type, data, is_terminal, created_at, origin_replica) "
        "VALUES ($1, $2, $3, $4, extract(epoch FROM now())::bigint, $5) RETURNING event_id",
        std::vector<std::string>{execution_id, event_type, data, is_terminal ? "true" : "false",
                                 origin});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return static_cast<std::uint64_t>(std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10));
}

// Drives poll_event_outbox_once() until `channel` holds at least `expected`
// events, or a bounded budget elapses; returns the total re-published.
//
// The poll's settle-horizon is the SERVER-GLOBAL all-committed xmin
// (pg_snapshot_xmin) — so a CONCURRENT test's still-open transaction on the
// shared test PostgreSQL pins that horizon BELOW a just-inserted outbox row and
// the poll correctly withholds the row until that unrelated txn commits (the
// head-of-line behaviour the design documents; in production the server owns its
// PG and only its own short txns can pin it). A single poll is therefore racy
// under parallel [pg] shards even though the delivery is guaranteed to arrive —
// so the test polls until it drains. Budget generous (~15s) but the common path
// resolves in one or two iterations; it is a safety cap, not the expected wait.
int poll_until(ExecutionTracker& tracker, ExecutionEventBus& bus, const std::string& channel,
               std::size_t expected) {
    int total = 0;
    for (int attempt = 0; attempt < 150; ++attempt) {
        auto got = tracker.poll_event_outbox_once();
        REQUIRE(got.has_value());
        total += *got;
        if (bus.snapshot(channel).size() >= expected)
            return total;
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    return total;
}
} // namespace

TEST_CASE("ExecutionTracker: WS-2a a completed execution durably appends "
          "agent-transition + execution-progress + execution-completed events",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    REQUIRE(tracker.set_agents_targeted(*id, 1));

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.completed_at = 1002;
    tracker.update_agent_status(*id, as); // upsert (agent-transition) + refresh_counts (terminal)

    auto rows = fetch_outbox(tracker_bundle.pool(), *id);
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].event_type == "agent-transition");
    CHECK_FALSE(rows[0].is_terminal);
    CHECK(rows[1].event_type == "execution-progress");
    CHECK(rows[1].is_terminal); // all agents responded -> the progress event is terminal-flagged
    CHECK(rows[2].event_type == "execution-completed");
    CHECK(rows[2].is_terminal);

    // event_id is a global durable MONOTONIC id — strictly increasing in
    // append order across the two separate transactions (upsert, then
    // refresh_counts).
    CHECK(rows[0].event_id < rows[1].event_id);
    CHECK(rows[1].event_id < rows[2].event_id);

    // The durable data mirrors what the in-memory bus would publish.
    CHECK(rows[2].data.find("succeeded") != std::string::npos);

    // Both-sides of invariant 1: the AUTHORITATIVE state committed in the SAME
    // transactions as its events — not the event without the state. Read via
    // the degrade-distinguishable accessor so a store error can't masquerade as
    // "no state".
    auto statuses = tracker.get_agent_statuses_checked(*id);
    REQUIRE(statuses.has_value());
    REQUIRE(statuses->size() == 1);
    CHECK((*statuses)[0].status == "success");
    auto exec = tracker.get_execution(*id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "succeeded");
}

TEST_CASE("ExecutionTracker: WS-2a-2 the durable append stamps origin_replica + a "
          "settle-horizon w_xid, and the live bus keeps the reconnect-safe "
          "per-channel counter id (Option A — durable id is outbox-only)",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;
    ExecutionEventBus bus;
    tracker.set_event_bus(&bus);

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    REQUIRE(tracker.set_agents_targeted(*id, 1));

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.completed_at = 1002;
    tracker.update_agent_status(*id, as); // agent-transition + progress + completed

    auto rows = fetch_outbox(tracker_bundle.pool(), *id);
    REQUIRE(rows.size() == 3);

    // Option A (self-adversarial K1): the LIVE bus id is the per-channel counter
    // assigned in PUBLISH order under the channel mutex (1, 2, 3 here), NOT the
    // durable outbox event_id — so buffer order == id order and a Last-Event-ID
    // reconnect is never stranded by a commit-order inversion. The durable
    // event_id lives in the outbox (rows below), for the poll cursor + slice-2
    // durable replay.
    auto published = bus.snapshot(*id);
    REQUIRE(published.size() == 3);
    CHECK(published[0].id == 1);
    CHECK(published[1].id == 2);
    CHECK(published[2].id == 3);
    // The durable outbox ids are a large fleet-wide IDENTITY sequence, NOT the
    // small per-channel counter — i.e. deliberately different from the bus ids.
    CHECK(rows[0].event_id >= 1);
    CHECK(rows[0].event_id < rows[1].event_id);
    CHECK(rows[1].event_id < rows[2].event_id);

    // skip-own: every append is stamped with this process's non-empty replica id,
    // identical across all three rows (one process). A peer replica's poll
    // excludes rows whose origin_replica != its own; this replica's poll skips
    // its own rows because they equal its id.
    REQUIRE_FALSE(rows[0].origin_replica.empty());
    CHECK(rows[0].origin_replica == rows[1].origin_replica);
    CHECK(rows[1].origin_replica == rows[2].origin_replica);

    // w_xid — the settle-horizon the cross-replica poll cursors on — is populated
    // by the column DEFAULT pg_current_xact_id() to the appending txn's xid, a
    // non-zero xid8. The two refresh_counts rows share one txn's xid; the
    // agent-transition row is a separate earlier txn, so its xid is <= theirs.
    CHECK(rows[0].w_xid > 0);
    CHECK(rows[1].w_xid > 0);
    CHECK(rows[1].w_xid == rows[2].w_xid);           // progress + completed: one txn
    CHECK(rows[0].w_xid <= rows[1].w_xid);           // transition committed first
}

TEST_CASE("ExecutionTracker: WS-2a-2 the poll re-publishes another replica's "
          "durable events onto this replica's bus, once, with a reconnect-safe "
          "local counter id (Option A)",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;
    ExecutionEventBus bus;
    tracker.set_event_bus(&bus);

    // The horizon was initialized at CONSTRUCTION (C1 fix), so this first poll is
    // a real pass over an empty window — it delivers nothing because no foreign
    // event has committed yet.
    auto init = tracker.poll_event_outbox_once();
    REQUIRE(init.has_value());
    CHECK(*init == 0);

    // Another replica appends a durable event (its own foreign origin id). e1 is
    // its durable OUTBOX event_id — NOT the id it will carry on this bus.
    auto e1 = insert_other_replica_event(tracker_bundle.pool(), "exec-x", "other-replica-aaaa",
                                         "agent-transition", R"({"status":"running"})");

    CHECK(poll_until(tracker, bus, "exec-x", 1) == 1);
    auto snap = bus.snapshot("exec-x");
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].id == 1); // re-published under a LOCAL per-channel counter id, not e1
    CHECK(snap[0].event_type == "agent-transition");

    // Poll again: the horizon advanced past e1 — no re-delivery (dedup by cursor).
    auto again = tracker.poll_event_outbox_once();
    REQUIRE(again.has_value());
    CHECK(*again == 0);
    CHECK(bus.snapshot("exec-x").size() == 1);

    // A NEW foreign event after the cursor advanced is still delivered.
    auto e2 = insert_other_replica_event(tracker_bundle.pool(), "exec-x", "other-replica-bbbb",
                                         "execution-completed", R"({"status":"succeeded"})",
                                         /*is_terminal=*/true);
    CHECK(poll_until(tracker, bus, "exec-x", 2) == 1);
    auto snap2 = bus.snapshot("exec-x");
    REQUIRE(snap2.size() == 2);
    CHECK(snap2[1].id == 2);            // second local counter id, monotonic on the bus
    CHECK(snap2[1].event_type == "execution-completed");
    CHECK(e2 > e1);                     // the DURABLE outbox ids are globally monotonic
}

TEST_CASE("ExecutionTracker: WS-2a-2 the poll SKIPS this replica's own rows "
          "(already published in-process) — no duplicate re-publish",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;
    ExecutionEventBus bus;
    tracker.set_event_bus(&bus);

    // Init the horizon BEFORE the own-append, so the own rows fall inside the
    // poll window and are candidates the skip-own filter must exclude.
    REQUIRE(tracker.poll_event_outbox_once().has_value());

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    REQUIRE(tracker.set_agents_targeted(*id, 1));
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.completed_at = 1002;
    tracker.update_agent_status(*id, as); // in-process publish of 3 own events

    auto before = bus.snapshot(*id);
    REQUIRE(before.size() == 3);

    // A FOREIGN event appended AFTER the own rows, on a different channel. When
    // the poll delivers it, every earlier row (the own rows) is also below the
    // settle-horizon — so they were candidates the skip-own filter had to reject.
    // This is what makes the "== 3" assertion below meaningful rather than
    // vacuously true under a transiently-pinned xmin (see poll_until).
    auto foreign = insert_other_replica_event(tracker_bundle.pool(), "witness-chan",
                                              "other-replica-cccc", "agent-transition",
                                              R"({"status":"running"})");
    CHECK(poll_until(tracker, bus, "witness-chan", 1) == 1); // only the foreign row, never the 3 own
    auto wsnap = bus.snapshot("witness-chan");
    REQUIRE(wsnap.size() == 1);
    CHECK(wsnap[0].id == 1); // local counter id on this bus (foreign's durable id is outbox-only)
    CHECK(wsnap[0].event_type == "agent-transition");
    CHECK(bus.snapshot(*id).size() == 3); // own channel unchanged — skip-own held
    (void)foreign;
}

TEST_CASE("ExecutionTracker: WS-2a-2 the poll surfaces a query failure as `unexpected` "
          "(distinguishable degrade, cursor not advanced) rather than a silent no-op",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;
    ExecutionEventBus bus;
    tracker.set_event_bus(&bus);

    // Establish the horizon on the healthy store first (so the degraded pass
    // exercises the main query path, not the init path).
    REQUIRE(tracker.poll_event_outbox_once().has_value());

    // Break the poll's SELECT deterministically by dropping the table it reads —
    // the same fault-injection the atomicity test uses. A degrade MUST return
    // `unexpected` (so the maint thread counts yuzu_exec_outbox_store_degrade_total
    // and, critically, does NOT advance poll_horizon_ — the window is re-read next
    // tick), never a silent `0` that reads as "nothing to deliver".
    {
        auto lease = tracker_bundle.pool().acquire();
        REQUIRE(lease);
        auto drop = pg::exec_params(lease.get(), "DROP TABLE execution_tracker.event_outbox",
                                    std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }

    auto degraded = tracker.poll_event_outbox_once();
    CHECK_FALSE(degraded.has_value()); // query failure surfaced as a degrade, not swallowed
}

TEST_CASE("ExecutionTracker: WS-2a the state write and its event append are "
          "ATOMIC — a failing append rolls the state write back (invariant 1)",
          "[pg][execution_tracker][outbox]") {
    // The headline WS-9 durability scenario: never state-without-event. The
    // agent_exec_status upsert and the event_outbox append share ONE
    // with_txn_for transaction, so if the append cannot commit, neither does
    // the state write. Injected by dropping event_outbox so every append
    // INSERT errors — the paired upsert must then leave no row.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());

    {
        auto lease = tracker_bundle.pool().acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(),
                                   "DROP TABLE execution_tracker.event_outbox",
                                   std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    tracker.update_agent_status(*id, as); // append fails -> whole txn rolls back

    // Strengthened assertion (governance quality-engineer): distinguish a
    // genuine rollback (read succeeds, zero rows) from a verification read that
    // itself errored — the plain get_agent_statuses() collapses both into an
    // empty vector via value_or({}), so it could not tell the two apart. Only
    // `event_outbox` was dropped; `agent_exec_status` is intact, so the checked
    // read MUST succeed, and its emptiness then PROVES the upsert rolled back
    // (not that the read failed).
    auto statuses = tracker.get_agent_statuses_checked(*id);
    REQUIRE(statuses.has_value());
    CHECK(statuses->empty());
}

TEST_CASE("ExecutionTracker: WS-2a mark_cancelled is atomic too — a failing "
          "append rolls the cancel back (invariant 1, all write sites)",
          "[pg][execution_tracker][outbox]") {
    // Extends the atomicity coverage beyond update_agent_status to the second
    // converted write path. mark_cancelled was a bare autocommit UPDATE before
    // the outbox existed; it is now transactional, so a failing append must
    // leave the execution NOT cancelled.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution()); // status "running"
    REQUIRE(id.has_value());

    {
        auto lease = tracker_bundle.pool().acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(), "DROP TABLE execution_tracker.event_outbox",
                                   std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    CHECK_FALSE(tracker.mark_cancelled(*id, "admin")); // append fails -> rollback -> false

    // The cancel was rolled back with the failing append: the execution is
    // still 'running', not 'cancelled'.
    auto exec = tracker.get_execution(*id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "running");
}

TEST_CASE("ExecutionTracker: WS-2a mark_cancelled durably appends a terminal "
          "execution-completed event",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    REQUIRE(tracker.mark_cancelled(*id, "admin"));

    auto rows = fetch_outbox(tracker_bundle.pool(), *id);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].event_type == "execution-completed");
    CHECK(rows[0].is_terminal);
    CHECK(rows[0].data.find("cancelled") != std::string::npos);
}

TEST_CASE("ExecutionTracker: WS-2a events appended on one instance are durable "
          "and readable from a SEPARATE instance (WS-9 failover scenario)",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle; // "replica A" — writes
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "running";
    tracker.update_agent_status(*id, as);

    // "replica B" — a second pool against the SAME database, sharing no
    // process memory with A. The in-memory bus could never surface A's events
    // here; the durable outbox does. One update_agent_status durably appends
    // both the agent-transition and the refresh_counts execution-progress
    // event (mirroring exactly what the in-memory bus publishes per call).
    pg::PgPool pool_b{{.conninfo = tracker_bundle.dsn(), .size = 2}};
    auto rows = fetch_outbox(pool_b, *id);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].event_type == "agent-transition");
    CHECK(rows[1].event_type == "execution-progress");
}

TEST_CASE("ExecutionTracker: WS-2a reap_event_outbox deletes only aged-out "
          "rows, missing-anchor PROCEEDs, and is clock-guarded",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "running";
    tracker.update_agent_status(*id, as); // agent-transition + execution-progress

    const std::size_t appended = fetch_outbox(tracker_bundle.pool(), *id).size();
    REQUIRE(appended == 2);

    // First pass: no anchor yet — PROCEED (missing-anchor decision), delete 0
    // (the rows are fresh, far inside the 24h window), no anomaly.
    auto first = tracker.reap_event_outbox();
    REQUIRE(first.has_value());
    CHECK(first->deleted == 0);
    CHECK_FALSE(first->clock_anomaly);
    CHECK(fetch_outbox(tracker_bundle.pool(), *id).size() == appended);

    // Age the rows past the 24h window (test-only backdate, no public hook).
    {
        auto lease = tracker_bundle.pool().acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.event_outbox SET created_at = created_at - 90000 "
            "WHERE execution_id = $1",
            std::vector<std::string>{*id});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker.reap_event_outbox();
    REQUIRE(second.has_value());
    CHECK(second->deleted == static_cast<int>(appended));
    CHECK_FALSE(second->clock_anomaly);
    CHECK(fetch_outbox(tracker_bundle.pool(), *id).empty());
}

TEST_CASE("ExecutionTracker: WS-2a reap_event_outbox declines on a "
          "forward-skewed anchor gap",
          "[pg][execution_tracker][outbox]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    // Establish a real anchor.
    REQUIRE(tracker_bundle->reap_event_outbox().has_value());
    {
        auto lease = tracker_bundle.pool().acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = (value::bigint - 200000)::text "
            "WHERE key = 'event_outbox_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }
    auto second = tracker_bundle->reap_event_outbox();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: WS-2a reap_event_outbox declines on a "
          "backward-stepped clock and on an unparseable anchor",
          "[pg][execution_tracker][outbox]") {
    SECTION("backward-stepped clock (anchor far in the future)") {
        yuzu::test::ExecutionTrackerPg tracker_bundle;
        REQUIRE(tracker_bundle->reap_event_outbox().has_value());
        {
            auto lease = tracker_bundle.pool().acquire();
            REQUIRE(lease);
            auto res = pg::exec_params(
                lease.get(),
                "UPDATE execution_tracker.reap_meta SET value = (value::bigint + 200000)::text "
                "WHERE key = 'event_outbox_reap_anchor'",
                std::vector<std::string>{});
            REQUIRE(res.status() == PGRES_COMMAND_OK);
        }
        auto second = tracker_bundle->reap_event_outbox();
        REQUIRE(second.has_value());
        CHECK(second->deleted == 0);
        CHECK(second->clock_anomaly);
    }

    SECTION("unparseable persisted anchor is sanitised, not coerced") {
        yuzu::test::ExecutionTrackerPg tracker_bundle;
        REQUIRE(tracker_bundle->reap_event_outbox().has_value());
        {
            auto lease = tracker_bundle.pool().acquire();
            REQUIRE(lease);
            auto res = pg::exec_params(
                lease.get(),
                "UPDATE execution_tracker.reap_meta SET value = '123junk' "
                "WHERE key = 'event_outbox_reap_anchor'",
                std::vector<std::string>{});
            REQUIRE(res.status() == PGRES_COMMAND_OK);
        }
        auto second = tracker_bundle->reap_event_outbox();
        REQUIRE(second.has_value());
        CHECK(second->deleted == 0);
        CHECK(second->clock_anomaly);
    }
}

TEST_CASE("ExecutionTracker: WS-2a reap_event_outbox on an unreachable pool "
          "degrades without crashing",
          "[execution_tracker][outbox]") {
    pg::PgPool unreachable{{.conninfo = "host=127.0.0.1 port=1 dbname=yuzu connect_timeout=1",
                            .size = 1,
                            .connect_timeout_s = 1}};
    ExecutionTracker closed(unreachable);
    REQUIRE(!closed.is_open());
    auto reaped = closed.reap_event_outbox();
    REQUIRE_FALSE(reaped.has_value());
    CHECK(reaped.error() == "execution tracker not open");
}

TEST_CASE("ExecutionTracker: WS-2a mark_cancelled of an UNKNOWN id is a no-op — "
          "no phantom durable event, returns false (self-adversarial C1/K6)",
          "[pg][execution_tracker][outbox]") {
    // ADR-2002 §5 event-WITHOUT-state direction: a cancel of an id that matches
    // no execution row must NOT append a durable execution-completed event.
    // (The UPDATE ... RETURNING id guard: zero rows matched -> no append, false.)
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    CHECK_FALSE(tracker.mark_cancelled("no-such-execution-id", "admin"));
    CHECK(fetch_outbox(tracker_bundle.pool(), "no-such-execution-id").empty());
}

TEST_CASE("ExecutionTracker: WS-2a mark_cancelled of an already-TERMINAL execution is a "
          "no-op — no status overwrite, no second event (PR #3842 review)",
          "[pg][execution_tracker][outbox]") {
    // The terminal-status guard: a cancel arriving after (or racing with) a
    // genuine terminal transition must NOT overwrite the true outcome back to
    // 'cancelled' NOR durably append a contradictory execution-completed frame.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    REQUIRE(tracker.set_agents_targeted(*id, 1));
    // Drive it to a genuine terminal 'succeeded'.
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    tracker.update_agent_status(*id, as);
    {
        auto exec = tracker.get_execution(*id);
        REQUIRE(exec.has_value());
        REQUIRE(exec->status == "succeeded");
    }
    const std::size_t rows_before = fetch_outbox(tracker_bundle.pool(), *id).size();

    // Cancel must be a no-op — the execution is already terminal.
    CHECK_FALSE(tracker.mark_cancelled(*id, "admin"));

    auto exec = tracker.get_execution(*id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "succeeded"); // NOT overwritten to 'cancelled'
    CHECK(fetch_outbox(tracker_bundle.pool(), *id).size() == rows_before); // no second frame
}

TEST_CASE("ExecutionTracker: WS-2a refresh_counts terminal transition is atomic — "
          "a failing append rolls the transition back (self-adversarial C4c)",
          "[pg][execution_tracker][outbox]") {
    // Isolates refresh_counts_once's append-failure rollback (the third write
    // path, whose terminal transition appends 1-2 events in one txn). A responded
    // agent row is inserted directly so refresh_counts sees all-responded WITHOUT
    // going through update_agent_status (whose own append would fire first).
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution()); // status "running"
    REQUIRE(id.has_value());
    REQUIRE(tracker.set_agents_targeted(*id, 1));

    {
        auto lease = tracker_bundle.pool().acquire();
        REQUIRE(lease);
        auto ins = pg::exec_params(
            lease.get(),
            "INSERT INTO execution_tracker.agent_exec_status "
            "(execution_id, agent_id, status, dispatched_at, first_response_at, completed_at, "
            " exit_code, error_detail, plugin_result_status) "
            "VALUES ($1, 'agent-1', 'success', 0, 0, 0, 0, '', 0)",
            std::vector<std::string>{*id});
        REQUIRE(ins.status() == PGRES_COMMAND_OK);
        auto drop = pg::exec_params(lease.get(), "DROP TABLE execution_tracker.event_outbox",
                                    std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }

    tracker.refresh_counts(*id); // recompute -> terminal transition -> append fails -> rollback

    // The terminal transition (status -> succeeded) rolled back with the failing
    // append; the execution is still 'running'.
    auto exec = tracker.get_execution(*id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "running");
}
