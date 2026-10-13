/**
 * test_execution_statistics.cpp — Unit tests for ExecutionTracker statistics
 *
 * Covers: get_fleet_summary, get_agent_statistics, get_definition_statistics
 * (capability 1.9 aggregation methods).
 */

#include "execution_tracker.hpp"
#include "pg/pg_exec.hpp"   // exec_params: degrade the store in the try_get_* test
#include "pg/pg_raii.hpp"
#include "test_execution_tracker_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::server;

// -- Helpers --

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static Execution make_exec(const std::string& def_id = "def-001",
                            const std::string& status = "succeeded",
                            int targeted = 2, int success = 2, int failure = 0,
                            int64_t dispatched_at = 0, int64_t completed_at = 0) {
    Execution e;
    e.definition_id = def_id;
    e.status = status;
    e.scope_expression = "ostype = 'windows'";
    e.dispatched_by = "admin";
    e.agents_targeted = targeted;
    e.agents_success = success;
    e.agents_failure = failure;
    e.dispatched_at = dispatched_at > 0 ? dispatched_at : now_epoch();
    e.completed_at = completed_at > 0 ? completed_at : (e.dispatched_at + 10);
    return e;
}

static void insert_agent_status(ExecutionTracker& tracker,
                                 const std::string& exec_id,
                                 const std::string& agent_id,
                                 const std::string& status,
                                 int exit_code = 0,
                                 int64_t dispatched_at = 0,
                                 int64_t completed_at = 0) {
    auto now = now_epoch();
    AgentExecStatus s;
    s.agent_id = agent_id;
    s.status = status;
    s.exit_code = exit_code;
    s.dispatched_at = dispatched_at > 0 ? dispatched_at : now;
    s.first_response_at = s.dispatched_at + 1;
    s.completed_at = completed_at > 0 ? completed_at : (s.dispatched_at + 5);
    tracker.update_agent_status(exec_id, s);
}

// ============================================================================
// get_fleet_summary
// ============================================================================

TEST_CASE("ExecutionStatistics: fleet summary empty DB returns zeros",
          "[pg][execution_statistics][fleet]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto summary = tracker.get_fleet_summary();
    CHECK(summary.total_executions == 0);
    CHECK(summary.executions_today == 0);
    CHECK(summary.active_agents == 0);
    CHECK(summary.overall_success_rate == 0.0);
    CHECK(summary.avg_duration_seconds == 0.0);
}

TEST_CASE("ExecutionStatistics: fleet summary after inserts",
          "[pg][execution_statistics][fleet]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Insert two completed executions
    auto e1 = make_exec("def-A", "succeeded", 3, 3, 0, now - 100, now - 90);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    auto e2 = make_exec("def-B", "completed", 2, 1, 1, now - 50, now - 40);
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());

    // Add agent statuses so active_agents is populated
    insert_agent_status(tracker, *id1, "agent-1", "success", 0, now - 100, now - 90);
    insert_agent_status(tracker, *id1, "agent-2", "success", 0, now - 100, now - 90);
    insert_agent_status(tracker, *id2, "agent-1", "success", 0, now - 50, now - 40);

    auto summary = tracker.get_fleet_summary();
    CHECK(summary.total_executions == 2);
    CHECK(summary.active_agents >= 2); // agent-1, agent-2 at minimum
}

TEST_CASE("ExecutionStatistics: fleet summary today count uses dispatched_at = now",
          "[pg][execution_statistics][fleet]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Execution dispatched today
    auto e1 = make_exec("def-A", "succeeded", 1, 1, 0, now, now + 5);
    tracker.create_execution(e1);

    // Execution dispatched long ago (30 days)
    auto e2 = make_exec("def-B", "succeeded", 1, 1, 0, now - 86400 * 30, now - 86400 * 30 + 5);
    tracker.create_execution(e2);

    auto summary = tracker.get_fleet_summary();
    CHECK(summary.total_executions == 2);
    CHECK(summary.executions_today >= 1); // at least the one dispatched today
}

TEST_CASE("ExecutionStatistics: fleet summary success rate calculation",
          "[pg][execution_statistics][fleet]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // All success: 5 targeted, 5 success
    auto e1 = make_exec("def-A", "succeeded", 5, 5, 0, now - 100, now - 90);
    tracker.create_execution(e1);

    // Half success: 4 targeted, 2 success, 2 failure
    auto e2 = make_exec("def-B", "completed", 4, 2, 2, now - 50, now - 40);
    tracker.create_execution(e2);

    auto summary = tracker.get_fleet_summary();
    // Overall: (5+2) success out of (5+4) targeted = 7/9 ~ 77.78%
    CHECK(summary.overall_success_rate > 70.0);
    CHECK(summary.overall_success_rate < 80.0);
}

TEST_CASE("ExecutionStatistics: fleet summary avg duration",
          "[pg][execution_statistics][fleet]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Duration: 10 seconds
    auto e1 = make_exec("def-A", "succeeded", 1, 1, 0, now - 100, now - 90);
    tracker.create_execution(e1);

    // Duration: 20 seconds
    auto e2 = make_exec("def-B", "succeeded", 1, 1, 0, now - 50, now - 30);
    tracker.create_execution(e2);

    auto summary = tracker.get_fleet_summary();
    // Average duration: (10 + 20) / 2 = 15
    CHECK(summary.avg_duration_seconds > 14.0);
    CHECK(summary.avg_duration_seconds < 16.0);
}

TEST_CASE("ExecutionStatistics: fleet summary division safety with agents_targeted=0",
          "[pg][execution_statistics][fleet]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Execution with 0 agents targeted
    auto e = make_exec("def-A", "succeeded", 0, 0, 0, now - 100, now - 90);
    tracker.create_execution(e);

    auto summary = tracker.get_fleet_summary();
    // Should not crash or produce NaN
    CHECK(summary.total_executions == 1);
    CHECK(summary.overall_success_rate == 0.0);
}

// ============================================================================
// get_agent_statistics
// ============================================================================

TEST_CASE("ExecutionStatistics: agent stats grouped correctly",
          "[pg][execution_statistics][agent_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    auto e1 = make_exec("def-A", "succeeded", 2, 2, 0, now - 100, now - 90);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    insert_agent_status(tracker, *id1, "agent-1", "success", 0, now - 100, now - 90);
    insert_agent_status(tracker, *id1, "agent-2", "success", 0, now - 100, now - 95);

    auto e2 = make_exec("def-B", "completed", 1, 1, 0, now - 50, now - 40);
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());

    insert_agent_status(tracker, *id2, "agent-1", "success", 0, now - 50, now - 40);

    auto stats = tracker.get_agent_statistics();
    CHECK(stats.size() == 2); // agent-1 and agent-2

    // Find agent-1 (should have 2 executions)
    bool found_agent1 = false;
    for (const auto& s : stats) {
        if (s.agent_id == "agent-1") {
            CHECK(s.total_executions == 2);
            CHECK(s.success_count == 2);
            CHECK(s.failure_count == 0);
            CHECK(s.success_rate == 100.0);
            found_agent1 = true;
        }
    }
    CHECK(found_agent1);
}

TEST_CASE("ExecutionStatistics: a 'running' (in-flight) execution is excluded from "
          "success/failure/total, not counted as a success (consistency-auditor Gate 4 finding, "
          "PR #3784 fix round)",
          "[pg][execution_statistics][agent_stats][adr1007]") {
    // The keepalive thread (ADR-1007, agents/core/src/agent.cpp) sends a bare
    // RUNNING response every 5 minutes for any long-running per-device
    // command -- exit_code defaults to 0 on the wire for a non-terminal
    // response, which used to satisfy this query's old success CASE
    // (`exit_code = 0 AND status != 'pending'`), counting a still-executing
    // command as a completed success. Turned this from a rare (only a
    // plugin crossing the 64KB output-flush threshold) into a routine
    // misclassification for any per-device dispatch running past 5 minutes.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();
    auto e1 = make_exec("def-running", "running", 1, 0, 0, now - 100, 0);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    // exit_code=0 mirrors the wire shape of a genuine RUNNING/keepalive
    // response (unset, proto default) -- exactly the value that used to
    // satisfy the old success CASE's `exit_code = 0` half.
    insert_agent_status(tracker, *id1, "agent-running", "running", /*exit_code=*/0, now - 100);

    auto stats = tracker.get_agent_statistics();
    bool found = false;
    for (const auto& s : stats) {
        if (s.agent_id == "agent-running")
            found = true;
    }
    // The running row must not appear at all -- WHERE excludes it, same as
    // 'pending'/'dispatched'. If this regresses to counting it (success OR
    // failure), `found` becomes true.
    CHECK_FALSE(found);
}

TEST_CASE("ExecutionStatistics: agent stats with agent_id filter",
          "[pg][execution_statistics][agent_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    auto e1 = make_exec("def-A", "succeeded", 2, 2, 0, now - 100, now - 90);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    insert_agent_status(tracker, *id1, "agent-1", "success", 0, now - 100, now - 90);
    insert_agent_status(tracker, *id1, "agent-2", "success", 0, now - 100, now - 95);

    ExecutionStatsQuery q;
    q.agent_id = "agent-2";
    auto stats = tracker.get_agent_statistics(q);
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].agent_id == "agent-2");
    CHECK(stats[0].total_executions == 1);
}

TEST_CASE("ExecutionStatistics: agent stats with since filter",
          "[pg][execution_statistics][agent_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Old execution
    auto e1 = make_exec("def-A", "succeeded", 1, 1, 0, now - 86400 * 30, now - 86400 * 30 + 5);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());
    insert_agent_status(tracker, *id1, "agent-1", "success", 0, now - 86400 * 30, now - 86400 * 30 + 5);

    // Recent execution
    auto e2 = make_exec("def-B", "succeeded", 1, 1, 0, now - 60, now - 50);
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());
    insert_agent_status(tracker, *id2, "agent-1", "success", 0, now - 60, now - 50);

    ExecutionStatsQuery q;
    q.since = now - 3600; // last hour
    auto stats = tracker.get_agent_statistics(q);
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].total_executions == 1); // only the recent one
}

TEST_CASE("ExecutionStatistics: since and until are presence-tracked and a literal 0 is not the "
          "unbounded sentinel (#4644)",
          "[pg][execution_statistics][since_until]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    const auto now = now_epoch();
    const int64_t old_ts = now - 86400 * 30;
    const int64_t recent_ts = now - 60;
    auto e1 = make_exec("def-A", "succeeded", 1, 1, 0, old_ts, old_ts + 5);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());
    insert_agent_status(tracker, *id1, "agent-1", "success", 0, old_ts, old_ts + 5);
    auto e2 = make_exec("def-B", "succeeded", 1, 1, 0, recent_ts, recent_ts + 5);
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());
    insert_agent_status(tracker, *id2, "agent-1", "success", 0, recent_ts, recent_ts + 5);

    const auto total_agent = [&](const ExecutionStatsQuery& q) {
        const auto s = tracker.get_agent_statistics(q);
        return s.empty() ? int64_t{0} : static_cast<int64_t>(s[0].total_executions);
    };
    const auto defs = [&](const ExecutionStatsQuery& q) {
        return tracker.get_definition_statistics(q).size();
    };

    ExecutionStatsQuery none;
    CHECK_FALSE(none.since.has_value());
    CHECK_FALSE(none.until.has_value());
    CHECK(total_agent(none) == 2);
    CHECK(defs(none) == 2);

    ExecutionStatsQuery since_zero;
    since_zero.since = 0; // literal bound at the epoch: matches what unset matches
    CHECK(total_agent(since_zero) == 2);
    CHECK(defs(since_zero) == 2);

    ExecutionStatsQuery until_old;
    until_old.until = old_ts + 100; // inclusive upper bound keeps only the old one
    CHECK(total_agent(until_old) == 1);
    CHECK(defs(until_old) == 1);

    // Presence, not a sentinel: a literal `until = 0` matches nothing. (No REST/MCP surface can
    // send it; the type must still not read it back as unbounded.)
    ExecutionStatsQuery until_zero;
    until_zero.until = 0;
    CHECK(total_agent(until_zero) == 0);
    CHECK(defs(until_zero) == 0);

    // The fleet summary takes the same presence-tracked bound.
    const auto unbounded = tracker.get_fleet_summary();
    CHECK(unbounded.total_executions == 2);
    CHECK(tracker.get_fleet_summary(int64_t{0}).total_executions == unbounded.total_executions);
    CHECK(tracker.get_fleet_summary(now - 3600).total_executions == 1);
}

TEST_CASE("ExecutionStatistics: agent stats limit",
          "[pg][execution_statistics][agent_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Create 5 agents with executions
    auto e1 = make_exec("def-A", "succeeded", 5, 5, 0, now - 100, now - 90);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    for (int i = 1; i <= 5; ++i) {
        insert_agent_status(tracker, *id1, "agent-" + std::to_string(i),
                            "success", 0, now - 100, now - 90);
    }

    ExecutionStatsQuery q;
    q.limit = 3;
    auto stats = tracker.get_agent_statistics(q);
    CHECK(stats.size() == 3);
}

TEST_CASE("ExecutionStatistics: agent stats success rate with mixed results",
          "[pg][execution_statistics][agent_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // 3 executions for agent-1: 2 success (exit_code 0) + 1 failure (exit_code 1)
    auto e1 = make_exec("def-A", "succeeded", 1, 1, 0, now - 300, now - 290);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());
    insert_agent_status(tracker, *id1, "agent-1", "success", 0, now - 300, now - 290);

    auto e2 = make_exec("def-A", "succeeded", 1, 1, 0, now - 200, now - 190);
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());
    insert_agent_status(tracker, *id2, "agent-1", "success", 0, now - 200, now - 190);

    auto e3 = make_exec("def-A", "completed", 1, 0, 1, now - 100, now - 90);
    auto id3 = tracker.create_execution(e3);
    REQUIRE(id3.has_value());
    insert_agent_status(tracker, *id3, "agent-1", "failure", 1, now - 100, now - 90);

    ExecutionStatsQuery q;
    q.agent_id = "agent-1";
    auto stats = tracker.get_agent_statistics(q);
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].total_executions == 3);
    CHECK(stats[0].success_count == 2);
    CHECK(stats[0].failure_count == 1);
    // Success rate: 2/3 ~ 66.67%
    CHECK(stats[0].success_rate > 60.0);
    CHECK(stats[0].success_rate < 70.0);
}

TEST_CASE("ExecutionStatistics: agent stats avg duration",
          "[pg][execution_statistics][agent_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Two executions for agent-1 with known durations
    auto e1 = make_exec("def-A", "succeeded", 1, 1, 0, now - 300, now - 290);
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());
    // Duration: completed_at - dispatched_at = 10 seconds
    insert_agent_status(tracker, *id1, "agent-1", "success", 0, now - 300, now - 290);

    auto e2 = make_exec("def-B", "succeeded", 1, 1, 0, now - 200, now - 180);
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());
    // Duration: 20 seconds
    insert_agent_status(tracker, *id2, "agent-1", "success", 0, now - 200, now - 180);

    ExecutionStatsQuery q;
    q.agent_id = "agent-1";
    auto stats = tracker.get_agent_statistics(q);
    REQUIRE(stats.size() == 1);
    // Average: (10 + 20) / 2 = 15
    CHECK(stats[0].avg_duration_seconds > 14.0);
    CHECK(stats[0].avg_duration_seconds < 16.0);
}

// ============================================================================
// get_definition_statistics
// ============================================================================

TEST_CASE("ExecutionStatistics: definition stats grouped correctly",
          "[pg][execution_statistics][definition_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Two executions for def-A
    tracker.create_execution(make_exec("def-A", "succeeded", 3, 3, 0, now - 200, now - 190));
    tracker.create_execution(make_exec("def-A", "completed", 2, 1, 1, now - 100, now - 90));

    // One execution for def-B
    tracker.create_execution(make_exec("def-B", "succeeded", 1, 1, 0, now - 50, now - 40));

    auto stats = tracker.get_definition_statistics();
    CHECK(stats.size() == 2);

    // def-A should have 2 total executions
    bool found_def_a = false;
    for (const auto& s : stats) {
        if (s.definition_id == "def-A") {
            CHECK(s.total_executions == 2);
            CHECK(s.total_agents == 5); // 3+2
            found_def_a = true;
        }
    }
    CHECK(found_def_a);
}

TEST_CASE("ExecutionStatistics: definition stats with definition_id filter",
          "[pg][execution_statistics][definition_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    tracker.create_execution(make_exec("def-A", "succeeded", 2, 2, 0, now - 100, now - 90));
    tracker.create_execution(make_exec("def-B", "succeeded", 1, 1, 0, now - 50, now - 40));

    ExecutionStatsQuery q;
    q.definition_id = "def-B";
    auto stats = tracker.get_definition_statistics(q);
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].definition_id == "def-B");
    CHECK(stats[0].total_executions == 1);
}

TEST_CASE("ExecutionStatistics: definition stats success rate",
          "[pg][execution_statistics][definition_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // def-A: 10 targeted, 8 success, 2 failure across executions
    tracker.create_execution(make_exec("def-A", "completed", 5, 4, 1, now - 200, now - 190));
    tracker.create_execution(make_exec("def-A", "completed", 5, 4, 1, now - 100, now - 90));

    ExecutionStatsQuery q;
    q.definition_id = "def-A";
    auto stats = tracker.get_definition_statistics(q);
    REQUIRE(stats.size() == 1);
    // Success rate: 8/10 = 80%
    CHECK(stats[0].success_rate > 79.0);
    CHECK(stats[0].success_rate < 81.0);
}

TEST_CASE("ExecutionStatistics: definition stats avg duration",
          "[pg][execution_statistics][definition_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Duration 10s and 20s
    tracker.create_execution(make_exec("def-A", "succeeded", 1, 1, 0, now - 200, now - 190));
    tracker.create_execution(make_exec("def-A", "succeeded", 1, 1, 0, now - 100, now - 80));

    ExecutionStatsQuery q;
    q.definition_id = "def-A";
    auto stats = tracker.get_definition_statistics(q);
    REQUIRE(stats.size() == 1);
    // Average: (10 + 20) / 2 = 15
    CHECK(stats[0].avg_duration_seconds > 14.0);
    CHECK(stats[0].avg_duration_seconds < 16.0);
}

TEST_CASE("ExecutionStatistics: definition stats skips pending/running executions",
          "[pg][execution_statistics][definition_stats]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto now = now_epoch();

    // Only pending/running should be excluded
    tracker.create_execution(make_exec("def-A", "pending", 1, 0, 0, now - 100, 0));
    tracker.create_execution(make_exec("def-A", "running", 1, 0, 0, now - 50, 0));
    tracker.create_execution(make_exec("def-A", "succeeded", 1, 1, 0, now - 10, now - 5));

    auto stats = tracker.get_definition_statistics();
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].total_executions == 1); // only the succeeded one
}

// ============================================================================
// #4644: a degraded read is distinguishable from "no executions"
// ============================================================================

TEST_CASE("ExecutionStatistics: try_get_* reports a degraded store as nullopt and not empty",
          "[pg][execution_statistics][degrade]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;
    auto id = tracker.create_execution(make_exec("def-degrade", "succeeded", 1, 1, 0));
    REQUIRE(id.has_value());
    insert_agent_status(tracker, *id, "agent-1", "success");

    // Healthy: a value, even when it is an honest empty one.
    REQUIRE(tracker.try_get_agent_statistics().has_value());
    CHECK(tracker.try_get_agent_statistics()->size() == 1);
    ExecutionStatsQuery none;
    none.visible_agents = std::vector<std::string>{}; // deny-all: honest empty, NOT a degrade
    REQUIRE(tracker.try_get_agent_statistics(none).has_value());
    CHECK(tracker.try_get_agent_statistics(none)->empty());
    REQUIRE(tracker.try_get_fleet_summary().has_value());
    CHECK(tracker.try_get_fleet_summary()->total_executions == 1);

    // Degraded: every statistics query reads this table.
    {
        auto lease = tracker_bundle.pool().try_acquire_for(std::chrono::seconds(5));
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(), "ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_4644",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    CHECK_FALSE(tracker.try_get_agent_statistics().has_value());
    CHECK_FALSE(tracker.try_get_definition_statistics().has_value());
    CHECK_FALSE(tracker.try_get_fleet_summary().has_value());
    // The deny-all fast path answers before any query, so it stays an honest empty even while the
    // store is degraded (a present-empty visible set reads nothing it could fail to read).
    REQUIRE(tracker.try_get_agent_statistics(none).has_value());
    CHECK(tracker.try_get_agent_statistics(none)->empty());
    // The plain forms keep their documented collapse for callers that cannot report a degrade.
    CHECK(tracker.get_agent_statistics().empty());
    CHECK(tracker.get_fleet_summary().total_executions == 0);
}
