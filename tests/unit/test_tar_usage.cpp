/**
 * test_tar_usage.cpp -- Unit tests for the `usage` derived fold (Wave 7
 * PR7.2b): the pure pairing/fold logic (tar_usage.hpp) and the
 * checked_transaction-based lifecycle + fold (tar_usage.cpp).
 *
 * DB-backed cases follow test_tar_store.cpp's TestTarDb pattern. The
 * fault-injection cases reuse the SAME RAISE(ABORT)/RAISE(ROLLBACK) trigger
 * idiom test_tar_store.cpp's checked_transaction tests established for
 * commit 1's primitive -- this file's whole point is proving the fold built
 * on that primitive inherits its atomicity, so it uses the identical
 * technique rather than inventing a second one.
 */

#include "tar_usage.hpp"
#include "tar_aggregator.hpp" // source_enabled
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::tar;
using namespace yuzu::tar::usage;

namespace {

struct TestTarDb {
    TarDatabase db;
    fs::path path;

    ~TestTarDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};

TestTarDb make_test_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_usage_");
    auto result = TarDatabase::open(tmp);
    REQUIRE(result.has_value());
    return TestTarDb{std::move(*result), tmp};
}

int64_t count_rows(TarDatabase& db, const std::string& table) {
    auto r = db.execute_query("SELECT COUNT(*) FROM " + table);
    REQUIRE(r.has_value());
    return std::stoll(r->rows[0][0]);
}

std::string cfg(TarDatabase& db, const char* key, const char* def = "") {
    return db.get_config(key, def);
}

// Seeds `n` process_live started/stopped pairs for `exe`, each a distinct
// pid, each running from `start` to `start + duration`, via the raw table
// (not the typed insert -- lets tests set exact ts/action pairs).
void seed_process_pair(TarDatabase& db, uint32_t pid, const std::string& exe, int64_t start,
                       int64_t stop, const std::string& user = "alice") {
    REQUIRE(db.execute_sql(std::format(
        "INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) VALUES "
        "({},1,'started',{},0,'{}','','{}')",
        start, pid, exe, user)));
    if (stop >= 0) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) VALUES "
            "({},1,'stopped',{},0,'{}','','{}')",
            stop, pid, exe, user)));
    }
}

} // namespace

// =============================================================================
// Pure logic: apply_event, expire_open_runs, cap_open_runs, fold_daily
// =============================================================================

TEST_CASE("usage: apply_event pairs started/stopped into a normal closed run",
          "[tar][usage][pure]") {
    FoldState state;
    ProcessEvent start;
    start.ts = 1000;
    start.action = "started";
    start.pid = 1;
    start.name = "a.exe";
    start.user = "alice";
    CHECK_FALSE(apply_event(state, start).has_value());
    CHECK(state.open.size() == 1);

    ProcessEvent stop = start;
    stop.ts = 1100;
    stop.action = "stopped";
    auto closed = apply_event(state, stop);
    REQUIRE(closed.has_value());
    CHECK(closed->kind == ClosedRun::Kind::normal);
    CHECK(closed->start_ts == 1000);
    CHECK(closed->end_ts == 1100);
    CHECK(state.open.empty());
    CHECK(state.unmatched_stops == 0);
}

TEST_CASE("usage: apply_event closes an unmatched stop with no state change",
          "[tar][usage][pure]") {
    FoldState state;
    ProcessEvent stop;
    stop.ts = 1000;
    stop.action = "stopped";
    stop.pid = 1;
    stop.name = "a.exe";
    CHECK_FALSE(apply_event(state, stop).has_value());
    CHECK(state.unmatched_stops == 1);
    CHECK(state.open.empty());
}

TEST_CASE("usage: apply_event supersedes a stale open run on a second started, clamping a "
          "backward clock step to 0s",
          "[tar][usage][pure]") {
    FoldState state;
    ProcessEvent start1;
    start1.ts = 1000;
    start1.action = "started";
    start1.pid = 1;
    start1.name = "a.exe";
    apply_event(state, start1);

    ProcessEvent start2 = start1;
    start2.ts = 500; // BEFORE start1's ts -- backward clock step
    auto superseded = apply_event(state, start2);
    REQUIRE(superseded.has_value());
    CHECK(superseded->kind == ClosedRun::Kind::superseded);
    CHECK(superseded->end_ts == superseded->start_ts); // clamped to 0s, not negative
    CHECK(state.clock_anomalies == 1);
    CHECK(state.open.size() == 1); // the NEW run is open
}

TEST_CASE("usage: expire_open_runs closes runs older than max_age as `expired`, 0s duration",
          "[tar][usage][pure]") {
    FoldState state;
    ProcessEvent start;
    start.ts = 0;
    start.action = "started";
    start.pid = 1;
    start.name = "a.exe";
    apply_event(state, start);

    auto closed = expire_open_runs(state, /*now=*/1'000'000, /*max_age=*/604800);
    REQUIRE(closed.size() == 1);
    CHECK(closed[0].kind == ClosedRun::Kind::expired);
    CHECK(closed[0].end_ts == closed[0].start_ts);
    CHECK(state.open.empty());
}

TEST_CASE("usage: cap_open_runs evicts the OLDEST run first, correctly, past the refactor to "
          "an ordered secondary index (issue #4253)",
          "[tar][usage][pure]") {
    // The pure regression this pins: cap_open_runs used to do a full O(N)
    // linear scan of `open` per eviction to find the minimum start_ts.
    // insert_open_run/erase_open_run now maintain a `open_by_start_ts`
    // secondary index instead -- this test proves that index stays correct
    // (evicts in the right ORDER), not just that eviction happens.
    FoldState state;
    for (uint32_t pid = 1; pid <= 5; ++pid) {
        OpenRun run;
        run.pid = pid;
        run.exe_key = "a.exe";
        run.user = "u";
        run.start_ts = static_cast<int64_t>(pid) * 100; // pid 1 is oldest
        insert_open_run(state, {run.pid, run.exe_key + std::to_string(pid)}, run);
    }
    REQUIRE(state.open.size() == 5);

    auto closed = cap_open_runs(state, /*max_open=*/2);
    REQUIRE(closed.size() == 3);
    // Evicted oldest-first: pid 1 (ts=100), pid 2 (ts=200), pid 3 (ts=300).
    CHECK(closed[0].start_ts == 100);
    CHECK(closed[1].start_ts == 200);
    CHECK(closed[2].start_ts == 300);
    for (const auto& c : closed)
        CHECK(c.kind == ClosedRun::Kind::capped);
    CHECK(state.open.size() == 2);
    // The two SURVIVORS must be the two newest (pid 4, pid 5) -- proves
    // open_by_start_ts and open never desynchronised across three evictions.
    REQUIRE(state.open_by_start_ts.size() == 2);
    CHECK(state.open_by_start_ts.begin()->first == 400);
}

TEST_CASE("usage: fold_daily aggregates run_count/total_seconds by (day_ts, exe_key), buckets "
          "expired+capped together, superseded separately",
          "[tar][usage][pure]") {
    std::vector<ClosedRun> runs;
    ClosedRun a;
    a.pid = 1;
    a.exe_key = "app.exe";
    a.user = "u";
    a.start_ts = 1000;
    a.end_ts = 1100;
    a.kind = ClosedRun::Kind::normal;
    ClosedRun b = a;
    b.pid = 2;
    b.start_ts = 2000;
    b.end_ts = 2050;
    b.kind = ClosedRun::Kind::expired;
    ClosedRun c = a;
    c.pid = 3;
    c.start_ts = 3000;
    c.end_ts = 3000;
    c.kind = ClosedRun::Kind::capped;
    ClosedRun d = a;
    d.pid = 4;
    d.start_ts = 4000;
    d.end_ts = 4010;
    d.kind = ClosedRun::Kind::superseded;

    auto deltas = fold_daily({a, b, c, d});
    REQUIRE(deltas.size() == 1); // same day, same exe_key
    const auto& delta = deltas[0];
    CHECK(delta.run_count == 4);
    CHECK(delta.total_seconds == 100 + 50 + 0 + 10);
    CHECK(delta.expired_runs == 2);   // b (expired) + c (capped)
    CHECK(delta.superseded_runs == 1); // d
}

TEST_CASE("usage: fold_daily saturates instead of overflowing on an extreme start_ts, and a "
          "SECOND extreme run in the same bucket saturates the accumulator too",
          "[tar][usage][pure]") {
    // Governance Gate 3 cpp-expert finding: apply_event's clamp guarantees
    // end_ts >= start_ts (mathematical non-negativity), not int64_t
    // representability -- a corrupt/adversarial process_live row with
    // start_ts near INT64_MIN still overflowed the plain subtraction this
    // file's own saturating_sub was added to prevent, at exactly the one
    // call site that hardening pass missed.
    ClosedRun extreme;
    extreme.pid = 1;
    extreme.exe_key = "corrupt.exe";
    extreme.user = "u";
    extreme.start_ts = std::numeric_limits<int64_t>::min() + 100;
    extreme.end_ts = 1000; // ordinary epoch second -- duration is ~INT64_MAX
    extreme.kind = ClosedRun::Kind::normal;

    auto deltas = fold_daily({extreme});
    REQUIRE(deltas.size() == 1);
    CHECK(deltas[0].total_seconds == std::numeric_limits<int64_t>::max()); // saturated, not UB

    // A second extreme run in the SAME (day_ts, exe_key) bucket: without its
    // own saturating accumulation, `total_seconds += duration` would overflow
    // AGAIN even though the first duration was already clamped to max().
    ClosedRun extreme2 = extreme;
    extreme2.pid = 2;
    auto deltas2 = fold_daily({extreme, extreme2});
    REQUIRE(deltas2.size() == 1);
    CHECK(deltas2[0].total_seconds == std::numeric_limits<int64_t>::max()); // still saturated
    CHECK(deltas2[0].run_count == 2); // both runs still counted, only the sum saturates
}

// =============================================================================
// Lifecycle: usage_lifecycle_state, usage_set_enabled, usage_ensure_baselined
// =============================================================================

TEST_CASE("usage: lifecycle is Disabled when usage_enabled is not true", "[tar][usage][lifecycle]") {
    auto t = make_test_db();
    REQUIRE(t.db.set_config("usage_enabled", "false"));
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::Disabled);
}

TEST_CASE("usage: lifecycle is PendingBaseline on a fresh DB -- enabled by default, never "
          "baselined",
          "[tar][usage][lifecycle]") {
    auto t = make_test_db();
    // usage_enabled absent -> default_enabled=true (registry) -> enabled.
    // usage_generation/usage_active_generation both absent -> mismatch.
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::PendingBaseline);
}

TEST_CASE("usage: usage_ensure_baselined moves PendingBaseline to Active and stamps the "
          "matching generation",
          "[tar][usage][lifecycle]") {
    auto t = make_test_db();
    REQUIRE(usage_lifecycle_state(t.db) == LifecycleState::PendingBaseline);

    auto result = usage_ensure_baselined(t.db, /*now=*/5000);
    REQUIRE(result.has_value());
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::Active);
    CHECK(cfg(t.db, "usage_coverage_since") == "5000");
    CHECK(cfg(t.db, "usage_hwm_id") == "0"); // empty process_live -> MAX(id)=0
}

TEST_CASE("usage: usage_ensure_baselined is a no-op once already Active", "[tar][usage][lifecycle]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 5000).has_value());
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) VALUES "
        "(1,0,'open',1,'a.exe','u',1)"));

    auto result = usage_ensure_baselined(t.db, /*now=*/6000);
    REQUIRE(result.has_value());
    CHECK(cfg(t.db, "usage_coverage_since") == "5000"); // UNCHANGED -- no-op, not a re-baseline
    CHECK(count_rows(t.db, "usage_live") == 1);         // the open run survives -- no-op proved
}

TEST_CASE("usage: usage_ensure_baselined is a no-op while Disabled", "[tar][usage][lifecycle]") {
    auto t = make_test_db();
    REQUIRE(t.db.set_config("usage_enabled", "false"));
    auto result = usage_ensure_baselined(t.db, 5000);
    REQUIRE(result.has_value()); // {} = "nothing to do", not a failure
    CHECK(cfg(t.db, "usage_coverage_since").empty());
}

TEST_CASE("usage: usage_set_enabled(false) bumps the generation, forcing PendingBaseline on "
          "the next enable -- forward-only across a pause",
          "[tar][usage][lifecycle]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    REQUIRE(usage_lifecycle_state(t.db) == LifecycleState::Active);

    REQUIRE(usage_set_enabled(t.db, /*enabled=*/false, /*now=*/2000));
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::Disabled);

    REQUIRE(usage_set_enabled(t.db, /*enabled=*/true, /*now=*/3000));
    // The KEY property: re-enabling does NOT resume Active on the stale
    // baseline -- the generation bump on disable means it must re-baseline.
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::PendingBaseline);

    REQUIRE(usage_ensure_baselined(t.db, 3000).has_value());
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::Active);
    CHECK(cfg(t.db, "usage_coverage_since") == "3000"); // re-baselined from the RE-enable time
}

TEST_CASE("usage: usage_set_enabled(true) is idempotent for an already-true source -- no "
          "spurious generation bump",
          "[tar][usage][lifecycle]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    REQUIRE(usage_lifecycle_state(t.db) == LifecycleState::Active);
    const auto gen_before = cfg(t.db, "usage_generation");

    // A direct usage_set_enabled(true) call -- unlike
    // apply_source_enabled_transition's idempotent-reassert shortcut, this
    // function itself always bumps. Callers (apply_source_enabled_transition)
    // are responsible for the idempotent-reassert check; this test pins that
    // usage_set_enabled alone, called twice with the same value, still
    // reaches Active again after each re-baseline (the caller-level
    // idempotence is covered in test_tar_aggregator.cpp).
    REQUIRE(usage_set_enabled(t.db, true, 1500));
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::PendingBaseline);
    CHECK(cfg(t.db, "usage_generation") != gen_before);
}

// =============================================================================
// Fold: run_usage_fold -- atomicity, gap detection, lag clamp, daily/user upsert
// =============================================================================

TEST_CASE("usage: run_usage_fold does nothing (ok=true) while usage or process is disabled",
          "[tar][usage][fold]") {
    auto t = make_test_db();
    REQUIRE(t.db.set_config("usage_enabled", "false"));
    auto result = run_usage_fold(t.db, 1000);
    CHECK(result.ok);
    CHECK(result.events_seen == 0);
}

TEST_CASE("usage: run_usage_fold refuses to consume events until baselined, then folds "
          "forward from the baseline, never retrospectively",
          "[tar][usage][fold]") {
    auto t = make_test_db();
    // Events exist BEFORE the fold ever ran -- forward-only must not fold them.
    seed_process_pair(t.db, 1, "pre.exe", 100, 200);

    auto first = run_usage_fold(t.db, /*now=*/1000);
    REQUIRE(first.ok);
    CHECK(first.events_seen == 0); // baseline just established -- nothing folded THIS tick
    CHECK(usage_lifecycle_state(t.db) == LifecycleState::Active);

    // Events written AFTER the baseline are the ones that get folded.
    seed_process_pair(t.db, 2, "post.exe", 2000, 2100);
    auto second = run_usage_fold(t.db, /*now=*/3000);
    REQUIRE(second.ok);
    CHECK(second.events_seen == 2); // post.exe's started+stopped
    CHECK(second.runs_closed == 1);

    auto rows = t.db.execute_query("SELECT exe_key FROM usage_daily");
    REQUIRE(rows.has_value());
    REQUIRE(rows->rows.size() == 1);
    CHECK(rows->rows[0][0] == "post.exe"); // pre.exe never appears -- not retrospectively folded
}

TEST_CASE("usage: a fault on usage_daily_user mid-fold commits NOTHING -- not usage_daily, "
          "not usage_live, not the hwm",
          "[tar][usage][fold]") {
    // The central regression this whole rewrite exists for (round 1 Blocker
    // 1 / round 2's residual): a partial commit must be structurally
    // impossible, not merely reduced. Fault the LAST table the fold writes
    // (usage_daily_user) and prove the FIRST (usage_daily) is not durable
    // either -- exactly the property execute_atomic_batch_gated's tolerant
    // data segment did not have.
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "a.exe", 2000, 2100);

    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_udu BEFORE INSERT ON usage_daily_user "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    const auto hwm_before = cfg(t.db, "usage_hwm_id");
    auto result = run_usage_fold(t.db, /*now=*/3000);
    CHECK_FALSE(result.ok);
    CHECK(count_rows(t.db, "usage_daily") == 0);    // NOT durable, despite running first
    CHECK(count_rows(t.db, "usage_live") == 0);     // NOT durable either
    CHECK(cfg(t.db, "usage_hwm_id") == hwm_before);  // hwm did not advance

    REQUIRE(t.db.execute_sql("DROP TRIGGER block_udu"));
    auto retry = run_usage_fold(t.db, /*now=*/3001);
    REQUIRE(retry.ok);
    CHECK(count_rows(t.db, "usage_daily") == 1); // applied exactly once on retry, not skipped
}

TEST_CASE("usage: a fault on usage_daily mid-fold also rolls back usage_live -- no per-table "
          "tolerant segment survived the rewrite",
          "[tar][usage][fold]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "a.exe", 2000, -1); // started only -- stays open

    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ud BEFORE INSERT ON usage_daily "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
    // No daily delta is produced by an open-only run, so force the trigger to
    // matter by also closing it -- add a stop event past the trigger's table.
    REQUIRE(t.db.execute_sql(
        "INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) VALUES "
        "(2100,1,'stopped',1,0,'a.exe','','alice')"));

    auto result = run_usage_fold(t.db, /*now=*/3000);
    CHECK_FALSE(result.ok);
    CHECK(count_rows(t.db, "usage_live") == 0); // the run's close never persisted either
}

TEST_CASE("usage: gap detection re-baselines the hwm to min_id-1 and counts the loss, in the "
          "SAME transaction as everything else",
          "[tar][usage][fold]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());

    // Simulate process_live's row-count prune having destroyed rows the fold
    // never read: insert filler rows to advance the AUTOINCREMENT counter,
    // delete them (surviving MIN(id) jumps past the persisted hwm), then
    // insert the pair the fold will actually see.
    for (int i = 0; i < 10; ++i)
        seed_process_pair(t.db, static_cast<uint32_t>(100 + i), "filler.exe", 0, -1);
    REQUIRE(t.db.execute_sql("DELETE FROM process_live"));
    REQUIRE(t.db.set_config("usage_hwm_id", "5")); // below the ids the filler rows consumed
    seed_process_pair(t.db, 1, "a.exe", 2000, 2100); // lands at id 11, 12 -- MIN(id)=11 > hwm+1=6

    auto result = run_usage_fold(t.db, /*now=*/3000);
    REQUIRE(result.ok);
    CHECK(result.gap_detected);
    CHECK(cfg(t.db, "usage_gap_count") == "1");
    CHECK(result.hwm_id == 12); // re-baselined to min_id-1=10, then advanced past id 12
}

TEST_CASE("usage: lag_events never reports negative (#4255) even when max_id trails the new "
          "hwm after a feeder reset",
          "[tar][usage][fold]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "a.exe", 2000, 2100);
    auto result = run_usage_fold(t.db, /*now=*/3000);
    REQUIRE(result.ok);
    // Steady state: max_id == new_hwm (every row was consumed), so lag is 0,
    // not negative -- the clamp is inert here but the property must hold
    // whenever max_id read at the top of the transaction is >= new_hwm as
    // computed from the SAME snapshot (see tar_usage.cpp's std::max clamp).
    CHECK(result.lag_events >= 0);
    CHECK(cfg(t.db, "usage_lag_events").find('-') == std::string::npos);
}

TEST_CASE("usage: usage_daily_user records distinct usernames per (day, exe) and usage_daily's "
          "distinct_users column matches",
          "[tar][usage][fold]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "shared.exe", 2000, 2100, "alice");
    seed_process_pair(t.db, 2, "shared.exe", 2100, 2200, "bob");
    seed_process_pair(t.db, 3, "shared.exe", 2200, 2300, "alice"); // repeat user, same day

    auto result = run_usage_fold(t.db, /*now=*/3000);
    REQUIRE(result.ok);
    CHECK(result.runs_closed == 3);

    CHECK(count_rows(t.db, "usage_daily_user") == 2); // alice, bob -- deduped
    auto distinct = t.db.execute_query("SELECT distinct_users FROM usage_daily WHERE exe_key = "
                                       "'shared.exe'");
    REQUIRE(distinct.has_value());
    REQUIRE(distinct->rows.size() == 1);
    CHECK(distinct->rows[0][0] == "2");
}

TEST_CASE("usage: a rollback leaves the connection usable and open runs are re-derivable "
          "exactly once on retry -- no fold_hwm replay guard needed",
          "[tar][usage][fold]") {
    // Mutation-style proof that checked_transaction's atomicity is what makes
    // a plain additive upsert safe under retry: if this property broke (a
    // partial commit survived), a naive additive re-application on retry
    // would double-count. It does not, because nothing commits on failure.
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "a.exe", 2000, 2100);

    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ud2 BEFORE INSERT ON usage_daily "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
    REQUIRE_FALSE(run_usage_fold(t.db, 3000).ok);
    CHECK(t.db.is_open()); // statement-preserving fault -- store stays usable

    REQUIRE(t.db.execute_sql("DROP TRIGGER block_ud2"));
    auto retry = run_usage_fold(t.db, 3001);
    REQUIRE(retry.ok);

    auto row = t.db.execute_query("SELECT run_count, total_seconds FROM usage_daily WHERE "
                                  "exe_key = 'a.exe'");
    REQUIRE(row.has_value());
    REQUIRE(row->rows.size() == 1);
    CHECK(row->rows[0][0] == "1");   // run_count == 1, not 2 -- applied exactly once
    CHECK(row->rows[0][1] == "100"); // total_seconds == 100, not 200
}

// =============================================================================
// Adversarial review Wave 7 PR7.2b fix round 1: forward-only boundary reads
// (Blocker 1) and clock-guard anchor tri-state / re-anchoring (Blocker 2)
// =============================================================================

TEST_CASE("usage: run_usage_fold refuses (not folds-from-row-1) when usage_hwm_id is absent "
          "while Active",
          "[tar][usage][fold]") {
    // The core regression: before the fix, a lossy pre-transaction read of
    // usage_hwm_id defaulted an absent/unreadable key to 0, so the fold would
    // consume `id > 0` -- every pre-boundary process_live row. Delete the key
    // out from under an otherwise-Active source (simulating corruption/a lost
    // write) and prove the fold refuses instead of silently folding from
    // row 1.
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "pre.exe", 100, 200); // predates baseline -- must never be folded
    REQUIRE(t.db.execute_sql("DELETE FROM tar_config WHERE key = 'usage_hwm_id'"));

    auto result = run_usage_fold(t.db, /*now=*/2000);
    CHECK_FALSE(result.ok);
    CHECK(count_rows(t.db, "usage_daily") == 0); // pre.exe was never folded
    CHECK(count_rows(t.db, "usage_live") == 0);
}

TEST_CASE("usage: run_usage_fold refuses when usage_hwm_id is malformed while Active",
          "[tar][usage][fold]") {
    // The prepare/step-failure sub-cases of the same defect are exercised by
    // code inspection only (matching commit 1's own precedent for a bare
    // read that cannot be fault-injected without corrupting the store file);
    // the parse-failure sub-case is directly testable and goes through the
    // identical `h.fail()` path.
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "pre.exe", 100, 200);
    REQUIRE(t.db.set_config("usage_hwm_id", "not_a_number"));

    auto result = run_usage_fold(t.db, /*now=*/2000);
    CHECK_FALSE(result.ok);
    CHECK(count_rows(t.db, "usage_daily") == 0);
}

TEST_CASE("usage: expire sweep declines on a genuinely-absent anchor (first fold after "
          "baseline) rather than proceeding",
          "[tar][usage][fold]") {
    // Before the fix, read_config_i64_locked's "0 on any fault OR absence"
    // return let an absent usage_last_fold_ts read as clock_plausible=true,
    // inverting TAR's own no-stored-reading-is-a-decline-trigger convention.
    // Seed a run already older than max_age so a wrongly-proceeding sweep
    // would expire it on this very first fold.
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "old.exe", 1000, -1); // started only -- stays open

    auto result = run_usage_fold(t.db, /*now=*/1000 + yuzu::tar::usage::kDefaultMaxAgeSeconds + 1);
    REQUIRE(result.ok);
    CHECK(result.runs_closed == 0);            // NOT expired -- sweep declined
    CHECK(count_rows(t.db, "usage_live") == 1); // the run is still open
}

TEST_CASE("usage: expire sweep declines when the anchor read fails, and still advances the "
          "anchor for the next tick",
          "[tar][usage][fold]") {
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "old.exe", 1000, -1);
    REQUIRE(t.db.set_config("usage_last_fold_ts", "not_a_number")); // malformed -- read fails

    auto result = run_usage_fold(t.db, /*now=*/1000 + yuzu::tar::usage::kDefaultMaxAgeSeconds + 1);
    REQUIRE(result.ok); // the read/parse failure declines the SWEEP only, not the whole fold
    CHECK(result.runs_closed == 0);
    CHECK(count_rows(t.db, "usage_live") == 1);
    CHECK(cfg(t.db, "usage_last_fold_ts") ==
          std::to_string(1000 + yuzu::tar::usage::kDefaultMaxAgeSeconds + 1)); // re-anchored
}

TEST_CASE("usage: a declined tick DOES advance the anchor, so an ordinary sleep/wake gap "
          "self-heals within ~2 ticks instead of freezing the guard forever",
          "[tar][usage][fold]") {
    // Wave 7 PR7.2b fix round 2, correcting fix round 1's own overcorrection
    // (governance Gate 4 happy-path finding): fix round 1 made
    // usage_last_fold_ts advance ONLY on a plausible tick. Since this key
    // has exactly one writer in the whole file, that meant ANY single
    // declined tick froze the anchor permanently -- every later tick
    // compared against the same stale value, the gap only grew, and the
    // guard declined forever. An ordinary laptop closed over a weekend hit
    // this on the very first wake tick. This test proves the corrected
    // behavior: the anchor advances even on a declined tick, so the NEXT
    // tick (a normal small gap relative to the just-advanced anchor) looks
    // plausible again and the sweep resumes.
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "old.exe", 1500, -1); // stays open across every tick below

    // Tick 1: establishes a real anchor at now=2000 (small gap, plausible).
    auto fold1 = run_usage_fold(t.db, /*now=*/2000);
    REQUIRE(fold1.ok);
    CHECK(cfg(t.db, "usage_last_fold_ts") == "2000");
    CHECK(cfg(t.db, "usage_expiry_declined_count") == ""); // never written -- no decline yet

    // Tick 2: a huge forward clock jump (device slept > kMaxPlausibleFoldGapSeconds
    // = 86400s) -- must decline THIS tick's sweep (the run must not be
    // wrongly force-closed against an untrustworthy `now`) but the anchor
    // MUST still advance, and the decline must be counted.
    const int64_t wake_now = 2000 + 700000; // > 8 days "asleep"
    auto fold2 = run_usage_fold(t.db, wake_now);
    REQUIRE(fold2.ok);
    CHECK(cfg(t.db, "usage_last_fold_ts") == std::to_string(wake_now)); // advanced -- the fix
    CHECK(count_rows(t.db, "usage_live") == 1); // run 1 still open, not wrongly expired
    CHECK(cfg(t.db, "usage_expiry_declined_count") == "1");

    // Tick 3: a normal small gap (500s) relative to tick 2's just-advanced
    // anchor -- must be judged plausible and resume the sweep. The run
    // (started at ts=1500) is now genuinely older than kDefaultMaxAgeSeconds
    // (7 days) measured against the real clock, so a correctly-healed guard
    // expires it; a still-frozen guard (the round-1 bug) would keep
    // declining forever and this run would never expire.
    const int64_t healed_now = wake_now + 500;
    auto fold3 = run_usage_fold(t.db, healed_now);
    REQUIRE(fold3.ok);
    REQUIRE(healed_now - 1500 > yuzu::tar::usage::kDefaultMaxAgeSeconds); // sanity: old enough
    CHECK(count_rows(t.db, "usage_live") == 0);  // expired -- the guard self-healed
    CHECK(cfg(t.db, "usage_last_fold_ts") == std::to_string(healed_now));
    CHECK(cfg(t.db, "usage_expiry_declined_count") == "1"); // unchanged -- tick 3 didn't decline
}

TEST_CASE("usage: a sustained bad clock still declines on its OWN first implausible tick",
          "[tar][usage][fold]") {
    // Unconditional anchor advancement (the fix above) does not weaken the
    // guard's per-tick decision -- it only stops a single decline from
    // becoming permanent. A clock that is wrong on tick N is still
    // correctly declined on tick N, every time it happens. This does NOT
    // prove protection against a SUSTAINED bad clock across multiple ticks --
    // per the design comment above run_usage_fold's anchor read, no local
    // heuristic can distinguish a one-off skip from a clock that stays wrong
    // and self-consistent, so a smoothly-incrementing bad clock is laundered
    // into trust after exactly one decline (governance Gate 8 security-
    // guardian re-review finding, LOW: this test's own title previously
    // overclaimed "the protection this guard was actually built for is
    // unchanged").
    auto t = make_test_db();
    REQUIRE(usage_ensure_baselined(t.db, 1000).has_value());
    seed_process_pair(t.db, 1, "old.exe", 1500, -1);

    auto fold1 = run_usage_fold(t.db, /*now=*/2000);
    REQUIRE(fold1.ok);

    // A backward clock step is exactly as implausible as a huge forward one.
    auto fold2 = run_usage_fold(t.db, /*now=*/1500);
    REQUIRE(fold2.ok);
    CHECK(count_rows(t.db, "usage_live") == 1); // declined -- not wrongly force-closed
    CHECK(cfg(t.db, "usage_expiry_declined_count") == "1");
}
