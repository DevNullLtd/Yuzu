/**
 * test_baseline_store.cpp — Unit tests for BaselineStore (Guardian Baselines)
 *
 * Covers:
 *   - schema migration applies cleanly against a fresh Postgres database
 *   - baseline CRUD round-trip (create / get / list / update / delete)
 *   - create generates a 12-hex id when none is supplied, honours a caller id
 *   - UNIQUE(name) collision surfaces as a kConflictPrefix error
 *   - unknown-id update/delete return a non-conflict error
 *   - created_at/updated_at stamped by the store; updated_at advances on update
 *   - member set replace is transactional + de-duplicates; get is sorted
 *   - set_members on a non-existent baseline is a not-found error
 *   - assignment include/exclude round-trip; invalid disposition aborts cleanly;
 *     duplicate group_id collapses to the last disposition (PK invariant)
 *   - delete_baseline cascades member + assignment rows (FK ON DELETE CASCADE)
 *   - reverse lookups: baselines_containing_rule, list_deployed_baselines
 *   - cross-store cleanup: remove_rule_everywhere / remove_group_everywhere
 *   - ADR-0055 catastrophic-read set: deployed_member_rule_ids() (both
 *     overloads) source from deployed_snapshot, NOT live members; a degraded
 *     store returns std::unexpected, never a silent empty container; a
 *     malformed/empty snapshot is a successful read that skips, not a degrade
 *   - get_members_checked() degrade-distinguishable twin of get_members()
 *   - bad-path (unroutable DSN) yields a closed store with sentinel returns
 *   - migration idempotency: re-open the same dsn
 *
 * No legacy-SQLite backfill test coverage: the dedicated backfill TEST_CASE
 * suite (ADR-0009/0055) was removed as part of a fresh-start-by-default
 * policy change (ADR-0009 amendment, 2026-08-25) -- no production fleet has
 * ever run a pre-Postgres build. BaselineStore::migrate_from_sqlite() itself
 * was retired (chore/retire-migrate-from-sqlite-batch-b, #3623); the "bad
 * path yields a closed store" test is unaffected -- it exercises
 * construction against an unroutable DSN, one of many sentinel-return
 * checks on a closed store, unrelated to backfill correctness.
 */

#include "baseline_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>
#include <thread>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own BaselineStore against a clone of this schema
// (ADR-0055 migration).
yuzu::test::PgTestTemplate baselinestore_tpl{"baselinestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    BaselineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("baselinestore template: store failed to migrate");
}};

Baseline make_baseline(std::string name) {
    Baseline b;
    b.name = std::move(name);
    b.description = "desc";
    b.created_by = "alice";
    b.updated_by = "alice";
    return b;
}

void exec_sql(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// Like exec_sql but never throws and asserts nothing, for use in a destructor (ScopeExit) that
// may run during unwinding. A failure is swallowed: the per-test database is dropped anyway.
void exec_sql_nothrow(const std::string& dsn, const std::string& sql) noexcept {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) == CONNECTION_OK)
        pg::PgResult result{PQexec(conn.get(), sql.c_str())};
}

// Simulate guardian_routes.cpp's deploy_baseline handler: snapshot the
// current member set into deployed_snapshot and flip lifecycle to deployed.
void deploy(BaselineStore& store, const std::string& baseline_id) {
    auto members = store.get_members_checked(baseline_id);
    REQUIRE(members.has_value());
    auto b = store.get_baseline(baseline_id);
    REQUIRE(b.has_value());
    b->lifecycle = kBaselineDeployed;
    b->deployed_snapshot = nlohmann::json(*members).dump();
    b->deployed_by = "bob";
    REQUIRE(store.update_baseline(*b).has_value());
}

} // namespace

// ── CRUD ─────────────────────────────────────────────────────────────────────

TEST_CASE("BaselineStore opens and applies its schema", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.baseline_count() == 0);
}

TEST_CASE("BaselineStore::deployed_baseline_count_checked counts only deployed Baselines and "
          "reports an error on degrade, never 0",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());

    auto none = store.deployed_baseline_count_checked();
    REQUIRE(none.has_value());
    CHECK(*none == 0);

    auto draft = store.create_baseline(make_baseline("draft-only"));
    auto live = store.create_baseline(make_baseline("will-deploy"));
    REQUIRE(draft.has_value());
    REQUIRE(live.has_value());
    deploy(store, *live);

    auto one = store.deployed_baseline_count_checked();
    REQUIRE(one.has_value());
    CHECK(*one == 1); // the draft is not counted
    CHECK(store.baseline_count() == 2);

    SECTION("a query-level failure") {
        exec_sql(db.dsn(), "ALTER TABLE baseline_store.baselines RENAME TO baselines_broken");
        auto degraded = store.deployed_baseline_count_checked();
        REQUIRE_FALSE(degraded.has_value());
        CHECK_FALSE(degraded.error().empty());
        exec_sql(db.dsn(), "ALTER TABLE baseline_store.baselines_broken RENAME TO baselines");
    }
    SECTION("a closed store") {
        PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
        BaselineStore bad(bad_pool);
        auto degraded = bad.deployed_baseline_count_checked();
        REQUIRE_FALSE(degraded.has_value());
        CHECK_FALSE(degraded.error().empty());
    }
}

TEST_CASE("Baseline CRUD round-trip", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_baseline(make_baseline("CIS Windows L1"));
    REQUIRE(created.has_value());
    const std::string id = *created;
    REQUIRE_FALSE(id.empty());
    REQUIRE(store.baseline_count() == 1);

    auto got = store.get_baseline(id);
    REQUIRE(got.has_value());
    CHECK(got->name == "CIS Windows L1");
    CHECK(got->description == "desc");
    CHECK(got->lifecycle == kBaselineDraft); // defaults to draft
    CHECK(got->created_by == "alice");
    CHECK(got->created_at > 0);
    CHECK(got->updated_at > 0);
    CHECK(got->deployed_at == 0);

    auto all = store.list_baselines();
    REQUIRE(all.size() == 1);
    CHECK(all[0].baseline_id == id);

    // Update mutable scalars (e.g. a deploy flipping lifecycle).
    Baseline upd = *got;
    upd.description = "edited";
    upd.lifecycle = kBaselineDeployed;
    upd.deployed_by = "bob";
    upd.deployed_at = 1000;
    upd.updated_by = "bob";
    REQUIRE(store.update_baseline(upd).has_value());

    auto after = store.get_baseline(id);
    REQUIRE(after.has_value());
    CHECK(after->description == "edited");
    CHECK(after->lifecycle == kBaselineDeployed);
    CHECK(after->deployed_by == "bob");
    CHECK(after->deployed_at == 1000);
    CHECK(after->created_at == got->created_at); // immutable
    CHECK(after->updated_at >= got->updated_at); // re-stamped

    REQUIRE(store.delete_baseline(id).has_value());
    CHECK_FALSE(store.get_baseline(id).has_value());
    CHECK(store.baseline_count() == 0);
}

TEST_CASE("create_baseline honours a caller-supplied id", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    Baseline b = make_baseline("named");
    b.baseline_id = "fixed-id-123";
    auto created = store.create_baseline(b);
    REQUIRE(created.has_value());
    CHECK(*created == "fixed-id-123");
    CHECK(store.get_baseline("fixed-id-123").has_value());
}

TEST_CASE("Duplicate baseline name is a conflict error", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.create_baseline(make_baseline("dup")).has_value());

    auto again = store.create_baseline(make_baseline("dup"));
    REQUIRE_FALSE(again.has_value());
    CHECK(is_conflict_error(again.error()));
}

TEST_CASE("update/delete of unknown baseline are non-conflict errors", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};

    Baseline ghost = make_baseline("ghost");
    ghost.baseline_id = "no-such";
    auto u = store.update_baseline(ghost);
    REQUIRE_FALSE(u.has_value());
    CHECK_FALSE(is_conflict_error(u.error()));

    auto d = store.delete_baseline("no-such");
    REQUIRE_FALSE(d.has_value());
    CHECK_FALSE(is_conflict_error(d.error()));
}

TEST_CASE("create_baseline/update_baseline reject an invalid lifecycle", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};

    Baseline bad = make_baseline("bad-lifecycle");
    bad.lifecycle = "active"; // not draft/deployed
    auto created = store.create_baseline(bad);
    REQUIRE_FALSE(created.has_value());
    CHECK_FALSE(is_conflict_error(created.error()));
    CHECK_FALSE(store.get_baseline_by_name("bad-lifecycle", nullptr).has_value());

    const std::string id = *store.create_baseline(make_baseline("ok-lifecycle"));
    Baseline update = *store.get_baseline(id);
    update.lifecycle = "active";
    auto updated = store.update_baseline(update);
    REQUIRE_FALSE(updated.has_value());
    CHECK_FALSE(is_conflict_error(updated.error()));
    CHECK(store.get_baseline(id)->lifecycle == kBaselineDraft); // untouched
}

TEST_CASE("Member set replace is transactional and de-duplicates", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("members"));

    REQUIRE(store.set_members(id, {"r1", "r2", "r1", "", "r3"}).has_value());
    auto m = store.get_members(id);
    REQUIRE(m == std::vector<std::string>{"r1", "r2", "r3"}); // sorted, de-duped, blanks dropped
    CHECK(store.member_count(id) == 3);

    // Replace wholesale.
    REQUIRE(store.set_members(id, {"r9", "r2"}).has_value());
    CHECK(store.get_members(id) == std::vector<std::string>{"r2", "r9"});

    // Clear.
    REQUIRE(store.set_members(id, {}).has_value());
    CHECK(store.get_members(id).empty());
}

TEST_CASE("set_members on a non-existent baseline is not-found", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    auto r = store.set_members("nope", {"r1"});
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(is_conflict_error(r.error()));
}

TEST_CASE("set_members/set_assignment with an EMPTY payload against a baseline that never "
          "existed is not-found, not a silent success",
          "[pg][baseline_store]") {
    // Regression test, NOT a TOCTOU race pin (governance Gate-8 re-review
    // correction: quality-engineer found the original comment here
    // overclaimed — a baseline_id that never existed was ALREADY caught by
    // the pre-fix code's up-front existence check; this case was never
    // racy). What this DOES pin: the post-fix touch-UPDATE's RETURNING-based
    // not-found detection still works correctly for the never-existed case,
    // now that the separate existence-check lease is gone. The actual TOCTOU
    // race — a baseline that EXISTS at call time, concurrently deleted mid-
    // operation — is pinned by the next test below, which holds the row lock
    // deliberately rather than relying on thread-scheduling luck.
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};

    auto members_r = store.set_members("nope", {});
    REQUIRE_FALSE(members_r.has_value());
    CHECK_FALSE(is_conflict_error(members_r.error()));

    auto assignment_r = store.set_assignment("nope", {});
    REQUIRE_FALSE(assignment_r.has_value());
    CHECK_FALSE(is_conflict_error(assignment_r.error()));
}

TEST_CASE("set_members correctly reports not-found when a concurrent DELETE wins the row-lock "
          "race against the touch-UPDATE (genuine TOCTOU reproduction, not thread-timing luck)",
          "[pg][baseline_store][concurrency]") {
    // This is the race the TOCTOU fix actually closes: a baseline that
    // EXISTS at call time, concurrently deleted mid-operation — NOT the
    // never-existed case in the test above (governance Gate-8 correction;
    // quality-engineer found that case was never racy). Uses a second,
    // independent connection holding an uncommitted DELETE to deterministically
    // force the interleaving via Postgres's own row lock, rather than hoping
    // two threads happen to race: store's set_members call is made to
    // genuinely BLOCK on the touch-UPDATE's row lock until this test resolves
    // the locker's transaction, so the outcome is controlled, not probabilistic.
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("race-victim"));

    pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        pg::PgResult r{PQexec(locker.get(), "BEGIN")};
        REQUIRE(r.ok());
    }
    {
        pg::PgResult r{PQexec(
            locker.get(),
            ("DELETE FROM baseline_store.baselines WHERE baseline_id = '" + id + "'").c_str())};
        REQUIRE(r.ok());
        CHECK(std::string(PQcmdTuples(r.get())) == "1");
    }
    // The row is now deleted-but-uncommitted: a concurrent UPDATE targeting
    // it must block until this transaction resolves (Postgres row-lock
    // semantics), then see the row is genuinely gone once we commit.
    bool set_members_ok = false;
    std::string set_members_error;
    std::chrono::steady_clock::duration call_duration{};
    std::thread t([&] {
        // Timestamped INSIDE the thread, not before spawning it — a
        // pre-spawn timestamp would still pass the >=150ms check below even
        // if the thread were scheduled so late it only reached the
        // touch-UPDATE after COMMIT already ran (quality-engineer, Gate 8
        // round 2: catches the already-deleted fast-path silently satisfying
        // the same assertion meant to prove the blocked-then-re-evaluate path).
        const auto call_start = std::chrono::steady_clock::now();
        auto r = store.set_members(id, {});
        call_duration = std::chrono::steady_clock::now() - call_start;
        set_members_ok = r.has_value();
        if (!r)
            set_members_error = r.error();
    });
    // Not load-bearing for correctness (the row lock forces the ordering
    // regardless of timing) — only gives the thread a realistic chance to
    // actually reach and block on the lock before we resolve it, rather than
    // committing before the thread has even started.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    // Join BEFORE any assertion that could throw (quality-engineer, Gate 8
    // round 2): a REQUIRE between spawning `t` and joining it would unwind
    // past a still-joinable std::thread on failure and call std::terminate,
    // aborting the whole shard instead of failing one test.
    pg::PgResult commit_result{PQexec(locker.get(), "COMMIT")};
    const bool commit_ok = commit_result.ok();
    const std::string commit_error = commit_ok ? "" : PQresultErrorMessage(commit_result.get());
    t.join();
    REQUIRE(commit_ok);
    INFO(commit_error);

    // Self-verifying against a future regression that weakens the row lock
    // (e.g. a read-committed lookup instead of the locking UPDATE): if
    // set_members's touch-UPDATE did NOT block on the held lock, it would
    // return almost immediately, well under the 200ms this test controls —
    // proving the test exercised the intended blocking path, not just a
    // coincidentally-correct fast race.
    CHECK(call_duration >= std::chrono::milliseconds(150));

    // The delete won the race: set_members must report not-found, never a
    // silent success against the now-deleted baseline (the pre-fix defect —
    // a row-count-blind touch-UPDATE reporting PGRES_COMMAND_OK on 0 rows).
    REQUIRE_FALSE(set_members_ok);
    CHECK(set_members_error.find("not found") != std::string::npos);
    CHECK(store.get_baseline(id).has_value() == false);
}

TEST_CASE("Assignment include/exclude round-trip and validation", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("assign"));

    REQUIRE(store.set_assignment(id, {{"g-prod", kAssignInclude}, {"g-jump", kAssignExclude}})
                .has_value());
    auto a = store.get_assignment(id);
    REQUIRE(a.size() == 2);
    // ORDER BY disposition, group_id → exclude sorts before include.
    CHECK(a[0].disposition == kAssignExclude);
    CHECK(a[0].group_id == "g-jump");
    CHECK(a[1].disposition == kAssignInclude);
    CHECK(a[1].group_id == "g-prod");

    // Invalid disposition aborts with nothing changed.
    auto bad = store.set_assignment(id, {{"g-x", "maybe"}});
    REQUIRE_FALSE(bad.has_value());
    CHECK_FALSE(is_conflict_error(bad.error()));
    CHECK(store.get_assignment(id).size() == 2); // untouched

    // Duplicate group_id collapses to the LAST disposition (PK invariant).
    REQUIRE(store.set_assignment(id, {{"g-dup", kAssignInclude}, {"g-dup", kAssignExclude}})
                .has_value());
    auto d = store.get_assignment(id);
    REQUIRE(d.size() == 1);
    CHECK(d[0].group_id == "g-dup");
    CHECK(d[0].disposition == kAssignExclude);
}

TEST_CASE("set_members/set_assignment advance the parent baseline's updated_at",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("touch"));
    const int64_t created_updated_at = store.get_baseline(id)->updated_at;

    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // now_epoch() is second-granular

    REQUIRE(store.set_members(id, {"r1"}).has_value());
    const int64_t after_members = store.get_baseline(id)->updated_at;
    CHECK(after_members > created_updated_at);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    REQUIRE(store.set_assignment(id, {{"g1", kAssignInclude}}).has_value());
    const int64_t after_assignment = store.get_baseline(id)->updated_at;
    CHECK(after_assignment > after_members);
}

TEST_CASE("delete_baseline cascades members and assignment", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("cascade"));
    REQUIRE(store.set_members(id, {"r1", "r2"}).has_value());
    REQUIRE(store.set_assignment(id, {{"g1", kAssignInclude}}).has_value());

    REQUIRE(store.delete_baseline(id).has_value());

    // If the FK cascade did not fire, these WHERE baseline_id=? queries would
    // still return the orphaned rows.
    CHECK(store.get_members(id).empty());
    CHECK(store.get_assignment(id).empty());
}

TEST_CASE("Reverse lookups: baselines_containing_rule + list_deployed_baselines",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string a = *store.create_baseline(make_baseline("A"));
    const std::string b = *store.create_baseline(make_baseline("B"));
    REQUIRE(store.set_members(a, {"shared", "only-a"}).has_value());
    REQUIRE(store.set_members(b, {"shared"}).has_value());

    auto containing = store.baselines_containing_rule("shared");
    std::sort(containing.begin(), containing.end());
    auto expect = std::vector<std::string>{a, b};
    std::sort(expect.begin(), expect.end());
    CHECK(containing == expect);
    CHECK(store.baselines_containing_rule("only-a") == std::vector<std::string>{a});

    // Only B is deployed.
    Baseline bb = *store.get_baseline(b);
    bb.lifecycle = kBaselineDeployed;
    REQUIRE(store.update_baseline(bb).has_value());
    auto deployed = store.list_deployed_baselines();
    REQUIRE(deployed.size() == 1);
    CHECK(deployed[0].baseline_id == b);
}

TEST_CASE("Cross-store cleanup hooks remove rows from every baseline", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string a = *store.create_baseline(make_baseline("A"));
    const std::string b = *store.create_baseline(make_baseline("B"));
    REQUIRE(store.set_members(a, {"r-gone", "keep"}).has_value());
    REQUIRE(store.set_members(b, {"r-gone"}).has_value());
    REQUIRE(store.set_assignment(a, {{"g-gone", kAssignInclude}}).has_value());
    REQUIRE(store.set_assignment(b, {{"g-gone", kAssignExclude}}).has_value());

    CHECK(store.remove_rule_everywhere("r-gone") == 2);
    CHECK(store.get_members(a) == std::vector<std::string>{"keep"});
    CHECK(store.get_members(b).empty());

    CHECK(store.remove_group_everywhere("g-gone") == 2);
    CHECK(store.get_assignment(a).empty());
    CHECK(store.get_assignment(b).empty());

    // Idempotent: removing what's already gone reports zero.
    CHECK(store.remove_rule_everywhere("r-gone") == 0);
}

TEST_CASE("Baselines persist across reopen", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    std::string id;
    {
        PgPool pool1{{.conninfo = db.dsn(), .size = 4}};
        BaselineStore store{pool1};
        REQUIRE(store.is_open());
        id = *store.create_baseline(make_baseline("persist"));
        REQUIRE(store.set_members(id, {"r1"}).has_value());
    }
    {
        PgPool pool2{{.conninfo = db.dsn(), .size = 4}};
        BaselineStore store{pool2}; // migration idempotent against the already-applied schema
        REQUIRE(store.is_open());
        auto got = store.get_baseline(id);
        REQUIRE(got.has_value());
        CHECK(got->name == "persist");
        CHECK(store.get_members(id) == std::vector<std::string>{"r1"});
    }
}

// ── Catastrophic-read set (ADR-0055, CLAUDE.md Guardian invariant) ─────────

TEST_CASE("deployed_member_rule_ids sources the deployed snapshot, not live members",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("deploy-target"));
    REQUIRE(store.set_members(id, {"guard-a", "guard-b"}).has_value());
    deploy(store, id);

    auto fleet = store.deployed_member_rule_ids();
    REQUIRE(fleet.has_value());
    CHECK(*fleet == std::unordered_set<std::string>{"guard-a", "guard-b"});

    auto per_baseline = store.deployed_member_rule_ids(id);
    REQUIRE(per_baseline.has_value());
    CHECK(*per_baseline == std::vector<std::string>{"guard-a", "guard-b"});

    // Draft-edit the live member set WITHOUT re-deploying — the catastrophic
    // invariant: the enforced set must NOT change until a Push-gated
    // re-deploy rewrites deployed_snapshot.
    REQUIRE(store.set_members(id, {"guard-c"}).has_value());
    CHECK(store.get_members(id) == std::vector<std::string>{"guard-c"}); // live members DID change

    auto fleet_after_edit = store.deployed_member_rule_ids();
    REQUIRE(fleet_after_edit.has_value());
    CHECK(*fleet_after_edit == std::unordered_set<std::string>{"guard-a", "guard-b"}); // unchanged

    auto per_baseline_after_edit = store.deployed_member_rule_ids(id);
    REQUIRE(per_baseline_after_edit.has_value());
    CHECK(*per_baseline_after_edit == std::vector<std::string>{"guard-a", "guard-b"}); // unchanged

    // Re-deploy converges the enforced set to the new live members.
    deploy(store, id);
    auto fleet_after_redeploy = store.deployed_member_rule_ids();
    REQUIRE(fleet_after_redeploy.has_value());
    CHECK(*fleet_after_redeploy == std::unordered_set<std::string>{"guard-c"});
}

TEST_CASE("deployed_member_rule_ids: a malformed/empty snapshot is a successful skip, not a "
          "degrade",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("malformed-snap"));

    // Never deployed: draft lifecycle, empty snapshot column.
    auto never_deployed = store.deployed_member_rule_ids();
    REQUIRE(never_deployed.has_value());
    CHECK(never_deployed->empty());
    auto never_deployed_pb = store.deployed_member_rule_ids(id);
    REQUIRE(never_deployed_pb.has_value());
    CHECK(never_deployed_pb->empty());

    // Deployed with a genuinely malformed (non-JSON-array) snapshot — the
    // store's public API can never write this; simulate a corrupt row
    // directly to exercise the fail-closed parse path.
    exec_sql(db.dsn(), "UPDATE baseline_store.baselines SET lifecycle = 'deployed', "
                       "deployed_snapshot = 'not json at all' WHERE baseline_id = '" + id + "'");
    auto malformed = store.deployed_member_rule_ids();
    REQUIRE(malformed.has_value()); // successful read, NOT std::unexpected
    CHECK(malformed->empty());
    auto malformed_pb = store.deployed_member_rule_ids(id);
    REQUIRE(malformed_pb.has_value());
    CHECK(malformed_pb->empty());
}

TEST_CASE("Bad path (unroutable DSN) yields a closed store with sentinel returns",
          "[pg][baseline_store]") {
    // No live rig needed — an unroutable address fails fast everywhere
    // (mirrors GuaranteedStateStore's equivalent bad-path test, ADR-0038).
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    BaselineStore bad(bad_pool);
    CHECK_FALSE(bad.is_open());

    CHECK_FALSE(bad.create_baseline(make_baseline("x")).has_value());
    CHECK_FALSE(bad.get_baseline("x").has_value());
    bool store_ok = true;
    CHECK_FALSE(bad.get_baseline_by_name("x", &store_ok).has_value());
    CHECK_FALSE(store_ok); // fault, not a genuine miss
    CHECK(bad.list_baselines().empty());
    CHECK_FALSE(bad.update_baseline(make_baseline("x")).has_value());
    CHECK_FALSE(bad.delete_baseline("x").has_value());
    CHECK_FALSE(bad.set_members("x", {"r1"}).has_value());
    CHECK(bad.get_members("x").empty());
    // get_members_checked is degrade-distinguishable: unexpected, not empty.
    CHECK_FALSE(bad.get_members_checked("x").has_value());
    CHECK(bad.baselines_containing_rule("x").empty());
    CHECK(bad.remove_rule_everywhere("x") == 0);
    CHECK_FALSE(bad.set_assignment("x", {{"g1", kAssignInclude}}).has_value());
    CHECK(bad.get_assignment("x").empty());
    CHECK(bad.remove_group_everywhere("x") == 0);
    CHECK(bad.list_deployed_baselines().empty());
    // Catastrophic-read set: unexpected on a closed store, never a silent
    // empty container.
    CHECK_FALSE(bad.deployed_member_rule_ids().has_value());
    CHECK_FALSE(bad.deployed_member_rule_ids("x").has_value());
    CHECK(bad.baseline_count() == 0);
    CHECK(bad.member_count("x") == 0);
}

// ── Post-mutation hook (#5513) ─────────────────────────────────────────────────
// The heartbeat reconcile's caches are dropped by this hook on a committed update (a deploy
// rewrites the deployed snapshot) or delete, BEFORE the caller's own policy-generation bump.

TEST_CASE("BaselineStore: the baseline-mutation hook fires once per committed update and delete",
          "[pg][baseline_store][baseline_hook]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());

    int fired = 0;
    std::vector<bool> present_seen;       // is the row there when the hook runs
    std::vector<std::string> deployed_seen; // the deployed set the hook can already read
    std::string id;
    store.set_on_baseline_mutation([&] {
        ++fired;
        present_seen.push_back(!id.empty() && store.get_baseline(id).has_value());
        const auto d = store.deployed_member_rule_ids();
        deployed_seen.push_back(d.has_value() ? std::to_string(d->size()) : std::string("degraded"));
    });

    auto created = store.create_baseline(make_baseline("hooked"));
    REQUIRE(created.has_value());
    id = *created;
    CHECK(fired == 0);  // a create is a draft: nothing deployed changed
    REQUIRE(store.set_members(id, {"r1", "r2"}).has_value());
    REQUIRE(store.set_assignment(id, {}).has_value());
    CHECK(fired == 0);  // membership and assignment edits do not touch the deployed snapshot

    deploy(store, id);  // update_baseline writing the deployed snapshot
    CHECK(fired == 1);
    REQUIRE(deployed_seen.size() == 1);
    CHECK(deployed_seen[0] == "2");  // AFTER commit: the new deployed set is already readable
    CHECK(present_seen[0]);

    REQUIRE(store.delete_baseline(id).has_value());
    CHECK(fired == 2);
    REQUIRE(present_seen.size() == 2);
    CHECK_FALSE(present_seen[1]);  // AFTER commit: the row is already gone
    CHECK(deployed_seen[1] == "0");

    // A mutation that did not commit does not fire it.
    auto b = make_baseline("ghost");
    b.baseline_id = "does-not-exist";
    CHECK_FALSE(store.update_baseline(b).has_value());
    CHECK_FALSE(store.delete_baseline("does-not-exist").has_value());
    auto dup1 = store.create_baseline(make_baseline("dup"));
    REQUIRE(dup1.has_value());
    auto other = store.create_baseline(make_baseline("other"));
    REQUIRE(other.has_value());
    auto clash = store.get_baseline(*other);
    REQUIRE(clash.has_value());
    clash->name = "dup";
    CHECK_FALSE(store.update_baseline(*clash).has_value());  // name conflict
    CHECK(fired == 2);
}

TEST_CASE("BaselineStore: a throwing baseline-mutation hook never breaks the mutation",
          "[pg][baseline_store][baseline_hook]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());
    int fired = 0;
    SECTION("std::exception") {
        store.set_on_baseline_mutation([&] {
            ++fired;
            throw std::runtime_error("hook exploded");
        });
    }
    SECTION("a non-std exception") {
        store.set_on_baseline_mutation([&] {
            ++fired;
            throw 42;
        });
    }
    auto created = store.create_baseline(make_baseline("throws"));
    REQUIRE(created.has_value());
    const std::string id = *created;
    REQUIRE(store.set_members(id, {"r1"}).has_value());
    deploy(store, id);  // update_baseline succeeds although the hook throws
    const auto got = store.get_baseline(id);
    REQUIRE(got.has_value());
    CHECK(got->lifecycle == kBaselineDeployed);  // committed
    REQUIRE(store.delete_baseline(id).has_value());
    CHECK(fired == 2);

    // No hook at all (the default, and what clearing it restores) is fine.
    store.set_on_baseline_mutation({});
    auto again = store.create_baseline(make_baseline("after"));
    REQUIRE(again.has_value());
    deploy(store, *again);
    CHECK(fired == 2);
}

TEST_CASE("BaselineStore: the baseline-mutation hook runs with no pool lease held",
          "[pg][baseline_store][baseline_hook]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    // One connection: if the mutating thread still held its lease while the hook ran, the
    // hook's own acquire could not succeed.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());
    int leases_granted = 0;
    int fired = 0;
    store.set_on_baseline_mutation([&] {
        ++fired;
        if (auto lease = pool.try_acquire_for(std::chrono::milliseconds(200)))
            ++leases_granted;
    });
    auto created = store.create_baseline(make_baseline("leased"));
    REQUIRE(created.has_value());
    auto b = store.get_baseline(*created);
    REQUIRE(b.has_value());
    b->description = "edited";
    REQUIRE(store.update_baseline(*b).has_value());
    REQUIRE(store.delete_baseline(*created).has_value());
    CHECK(fired == 2);
    CHECK(leases_granted == 2);
}

TEST_CASE("BaselineStore: a mutation that fails inside the database does not fire the baseline-mutation hook",
          "[pg][baseline_store][baseline_hook]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());
    auto created = store.create_baseline(make_baseline("sql-error"));
    REQUIRE(created.has_value());
    const std::string id = *created;
    auto row = store.get_baseline(id);
    REQUIRE(row.has_value());

    int fired = 0;
    store.set_on_baseline_mutation([&] { ++fired; });

    // Break the table from a second connection: the generic SQL-error arm of both writers. The
    // rename back runs on EVERY exit, including a failed REQUIRE below (declared after the
    // rename it undoes, so it destructs first).
    exec_sql(db.dsn(), "ALTER TABLE baseline_store.baselines RENAME TO baselines_broken");
    bool renamed_back = false;
    const auto restore_table = [&] {
        if (!renamed_back)
            exec_sql_nothrow(db.dsn(),
                             "ALTER TABLE baseline_store.baselines_broken RENAME TO baselines");
    };
    yuzu::test::ScopeExit restore{restore_table};
    row->description = "edited";
    const auto upd = store.update_baseline(*row);
    REQUIRE_FALSE(upd.has_value());
    CHECK(upd.error().find("update failed") != std::string::npos);
    const auto del = store.delete_baseline(id);
    REQUIRE_FALSE(del.has_value());
    CHECK(del.error().find("delete failed") != std::string::npos);
    CHECK(fired == 0);  // nothing committed, nothing announced

    // And once the table is back the same calls commit and fire.
    exec_sql(db.dsn(), "ALTER TABLE baseline_store.baselines_broken RENAME TO baselines");
    renamed_back = true;
    REQUIRE(store.update_baseline(*row).has_value());
    REQUIRE(store.delete_baseline(id).has_value());
    CHECK(fired == 2);
}

TEST_CASE("BaselineStore: a mutation that cannot get a connection does not fire the baseline-mutation hook",
          "[pg][baseline_store][baseline_hook]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    // One connection, held by the test, and a short saturation fast-fail: the writers' bounded
    // acquire gives up at once (the !lease arm) instead of waiting out its full write timeout.
    PgPool pool{{.conninfo = db.dsn(), .size = 1, .saturated_fast_fail = std::chrono::milliseconds{1}}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());
    auto created = store.create_baseline(make_baseline("no-lease"));
    REQUIRE(created.has_value());
    auto row = store.get_baseline(*created);
    REQUIRE(row.has_value());

    int fired = 0;
    store.set_on_baseline_mutation([&] { ++fired; });
    {
        auto held = pool.acquire();
        REQUIRE(held);
        const auto upd = store.update_baseline(*row);
        REQUIRE_FALSE(upd.has_value());
        CHECK(upd.error().find("no database connection") != std::string::npos);
        const auto del = store.delete_baseline(*created);
        REQUIRE_FALSE(del.has_value());
        CHECK(del.error().find("no database connection") != std::string::npos);
    }
    CHECK(fired == 0);
    REQUIRE(store.delete_baseline(*created).has_value());  // the lease is back: it commits and fires
    CHECK(fired == 1);
}

TEST_CASE("BaselineStore: a create fires the baseline-mutation hook only when the baseline is created deployed",
          "[pg][baseline_store][baseline_hook]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};  // size 1: also proves no lease is held in the hook
    BaselineStore store{pool};
    REQUIRE(store.is_open());

    int fired = 0;
    std::vector<std::string> deployed_seen;
    store.set_on_baseline_mutation([&] {
        ++fired;
        const auto d = store.deployed_member_rule_ids();
        deployed_seen.push_back(d.has_value() ? std::to_string(d->size()) : std::string("degraded"));
    });

    // A draft create (what every route does) changes no deployed set: silent.
    REQUIRE(store.create_baseline(make_baseline("draft-one")).has_value());
    CHECK(fired == 0);

    // A create that is already deployed does change it: fires once, AFTER commit, so the hook
    // already reads the new deployed set, and with no lease held (the pool has one connection).
    auto dep = make_baseline("born-deployed");
    dep.lifecycle = kBaselineDeployed;
    dep.deployed_snapshot = nlohmann::json(std::vector<std::string>{"r1", "r2", "r3"}).dump();
    dep.deployed_by = "bob";
    REQUIRE(store.create_baseline(dep).has_value());
    CHECK(fired == 1);
    REQUIRE(deployed_seen.size() == 1);
    CHECK(deployed_seen[0] == "3");

    // A create that fails (name conflict, invalid lifecycle) fires nothing.
    CHECK_FALSE(store.create_baseline(dep).has_value());
    auto bad = make_baseline("bad-lifecycle");
    bad.lifecycle = "bogus";
    CHECK_FALSE(store.create_baseline(bad).has_value());
    CHECK(fired == 1);
}
