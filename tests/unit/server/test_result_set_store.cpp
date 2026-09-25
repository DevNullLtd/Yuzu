/**
 * test_result_set_store.cpp — Unit tests for the scope-walking result-set store.
 *
 * Covers: synchronous + asynchronous create, membership + lineage, alias
 * resolution, pin/unpin (+ cap), delete (pinned-rejected), quota, async
 * materialisation, touch TTL extension, and GC sweep. Migrated Postgres store
 * (ADR-0036, schema `result_set_store`). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken.
 *
 * No legacy-SQLite backfill test coverage: the dedicated migrate_from_sqlite
 * TEST_CASE suite was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment) -- no production fleet has ever run a
 * pre-Postgres build. ResultSetStore::migrate_from_sqlite() itself was
 * retired (chore/retire-migrate-from-sqlite-batch-b, #3623).
 */

#include "result_set_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own ResultSetStore against a clone of this schema.
yuzu::test::PgTestTemplate result_set_tpl{"resultset", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResultSetStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}};

CreateRequest req(const std::string& owner, const std::string& name = "",
                  std::optional<std::string> parent = std::nullopt) {
    CreateRequest r;
    r.owner_principal = owner;
    r.name = name;
    r.parent_id = std::move(parent);
    r.source_kind = std::string(source_kind::kInventoryQuery);
    r.source_payload = R"({"query":"os.platform == \"windows\""})";
    return r;
}

// Run a raw SQL statement against the test database on a second connection —
// lets a test simulate TTL expiry / form a parent_id cycle that the public API
// deliberately cannot produce.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// Scalar SELECT on a second connection — column 0, row 0, as text; "" when
// the result set is genuinely empty. Used by the gc_meta assertions below,
// where "row absent" vs. "row present with some value" is the point.
std::string query_scalar(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    if (PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

// Unwrap helpers for the four type-distinguishable-error reads (ADR-0036 /
// docs/postgres-store-playbook.md "authoritative reads must be
// type-distinguishable"): every call below hits a live, healthy Postgres, so
// a DbError here is a genuine test-infrastructure failure, not an expected
// branch — REQUIRE it away loudly and hand back the plain
// optional/bool/set the pre-widening tests were written against.
std::optional<ResultSet> get_ok(ResultSetStore& s, const std::string& id) {
    auto r = s.get(id);
    REQUIRE(r.has_value());
    return *r;
}
bool contains_ok(ResultSetStore& s, const std::string& id, const std::string& device_id) {
    auto r = s.contains(id, device_id);
    REQUIRE(r.has_value());
    return *r;
}
std::optional<std::string> resolve_alias_ok(ResultSetStore& s, const std::string& owner,
                                            const std::string& name) {
    auto r = s.resolve_alias(owner, name);
    REQUIRE(r.has_value());
    return *r;
}
std::unordered_set<std::string> member_set_owned_ok(ResultSetStore& s, const std::string& id,
                                                    const std::string& owner) {
    auto r = s.member_set_owned(id, owner);
    REQUIRE(r.has_value());
    return *r;
}

} // namespace

TEST_CASE("ResultSetStore: synchronous create, get, members", "[pg][result_set][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    std::vector<std::string> members = {"dev-a", "dev-b", "dev-c"};
    auto rs = store.create_materialized(req("alice", "win-fleet"), members);
    REQUIRE(rs.has_value());
    CHECK(rs->id.starts_with("rs_"));
    CHECK(rs->status == ResultSetStatus::Materialized);
    CHECK(rs->device_count == 3);
    CHECK(rs->name == "win-fleet");
    CHECK_FALSE(rs->pinned);

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->owner_principal == "alice");

    std::string cursor;
    auto devs = store.members(rs->id, "", 100, cursor);
    REQUIRE(devs.size() == 3);
    CHECK(cursor.empty());
    CHECK(contains_ok(store, rs->id, "dev-b"));
    CHECK_FALSE(contains_ok(store, rs->id, "dev-z"));
}

TEST_CASE("ResultSetStore: members_checked matches the plain wrapper on the healthy path, "
          "and fails closed (DbError) rather than silently truncating on a degraded read "
          "(#4306 finding 3)",
          "[pg][result_set][crud][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "win-fleet"), {"dev-a", "dev-b", "dev-c"});
    REQUIRE(rs.has_value());

    // Healthy path: members_checked() reports the exact same page as the
    // plain wrapper.
    auto checked = store.members_checked(rs->id, "", 100);
    REQUIRE(checked.has_value());
    CHECK(checked->device_ids.size() == 3);
    CHECK(checked->next_cursor.empty());

    // Same lock-timeout technique as test_approval_manager.cpp's
    // lock_timeout_ms precedent (#2786/#2456): a second raw connection holds
    // an ACCESS EXCLUSIVE table lock, and the store under test is built
    // against a short-lock_timeout_ms pool so its blocked read fails with a
    // real, deterministic SQLSTATE 55P03 rather than hanging or being
    // retried away.
    PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    ResultSetStore degraded_store{short_lock_pool};
    REQUIRE(degraded_store.is_open());

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_set_members IN ACCESS "
                            "EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto degraded = degraded_store.members_checked(rs->id, "", 100);
    REQUIRE_FALSE(degraded.has_value());
    CHECK(degraded.error() == ResultSetError::DbError);

    // The plain wrapper's fallback shape is unchanged: empty vector, cleared
    // cursor — never a partial/truncated-but-nonempty page.
    std::string next = "sentinel";
    auto plain = degraded_store.members(rs->id, "", 100, next);
    CHECK(plain.empty());
    CHECK(next.empty());

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    // And the fault clears: the same store reads correctly once the lock
    // releases.
    auto recovered = degraded_store.members_checked(rs->id, "", 100);
    REQUIRE(recovered.has_value());
    CHECK(recovered->device_ids.size() == 3);
}

TEST_CASE("ResultSetStore: lineage walks parent chain root-first", "[pg][result_set][lineage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto g = store.create_materialized(req("alice", "all"), {"a", "b", "c", "d"});
    REQUIRE(g.has_value());
    auto mid = store.create_materialized(req("alice", "windows", g->id), {"a", "b"});
    REQUIRE(mid.has_value());
    auto leaf = store.create_materialized(req("alice", "suspects", mid->id), {"a"});
    REQUIRE(leaf.has_value());

    auto chain = store.lineage(leaf->id, "alice");
    REQUIRE(chain.size() == 3);
    CHECK(chain.front().name == "all");     // root first
    CHECK(chain.back().name == "suspects"); // leaf last
    CHECK(chain.front().device_count == 4);
}

TEST_CASE("ResultSetStore: lineage_checked matches the plain wrapper on the healthy path, "
          "and fails closed (DbError) on a FIRST-hop query failure rather than returning the "
          "partial chain the pre-#4306 plain lineage() used to (#4306 finding 3) -- gov-4306-S2: "
          "renamed from a prior title that claimed 'mid-walk' coverage; a table-wide lock (the "
          "fault-injection technique below) necessarily faults every hop including the first, "
          "so old and new lineage_checked() code behave IDENTICALLY here (both return empty on "
          "a first-hop failure) and this test cannot by itself distinguish them. The actual "
          "shipped semantic shift -- a failure AFTER >=1 successful hop now discards the whole "
          "accumulated chain instead of returning it partial -- has no test coverage; a genuine "
          "2nd-hop fault would need a per-row injection (e.g. Postgres row-level security), "
          "which was attempted and dropped: the shared test DSN's role is a superuser with "
          "rolbypassrls=true, so RLS policies are unconditionally bypassed on every connection "
          "these tests can construct from it, and provisioning a dedicated non-superuser role "
          "with its own credentials/pool is materially more than a contained fix-round diff",
          "[pg][result_set][lineage][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto g = store.create_materialized(req("alice", "all"), {"a", "b", "c", "d"});
    REQUIRE(g.has_value());
    auto mid = store.create_materialized(req("alice", "windows", g->id), {"a", "b"});
    REQUIRE(mid.has_value());
    auto leaf = store.create_materialized(req("alice", "suspects", mid->id), {"a"});
    REQUIRE(leaf.has_value());

    // Healthy path: lineage_checked() reports the exact same chain as the
    // plain wrapper.
    auto checked = store.lineage_checked(leaf->id, "alice");
    REQUIRE(checked.has_value());
    REQUIRE(checked->size() == 3);
    CHECK(checked->front().name == "all");
    CHECK(checked->back().name == "suspects");

    // Same lock-timeout technique as above: lock result_sets (lineage_checked
    // walks that table on every hop, including the FIRST — the leaf row
    // itself) so the very first hop of the walk fails deterministically with
    // 55P03.
    PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    ResultSetStore degraded_store{short_lock_pool};
    REQUIRE(degraded_store.is_open());

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_sets IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto degraded = degraded_store.lineage_checked(leaf->id, "alice");
    REQUIRE_FALSE(degraded.has_value());
    CHECK(degraded.error() == ResultSetError::DbError);

    // The plain wrapper's fallback shape is unchanged in KIND (empty) at
    // THIS (first-hop) fault point specifically, since a first hop always
    // accumulates zero prior nodes either way. The documented semantic shift
    // (#4306) this general contract describes -- the pre-existing plain
    // lineage() returned whatever partial chain it had accumulated before a
    // mid-walk (2nd+ hop) failure, whereas the wrapper built on
    // lineage_checked discards it and returns EMPTY instead -- is real and
    // shipped but not distinguishable from old behavior by this particular
    // fault injection; see the TEST_CASE name for why.
    auto plain = degraded_store.lineage(leaf->id, "alice");
    CHECK(plain.empty());

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    auto recovered = degraded_store.lineage_checked(leaf->id, "alice");
    REQUIRE(recovered.has_value());
    CHECK(recovered->size() == 3);
}

TEST_CASE("ResultSetStore: alias resolution is owner-scoped", "[pg][result_set][alias]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto a = store.create_materialized(req("alice", "chrome"), {"x"});
    REQUIRE(a.has_value());
    store.create_materialized(req("bob", "chrome"), {"y"});

    auto resolved = resolve_alias_ok(store, "alice", "chrome");
    REQUIRE(resolved.has_value());
    CHECK(*resolved == a->id);
    CHECK_FALSE(resolve_alias_ok(store, "alice", "nonexistent").has_value());
    CHECK_FALSE(resolve_alias_ok(store, "carol", "chrome").has_value());
}

TEST_CASE("ResultSetStore: pin/unpin and pinned-delete rejection", "[pg][result_set][pin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "pinme"), {"a"});
    REQUIRE(rs.has_value());

    auto pinned = store.pin(rs->id);
    REQUIRE(pinned.has_value());
    CHECK(pinned->pinned);
    CHECK(pinned->ttl_at == INT64_MAX);

    // Delete of a pinned set must be rejected.
    auto del = store.delete_set(rs->id);
    REQUIRE_FALSE(del.has_value());
    CHECK(del.error() == ResultSetError::Pinned);

    auto unpinned = store.unpin(rs->id);
    REQUIRE(unpinned.has_value());
    CHECK_FALSE(unpinned->pinned);
    CHECK(unpinned->ttl_at < INT64_MAX);

    // Now deletable.
    CHECK(store.delete_set(rs->id).has_value());
    CHECK_FALSE(get_ok(store, rs->id).has_value());
}

TEST_CASE("ResultSetStore: async create -> materialize", "[pg][result_set][async]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "tar-suspects");
    r.source_kind = std::string(source_kind::kTarQuery);
    r.source_payload = R"({"sql":"SELECT 1"})";
    auto rs = store.create_pending(r, "exec-123");
    REQUIRE(rs.has_value());
    CHECK(rs->status == ResultSetStatus::Pending);
    CHECK(rs->device_count == 0);

    auto pending = store.list_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].source_execution_id == "exec-123");
    CHECK(pending[0].source_kind == source_kind::kTarQuery);

    auto m = store.materialize(rs->id, {"dev-1", "dev-2"});
    REQUIRE(m.has_value());

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Materialized);
    CHECK(got->device_count == 2);
    CHECK(store.list_pending().empty());
    CHECK(contains_ok(store, rs->id, "dev-1"));
}

// UP-6 (2026-07-26 hardening round, S2): materialize() must dedup + drop
// empty-string device_ids exactly like insert_row_impl — pre-fix,
// device_count reflected the raw request size (over-reporting on
// duplicates) rather than the rows actually stored.
TEST_CASE("ResultSetStore: materialize dedups members and drops empty ids",
          "[pg][result_set][async][dedup]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "dedup-check");
    r.source_kind = std::string(source_kind::kTarQuery);
    r.source_payload = R"({"sql":"SELECT 1"})";
    auto rs = store.create_pending(r, "exec-dedup");
    REQUIRE(rs.has_value());

    auto m = store.materialize(rs->id, {"a", "a", ""});
    REQUIRE(m.has_value());

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->device_count == 1); // NOT 3 — deduped "a" and dropped ""
    std::string cursor;
    auto members = store.members(rs->id, "", 100, cursor);
    REQUIRE(members.size() == 1);
    CHECK(members[0] == "a");
}

TEST_CASE("ResultSetStore: touch extends TTL", "[pg][result_set][ttl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice"), {"a"});
    REQUIRE(rs.has_value());
    int64_t orig_ttl = rs->ttl_at;

    store.touch(rs->id);
    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->ttl_at >= orig_ttl);
    CHECK(got->last_used_at >= rs->last_used_at);
}

TEST_CASE("ResultSetStore: GC sweep removes expired unpinned sets", "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto live = store.create_materialized(req("alice", "live"), {"a"});
    auto pinned = store.create_materialized(req("alice", "kept"), {"b"});
    REQUIRE(live.has_value());
    REQUIRE(pinned.has_value());
    REQUIRE(store.pin(pinned->id).has_value());

    // No expired rows yet (default TTL is 1h in the future).
    CHECK(store.gc_sweep() == 0);
    CHECK(get_ok(store, live->id).has_value());
    CHECK(get_ok(store, pinned->id).has_value());
}

TEST_CASE("ResultSetStore: per-owner quota enforced", "[pg][result_set][quota]") {
    // The hard cap is 10k which is impractical to hit in a unit test directly,
    // so this asserts the count helper that drives the cap and a representative
    // create succeeds; the cap branch is covered by the REST-layer test.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    for (int i = 0; i < 5; ++i)
        REQUIRE(store.create_materialized(req("alice"), {"a"}).has_value());
    CHECK(store.count_for_owner("alice") == 5);
    CHECK(store.count_for_owner("bob") == 0);
}

TEST_CASE("ResultSetStore: count_for_owner_checked fails closed (DbError) rather than "
          "reading a degraded backend as a genuinely-empty owner (#4306 finding 1)",
          "[pg][result_set][quota][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    for (int i = 0; i < 5; ++i)
        REQUIRE(store.create_materialized(req("alice"), {"a"}).has_value());

    auto checked = store.count_for_owner_checked("alice");
    REQUIRE(checked.has_value());
    CHECK(*checked == 5);

    PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    ResultSetStore degraded_store{short_lock_pool};
    REQUIRE(degraded_store.is_open());

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_sets IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto degraded = degraded_store.count_for_owner_checked("alice");
    REQUIRE_FALSE(degraded.has_value());
    CHECK(degraded.error() == ResultSetError::DbError);

    // The plain wrapper's fallback shape is unchanged: 0, indistinguishable
    // in KIND from a genuinely-empty owner by design (deny-or-benign wrapper)
    // — this is exactly why the two async-producer pre-dispatch call sites
    // moved to the checked method instead of relying on this fallback.
    CHECK(degraded_store.count_for_owner("alice") == 0);

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    auto recovered = degraded_store.count_for_owner_checked("alice");
    REQUIRE(recovered.has_value());
    CHECK(*recovered == 5);
}

TEST_CASE("ResultSetStore: count_for_owner_checked's predicate matches insert_row_impl's "
          "authoritative in-txn recheck exactly -- an expired-but-unswept, unpinned row does "
          "NOT count against the quota (#4306 fold-in A, Gate 4 UP-6 parity)",
          "[pg][result_set][quota][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto live = store.create_materialized(req("alice", "live"), {"a"});
    REQUIRE(live.has_value());
    auto stale = store.create_materialized(req("alice", "stale"), {"b"});
    REQUIRE(stale.has_value());
    auto pinned = store.create_materialized(req("alice", "pinned-but-expired"), {"c"});
    REQUIRE(pinned.has_value());
    REQUIRE(store.pin(pinned->id).has_value());

    // Age `stale` past its TTL (unpinned -- must NOT count) and `pinned`'s
    // ttl_at too, even though it's pinned (pinned rows count regardless of
    // ttl_at, same as the authoritative check's `pinned OR ...` predicate).
    // Both created_at and ttl_at move together (same idiom as this file's
    // other TTL-expiry tests) -- the table's own CHECK (ttl_at >= created_at)
    // rejects a ttl_at-only update against a real, recent created_at.
    exec_sql(db.dsn(),
             "UPDATE result_set_store.result_sets SET created_at = 1, ttl_at = 2 WHERE id IN ('" +
                 stale->id + "', '" + pinned->id + "')");

    // Before this fix, the pre-check counted all 3 (no ttl/pinned filter);
    // the authoritative in-txn check in insert_row_impl would only ever have
    // counted 2 (live + pinned) -- a discrepancy that could reject a
    // dispatch the authoritative check would have allowed. Now they agree.
    auto checked = store.count_for_owner_checked("alice");
    REQUIRE(checked.has_value());
    CHECK(*checked == 2); // live + pinned-but-expired; stale excluded
}

TEST_CASE("ResultSetStore: list_by_owner_checked matches the plain wrapper on the healthy "
          "path, and fails closed (DbError) rather than reading a degraded backend as an "
          "empty list (#4306 finding 3 / #4307 finding 2)",
          "[pg][result_set][crud][4306]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    REQUIRE(store.create_materialized(req("alice", "a1"), {"a"}).has_value());
    REQUIRE(store.create_materialized(req("alice", "a2"), {"b"}).has_value());

    std::string next;
    auto checked = store.list_by_owner_checked("alice", "", 50);
    REQUIRE(checked.has_value());
    CHECK(checked->sets.size() == 2);
    CHECK(checked->next_cursor.empty());

    PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    ResultSetStore degraded_store{short_lock_pool};
    REQUIRE(degraded_store.is_open());

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE result_set_store.result_sets IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto degraded = degraded_store.list_by_owner_checked("alice", "", 50);
    REQUIRE_FALSE(degraded.has_value());
    CHECK(degraded.error() == ResultSetError::DbError);

    std::string plain_next = "sentinel";
    auto plain = degraded_store.list_by_owner("alice", "", 50, plain_next);
    CHECK(plain.empty());
    CHECK(plain_next.empty());

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    auto recovered = degraded_store.list_by_owner_checked("alice", "", 50);
    REQUIRE(recovered.has_value());
    CHECK(recovered->sets.size() == 2);
}

TEST_CASE("ResultSetStore: GC sweep deletes expired unpinned rows and returns the count",
          "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto expired = store.create_materialized(req("alice", "stale"), {"a", "b"});
    auto pinned = store.create_materialized(req("alice", "kept"), {"c"});
    auto live = store.create_materialized(req("alice", "fresh"), {"d"});
    REQUIRE(expired.has_value());
    REQUIRE(pinned.has_value());
    REQUIRE(live.has_value());
    REQUIRE(store.pin(pinned->id).has_value());

    // Force the unpinned row's TTL into the past; pinned keeps INT64_MAX, live
    // stays an hour out. Only `expired` should be swept (exercises the actual
    // DELETE branch the prior GC test never hit — review finding O/D).
    // created_at must stay <= ttl_at (schema CHECK), so age the row wholesale.
    exec_sql(db.dsn(), "UPDATE result_set_store.result_sets SET created_at = 1, ttl_at = 2 WHERE "
                       "id = '" +
                          expired->id + "';");

    int swept = store.gc_sweep();
    CHECK(swept == 1);
    CHECK_FALSE(get_ok(store, expired->id).has_value());
    CHECK(get_ok(store, pinned->id).has_value());
    CHECK(get_ok(store, live->id).has_value());
    CHECK_FALSE(contains_ok(store, expired->id, "a")); // members cascade-deleted
}

TEST_CASE("ResultSetStore: per-set member cap is enforced", "[pg][result_set][cap]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    std::vector<std::string> members;
    members.reserve(ResultSetStore::kMaxMembersPerSet + 1);
    for (int i = 0; i <= ResultSetStore::kMaxMembersPerSet; ++i)
        members.push_back("dev-" + std::to_string(i));

    auto rs = store.create_materialized(req("alice", "toobig"), members);
    REQUIRE_FALSE(rs.has_value());
    CHECK(rs.error() == ResultSetError::TooManyMembers);
}

TEST_CASE("ResultSetStore: device_count reflects distinct members", "[pg][result_set][dedup]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "dups"), {"a", "a", "b", "b", "b", "c"});
    REQUIRE(rs.has_value());
    CHECK(rs->device_count == 3); // ON CONFLICT DO NOTHING dedups; the count must agree (L)
    std::string cursor;
    CHECK(store.members(rs->id, "", 100, cursor).size() == 3);
}

TEST_CASE("ResultSetStore: member_set_owned is owner-scoped", "[pg][result_set][owner]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "set"), {"a", "b", "c"});
    REQUIRE(rs.has_value());

    auto owned = member_set_owned_ok(store, rs->id, "alice");
    CHECK(owned.size() == 3);
    CHECK(owned.contains("b"));
    // A non-owner sees an empty membership — the authorization gate for B1.
    CHECK(member_set_owned_ok(store, rs->id, "bob").empty());
}

TEST_CASE("ResultSetStore: lineage stops at a cross-owner ancestor", "[pg][result_set][lineage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto root = store.create_materialized(req("alice", "alice-root"), {"a"});
    REQUIRE(root.has_value());
    // Bob parents his set onto alice's row (the store does not owner-check the
    // parent edge — the REST layer does). lineage(bob's leaf, "bob") must NOT
    // leak alice's node (review finding B2).
    auto leaf = store.create_materialized(req("bob", "bob-leaf", root->id), {"b"});
    REQUIRE(leaf.has_value());

    auto chain = store.lineage(leaf->id, "bob");
    REQUIRE(chain.size() == 1);
    CHECK(chain.front().name == "bob-leaf");

    auto achain = store.lineage(root->id, "alice"); // alice still sees her own
    REQUIRE(achain.size() == 1);
    CHECK(achain.front().name == "alice-root");
}

TEST_CASE("ResultSetStore: lineage terminates on a parent_id cycle", "[pg][result_set][lineage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto a = store.create_materialized(req("alice", "A"), {"x"});
    auto b = store.create_materialized(req("alice", "B", a->id), {"y"});
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    // Close the loop A->B->A with a direct write the public API can't make (J).
    exec_sql(db.dsn(), "UPDATE result_set_store.result_sets SET parent_id = '" + b->id +
                          "' WHERE id = '" + a->id + "';");

    auto chain = store.lineage(a->id, "alice"); // must not spin forever
    CHECK(chain.size() <= static_cast<size_t>(ResultSetStore::kLineageDepthCap));
    CHECK(chain.size() >= 1);
}

TEST_CASE("ResultSetStore: members paginate past the page size", "[pg][result_set][pagination]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    std::vector<std::string> members;
    members.reserve(6000);
    for (int i = 0; i < 6000; ++i)
        members.push_back("dev-" + std::to_string(100000 + i)); // fixed width → sortable
    auto rs = store.create_materialized(req("alice", "big"), members);
    REQUIRE(rs.has_value());
    CHECK(rs->device_count == 6000);

    // Walk with separate in/out cursors (the correct idiom — review B3) and
    // confirm the loop terminates and returns every distinct member.
    std::unordered_set<std::string> seen;
    std::string cur;
    int iterations = 0;
    while (true) {
        std::string next;
        auto page = store.members(rs->id, cur, 5000, next);
        seen.insert(page.begin(), page.end());
        if (next.empty())
            break;
        cur = next;
        REQUIRE(++iterations < 10); // guard: must not loop forever
    }
    CHECK(seen.size() == 6000);
}

// gov fjarvis B1 (offline_endpoint_store precedent): a reachable database whose
// schema migration FAILS must leave the store !is_open() — server.cpp wires
// that to startup_failed_ (fail closed, not serve-degraded). Force the failure
// by pre-seeding a conflicting table with no schema_meta row: the migration
// runner's schema-drift guard refuses (version 0 but tables exist).
TEST_CASE("ResultSetStore reports !is_open on a migration failure", "[pg][result_set]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA result_set_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE result_set_store.result_sets (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResultSetStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ = true
}

// S3b (2026-07-26 hardening round): with the backing table dropped, the
// four type-distinguishable reads must each report DbError distinctly from
// "not found"/"not a member" — REQUIRE_FALSE(has_value()) +
// .error() == DbError, not a truthy-but-empty result.
TEST_CASE("ResultSetStore: get/contains/resolve_alias report DbError on a genuine "
          "store failure",
          "[pg][result_set][dberror]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    auto rs = store.create_materialized(req("alice", "will-degrade"), {"dev-a"});
    REQUIRE(rs.has_value());

    exec_sql(db.dsn(), "DROP TABLE result_set_store.result_set_members CASCADE");
    exec_sql(db.dsn(), "DROP TABLE result_set_store.result_sets CASCADE");

    SECTION("get reports DbError, not an empty optional") {
        auto r = store.get(rs->id);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ResultSetError::DbError);
    }
    SECTION("contains reports DbError, not false") {
        auto r = store.contains(rs->id, "dev-a");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ResultSetError::DbError);
    }
    SECTION("resolve_alias reports DbError, not nullopt") {
        auto r = store.resolve_alias("alice", "will-degrade");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ResultSetError::DbError);
    }
    SECTION("member_set_owned reports DbError, not an empty set") {
        auto r = store.member_set_owned(rs->id, "alice");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ResultSetError::DbError);
    }
}

// gc_sweep cap (2026-07-29 hardening round): bulk-insert kGcSweepCapPerPass+1
// expired, unpinned rows directly via SQL — looping create_materialized 5001
// times would make this test the slow part of the whole suite. A `live`
// (unexpired, unpinned) row is seeded alongside so datable (5002) stays
// strictly greater than expiring (5001) and part 1's would_wipe classifier
// (expiring >= datable) does NOT trip; the decline-once/would_wipe shape is
// covered separately below. With would_wipe false and no prior last_pass_now
// row in a fresh template clone (so big_step can't trip either), this pass
// classifies clean (Anomaly::None) and the unconditional per-pass cap (part
// 5) is the only thing bounding the delete — exactly what this test pins.
TEST_CASE("ResultSetStore: GC sweep caps a large expired batch at kGcSweepCapPerPass",
          "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    auto pinned = store.create_materialized(req("alice", "kept-cap"), {"z"});
    REQUIRE(pinned.has_value());
    REQUIRE(store.pin(pinned->id).has_value());
    auto live = store.create_materialized(req("alice", "fresh-cap"), {"y"});
    REQUIRE(live.has_value());

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        // kGcSweepCapPerPass (5000) + 1 rows, well in the past; created_at <=
        // ttl_at satisfies the schema CHECK.
        PgResult r{PQexec(
            conn.get(),
            "INSERT INTO result_set_store.result_sets "
            "(id, owner_principal, created_at, ttl_at, last_used_at, source_kind, "
            "source_payload) "
            "SELECT 'rs_capbulk' || lpad(g::text, 6, '0'), 'alice', 1, 2, 1, 'manual_curate', "
            "'{}' "
            "FROM generate_series(1, 5001) AS g")};
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.ok());
    }

    CHECK(store.gc_sweep() == 5000); // capped exactly at kGcSweepCapPerPass
    CHECK(store.gc_sweep() == 1);    // second pass drains the single remainder
    CHECK(get_ok(store, pinned->id).has_value());
    CHECK(get_ok(store, live->id).has_value());
}

// gc_sweep would_wipe decline-once (2026-07-29 hardening round): when EVERY
// datable (unpinned) row is expired, part 1's would_wipe classifier trips —
// the pass reports the anomaly, records it in gc_meta, and declines to
// delete anything. An identical next pass (same fact set) is a suppressed
// repeat: the report is skipped, but the drain (capped) proceeds — a
// legitimately all-expired table still ages out, just one pass later.
TEST_CASE("ResultSetStore: GC sweep declines once on an all-expired (would_wipe) table",
          "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    auto a = store.create_materialized(req("alice", "wipe-a"), {"a"});
    auto b = store.create_materialized(req("alice", "wipe-b"), {"b"});
    auto c = store.create_materialized(req("alice", "wipe-c"), {"c"});
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(c.has_value());
    // Every unpinned row in this store is aged into the past — no live row
    // survives, so expiring == datable (would_wipe: expiring >= datable).
    exec_sql(db.dsn(),
            "UPDATE result_set_store.result_sets SET created_at = 1, ttl_at = 2 WHERE id IN ('" +
                a->id + "', '" + b->id + "', '" + c->id + "');");

    CHECK(store.gc_sweep() == 0); // declined: would_wipe, nothing deleted
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM result_set_store.gc_meta WHERE "
                                 "key = 'last_anomaly_facts'") == "1");
    CHECK(get_ok(store, a->id).has_value()); // still present — the decline held

    CHECK(store.gc_sweep() == 3); // suppressed repeat: same facts, drains (capped) anyway
    // The anomaly-dedup row is NOT cleared by a suppressed-repeat drain — it
    // is cleared only by a genuinely clean pass (anomaly == None), asserted
    // next. The table is now empty, so a naive re-check of this key would
    // pass for the wrong reason; assert against a THIRD, fresh, unexpired
    // row instead so the "still there after the drain" claim is meaningful.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM result_set_store.gc_meta WHERE "
                                 "key = 'last_anomaly_facts'") == "1");
    CHECK_FALSE(get_ok(store, a->id).has_value()); // drained

    auto fresh = store.create_materialized(req("alice", "wipe-fresh"), {"d"});
    REQUIRE(fresh.has_value());
    CHECK(store.gc_sweep() == 0); // clean pass: nothing expired
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM result_set_store.gc_meta WHERE "
                                 "key = 'last_anomaly_facts'") == "0"); // consumed/cleared
}

// gc_sweep clock anomaly / prev_unusable (2026-07-29 hardening round): a
// persisted last_pass_now reading from AHEAD of the current wall clock is
// sanitised to unusable BEFORE any arithmetic (part 3) and classifies
// BadState — checked first, ahead of Step/Wipe (docs: audit_retention_rules.
// hpp precedence). CONTRACT SURPRISE vs. a naive "same facts -> suppressed
// repeat" expectation: gc_sweep stamps a FRESH, honest last_pass_now on
// EVERY pass (including a declining one) before it even evaluates the
// anomaly, so the poisoned reading is self-healed by the very first call —
// pass 2 reads pass 1's (now-valid) stamp, prev_unusable comes back false,
// and the second pass is a genuinely CLEAN pass (Anomaly::None), not a
// suppressed repeat of BadState. It still drains (and clears the dedup row,
// since a clean pass always does), just via a different path than the
// would_wipe test above.
TEST_CASE("ResultSetStore: GC sweep declines once on a clock reading ahead of now",
          "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    const auto wall_now = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    exec_sql(db.dsn(), "INSERT INTO result_set_store.gc_meta (key, value) VALUES "
                       "('last_pass_now', '" +
                          std::to_string(wall_now + 999'999) +
                          "') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;");

    auto expired_a = store.create_materialized(req("alice", "clock-a"), {"a"});
    auto expired_b = store.create_materialized(req("alice", "clock-b"), {"b"});
    auto live = store.create_materialized(req("alice", "clock-live"), {"c"}); // avoids would_wipe
    REQUIRE(expired_a.has_value());
    REQUIRE(expired_b.has_value());
    REQUIRE(live.has_value());
    exec_sql(db.dsn(), "UPDATE result_set_store.result_sets SET created_at = 1, ttl_at = 2 WHERE "
                       "id IN ('" +
                          expired_a->id + "', '" + expired_b->id + "');");

    CHECK(store.gc_sweep() == 0); // declined: prev_unusable (BadState)
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM result_set_store.gc_meta WHERE "
                                 "key = 'last_anomaly_facts'") == "1");

    // Self-healed: the stamp gc_sweep() just wrote is an honest reading, so
    // this pass is clean, drains both expired rows, and clears the dedup row.
    CHECK(store.gc_sweep() == 2);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM result_set_store.gc_meta WHERE "
                                 "key = 'last_anomaly_facts'") == "0");
    CHECK_FALSE(get_ok(store, expired_a->id).has_value());
    CHECK_FALSE(get_ok(store, expired_b->id).has_value());
    CHECK(get_ok(store, live->id).has_value());
}

// gc_sweep advisory-lock skip (2026-07-29 hardening round): a sibling
// replica already sweeping holds the fleet-wide try-advisory-xact-lock, so
// this pass must skip quietly — return 0 and never even reach the meta
// read/stamp (which run only after the try-lock succeeds), never mind the
// delete.
TEST_CASE("ResultSetStore: GC sweep skips quietly when a sibling holds the advisory lock",
          "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM result_set_store.gc_meta WHERE "
                                 "key = 'last_pass_now'") == "0");

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        PgResult begin{PQexec(locker.get(), "BEGIN")};
        INFO(PQresultErrorMessage(begin.get()));
        REQUIRE(begin.ok());
        PgResult lock{PQexec(
            locker.get(),
            "SELECT pg_advisory_xact_lock(hashtextextended('result_set_store:gc_sweep', 0))")};
        INFO(PQresultErrorMessage(lock.get()));
        REQUIRE(lock.ok());
    }

    CHECK(store.gc_sweep() == 0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM result_set_store.gc_meta WHERE "
                                 "key = 'last_pass_now'") == "0"); // never reached the stamp

    PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    INFO(PQresultErrorMessage(rollback.get()));
    REQUIRE(rollback.ok());
}

// PinLimit (2026-07-29 hardening round): kMaxPinsPerOwner
// (result_set_store.hpp) caps concurrent pins per owner at 50 — the 51st pin
// for one owner must be rejected, and a second, independent owner must be
// unaffected (the cap is per-owner, not global).
TEST_CASE("ResultSetStore: pin enforces kMaxPinsPerOwner, per owner", "[pg][result_set][pin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    std::vector<std::string> ids;
    ids.reserve(static_cast<size_t>(ResultSetStore::kMaxPinsPerOwner) + 1);
    for (int i = 0; i <= ResultSetStore::kMaxPinsPerOwner; ++i) {
        auto rs = store.create_materialized(req("alice"), {"dev-" + std::to_string(i)});
        REQUIRE(rs.has_value());
        ids.push_back(rs->id);
    }
    for (int i = 0; i < ResultSetStore::kMaxPinsPerOwner; ++i)
        REQUIRE(store.pin(ids[static_cast<size_t>(i)]).has_value());

    auto over = store.pin(ids[static_cast<size_t>(ResultSetStore::kMaxPinsPerOwner)]);
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error() == ResultSetError::PinLimit);

    // A different owner's cap is independent — not exhausted by alice's pins.
    auto bobs = store.create_materialized(req("bob"), {"z"});
    REQUIRE(bobs.has_value());
    auto bob_pin = store.pin(bobs->id);
    REQUIRE(bob_pin.has_value());
    CHECK(bob_pin->pinned);
}

// json-dump-depth-guard fix (#2437-class): mark_failed's whole job is to
// merge a failure reason into source_payload and write it back, and
// nlohmann::json::dump() is unboundedly recursive. It has no HTTP
// request/response of its own to answer with a 400 (today it has no
// production caller at all - a store method ahead of a future caller, not a
// currently-wired background thread, per governance Gate 4/6), so it cannot
// simply reject: it must still transition the row to `failed` while never
// re-dumping a payload that could crash the process.
TEST_CASE("ResultSetStore: mark_failed merges a failure reason into a healthy "
          "pending row",
          "[pg][result_set][mark_failed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "healthy-pending");
    r.source_kind = std::string(source_kind::kTarQuery);
    r.source_payload = R"({"sql":"SELECT 1"})";
    auto rs = store.create_pending(r, "exec-ok");
    REQUIRE(rs.has_value());

    store.mark_failed(rs->id, "no agents reached");

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Failed);
    auto payload = nlohmann::json::parse(got->source_payload, nullptr, false);
    REQUIRE_FALSE(payload.is_discarded());
    REQUIRE(payload.is_object());
    CHECK(payload["failure"] == "no agents reached");
    // The original payload is PRESERVED (merged into), not discarded, when it
    // is safely shallow: only a nesting-limit violation triggers discard.
    CHECK(payload["sql"] == "SELECT 1");
}

TEST_CASE("ResultSetStore: mark_failed heals a source_payload nested past the "
          "depth limit instead of re-dumping it",
          "[pg][result_set][mark_failed][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "poisoned-pending");
    r.source_kind = std::string(source_kind::kTarQuery);
    // A raw string, never materialised as a live nlohmann::json object at
    // this depth. kMcpMaxJsonDepth is 32; 40 is comfortably past it and still
    // trivially safe to construct/dump directly in this test process,
    // orders of magnitude short of the ~100,000-level depth that actually
    // SIGSEGVs the real dump() call this guard exists to prevent.
    r.source_payload =
        std::string(R"({"sql":"SELECT 1","junk":)") + std::string(40, '[') + std::string(40, ']') + "}";
    auto rs = store.create_pending(r, "exec-poisoned");
    REQUIRE(rs.has_value());

    // This call must not crash (obviously, since we get to make the
    // assertions below) AND must not leave the poisoned tree in place.
    store.mark_failed(rs->id, "dispatch error");

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Failed);
    // Healed: the row is now safely shallow, not the original poisoned tree.
    auto payload = nlohmann::json::parse(got->source_payload, nullptr, false);
    REQUIRE_FALSE(payload.is_discarded());
    REQUIRE(payload.is_object());
    CHECK(payload["failure"] == "dispatch error");
    CHECK(payload.contains("note"));
    CHECK_FALSE(payload.contains("sql"));
    CHECK_FALSE(payload.contains("junk"));
}

// #4493: mark_failed's SELECT/UPDATE are both gated on status = 'pending' by
// design (heal_poisoned_payload below is the dedicated path for everything
// else) -- this pins that scope down so it can't silently widen while other
// work touches this file.
TEST_CASE("ResultSetStore: mark_failed is a no-op on a materialized row",
          "[pg][result_set][mark_failed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "already-materialized"), {"dev-a"});
    REQUIRE(rs.has_value());

    store.mark_failed(rs->id, "should not apply");

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Materialized);
    auto payload = nlohmann::json::parse(got->source_payload, nullptr, false);
    REQUIRE_FALSE(payload.is_discarded());
    CHECK_FALSE(payload.contains("failure"));
}

// #4493: a Materialized row has NO path through mark_failed, so a poisoned
// source_payload on one was stuck forever (issue #4493). heal_poisoned_payload
// is the dedicated, status-agnostic fix: it discards the poisoned blob the
// same way mark_failed does for a pending row, but -- unlike mark_failed --
// never rewrites status, since the row's members are real and still
// scope-walkable regardless of what its provenance blob says.
TEST_CASE("ResultSetStore: heal_poisoned_payload heals a materialized row's "
          "poisoned source_payload without touching status or members",
          "[pg][result_set][heal_poisoned_payload][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "poisoned-materialized");
    r.source_kind = std::string(source_kind::kTarQuery);
    // Same idiom as the poisoned-pending test above: 40 levels, comfortably
    // past kMcpMaxJsonDepth (32) and orders of magnitude short of the real
    // attack depth, safe to construct/dump directly in this test process.
    r.source_payload = std::string(R"({"sql":"SELECT 1","junk":)") + std::string(40, '[') +
                        std::string(40, ']') + "}";
    auto rs = store.create_materialized(r, {"dev-a", "dev-b"});
    REQUIRE(rs.has_value());
    REQUIRE(rs->status == ResultSetStatus::Materialized);

    // Must not crash, and must report that it actually healed something.
    CHECK(store.heal_poisoned_payload(rs->id));

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    // Status is UNCHANGED -- this is the whole point of the dedicated path.
    CHECK(got->status == ResultSetStatus::Materialized);
    CHECK(got->device_count == 2);
    auto payload = nlohmann::json::parse(got->source_payload, nullptr, false);
    REQUIRE_FALSE(payload.is_discarded());
    REQUIRE(payload.is_object());
    CHECK(payload.contains("note"));
    CHECK_FALSE(payload.contains("failure"));
    CHECK_FALSE(payload.contains("sql"));
    CHECK_FALSE(payload.contains("junk"));

    // The row's real members are untouched and still scope-walkable --
    // healing the provenance blob must never touch result_set_members.
    auto members = member_set_owned_ok(store, rs->id, "alice");
    CHECK(members == std::unordered_set<std::string>{"dev-a", "dev-b"});
}

TEST_CASE("ResultSetStore: heal_poisoned_payload is a no-op on a healthy payload",
          "[pg][result_set][heal_poisoned_payload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "healthy-materialized");
    r.source_kind = std::string(source_kind::kTarQuery);
    r.source_payload = R"({"sql":"SELECT 1"})";
    auto rs = store.create_materialized(r, {"dev-a"});
    REQUIRE(rs.has_value());

    CHECK_FALSE(store.heal_poisoned_payload(rs->id));

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Materialized);
    // Byte-identical -- a no-op never rewrites a healthy row's payload.
    CHECK(got->source_payload == r.source_payload);
}

// Acceptance criteria "for symmetry": a Failed row can be poisoned by the
// same class of path (pre-guard write, direct DB manipulation) and had no
// heal path either, since mark_failed's own predicate never matches a row
// that is already 'failed'.
TEST_CASE("ResultSetStore: heal_poisoned_payload also heals an already-failed row",
          "[pg][result_set][heal_poisoned_payload][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "poisoned-failed");
    r.source_kind = std::string(source_kind::kTarQuery);
    r.source_payload = R"({"sql":"SELECT 1"})";
    auto rs = store.create_pending(r, "exec-poisoned-failed");
    REQUIRE(rs.has_value());

    const std::string poisoned = std::string(R"({"failure":"no agents reached","junk":)") +
                                  std::string(40, '[') + std::string(40, ']') + "}";
    exec_sql(db.dsn(), "UPDATE result_set_store.result_sets SET status = 'failed', "
                        "source_payload = '" +
                            poisoned + "' WHERE id = '" + rs->id + "'");

    CHECK(store.heal_poisoned_payload(rs->id));

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Failed);
    auto payload = nlohmann::json::parse(got->source_payload, nullptr, false);
    REQUIRE_FALSE(payload.is_discarded());
    CHECK(payload.contains("note"));
    CHECK_FALSE(payload.contains("failure"));
    CHECK_FALSE(payload.contains("junk"));
}

// #4540 (BLOCKING finding 2): heal_poisoned_payload SELECTs the row, then
// UPDATEs it -- if a concurrent delete_set / GC sweep removes the row in
// between (both are independent connection leases with no shared lock), the
// UPDATE must affect zero rows and the method must report that as a failure,
// never as the success it used to report unconditionally once
// PGRES_COMMAND_OK was seen. Simulated deterministically with a BEFORE
// UPDATE trigger that deletes the row instead of letting the update apply --
// installed only after the row is safely seeded, so from heal's own SELECT
// the row looks present and poisoned, and by the time its UPDATE statement
// runs the row is already gone, the same window a real concurrent delete
// opens.
TEST_CASE("ResultSetStore: heal_poisoned_payload reports failure (not success) "
          "when the row is deleted out from under its own UPDATE",
          "[pg][result_set][heal_poisoned_payload][security][heal_race_4540]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "vanishes-mid-heal");
    r.source_kind = std::string(source_kind::kTarQuery);
    r.source_payload = std::string(R"({"sql":"SELECT 1","junk":)") + std::string(40, '[') +
                        std::string(40, ']') + "}";
    auto rs = store.create_materialized(r, {"dev-a"});
    REQUIRE(rs.has_value());

    exec_sql(db.dsn(),
             "CREATE OR REPLACE FUNCTION test_4540_vanish_mid_heal() RETURNS trigger AS $$ "
             "BEGIN DELETE FROM result_set_store.result_sets WHERE id = OLD.id; RETURN NULL; "
             "END; $$ LANGUAGE plpgsql");
    exec_sql(db.dsn(), "CREATE TRIGGER test_4540_vanish_mid_heal BEFORE UPDATE ON "
                        "result_set_store.result_sets FOR EACH ROW EXECUTE FUNCTION "
                        "test_4540_vanish_mid_heal()");

    CHECK_FALSE(store.heal_poisoned_payload(rs->id));

    exec_sql(db.dsn(), "DROP TRIGGER test_4540_vanish_mid_heal ON result_set_store.result_sets");
    exec_sql(db.dsn(), "DROP FUNCTION test_4540_vanish_mid_heal()");

    // The trigger's own DELETE really ran -- the row is genuinely gone, not
    // merely reporting a mismatched status while still present.
    CHECK_FALSE(get_ok(store, rs->id).has_value());
}
