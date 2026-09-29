/**
 * test_quarantine_store.cpp — `QuarantineStore` (Guardian device-quarantine
 * bookkeeping, Guardian design §11.7). Migrated Postgres store
 * (ADR-0006/0009, schema `quarantine_store`).
 *
 * Covers:
 *  - quarantine_device: success, empty agent_id rejected, ON CONFLICT
 *    (agent_id) WHERE status='active' verified race-safe against a live
 *    Postgres instance (docs/postgres-store-playbook.md's explicit warning
 *    that this syntax is easy to get subtly wrong by reasoning alone).
 *  - release_device: success (single guarded UPDATE), not-quarantined.
 *  - get_status: found, genuinely-absent (nullopt value, not an error), and
 *    empty agent_id (precondition miss, not a store failure).
 *  - list_quarantined / get_history: multiple records, newest-first
 *    ordering, history survives release + re-quarantine cycles.
 *  - fail-closed construction (migration-drift case).
 *
 * Migrated Postgres store (ADR-0047, authoritative/fail-hard per ADR-0012
 * §1). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set
 * but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases
 * use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the fail-closed construction
 * case uses plain YUZU_REQUIRE_PG_DB, per the plain-migration-test carve-out
 * documented on that macro.
 *
 * No legacy-SQLite backfill test coverage: `QuarantineStore::migrate_from_sqlite()` itself was
 * retired (chore/retire-migrate-from-sqlite-batch-a, #3623, ADR-0047 Update, 2026-09-03) -- no
 * production fleet has ever run a pre-Postgres build, so the mandatory fingerprint-verified
 * backfill never had real legacy data to protect. `server.cpp` now runs
 * `legacy_sqlite_probe::warn_if_legacy_rows` over `quarantine_records` instead.
 */

#include "quarantine_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <string>
#include <vector>

using yuzu::server::QuarantineRecord;
using yuzu::server::QuarantineStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate quarantine_tpl{"quarantinestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    QuarantineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("quarantine_store template: store failed to migrate");
}};

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("QuarantineStore: construction fails closed on migration drift", "[pg][quarantine]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    // Pre-seed: create the quarantine_store schema + a conflicting table, but
    // no public.schema_meta row — the drift guard refuses (version 0 but
    // tables exist).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA quarantine_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE quarantine_store.quarantine_records (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    QuarantineStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ = true
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

TEST_CASE("QuarantineStore: quarantine and release device", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto result =
        store.quarantine_device("agent-001", "admin", "Suspicious activity", "10.0.0.1,10.0.0.2");
    REQUIRE(result.has_value());

    auto status = store.get_status("agent-001");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->status == "active");
    CHECK((*status)->quarantined_by == "admin");
    CHECK((*status)->reason == "Suspicious activity");
    CHECK((*status)->whitelist == "10.0.0.1,10.0.0.2");
    CHECK((*status)->quarantined_at > 0);

    auto release = store.release_device("agent-001");
    REQUIRE(release.has_value());

    auto after = store.get_status("agent-001");
    REQUIRE(after.has_value()); // the READ succeeded
    CHECK_FALSE(after->has_value()); // ...it just found nothing active
}

TEST_CASE("QuarantineStore: quarantine_device rejects an empty agent_id", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.quarantine_device("", "admin", "reason", "");
    CHECK_FALSE(result.has_value());
    // gov-fix(quality-engineer): exact message, not just has_value() --
    // this precondition-miss must stay UNPREFIXED (a 400 business error, not
    // a db_error:-prefixed 503) or the REST/MCP classification silently
    // misroutes it.
    CHECK(result.error() == "agent_id is required");
}

// Verifies the ON CONFLICT (agent_id) WHERE status = 'active' DO NOTHING
// syntax against a live Postgres instance — the partial-unique-index
// arbiter this store relies on to replace the legacy check-then-insert-
// under-mutex race (docs/postgres-store-playbook.md's explicit warning:
// this class of syntax is easy to get subtly wrong by reasoning alone).
TEST_CASE("QuarantineStore: double quarantine rejected (partial unique index race-safe)",
          "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto first = store.quarantine_device("agent-002", "admin", "First", "");
    REQUIRE(first.has_value());
    auto second = store.quarantine_device("agent-002", "admin", "Second", "");
    CHECK_FALSE(second.has_value());
    CHECK(second.error() == "device is already quarantined");

    // Exactly one active row, carrying the FIRST call's reason (the conflict
    // truly did nothing — it did not silently overwrite).
    auto status = store.get_status("agent-002");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->reason == "First");

    // A device can be re-quarantined after release (the partial index only
    // excludes a SECOND simultaneously-active row, not history).
    REQUIRE(store.release_device("agent-002").has_value());
    auto third = store.quarantine_device("agent-002", "admin", "Third", "");
    CHECK(third.has_value());
}

TEST_CASE("QuarantineStore: release non-quarantined device", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.release_device("agent-nonexistent");
    CHECK_FALSE(result.has_value());
    CHECK(result.error() == "device is not quarantined");
}

TEST_CASE("QuarantineStore: non-quarantined device has no active status", "[pg][quarantine][status]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto status = store.get_status("agent-clean");
    REQUIRE(status.has_value()); // the READ succeeded
    CHECK_FALSE(status->has_value()); // ...it just found nothing

    auto empty_id = store.get_status("");
    REQUIRE(empty_id.has_value());
    CHECK_FALSE(empty_id->has_value());
}

TEST_CASE("QuarantineStore: list quarantined devices", "[pg][quarantine][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-list-1", "admin", "Reason 1", "").has_value());
    REQUIRE(store.quarantine_device("agent-list-2", "admin", "Reason 2", "").has_value());

    auto list = store.list_quarantined();
    REQUIRE(list.has_value()); // AUTHORITATIVE read succeeded
    int found = 0;
    for (const auto& r : *list)
        if (r.agent_id == "agent-list-1" || r.agent_id == "agent-list-2")
            ++found;
    CHECK(found == 2);

    REQUIRE(store.release_device("agent-list-1").has_value());
    auto list2 = store.list_quarantined();
    REQUIRE(list2.has_value());
    bool has_1 = false, has_2 = false;
    for (const auto& r : *list2) {
        if (r.agent_id == "agent-list-1")
            has_1 = true;
        if (r.agent_id == "agent-list-2")
            has_2 = true;
    }
    CHECK_FALSE(has_1); // released, no longer active
    CHECK(has_2);
}

TEST_CASE("QuarantineStore: history tracking survives release + re-quarantine cycles",
          "[pg][quarantine][history]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-hist", "admin", "First quarantine", "").has_value());
    REQUIRE(store.release_device("agent-hist").has_value());

    REQUIRE(store.quarantine_device("agent-hist", "security-team", "Second quarantine",
                                    "10.0.0.1")
                .has_value());
    REQUIRE(store.release_device("agent-hist").has_value());

    auto history = store.get_history("agent-hist");
    REQUIRE(history.has_value());
    REQUIRE(history->size() == 2);
    // Most recent first.
    CHECK((*history)[0].reason == "Second quarantine");
    CHECK((*history)[0].status == "released");
    CHECK((*history)[1].reason == "First quarantine");
}

TEST_CASE("QuarantineStore: get_history on an empty agent_id returns an empty result, not degraded",
          "[pg][quarantine][history]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto history = store.get_history("");
    REQUIRE(history.has_value());
    CHECK(history->empty());
}

// ── Endpoint-confirmation state (#3425 schema v2) ──────────────────────────

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed happy path, read back via get_status",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-001", "admin", "reason", "10.0.0.1").has_value());

    auto fresh = store.get_status("agent-001");
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->has_value());
    CHECK((*fresh)->last_applied_at == 0); // never, matches released_at's sentinel
    CHECK((*fresh)->last_confirmed_at == 0);

    REQUIRE(store.mark_endpoint_applied("agent-001", (*fresh)->id, 1000).has_value());
    auto after_apply = store.get_status("agent-001");
    REQUIRE(after_apply.has_value());
    REQUIRE(after_apply->has_value());
    CHECK((*after_apply)->last_applied_at == 1000);
    CHECK((*after_apply)->last_confirmed_at == 0); // apply alone is not confirmation

    REQUIRE(store.mark_endpoint_confirmed("agent-001", (*fresh)->id, 2000).has_value());
    auto after_confirm = store.get_status("agent-001");
    REQUIRE(after_confirm.has_value());
    REQUIRE(after_confirm->has_value());
    CHECK((*after_confirm)->last_applied_at == 1000); // unaffected by the confirm write
    CHECK((*after_confirm)->last_confirmed_at == 2000);
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed on a non-quarantined device is a "
          "business error, not a store failure",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto applied = store.mark_endpoint_applied("never-quarantined", /*record_id=*/0, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "device is not quarantined");
    CHECK_FALSE(applied.error().starts_with(yuzu::server::kQuarantineDbErrorPrefix));

    auto confirmed = store.mark_endpoint_confirmed("never-quarantined", /*record_id=*/0, 1000);
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error() == "device is not quarantined");
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed on a RELEASED (not active) record "
          "is also a business error — the guarded UPDATE only matches status='active'",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-002", "admin", "reason", "").has_value());
    auto before_release = store.get_status("agent-002");
    REQUIRE(before_release.has_value());
    REQUIRE(before_release->has_value());
    const auto record_id = (*before_release)->id;
    REQUIRE(store.release_device("agent-002").has_value());

    // Even with the CORRECT (real, pre-release) id, status != 'active' alone
    // still fails the guarded UPDATE — id-scoping is additive, not a
    // replacement for the status check.
    auto applied = store.mark_endpoint_applied("agent-002", record_id, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "device is not quarantined");
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed with the WRONG record id (a "
          "release-then-requarantine race) is a business error, never silently stamps the new "
          "record (governance Gate 4, unhappy-path Finding A)",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-003", "admin", "malware", "10.0.0.1").has_value());
    auto old_status = store.get_status("agent-003");
    REQUIRE(old_status.has_value());
    REQUIRE(old_status->has_value());
    const auto old_id = (*old_status)->id;

    // Simulates the race: the OLD record is released and a NEW, unrelated
    // active record now exists for the same agent_id by the time the write
    // for the OLD record's dispatch arrives.
    REQUIRE(store.release_device("agent-003").has_value());
    REQUIRE(
        store.quarantine_device("agent-003", "admin", "NEW-reason", "99.99.99.99").has_value());
    auto new_status = store.get_status("agent-003");
    REQUIRE(new_status.has_value());
    REQUIRE(new_status->has_value());
    const auto new_id = (*new_status)->id;
    REQUIRE(new_id != old_id); // a genuinely different row

    // Using the STALE (old) record id must fail — id AND status='active' AND
    // agent_id all have to match; the id alone belonging to a real row that
    // once existed is not enough.
    auto applied = store.mark_endpoint_applied("agent-003", old_id, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "device is not quarantined");
    auto confirmed = store.mark_endpoint_confirmed("agent-003", old_id, 1000);
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error() == "device is not quarantined");

    // The NEW record must be completely untouched by either failed call —
    // this is the exact misattribution Finding A described.
    auto after = store.get_status("agent-003");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->id == new_id);
    CHECK((*after)->last_applied_at == 0);
    CHECK((*after)->last_confirmed_at == 0);

    // Using the CURRENT (new) record id succeeds, proving id-scoping isn't
    // simply broken/over-strict.
    REQUIRE(store.mark_endpoint_applied("agent-003", new_id, 1000).has_value());
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed share quarantine_device's "
          "empty-agent_id precondition guard",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    // A precondition the store enforces BEFORE ever touching the pool — the
    // db_error PREFIX contract on a genuine store failure is exercised
    // end-to-end by the construction-fails-closed test above.
    auto applied = store.mark_endpoint_applied("", /*record_id=*/0, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "agent_id is required");

    auto confirmed = store.mark_endpoint_confirmed("", /*record_id=*/0, 1000);
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error() == "agent_id is required");
}

// UP-7 pattern (test_api_token_store.cpp's v2->v3 case): every other test in
// this file clones `quarantine_tpl`, already at v2 — the real v1->v2 upgrade
// path (PgMigrationRunner applying v2's ALTER against a genuinely-populated
// v1 table) is otherwise untested. Hand-seeds v1 DDL verbatim (copied from
// migrations() in quarantine_store.cpp, file-local and not exported), stamps
// schema_meta at v1, and inserts an active row BEFORE handing the database
// to a real QuarantineStore construction.
TEST_CASE("QuarantineStore: a genuine v1->v2 upgrade (real ALTER against a populated table) "
          "opens cleanly and the new columns default to 0 on the pre-existing row",
          "[pg][quarantine][store][migration]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA quarantine_store")};
        REQUIRE(schema.ok());

        // v1 DDL, copied from migrations() in quarantine_store.cpp — but
        // SCHEMA-QUALIFIED throughout, unlike the source: the real
        // migration runs its unqualified DDL under a transaction whose
        // search_path PgMigrationRunner sets to the store schema (see that
        // file's own "Unqualified DDL" comment), which a raw PQexec on a
        // plain connection does NOT do (mirrors the api_token_store UP-7
        // precedent's own schema-qualified copy, for the identical reason).
        PgResult v1{PQexec(conn.get(),
                           "CREATE TABLE quarantine_store.quarantine_records ("
                           "  id              BIGSERIAL PRIMARY KEY,"
                           "  agent_id        TEXT NOT NULL,"
                           "  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN "
                           "('active', 'released')),"
                           "  quarantined_by  TEXT NOT NULL DEFAULT '',"
                           "  quarantined_at  BIGINT NOT NULL DEFAULT 0,"
                           "  released_at     BIGINT NOT NULL DEFAULT 0,"
                           "  whitelist       TEXT NOT NULL DEFAULT '',"
                           "  reason          TEXT NOT NULL DEFAULT '');"
                           "CREATE INDEX idx_quarantine_agent ON "
                           "quarantine_store.quarantine_records(agent_id);"
                           "CREATE UNIQUE INDEX idx_quarantine_agent_active ON "
                           "quarantine_store.quarantine_records(agent_id) WHERE status = 'active';"
                           "CREATE TABLE quarantine_store.quarantine_meta ("
                           "  key   TEXT PRIMARY KEY,"
                           "  value TEXT NOT NULL"
                           ")")};
        REQUIRE(v1.ok());
        PgResult stamp{PQexec(conn.get(),
                              "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                              "VALUES ('quarantine_store', 1, extract(epoch FROM now())::bigint)")};
        REQUIRE(stamp.ok());

        // A row genuinely present BEFORE the v2 ALTER runs.
        PgResult seed{PQexec(conn.get(),
                             "INSERT INTO quarantine_store.quarantine_records "
                             "(agent_id, status, quarantined_by, quarantined_at, whitelist, "
                             "reason) VALUES ('pre-v2-agent', 'active', 'admin', 1000, "
                             "'10.0.0.1', 'pre-upgrade')")};
        REQUIRE(seed.ok());
    }

    // The real construction path: PgMigrationRunner::run reads version 1
    // from schema_meta and applies v2's ALTER against the table seeded above.
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    // Pin the new columns from the OUTSIDE: get_status's kRecordCols
    // projection now includes both, and the pre-existing row reads 0/0 (the
    // DEFAULT), not an error.
    auto status = store.get_status("pre-v2-agent");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->quarantined_by == "admin"); // untouched by the ALTER
    CHECK((*status)->last_applied_at == 0);
    CHECK((*status)->last_confirmed_at == 0);

    // And mark_endpoint_applied/confirmed round-trip through the now-v2
    // schema end-to-end for that same pre-existing row.
    REQUIRE(store.mark_endpoint_applied("pre-v2-agent", (*status)->id, 5000).has_value());
    auto after = store.get_status("pre-v2-agent");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->last_applied_at == 5000);

    // v3 (#3623, migrate_from_sqlite retired): the same construction call also runs the
    // DROP TABLE against quarantine_meta — seeded by the v1 DDL above but never touched by
    // v2's ALTER, so this is the only ladder test that actually exercises the drop landing
    // against a populated (not merely fresh-templated) database.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult ver{PQexec(conn.get(),
                            "SELECT version FROM public.schema_meta WHERE store = "
                            "'quarantine_store'")};
        REQUIRE(ver.ok());
        REQUIRE(PQntuples(ver.get()) == 1);
        CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "3");
        PgResult tbl{PQexec(conn.get(),
                            "SELECT COUNT(*) FROM information_schema.tables WHERE "
                            "table_schema = 'quarantine_store' AND table_name = "
                            "'quarantine_meta'")};
        REQUIRE(tbl.ok());
        CHECK(std::string(PQgetvalue(tbl.get(), 0, 0)) == "0");
    }
}
