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
 *  - request_release / mark_released: the two-step release (single guarded UPDATEs),
 *    not-quarantined, the releasing state, the forced end and the owed-release list (schema v4).
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

#include <chrono>
#include <expected>
#include <optional>
#include <string>
#include <vector>

using yuzu::server::classify_quarantine_write;
using yuzu::server::kApplyClaimTtlSecs;
using yuzu::server::kQuarantineApplyInFlight;
using yuzu::server::kQuarantineNotQuarantined;
using yuzu::server::QuarantineRecord;
using yuzu::server::QuarantineStore;
using yuzu::server::QuarantineWrite;
using yuzu::server::ReleaseEnd;
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

// The token a confirmed end presents (#7613): the apply generation read now, with no claim live.
std::int64_t fence_of(QuarantineStore& store, const std::string& agent_id, std::int64_t record_id) {
    auto token = store.apply_fence_token(agent_id, record_id);
    REQUIRE(token.has_value());
    REQUIRE(token->has_value());
    return **token;
}

// An ended record: the release asked for, then the device's confirmation recorded.
void end_record(QuarantineStore& store, const std::string& agent_id) {
    auto id = store.request_release(agent_id);
    REQUIRE(id.has_value());
    REQUIRE(store.mark_released(agent_id, *id, ReleaseEnd::device_confirmed,
                                fence_of(store, agent_id, *id))
                .has_value());
}

std::optional<QuarantineRecord> active_row(QuarantineStore& store, const std::string& agent_id) {
    auto st = store.get_status(agent_id);
    REQUIRE(st.has_value());
    return *st;
}

// One statement on a fresh connection: ages a claim or seeds a historical value the store itself
// would never write.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

bool owed_contains(QuarantineStore& store, const std::string& agent_id) {
    auto owed = store.list_release_owed();
    REQUIRE(owed.has_value());
    for (const auto& r : *owed)
        if (r.agent_id == agent_id)
            return true;
    return false;
}

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

    end_record(store, "agent-001");

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
    end_record(store, "agent-002");
    auto third = store.quarantine_device("agent-002", "admin", "Third", "");
    CHECK(third.has_value());
}

TEST_CASE("QuarantineStore: request_release on a non-quarantined device", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.request_release("agent-nonexistent");
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

TEST_CASE("QuarantineStore: list_quarantined_in pushes the id restriction and the limit into the query",
          "[pg][quarantine][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    for (const char* id : {"s-a", "s-b", "s-c", "s-d"})
        REQUIRE(store.quarantine_device(id, "admin", "r", "").has_value());

    {   // nullptr = every agent, newest first
        auto all = store.list_quarantined_in(nullptr, 0);
        REQUIRE(all.has_value());
        REQUIRE(all->size() == 4);
        CHECK((*all)[0].agent_id == "s-d"); // newest first
    }
    {   // restricted to ids: only those come back
        const std::vector<std::string> ids{"s-b", "s-d", "not-quarantined"};
        auto r = store.list_quarantined_in(&ids, 0);
        REQUIRE(r.has_value());
        REQUIRE(r->size() == 2);
        CHECK((*r)[0].agent_id == "s-d");
        CHECK((*r)[1].agent_id == "s-b");
    }
    {   // the LIMIT applies to the restricted set (an excluded record cannot displace one)
        const std::vector<std::string> ids{"s-a", "s-b"};
        auto r = store.list_quarantined_in(&ids, 1);
        REQUIRE(r.has_value());
        REQUIRE(r->size() == 1);
        CHECK((*r)[0].agent_id == "s-b"); // newest of the two, not s-d
    }
    {   // present-but-empty = deny-all, no matter the limit
        const std::vector<std::string> none;
        auto r = store.list_quarantined_in(&none, 0);
        REQUIRE(r.has_value());
        CHECK(r->empty());
    }
    {   // a released record is not active
        end_record(store, "s-d");
        auto r = store.list_quarantined_in(nullptr, 0);
        REQUIRE(r.has_value());
        CHECK(r->size() == 3);
    }
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

    end_record(store, "agent-list-1");
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
    end_record(store, "agent-hist");

    REQUIRE(store.quarantine_device("agent-hist", "security-team", "Second quarantine",
                                    "10.0.0.1")
                .has_value());
    end_record(store, "agent-hist");

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
    end_record(store, "agent-002");

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
    end_record(store, "agent-003");
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
    // v4 (PRQ.2): the same construction call applies the release columns; the pre-existing row
    // reads 0 for each (never) and keeps its stored status.
    CHECK((*status)->status == "active");
    CHECK((*status)->release_requested_at == 0);
    CHECK((*status)->device_release_owed_at == 0);

    // And mark_endpoint_applied/confirmed round-trip through the now-v2
    // schema end-to-end for that same pre-existing row.
    REQUIRE(store.mark_endpoint_applied("pre-v2-agent", (*status)->id, 5000).has_value());
    auto after = store.get_status("pre-v2-agent");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->last_applied_at == 5000);

    // v3 (#3623, migrate_from_sqlite retired), v4 (PRQ.2) and v5 (#7613): the same construction call also runs the
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
        CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "5");
        PgResult tbl{PQexec(conn.get(),
                            "SELECT COUNT(*) FROM information_schema.tables WHERE "
                            "table_schema = 'quarantine_store' AND table_name = "
                            "'quarantine_meta'")};
        REQUIRE(tbl.ok());
        CHECK(std::string(PQgetvalue(tbl.get(), 0, 0)) == "0");
    }
}

// ── The release (PRQ.2 schema v4) ───────────────────────────────────────────

TEST_CASE("QuarantineStore: v4 applies; the two release columns default to 0 and the owed-release "
          "partial index exists",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-r1", "admin", "reason", "").has_value());
    const auto row = active_row(store, "agent-r1");
    REQUIRE(row.has_value());
    CHECK(row->status == "active");
    CHECK(row->release_requested_at == 0);
    CHECK(row->device_release_owed_at == 0);

    // The partial index the per-tick owed read relies on, and no column for a device-reported limit.
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult idx{PQexec(conn.get(),
                        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'quarantine_store' AND "
                        "indexname = 'idx_quarantine_release_owed'")};
    REQUIRE(idx.ok());
    REQUIRE(PQntuples(idx.get()) == 1);
    const std::string def = PQgetvalue(idx.get(), 0, 0);
    CHECK(def.find("(agent_id, id)") != std::string::npos);
    CHECK(def.find("device_release_owed_at <> 0") != std::string::npos);
    CHECK(def.find("'released'") != std::string::npos);
    PgResult cols{PQexec(conn.get(),
                         "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = "
                         "'quarantine_store' AND table_name = 'quarantine_records' AND column_name IN "
                         "('release_requested_at', 'device_release_owed_at', 'endpoint_ttl_expires')")};
    REQUIRE(cols.ok());
    CHECK(std::string(PQgetvalue(cols.get(), 0, 0)) == "2");
}

TEST_CASE("QuarantineStore: request_release returns the record id and the record reads releasing but stays listed",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-r2", "admin", "reason", "10.0.0.1").has_value());
    const auto before = active_row(store, "agent-r2");
    REQUIRE(before.has_value());

    auto id = store.request_release("agent-r2");
    REQUIRE(id.has_value());
    CHECK(*id == before->id);

    const auto after = active_row(store, "agent-r2");
    REQUIRE(after.has_value()); // still the device's active record
    CHECK(after->status == "releasing");
    CHECK(after->release_requested_at > 0);
    CHECK(after->id == before->id);

    // list_quarantined and list_quarantined_in still return it (the dispatch refusal stays)
    auto all = store.list_quarantined();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 1);
    CHECK((*all)[0].status == "releasing");
    const std::vector<std::string> ids{"agent-r2"};
    auto scoped = store.list_quarantined_in(&ids, 0);
    REQUIRE(scoped.has_value());
    REQUIRE(scoped->size() == 1);
    CHECK((*scoped)[0].status == "releasing");
}

TEST_CASE("QuarantineStore: request_release is idempotent: the first timestamp and the same id",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-r3", "admin", "reason", "").has_value());

    auto first = store.request_release("agent-r3");
    REQUIRE(first.has_value());
    const auto stamp = active_row(store, "agent-r3")->release_requested_at;
    auto second = store.request_release("agent-r3");
    REQUIRE(second.has_value());
    CHECK(*second == *first);
    CHECK(active_row(store, "agent-r3")->release_requested_at == stamp);
}

TEST_CASE("QuarantineStore: request_release with no active record is an unprefixed business error",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto none = store.request_release("never-quarantined");
    REQUIRE_FALSE(none.has_value());
    CHECK(none.error() == "device is not quarantined");
    CHECK_FALSE(none.error().starts_with(yuzu::server::kQuarantineDbErrorPrefix));
    auto empty = store.request_release("");
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error() == "agent_id is required");

    // an ended record is not an active one either
    REQUIRE(store.quarantine_device("agent-r4", "admin", "reason", "").has_value());
    end_record(store, "agent-r4");
    auto ended = store.request_release("agent-r4");
    REQUIRE_FALSE(ended.has_value());
    CHECK(ended.error() == "device is not quarantined");
}

TEST_CASE("QuarantineStore: a releasing record still refuses quarantine_device",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-r5", "admin", "reason", "").has_value());
    REQUIRE(store.request_release("agent-r5").has_value());

    auto again = store.quarantine_device("agent-r5", "admin", "again", "");
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error() == "device is already quarantined");
}

TEST_CASE("QuarantineStore: mark_released(device_confirmed) ends the record and a new quarantine then succeeds",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-r6", "admin", "reason", "").has_value());
    auto id = store.request_release("agent-r6");
    REQUIRE(id.has_value());

    REQUIRE(store.mark_released("agent-r6", *id, ReleaseEnd::device_confirmed,
                                fence_of(store, "agent-r6", *id))
                .has_value());
    CHECK_FALSE(active_row(store, "agent-r6").has_value());
    CHECK_FALSE(owed_contains(store, "agent-r6")); // nothing owed on a confirmed end
    auto history = store.get_history("agent-r6");
    REQUIRE(history.has_value());
    REQUIRE(history->size() == 1);
    CHECK((*history)[0].status == "released");
    CHECK((*history)[0].released_at > 0);
    CHECK((*history)[0].device_release_owed_at == 0);

    CHECK(store.quarantine_device("agent-r6", "admin", "again", "").has_value());
}

TEST_CASE("QuarantineStore: mark_released with a stale record id affects no row",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-r7", "admin", "old", "").has_value());
    const auto old_id = active_row(store, "agent-r7")->id;
    end_record(store, "agent-r7");
    REQUIRE(store.quarantine_device("agent-r7", "admin", "new", "").has_value());
    const auto new_id = active_row(store, "agent-r7")->id;
    REQUIRE(new_id != old_id);

    auto stale = store.mark_released("agent-r7", old_id, ReleaseEnd::device_confirmed,
                                     fence_of(store, "agent-r7", old_id));
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error() == "device is not quarantined");
    auto stale_forced = store.mark_released("agent-r7", old_id, ReleaseEnd::forced);
    REQUIRE_FALSE(stale_forced.has_value());
    CHECK(stale_forced.error() == "device is not quarantined");
    // the new record is untouched
    const auto row = active_row(store, "agent-r7");
    REQUIRE(row.has_value());
    CHECK(row->id == new_id);
    CHECK(row->status == "active");
}

TEST_CASE("QuarantineStore: mark_released(forced) ends the record, leaves it out of the active list and owes the device a release",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    // a releasing record forced
    REQUIRE(store.quarantine_device("agent-f1", "admin", "reason", "").has_value());
    auto id = store.request_release("agent-f1");
    REQUIRE(id.has_value());
    REQUIRE(store.mark_released("agent-f1", *id, ReleaseEnd::forced).has_value());
    CHECK_FALSE(active_row(store, "agent-f1").has_value());
    auto active = store.list_quarantined();
    REQUIRE(active.has_value());
    CHECK(active->empty());
    CHECK(owed_contains(store, "agent-f1"));
    auto history = store.get_history("agent-f1");
    REQUIRE(history.has_value());
    REQUIRE(history->size() == 1);
    CHECK((*history)[0].status == "released");
    CHECK((*history)[0].device_release_owed_at > 0);

    // an active (not yet releasing) record can be forced too
    REQUIRE(store.quarantine_device("agent-f2", "admin", "reason", "").has_value());
    const auto f2 = active_row(store, "agent-f2")->id;
    REQUIRE(store.mark_released("agent-f2", f2, ReleaseEnd::forced).has_value());
    CHECK(owed_contains(store, "agent-f2"));
}

TEST_CASE("QuarantineStore: list_release_owed leaves out a forced record once the device has a newer record",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    // newer ACTIVE record
    REQUIRE(store.quarantine_device("agent-n1", "admin", "old", "").has_value());
    REQUIRE(store.mark_released("agent-n1", active_row(store, "agent-n1")->id, ReleaseEnd::forced)
                .has_value());
    REQUIRE(owed_contains(store, "agent-n1"));
    REQUIRE(store.quarantine_device("agent-n1", "admin", "new", "").has_value());
    CHECK_FALSE(owed_contains(store, "agent-n1"));

    // newer RELEASED record
    REQUIRE(store.quarantine_device("agent-n2", "admin", "old", "").has_value());
    REQUIRE(store.mark_released("agent-n2", active_row(store, "agent-n2")->id, ReleaseEnd::forced)
                .has_value());
    REQUIRE(store.quarantine_device("agent-n2", "admin", "new", "").has_value());
    end_record(store, "agent-n2");
    CHECK_FALSE(owed_contains(store, "agent-n2"));
}

TEST_CASE("QuarantineStore: clear_release_owed removes the mark; a repeat and a stale id affect no row",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-c1", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-c1")->id;
    REQUIRE(store.mark_released("agent-c1", id, ReleaseEnd::forced).has_value());
    REQUIRE(owed_contains(store, "agent-c1"));

    auto stale = store.clear_release_owed("agent-c1", id + 1000, 0);
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error() == "device is not quarantined");
    CHECK(owed_contains(store, "agent-c1"));

    REQUIRE(store.clear_release_owed("agent-c1", id, fence_of(store, "agent-c1", id)).has_value());
    CHECK_FALSE(owed_contains(store, "agent-c1"));
    auto again = store.clear_release_owed("agent-c1", id, fence_of(store, "agent-c1", id));
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error() == "device is not quarantined");
    // a record that was never forced has nothing to clear
    REQUIRE(store.quarantine_device("agent-c2", "admin", "reason", "").has_value());
    end_record(store, "agent-c2");
    auto history = store.get_history("agent-c2");
    REQUIRE(history.has_value());
    auto none = store.clear_release_owed("agent-c2", (*history)[0].id,
                                         fence_of(store, "agent-c2", (*history)[0].id));
    REQUIRE_FALSE(none.has_value());
}

TEST_CASE("QuarantineStore: mark_endpoint_confirmed refuses a row whose release has been requested "
          "(#8045)",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-r6", "admin", "malware", "").has_value());
    const auto id = active_row(store, "agent-r6")->id;
    REQUIRE(store.mark_endpoint_confirmed("agent-r6", id, 1000).has_value()); // active: stamps
    REQUIRE(store.request_release("agent-r6").has_value());
    auto refused = store.mark_endpoint_confirmed("agent-r6", id, 2000);
    REQUIRE_FALSE(refused.has_value()); // releasing: no longer confirmed as contained
    CHECK(refused.error() == std::string(kQuarantineNotQuarantined));
    CHECK(active_row(store, "agent-r6")->last_confirmed_at == 1000); // the stamp did not move
}

TEST_CASE("QuarantineStore: mark_endpoint_confirmed stamps last_confirmed_at, the latest confirm wins, and "
          "a stale record id is refused",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-t1", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-t1")->id;

    REQUIRE(store.mark_endpoint_confirmed("agent-t1", id, 2000).has_value());
    CHECK(active_row(store, "agent-t1")->last_confirmed_at == 2000);
    REQUIRE(store.mark_endpoint_confirmed("agent-t1", id, 3000).has_value());
    CHECK(active_row(store, "agent-t1")->last_confirmed_at == 3000);

    auto stale = store.mark_endpoint_confirmed("agent-t1", id + 1000, 4000);
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error() == "device is not quarantined");
    CHECK(active_row(store, "agent-t1")->last_confirmed_at == 3000);
}

// ── #7584b, #7628: the store's smaller contracts ──────────────────────────────

TEST_CASE("QuarantineStore: a historical non-zero release_requested_at seeded by SQL is unchanged by "
          "request_release (the CASE keeps the first request)",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-h1", "admin", "reason", "").has_value());
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET release_requested_at = 12345 "
                       "WHERE agent_id = 'agent-h1'");

    auto id = store.request_release("agent-h1");
    REQUIRE(id.has_value());
    const auto row = active_row(store, "agent-h1");
    REQUIRE(row.has_value());
    CHECK(row->id == *id);
    CHECK(row->release_requested_at == 12345);
    CHECK(row->status == "releasing");
}

TEST_CASE("QuarantineStore: quarantine_device returns the new row's id", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    auto first = store.quarantine_device("agent-i1", "admin", "reason", "");
    REQUIRE(first.has_value());
    CHECK(*first == active_row(store, "agent-i1")->id);
    end_record(store, "agent-i1");
    auto second = store.quarantine_device("agent-i1", "admin", "again", "");
    REQUIRE(second.has_value());
    CHECK(*second > *first);
    CHECK(*second == active_row(store, "agent-i1")->id);
    // a conflict is still the unprefixed business error, carrying no id
    auto dup = store.quarantine_device("agent-i1", "admin", "dup", "");
    REQUIRE_FALSE(dup.has_value());
    CHECK(dup.error() == "device is already quarantined");
}

// ── The apply claim and generation (#7613) ───────────────────────────────────

TEST_CASE("QuarantineStore: v5 adds the two apply columns, defaulting to 0 (no claim, generation 0)",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-v5", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-v5")->id;
    auto token = store.apply_fence_token("agent-v5", id);
    REQUIRE(token.has_value());
    REQUIRE(token->has_value());
    CHECK(**token == 0); // no apply has ever been claimed
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult cols{PQexec(conn.get(),
                         "SELECT column_name, data_type, column_default FROM information_schema.columns "
                         "WHERE table_schema = 'quarantine_store' AND table_name = 'quarantine_records' "
                         "AND column_name IN ('apply_gen', 'apply_claimed_at') ORDER BY column_name")};
    REQUIRE(cols.ok());
    REQUIRE(PQntuples(cols.get()) == 2);
    CHECK(std::string(PQgetvalue(cols.get(), 0, 0)) == "apply_claimed_at");
    CHECK(std::string(PQgetvalue(cols.get(), 1, 0)) == "apply_gen");
    CHECK(std::string(PQgetvalue(cols.get(), 0, 1)) == "bigint");
    CHECK(std::string(PQgetvalue(cols.get(), 1, 2)) == "0");
}

TEST_CASE("QuarantineStore: claim_apply moves the generation by one each time and refuses a releasing "
          "row, an ended row and a second live claim; an expired claim is taken over",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-a1", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-a1")->id;

    auto g1 = store.claim_apply("agent-a1", id);
    REQUIRE(g1.has_value());
    CHECK(*g1 == 1);
    // a live claim refuses another: the answer is the business error, nothing is dispatched
    auto blocked = store.claim_apply("agent-a1", id);
    REQUIRE_FALSE(blocked.has_value());
    CHECK(blocked.error() == std::string(kQuarantineNotQuarantined));
    REQUIRE(store.release_apply_claim("agent-a1", id, *g1).has_value());
    auto g2 = store.claim_apply("agent-a1", id);
    REQUIRE(g2.has_value());
    CHECK(*g2 == 2); // the generation outlives each claim
    REQUIRE(store.release_apply_claim("agent-a1", id, *g2).has_value());

    // an expired claim (older than kApplyClaimTtlSecs) no longer counts: it is taken over
    auto g3 = store.claim_apply("agent-a1", id);
    REQUIRE(g3.has_value());
    CHECK(*g3 == 3);
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = 1 WHERE id = " +
                           std::to_string(id));
    auto g4 = store.claim_apply("agent-a1", id);
    REQUIRE(g4.has_value());
    CHECK(*g4 == 4);
    // a claim seeded just inside the window still blocks
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = "
                       "EXTRACT(EPOCH FROM now())::bigint - " +
                           std::to_string(kApplyClaimTtlSecs - 30) + " WHERE id = " + std::to_string(id));
    CHECK_FALSE(store.claim_apply("agent-a1", id).has_value());
    REQUIRE(store.release_apply_claim("agent-a1", id, *g4).has_value());

    // a stale record id and an unknown device are the same business error
    CHECK(store.claim_apply("agent-a1", id + 1000).error() == std::string(kQuarantineNotQuarantined));
    CHECK(store.claim_apply("nobody", 1).error() == std::string(kQuarantineNotQuarantined));
    CHECK(store.claim_apply("", 1).error() == "agent_id is required");

    // a releasing row is never claimed: containment is not re-applied under a release
    REQUIRE(store.request_release("agent-a1").has_value());
    auto releasing = store.claim_apply("agent-a1", id);
    REQUIRE_FALSE(releasing.has_value());
    CHECK(releasing.error() == std::string(kQuarantineNotQuarantined));
    // an ended row neither
    REQUIRE(store.mark_released("agent-a1", id, ReleaseEnd::forced).has_value());
    CHECK(store.claim_apply("agent-a1", id).error() == std::string(kQuarantineNotQuarantined));
}

TEST_CASE("QuarantineStore: release_apply_claim clears only its own generation, so an expired holder "
          "cannot drop a replacement's live claim",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-a2", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-a2")->id;

    auto holder_a = store.claim_apply("agent-a2", id);
    REQUIRE(holder_a.has_value());
    // A's claim ages past the window (a stalled dispatch), and B takes over.
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = 1 WHERE id = " +
                           std::to_string(id));
    auto holder_b = store.claim_apply("agent-a2", id);
    REQUIRE(holder_b.has_value());
    REQUIRE(*holder_b == *holder_a + 1);
    // A finally returns and releases ITS generation: B's claim is left alone.
    REQUIRE(store.release_apply_claim("agent-a2", id, *holder_a).has_value());
    auto token = store.apply_fence_token("agent-a2", id);
    REQUIRE(token.has_value());
    CHECK_FALSE(token->has_value()); // B's claim is still live
    CHECK_FALSE(store.claim_apply("agent-a2", id).has_value());
    // B releases its own: the claim is gone and the generation is B's.
    REQUIRE(store.release_apply_claim("agent-a2", id, *holder_b).has_value());
    token = store.apply_fence_token("agent-a2", id);
    REQUIRE(token.has_value());
    REQUIRE(token->has_value());
    CHECK(**token == *holder_b);
    // releasing a generation that never existed, or on an unknown record, is a successful no-op
    CHECK(store.release_apply_claim("agent-a2", id, 99).has_value());
    CHECK(store.release_apply_claim("agent-a2", id + 1000, 1).has_value());
}

TEST_CASE("QuarantineStore: apply_fence_token is the generation when no claim is live, empty while one "
          "is, the bumped generation after its release, and empty for an unknown record",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    auto steady_now = std::chrono::steady_clock::now();
    store.set_steady_now_fn([&steady_now] { return steady_now; });
    REQUIRE(store.quarantine_device("agent-a3", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-a3")->id;

    auto fresh = store.apply_fence_token("agent-a3", id);
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->has_value());
    CHECK(**fresh == 0);

    auto claim = store.claim_apply("agent-a3", id);
    REQUIRE(claim.has_value());
    auto during = store.apply_fence_token("agent-a3", id);
    REQUIRE(during.has_value());
    CHECK_FALSE(during->has_value()); // a claim is live: nothing may be read as settled

    REQUIRE(store.release_apply_claim("agent-a3", id, *claim).has_value());
    auto after = store.apply_fence_token("agent-a3", id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK(**after == 1); // the bumped generation: a token read before the apply no longer matches

    // an expired claim does not hide the token either (the claim ages out on both clocks)
    auto again = store.claim_apply("agent-a3", id);
    REQUIRE(again.has_value());
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = 1 WHERE id = " +
                           std::to_string(id));
    steady_now += std::chrono::seconds(kApplyClaimTtlSecs + 1);
    auto expired = store.apply_fence_token("agent-a3", id);
    REQUIRE(expired.has_value());
    REQUIRE(expired->has_value());
    CHECK(**expired == 2);

    // an unknown record and an unknown device have no token; the read did not fail
    auto unknown = store.apply_fence_token("agent-a3", id + 1000);
    REQUIRE(unknown.has_value());
    CHECK_FALSE(unknown->has_value());
    auto nobody = store.apply_fence_token("nobody", 1);
    REQUIRE(nobody.has_value());
    CHECK_FALSE(nobody->has_value());
    // the token is readable on an ended record too (the owed leg reads it)
    REQUIRE(store.release_apply_claim("agent-a3", id, *again).has_value());
    REQUIRE(store.mark_released("agent-a3", id, ReleaseEnd::forced).has_value());
    auto ended = store.apply_fence_token("agent-a3", id);
    REQUIRE(ended.has_value());
    REQUIRE(ended->has_value());
    CHECK(**ended == 2);
}

TEST_CASE("QuarantineStore: a step of the database clock cannot make a claim this process stamped "
          "read expired; another store instance, which stamped nothing, goes by the database alone",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    auto steady_now = std::chrono::steady_clock::now();
    store.set_steady_now_fn([&steady_now] { return steady_now; });
    REQUIRE(store.quarantine_device("agent-s1", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-s1")->id;

    auto claim = store.claim_apply("agent-s1", id);
    REQUIRE(claim.has_value());
    // The database clock jumps forward past the window: the stamp now reads two minutes old.
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = 1 WHERE id = " +
                           std::to_string(id));
    const auto hidden = store.apply_fence_token("agent-s1", id);
    REQUIRE(hidden.has_value());
    CHECK_FALSE(hidden->has_value()); // the monotonic clock still says the claim is live

    // A process that stamped nothing (a restart) has only the database to go by.
    {
        QuarantineStore other{pool};
        REQUIRE(other.is_open());
        const auto bare = other.apply_fence_token("agent-s1", id);
        REQUIRE(bare.has_value());
        REQUIRE(bare->has_value());
        CHECK(**bare == *claim);
    }

    // Once the monotonic window has passed too, the token is readable again.
    steady_now += std::chrono::seconds(kApplyClaimTtlSecs - 1);
    CHECK_FALSE(store.apply_fence_token("agent-s1", id)->has_value());
    steady_now += std::chrono::seconds(2);
    const auto released = store.apply_fence_token("agent-s1", id);
    REQUIRE(released.has_value());
    REQUIRE(released->has_value());
    CHECK(**released == *claim);

    // A fresh claim is hidden again, and releasing it drops the local entry with the database claim.
    auto second = store.claim_apply("agent-s1", id);
    REQUIRE(second.has_value());
    REQUIRE(store.release_apply_claim("agent-s1", id, *second).has_value());
    const auto after = store.apply_fence_token("agent-s1", id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK(**after == *second);
}

namespace {
// Stamp the record's claim `age_secs` old, counted back from the database's now(). The test host
// and the database share a clock, so this pins the edges of the window, not which clock the store
// reads: that is tests/test_quarantine_wiring_lexical.py's job.
void stamp_claim_age(const std::string& dsn, std::int64_t id, std::int64_t age_secs) {
    exec_sql(dsn, "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = "
                  "EXTRACT(EPOCH FROM now())::bigint - " +
                      std::to_string(age_secs) + " WHERE id = " + std::to_string(id));
}
} // namespace

TEST_CASE("QuarantineStore: at the 120 s claim window edge a claim 110 s old is live and one 121 s "
          "old is expired for the claim and the token read and both fenced ends",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    // The device-confirmed end and claim_apply and the token read, on an active record.
    REQUIRE(store.quarantine_device("agent-c1", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-c1")->id;
    stamp_claim_age(db.dsn(), id, kApplyClaimTtlSecs - 10);
    CHECK_FALSE(store.claim_apply("agent-c1", id).has_value());
    const auto live_token = store.apply_fence_token("agent-c1", id);
    REQUIRE(live_token.has_value());
    CHECK_FALSE(live_token->has_value()); // empty: nothing may be read as settled
    const auto live_end = store.mark_released("agent-c1", id, ReleaseEnd::device_confirmed, 0);
    REQUIRE_FALSE(live_end.has_value());
    CHECK(classify_quarantine_write(live_end) == QuarantineWrite::apply_in_flight);

    stamp_claim_age(db.dsn(), id, kApplyClaimTtlSecs + 1);
    const auto expired_token = store.apply_fence_token("agent-c1", id);
    REQUIRE(expired_token.has_value());
    REQUIRE(expired_token->has_value());
    CHECK(**expired_token == 0);
    const auto taken = store.claim_apply("agent-c1", id);
    REQUIRE(taken.has_value());
    CHECK(*taken == 1);
    stamp_claim_age(db.dsn(), id, kApplyClaimTtlSecs + 1); // the taken claim ages out as well
    REQUIRE(store.mark_released("agent-c1", id, ReleaseEnd::device_confirmed, *taken).has_value());

    // The owed-release clear, on a record a forced end left owed.
    REQUIRE(store.quarantine_device("agent-c2", "admin", "reason", "").has_value());
    const auto owed_id = active_row(store, "agent-c2")->id;
    REQUIRE(store.mark_released("agent-c2", owed_id, ReleaseEnd::forced).has_value());
    stamp_claim_age(db.dsn(), owed_id, kApplyClaimTtlSecs - 10);
    const auto live_clear = store.clear_release_owed("agent-c2", owed_id, 0);
    REQUIRE_FALSE(live_clear.has_value());
    CHECK(classify_quarantine_write(live_clear) == QuarantineWrite::apply_in_flight);
    CHECK(owed_contains(store, "agent-c2"));
    stamp_claim_age(db.dsn(), owed_id, kApplyClaimTtlSecs + 1);
    REQUIRE(store.clear_release_owed("agent-c2", owed_id, 0).has_value());
    CHECK_FALSE(owed_contains(store, "agent-c2"));
}

TEST_CASE("QuarantineStore: a confirmed end needs the generation it observed against: refused with no "
          "fence, under a live claim, and after a later apply; a forced end ignores both",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    const auto classify = [](const std::expected<void, std::string>& r) {
        return classify_quarantine_write(r);
    };

    SECTION("no fence: refused without a round trip, the record is untouched") {
        REQUIRE(store.quarantine_device("agent-m1", "admin", "reason", "").has_value());
        const auto id = active_row(store, "agent-m1")->id;
        REQUIRE(store.request_release("agent-m1").has_value());
        auto r = store.mark_released("agent-m1", id, ReleaseEnd::device_confirmed);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == std::string(kQuarantineApplyInFlight));
        CHECK(classify(r) == QuarantineWrite::apply_in_flight);
        CHECK(active_row(store, "agent-m1").has_value()); // still releasing and listed
    }
    SECTION("under a live claim: refused even with the right generation") {
        REQUIRE(store.quarantine_device("agent-m2", "admin", "reason", "").has_value());
        const auto id = active_row(store, "agent-m2")->id;
        const auto token = store.apply_fence_token("agent-m2", id);
        REQUIRE(token.has_value());
        REQUIRE(token->has_value());
        auto claim = store.claim_apply("agent-m2", id); // generation moves to 1, claim live
        REQUIRE(claim.has_value());
        auto r = store.mark_released("agent-m2", id, ReleaseEnd::device_confirmed, **token);
        REQUIRE_FALSE(r.has_value());
        CHECK(classify(r) == QuarantineWrite::apply_in_flight);
        // a token matching the CURRENT generation is still refused while the claim is live
        auto current = store.mark_released("agent-m2", id, ReleaseEnd::device_confirmed, *claim);
        REQUIRE_FALSE(current.has_value());
        CHECK(classify(current) == QuarantineWrite::apply_in_flight);
        CHECK(active_row(store, "agent-m2").has_value());
    }
    SECTION("the late-apply order: a token read before an apply that has since returned is stale") {
        REQUIRE(store.quarantine_device("agent-m3", "admin", "reason", "").has_value());
        const auto id = active_row(store, "agent-m3")->id;
        const auto token = store.apply_fence_token("agent-m3", id); // read BEFORE the release goes out
        REQUIRE(token.has_value());
        REQUIRE(token->has_value());
        auto claim = store.claim_apply("agent-m3", id);              // an apply is claimed after it...
        REQUIRE(claim.has_value());
        REQUIRE(store.release_apply_claim("agent-m3", id, *claim).has_value()); // ...and has returned
        auto r = store.mark_released("agent-m3", id, ReleaseEnd::device_confirmed, **token);
        REQUIRE_FALSE(r.has_value());
        CHECK(classify(r) == QuarantineWrite::apply_in_flight);
        CHECK(active_row(store, "agent-m3").has_value());
        // a fresh token, read now, succeeds
        const auto fresh = store.apply_fence_token("agent-m3", id);
        REQUIRE(fresh.has_value());
        REQUIRE(fresh->has_value());
        CHECK(store.mark_released("agent-m3", id, ReleaseEnd::device_confirmed, **fresh).has_value());
        CHECK_FALSE(active_row(store, "agent-m3").has_value());
    }
    SECTION("a zero-row mark with a fence is not_quarantined, not apply_in_flight") {
        REQUIRE(store.quarantine_device("agent-m4", "admin", "reason", "").has_value());
        const auto id = active_row(store, "agent-m4")->id;
        auto stale = store.mark_released("agent-m4", id + 1000, ReleaseEnd::device_confirmed, 0);
        REQUIRE_FALSE(stale.has_value());
        CHECK(classify(stale) == QuarantineWrite::not_quarantined);
        end_record(store, "agent-m4");
        auto ended = store.mark_released("agent-m4", id, ReleaseEnd::device_confirmed, 0);
        REQUIRE_FALSE(ended.has_value());
        CHECK(classify(ended) == QuarantineWrite::not_quarantined);
    }
    SECTION("forced ignores the fence and any live claim, and leaves both columns as they are") {
        REQUIRE(store.quarantine_device("agent-m5", "admin", "reason", "").has_value());
        const auto id = active_row(store, "agent-m5")->id;
        auto claim = store.claim_apply("agent-m5", id); // live
        REQUIRE(claim.has_value());
        REQUIRE(store.mark_released("agent-m5", id, ReleaseEnd::forced).has_value());
        CHECK(owed_contains(store, "agent-m5"));
        // the owed leg still sees the live claim: no token while it lasts
        auto token = store.apply_fence_token("agent-m5", id);
        REQUIRE(token.has_value());
        CHECK_FALSE(token->has_value());
    }
}

TEST_CASE("QuarantineStore: clear_release_owed needs the fence too: refused with none, under a live claim "
          "and after a later apply; it succeeds with the current token",
          "[pg][quarantine][apply_fence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-o1", "admin", "reason", "").has_value());
    const auto id = active_row(store, "agent-o1")->id;
    REQUIRE(store.mark_released("agent-o1", id, ReleaseEnd::forced).has_value());
    REQUIRE(owed_contains(store, "agent-o1"));

    // no fence
    auto none = store.clear_release_owed("agent-o1", id, std::nullopt);
    REQUIRE_FALSE(none.has_value());
    CHECK(classify_quarantine_write(none) == QuarantineWrite::apply_in_flight);

    // An ended record is not claimable (status released), so the late-apply order for the owed leg
    // is a claim taken before the end, seeded directly: a token read, then an apply claimed and live.
    const auto token = store.apply_fence_token("agent-o1", id);
    REQUIRE(token.has_value());
    REQUIRE(token->has_value());
    CHECK_FALSE(store.claim_apply("agent-o1", id).has_value());
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_gen = apply_gen + 1, "
                       "apply_claimed_at = EXTRACT(EPOCH FROM now())::bigint WHERE id = " +
                           std::to_string(id));
    auto live = store.clear_release_owed("agent-o1", id, **token);
    REQUIRE_FALSE(live.has_value());
    CHECK(classify_quarantine_write(live) == QuarantineWrite::apply_in_flight);
    // the claim returns: the old token is stale (the generation moved), a fresh one works
    exec_sql(db.dsn(), "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = 0 WHERE id = " +
                           std::to_string(id));
    auto stale = store.clear_release_owed("agent-o1", id, **token);
    REQUIRE_FALSE(stale.has_value());
    CHECK(classify_quarantine_write(stale) == QuarantineWrite::apply_in_flight);
    CHECK(owed_contains(store, "agent-o1"));
    const auto fresh = store.apply_fence_token("agent-o1", id);
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->has_value());
    REQUIRE(store.clear_release_owed("agent-o1", id, **fresh).has_value());
    CHECK_FALSE(owed_contains(store, "agent-o1"));
    // already cleared: the business error, not the fence
    auto again = store.clear_release_owed("agent-o1", id, **fresh);
    REQUIRE_FALSE(again.has_value());
    CHECK(classify_quarantine_write(again) == QuarantineWrite::not_quarantined);
}

TEST_CASE("QuarantineStore: list_release_owed_in pushes the scope and the limit into the query, and an "
          "empty scope returns nothing without a round trip",
          "[pg][quarantine][release]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());
    for (const char* agent : {"agent-w1", "agent-w2", "agent-w3"}) {
        REQUIRE(store.quarantine_device(agent, "admin", "reason", "").has_value());
        REQUIRE(store.mark_released(agent, active_row(store, agent)->id, ReleaseEnd::forced).has_value());
    }
    // a device with an active record and one owed record is not owed (its new record governs)
    REQUIRE(store.quarantine_device("agent-w1", "admin", "again", "").has_value());
    // an ended-and-confirmed record is not owed either
    REQUIRE(store.quarantine_device("agent-w4", "admin", "reason", "").has_value());
    end_record(store, "agent-w4");

    auto all = store.list_release_owed_in(nullptr, 0);
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 2);
    for (const auto& r : *all) {
        CHECK(r.status == "released");
        CHECK(r.device_release_owed_at != 0);
    }
    // list_release_owed() is the unscoped, unlimited form
    auto plain = store.list_release_owed();
    REQUIRE(plain.has_value());
    CHECK(plain->size() == 2);

    const std::vector<std::string> scope{"agent-w1", "agent-w3", "agent-w4"};
    auto scoped = store.list_release_owed_in(&scope, 0);
    REQUIRE(scoped.has_value());
    REQUIRE(scoped->size() == 1);
    CHECK((*scoped)[0].agent_id == "agent-w3");

    auto limited = store.list_release_owed_in(nullptr, 1);
    REQUIRE(limited.has_value());
    CHECK(limited->size() == 1);

    // deny-all: an empty scope matches nothing, with no round trip
    const std::vector<std::string> nobody;
    auto none = store.list_release_owed_in(&nobody, 0);
    REQUIRE(none.has_value());
    CHECK(none->empty());
}
