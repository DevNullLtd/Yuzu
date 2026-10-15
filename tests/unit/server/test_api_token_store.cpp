/**
 * test_api_token_store.cpp — Unit tests for the Postgres-backed API token
 * authentication store (PR 4.1 port, schema `api_token_store`, ADR-0006/0012).
 *
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, FAILS when it is set
 * but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour tests
 * clone a pre-migrated PgTestTemplate (one migration paid across the whole
 * file, not per test); the migration-failure test stays on plain
 * YUZU_REQUIRE_PG_DB — it needs an unmigrated database to pre-seed a
 * conflicting schema against.
 */

#include "api_token_store.hpp"
#include "engine_principal_store.hpp"
#include "engine_store_error_class.hpp" // #2404: assert the terminal-vs-transient class

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "test_api_token_pg_helper.hpp" // shared "apitoken" PgTestTemplate (one registration)


#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <expected>
#include <latch>
#include <optional>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

// The pre-migrated "apitoken" PgTestTemplate is defined once in
// test_api_token_pg_helper.hpp (as yuzu::test::apitoken_pg_template) and shared
// by every auth fixture TU. This file reuses it rather than registering a second
// callback under the same key, which used to force an extra replay-verification
// migration per suite run.

// ── Construction fail-closed ──────────────────────────────────────────────
//
// ADR-0012 §1: construction is fail-CLOSED — a reachable database whose
// schema can't migrate leaves the store !is_open(), which server.cpp wires
// to startup_failed_ (refuse to start, not serve-degraded). Force the
// failure by pre-seeding the store's schema with a conflicting table and no
// schema_meta row: the migration runner's drift guard refuses. Mirrors
// test_preflight_run_store.cpp's "reports !is_open on a migration failure".
TEST_CASE("ApiTokenStore reports !is_open on a migration failure", "[pg][token][store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA api_token_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE api_token_store.api_tokens (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ApiTokenStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ (fail-closed)
}

// #2961 round-2 finding (item 6): the post-migration projection smoke-read
// added alongside #3013's runner guard is a SECOND, independent line of
// defence — it must catch the case the runner guard itself cannot: a
// version already recorded in `public.schema_meta` (here forged directly,
// modelling a DIFFERENT binary that stamped v3 without ever running the v3
// ALTER) that does not match what the schema actually contains. Disabling
// the smoke-read left [token] 184/184 green before this test existed.
TEST_CASE("ApiTokenStore reports !is_open when schema_meta claims v3 but the schema is only "
          "at v2 (post-migration smoke-read guard, #2961 round-2)",
          "[pg][token][store][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA api_token_store")};
        REQUIRE(schema.ok());

        // v1 + v2 DDL only, copied verbatim from migrations() in
        // api_token_store.cpp — deliberately missing v3's rotation_initiator
        // column.
        PgResult v1{PQexec(conn.get(),
                           "CREATE TABLE api_token_store.api_tokens ("
                           "  token_id      TEXT PRIMARY KEY,"
                           "  token_hash    TEXT NOT NULL UNIQUE,"
                           "  name          TEXT NOT NULL,"
                           "  principal_id  TEXT NOT NULL DEFAULT '',"
                           "  scope_service TEXT NOT NULL DEFAULT '',"
                           "  mcp_tier      TEXT NOT NULL DEFAULT '',"
                           "  principal_kind TEXT NOT NULL DEFAULT 'human' "
                           "    CHECK (principal_kind IN ('human','engine')),"
                           "  created_at    BIGINT NOT NULL DEFAULT 0,"
                           "  expires_at    BIGINT NOT NULL DEFAULT 0,"
                           "  last_used_at  BIGINT NOT NULL DEFAULT 0,"
                           "  revoked       BOOLEAN NOT NULL DEFAULT FALSE);"
                           "CREATE INDEX api_tokens_principal_idx ON "
                           "api_token_store.api_tokens (principal_id)")};
        REQUIRE(v1.ok());
        PgResult v2{PQexec(
            conn.get(),
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN rotation_group TEXT NOT NULL "
            "DEFAULT '';"
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN supersedes_token_id TEXT NOT "
            "NULL DEFAULT '';"
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN overlap_expires_at BIGINT NOT "
            "NULL DEFAULT 0;"
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN confirmed_at BIGINT NOT NULL "
            "DEFAULT 0")};
        REQUIRE(v2.ok());

        // Stamp schema_meta at v3 — a LIE: the schema actually stopped at
        // v2. Models a database another binary's runner believed it already
        // migrated to v3 (so `PgMigrationRunner::run` sees nothing pending
        // and returns true), never a real v3 upgrade run against this
        // schema.
        PgResult stamp{PQexec(conn.get(),
                              "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                              "VALUES ('api_token_store', 3, extract(epoch FROM now())::bigint)")};
        REQUIRE(stamp.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ApiTokenStore store{pool};
    // The migration runner itself sees version 3 already recorded and
    // returns true trivially — construction must NOT stop there. The
    // smoke-read against every column this store's runtime queries select
    // (including rotation_initiator, missing here) is what catches the
    // forged version and fails the store closed.
    CHECK_FALSE(store.is_open());
}

// UP-7 (#2961 fix-round finding, review): every other test in this file
// clones `apitoken_pg_template`, which is already at v3 — the pre-v3 state
// elsewhere in this file is modelled by an `UPDATE ... rotation_initiator =
// ''` against an already-v3 schema, never a genuine unmigrated database. That
// leaves the ACTUAL v2->v3 upgrade path — the migration runner applying
// v3's `ALTER TABLE ... ADD COLUMN` against a real v2 database with rows
// already in it, the one state a real rolling upgrade produces — completely
// untested, and it's exactly where both the migration-numbering collision
// (item 1) and the ACCESS EXCLUSIVE lock-timing note (UP-6,
// docs/user-manual/server-admin.md) live. `YUZU_REQUIRE_PG_DB` (fresh,
// non-template) is the documented vehicle for this, per CLAUDE.md's test
// conventions section — hand-seeds v1+v2 by direct SQL (copied verbatim
// from `migrations()` in api_token_store.cpp, since that vector is
// file-local and not exported), plants `schema_meta` at v2, and inserts a
// row BEFORE handing the database to a real `ApiTokenStore` construction —
// so the v3 ALTER genuinely runs against a populated table through the real
// `PgMigrationRunner::run` path, not a synthetic one.
TEST_CASE("ApiTokenStore: a genuine v2->v3 upgrade (real ALTER against a populated table) "
          "opens cleanly and the new column is usable end-to-end (#2961 UP-7)",
          "[pg][token][store][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    std::string preexisting_token_id;
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA api_token_store")};
        REQUIRE(schema.ok());

        // v1 + v2 DDL, copied verbatim from migrations() in api_token_store.cpp.
        PgResult v1{PQexec(conn.get(),
                           "CREATE TABLE api_token_store.api_tokens ("
                           "  token_id      TEXT PRIMARY KEY,"
                           "  token_hash    TEXT NOT NULL UNIQUE,"
                           "  name          TEXT NOT NULL,"
                           "  principal_id  TEXT NOT NULL DEFAULT '',"
                           "  scope_service TEXT NOT NULL DEFAULT '',"
                           "  mcp_tier      TEXT NOT NULL DEFAULT '',"
                           "  principal_kind TEXT NOT NULL DEFAULT 'human' "
                           "    CHECK (principal_kind IN ('human','engine')),"
                           "  created_at    BIGINT NOT NULL DEFAULT 0,"
                           "  expires_at    BIGINT NOT NULL DEFAULT 0,"
                           "  last_used_at  BIGINT NOT NULL DEFAULT 0,"
                           "  revoked       BOOLEAN NOT NULL DEFAULT FALSE);"
                           "CREATE INDEX api_tokens_principal_idx ON "
                           "api_token_store.api_tokens (principal_id)")};
        REQUIRE(v1.ok());
        PgResult v2{PQexec(
            conn.get(),
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN rotation_group TEXT NOT NULL "
            "DEFAULT '';"
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN supersedes_token_id TEXT NOT "
            "NULL DEFAULT '';"
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN overlap_expires_at BIGINT NOT "
            "NULL DEFAULT 0;"
            "ALTER TABLE api_token_store.api_tokens ADD COLUMN confirmed_at BIGINT NOT NULL "
            "DEFAULT 0")};
        REQUIRE(v2.ok());
        PgResult stamp{PQexec(conn.get(),
                              "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                              "VALUES ('api_token_store', 2, extract(epoch FROM now())::bigint)")};
        REQUIRE(stamp.ok());

        // A row genuinely present BEFORE the v3 ALTER runs — the shape a
        // real populated table has mid-upgrade, not an empty one.
        preexisting_token_id = "pre-v3-token-deadbeef01";
        const char* seed_values[] = {preexisting_token_id.c_str()};
        PgResult seed{PQexecParams(
            conn.get(),
            "INSERT INTO api_token_store.api_tokens (token_id, token_hash, name, principal_id) "
            "VALUES ($1, 'pre-v3-hash', 'pre-existing', 'restart-carol')",
            1, nullptr, seed_values, nullptr, nullptr, 0)};
        REQUIRE(seed.ok());
    }

    // The real construction path: PgMigrationRunner::run reads version 2 from
    // schema_meta and applies v3's ALTER against the table seeded above.
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    // Pin the item-1(c) schema-projection smoke-read from the OUTSIDE too:
    // every runtime query this store issues (list_tokens uses the same
    // kTokenColsTail projection the constructor's own smoke-read checks) now
    // succeeds against the upgraded schema, including for the row that
    // predates the ALTER.
    auto tokens = store.list_tokens("restart-carol");
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    CHECK(tokens->at(0).token_id == preexisting_token_id);
    CHECK(tokens->at(0).rotation_initiator.empty()); // new column, DEFAULT '' on the old row

    // And a fresh mint through the now-v3 schema round-trips end-to-end.
    auto raw = store.create_token("post-upgrade", "restart-carol");
    REQUIRE(raw.has_value());
    auto validated = store.validate_token(*raw);
    REQUIRE(validated.has_value());
    CHECK(validated->principal_id == "restart-carol");
}

// #2964 fix round, chaos-injection finding: reproduces #3013's migration-
// numbering-collision hazard directly, rather than a generic drift guard.
// `PgMigrationRunner::run` skips any migration whose id is `<= the stored
// SCALAR high-water mark` — there is no applied-SET table behind it — so a
// database that reached v3 via a DIFFERENT migration (e.g. this store's
// sibling PR #2961, which independently claimed id 3 for an unrelated
// column before the two were reconciled) reports `run()` success while
// THIS store's own v4 (`rotation_retention_meta`) was never actually
// created. Pre-seed exactly that shape: a schema whose `api_tokens` table
// matches the full v1+v2 projection (so the migration runner's own v1==0
// schema-drift guard does not fire) but with NO `rotation_retention_meta`
// table, and a `schema_meta` row already claiming v3. Before the
// construction-time smoke-read this test pins, the store opened anyway —
// every subsequent `sweep_expired_rotations` tick then returned `Failed`
// forever with the schema fault silently indistinguishable from ordinary
// pool contention (finding 2's own `fail_reason`/`fail()` fix makes THAT
// half diagnosable; this test is about refusing to open at all).
TEST_CASE("ApiTokenStore fails closed at construction when rotation_retention_meta is missing "
          "despite schema_meta already claiming v4 (#3013 migration-numbering collision)",
          "[pg][token][store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA api_token_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(),
                          "CREATE TABLE api_token_store.api_tokens ("
                          "  token_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,"
                          "  name TEXT NOT NULL, principal_id TEXT NOT NULL DEFAULT '',"
                          "  scope_service TEXT NOT NULL DEFAULT '', mcp_tier TEXT NOT NULL DEFAULT '',"
                          "  principal_kind TEXT NOT NULL DEFAULT 'human',"
                          "  created_at BIGINT NOT NULL DEFAULT 0, expires_at BIGINT NOT NULL DEFAULT 0,"
                          "  last_used_at BIGINT NOT NULL DEFAULT 0, revoked BOOLEAN NOT NULL DEFAULT FALSE,"
                          "  rotation_group TEXT NOT NULL DEFAULT '',"
                          "  supersedes_token_id TEXT NOT NULL DEFAULT '',"
                          "  overlap_expires_at BIGINT NOT NULL DEFAULT 0,"
                          "  confirmed_at BIGINT NOT NULL DEFAULT 0,"
                          // v3 (#2961), seeded deliberately: without it the SIBLING
                          // projection smoke-read fails first on the missing column and
                          // this test passes for the wrong reason — green while proving
                          // nothing about the guard it names. Everything v1+v2+v3 should
                          // contain is present; ONLY v4's table is absent.
                          "  rotation_initiator TEXT NOT NULL DEFAULT '')")};
        REQUIRE(t.ok());
        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE IF NOT EXISTS public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult ins{PQexec(conn.get(),
                            "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                            // Forge at 4 — this store's CURRENT top id after #2961's v3
                            // landed first and this migration renumbered 3 -> 4. The runner
                            // sees `4 <= 4`, skips, and reports success; nothing creates
                            // rotation_retention_meta. Forging 3 would make it genuinely RUN
                            // v4 and create the table, and the test would exercise nothing.
                            "VALUES ('api_token_store', 4, 0)")};
        REQUIRE(ins.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ApiTokenStore store{pool};
    // The migration runner itself reports success (nothing to apply, v3
    // already "claimed") — the smoke-read is what refuses to open.
    CHECK_FALSE(store.is_open());
}

// ── Regression guard: behaviour preserved verbatim across the PG port ────

TEST_CASE("ApiTokenStore: create and validate token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Test Token", "admin");
    REQUIRE(result.has_value());
    CHECK(result->starts_with("yuzu_"));
    CHECK(result->size() == 37); // "yuzu_" + 32 chars

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->name == "Test Token");
    CHECK(validated->principal_id == "admin");
    CHECK(validated->created_at > 0);
}

TEST_CASE("ApiTokenStore: invalid token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto validated = store.validate_token("yuzu_invalid_token_123456789012");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: empty token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto validated = store.validate_token("");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: revoked token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Revocable", "admin");
    REQUIRE(raw.has_value());

    // Validate before revocation
    auto valid1 = store.validate_token(*raw);
    REQUIRE(valid1.has_value());

    // Revoke
    auto revoked = store.revoke_token(valid1->token_id);
    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // Validate after revocation
    auto valid2 = store.validate_token(*raw);
    CHECK(!valid2.has_value());
}

TEST_CASE("ApiTokenStore: expired token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    // Create token that expired 1 second ago
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto raw = store.create_token("Expired", "admin", now - 1);
    REQUIRE(raw.has_value());

    auto validated = store.validate_token(*raw);
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: list tokens", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    store.create_token("Token A", "alice");
    store.create_token("Token B", "alice");
    store.create_token("Token C", "bob");

    auto all = store.list_tokens().value();
    CHECK(all.size() == 3);

    auto alice_tokens = store.list_tokens("alice").value();
    CHECK(alice_tokens.size() == 2);

    auto bob_tokens = store.list_tokens("bob").value();
    CHECK(bob_tokens.size() == 1);

    // Token hashes should never be exposed in listings
    for (const auto& t : all)
        CHECK(t.token_hash.empty());
}

TEST_CASE("ApiTokenStore: delete token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Deletable", "admin");
    REQUIRE(raw.has_value());

    auto valid = store.validate_token(*raw);
    REQUIRE(valid.has_value());

    auto deleted = store.delete_token(valid->token_id);
    REQUIRE(deleted.has_value());
    CHECK(*deleted);

    auto after = store.validate_token(*raw);
    CHECK(!after.has_value());

    auto list = store.list_tokens().value();
    CHECK(list.empty());
}

TEST_CASE("ApiTokenStore: last_used_at updated on validation", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Usage", "admin");
    REQUIRE(raw.has_value());

    auto before = store.list_tokens().value();
    REQUIRE(before.size() == 1);
    CHECK(before[0].last_used_at == 0);

    store.validate_token(*raw);

    auto after = store.list_tokens().value();
    REQUIRE(after.size() == 1);
    CHECK(after[0].last_used_at > 0);
}

TEST_CASE("ApiTokenStore: empty name rejected", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto result = store.create_token("", "admin");
    CHECK(!result.has_value());
}

TEST_CASE("ApiTokenStore: revoke nonexistent token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto revoked = store.revoke_token("nonexistent");
    REQUIRE(revoked.has_value()); // DB write ran fine — the id just didn't exist
    CHECK_FALSE(*revoked);
}

// ── get_token: metadata lookup for owner-scoped revoke (#222) ────────────────

TEST_CASE("ApiTokenStore: get_token returns metadata for ownership check",
          "[pg][token][crud][owner]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Alice's token", "alice");
    REQUIRE(raw.has_value());
    auto listing = store.list_tokens("alice").value();
    REQUIRE(listing.size() == 1);
    auto token_id = listing[0].token_id;

    auto looked_up = store.get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->token_id == token_id);
    CHECK(looked_up->principal_id == "alice");
    CHECK(looked_up->name == "Alice's token");
    CHECK(looked_up->revoked == false);
    // The raw hash must never surface through metadata lookups.
    CHECK(looked_up->token_hash.empty());
}

TEST_CASE("ApiTokenStore: get_token returns nullopt for unknown id",
          "[pg][token][crud][owner]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    CHECK(!store.get_token("does-not-exist").value().has_value());
    CHECK(!store.get_token("").value().has_value());
}

TEST_CASE("ApiTokenStore: list_tokens(principal) scopes results to owner",
          "[pg][token][crud][owner]") {
    // Gate 4 consistency auditor finding C1: the Settings dashboard
    // `render_api_tokens_fragment` previously called list_tokens() with no
    // principal filter, rendering every user's token IDs, names, owners,
    // timestamps, and MCP tiers in the HTMX response body to anyone
    // holding `ApiToken:Read`. The fix scopes the fragment by
    // `session->username` for non-admin sessions. This test pins the
    // underlying store contract the fix depends on: list_tokens(principal)
    // must return ONLY that principal's tokens, with no leakage across
    // owners.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    REQUIRE(store.create_token("alice-a", "alice").has_value());
    REQUIRE(store.create_token("alice-b", "alice").has_value());
    REQUIRE(store.create_token("bob-a", "bob").has_value());
    REQUIRE(store.create_token("root-a", "root").has_value());

    auto alice_tokens = store.list_tokens("alice").value();
    auto bob_tokens = store.list_tokens("bob").value();
    auto root_tokens = store.list_tokens("root").value();
    auto all_tokens = store.list_tokens().value();

    REQUIRE(alice_tokens.size() == 2);
    REQUIRE(bob_tokens.size() == 1);
    REQUIRE(root_tokens.size() == 1);
    REQUIRE(all_tokens.size() == 4);

    // Every token returned for alice is owned by alice — no cross-contamination.
    for (const auto& t : alice_tokens)
        CHECK(t.principal_id == "alice");
    for (const auto& t : bob_tokens)
        CHECK(t.principal_id == "bob");
    for (const auto& t : root_tokens)
        CHECK(t.principal_id == "root");

    // Bob's name does not appear in alice's listing under any column.
    for (const auto& t : alice_tokens) {
        CHECK(t.name != "bob-a");
        CHECK(t.name != "root-a");
    }
}

TEST_CASE("ApiTokenStore: get_token distinguishes owners for IDOR defense",
          "[pg][token][crud][owner]") {
    // This test encodes the core invariant that the REST DELETE handler
    // relies on to close #222: looking up a token by id must surface the
    // owning principal_id so the handler can reject cross-user revokes.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    REQUIRE(store.create_token("alice-key", "alice").has_value());
    REQUIRE(store.create_token("bob-key", "bob").has_value());

    auto alice_tokens = store.list_tokens("alice").value();
    auto bob_tokens = store.list_tokens("bob").value();
    REQUIRE(alice_tokens.size() == 1);
    REQUIRE(bob_tokens.size() == 1);

    auto alice_looked_up = store.get_token(alice_tokens[0].token_id).value();
    auto bob_looked_up = store.get_token(bob_tokens[0].token_id).value();
    REQUIRE(alice_looked_up.has_value());
    REQUIRE(bob_looked_up.has_value());
    CHECK(alice_looked_up->principal_id == "alice");
    CHECK(bob_looked_up->principal_id == "bob");
    CHECK(alice_looked_up->principal_id != bob_looked_up->principal_id);
}

// ── New coverage (PR 4.1): principal_kind ─────────────────────────────────

TEST_CASE("ApiTokenStore: principal_kind defaults to 'human' for a row inserted without it",
          "[pg][token][crud][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    // Bypass principal_kind entirely — the column's DEFAULT 'human' must
    // apply, mirroring every pre-port token row (the migration adds the
    // column with that default; existing rows never set it explicitly).
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.api_tokens (token_id, token_hash, name, principal_id) "
            "VALUES ($1,$2,$3,$4)",
            std::vector<std::string>{"legacy-row", "legacy-row-hash", "Legacy Token", "admin"});
        REQUIRE(res.ok());
    }

    auto looked_up = store.get_token("legacy-row").value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->principal_kind == "human");

    auto listing = store.list_tokens("admin").value();
    REQUIRE(listing.size() == 1);
    CHECK(listing[0].principal_kind == "human");
}

// PR 4.1 keeps principal_kind INERT: `create_token` has no parameter to write
// "engine" (that write path + its lifecycle/tier/referential checks land in
// PR 4.2, design doc §§6-8/11), so the ONLY thing this store mints is "human".
// The seam is proven two ways: the create path is pinned to "human", and the
// column's CHECK is the schema-level allowlist that bounds any direct write.
// (A previous revision of this test minted an `engine` token through
// `create_token(..., "engine")` and asserted it round-tripped — that enshrined
// an engine code path the attribution layer does not yet honour; removed.)
TEST_CASE("ApiTokenStore: create_token pins principal_kind to 'human'; the CHECK bounds the column",
          "[pg][token][crud][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    // Engine block prerequisites (design doc §6/§7/§8): mcp_tier must be
    // "readonly", expires_at must be non-zero and within the 90-day ceiling,
    // and the referent resolver must be wired — a stub reporting Active,
    // matching how server.cpp wires the real EnginePrincipalStore.
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto human_raw = store.create_token("human-token", "alice");
    REQUIRE(human_raw.has_value());
    // The get_token/validate paths returning std::expected are covered by the
    // dedicated PR-4.1 read tests below; here we assert both the human and the
    // engine mint paths succeed against the wired referent check.
    auto v = store.validate_token(*human_raw);
    REQUIRE(v.has_value());
    CHECK(v->principal_kind == "human");
    auto meta = store.get_token(v->token_id).value();
    REQUIRE(meta.has_value());
    CHECK(meta->principal_kind == "human");
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto engine_raw =
        store.create_token("engine-token", "svc-ci", now + 3600, "", "readonly", "engine");
    REQUIRE(engine_raw.has_value());
    auto ev = store.validate_token(*engine_raw);
    REQUIRE(ev.has_value());
    CHECK(ev->principal_kind == "engine");

    // (b) The column CHECK is the schema-level allowlist: a direct write of a
    // value outside ('human','engine') is rejected at the database, never
    // silently stored. ('engine' itself is in the allowlist — it is the seam
    // PR 4.2 will use — so we probe with a value the allowlist excludes.)
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.api_tokens "
            "(token_id, token_hash, name, principal_id, principal_kind) VALUES ($1,$2,$3,$4,$5)",
            std::vector<std::string>{"bad-kind", "bad-kind-hash", "Bad Kind", "admin", "robot"});
        CHECK_FALSE(res.ok()); // CHECK (principal_kind IN ('human','engine')) violation
    }
}

// ── New coverage (PR 4.1): RETURNING-based mutate-and-return idiom (#1033) ─

TEST_CASE("ApiTokenStore: revoke_token RETURNING contract — false for an unknown id, true "
          "and cache-invalidated for a real one",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto miss = store.revoke_token("does-not-exist");
    REQUIRE(miss.has_value()); // DB write ran; nothing matched (a real 404, not an error)
    CHECK_FALSE(*miss);

    auto raw = store.create_token("returning-revoke", "admin");
    REQUIRE(raw.has_value());
    auto validated = store.validate_token(*raw); // populates the in-memory cache
    REQUIRE(validated.has_value());
    CHECK(store.cache_size() == 1);

    auto hit = store.revoke_token(validated->token_id);
    REQUIRE(hit.has_value());
    CHECK(*hit);
    // Cache invalidation: a follow-up validate must not resurrect the
    // pre-revoke cached (revoked=false) entry within the 60s TTL window —
    // it must fall through to Postgres and see revoked=TRUE.
    CHECK_FALSE(store.validate_token(*raw).has_value());
}

TEST_CASE("ApiTokenStore: delete_token RETURNING contract — false for an unknown id, true "
          "and cache-invalidated for a real one",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    CHECK_FALSE(store.delete_token("does-not-exist").value());

    auto raw = store.create_token("returning-delete", "admin");
    REQUIRE(raw.has_value());
    auto validated = store.validate_token(*raw);
    REQUIRE(validated.has_value());

    CHECK(store.delete_token(validated->token_id).value());
    CHECK_FALSE(store.validate_token(*raw).has_value());
    CHECK_FALSE(store.get_token(validated->token_id).value().has_value());
}

TEST_CASE("ApiTokenStore: revoke_for_principal returns the exact affected count and "
          "invalidates every cached hash",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto r1 = store.create_token("p1", "carol");
    auto r2 = store.create_token("p2", "carol");
    auto r3 = store.create_token("other-owner", "dave");
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    REQUIRE(r3.has_value());

    // Populate the cache for all three so invalidation is actually exercised.
    REQUIRE(store.validate_token(*r1).has_value());
    REQUIRE(store.validate_token(*r2).has_value());
    REQUIRE(store.validate_token(*r3).has_value());
    CHECK(store.cache_size() == 3);

    auto n = store.revoke_for_principal("carol");
    REQUIRE(n.has_value());
    CHECK(*n == 2);

    // Carol's tokens are gone even via cache (invalidated) — not merely
    // revoked-in-the-database-but-still-cached-valid.
    CHECK_FALSE(store.validate_token(*r1).has_value());
    CHECK_FALSE(store.validate_token(*r2).has_value());
    // Dave's token, and his cache entry, are untouched.
    CHECK(store.validate_token(*r3).has_value());

    // No principal / unknown principal is a strict no-op — never a fail-open
    // "revoked everything", and (post PR-4.1 typed result) never an error:
    // the DB write ran and simply matched nothing.
    auto none = store.revoke_for_principal("nobody");
    REQUIRE(none.has_value());
    CHECK(*none == 0);
    auto empty = store.revoke_for_principal("");
    REQUIRE(empty.has_value()); // empty principal is an argument guard, not a DB failure
    CHECK(*empty == 0);
}

// PR 4.1 typed-revoke contract (ADR-0030 §Posture): a revoke whose DB write
// does NOT land must return `unexpected`, never a value that reads as "nothing
// matched" — otherwise "Sign out everywhere" reports success during an outage.
// Force a deterministic write failure by dropping the table out from under an
// open store (each YUZU_REQUIRE_PG_DB_TPL test gets its own clone, so this
// cannot bleed into another case). Before the typed result both calls returned
// 0/false — indistinguishable from a clean "no such token", the exact silent
// success this PR's review blocked.
TEST_CASE("ApiTokenStore: revoke surfaces a DB write failure as unexpected, not a false 'no match'",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("victim", "erin");
    REQUIRE(raw.has_value());
    auto v = store.validate_token(*raw);
    REQUIRE(v.has_value());

    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto drop = pg::exec_params(lease.get(), "DROP TABLE api_token_store.api_tokens",
                                    std::vector<std::string>{});
        REQUIRE(drop.ok());
    }

    auto single = store.revoke_token(v->token_id);
    CHECK_FALSE(single.has_value()); // DB error → unexpected, NOT value(false)

    auto bulk = store.revoke_for_principal("erin");
    CHECK_FALSE(bulk.has_value()); // DB error → unexpected, NOT value(0)
}

// ── New coverage (PR 4.1): revoke_generation_ cache TOCTOU guard ─────────
//
// The header/impl comment (api_token_store.hpp/.cpp) documents the contract:
// under the pool there is no single connection-wide mutex serializing a
// validate_token's SELECT against a concurrent revoke_token's UPDATE the way
// the old sqlite db_mtx_ did, so revoke_generation_ is the SOLE guard against
// a stale (revoked=false) cache write surviving a race.
//
// A literal single-threaded reproduction is not possible through the public
// API alone (there is no injection point to pause validate_token between its
// snapshot and its cache-write re-check without a store-side test hook,
// which is out of this port's scope). This test instead makes the race
// reliable — not luck-dependent — by exploiting a structural asymmetry:
// validate_token needs TWO sequential Postgres round trips (SELECT, then the
// last_used_at UPDATE) before it reaches the generation re-check, while
// revoke_token's generation bump is an in-memory fetch_add that runs BEFORE
// its own single UPDATE round trip even starts. Releasing both calls from
// the same std::latch means revoke_token's bump is essentially guaranteed to
// land inside validate_token's window every run on any real machine (an
// atomic increment vs. two live network round trips), so this is
// deterministic in practice even though it is two threads, not one.
TEST_CASE("ApiTokenStore: revoke_generation_ guard prevents a stale cache write racing a "
          "concurrent revoke",
          "[pg][token][auth][toctou]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("race-token", "admin");
    REQUIRE(raw.has_value());
    auto listing = store.list_tokens("admin").value();
    REQUIRE(listing.size() == 1);
    auto token_id = listing[0].token_id;

    std::latch start{2};
    std::optional<ApiToken> validated;
    std::expected<bool, std::string> revoked;
    std::thread t_validate([&] {
        start.arrive_and_wait();
        validated = store.validate_token(*raw);
    });
    std::thread t_revoke([&] {
        start.arrive_and_wait();
        revoked = store.revoke_token(token_id);
    });
    t_validate.join();
    t_revoke.join();

    REQUIRE(revoked.has_value());
    CHECK(*revoked);
    // Whatever validate_token itself returned for THIS race is secondary —
    // the guard's job is that no STALE cache entry survives. Assert against
    // the cache directly: a follow-up validate_token (strictly after both
    // threads have joined) must never resurrect a pre-revoke "still valid"
    // answer from a racy cache write.
    auto after = store.validate_token(*raw);
    CHECK_FALSE(after.has_value());
}

TEST_CASE("ApiTokenStore: the post-commit generation bump prevents a validate that read "
          "pre-commit data from poisoning the cache",
          "[pg][token][auth][toctou]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}}; // revoke + validate each need a lease concurrently
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("poison-token", "admin");
    REQUIRE(raw.has_value());
    auto id = store.list_tokens("admin").value().at(0).token_id;

    // Do NOT validate raw before the race — its cache must start empty.

    std::binary_semaphore first_bump_done{0};
    std::binary_semaphore release_revoke{0};
    std::binary_semaphore validate_selected{0};
    std::binary_semaphore release_validate{0};

    store.test_hook_after_first_revoke_bump_ = [&] {
        first_bump_done.release(); // tell main the first bump landed
        release_revoke.acquire();  // pause revoke here (before its UPDATE) until main lets it proceed
    };
    store.test_hook_after_validate_select_ = [&] {
        validate_selected.release(); // tell main the SELECT (pre-commit read) is done
        release_validate.acquire();  // pause validate before its generation re-check until main lets it proceed
    };

    std::expected<bool, std::string> revoked;
    std::optional<ApiToken> validated;
    std::thread t_revoke([&] { revoked = store.revoke_token(id); });
    first_bump_done.acquire(); // first bump done; revoke paused before UPDATE (row still revoked=false)

    std::thread t_validate([&] { validated = store.validate_token(*raw); });
    validate_selected.acquire(); // validate snapshotted gen (post-first-bump), SELECTed revoked=false, paused before re-check

    release_revoke.release(); // let revoke finish: UPDATE commit + SECOND bump + invalidate_cache
    t_revoke.join();          // ensure revoke's invalidate ran BEFORE validate's re-check/insert

    release_validate.release(); // let validate do its re-check (must observe the second bump -> skip cache write)
    t_validate.join();

    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // Clear hooks so the verification call runs normally.
    store.test_hook_after_first_revoke_bump_ = nullptr;
    store.test_hook_after_validate_select_ = nullptr;

    // THE ASSERTION THAT ISOLATES THE FIX: no poisoned entry survives. Without the
    // post-commit second bump, validate's re-check would have matched its snapshot
    // and cached the stale revoked=false row (inserted after revoke's invalidate),
    // and this next call would resurrect the revoked token from cache.
    auto after = store.validate_token(*raw);
    CHECK_FALSE(after.has_value());
}

// ── New coverage (PR 4.3): overlap-pair credential rotation, design doc §7 ─

namespace {

int64_t test_now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

constexpr int64_t kDay = 24 * 3600;
constexpr int64_t k90Days = 90 * kDay;
constexpr int64_t kDefaultOverlapSecs = 7 * kDay;

// Direct-SQL peek at a token row's raw `token_hash` column — used only to
// prove the raw secret was never persisted anywhere, not exercised through
// the store's own (hash-masking) public API.
std::string raw_hash_column(PgPool& pool, const std::string& token_id) {
    auto lease = pool.acquire();
    if (!lease)
        return {};
    pg::PgResult res =
        pg::exec_params(lease.get(),
                        "SELECT token_hash FROM api_token_store.api_tokens WHERE token_id = $1",
                        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return {};
    return PQgetvalue(res.get(), 0, 0);
}

// RAII reset for any ApiTokenStore `std::function<void(pg_conn*)>` test-only
// hook member (test_hook_before_rotate_group_read_,
// test_hook_before_mint_commit_, and any future sibling of the same shape —
// takes the member BY REFERENCE rather than hardcoding one, so a second
// hook never needs its own hand-rolled copy of this class). A manual
// set/clear pair leaves the hook armed for the rest of the TEST_CASE if a
// REQUIRE/CHECK inside the guarded scope fails (Catch2 throws on assertion
// failure) — exactly the non-RAII cleanup shape this repo blocks in
// production code; this guard exists so no test needs to hand-roll that
// pattern for a new hook (round 6: a test doing exactly that for
// test_hook_before_mint_commit_, four REQUIREs deep in the hook body, was
// the defect this generalisation closes).
// SAVES AND RESTORES the prior value (rather than resetting to `nullptr`) —
// today the prior value is always null (the store is otherwise unhooked), but
// a save/clear-to-null guard would silently corrupt a nested or sequenced use
// (this exact class re-armed inside another guarded scope, or two of these in
// the same TEST_CASE), which its own doc comment above invites.
class ScopedPgConnHook {
public:
    ScopedPgConnHook(std::function<void(pg_conn*)>& slot, std::function<void(pg_conn*)> hook)
        : slot_(slot), prior_(std::move(slot_)) {
        slot_ = std::move(hook);
    }
    ~ScopedPgConnHook() { slot_ = std::move(prior_); }
    ScopedPgConnHook(const ScopedPgConnHook&) = delete;
    ScopedPgConnHook& operator=(const ScopedPgConnHook&) = delete;

private:
    std::function<void(pg_conn*)>& slot_;
    std::function<void(pg_conn*)> prior_;
};

// P2 #11: manually wires two already-created tokens into the overlap-pair
// rotation shape `rotate_engine_credential` (and, for a human principal, the
// sibling `rotate_token`, both present in this tree) would leave behind:
// predecessor gets `rotation_group` + `overlap_expires_at`; successor gets
// the SAME `rotation_group` + `supersedes_token_id == predecessor's
// token_id`. `rotate_token` itself always produces a well-formed pair
// through its own validation, so this direct-SQL seam exists ONLY for tests
// that need an arbitrary/malformed pair shape (e.g. an orphaned or
// mismatched group) `rotate_token`'s own validation would refuse to create —
// matching the file's existing direct-SQL precedent (raw_hash_column above,
// the F3 trigger seam below).
void wire_manual_rotation_pair(PgPool& pool, const std::string& rotation_group,
                               const std::string& predecessor_id, const std::string& successor_id,
                               int64_t overlap_expires_at) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r1 = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET rotation_group = $1, overlap_expires_at = $2 "
        "WHERE token_id = $3",
        std::vector<std::string>{rotation_group, std::to_string(overlap_expires_at), predecessor_id});
    REQUIRE(r1.ok());
    pg::PgResult r2 = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET rotation_group = $1, supersedes_token_id = $2 "
        "WHERE token_id = $3",
        std::vector<std::string>{rotation_group, predecessor_id, successor_id});
    REQUIRE(r2.ok());
}

// #2964: PostgreSQL's OWN clock, queried directly — the T12 rotation
// sweep's clock-guard DECISION reads it inside its own session-locked
// transaction, not the `now` argument a caller passes to
// `sweep_expired_rotations` (mirrors `AuditStore::cleanup_once`'s identical
// divergence; `test_audit_store.cpp` carries the same helper under the
// name `pg_now`). Sweep tests below force a predecessor's
// `overlap_expires_at` relative to THIS reading — never rely on a
// synthetic future `now` argument to "time-travel" the eligibility
// decision, which no longer works once the decision reads PG's own clock.
int64_t pg_now(PgPool& pool) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r{PQexec(lease.get(), "SELECT EXTRACT(EPOCH FROM now())::bigint")};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    return std::stoll(PQgetvalue(r.get(), 0, 0));
}

// Force an EXISTING predecessor row's overlap window to a specific instant
// (typically already-elapsed relative to `pg_now`) via a direct UPDATE —
// simulates "the window has now elapsed" without an actual wall-clock
// wait. Narrower than `wire_manual_rotation_pair` above (which also wires
// the rotation_group/supersedes_token_id linkage for a FRESH pair) — this
// only rewrites the deadline on a pair `rotate_engine_credential`/
// `rotate_token` already minted correctly.
void force_overlap_expires_at(PgPool& pool, const std::string& token_id,
                              int64_t overlap_expires_at) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET overlap_expires_at = $1 WHERE token_id = $2",
        std::vector<std::string>{std::to_string(overlap_expires_at), token_id});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

// #2964: settle this store's clock-guard bootstrap marker with a pass over
// an EMPTY table (nothing eligible yet, so `!has_expired` short-circuits
// to `Anomaly::None` before `no_anchor` is even tested — routed concern
// part 6) — mirrors `AuditStore`'s own `anchor_guard`
// (`test_audit_store.cpp`). Needed because almost every sweep test below is
// about something else (the auto-revoke shape, UP-5, UP-6) and each would
// otherwise spend its FIRST-ever pass on a fresh `YUZU_REQUIRE_PG_DB_TPL`
// clone absorbing a bootstrap decline it never meant to exercise. Call
// BEFORE minting any rotation pair.
void anchor_sweep_guard(ApiTokenStore& store, int64_t now) {
    auto r = store.sweep_expired_rotations(now);
    REQUIRE(r.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(r.revoked.empty());
}

// #2964: mint one harmless companion rotation pair whose overlap window
// stays comfortably in the future. Originally existed so a test's OWN
// single- (or few-) pair setup elapsing all at once was not indistinguishable
// from a genuine would-wipe clock jump; this store no longer adopts the
// would-wipe probe at all (`Facts::would_wipe` is hardcoded `false` — see
// the DELIBERATE NON-ADOPTION comment near `kRotationSweepBigStepSecs`'s
// definition), so calling this is no longer load-bearing for THAT reason.
// Kept at existing call sites anyway (removing 10 call sites is not this
// change's job) and still harmless — it simply adds one more live,
// non-interfering rotation pair to the fixture. Call once per test that
// expects an actual DRAIN, under a principal the test itself never
// otherwise touches.
void seed_sweep_survivor(ApiTokenStore& store, int64_t now, const std::string& survivor_principal) {
    REQUIRE(store.create_token("survivor-pred", survivor_principal, now + k90Days).has_value());
    const std::string pred_id = store.list_active_for_principal(survivor_principal)[0].token_id;
    auto rotated = store.rotate_token(pred_id, kDay, now, survivor_principal, "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
}

} // namespace

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a HUMAN rotation pair's swept predecessor "
          "reports principal_kind=='human' — the signal server.cpp's sweep driver "
          "(rotation_sweep_names_for_kind) keys its metric/audit routing on (P2 #11)",
          "[pg][token][rotation][sweep][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string principal = "alice-p2-11-sweep";
    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    seed_sweep_survivor(store, now, "alice-p2-11-sweep-survivor");

    // principal_kind defaults to "human" — create_token's public signature
    // has no way to mint anything else without ALSO passing "engine" (which
    // triggers the engine-only referent-check block), so the default arm
    // exercised here IS the human path under test.
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    auto succ_raw = store.create_token("succ", principal, now + k90Days);
    REQUIRE(succ_raw.has_value());

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = active[0].name == "pred" ? &active[0] : &active[1];
    const ApiToken* successor = active[0].name == "succ" ? &active[0] : &active[1];
    REQUIRE(predecessor->principal_kind == "human");
    REQUIRE(successor->principal_kind == "human");

    // UP-5: the sweep only auto-revokes when the successor has been
    // presented at least once — present it here so this test (which is
    // about principal_kind routing, not UP-5 itself) still exercises the
    // auto-revoke path.
    REQUIRE(store.validate_token(*succ_raw).has_value());

    // Overlap window already elapsed — this tick's sweep must pick it up.
    wire_manual_rotation_pair(pool, predecessor->token_id, predecessor->token_id,
                              successor->token_id, now - 1);

    auto swept = store.sweep_expired_rotations(now);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(swept.revoked.size() == 1);
    CHECK(swept.revoked[0].token_id == predecessor->token_id);
    // THE ASSERTION THIS TEST EXISTS FOR: the store hands the driver a real
    // "human" tag on the swept row — not a value that quietly defaults to
    // "engine" or gets lost between the scan and the returned ApiToken. A
    // wrong value here would misroute EVERY human rotation to the engine
    // metric/audit family regardless of how correct the driver's own
    // branching logic is.
    CHECK(swept.revoked[0].principal_kind == "human");
}

TEST_CASE("ApiTokenStore::list_rotations_nearing_expiry_unused: a HUMAN pair nearing expiry "
          "reports principal_kind=='human' on BOTH halves of the returned pair (P2 #11)",
          "[pg][token][rotation][sweep][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string principal = "alice-p2-11-nearing";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    REQUIRE(store.create_token("succ", principal, now + k90Days).has_value());

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = active[0].name == "pred" ? &active[0] : &active[1];
    const ApiToken* successor = active[0].name == "succ" ? &active[0] : &active[1];

    // Window ends 1h from now (inside a 24h warn lead); successor's
    // last_used_at stays 0 (create_token never touches it) — the "never
    // presented" precondition this half's query requires.
    wire_manual_rotation_pair(pool, predecessor->token_id, predecessor->token_id,
                              successor->token_id, now + 3600);

    // #2964 fix round finding 7: this half now reads PostgreSQL's own clock
    // internally (see `NearingExpiryResult::pg_now`) instead of taking a
    // caller-supplied `now` — mirrors the `sweep_expired_rotations` tests'
    // existing `pg_now(pool)`/`force_overlap_expires_at` idiom above.
    auto nearing = store.list_rotations_nearing_expiry_unused(24 * 3600);
    REQUIRE(nearing.pairs.size() == 1);
    CHECK(nearing.pairs[0].predecessor.token_id == predecessor->token_id);
    CHECK(nearing.pairs[0].successor.token_id == successor->token_id);
    // Both halves must carry "human" — server.cpp's successor-unused path
    // keys its family/action off pair.predecessor.principal_kind.
    CHECK(nearing.pairs[0].predecessor.principal_kind == "human");
    CHECK(nearing.pairs[0].successor.principal_kind == "human");
}

// #2964 fix round item 4: pin the rotation SLA `docs/user-manual/authentication.md`
// and `docs/user-manual/engine-principals.md` now state explicitly — "a
// predecessor is revoked within one 60-second tick of its overlap window
// elapsing; on the first occurrence of a given clock-anomaly type the tick
// declines instead and revocation defers to the next tick (roughly 120
// seconds total)". Deliberately does NOT call `anchor_sweep_guard` first
// (every other sweep test in this file does, precisely to AVOID exercising
// this path) — the very first sweep this store ever runs, against the very
// first rotation pair it ever sees, IS the bootstrap case the SLA text is
// making a claim about, and it needs a genuinely fresh
// `YUZU_REQUIRE_PG_DB_TPL` clone (no prior `rotation_retention_meta` row) to
// reach it.
//
// Chaos-injection measured the PRE-fix behaviour as TWO declined ticks
// (facts "ew--b" then "ew---") for exactly this scenario, because
// `would_wipe` was true for a lone elapsed pair with no population floor —
// the bootstrap tick declined on the COMBINED no-anchor+would-wipe fact set,
// and the very next tick (anchor now settled, would_wipe still true)
// declined AGAIN on a fact set that had changed only in its `no_anchor` bit,
// so fact-set dedup did not suppress it. `api_token_store.cpp`'s current
// shape closes that differently from the round-2 fix's population-floor
// attempt (which was itself found, in round 3 review, to move the swallow
// above the floor rather than close it — see the DELIBERATE NON-ADOPTION
// comment near `kRotationSweepBigStepSecs`'s definition): `would_wipe` is
// now hardcoded `false` for this store, so the bootstrap tick's facts are
// always `e---b` (has_expired + no_anchor only) — `Anomaly::NoAnchor` — and
// the tick immediately after re-anchors with `no_anchor` now false and
// (given the ~60s the test itself takes, nowhere close to
// `kRotationSweepBigStepSecs` = 1h) `big_step` false too, so its facts are
// `e----` and `classify()` returns `Anomaly::None` — an ordinary accepted,
// draining tick.
TEST_CASE("ApiTokenStore::sweep_expired_rotations: a fresh database's FIRST-ever rotation "
          "declines exactly ONE bootstrap tick, then drains on the very next tick — the "
          "SLA docs/user-manual/authentication.md and engine-principals.md promise",
          "[pg][token][rotation][sweep][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string principal = "alice-sla-bootstrap";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;

    auto succ_raw = store.rotate_token(pred_id, kDefaultOverlapSecs, now, principal, "", "");
    REQUIRE(succ_raw.has_value());
    // UP-5: the sweep only auto-revokes once the successor has been
    // presented at least once.
    REQUIRE(store.validate_token(*succ_raw).has_value());

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = active[0].token_id == pred_id ? &active[0] : &active[1];

    // Overlap window already elapsed relative to PostgreSQL's own clock —
    // the sweep's decision reads that, not a caller-supplied `now`.
    force_overlap_expires_at(pool, predecessor->token_id, pg_now(pool) - 1);

    // Tick 1: the very first pass this store has ever run, over a table with
    // one eligible, already-elapsed pair and no durable anchor yet — the
    // bootstrap case. Must decline, not revoke.
    auto tick1 = store.sweep_expired_rotations(now);
    CHECK(tick1.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(tick1.decline_anomaly == audit_retention::Anomaly::NoAnchor);
    // #2964 round 3 review (finding 2): `no_anchor` is the RAW fact
    // server.cpp's metric split routes on — pinned separately from
    // `decline_anomaly` because a future fact collision could make the two
    // disagree (see `SweepResult::no_anchor`'s own doc comment).
    CHECK(tick1.no_anchor);
    CHECK(tick1.revoked.empty());

    // Tick 2 (the "next 60-second tick" the docs describe): the anchor is
    // now settled, so this pass proceeds to classify and drain normally —
    // this is the assertion that PINS the docs' "~120 seconds total, not
    // two declined ticks" claim.
    auto tick2 = store.sweep_expired_rotations(now);
    CHECK(tick2.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(tick2.revoked.size() == 1);
    CHECK(tick2.revoked[0].token_id == predecessor->token_id);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects an overlap window below the 24h "
          "floor",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto now = test_now_epoch();
    // No active credential exists at all — the floor check still fires
    // first (pure math, no DB dependency), and its message is distinct from
    // the "no active credential" rejection.
    auto rotated =
        store.rotate_engine_credential("engine:rotation-floor", kDay - 1, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("floor") != std::string::npos);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential with no active credential is rejected",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto now = test_now_epoch();
    auto rotated = store.rotate_engine_credential("engine:rotation-empty", kDefaultOverlapSecs,
                                                  now, "admin");
    REQUIRE_FALSE(rotated.has_value());
}

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects a window exceeding the "
          "predecessor's own expiry rather than truncating it",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-tight-expiry";
    auto now = test_now_epoch();
    // Predecessor expires in 1h — a 24h (floor) overlap window cannot fit
    // before it, so the mint must be rejected, not silently shrunk.
    auto minted =
        store.create_token("tight", principal, now + 3600, "", "readonly", "engine");
    REQUIRE(minted.has_value());

    auto rotated = store.rotate_engine_credential(principal, kDay, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("expiry") != std::string::npos);

    // Rejected mint must not have minted a successor.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 1);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential mints a successor, stamps the rotation "
          "pair, and returns the raw secret exactly once — never persisted",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-mint";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto before = store.list_active_for_principal(principal);
    REQUIRE(before.size() == 1);
    const std::string predecessor_id = before[0].token_id;

    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    CHECK(rotated->starts_with("yuzu_"));
    CHECK(*rotated != *predecessor_raw);

    auto after = store.list_active_for_principal(principal);
    REQUIRE(after.size() == 2);

    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : after) {
        CHECK(t.token_hash.empty()); // masked, per list_active_for_principal's contract
        if (t.token_id == predecessor_id)
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);

    CHECK_FALSE(predecessor->rotation_group.empty());
    CHECK(predecessor->rotation_group == successor->rotation_group);
    CHECK(predecessor->overlap_expires_at == now + kDefaultOverlapSecs);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
    CHECK(predecessor->supersedes_token_id.empty());

    // The raw secret is never stored — only its SHA-256 hash.
    auto stored_hash = raw_hash_column(pool, successor->token_id);
    CHECK_FALSE(stored_hash.empty());
    CHECK(stored_hash != *rotated);
    CHECK(stored_hash.size() == 64); // hex-encoded SHA-256
}

TEST_CASE("ApiTokenStore: rotate_engine_credential re-serves the same raw within the grace "
          "window, and never mints a third credential",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-reserve";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto first = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(first.has_value());

    // Retry "immediately" (a lost-response / dropped-connection scenario) —
    // must re-serve the SAME successor raw, never mint a new one, PROVIDED
    // the retry comes from the SAME operator who initiated the rotation
    // (Hermes F4).
    auto retry = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(retry.has_value());
    CHECK(*retry == *first);

    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2); // still exactly the predecessor + one successor
}

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects a grace-window re-serve to a "
          "different operator than the one who initiated the rotation",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-reserve-wrong-user";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto first = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(first.has_value());

    // A DIFFERENT operator retrying within the grace window must never
    // receive admin's in-flight successor secret (Hermes F4).
    auto stolen = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "mallory");
    REQUIRE_FALSE(stolen.has_value());
    CHECK(stolen.error().find("different operator") != std::string::npos);

    // The rejection did not mint a third credential, and the SAME operator
    // can still re-serve successfully afterward.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);

    auto retry_same_user =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(retry_same_user.has_value());
    CHECK(*retry_same_user == *first);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects a retry once the grace window has "
          "elapsed — no third credential is ever minted",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-grace-lapsed";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto first = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(first.has_value());

    // Simulate the grace window (kRotationGraceSecs, 120s) lapsing by
    // advancing the caller-supplied `now` rather than sleeping — the epoch
    // side of the idempotency check (now - successor.created_at) is what
    // gates this, independent of wall-clock elapsed time.
    auto lapsed_now = now + 300;
    auto retry =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, lapsed_now, "admin");
    REQUIRE_FALSE(retry.has_value());
    CHECK(retry.error().find("grace") != std::string::npos);

    // No third credential was minted by the rejected retry.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential defensively rejects when three active "
          "credentials already exist for the principal (the ≤2 ceiling holds even against a "
          "credential minted outside rotate)",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-over-ceiling";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("a", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("b", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("c", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.list_active_for_principal(principal).size() == 3);

    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("more than two") != std::string::npos);

    // Never picks one to arbitrate — the count stays exactly 3, no fourth
    // credential minted either.
    CHECK(store.list_active_for_principal(principal).size() == 3);
}

// ── Hermes review (PR 4.3 round 2): F1-F5 hardening ───────────────────────

TEST_CASE("ApiTokenStore: concurrent rotate_engine_credential calls for the same principal "
          "never exceed the ≤2 active ceiling (Hermes F1)",
          "[pg][token][rotation][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-concurrent";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    // Every thread races rotate_engine_credential for the SAME principal at
    // the SAME `now`, with a distinct requesting_user each — before F1, the
    // unlocked read-then-mint let multiple threads all observe 1-active and
    // all mint, blowing the ≤2 ceiling. std::latch lines every thread up at
    // the starting gun so they hit the advisory lock as concurrently as the
    // test process can arrange.
    constexpr int kThreads = 6;
    std::latch start_latch{kThreads};
    std::vector<std::thread> threads;
    std::mutex results_mtx;
    std::vector<std::expected<std::string, std::string>> results;

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i]() {
            start_latch.arrive_and_wait();
            auto r = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now,
                                                     "operator-" + std::to_string(i));
            std::lock_guard lock(results_mtx);
            results.push_back(std::move(r));
        });
    }
    for (auto& t : threads)
        t.join();

    // Exactly ONE thread's call is the 1-active mint winner — every other
    // thread's call is serialized behind the advisory lock and, upon its
    // own re-read, sees 2-active. Since every thread used a DIFFERENT
    // requesting_user, none of the losers share the winner's identity, so
    // F4's binding rejects every one of them (never a silent re-serve to
    // the wrong caller, and never a THIRD mint).
    int successes = 0;
    for (const auto& r : results) {
        if (r.has_value())
            ++successes;
        else
            CHECK(r.error().find("different operator") != std::string::npos);
    }
    CHECK(successes == 1);

    // The ≤2 ceiling holds under concurrency — never 3.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential never leaves an orphaned rotation pair — "
          "mint and pair-stamp always commit together (Hermes F2)",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-no-orphan";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    // Every row with a non-empty rotation_group must have exactly one
    // sibling sharing it (predecessor + successor) — never a lone stamped
    // row, which would mean the INSERT committed without the pair-stamp (or
    // vice versa).
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    CHECK_FALSE(active[0].rotation_group.empty());
    CHECK(active[0].rotation_group == active[1].rotation_group);

    const ApiToken* predecessor = active[0].supersedes_token_id.empty() ? &active[0] : &active[1];
    const ApiToken* successor = active[0].supersedes_token_id.empty() ? &active[1] : &active[0];
    CHECK(predecessor->overlap_expires_at > 0);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: rolls back the predecessor's revoke when "
          "the successor's rotation-state clear fails — neither half applies (Hermes F3)",
          "[pg][token][rotation][sweep]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-sweep-rollback";
    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    seed_sweep_survivor(store, now, "rotation-sweep-rollback-survivor");

    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDay, now, "admin");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : active) {
        if (t.supersedes_token_id.empty())
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);
    const std::string predecessor_id = predecessor->token_id;
    const std::string successor_id = successor->token_id;
    const std::string rotation_group = predecessor->rotation_group;

    // UP-5: the sweep only attempts the auto-revoke transaction under test
    // here (the one whose rollback this test exercises) when the successor
    // has been presented at least once — present it so the F3 rollback path
    // is actually reached rather than short-circuited by the never-used
    // carve-out.
    REQUIRE(store.validate_token(*rotated).has_value());

    // Force the successor's rotation-state clear to fail with a genuine SQL
    // execution error (never merely a zero-row match) — a BEFORE UPDATE
    // trigger that raises only when THIS successor's rotation_group is
    // being cleared. Scoped to this test's own cloned database (PgTestTemplate),
    // so it can't leak into any other test.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string fn_sql =
            "CREATE OR REPLACE FUNCTION api_token_store.f3_force_clear_fail() "
            "RETURNS trigger AS $$ BEGIN IF NEW.token_id = '" +
            successor_id +
            "' AND NEW.rotation_group = '' THEN "
            "RAISE EXCEPTION 'F3 test: forced clear failure'; END IF; RETURN NEW; END; $$ "
            "LANGUAGE plpgsql;";
        PgResult fn_res{PQexec(conn.get(), fn_sql.c_str())};
        REQUIRE(fn_res.ok());
        PgResult trig_res{PQexec(
            conn.get(),
            "CREATE TRIGGER f3_force_clear_fail BEFORE UPDATE ON api_token_store.api_tokens "
            "FOR EACH ROW EXECUTE FUNCTION api_token_store.f3_force_clear_fail();")};
        REQUIRE(trig_res.ok());
    }

    // AFTER the overlap window elapses (forced directly relative to
    // PostgreSQL's own clock — #2964, the sweep's eligibility decision no
    // longer reads the `now` argument), sweep attempts to revoke the
    // predecessor + clear the successor together in one transaction — the
    // clear fails, so NEITHER change may commit.
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);
    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    CHECK(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(swept.revoked.empty());

    auto predecessor_after = store.get_token(predecessor_id).value();
    REQUIRE(predecessor_after.has_value());
    CHECK_FALSE(predecessor_after->revoked); // rolled back — NOT revoked

    auto successor_after = store.get_token(successor_id).value();
    REQUIRE(successor_after.has_value());
    CHECK_FALSE(successor_after->rotation_group.empty()); // rolled back — still linked
    CHECK(successor_after->rotation_group == rotation_group);

    // Idempotent: re-running the (still-failing) sweep doesn't corrupt
    // anything further — same clean rollback each time.
    auto swept_again = store.sweep_expired_rotations(now + kDay + 2);
    CHECK(swept_again.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(swept_again.revoked.empty());
    auto predecessor_still = store.get_token(predecessor_id).value();
    REQUIRE(predecessor_still.has_value());
    CHECK_FALSE(predecessor_still->revoked);
}

TEST_CASE("ApiTokenStore: confirm_rotation cuts over immediately — revokes the predecessor, "
          "sets confirmed_at, and clears the successor's rotation state (Hermes F5)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    auto before = store.list_active_for_principal(principal);
    REQUIRE(before.size() == 2);
    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : before) {
        if (t.supersedes_token_id.empty())
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);
    const std::string predecessor_id = predecessor->token_id;
    const std::string successor_id = successor->token_id;

    auto confirmed = store.confirm_rotation(principal, successor_id, *rotated, "admin");
    REQUIRE(confirmed.has_value());

    auto predecessor_after = store.get_token(predecessor_id).value();
    REQUIRE(predecessor_after.has_value());
    CHECK(predecessor_after->revoked); // immediate cutover, not "wait for the window"

    auto successor_after = store.get_token(successor_id).value();
    REQUIRE(successor_after.has_value());
    CHECK_FALSE(successor_after->revoked);
    CHECK(successor_after->confirmed_at > 0); // the previously-dead column, now live
    CHECK(successor_after->rotation_group.empty());
    CHECK(successor_after->supersedes_token_id.empty());
    CHECK(successor_after->overlap_expires_at == 0);

    // Exactly one active credential remains — the confirmed successor.
    auto active_after = store.list_active_for_principal(principal);
    REQUIRE(active_after.size() == 1);
    CHECK(active_after[0].token_id == successor_id);

    // A fresh rotation may now begin (the pair fully resolved).
    auto next_rotate =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    CHECK(next_rotate.has_value());
}

TEST_CASE("ApiTokenStore: confirm_rotation rejects an operator who did not initiate the "
          "rotation (Hermes F4/F5 binding)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-wrong-user";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    // The CORRECT successor id is supplied so this isolates the operator check
    // (a wrong id would trip the #2384 token_id pin first).
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // #3015: PoP is checked LAST (after the initiator binding), so a correct
    // secret here does not let a non-initiator caller past the operator
    // check — the test would be weaker, not stronger, with a wrong secret.
    auto stolen_confirm = store.confirm_rotation(principal, successor_id, *rotated, "mallory");
    REQUIRE_FALSE(stolen_confirm.has_value());
    CHECK(stolen_confirm.error().find("different operator") != std::string::npos);

    // Rejected — both credentials remain exactly as rotate left them.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);
    for (const auto& t : active)
        CHECK(t.confirmed_at == 0);

    // The SAME operator who initiated it can still confirm afterward.
    auto real_confirm = store.confirm_rotation(principal, successor_id, *rotated, "admin");
    CHECK(real_confirm.has_value());
}

TEST_CASE("ApiTokenStore: confirm_rotation sole-credential states are terminal, but a "
          "genuinely empty read stays retryable (#2404)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-sole";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    const std::string sole_id = store.list_active_for_principal(principal).at(0).token_id;

    // One never-rotated credential, pin MATCHES it: resolved without a confirm
    // (confirmed_at == 0). Terminal conflict, NOT the old retryable error —
    // this is the positive-read guarantee (#2404). Pre-#2384 wording proof: a
    // client must be told "nothing to confirm", not told to retry.
    auto resolved = store.confirm_rotation(principal, sole_id, "irrelevant-secret", "admin");
    REQUIRE_FALSE(resolved.has_value());
    CHECK(resolved.error().find("already the sole active credential") != std::string::npos);
    CHECK(classify_engine_store_error(resolved.error()) == E::Conflict);

    // One credential, pin does NOT match it: the pinned rotation moved on.
    auto other = store.confirm_rotation(principal, "deadbeefdeadbeefdeadbeef",
                                        "irrelevant-secret", "admin");
    REQUIRE_FALSE(other.has_value());
    CHECK(other.error().find("the rotation was resolved") != std::string::npos);
    CHECK(classify_engine_store_error(other.error()) == E::Conflict);

    // Now revoke the sole credential so the read is genuinely EMPTY. That case
    // is ambiguous with a swallowed SELECT failure, so it MUST stay the
    // retryable "no in-flight rotation to confirm" (Transient), never a
    // terminal 409 (regression guard for the positive-read boundary).
    REQUIRE(store.revoke_token(sole_id).value());
    REQUIRE(store.list_active_for_principal(principal).empty());
    auto none = store.confirm_rotation(principal, sole_id, "irrelevant-secret", "admin");
    REQUIRE_FALSE(none.has_value());
    CHECK(none.error().find("no in-flight rotation to confirm") != std::string::npos);
    CHECK(classify_engine_store_error(none.error()) == E::Transient);
}

TEST_CASE("ApiTokenStore: confirm_rotation replay after success is a terminal already-confirmed "
          "conflict, not a retryable 503 (#2404)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-replay";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // First confirm succeeds (the real cutover).
    REQUIRE(store.confirm_rotation(principal, successor_id, *rotated, "admin").has_value());

    // The network-dropped-200 replay: SAME args. The successor is now the sole
    // active credential with confirmed_at set, so this is terminal, not 503.
    auto replay = store.confirm_rotation(principal, successor_id, "irrelevant-secret", "admin");
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error().find("rotation already confirmed") != std::string::npos);
    CHECK(replay.error().find("sole active credential") != std::string::npos);
    CHECK(classify_engine_store_error(replay.error()) == E::Conflict);
    // No side effect: still exactly one active credential.
    CHECK(store.list_active_for_principal(principal).size() == 1);
}

TEST_CASE("ApiTokenStore: confirm_rotation after the sweep cuts over is a terminal "
          "already-resolved conflict (#2404)",
          "[pg][token][rotation][confirm][sweep]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-swept";
    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    seed_sweep_survivor(store, now, "rotation-confirm-swept-survivor");

    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDay, now, "admin");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    std::string predecessor_id;
    for (const auto& t : store.list_active_for_principal(principal)) {
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
        else
            predecessor_id = t.token_id;
    }
    REQUIRE_FALSE(successor_id.empty());
    REQUIRE_FALSE(predecessor_id.empty());

    // UP-5: present the successor so the sweep below actually auto-revokes
    // (a never-used successor is now left alone) — this test is about the
    // #2404 confirm-vs-sweep race, not UP-5 itself.
    REQUIRE(store.validate_token(*rotated).has_value());

    // The overlap sweep auto-revokes the predecessor and clears the successor
    // (which was never confirmed: confirmed_at stays 0). Forced into the
    // past relative to PostgreSQL's own clock (#2964).
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);
    auto sweep_result = store.sweep_expired_rotations(now + kDay + 1);
    REQUIRE(sweep_result.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(sweep_result.revoked.size() == 1);
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK(active[0].confirmed_at == 0); // resolved by sweep, not by a confirm

    // A confirm racing the sweep now finds the successor resolved. Terminal,
    // and worded "no rotation in flight" (not "already confirmed") because the
    // cutover was the sweep, not an explicit confirm. Assert the contiguous
    // fragment unique to kSoleResolved ("already the sole active credential"):
    // it disambiguates from kSoleConfirmed ("is the sole...") and kSoleOtherToken
    // (no "sole active credential") in a single check, so a partial message
    // drift on one branch can't false-pass (qe review, #2404).
    auto swept_confirm =
        store.confirm_rotation(principal, successor_id, "irrelevant-secret", "admin");
    REQUIRE_FALSE(swept_confirm.has_value());
    CHECK(swept_confirm.error().find("no rotation in flight") != std::string::npos);
    CHECK(swept_confirm.error().find("already the sole active credential") != std::string::npos);
    CHECK(classify_engine_store_error(swept_confirm.error()) == E::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_rotation with more than two active credentials is a terminal "
          "client error, not a retryable 503 (#2404)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-overfull";
    auto now = test_now_epoch();
    // The store's create_token has no ≤2 ceiling (only the mint route does), so
    // three direct mints reproduce the "credential minted outside rotation"
    // shape (same setup as the rotate over-ceiling test).
    REQUIRE(store.create_token("a", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("b", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("c", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.list_active_for_principal(principal).size() == 3);

    auto over = store.confirm_rotation(principal, "deadbeefdeadbeefdeadbeef",
                                       "irrelevant-secret", "admin");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().find("more than two active credentials") != std::string::npos);
    CHECK(classify_engine_store_error(over.error()) == E::ClientValidation);
    CHECK(store.list_active_for_principal(principal).size() == 3); // never arbitrated
}

TEST_CASE("ApiTokenStore: confirm_rotation on a sole credential with stale rotation linkage is "
          "terminal and does NOT advise rotate (#2404 F1)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-stale-linkage";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    std::string predecessor_id, successor_id;
    for (const auto& t : store.list_active_for_principal(principal)) {
        if (t.supersedes_token_id.empty())
            predecessor_id = t.token_id;
        else
            successor_id = t.token_id;
    }
    REQUIRE_FALSE(successor_id.empty());

    // Manufacture the F1 defect state: revoke the predecessor by DIRECT SQL,
    // bypassing revoke_token's resolve_rotation_pair_after_revoke, so the
    // surviving successor keeps its (now stale) rotation_group + supersedes.
    // This is the durable state a best-effort pair-resolve failure leaves.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "UPDATE api_token_store.api_tokens SET revoked = TRUE WHERE token_id = '" +
            predecessor_id + "';";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK_FALSE(active[0].rotation_group.empty()); // stale linkage survived

    auto stale = store.confirm_rotation(principal, successor_id, "irrelevant-secret", "admin");
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error().find("unresolved rotation metadata") != std::string::npos);
    CHECK(classify_engine_store_error(stale.error()) == E::Conflict);
    // MUST NOT tell the operator to rotate from this state (rotating would
    // strand a malformed pair). It says "do not rotate", never "rotate again".
    CHECK(stale.error().find("do not rotate") != std::string::npos);
    CHECK(stale.error().find("rotate again") == std::string::npos);
}

TEST_CASE("ApiTokenStore: confirm_rotation never misattributes a historical confirmed_at across "
          "a later rotation (#2404 F2)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-historical";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    // R1: rotate + confirm. S1 becomes the sole active credential, confirmed.
    auto r1_rotated =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(r1_rotated.has_value());
    std::string s1_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            s1_id = t.token_id;
    REQUIRE_FALSE(s1_id.empty());
    REQUIRE(store.confirm_rotation(principal, s1_id, *r1_rotated, "admin").has_value());
    REQUIRE(store.get_token(s1_id).value()->confirmed_at > 0); // S1 carries R1's marker

    // R2: rotate again (S1 is now the predecessor, KEEPING its confirmed_at),
    // then revoke R2's successor so the pair resolves back to S1 alone.
    REQUIRE(store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin")
                .has_value());
    std::string s2_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            s2_id = t.token_id;
    REQUIRE_FALSE(s2_id.empty());
    REQUIRE(store.revoke_token(s2_id).value()); // resolves the pair -> S1 sole, clear
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == s1_id);

    // Pin = S1 (the confirmed survivor): "already confirmed" is TRUE and
    // correct — the rotation in which S1 was successor (R1) WAS confirmed.
    auto pin_s1 = store.confirm_rotation(principal, s1_id, "irrelevant-secret", "admin");
    REQUIRE_FALSE(pin_s1.has_value());
    CHECK(pin_s1.error().find("rotation already confirmed") != std::string::npos);

    // Pin = S2 (R2's successor, which was resolved by REVOKE, not confirm):
    // the message must NOT claim "already confirmed" — it says "the rotation
    // was resolved", the cause-agnostic wording for a non-matching pin. This
    // is the F2 guard: historical confirmed_at never attributes R2's cause.
    auto pin_s2 = store.confirm_rotation(principal, s2_id, "irrelevant-secret", "admin");
    REQUIRE_FALSE(pin_s2.has_value());
    CHECK(pin_s2.error().find("the rotation was resolved") != std::string::npos);
    CHECK(pin_s2.error().find("already confirmed") == std::string::npos);
}

TEST_CASE("ApiTokenStore: confirm_rotation rejects a token_id that is not the pending "
          "successor — no mutation (#2384 pin)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-mismatch";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    std::string predecessor_id, successor_id, rotation_group;
    for (const auto& t : store.list_active_for_principal(principal)) {
        if (t.supersedes_token_id.empty()) {
            predecessor_id = t.token_id;
        } else {
            successor_id = t.token_id;
            rotation_group = t.rotation_group;
        }
    }
    REQUIRE_FALSE(successor_id.empty());

    // The PREDECESSOR's id (the likely operator mistake) and a bogus id both
    // mismatch the pending successor.
    for (const std::string& wrong : {predecessor_id, std::string{"feedfacefeedfacefeedface"}}) {
        auto mismatch = store.confirm_rotation(principal, wrong, "irrelevant-secret", "admin");
        REQUIRE_FALSE(mismatch.has_value());
        CHECK(mismatch.error().find("does not match the pending rotation") != std::string::npos);
    }

    // No mutation: both credentials active, linkage intact, confirmed_at unset.
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    for (const auto& t : active) {
        CHECK(t.confirmed_at == 0);
        CHECK(t.rotation_group == rotation_group);
        if (t.token_id == successor_id)
            CHECK(t.supersedes_token_id == predecessor_id);
    }

    // Empty token_id is rejected by the input guard, same no-mutation posture.
    auto empty_id = store.confirm_rotation(principal, "", "irrelevant-secret", "admin");
    REQUIRE_FALSE(empty_id.has_value());
    CHECK(empty_id.error().find("token_id required") != std::string::npos);

    // The correct id still confirms — the rejections above consumed nothing.
    CHECK(store.confirm_rotation(principal, successor_id, *rotated, "admin").has_value());
}

TEST_CASE("ApiTokenStore: a blind retry carrying an EARLIER rotation's successor id cannot "
          "confirm a LATER rotation (#2384 regression)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-blind-retry";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    // Rotation 1: rotate + confirm with R1's successor id (the happy flow).
    auto r1_rotated =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(r1_rotated.has_value());
    std::string r1_successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            r1_successor_id = t.token_id;
    REQUIRE_FALSE(r1_successor_id.empty());
    REQUIRE(store.confirm_rotation(principal, r1_successor_id, *r1_rotated, "admin").has_value());

    // Rotation 2 begins: R1's successor is now R2's predecessor.
    auto r2_rotated =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(r2_rotated.has_value());
    std::string r2_successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            r2_successor_id = t.token_id;
    REQUIRE_FALSE(r2_successor_id.empty());
    REQUIRE(r2_successor_id != r1_successor_id);

    // THE #2384 SCENARIO: a blind retry of the R1 confirm (same args, same
    // operator) lands after R2 started. Pre-pin this confirmed R2 early and
    // revoked R2's predecessor — R1's still-live successor. Now it mismatches.
    // The REAL R1 secret is deliberately reused here too (#3015): the pin
    // mismatch must fire regardless of whether the presented secret happens
    // to be correct for r1_successor_id — PoP is checked strictly after it.
    auto stale_retry =
        store.confirm_rotation(principal, r1_successor_id, *r1_rotated, "admin");
    REQUIRE_FALSE(stale_retry.has_value());
    CHECK(stale_retry.error().find("does not match the pending rotation") != std::string::npos);

    // R2 is untouched: its predecessor (R1's successor) is still active and
    // the pair is still pending. NOTE: R2's predecessor legitimately RETAINS
    // its historical confirmed_at from R1 (kept as a marker by design) — only
    // R2's successor must be unconfirmed.
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    bool r1_successor_still_active = false;
    for (const auto& t : active) {
        if (t.token_id == r1_successor_id) {
            r1_successor_still_active = true;
            CHECK(t.revoked == false);
        }
        if (t.token_id == r2_successor_id)
            CHECK(t.confirmed_at == 0);
    }
    CHECK(r1_successor_still_active);

    // R2's own successor id confirms R2 normally.
    CHECK(store.confirm_rotation(principal, r2_successor_id, *r2_rotated, "admin").has_value());
}

// ── Manual revoke resolves the rotation pair (design §7, PR #2284 review Major 3) ──

TEST_CASE("ApiTokenStore: revoking a rotation PREDECESSOR resolves the pair — the successor "
          "becomes a standalone active credential",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:revoke-predecessor";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    const std::string predecessor_id = store.list_active_for_principal(principal).at(0).token_id;
    REQUIRE(store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin").has_value());

    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto revoked = store.revoke_token(predecessor_id);
    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // The successor is now the sole active credential with its rotation state cleared.
    auto after = store.list_active_for_principal(principal);
    REQUIRE(after.size() == 1);
    CHECK(after[0].token_id == successor_id);
    CHECK(after[0].rotation_group.empty());
    CHECK(after[0].supersedes_token_id.empty());
    CHECK(after[0].overlap_expires_at == 0);
}

TEST_CASE("ApiTokenStore: revoking a rotation SUCCESSOR clears the predecessor's rotation state so "
          "the sweep does NOT auto-revoke the principal's last credential",
          "[pg][token][rotation][sweep]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:revoke-successor";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    const std::string predecessor_id = store.list_active_for_principal(principal).at(0).token_id;
    // Short overlap so the sweep would fire after now+kDay.
    REQUIRE(store.rotate_engine_credential(principal, kDay, now, "admin").has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Revoke the SUCCESSOR — the predecessor is now the only credential.
    auto revoked = store.revoke_token(successor_id);
    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // Predecessor's rotation state is cleared (overlap_expires_at -> 0) so it is
    // no longer a sweep target.
    auto pred = store.get_token(predecessor_id);
    REQUIRE(pred.has_value());
    REQUIRE(pred->has_value());
    CHECK_FALSE((*pred)->revoked);
    CHECK((*pred)->overlap_expires_at == 0);
    CHECK((*pred)->rotation_group.empty());

    // Run the sweep AFTER the original overlap window would have elapsed. Without
    // the §7 fix the sweep would auto-revoke the predecessor as
    // "overlap_window_elapsed", leaving the principal with ZERO credentials.
    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    CHECK(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(swept.revoked.empty()); // nothing to auto-revoke — the pair was already resolved

    auto still = store.get_token(predecessor_id);
    REQUIRE(still.has_value());
    REQUIRE(still->has_value());
    CHECK_FALSE((*still)->revoked); // predecessor survives — principal keeps a credential
    CHECK(store.list_active_for_principal(principal).size() == 1);
}

// ── validate_token_checked: the tri-state a held-open stream needs ───────────
//
// `validate_token` folds "definitively gone" and "cannot reach the store" into
// the same nullopt. That is right for request auth — both answers mean 401 — and
// wrong for an MCP SSE stream, which must cut a REVOKED credential immediately
// (ADR-1005 Decision 15(c)) while riding out a transient backend blip rather than
// killing every live stream on the fleet at once (Decision 15(i), chaos CH-4).

TEST_CASE("ApiTokenStore: validate_token_checked reports a live token as valid",
          "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("Stream Token", "alice");
    REQUIRE(raw.has_value());

    auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kValid);
    REQUIRE(checked.token.has_value());
    CHECK(checked.token->principal_id == "alice");
}

TEST_CASE("ApiTokenStore: a revoked token is DEFINITIVELY invalid, not indeterminate",
          "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("Doomed", "alice");
    REQUIRE(raw.has_value());
    auto live = store.validate_token(*raw);
    REQUIRE(live.has_value());

    REQUIRE(store.revoke_token(live->token_id));

    auto checked = store.validate_token_checked(*raw);
    // kInvalid — NOT kUnavailable. A revocation must cut the stream on the next
    // tick; if it were reported as indeterminate it would instead buy the revoked
    // credential a full grace window of extra life.
    CHECK(checked.status == ApiTokenStore::TokenCheck::kInvalid);
    CHECK_FALSE(checked.token.has_value());
}

TEST_CASE("ApiTokenStore: an unknown token is definitively invalid", "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto checked = store.validate_token_checked("yuzu_never_issued_0123456789012");
    CHECK(checked.status == ApiTokenStore::TokenCheck::kInvalid);
}

TEST_CASE("ApiTokenStore: an empty token is definitively invalid", "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    CHECK(store.validate_token_checked("").status == ApiTokenStore::TokenCheck::kInvalid);
}

TEST_CASE("ApiTokenStore: an EXHAUSTED connection pool is kUnavailable, not kInvalid",
          "[pg][token][auth][stream]") {
    // The third way the store can fail to answer, and the only one the two schema
    // saboteurs below do NOT reach: `pool_.try_acquire_for(kReadTimeout)` returns no
    // lease. Same safe verdict, different branch — and it is the branch a real
    // Postgres brown-out takes, so leaving it untested left the most likely
    // production path unguarded.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    // A pool of exactly one, whose sole connection we hold for the duration.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("pool-starved", "alice");
    REQUIRE(raw.has_value());

    // Do NOT validate first — a cached token would answer from memory and never
    // need a connection, testing nothing.
    auto hog = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(hog); // we now hold the only connection

    const auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kUnavailable);
    CHECK_FALSE(checked.token.has_value()); // indeterminate NEVER grants access
}

TEST_CASE("ApiTokenStore: an unreadable store is kUnavailable, NOT kInvalid",
          "[pg][token][auth][stream]") {
    // The whole reason validate_token_checked exists. validate_token collapses "the row
    // is gone" and "I could not read the table" into the same nullopt — right for
    // request auth (both mean 401), fatal for a held-open stream, where the first must
    // kill it immediately and the second must NOT (an auth-store hiccup would otherwise
    // cut every stream on the fleet at once — ADR-1005 Decision 15(i), chaos CH-4).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("doomed-store", "alice");
    REQUIRE(raw.has_value());

    // Break the store from a second connection. Do NOT validate first — a cached token
    // would answer from memory and never touch the dropped table.
    {
        PgConn saboteur{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        PgResult r{PQexec(saboteur.get(), "DROP TABLE api_token_store.api_tokens")};
        REQUIRE(r.ok());
    }

    const auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kUnavailable);
    CHECK_FALSE(checked.token.has_value()); // indeterminate NEVER grants access
}

TEST_CASE("ApiTokenStore: a CONTENDED store is kUnavailable, not a false revocation",
          "[pg][token][auth][stream][ch4]") {
    // The bug this replaced: validate_token_checked used to call validate_token and then
    // probe the store with a DIFFERENT trivial statement to decide whether the negative
    // answer was real. But validate_token folds a failed row lookup into the same nullopt
    // as "no such row" — and the probe statement can still succeed on a merely-contended
    // store. A healthy stream was therefore killed as `credential_revoked` because the
    // backend was busy, and the 60 s grace window that exists for exactly this fault was
    // unreachable.
    //
    // Here the table is present (so a "SELECT 1 FROM api_tokens LIMIT 1" probe WOULD
    // succeed) but the row lookup cannot run, because the column it needs is gone.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("busy-store", "alice");
    REQUIRE(raw.has_value());

    {
        PgConn saboteur{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        // Rename the column the lookup selects: the table still exists, so a naive probe
        // is happy — only the real query fails.
        PgResult r{PQexec(saboteur.get(),
                          "ALTER TABLE api_token_store.api_tokens "
                          "RENAME COLUMN token_hash TO gone")};
        REQUIRE(r.ok());
    }

    const auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kUnavailable);
    CHECK_FALSE(checked.token.has_value());
}

TEST_CASE("ApiTokenStore: re-validation does not write last_used_at",
          "[pg][token][auth][stream]") {
    // Re-validation runs on every heartbeat tick of every live stream. Writing here would
    // make last_used_at track heartbeats instead of actual calls, and would put a write on
    // a pooled connection each time a stream's cache entry expired — a thundering herd
    // that every token-authenticated request then queues behind.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("read-only-check", "alice");
    REQUIRE(raw.has_value());

    const auto before = store.validate_token_checked(*raw);
    REQUIRE(before.status == ApiTokenStore::TokenCheck::kValid);
    CHECK(before.token->last_used_at == 0); // create_token leaves it unset

    // Read the column straight from the DB — a write by the check would show up here even
    // though the cached copy would not.
    PgConn reader{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(reader.get()) == CONNECTION_OK);
    PgResult r{PQexec(reader.get(), "SELECT last_used_at FROM api_token_store.api_tokens")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "0"); // a READ — it did not stamp
}


// ── Human arm: token-keyed overlap-pair rotation (P2 #11, SOC 2 CC6.3) ─────

TEST_CASE("ApiTokenStore: rotate_token rejects an overlap window below the 24h floor",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // No token with this id exists at all — the floor check still fires
    // first (pure math, no DB dependency), distinct message from "no such
    // token".
    auto rotated = store.rotate_token("deadbeefdeadbeefdeadbeef", kDay - 1, now, "admin", "", "");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("floor") != std::string::npos);
}

TEST_CASE("ApiTokenStore: rotate_token rejects an unknown token_id",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto rotated =
        store.rotate_token("deadbeefdeadbeefdeadbeef", kDefaultOverlapSecs, now, "admin", "", "");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("no such token") != std::string::npos);
    CHECK(classify_engine_store_error(rotated.error()) == E::ClientValidation);
}

TEST_CASE("ApiTokenStore: rotate_token rejects an engine-kind token — human arm only",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto now = test_now_epoch();
    auto minted =
        store.create_token("svc", "engine:human-arm-guard", now + k90Days, "", "readonly",
                           "engine");
    REQUIRE(minted.has_value());
    auto active = store.list_active_for_principal("engine:human-arm-guard");
    REQUIRE(active.size() == 1);

    // requesting_user must equal the row's own principal_id to clear the
    // self-service ownership gate and reach the kind check at all — a
    // human requesting_user could never own an "engine:"-namespaced row in
    // practice, but this proves the kind guard fires as a defense-in-depth
    // backstop on the (structurally unreachable in production) case where it
    // does. caller_mcp_tier is passed matching the row's own "readonly" tier
    // so the authority-inheritance guard (checked earlier in the sequence)
    // clears and this test reaches — and isolates — the kind check it
    // targets.
    auto rotated = store.rotate_token(active[0].token_id, kDefaultOverlapSecs, now,
                                      "engine:human-arm-guard", "readonly", "", std::nullopt);
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("human-owned") != std::string::npos);
}

TEST_CASE("ApiTokenStore: rotate_token rejects a non-owner even with a valid token_id — "
          "self-service only, no admin override, and indistinguishable from a missing token",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-pat", "alice", now + k90Days);
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;

    // "admin" is a DIFFERENT user, not merely a different requesting_user
    // label — there is no admin-override arm on this path (deliberate
    // asymmetry with the engine arm's third-party-admin design).
    auto stolen = store.rotate_token(token_id, kDefaultOverlapSecs, now, "admin", "", "");
    REQUIRE_FALSE(stolen.has_value());
    CHECK(stolen.error() == "no such token to rotate"); // byte-identical to the genuine 404 case
    CHECK(classify_engine_store_error(stolen.error()) == E::ClientValidation);

    // No state mutated by the rejected cross-user attempt.
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].rotation_group.empty());

    // The genuine owner can still rotate normally afterward.
    auto real = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", "", "");
    CHECK(real.has_value());
}

// ── Authority-inheritance guard (governance Gate 7 CRITICAL fix) ───────────
//
// `rotate_token` used to copy the predecessor's `mcp_tier`/`scope_service`
// verbatim into the successor with no check that the CALLER's own current
// authority matched — so an operator-tier caller could pick their own
// untiered sibling token as the predecessor and receive an untiered,
// perpetual, full-authority successor. These three cases pin the fix.

TEST_CASE("ApiTokenStore: rotate_token refuses when the caller's own mcp_tier does not match "
          "the predecessor's — authority-inheritance guard, no successor row inserted",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    // Predecessor is UNTIERED, no scope_service, perpetual — the classic
    // full-authority credential the finding traces.
    auto raw = store.create_token("alices-untiered-pat", "alice", 0);
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;
    REQUIRE(store.list_active_for_principal("alice").size() == 1);

    // Caller presents an operator-tier authority the predecessor does NOT
    // carry — without the guard this would mint a fresh untiered/perpetual
    // successor for an operator-tier caller: exactly the escalation this
    // fix closes.
    auto rotated = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", "operator", "",
                                      std::nullopt);
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error() == "no such token to rotate"); // same wording as absent/not-owned —
                                                          // not an authority-probing oracle
    CHECK(classify_engine_store_error(rotated.error()) == E::ClientValidation);

    // No successor minted — row count for the principal is unchanged, and
    // the predecessor was never stamped into a rotation pair either.
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == token_id);
    CHECK(active[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: rotate_token succeeds when the caller's tier/scope match the "
          "predecessor's, and the successor inherits both verbatim",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-operator-pat", "alice", now + k90Days, "svc-a",
                                  "operator");
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", "operator",
                                      "svc-a", std::nullopt);
    REQUIRE(rotated.has_value());

    // Pins inheritance itself — nothing else in this suite asserts the
    // minted successor's mcp_tier/scope_service against the predecessor's.
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("alice"))
        if (t.token_id != token_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());
    auto successor = store.get_token(successor_id);
    REQUIRE(successor.has_value());
    REQUIRE(successor->has_value());
    CHECK((*successor)->mcp_tier == "operator");
    CHECK((*successor)->scope_service == "svc-a");
}

TEST_CASE("ApiTokenStore: rotate_token refuses on a scope_service mismatch even when the tier "
          "matches — the guard checks BOTH dimensions",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-scoped-pat", "alice", now + k90Days, "svc-a",
                                  "operator");
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;
    REQUIRE(store.list_active_for_principal("alice").size() == 1);

    // Same tier as the predecessor, DIFFERENT scope_service — the caller's
    // own token is scoped to a different service than the one being
    // rotated.
    auto rotated = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", "operator",
                                      "svc-b", std::nullopt);
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error() == "no such token to rotate");

    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == token_id);
}

TEST_CASE("ApiTokenStore: rotate_token succeeds when the caller holds NO standing tier/scope "
          "authority at all, even against a TIERED/SCOPED predecessor — the #2963 "
          "full-authority exception, and the successor inherits the TOKEN's own tier/scope, "
          "never the caller's",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // Predecessor is operator-tier + service-scoped — exactly the case an
    // interactive dashboard/cookie session (empty tier/scope) could not
    // reach before #2963, backwards precisely when the reason to rotate is
    // that the secret may be compromised.
    auto raw = store.create_token("alices-operator-pat", "alice", now + k90Days, "svc-a",
                                  "operator");
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;

    // Caller presents NO standing authority ("", "") — a plain cookie
    // session — not the predecessor's own "operator"/"svc-a".
    auto rotated = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", "", "",
                                      std::nullopt);
    REQUIRE(rotated.has_value());

    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("alice"))
        if (t.token_id != token_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());
    auto successor = store.get_token(successor_id);
    REQUIRE(successor.has_value());
    REQUIRE(successor->has_value());
    // Inherits the PREDECESSOR's tier/scope verbatim — the caller's own
    // (empty) authority never leaks into the successor. Nothing is
    // escalated: the minted credential is exactly as narrow as the one it
    // replaces.
    CHECK((*successor)->mcp_tier == "operator");
    CHECK((*successor)->scope_service == "svc-a");
}

TEST_CASE("ApiTokenStore: confirm_token_rotation succeeds with the SAME full-authority caller "
          "that initiated the rotation via the #2963 exception — rotate and confirm must "
          "agree on the identical caller/token pair",
          "[pg][token][rotation][human][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto raw = store.create_token("bobs-supervised-pat", "bob", now + k90Days, "svc-z",
                                  "supervised");
    REQUIRE(raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("bob")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "bob", "", "",
                                      std::nullopt);
    REQUIRE(rotated.has_value());
    const std::string raw_secret = *rotated;

    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("bob"))
        if (t.supersedes_token_id == predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto confirmed = store.confirm_token_rotation(successor_id, raw_secret, "bob", "", "");
    REQUIRE(confirmed.has_value());
    auto active = store.list_active_for_principal("bob");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK(active[0].mcp_tier == "supervised");
    CHECK(active[0].scope_service == "svc-z");
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a non-owner even with the correct "
          "pinned successor token_id — self-service only",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-pat", "alice", now + k90Days);
    REQUIRE(raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("alice"))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // "admin" knows the correct successor token_id (e.g. observed in an
    // audit log) but is not alice — must still be rejected, byte-identical
    // to the not-found wording, never a distinguishable "not yours". #3015
    // oracle-freedom: "admin" ALSO presents the CORRECT raw secret here —
    // proves the ownership check still wins and the outcome does not flip
    // to "confirmed" nor to a distinguishable "wrong secret", because PoP
    // is checked strictly after ownership.
    auto stolen_confirm = store.confirm_token_rotation(successor_id, *rotated, "admin", "", "");
    REQUIRE_FALSE(stolen_confirm.has_value());
    CHECK(stolen_confirm.error() == "no such token to confirm");
    CHECK(classify_engine_store_error(stolen_confirm.error()) == E::ClientValidation);

    // Nothing mutated — the pair is still intact and alice can still confirm.
    CHECK(store.list_active_for_principal("alice").size() == 2);
    auto real_confirm = store.confirm_token_rotation(successor_id, *rotated, "alice", "", "");
    CHECK(real_confirm.has_value());
}

TEST_CASE("ApiTokenStore: rotate_token rejects a window exceeding the predecessor's own "
          "expiry rather than truncating it",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // Predecessor expires in 1h — a 24h (floor) overlap window cannot fit
    // before it, so the mint must be rejected, not silently shrunk.
    auto minted = store.create_token("tight", "alice", now + 3600);
    REQUIRE(minted.has_value());
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    const std::string token_id = active[0].token_id;

    auto rotated = store.rotate_token(token_id, kDay, now, "alice", "", "");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("expiry") != std::string::npos);

    // Rejected mint must not have minted a successor.
    CHECK(store.list_active_for_principal("alice").size() == 1);
}

TEST_CASE("ApiTokenStore: rotate_token mints a successor, stamps the rotation pair, and "
          "inherits the predecessor's expiry verbatim",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    auto before = store.list_active_for_principal("alice");
    REQUIRE(before.size() == 1);
    const std::string predecessor_id = before[0].token_id;
    const int64_t predecessor_expires_at = before[0].expires_at;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());
    CHECK(rotated->starts_with("yuzu_"));
    CHECK(*rotated != *predecessor_raw);

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);

    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : after) {
        CHECK(t.principal_kind == "human");
        if (t.token_id == predecessor_id)
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);

    CHECK_FALSE(predecessor->rotation_group.empty());
    CHECK(predecessor->rotation_group == successor->rotation_group);
    CHECK(predecessor->overlap_expires_at == now + kDefaultOverlapSecs);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
    CHECK(predecessor->supersedes_token_id.empty());
    // Successor TTL: inherited verbatim, never recomputed as now+90d.
    CHECK(successor->expires_at == predecessor_expires_at);
    CHECK(successor->name == "my-pat");

    auto stored_hash = raw_hash_column(pool, successor->token_id);
    CHECK_FALSE(stored_hash.empty());
    CHECK(stored_hash != *rotated);
}

TEST_CASE("ApiTokenStore: rotate_token honours an explicit successor_expires_at override",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    auto before = store.list_active_for_principal("alice");
    REQUIRE(before.size() == 1);
    const std::string predecessor_id = before[0].token_id;

    const int64_t override_expiry = now + kDefaultOverlapSecs + kDay;
    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "",
                                      override_expiry);
    REQUIRE(rotated.has_value());

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);
    for (const auto& t : after) {
        if (t.token_id != predecessor_id)
            CHECK(t.expires_at == override_expiry);
    }
}

TEST_CASE("ApiTokenStore: rotate_token — a perpetual predecessor yields a perpetual "
          "successor unless overridden",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("perma-pat", "alice"); // expires_at defaults to 0
    REQUIRE(predecessor_raw.has_value());
    auto before = store.list_active_for_principal("alice");
    REQUIRE(before.size() == 1);
    REQUIRE(before[0].expires_at == 0);
    const std::string predecessor_id = before[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);
    for (const auto& t : after) {
        if (t.token_id != predecessor_id)
            CHECK(t.expires_at == 0); // never silently forced onto a 90d ceiling
    }
}

TEST_CASE("ApiTokenStore: rotate_token — a human's OTHER unrelated active tokens never "
          "count against the <=2 ceiling (the core reason the human arm is token-keyed, "
          "not principal-keyed)",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // alice holds THREE unrelated, never-rotated tokens — a principal-keyed
    // ceiling (the engine arm's own arbitration) would defensively reject
    // any rotate call here (">2 active"); the token-keyed arm must not.
    auto t1 = store.create_token("laptop", "alice", now + k90Days);
    auto t2 = store.create_token("ci-runner", "alice", now + k90Days);
    auto t3 = store.create_token("cli", "alice", now + k90Days);
    REQUIRE(t1.has_value());
    REQUIRE(t2.has_value());
    REQUIRE(t3.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 3);

    auto active = store.list_active_for_principal("alice");
    std::string ci_id;
    for (const auto& t : active)
        if (t.name == "ci-runner")
            ci_id = t.token_id;
    REQUIRE_FALSE(ci_id.empty());

    auto rotated = store.rotate_token(ci_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());

    // Now 4 active total (laptop, cli untouched + the ci-runner pair), but
    // the rotate call itself must have succeeded cleanly.
    CHECK(store.list_active_for_principal("alice").size() == 4);
}

TEST_CASE("ApiTokenStore: rotate_token re-serves the same raw within the grace window, and "
          "never mints a third credential for that group",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto first = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(first.has_value());

    auto retry = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(retry.has_value());
    CHECK(*retry == *first);

    CHECK(store.list_active_for_principal("alice").size() == 2);
}

TEST_CASE("ApiTokenStore: rotate_token — a query failure in the conflict arm's active-set "
          "re-read classifies Transient, never the terminal 'not a recognized rotation "
          "pair' conflict",
          "[pg][token][rotation]") {
    // Regression for a gap found in review: read_active_in_rotation_group_on_conn (a
    // group-scoped SQL query, since removed) swallowed a query failure into the same
    // empty vector as a genuinely-empty group, and the conflict arm then reported that
    // as the terminal "not a recognized rotation pair" ClientValidation — inverting
    // #2404 in the other direction (a transient DB hiccup reported as permanent,
    // do-not-retry). The fix reuses the principal-wide read + in-memory filter
    // (confirm_token_rotation's already-correct pattern); this test proves a query
    // failure AT THAT EXACT POINT stays Transient/retryable.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    // First rotate mints the pair and lands us in the re-serve/conflict arm for
    // any subsequent call on the same predecessor.
    auto first = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(first.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 2);

    // Poison the transaction's OWN connection right before the conflict arm's
    // active-set re-read — a genuine mid-transaction query failure, not a
    // simulated one: every statement on this connection fails until rollback.
    // Scoped (RAII): the hook clears itself even if a REQUIRE/CHECK below
    // throws, so it can never leak armed into the rest of this TEST_CASE.
    std::expected<std::string, std::string> retry;
    {
        ScopedPgConnHook hook_guard(store.test_hook_before_rotate_group_read_, [](pg_conn* conn) {
            (void)pg::exec_params(conn, "SELECT 1/0", std::vector<std::string>{});
        });
        retry = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    }

    REQUIRE_FALSE(retry.has_value());
    // Reuses the SAME wording (and Transient class) the pre-mint lookup-failure
    // branch uses — never the terminal "not a recognized rotation pair" conflict.
    CHECK(retry.error() == "no active credential to rotate — mint one first");
    CHECK(classify_engine_store_error(retry.error()) == E::Transient);

    // The poisoned transaction rolled back — no state corrupted, and the pair
    // is exactly as it was before the failed retry.
    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);

    // A normal call afterward (hook cleared) still works.
    auto clean_retry =
        store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(clean_retry.has_value());
    CHECK(*clean_retry == *first);
}

TEST_CASE("ApiTokenStore: rotate_token — a COMMIT failure after the mint arm returns true "
          "never leaks a grace-cache entry (round 4 regression)",
          "[pg][token][rotation]") {
    // Regression for a gap found in review: store_rotation_raw was hoisted
    // above the `if (!ok)` check, so a COMMIT failure — which PgPool::run_in_txn
    // (pg/pg_pool.cpp) can still report AFTER the callback itself returned
    // true (the aborted/idle-transaction refusal, or PgTxn::commit() itself
    // failing, pg/pg_raii.hpp) — inserted a grace-cache entry keyed to a
    // candidate_token_id with NO committed row. Nothing can ever evict it:
    // evict_rotation_raw fires only on confirm-success or the sweep
    // resolving a pair, both of which require a committed row to exist at
    // all, and scrub_elapsed_grace_secrets zeroes the entry's `raw` past the
    // grace window but deliberately never erases the entry itself.
    //
    // This forces exactly that outcome by killing the transaction's own
    // backend connection right after the mint arm's INSERT+UPDATE have
    // already succeeded, but before with_txn_for attempts COMMIT — a genuine
    // commit failure, not a simulated one — and asserts the grace cache is
    // EMPTY afterward. LeakSanitizer cannot catch this class of leak (the
    // entry stays reachable from a live member map, `rotation_grace_cache_`),
    // so this targeted assertion is the only detector.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    REQUIRE(store.rotation_grace_cache_size() == 0);

    // Scoped (RAII): the hook clears itself even if one of the several
    // REQUIREs inside its body throws (Catch2 assertion-failure semantics),
    // so it can never leak armed into the rest of this TEST_CASE — same
    // discipline as the conflict-arm hook above, via the same guard class.
    std::expected<std::string, std::string> rotated;
    {
        ScopedPgConnHook hook_guard(store.test_hook_before_mint_commit_, [&pool](pg_conn* conn) {
            const int victim_pid = PQbackendPID(conn);
            REQUIRE(victim_pid > 0);
            {
                // A second, independent connection sends the kill. Bounded
                // acquire + REQUIRE rather than a bare `pool.acquire()`: this
                // re-enters the pool from inside a live txn callback while
                // already holding the txn's own lease — safe today at
                // size = 4, but a bare acquire would hang CI forever (a
                // silent self-deadlock) if the pool size were ever reduced.
                // A bounded wait turns that into a loud, fast test failure
                // instead.
                auto axe = pool.try_acquire_for(std::chrono::seconds(5));
                REQUIRE(static_cast<bool>(axe));
                const std::string kill =
                    "SELECT pg_terminate_backend(" + std::to_string(victim_pid) + ")";
                PgResult res{PQexec(axe.get(), kill.c_str())};
                REQUIRE(res.status() == PGRES_TUPLES_OK);
            }
            // pg_terminate_backend returns when the signal is SENT, not when
            // the backend has actually exited (same pattern as
            // test_pg_pool.cpp's "PgPool discards a connection lost
            // mid-use") — poll on the VICTIM connection until the client
            // side observes the loss, so the COMMIT that follows this
            // hook's return genuinely fails rather than racing a connection
            // that hasn't died yet.
            bool severed = false;
            for (int i = 0; i < 100 && !severed; ++i) {
                PgResult ping{PQexec(conn, "SELECT 1")};
                severed = ping.status() != PGRES_TUPLES_OK && PQstatus(conn) != CONNECTION_OK;
                if (!severed)
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            REQUIRE(severed);
        });
        rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    }

    // The transaction never committed, so rotate_token must report failure...
    REQUIRE_FALSE(rotated.has_value());
    // ...and — the actual defect under test — no grace-cache entry may have
    // leaked for this failed-commit attempt.
    CHECK(store.rotation_grace_cache_size() == 0);

    // The DB-side rollback (connection loss aborts the in-flight transaction
    // server-side too) means the predecessor is untouched — still the
    // principal's sole active token, never mid-rotation.
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == predecessor_id);
    CHECK(active[0].rotation_group.empty());
}

// NOTE: there is no "grace-window re-serve to a different operator" test for
// the human arm — unlike the engine arm (where requesting_user is a
// third-party admin), self-service means ANY requesting_user other than the
// token's own owner is rejected by the ownership gate before it ever reaches
// the grace-window logic at all (see the dedicated non-owner tests above).
// The in-flight-rotation "different operator" state the engine arm's grace
// cache guards against is therefore structurally unreachable here.

TEST_CASE("ApiTokenStore: confirm_token_rotation cuts over immediately — revokes the "
          "predecessor and clears the successor's rotation state",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 2);
    std::string successor_id;
    for (const auto& t : active)
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto confirmed = store.confirm_token_rotation(successor_id, *rotated, "alice", "", "");
    REQUIRE(confirmed.has_value());

    // Predecessor is revoked immediately (no need to wait for the overlap
    // window), and the successor is now a standalone active credential.
    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 1);
    CHECK(after[0].token_id == successor_id);
    CHECK(after[0].rotation_group.empty());
    CHECK(after[0].supersedes_token_id.empty());
    CHECK(after[0].overlap_expires_at == 0);

    CHECK_FALSE(store.validate_token(*predecessor_raw).has_value());
}

// NOTE: there is no "confirm from a different operator" test for the human
// arm — same reasoning as rotate_token above: self-service means a non-owner
// requesting_user is rejected by the ownership gate before it ever reaches
// the initiator-binding check. See "confirm_token_rotation rejects a
// non-owner..." above.

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a token_id that is not the "
          "pending rotation's successor",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());

    // Passing the PREDECESSOR's own id (not the successor's) must be
    // rejected by the pin check, never silently accepted.
    auto mismatch =
        store.confirm_token_rotation(predecessor_id, "irrelevant-secret", "alice", "", "");
    REQUIRE_FALSE(mismatch.has_value());
    CHECK(store.list_active_for_principal("alice").size() == 2); // unchanged
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on an unknown token_id is a terminal "
          "client error, never a masked-failure retry",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto confirmed = store.confirm_token_rotation("deadbeefdeadbeefdeadbeef",
                                                  "irrelevant-secret", "admin", "", "");
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error().find("no such token") != std::string::npos);
    CHECK(classify_engine_store_error(confirmed.error()) == E::ClientValidation);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a token that was never part of a "
          "rotation is a terminal Conflict — own wording, arm-parity with the engine "
          "arm's kSoleOtherToken (round 5 adjudication)",
          "[pg][token][rotation]") {
    // Round-4 review found this branch originally reused confirm_rotation's
    // (engine arm) kSoleOtherToken wording verbatim, byte-for-byte, and so
    // silently inherited that string's classification via the "the rotation
    // was resolved" substring — a genuine bug, since the two states are
    // different FACTS (a pin mismatch against a DIFFERENT surviving
    // credential, vs. nothing pending at all) even though both happen to be
    // Conflict. Round 4's fix gave this state its own wording but ALSO
    // reclassified it to Transient, reasoning from the "call rotate again"
    // prose — round 5 adjudication refuted that: #2404 precedent, arm parity
    // with `kSoleOtherToken` (identical "rotate again" guidance, Conflict),
    // and `rotation_confirm_state.hpp`'s own "every terminal state ->
    // Conflict or ClientValidation" contract all say Conflict. This state
    // keeps its own (round-4) wording — own classifier entry, correct class.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto raw = store.create_token("never-rotated", "alice", now + k90Days);
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;

    auto confirmed =
        store.confirm_token_rotation(token_id, "irrelevant-secret", "alice", "", "");
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error().find("no rotation currently pending") != std::string::npos);
    CHECK(confirmed.error().find("the rotation was resolved") == std::string::npos);
    CHECK(classify_engine_store_error(confirmed.error()) == E::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation replay after success is a terminal "
          "Conflict, own wording distinct from the engine arm's own confirm-replay "
          "strings",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("alice"))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;

    REQUIRE(store.confirm_token_rotation(successor_id, *rotated, "alice", "", "").has_value());

    // Replay: the successor is now the SOLE active credential for alice, and
    // it is not in the pinned rotation_group any more (kGroupEmpty) — a
    // POSITIVE fact (rotation_confirm_state.hpp), terminal Conflict.
    auto replay =
        store.confirm_token_rotation(successor_id, "irrelevant-secret", "alice", "", "");
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error().find("no rotation currently pending") != std::string::npos);
    CHECK(replay.error().find("the rotation was resolved") == std::string::npos);
    CHECK(classify_engine_store_error(replay.error()) == E::Conflict);
}

TEST_CASE("ApiTokenStore: sweep_expired_rotations auto-revokes an elapsed human "
          "predecessor exactly like the engine arm",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    seed_sweep_survivor(store, now, "alice-parity-survivor");

    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    // Short overlap so the sweep at `now + kDay` finds it elapsed.
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "alice", "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 2);

    // UP-5: present the successor so the sweep actually auto-revokes (a
    // never-used successor is now left alone — see the dedicated UP-5 test
    // below); this test is about the human/engine sweep parity, not UP-5.
    REQUIRE(store.validate_token(*rotated).has_value());

    // Forced into the past relative to PostgreSQL's own clock — #2964, the
    // sweep's eligibility decision no longer reads the `now` argument.
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);
    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(swept.revoked.size() == 1);
    CHECK(swept.revoked[0].token_id == predecessor_id);

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 1);
    CHECK(after[0].rotation_group.empty()); // successor's linkage cleared too
}

// ── P2 #11 / SOC 2 CC6.3: token-keyed rotation for HUMAN-owned tokens ──────
//
// `rotate_token`/`confirm_token_rotation` do not exist on ApiTokenStore as of
// this writing — this section is written against their PINNED signatures (P5
// task brief) precisely so it is an INDEPENDENT regression suite for whoever
// lands the implementation, not a test written by the same author grading
// their own blind spots. It will not compile until both land with exactly:
//
//   [[nodiscard]] std::expected<std::string, std::string>
//   rotate_token(const std::string& predecessor_token_id, int64_t overlap_secs,
//                int64_t now, const std::string& requesting_user,
//                std::optional<int64_t> successor_expires_at = std::nullopt);
//
//   [[nodiscard]] std::expected<void, std::string>
//   confirm_token_rotation(const std::string& successor_token_id,
//                          const std::string& requesting_user);
//
// THE regression this whole section exists to catch: `rotate_engine_credential`
// / `confirm_rotation` above arbitrate on `read_active_for_principal_on_conn`'s
// PRINCIPAL-scoped count — correct for an engine principal, which owns exactly
// one rotation lineage, but wrong for a human, who routinely holds N unrelated
// tokens under the SAME principal_id (their username). A naive port that
// reused the principal-scoped read would mean a user with exactly 2 tokens can
// NEVER rotate either one (an unrelated second token always reads as
// "rotation already in flight"), and a user with 3+ ALWAYS hits the >2-active
// defensive reject — for every token, every time. `rotate_token` takes a
// TOKEN id, not a PRINCIPAL id, specifically so the ≤2 ceiling is scoped to
// the predecessor's own rotation GROUP, never the principal's whole set.
//
// Classifier calibration below: substrings already pinned as GENERIC shared
// vocabulary in engine_store_error_class.hpp (floor/ceiling/expiry/
// different-operator/grace-window/pin-mismatch — none of it says "engine")
// are asserted verbatim, since the header's own docstring says it classifies
// EnginePrincipalStore *and* ApiTokenStore errors generically. Confirm-side
// rotation-STATE wording (sole/resolved/unresolved), which is more likely to
// be reworded for a "rotation group" mental model instead of a "principal"
// one, is asserted only via `classify_engine_store_error`'s returned CLASS —
// still a real tripwire (per the header's #2404 doctrine, a reworded message
// that drops every keyed substring silently reclassifies to the retryable
// Transient default, and an honest client then retries a terminal failure
// forever), without hard-pinning prose this suite's author cannot know yet.

namespace {

using yuzu::server::detail::classify_engine_store_error;
using ClsE = yuzu::server::detail::EngineStoreErrorClass;

} // namespace

// ── Item 1: THE regression — group-scoped, not principal-scoped ───────────

TEST_CASE("ApiTokenStore: rotate_token on a human token is GROUP-scoped, not "
          "principal-scoped — a user holding 3 unrelated active tokens can "
          "rotate ONE without hitting the engine machine's principal-wide "
          "ceiling (P2 #11 THE regression)",
          "[pg][token][rotation][human]") {
    // Defect this catches: if rotate_token were ported by reusing
    // read_active_for_principal_on_conn's principal-keyed count (as
    // rotate_engine_credential does), alice's 3rd active token would put her
    // principal-wide count at 3 BEFORE rotate even starts, landing the >2
    // defensive reject on every call — this is the exact production shape
    // (any user with 2+ unrelated tokens can never rotate any of them) and is
    // the entire reason rotate_token takes a token_id, not a principal_id.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t1 = store.create_token("CI token", "alice", now + k90Days);
    auto t2 = store.create_token("Laptop PAT", "alice", now + k90Days);
    auto t3 = store.create_token("Backup script", "alice", now + k90Days);
    REQUIRE(t1.has_value());
    REQUIRE(t2.has_value());
    REQUIRE(t3.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 3);

    auto v2 = store.validate_token(*t2);
    REQUIRE(v2.has_value());
    const std::string t2_id = v2->token_id;

    auto rotated = store.rotate_token(t2_id, kDefaultOverlapSecs, now, "alice", "", "");
    REQUIRE(rotated.has_value());
    CHECK(rotated->starts_with("yuzu_"));

    // t1 and t3 are completely untouched: still active, no rotation state.
    auto v1 = store.validate_token(*t1);
    REQUIRE(v1.has_value());
    CHECK(v1->rotation_group.empty());
    auto v3 = store.validate_token(*t3);
    REQUIRE(v3.has_value());
    CHECK(v3->rotation_group.empty());

    // alice now has 4 active credentials fleet-wide (t1, t3, predecessor t2,
    // successor) — a principal-wide ≤2 ceiling would have instantly rejected
    // this rotate. It succeeded anyway.
    CHECK(store.list_active_for_principal("alice").size() == 4);
}

// ── Item 2: ≤2 ceiling is per-GROUP, other tokens irrelevant ───────────────

TEST_CASE("ApiTokenStore: rotate_token's ≤2 ceiling is scoped to the "
          "predecessor's rotation GROUP — a same-user unrelated token never "
          "trips, or is tripped by, another group's arbitration",
          "[pg][token][rotation][human]") {
    // Defect this catches: if the arbitration read counted the principal's
    // whole active set, rotating token A twice (predecessor+successor = 2)
    // while bob ALSO holds unrelated token B would see 3-active and hit the
    // defensive ">2 active, resolve manually" reject — even though B has
    // nothing to do with A's rotation. A group-scoped read must ignore B.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto a = store.create_token("Token A", "bob", now + k90Days);
    auto b = store.create_token("Token B", "bob", now + k90Days);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    auto va = store.validate_token(*a);
    REQUIRE(va.has_value());
    const std::string a_id = va->token_id;

    // First rotate of A mints a successor -> A's group now has 2 rows.
    auto first = store.rotate_token(a_id, kDefaultOverlapSecs, now, "bob", "", "");
    REQUIRE(first.has_value());

    // A same-operator retry within grace re-serves the SAME raw — the
    // in-flight-pair re-serve arm, exercised at A's group scope alone.
    auto retry = store.rotate_token(a_id, kDefaultOverlapSecs, now, "bob", "", "");
    REQUIRE(retry.has_value());
    CHECK(*retry == *first);

    // A non-owner probing A's in-flight pair is rejected by the store-level
    // self-service ownership gate (item 7's dedicated coverage), never by
    // the F4-style "different operator" grace-window conflict — under
    // self-service there is only ONE legitimate requesting_user per token,
    // so that state is unreachable via a wrong caller (see :851 in the
    // checklist). No distinguishable wording is asserted here on purpose —
    // asserting one would itself be an enumeration-oracle regression (item
    // 7b). B, held by the SAME principal, plays no part in this rejection.
    auto stolen = store.rotate_token(a_id, kDefaultOverlapSecs, now, "mallory", "", "");
    REQUIRE_FALSE(stolen.has_value());

    // B is completely unaffected throughout.
    auto vb = store.validate_token(*b);
    REQUIRE(vb.has_value());
    CHECK(vb->rotation_group.empty());
    CHECK_FALSE(vb->revoked);
}

// ── Item 2b: Hermes F2 atomic pair-commit (token-keyed twin of :1012) ─────

TEST_CASE("ApiTokenStore: rotate_token never leaves an orphaned rotation "
          "pair — mint and pair-stamp always commit together (Hermes F2, "
          "human arm)",
          "[pg][token][rotation][human]") {
    // Token-keyed twin of :1012. Every prior human-arm test asserted the
    // SUCCESSOR side of the pair (supersedes_token_id, TTL inheritance,
    // etc.) but never fetched the PREDECESSOR row after a successful
    // rotate_token and checked IT was stamped. Defect this catches: an
    // implementation whose successor INSERT and predecessor pair-stamp
    // UPDATE are not the same atomic transaction could mint a
    // correctly-linked successor while the predecessor's own
    // rotation_group/overlap_expires_at are left at their pre-rotation
    // defaults — an orphaned pair, invisible to every assertion this suite
    // made before this test, and exactly F2's defect class. It matters more
    // here than in the engine arm: `sweep_expired_rotations`'s auto-revoke
    // depends entirely on the predecessor's own `overlap_expires_at` being
    // stamped (see the two tests below), so an orphan here silently
    // disables the sweep for that credential, not just the pairing record.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Pair-commit PAT", "priya", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "priya", "", "");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("priya");
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& tok : active) {
        if (tok.token_id == predecessor_id)
            predecessor = &tok;
        else
            successor = &tok;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);

    // The full triple :1012 asserts — predecessor side included, which is
    // exactly the half every earlier test in this section skipped.
    CHECK_FALSE(predecessor->rotation_group.empty());
    CHECK(predecessor->rotation_group == successor->rotation_group);
    CHECK(predecessor->overlap_expires_at > 0);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
    CHECK(predecessor->supersedes_token_id.empty());
}

TEST_CASE("ApiTokenStore: sweep_expired_rotations auto-revokes a human "
          "predecessor whose overlap window has lapsed, and clears the "
          "surviving successor's rotation state",
          "[pg][token][rotation][human][sweep]") {
    // Defect this catches: `sweep_expired_rotations` is untouched by
    // anything else in this section — if it were never invoked here it
    // would ship with zero coverage on the token-keyed path despite being
    // the SOLE enforcement of predecessor auto-revoke (validate_token never
    // checks overlap_expires_at, per its own doc comment). This also
    // exercises the F2 pair-stamp's SECOND-ORDER consequence the previous
    // test names: the sweep only finds this predecessor eligible because
    // rotate_token stamped its overlap_expires_at correctly.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    seed_sweep_survivor(store, now, "sanjay-clears-successor-survivor");

    auto t = store.create_token("Sweep PAT", "sanjay", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    // A short overlap window so the sweep fires shortly after `now`.
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "sanjay", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("sanjay"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // UP-5: present the successor so the sweep actually auto-revokes (this
    // test is about the sweep's own auto-revoke/clear behavior, not UP-5's
    // never-used carve-out, which has its own dedicated test).
    REQUIRE(store.validate_token(*rotated).has_value());

    // Forced into the past relative to PostgreSQL's own clock — #2964, the
    // sweep's eligibility decision no longer reads the `now` argument.
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);
    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    bool predecessor_in_swept = false;
    for (const auto& tok : swept.revoked)
        if (tok.token_id == predecessor_id)
            predecessor_in_swept = true;
    CHECK(predecessor_in_swept);

    auto active = store.list_active_for_principal("sanjay");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK(active[0].rotation_group.empty());       // cleared by the sweep
    CHECK(active[0].supersedes_token_id.empty());
    CHECK(active[0].overlap_expires_at == 0);

    auto pred = store.get_token(predecessor_id);
    REQUIRE(pred.has_value());
    REQUIRE(pred->has_value());
    CHECK((*pred)->revoked); // the predecessor was actually revoked
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a NEVER-USED successor's predecessor is "
          "left active past its overlap window — never auto-revoked to zero usable "
          "credentials (UP-5)",
          "[pg][token][rotation][human][sweep][up5]") {
    // Defect this catches: pre-fix, sweep_expired_rotations auto-revoked the
    // predecessor purely on `overlap_expires_at <= now` plus "a live
    // successor row exists" — with no regard for whether that successor's
    // secret was ever actually delivered/used. A dropped rotate response or
    // an operator who never picked up the new credential ends the overlap
    // window with the WORKING credential revoked and the never-presented
    // one the principal's only (unusable, because unknown to them)
    // credential — zero usable credentials, unattended.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Lost-successor PAT", "priya-up5", now + k90Days);
    REQUIRE(t.has_value());
    const std::string predecessor_id = store.list_active_for_principal("priya-up5")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDay, now, "priya-up5", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("priya-up5"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Deliberately never validate the successor — the "secret was lost /
    // never delivered" case this fix guards against.

    // Forced into the past relative to PostgreSQL's own clock — #2964 —
    // so this genuinely exercises "elapsed AND never-used-successor", not
    // merely "not yet elapsed for an unrelated reason".
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);
    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    // THE ASSERTION THIS TEST EXISTS FOR: pre-fix this predecessor would be
    // in `swept` (auto-revoked). Post-fix it must be left alone.
    CHECK(swept.revoked.empty());

    auto pred_after = store.get_token(predecessor_id);
    REQUIRE(pred_after.has_value());
    REQUIRE(pred_after->has_value());
    CHECK_FALSE((*pred_after)->revoked);
    auto succ_after = store.get_token(successor_id);
    REQUIRE(succ_after.has_value());
    REQUIRE(succ_after->has_value());
    CHECK_FALSE((*succ_after)->revoked);
    // Both credentials genuinely still active — never zero.
    CHECK(store.list_active_for_principal("priya-up5").size() == 2);

    // The pair keeps warning even PAST its own overlap window —
    // list_rotations_nearing_expiry_unused no longer stops surfacing an
    // unused-successor pair once `overlap_expires_at <= now` (the old
    // "strictly future" floor this fix removes for exactly this case).
    // #2964 fix round finding 7: no longer takes a caller `now` — the
    // predecessor's `overlap_expires_at` was already forced into the past
    // relative to PostgreSQL's own clock above (`force_overlap_expires_at`),
    // so it is found regardless of which instant this half's own internal
    // PG clock read lands on.
    auto nearing = store.list_rotations_nearing_expiry_unused(3600);
    bool found = false;
    for (const auto& pair : nearing.pairs)
        if (pair.predecessor.token_id == predecessor_id)
            found = true;
    CHECK(found);

    // Idempotent — a much later sweep still declines; this is not a
    // one-tick reprieve, it is an indefinite hold until an operator acts.
    auto second = store.sweep_expired_rotations(now + kDay + 100);
    CHECK(second.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(second.revoked.empty());
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: caps auto-revokes per tick — a clock jump "
          "degrades to a multi-tick drain, never a single fleet-wide cutover (UP-6)",
          "[pg][token][rotation][human][sweep][up6]") {
    // Defect this catches: pre-fix, the predecessor scan had no LIMIT at
    // all — every eligible predecessor was processed in one tick,
    // regardless of count. A single forward clock step (NTP correction,
    // clock drift fix) would then cut over every in-flight rotation
    // fleet-wide in that one 60s tick.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    // Principal deliberately does NOT match the `cap-test-up6-%` LIKE
    // pattern the bulk force-elapse UPDATE below uses, or this survivor
    // would be swept into the past right along with the 201 pairs under
    // test and stop being a survivor.
    seed_sweep_survivor(store, now, "cap-survivor-only");

    // kMaxAutoRevokesPerTick (api_token_store.cpp, currently 200) + 1 —
    // one more pair than the cap allows in a single tick, each on its own
    // principal so no per-rotation-group ceiling gets in the way.
    constexpr int kPairs = 201;
    for (int i = 0; i < kPairs; ++i) {
        const std::string principal = "cap-test-up6-" + std::to_string(i);
        REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
        const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
        auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
        REQUIRE(rotated.has_value());
        // UP-5: the successor must be USED, or this pair is excluded from
        // the cap-eligible set entirely by the never-used carve-out — this
        // test is about UP-6's cap, not UP-5's carve-out.
        REQUIRE(store.validate_token(*rotated).has_value());
    }

    // Force every predecessor's overlap window into the past relative to
    // PostgreSQL's own clock (#2964) in ONE bulk UPDATE — 201 individual
    // round trips would work too, but this is the same operation the
    // production sweep itself would observe.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "UPDATE api_token_store.api_tokens SET overlap_expires_at = $1 "
            "WHERE principal_id LIKE 'cap-test-up6-%' AND supersedes_token_id = ''",
            std::vector<std::string>{std::to_string(pg_now(pool) - 1)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    // THE ASSERTION THIS TEST EXISTS FOR: pre-fix, `swept.revoked.size()`
    // would be 201 (every eligible row, unconditionally, in one tick).
    // Post-fix it is capped, and the cap is reported.
    CHECK(swept.capped);
    CHECK(swept.revoked.size() == 200);

    // The remainder drains on the NEXT tick — nothing is lost, only
    // deferred, and the second tick reports itself uncapped.
    auto second = store.sweep_expired_rotations(now + kDay + 2);
    REQUIRE(second.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK_FALSE(second.capped);
    CHECK(second.revoked.size() == 1);
}

// ── #2964: clock-guarded-retention shape (routed concern, all seven parts) ──

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a persisted prior reading + a "
          "forward-skewed pass declines rather than drains — the reviewer's falsifier",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: with a genuinely stale durable
    // anchor (`last_pass_now` far enough behind PostgreSQL's own clock to
    // trip the absolute step threshold, part 7), the sweep must DECLINE —
    // never silently auto-revoke a live credential on an unverified clock
    // history. Reverting the production `big_step` check (or the anchor
    // read it depends on) makes this test fail: `first.outcome` would come
    // back `Ok` with the predecessor already in `first.revoked`.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    seed_sweep_survivor(store, now, "falsifier-survivor");

    auto t = store.create_token("Falsifier PAT", "falsifier-principal", now + k90Days);
    REQUIRE(t.has_value());
    const std::string predecessor_id =
        store.list_active_for_principal("falsifier-principal")[0].token_id;
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "falsifier-principal", "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);

    // Directly poison the durable anchor to a reading far enough in the
    // past to trip `kRotationSweepBigStepSecs` — simulates a server that
    // has not swept in a very long time (or whose clock jumped forward),
    // WITHOUT waiting for real time to pass. Direct-SQL precedent:
    // `force_overlap_expires_at` above / `wire_manual_rotation_pair`.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{
                std::to_string(pg_now(pool) - kRotationSweepBigStepSecs - 1000)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    auto first = store.sweep_expired_rotations(now);
    REQUIRE(first.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(first.revoked.empty());
    CHECK_FALSE(first.decline_reason.empty());

    // Both credentials in the pair stay fully active — nothing was
    // auto-revoked on the unverified reading.
    auto pred_after = store.get_token(predecessor_id);
    REQUIRE(pred_after.has_value());
    REQUIRE(pred_after->has_value());
    CHECK_FALSE((*pred_after)->revoked);

    // Not permanent: the decline re-anchors, so the VERY NEXT pass compares
    // against a fresh reading (no longer a big step) and drains, paced by
    // the cap as always — the same "declines once, then drains" shape
    // `AuditStore` documents for its own #2579 fix.
    auto second = store.sweep_expired_rotations(now + 1);
    REQUIRE(second.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(second.revoked.size() == 1);
    CHECK(second.revoked[0].token_id == predecessor_id);
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a big-step anomaly arriving on a database "
          "that has never reached a verdict still reports no_anchor=true (#2964 round 3 review "
          "finding 2)",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: `classify`'s precedence
    // (`BadState > Step > Wipe > NoAnchor`, `audit_retention_rules.hpp`)
    // means a tick that observes BOTH a big step AND a not-yet-settled
    // bootstrap classifies as `Anomaly::Step`, not `Anomaly::NoAnchor` — but
    // `facts.no_anchor` is still true, and `SweepResult::no_anchor` (the raw
    // fact server.cpp's metric split routes on) must reflect that
    // regardless of which anomaly `decline_anomaly` names. Simulated the
    // same way the reviewer's falsifier test above does: a directly-poisoned
    // durable `last_pass_now` far enough in the past to trip the step
    // threshold, but — unlike every other test in this file, which anchors
    // via `anchor_sweep_guard` first — deliberately WITHOUT ever letting a
    // pass settle `bootstrap_settled`, simulating a prior pass that reached
    // the unconditional re-anchor stamp but failed before reaching a verdict
    // (`sweep_expired_rotations`'s own comment: "the pass has now reached a
    // VERDICT — settle the bootstrap marker HERE ... so a pass whose probes
    // fail leaves the trigger armed").
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    const std::string principal = "no-anchor-plus-step";
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
    auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
    force_overlap_expires_at(pool, pred_id, pg_now(pool) - 1);

    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{
                std::to_string(pg_now(pool) - kRotationSweepBigStepSecs - 1000)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
        // Deliberately NO 'bootstrap_settled' row — this is the whole point.
    }

    auto tick = store.sweep_expired_rotations(now);
    REQUIRE(tick.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(tick.decline_anomaly == audit_retention::Anomaly::Step);
    // THE FIELD THIS TEST PINS: true even though `decline_anomaly` named a
    // DIFFERENT anomaly — a caller switching on `decline_anomaly ==
    // NoAnchor` instead would miscount this tick to the clock-anomaly
    // series, exactly the false "the clock moved" claim the bootstrap-vs-
    // clock-anomaly counter split exists to avoid.
    CHECK(tick.no_anchor);
    CHECK(tick.revoked.empty());
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a decline is distinguishable from "
          "\"nothing eligible\" through the typed outcome",
          "[pg][token][rotation][sweep][clock-guard]") {
    // Pre-#2964 the store returned an empty vector for BOTH "the clock
    // guard declined" and "nothing was eligible this tick" — this test
    // pins that the typed outcome tells them apart.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();

    // "Nothing eligible": an anchored, empty store — Ok, not Declined.
    auto nothing_eligible = store.sweep_expired_rotations(now);
    REQUIRE(nothing_eligible.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(nothing_eligible.revoked.empty());

    // "Declined": poison the (now-settled) anchor to trip the step
    // threshold, then mint + elapse ONE eligible pair.
    seed_sweep_survivor(store, now, "distinguish-survivor");
    auto t = store.create_token("Distinguish PAT", "distinguish-principal", now + k90Days);
    REQUIRE(t.has_value());
    const std::string predecessor_id =
        store.list_active_for_principal("distinguish-principal")[0].token_id;
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "distinguish-principal", "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{
                std::to_string(pg_now(pool) - kRotationSweepBigStepSecs - 1000)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    auto declined = store.sweep_expired_rotations(now);
    // THE ASSERTION THIS TEST EXISTS FOR: both calls left `revoked` empty,
    // but only ONE of them is a clock-guard decline — the typed outcome is
    // what tells them apart (a bool/empty-vector-only contract could not).
    REQUIRE(declined.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(declined.revoked.empty());
    CHECK(declined.outcome != nothing_eligible.outcome);
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: SweepOutcome::SkippedLock when another "
          "session already holds the store-wide sweep lock",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: `sweep_expired_rotations` uses a
    // TRY-lock (`pg_try_advisory_lock`, never the blocking form) on a
    // store-wide SESSION advisory lock in its own key namespace
    // (`hashtextextended('api_token_store:rotation_sweep', 0)`) — holding
    // that exact lock from an independent raw connection, the same key a
    // second server replica would race for, must make the store's own call
    // return `SkippedLock` immediately rather than block or fail.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);

    // Hold the sweep's own lock from an independent connection — the exact
    // key `sweep_expired_rotations` itself takes.
    auto holder = pool.acquire();
    REQUIRE(holder);
    {
        pg::PgResult lock_res{PQexec(
            holder.get(),
            "SELECT pg_try_advisory_lock(hashtextextended('api_token_store:rotation_sweep', 0))")};
        REQUIRE(lock_res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(lock_res.get()) == 1);
        REQUIRE(std::string(PQgetvalue(lock_res.get(), 0, 0)) == "t");
    }

    auto swept = store.sweep_expired_rotations(now);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::SkippedLock);
    CHECK(swept.revoked.empty());
    CHECK(swept.decline_reason.empty()); // SkippedLock is routine, not a decline
    CHECK(swept.fail_reason.empty());    // and not a failure either

    // Release, and confirm the sweep can now proceed normally.
    {
        pg::PgResult unlock_res{PQexec(
            holder.get(),
            "SELECT pg_advisory_unlock(hashtextextended('api_token_store:rotation_sweep', 0))")};
        REQUIRE(unlock_res.status() == PGRES_TUPLES_OK);
        REQUIRE(std::string(PQgetvalue(unlock_res.get(), 0, 0)) == "t");
    }
    auto after_release = store.sweep_expired_rotations(now + 1);
    CHECK(after_release.outcome == ApiTokenStore::SweepOutcome::Ok);
}

TEST_CASE("ApiTokenStore::rotation_sweep_last_pass_now: nullopt before any pass has reached a "
          "verdict, and PERSISTS across a fresh store reconstruction against the same DSN",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: `last_pass_now` is a durable,
    // CLUSTER-WIDE PostgreSQL row (`rotation_retention_meta.last_pass_now`),
    // never process-local state cached on the C++ `ApiTokenStore` object —
    // a second `ApiTokenStore` constructed against the SAME DSN must observe
    // the SAME reading. Nothing in this file builds a second store against
    // one database anywhere else, so a regression that cached this value on
    // the object instead of reading it from PostgreSQL would pass every
    // other test here and only break multi-replica deployments in
    // production, where every replica must observe the ONE shared anchor
    // (see the accessor's own doc comment, Part 2 + the routed concern's
    // unnumbered SINGLE-WRITER clause).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    {
        ApiTokenStore store{pool};
        REQUIRE(store.is_open());
        // Fresh database, no pass has ever reached a verdict yet.
        CHECK_FALSE(store.rotation_sweep_last_pass_now().has_value());

        auto now = test_now_epoch();
        auto first = store.sweep_expired_rotations(now);
        REQUIRE(first.outcome == ApiTokenStore::SweepOutcome::Ok);
        auto stamped = store.rotation_sweep_last_pass_now();
        REQUIRE(stamped.has_value());
        CHECK(*stamped > 0);
    }

    // A SECOND, independently constructed store against the SAME DSN reads
    // the identical durable reading — not `nullopt`, and not a fresh `0`, as
    // a process-local cache would produce on a brand-new object.
    {
        ApiTokenStore second_store{pool};
        REQUIRE(second_store.is_open());
        auto reread = second_store.rotation_sweep_last_pass_now();
        REQUIRE(reread.has_value());
        CHECK(*reread > 0);
    }
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a tree of only never-used-successor "
          "pairs never gets swept (UP-5 pairs are excluded from the ELIGIBLE set)",
          "[pg][token][rotation][sweep][clock-guard][up5]") {
    // THE ASSERTION THIS TEST EXISTS FOR: every predecessor here is
    // permanently ineligible (its successor was never presented) and every
    // one has an elapsed overlap window — the eligibility probe's
    // `kRotationEligiblePredicate` (shared with the candidate SELECT) must
    // exclude these via its `s.last_used_at <> 0` clause (UP-5), or
    // `has_expired` would read TRUE for a population that has nothing this
    // sweep is actually allowed to touch. This store's `would_wipe` fact is
    // hardcoded `false` (see the DELIBERATE NON-ADOPTION comment near
    // `kRotationSweepBigStepSecs`'s definition), so this test no longer
    // exercises a would-wipe misclassification risk — it pins the narrower,
    // still load-bearing claim that the UP-5 exclusion keeps these rows out
    // of `has_expired` (and therefore out of the candidate SELECT) at all.
    // Reverting the probe SQL to drop the `s.last_used_at <> 0` clause
    // (part 1's own eligibility predicate, not part 5 — #2964 round 3
    // review finding 6 caught this exact mis-citation already fixed in the
    // header but missed here) makes `swept.revoked` non-empty below — this
    // test would then be revoking predecessors whose successor secret was
    // never confirmed presented, the exact UP-5 failure mode.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);

    // Deliberately NO survivor pair and NO other activity — the whole
    // point is that the UP-5 exclusion alone is enough; nothing else props
    // this up.
    for (int i = 0; i < 3; ++i) {
        const std::string principal = "up5-only-tree-" + std::to_string(i);
        REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
        const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
        auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
        REQUIRE(rotated.has_value());
        // Deliberately never validate the successor (UP-5's carve-out).
        force_overlap_expires_at(pool, pred_id, pg_now(pool) - 1);
    }

    auto swept = store.sweep_expired_rotations(now);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(swept.revoked.empty());
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a large, wholly-expired eligible "
          "population still drains as Ok, with no last_anomaly_facts row — pins the "
          "DELIBERATE NON-ADOPTION of routed-concern part 1's would-wipe half against a "
          "silent reintroduction",
          "[pg][token][rotation][sweep][clock-guard][up6]") {
    // THE ASSERTION THIS TEST EXISTS FOR: this store does NOT adopt the
    // clock-guarded-retention routed concern's part-1 would-wipe probe (see
    // the DELIBERATE NON-ADOPTION comment near `kRotationSweepBigStepSecs`'s
    // definition) — 100% eligible expiry is this store's ROUTINE drain
    // shape, not evidence of a clock anomaly. Nothing existing pins this:
    // the fact-set dedup tests above assert `decline_anomaly ==
    // Anomaly::Step`, and `classify`'s precedence (`BadState > Step > Wipe
    // > NoAnchor`) means Step already outranks Wipe in every scenario those
    // tests construct — a reintroduced would-wipe probe stays completely
    // hidden behind Step there. This test constructs a population with NO
    // big-step, NO bad-state, and NO missing anchor — ONLY a large, wholly
    // expired eligible set — so a reintroduced would-wipe probe has nothing
    // else to hide behind: it would surface here as `Declined`,
    // `Anomaly::Wipe`, zero revocations, and a `last_anomaly_facts` row,
    // none of which a correctly non-adopting sweep produces.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);

    // A population well past any plausible would-wipe population floor a
    // reintroduced probe might use (`kMinWipeProbePopulation`, since
    // removed — the DELIBERATE NON-ADOPTION comment's own account of that
    // first attempt is why no floor closes this gap).
    constexpr int kPairs = 50;
    for (int i = 0; i < kPairs; ++i) {
        const std::string principal = "s5-pin-would-wipe-" + std::to_string(i);
        REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
        const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
        auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
        REQUIRE(rotated.has_value());
        REQUIRE(store.validate_token(*rotated).has_value()); // UP-5: successor presented
        force_overlap_expires_at(pool, pred_id, pg_now(pool) - 1);
    }

    auto swept = store.sweep_expired_rotations(now);
    // THE FIELD THIS TEST PINS: a wholly-expired population is a ROUTINE
    // drain, never a decline.
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(swept.revoked.size() == static_cast<std::size_t>(kPairs));

    // No `last_anomaly_facts` row survives this all-Ok tick. A reintroduced
    // would-wipe probe that classified this population as `Wipe` would have
    // written one when it declined — its continued absence here is
    // asserted directly, not merely inferred from the outcome above.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "SELECT value FROM api_token_store.rotation_retention_meta WHERE key = "
            "'last_anomaly_facts'",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(PQntuples(r.get()) == 0);
    }
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: the anchor sanitiser treats an "
          "ahead-of-now, a negative, and an unparseable reading as an anomaly",
          "[pg][token][rotation][sweep][clock-guard]") {
    // Three independent malformed-anchor shapes, each of which must decline
    // (never a quiet reset — routed concern part 3) rather than silently
    // draining on an untrustworthy comparison point. Each SECTION gets its
    // own fresh PgTestTemplate clone (the enclosing TEST_CASE body,
    // including YUZU_REQUIRE_PG_DB_TPL, re-runs per leaf SECTION).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);
    seed_sweep_survivor(store, now, "sanitiser-survivor");

    auto t = store.create_token("Sanitiser PAT", "sanitiser-principal", now + k90Days);
    REQUIRE(t.has_value());
    const std::string predecessor_id =
        store.list_active_for_principal("sanitiser-principal")[0].token_id;
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "sanitiser-principal", "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
    force_overlap_expires_at(pool, predecessor_id, pg_now(pool) - 1);

    std::string poisoned_value;
    SECTION("ahead-of-now") { poisoned_value = std::to_string(pg_now(pool) + 10'000'000); }
    SECTION("negative") { poisoned_value = "-1"; }
    SECTION("unparseable") { poisoned_value = "not-a-number"; }

    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{poisoned_value});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    auto swept = store.sweep_expired_rotations(now);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(swept.revoked.empty());
    auto pred_after = store.get_token(predecessor_id);
    REQUIRE(pred_after.has_value());
    REQUIRE(pred_after->has_value());
    CHECK_FALSE((*pred_after)->revoked); // never auto-revoked on a corrupt reading
}

// ── #2964 round 3 review finding 7: fact-set dedup mechanism coverage ───────
// (zero coverage before this — the review's own mutation test replaced the
// dedup comparison with `if (true)`, disabling suppression entirely, and the
// full 176-case suite stayed green.)

TEST_CASE("ApiTokenStore::sweep_expired_rotations: fact-set dedup SUPPRESSES a repeat of the "
          "IDENTICAL anomaly and drains on the second tick",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: the SECOND tick, observing the
    // same anomaly SHAPE (`big_step`, with `has_expired` also true) as the
    // first, must NOT decline again — it must be suppressed and drain.
    // Disabling the dedup comparison (mutating `facts_ser != last_facts` to
    // `true`) makes this test fail: `second.outcome` would come back
    // `Declined` a second time and `second.revoked` would stay empty.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);

    const std::string principal = "dedup-identical-repeat";
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
    auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
    force_overlap_expires_at(pool, pred_id, pg_now(pool) - 1);

    auto poison_big_step = [&]() {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{
                std::to_string(pg_now(pool) - kRotationSweepBigStepSecs - 1000)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    };

    // Tick 1: poisoned anchor trips `big_step` — declines and records facts
    // "e-s--" (has_expired + big_step only; would_wipe is hardcoded false
    // for this store, prev_unusable/no_anchor both false).
    poison_big_step();
    auto first = store.sweep_expired_rotations(now);
    REQUIRE(first.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(first.decline_anomaly == audit_retention::Anomaly::Step);
    CHECK(first.revoked.empty());

    // Re-poison the anchor to trip the SAME anomaly SHAPE again (a fresh
    // big-step gap measured from the NOW-current pg_now, since tick 1's own
    // decline already re-anchored to it) — the fact SET this produces is
    // byte-identical to tick 1's ("e-s--"), even though the underlying
    // stamped VALUE differs. This simulates the real-world case the routed
    // concern's own "identical anomaly repeating tick after tick" language
    // describes: a clock fault that keeps landing on the same big-step
    // shape, not a literal replay of the same durable row.
    poison_big_step();
    auto second = store.sweep_expired_rotations(now + 1);
    // THE FIELD THIS TEST PINS: suppressed and drained, not declined again.
    REQUIRE(second.outcome == ApiTokenStore::SweepOutcome::Ok);
    REQUIRE(second.revoked.size() == 1);
    CHECK(second.revoked[0].token_id == pred_id);
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: fact-set dedup does NOT suppress a "
          "DIFFERENT anomaly arriving on top of an already-recorded one",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: dedup compares the WHOLE fact set,
    // never a latch bool — a genuinely different anomaly must decline again
    // even though SOME anomaly was already recorded. Collapsing the
    // comparison to a bool ("has any anomaly been recorded at all") makes
    // this test fail: `second.outcome` would come back `Ok` instead of
    // `Declined` a second time, with the predecessor silently auto-revoked
    // on an unrelated, still-unverified reading.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);

    const std::string principal = "dedup-different-anomaly";
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
    auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
    force_overlap_expires_at(pool, pred_id, pg_now(pool) - 1);

    // Tick 1: poison to trip `big_step` — declines, records facts "e-s--"
    // (Anomaly::Step).
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{
                std::to_string(pg_now(pool) - kRotationSweepBigStepSecs - 1000)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto first = store.sweep_expired_rotations(now);
    REQUIRE(first.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(first.decline_anomaly == audit_retention::Anomaly::Step);
    CHECK(first.revoked.empty());

    // Tick 2: a DIFFERENT anomaly — poison to an unparseable reading
    // (`prev_unusable`) instead. `prev.reset()` on an unusable reading means
    // `big_step` cannot also be true (it requires `prev.has_value()`), so
    // the resulting fact set is "e--u-" (has_expired + prev_unusable only)
    // — genuinely different from tick 1's "e-s--".
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{"not-a-number"});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto second = store.sweep_expired_rotations(now + 1);
    // THE FIELD THIS TEST PINS: a genuinely new anomaly declines again.
    REQUIRE(second.outcome == ApiTokenStore::SweepOutcome::Declined);
    CHECK(second.decline_anomaly == audit_retention::Anomaly::BadState);
    CHECK(second.revoked.empty());

    auto pred_after = store.get_token(pred_id);
    REQUIRE(pred_after.has_value());
    REQUIRE(pred_after->has_value());
    CHECK_FALSE((*pred_after)->revoked);
}

TEST_CASE("ApiTokenStore: list_rotations_nearing_expiry_unused surfaces a "
          "human rotation pair whose overlap window is about to lapse and "
          "whose successor has never been presented",
          "[pg][token][rotation][human][sweep]") {
    // Defect this catches: like sweep_expired_rotations, this read-only T12
    // half is never exercised anywhere else in this section — an
    // implementation whose rotate_token mints a pair with the fields this
    // query filters on populated INCORRECTLY (e.g. `last_used_at` stamped
    // at mint time, or `overlap_expires_at` left outside the warn window)
    // would silently never surface the "successor unused, window closing"
    // operational-health signal for a human PAT, with no test catching it.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Unused-successor PAT", "tanya", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    // Overlap window ends in exactly 1 day — ask for pairs whose window
    // ends within 2 days, so this pair is within the warn threshold but its
    // window has NOT yet elapsed.
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "tanya", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("tanya"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // #2964 fix round finding 7: no longer takes a caller `now` (reads
    // PostgreSQL's own clock internally) — the predecessor's overlap window
    // was set relative to `now` above, which is real wall-clock time here,
    // so this is equivalent.
    auto nearing = store.list_rotations_nearing_expiry_unused(/*warn_within_secs=*/2 * kDay);
    bool found = false;
    for (const auto& pair : nearing.pairs) {
        if (pair.predecessor.token_id == predecessor_id) {
            found = true;
            CHECK(pair.successor.token_id == successor_id);
            CHECK(pair.successor.last_used_at == 0); // never presented
        }
    }
    CHECK(found);

    // A rotation NOT nearing expiry (fresh, full-length overlap) must NOT be
    // surfaced — proves this isn't just "every in-flight pair, unfiltered".
    auto t2 = store.create_token("Not-nearing PAT", "tanya", now + k90Days);
    REQUIRE(t2.has_value());
    auto vt2 = store.validate_token(*t2);
    REQUIRE(vt2.has_value());
    auto rotated2 =
        store.rotate_token(vt2->token_id, kDefaultOverlapSecs, now, "tanya", "", ""); // 7d overlap
    REQUIRE(rotated2.has_value());
    auto nearing2 = store.list_rotations_nearing_expiry_unused(/*warn_within_secs=*/2 * kDay);
    for (const auto& pair : nearing2.pairs)
        CHECK(pair.predecessor.token_id != vt2->token_id);
}

// ── Item 2c: group-scoped >2 active defensive reject (token-keyed twin of
//    :921/:1356) ──────────────────────────────────────────────────────────
//
// Distinct from item 1's regression (unrelated same-principal tokens must
// NOT trip a ceiling) — this is the opposite-direction property: THREE
// active rows sharing the SAME rotation_group must still be defensively
// rejected, never silently arbitrated. Both matter, and each needs its own
// case because they pull in opposite directions: item 1 proves the
// arbitration read must NOT be principal-wide; this proves it must still
// correctly detect an overfull GROUP once it is properly group-scoped.
// Manufactured via raw SQL (create_token exposes no rotation_group
// parameter) — the same manufactured-state technique already used for the
// :1389 stale-linkage twin above. Both the classifier CLASS and the
// verbatim substring `"more than two active credentials"` are asserted
// here — NOT the confirm-side rotation-state-prose exemption this
// section's calibration rule applies elsewhere. That substring is already
// generic, non-engine-scoped classifier vocabulary
// (engine_store_error_class.hpp:118, "more than two active credentials"),
// and both engine references pin it verbatim (:921, :1356) — the
// implementer has no legitimate wording freedom the classifier doesn't
// already claim. A class-only assertion here would be too weak: an
// unrelated ClientValidation failure (e.g. a bad successor_expires_at
// colliding with the manufactured state) would satisfy it without the >2
// branch ever firing, proving nothing about what this test claims to
// cover.

TEST_CASE("ApiTokenStore: rotate_token defensively rejects when three "
          "active rows already share ONE rotation_group, rather than "
          "arbitrating which pair is authoritative — token-keyed twin of "
          ":921",
          "[pg][token][rotation][human]") {
    // Defect this catches: resolve_rotation_pair_after_revoke
    // (api_token_store.cpp:686-716) already scopes its own UPDATE by
    // rotation_group — a group-scoped defensive ">2" branch is exactly the
    // kind of port detail a naive implementation, having correctly moved
    // the ARBITRATION read from principal-wide to group-scoped (item 1),
    // could still drop: e.g. by reusing the OLD principal-wide ">2" check
    // (which would reject this case for the wrong reason and ALSO wrongly
    // reject item 1's legitimately-unrelated-tokens case), or by never
    // checking group size at all and instead picking an arbitrary pair
    // from the 3 rows to treat as authoritative — silently discarding the
    // third credential's rotation eligibility with no error.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Overfull-group PAT", "wendy", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "wendy", "", "");
    REQUIRE(rotated.has_value());
    std::string rotation_group;
    for (const auto& tok : store.list_active_for_principal("wendy"))
        if (tok.token_id == predecessor_id)
            rotation_group = tok.rotation_group;
    REQUIRE_FALSE(rotation_group.empty());

    // Manufacture a THIRD active row sharing that same rotation_group —
    // create_token has no rotation_group parameter, so this can only be
    // done by raw SQL, mirroring the resolve_rotation_pair_after_revoke
    // implementation's own column set.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "INSERT INTO api_token_store.api_tokens "
            "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, "
            " principal_kind, created_at, expires_at, revoked, rotation_group) "
            "VALUES ('overfull0000000000000001', 'fakehash-overfull-rotate-01', "
            "'Manufactured extra', 'wendy', '', '', 'human', " +
            std::to_string(now) + ", " + std::to_string(now + k90Days) +
            ", FALSE, '" + rotation_group + "');";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto overfull = store.list_active_for_principal("wendy");
    int in_group = 0;
    for (const auto& tok : overfull)
        if (tok.rotation_group == rotation_group)
            ++in_group;
    REQUIRE(in_group == 3);

    auto over = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "wendy", "", "");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().find("more than two active credentials") != std::string::npos);
    CHECK(classify_engine_store_error(over.error()) == ClsE::ClientValidation);

    // Never arbitrates — the group stays at exactly 3, no fourth row minted.
    auto after = store.list_active_for_principal("wendy");
    int still_in_group = 0;
    for (const auto& tok : after)
        if (tok.rotation_group == rotation_group)
            ++still_in_group;
    CHECK(still_in_group == 3);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a group with three "
          "active rows is a terminal client error, not retryable — "
          "token-keyed twin of :1356",
          "[pg][token][rotation][human][confirm]") {
    // Defect this catches: the confirm-side counterpart to the test above —
    // an implementation could correctly defend rotate_token's mint path
    // against an overfull group while leaving confirm_token_rotation to
    // fall through to the generic "no in-flight rotation" retryable
    // default, which would tell an idempotent-hint-honouring client to
    // retry a call that can never succeed from this state.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Overfull-confirm PAT", "xena", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "xena", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id, rotation_group;
    for (const auto& tok : store.list_active_for_principal("xena")) {
        if (tok.supersedes_token_id == predecessor_id) {
            successor_id = tok.token_id;
            rotation_group = tok.rotation_group;
        }
    }
    REQUIRE_FALSE(successor_id.empty());

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "INSERT INTO api_token_store.api_tokens "
            "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, "
            " principal_kind, created_at, expires_at, revoked, rotation_group) "
            "VALUES ('overfull0000000000000002', 'fakehash-overfull-confirm-02', "
            "'Manufactured extra', 'xena', '', '', 'human', " +
            std::to_string(now) + ", " + std::to_string(now + k90Days) +
            ", FALSE, '" + rotation_group + "');";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto overfull = store.list_active_for_principal("xena");
    int in_group = 0;
    for (const auto& tok : overfull)
        if (tok.rotation_group == rotation_group)
            ++in_group;
    REQUIRE(in_group == 3);

    auto over =
        store.confirm_token_rotation(successor_id, "irrelevant-secret", "xena", "", "");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().find("more than two active credentials") != std::string::npos);
    CHECK(classify_engine_store_error(over.error()) == ClsE::ClientValidation);

    // Never arbitrates: no confirmed_at stamped, group untouched at 3.
    auto after = store.list_active_for_principal("xena");
    int still_in_group = 0;
    for (const auto& tok : after) {
        if (tok.rotation_group == rotation_group) {
            ++still_in_group;
            CHECK(tok.confirmed_at == 0);
        }
    }
    CHECK(still_in_group == 3);
}

// ── Item 3: concurrency ─────────────────────────────────────────────────

TEST_CASE("ApiTokenStore: concurrent rotate_token calls for the SAME "
          "predecessor and SAME owner never exceed the ≤2 active ceiling, "
          "and every call succeeds with the identical raw secret (human "
          "twin of Hermes F1)",
          "[pg][token][rotation][human][concurrency]") {
    // Defect this catches: an unlocked (or principal-scoped-locked but
    // group-blind) read-then-mint would let multiple racing threads all
    // observe "1 in this group" and all mint, blowing the ≤2 ceiling for a
    // SINGLE token's rotation lineage — mirrors :953's engine test's core
    // property, keyed by token_id. The per-thread OUTCOME deliberately
    // differs from :953: under the store-level self-service rule
    // (requesting_user must equal the token's own principal_id on every
    // call), there is exactly ONE legitimate requesting_user for a given
    // token, so :953's shape — distinct "operator-N" identities, each
    // individually rejected by the F4 binding — has no human analog (see
    // :851 in the round-4 checklist: that state is unreachable here, a
    // non-owner is bounced by the ownership gate before ever reaching it).
    // The realistic human race is the SAME owner double-clicking "rotate"
    // in two tabs: every thread below shares carol's identity, so every
    // thread must succeed, and every success must carry the IDENTICAL raw
    // secret (the losers hit the re-serve arm, not a rejection).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Racy PAT", "carol", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    constexpr int kThreads = 6;
    std::latch start_latch{kThreads};
    std::vector<std::thread> threads;
    std::mutex results_mtx;
    std::vector<std::expected<std::string, std::string>> results;

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&]() {
            start_latch.arrive_and_wait();
            auto r = store.rotate_token(t_id, kDefaultOverlapSecs, now, "carol", "", "");
            std::lock_guard lock(results_mtx);
            results.push_back(std::move(r));
        });
    }
    for (auto& th : threads)
        th.join();

    // Every thread is carol racing her own token: every call must succeed
    // (the winner mints, every loser re-serves), and no two calls may
    // return DIFFERENT raw values — that would mean a second successor was
    // minted, which the ceiling check below would also catch.
    REQUIRE(results.size() == static_cast<std::size_t>(kThreads));
    for (const auto& r : results)
        REQUIRE(r.has_value());
    for (const auto& r : results)
        CHECK(*r == *results.front());

    // The ≤2 ceiling for THIS token's group holds under concurrency — never
    // a third mint from a lost race.
    int related = 0;
    for (const auto& tok : store.list_active_for_principal("carol"))
        if (tok.token_id == t_id || tok.supersedes_token_id == t_id)
            ++related;
    CHECK(related == 2);
}

TEST_CASE("ApiTokenStore: concurrent rotate_token calls on TWO DIFFERENT "
          "tokens owned by the SAME principal both succeed",
          "[pg][token][rotation][human][concurrency]") {
    // Defect this catches: if the advisory lock (or any other serialization
    // point) keys on principal_id rather than the predecessor's own rotation
    // group, two genuinely independent rotations for the same user would
    // contend the SAME lock. Contention alone is harmless (they just
    // serialize) — but if the arbitration read is ALSO principal-scoped, the
    // second call to acquire the lock would observe 3-active (its own
    // unrelated predecessor + the first rotation's now-2-active pair) and
    // hit the defensive >2 reject. Both must succeed regardless of
    // interleaving — this is item 1/2's group-scoping guarantee, but proven
    // under genuine concurrency rather than sequential calls.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto a = store.create_token("Token A", "dave", now + k90Days);
    auto b = store.create_token("Token B", "dave", now + k90Days);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    auto va = store.validate_token(*a);
    auto vb = store.validate_token(*b);
    REQUIRE(va.has_value());
    REQUIRE(vb.has_value());
    const std::string a_id = va->token_id;
    const std::string b_id = vb->token_id;

    std::latch start_latch{2};
    std::expected<std::string, std::string> result_a, result_b;
    std::thread ta([&]() {
        start_latch.arrive_and_wait();
        result_a = store.rotate_token(a_id, kDefaultOverlapSecs, now, "dave", "", "");
    });
    std::thread tb([&]() {
        start_latch.arrive_and_wait();
        result_b = store.rotate_token(b_id, kDefaultOverlapSecs, now, "dave", "", "");
    });
    ta.join();
    tb.join();

    REQUIRE(result_a.has_value());
    REQUIRE(result_b.has_value());
    CHECK(store.list_active_for_principal("dave").size() == 4); // 2 groups x 2 rows
}

// ── Item 4: successor TTL inheritance ───────────────────────────────────

TEST_CASE("ApiTokenStore: rotate_token's successor inherits the "
          "predecessor's absolute expires_at verbatim, never resetting to a "
          "fresh 90-day window",
          "[pg][token][rotation][human]") {
    // Defect this catches: the engine arm always mints a fresh now+90-days
    // candidate (see candidate_expires_at in rotate_engine_credential) — a
    // naive port would silently widen (or shrink) a human PAT's lifetime on
    // every rotation instead of preserving the operator's original choice.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    const int64_t predecessor_expiry = now + 180 * kDay; // deliberately NOT 90 days
    auto t = store.create_token("Long-lived PAT", "erin", predecessor_expiry);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "erin", "", "");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("erin");
    const ApiToken* successor = nullptr;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor = &tok;
    REQUIRE(successor != nullptr);
    CHECK(successor->expires_at == predecessor_expiry);
}

TEST_CASE("ApiTokenStore: rotate_token on a PERPETUAL predecessor "
          "(expires_at == 0) yields a perpetual successor",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Perpetual PAT", "frank"); // expires_at defaults 0
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;
    auto pre = store.get_token(t_id);
    REQUIRE(pre.has_value());
    REQUIRE(pre->has_value());
    REQUIRE((*pre)->expires_at == 0);

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "frank", "", "");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("frank");
    const ApiToken* successor = nullptr;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor = &tok;
    REQUIRE(successor != nullptr);
    CHECK(successor->expires_at == 0); // perpetual, not defaulted to a 90-day window
}

TEST_CASE("ApiTokenStore: rotate_token's optional successor_expires_at "
          "override is honoured when supplied and valid",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Overridable PAT", "grace", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // A valid override in the future, past the overlap window's own end.
    const int64_t override_expiry = now + 30 * kDay;
    auto rotated =
        store.rotate_token(t_id, kDefaultOverlapSecs, now, "grace", "", "", override_expiry);
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("grace");
    const ApiToken* successor = nullptr;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor = &tok;
    REQUIRE(successor != nullptr);
    CHECK(successor->expires_at == override_expiry); // caller's value, not inherited
}

TEST_CASE("ApiTokenStore: rotate_token rejects a successor_expires_at "
          "override that has already elapsed — never silently swapped for "
          "the inherited value",
          "[pg][token][rotation][human]") {
    // Defect this catches: an implementation that only conditionally uses
    // the override when non-empty, without validating the SUPPLIED value's
    // own sanity, would mint a successor that is already expired the
    // instant it is issued.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("PAT", "heidi", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated =
        store.rotate_token(t_id, kDefaultOverlapSecs, now, "heidi", "", "", now - 1);
    REQUIRE_FALSE(rotated.has_value());

    // No successor minted; predecessor untouched.
    auto active = store.list_active_for_principal("heidi");
    REQUIRE(active.size() == 1);
    CHECK(active[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: rotate_token rejects a successor_expires_at "
          "override that would fall before the overlap window's own end",
          "[pg][token][rotation][human]") {
    // Token-keyed analog of the "overlap window would exceed the successor
    // credential's expiry" ClientValidation substring already pinned in
    // engine_store_error_class.hpp — the successor's own candidate expiry,
    // whether inherited or overridden, must never be exceeded by the
    // requested overlap window.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("PAT", "ivy", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // Overlap window ends at now+kDefaultOverlapSecs (7d); override the
    // successor to expire at now+1d — BEFORE the window it would need to
    // survive.
    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "ivy", "", "", now + kDay);
    REQUIRE_FALSE(rotated.has_value());
    CHECK(classify_engine_store_error(rotated.error()) == ClsE::ClientValidation);

    auto active = store.list_active_for_principal("ivy");
    REQUIRE(active.size() == 1); // no successor minted
}

TEST_CASE("ApiTokenStore: rotate_token rejects an overlap window that would "
          "exceed the predecessor's near-expiry, rather than silently "
          "truncating it",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // Predecessor expires in 1 day — far less than the requested overlap.
    auto t = store.create_token("Nearly-expired PAT", "ivan", now + kDay);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "ivan", "", "");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("expiry") != std::string::npos);
    CHECK(classify_engine_store_error(rotated.error()) == ClsE::ClientValidation);

    // No successor minted, no truncated window silently applied.
    auto active = store.list_active_for_principal("ivan");
    REQUIRE(active.size() == 1);
    CHECK(active[0].rotation_group.empty());
    CHECK(active[0].expires_at == now + kDay); // untouched, not truncated
}

// ── Item 5: classifier round-trip — the remaining reachable rotate_token
//    error paths not already covered (with classify checks) above ─────────

TEST_CASE("ApiTokenStore: rotate_token error classification round-trip — "
          "floor/ceiling/requesting_user/grace-elapsed (#2404 tripwire, "
          "human arm)",
          "[pg][token][rotation][human][classifier]") {
    // Each scenario's defect: a new or reworded rotate_token error message
    // that drops the keyed substring classify_engine_store_error already
    // commits to silently reclassifies to the retryable Transient default —
    // an honest client then retries a terminal client/conflict error
    // forever. This is the tripwire.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto now = test_now_epoch();

    // Floor: below the 24h minimum. Pure-math input validation — asserted
    // (like the engine floor test at :705) against a bogus token_id, on the
    // assumption it fires before any DB lookup of the predecessor.
    {
        auto r = store.rotate_token("deadbeefdeadbeefdeadbeef", kDay - 1, now, "admin", "", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("floor") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // Ceiling: absurdly large overlap window (well past any sane maximum).
    {
        constexpr int64_t kAbsurdOverlap = 11LL * 365 * kDay;
        auto r = store.rotate_token("deadbeefdeadbeefdeadbeef", kAbsurdOverlap, now, "admin", "",
                                    "");
        REQUIRE_FALSE(r.has_value());
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // requesting_user required — a REAL token so the empty-user guard is
    // isolated from any "token not found" ambiguity.
    {
        auto t = store.create_token("Guard PAT", "judy-req", now + k90Days);
        REQUIRE(t.has_value());
        auto vt = store.validate_token(*t);
        REQUIRE(vt.has_value());
        auto r = store.rotate_token(vt->token_id, kDefaultOverlapSecs, now, "", "", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("required") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // Grace window elapsed: a same-operator retry more than kRotationGraceSecs
    // after the successor's own mint (epoch side, no sleep needed). Mirrors
    // :887, which — beyond the rejection itself — re-reads the active set to
    // prove the rejected retry minted no THIRD credential; the rejection
    // alone is only half the property.
    {
        auto t = store.create_token("Grace PAT", "judy-grace", now + k90Days);
        REQUIRE(t.has_value());
        auto vt = store.validate_token(*t);
        REQUIRE(vt.has_value());
        auto first =
            store.rotate_token(vt->token_id, kDefaultOverlapSecs, now, "judy-grace", "", "");
        REQUIRE(first.has_value());
        auto lapsed = store.rotate_token(vt->token_id, kDefaultOverlapSecs, now + 300,
                                         "judy-grace", "", "");
        REQUIRE_FALSE(lapsed.has_value());
        CHECK(lapsed.error().find("grace") != std::string::npos);
        CHECK(classify_engine_store_error(lapsed.error()) == ClsE::Conflict);

        // No third credential was minted by the rejected retry (:887's other
        // half).
        CHECK(store.list_active_for_principal("judy-grace").size() == 2);
    }
}

TEST_CASE("ApiTokenStore: confirm_token_rotation error classification "
          "round-trip — input validation (#2404 tripwire, human arm)",
          "[pg][token][rotation][human][classifier]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto now = test_now_epoch();

    // Empty successor_token_id.
    {
        auto r = store.confirm_token_rotation("", "irrelevant-secret", "admin", "", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("required") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // Empty requesting_user, against a real token so the outcome isn't
    // confounded with a "token not found" branch. A non-empty secret is
    // supplied so this genuinely isolates the requesting_user guard rather
    // than tripping the #3015 secret guard first.
    std::string kelly_token_id;
    {
        auto t = store.create_token("Confirm-guard PAT", "kelly", now + k90Days);
        REQUIRE(t.has_value());
        auto vt = store.validate_token(*t);
        REQUIRE(vt.has_value());
        kelly_token_id = vt->token_id;
        auto r = store.confirm_token_rotation(vt->token_id, "irrelevant-secret", "", "", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("required") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // #3015: empty presented_secret, against the SAME real/owned token, a
    // non-empty requesting_user — isolates the secret guard specifically.
    // Distinct message ("secret required") from the requesting_user case
    // above, but the SAME ClientValidation class / 400.
    {
        auto r = store.confirm_token_rotation(kelly_token_id, "", "kelly", "", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("secret required") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }
}

// ── Item 6: confirm_token_rotation replay / terminal states ────────────

TEST_CASE("ApiTokenStore: confirm_token_rotation on a never-rotated solo "
          "credential is terminal, not retryable (#2404, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Defect this catches: collapsing this into the same "no in-flight
    // rotation" retryable bucket as a genuinely empty read (item 6's other
    // half, below) would tell an idempotent-hint-honouring client to retry a
    // call that can never succeed — there was never a rotation to confirm.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Solo PAT", "leo", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());

    // Confirm-side rotation-STATE wording is asserted via classifier CLASS
    // only, never verbatim (calibration rule stated in this section's header
    // comment) — this scenario is more likely to be reworded for a "rotation
    // group" model than the generic floor/ceiling/operator-binding strings.
    auto resolved =
        store.confirm_token_rotation(vt->token_id, "irrelevant-secret", "leo", "", "");
    REQUIRE_FALSE(resolved.has_value());
    CHECK(classify_engine_store_error(resolved.error()) == ClsE::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation replay after success is a "
          "terminal already-confirmed conflict, not a retryable 503 "
          "(#2404, human arm)",
          "[pg][token][rotation][human][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Replay PAT", "mia", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "mia", "", "");
    REQUIRE(rotated.has_value());
    auto active = store.list_active_for_principal("mia");
    std::string successor_id;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // First confirm succeeds (the real cutover).
    REQUIRE(store.confirm_token_rotation(successor_id, *rotated, "mia", "", "").has_value());

    // The network-dropped-200 replay: SAME args. Terminal, not 503.
    auto replay =
        store.confirm_token_rotation(successor_id, "irrelevant-secret", "mia", "", "");
    REQUIRE_FALSE(replay.has_value());
    CHECK(classify_engine_store_error(replay.error()) == ClsE::Conflict);
    CHECK(store.list_active_for_principal("mia").size() == 1); // no side effect
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a stale/mismatched "
          "successor id while a DIFFERENT rotation is pending (#2384 twin, "
          "human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed analog of :1501/:1556 — a blind retry (or an operator's
    // copy-paste of the wrong id) carrying an id that does not match the
    // pending successor must never mutate state.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Mismatch PAT", "nina", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "nina", "", "");
    REQUIRE(rotated.has_value());

    std::string successor_id, rotation_group;
    for (const auto& tok : store.list_active_for_principal("nina")) {
        if (tok.supersedes_token_id == predecessor_id) {
            successor_id = tok.token_id;
            rotation_group = tok.rotation_group;
        }
    }
    REQUIRE_FALSE(successor_id.empty());

    // The PREDECESSOR's own id (the likely operator mistake) resolves to a
    // REAL row nina owns, currently in-rotation but holding the WRONG role
    // in the pair (predecessor, not successor) — this genuinely reaches the
    // pin-mismatch branch.
    auto mismatch =
        store.confirm_token_rotation(predecessor_id, "irrelevant-secret", "nina", "", "");
    REQUIRE_FALSE(mismatch.has_value());
    CHECK(mismatch.error().find("does not match the pending rotation") != std::string::npos);
    CHECK(classify_engine_store_error(mismatch.error()) == ClsE::Conflict);

    // A FABRICATED id never resolves to any row at all, so it CANNOT reach
    // the pin-mismatch branch (which requires a resolved, owned row to
    // compare a role against) — it is deliberately NOT asserted to produce
    // the pin-mismatch message here. Engine-precedent mismatch, recorded so
    // the next reader does not "fix" this back: the engine arm resolves
    // confirm by PRINCIPAL, so it can compare any supplied id against a
    // known successor without a row lookup first; the human arm is
    // TOKEN-keyed and must resolve the id to a row before it can compare
    // roles — an id that never resolves can never reach that comparison.
    // Instead, the store folds "never existed" into the SAME response as
    // "exists, but belongs to someone else" — the enumeration-resistance
    // property item 7b already establishes — so this is asserted by
    // comparing the fabricated id's result DIRECTLY against a genuinely
    // not-owned real token_id's result, not against a hardcoded
    // string/class, so it keeps holding regardless of the implementer's
    // chosen not-found wording.
    auto other_owner = store.create_token("Not nina's PAT", "mallory-2384", now + k90Days);
    REQUIRE(other_owner.has_value());
    auto vt_other = store.validate_token(*other_owner);
    REQUIRE(vt_other.has_value());

    auto fabricated = store.confirm_token_rotation("feedfacefeedfacefeedface",
                                                    "irrelevant-secret", "nina", "", "");
    auto not_owned =
        store.confirm_token_rotation(vt_other->token_id, "irrelevant-secret", "nina", "", "");
    REQUIRE_FALSE(fabricated.has_value());
    REQUIRE_FALSE(not_owned.has_value());
    CHECK(fabricated.error() == not_owned.error());
    CHECK(classify_engine_store_error(fabricated.error()) ==
          classify_engine_store_error(not_owned.error()));

    // No mutation: both of nina's credentials active, linkage intact,
    // unconfirmed.
    auto active = store.list_active_for_principal("nina");
    REQUIRE(active.size() == 2);
    for (const auto& tok : active) {
        CHECK(tok.confirmed_at == 0);
        CHECK(tok.rotation_group == rotation_group);
    }

    // The correct id still confirms — the rejections above consumed nothing.
    CHECK(store.confirm_token_rotation(successor_id, *rotated, "nina", "", "").has_value());
}

TEST_CASE("ApiTokenStore: a blind retry carrying an EARLIER rotation's "
          "successor id cannot confirm a LATER rotation on the SAME token "
          "lineage (#2384 twin, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed analog of :1556. The id that mismatches here is not a
    // bogus/unrelated string (that's the previous test) — it is a REAL,
    // currently-active token_id that legitimately played TWO roles: R1's
    // (already-confirmed) successor, and R2's (still-pending) predecessor.
    // Defect this catches: a confirm that resolves its target row by
    // token_id and then checks ONLY "is this row part of an active,
    // in-flight pair" — without also requiring it be the PAIR'S SUCCESSOR —
    // would find r1_successor_id sitting right there as R2's live
    // predecessor and could wrongly treat the replay as legitimate,
    // confirming R2 (and revoking R2's actual, still-unconfirmed
    // predecessor) using an id the caller never associated with R2 at all.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Blind-retry PAT", "paul", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // R1: rotate + confirm with R1's successor id (the happy flow).
    auto r1 = store.rotate_token(t_id, kDefaultOverlapSecs, now, "paul", "", "");
    REQUIRE(r1.has_value());
    std::string r1_successor_id;
    for (const auto& tok : store.list_active_for_principal("paul"))
        if (tok.supersedes_token_id == t_id)
            r1_successor_id = tok.token_id;
    REQUIRE_FALSE(r1_successor_id.empty());
    REQUIRE(store.confirm_token_rotation(r1_successor_id, *r1, "paul", "", "").has_value());

    // R2 begins: R1's successor is now R2's predecessor.
    auto r2 = store.rotate_token(r1_successor_id, kDefaultOverlapSecs, now, "paul", "", "");
    REQUIRE(r2.has_value());
    std::string r2_successor_id;
    for (const auto& tok : store.list_active_for_principal("paul"))
        if (tok.supersedes_token_id == r1_successor_id)
            r2_successor_id = tok.token_id;
    REQUIRE_FALSE(r2_successor_id.empty());
    REQUIRE(r2_successor_id != r1_successor_id);

    // THE #2384 SCENARIO, token-keyed: a blind retry of the R1 confirm (same
    // args, same operator) lands after R2 started.
    auto stale_retry =
        store.confirm_token_rotation(r1_successor_id, *r1, "paul", "", "");
    REQUIRE_FALSE(stale_retry.has_value());
    CHECK(stale_retry.error().find("does not match the pending rotation") != std::string::npos);
    CHECK(classify_engine_store_error(stale_retry.error()) == ClsE::Conflict);

    // R2 is untouched: r1_successor_id (R2's predecessor) is still active and
    // unrevoked; R2's own successor remains unconfirmed. NOTE: r1_successor_id
    // legitimately RETAINS its historical confirmed_at from R1 (a marker, by
    // design) — only R2's successor must be unconfirmed.
    auto active = store.list_active_for_principal("paul");
    REQUIRE(active.size() == 2);
    bool r1_successor_still_active = false;
    for (const auto& tok : active) {
        if (tok.token_id == r1_successor_id) {
            r1_successor_still_active = true;
            CHECK_FALSE(tok.revoked);
        }
        if (tok.token_id == r2_successor_id)
            CHECK(tok.confirmed_at == 0);
    }
    CHECK(r1_successor_still_active);

    // R2's own successor id confirms R2 normally.
    CHECK(store.confirm_token_rotation(r2_successor_id, *r2, "paul", "", "").has_value());
}

TEST_CASE("ApiTokenStore: a successor id from ONE token's already-resolved "
          "rotation cannot confirm a pending rotation on a DIFFERENT token "
          "owned by the same user (cross-lineage #2384 twin, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Defect this catches: group-scoped arbitration (items 1/2) means a
    // single user can have MULTIPLE lineages in flight simultaneously — a
    // shape the engine arm never has (one principal owns exactly one
    // lineage). If confirm resolves "the pending pair" by scanning the
    // PRINCIPAL's whole active set for ANY 2-row rotation pair, instead of
    // resolving the SPECIFIC group the supplied token_id itself belongs to,
    // an id from lineage A could be accepted against lineage B's unrelated
    // in-flight pair — silently confirming (and cutting over) the WRONG
    // rotation. If that happened here, `cross.has_value()` below would be
    // true and lineage B would show one confirmed/one revoked row instead of
    // two untouched, unconfirmed ones.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();

    // Lineage A: rotate + confirm, fully resolved — its former successor A2
    // is now sole and carries a historical confirmed_at, no live group.
    auto a = store.create_token("Lineage A", "quinn", now + k90Days);
    REQUIRE(a.has_value());
    auto va = store.validate_token(*a);
    REQUIRE(va.has_value());
    const std::string a1_id = va->token_id;
    auto ra = store.rotate_token(a1_id, kDefaultOverlapSecs, now, "quinn", "", "");
    REQUIRE(ra.has_value());
    std::string a2_id;
    for (const auto& tok : store.list_active_for_principal("quinn"))
        if (tok.supersedes_token_id == a1_id)
            a2_id = tok.token_id;
    REQUIRE_FALSE(a2_id.empty());
    REQUIRE(store.confirm_token_rotation(a2_id, *ra, "quinn", "", "").has_value());

    // Lineage B: a SEPARATE token for the SAME user, rotated but NOT yet
    // confirmed — a genuinely pending, unrelated pair, and (crucially) the
    // ONLY 2-row pending pair this principal currently has.
    auto b = store.create_token("Lineage B", "quinn", now + k90Days);
    REQUIRE(b.has_value());
    auto vb = store.validate_token(*b);
    REQUIRE(vb.has_value());
    const std::string b1_id = vb->token_id;
    auto rb = store.rotate_token(b1_id, kDefaultOverlapSecs, now, "quinn", "", "");
    REQUIRE(rb.has_value());
    std::string b2_id;
    for (const auto& tok : store.list_active_for_principal("quinn"))
        if (tok.supersedes_token_id == b1_id)
            b2_id = tok.token_id;
    REQUIRE_FALSE(b2_id.empty());

    // A2 (lineage A's resolved-away successor id) must NOT confirm lineage
    // B's pending pair.
    auto cross = store.confirm_token_rotation(a2_id, "irrelevant-secret", "quinn", "", "");
    REQUIRE_FALSE(cross.has_value());
    CHECK(classify_engine_store_error(cross.error()) == ClsE::Conflict);

    // Lineage B is completely untouched: still exactly 2 active rows in its
    // own group, unconfirmed, unrevoked.
    int b_group_active = 0;
    for (const auto& tok : store.list_active_for_principal("quinn")) {
        if (tok.token_id == b1_id || tok.token_id == b2_id) {
            ++b_group_active;
            CHECK(tok.confirmed_at == 0);
            CHECK_FALSE(tok.revoked);
        }
    }
    CHECK(b_group_active == 2);

    // B's own successor id still confirms B normally.
    CHECK(store.confirm_token_rotation(b2_id, *rb, "quinn", "", "").has_value());
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a group already resolved "
          "by REVOKE is a terminal fact even though the OWNER's overall "
          "active read is non-empty (positive read vs. genuinely empty, "
          "human arm)",
          "[pg][token][rotation][human][confirm]") {
    // The subtle half of item 6: this must NOT be confused with a genuinely
    // empty/ambiguous read. karen's active-set read is non-empty throughout
    // (the predecessor survives, plus an unrelated token) — the fact that
    // THIS SPECIFIC group has zero in-flight rows is a POSITIVE result, so
    // the rejection must be terminal, never the retryable "no in-flight
    // rotation" reserved for a read that came back with nothing at all.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Group A", "karen", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // Unrelated token proving karen's active-set read is genuinely non-empty
    // throughout this test.
    auto b = store.create_token("Unrelated B", "karen", now + k90Days);
    REQUIRE(b.has_value());

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "karen", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("karen"))
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Resolve the pair by REVOKING the successor directly (not confirming) —
    // the §7 manual-revoke-resolves-the-pair contract (mirrors the engine
    // tests at :1621/:1657): the predecessor `t_id` survives as karen's sole
    // credential for that lineage, rotation state cleared.
    REQUIRE(store.revoke_token(successor_id).value());
    auto after_revoke = store.get_token(t_id);
    REQUIRE(after_revoke.has_value());
    REQUIRE(after_revoke->has_value());
    CHECK((*after_revoke)->rotation_group.empty());

    // A confirm naming the now-revoked successor id must be told the
    // rotation resolved — terminal — never the retryable "no in-flight
    // rotation" (reserved below for a genuinely empty read).
    auto resolved =
        store.confirm_token_rotation(successor_id, "irrelevant-secret", "karen", "", "");
    REQUIRE_FALSE(resolved.has_value());
    CHECK(classify_engine_store_error(resolved.error()) == ClsE::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a revoked, "
          "never-rotated token_id is a terminal nothing-to-confirm, not "
          "retryable (#2404, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // RENAMED + RECLASSIFIED post-merge review. Originally named "...on a
    // genuinely EMPTY read stays retryable..." and asserted Transient — but
    // this scenario does not reach the read-ambiguity state that name
    // describes. confirm_token_rotation resolves the PINNED row by
    // token_id FIRST; that row is FOUND here (it exists, merely revoked),
    // and its own rotation_group field is empty — a definite POSITIVE fact
    // ("this token_id was never part of any rotation"). It never touches a
    // principal-wide or group-scoped active read, so the "indistinguishable
    // from a swallowed SELECT failure" reasoning this test used to cite
    // does not apply here.
    //
    // Formally adjudicated to Conflict after this suite was first written,
    // on three grounds: #2404 already litigated the identical shape on the
    // engine arm, where a 503 made an idempotent-hint-honouring client
    // retry a permanently-failing call forever; the engine's
    // kSoleOtherToken (same "rotate again" guidance) is Conflict; and
    // rotation_confirm_state.hpp documents every terminal state as
    // Conflict or ClientValidation, never Transient. Do NOT flip this back
    // to Transient.
    //
    // The genuinely-ambiguous kAmbiguousEmpty path — where the pinned row
    // DOES have a non-empty rotation_group (so a partner read is actually
    // attempted) and that group-scoped read itself comes back empty,
    // indistinguishable from a swallowed SELECT failure — is a DIFFERENT,
    // narrower state this test does not exercise. It was not added here:
    // constructing it needs knowledge of which specific query the
    // group-scoped partner read runs (to sabotage that query alone while
    // leaving the single-row pin lookup intact), and that implementation
    // detail is not visible from this worktree (the merged implementation
    // lives outside it). Reachability and worth are open questions for
    // whoever holds the merged source, not answered here.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Doomed PAT", "oscar", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    REQUIRE(store.revoke_token(t_id).value());
    REQUIRE(store.list_active_for_principal("oscar").empty());

    auto none = store.confirm_token_rotation(t_id, "irrelevant-secret", "oscar", "", "");
    REQUIRE_FALSE(none.has_value());
    CHECK(classify_engine_store_error(none.error()) == ClsE::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a sole credential with "
          "stale rotation linkage is terminal and does NOT mutate — token-"
          "keyed twin of :1389 (#2404 F1, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed twin of :1389. Manufactures the F1 defect state: revoke
    // the predecessor by DIRECT SQL, bypassing the store's own
    // resolve_rotation_pair_after_revoke, so the surviving successor keeps
    // its (now stale) rotation_group/supersedes linkage — the durable state
    // a best-effort pair-resolve failure leaves. Defect this catches: a
    // confirm that trusts a non-empty rotation_group as proof of a LIVE,
    // recognizable pair (without checking the partner it names still
    // exists) would either wrongly report a normal in-flight rotation, or
    // — far worse — silently accept and mutate from a state where rotating
    // would strand a malformed pair, exactly what the F1 remediation
    // guidance ("do not rotate") exists to prevent. Prose-level wording
    // ("do not rotate" vs "rotate again") is confirm-side rotation-state
    // text and is deliberately NOT hard-pinned here per this section's
    // calibration rule — only the terminal CLASS and the no-mutation
    // invariant are asserted, both of which are structurally verifiable
    // regardless of the implementer's chosen wording.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Stale-linkage PAT", "uma", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "uma", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("uma"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Revoke the predecessor by RAW SQL, bypassing revoke_token's own
    // pair-resolve helper — the successor's rotation_group/supersedes
    // linkage survives, now stale.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "UPDATE api_token_store.api_tokens SET revoked = TRUE WHERE token_id = '" +
            predecessor_id + "';";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto active = store.list_active_for_principal("uma");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK_FALSE(active[0].rotation_group.empty()); // stale linkage survived

    auto stale =
        store.confirm_token_rotation(successor_id, "irrelevant-secret", "uma", "", "");
    REQUIRE_FALSE(stale.has_value());
    CHECK(classify_engine_store_error(stale.error()) == ClsE::Conflict);

    // No mutation: the successor's stale linkage is untouched, not silently
    // "cleaned up" or cut over by the rejected confirm.
    auto after = store.list_active_for_principal("uma");
    REQUIRE(after.size() == 1);
    CHECK(after[0].token_id == successor_id);
    CHECK(after[0].confirmed_at == 0);
    CHECK_FALSE(after[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: a credential's historical confirmed_at survives a "
          "LATER rotation and is never reset or transferred to a "
          "differently-resolved successor — token-keyed twin of :1445 "
          "(#2404 F2, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed twin of :1445, asserted on the STORE'S DATA rather than
    // confirm's error prose (this section's calibration rule: confirm-side
    // rotation-state WORDING is classify()-only; the field itself is not
    // wording, so it is asserted directly and can still fail on its own
    // terms). Defect this catches: an implementation that clears or
    // reassigns confirmed_at when a LATER rotation on the same lineage
    // resolves (whether by confirm or by revoke) would destroy the
    // historical "this credential's own rotation WAS confirmed" marker —
    // exactly the misattribution #2404 F2 exists to prevent, just observed
    // on the row instead of in the message.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Historical-marker PAT", "vince", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());

    // R1: rotate + confirm. S1 becomes the sole active credential, confirmed.
    auto r1 = store.rotate_token(vt->token_id, kDefaultOverlapSecs, now, "vince", "", "");
    REQUIRE(r1.has_value());
    std::string s1_id;
    for (const auto& tok : store.list_active_for_principal("vince"))
        if (!tok.supersedes_token_id.empty())
            s1_id = tok.token_id;
    REQUIRE_FALSE(s1_id.empty());
    REQUIRE(store.confirm_token_rotation(s1_id, *r1, "vince", "", "").has_value());
    auto s1_after_r1 = store.get_token(s1_id);
    REQUIRE(s1_after_r1.has_value());
    REQUIRE(s1_after_r1->has_value());
    const int64_t s1_confirmed_at = (*s1_after_r1)->confirmed_at;
    REQUIRE(s1_confirmed_at > 0); // S1 carries R1's marker

    // R2: rotate again — S1 is now R2's predecessor and must KEEP its
    // confirmed_at. Then resolve R2 by REVOKING its successor (not
    // confirming), so the pair resolves back to S1 alone.
    auto r2 = store.rotate_token(s1_id, kDefaultOverlapSecs, now, "vince", "", "");
    REQUIRE(r2.has_value());
    std::string s2_id;
    for (const auto& tok : store.list_active_for_principal("vince"))
        if (tok.supersedes_token_id == s1_id)
            s2_id = tok.token_id;
    REQUIRE_FALSE(s2_id.empty());
    REQUIRE(store.revoke_token(s2_id).value()); // resolves the pair -> S1 sole, clear

    auto active = store.list_active_for_principal("vince");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == s1_id);

    // THE assertion: S1's confirmed_at is EXACTLY what it was after R1's
    // confirm — untouched by R2 starting, and untouched by R2 being
    // resolved via revoke rather than confirm.
    CHECK(active[0].confirmed_at == s1_confirmed_at);

    // S2 (R2's successor, resolved by revoke, never confirmed) must NOT
    // have been stamped with any confirmed_at of its own.
    auto s2_final = store.get_token(s2_id);
    REQUIRE(s2_final.has_value());
    REQUIRE(s2_final->has_value());
    CHECK((*s2_final)->confirmed_at == 0);
    CHECK((*s2_final)->revoked);
}

// ── Item 7: strictly self-service — requesting_user IS the owner ─────────

TEST_CASE("ApiTokenStore: rotate_token is strictly self-service — a second "
          "session for the SAME owner re-serves identically, a DIFFERENT "
          "user is rejected even before any rotation is in flight",
          "[pg][token][rotation][human]") {
    // Defect this catches: the engine arm's requesting_user binding (F4)
    // only fires on the RE-SERVE arm (2-active, grace window) — the
    // 1-active MINT path accepts ANY requesting_user, because an engine
    // credential is rotated by an admin operator ACTING ON BEHALF OF the
    // engine principal, not by the principal itself. A human PAT has no such
    // delegate: requesting_user must equal the token's own principal_id on
    // EVERY call, including the very first mint, or any authenticated user
    // could rotate any other user's token the moment they knew its
    // token_id — an authorization bypass with no analog in the engine arm.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Alice's PAT", "alice-owner", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // A DIFFERENT user, before any rotation is in flight, is rejected.
    auto stolen = store.rotate_token(t_id, kDefaultOverlapSecs, now, "mallory", "", "");
    REQUIRE_FALSE(stolen.has_value());
    auto after_stolen = store.list_active_for_principal("alice-owner");
    REQUIRE(after_stolen.size() == 1);
    CHECK(after_stolen[0].rotation_group.empty()); // no successor minted

    // The genuine owner — a "second session", i.e. a fresh call carrying the
    // SAME identity — succeeds normally.
    auto real = store.rotate_token(t_id, kDefaultOverlapSecs, now, "alice-owner", "", "");
    REQUIRE(real.has_value());

    // And a further same-owner call re-serves idempotently (second session,
    // still within grace) rather than erroring or minting a third row.
    auto second_session = store.rotate_token(t_id, kDefaultOverlapSecs, now, "alice-owner", "", "");
    REQUIRE(second_session.has_value());
    CHECK(*second_session == *real);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation is strictly self-service — "
          "a DIFFERENT user may not confirm someone else's in-flight "
          "rotation, but the owner's own second session can",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Bob's PAT", "bob-owner", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;
    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "bob-owner", "", "");
    REQUIRE(rotated.has_value());

    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("bob-owner"))
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // #3015 oracle-freedom: mallory ALSO presents the CORRECT raw secret —
    // ownership still wins, and the outcome does not flip to "confirmed" nor
    // to a distinguishable "wrong secret" (PoP is checked strictly after
    // ownership).
    auto stolen_confirm =
        store.confirm_token_rotation(successor_id, *rotated, "mallory", "", "");
    REQUIRE_FALSE(stolen_confirm.has_value());
    for (const auto& tok : store.list_active_for_principal("bob-owner"))
        CHECK(tok.confirmed_at == 0); // both credentials unchanged

    // The owner's own confirm (a fresh call — "second session") still works.
    CHECK(store.confirm_token_rotation(successor_id, *rotated, "bob-owner", "", "").has_value());
}

// ── Item 7b: absence of a token_id enumeration oracle ──────────────────
//
// The design fact the two self-service tests above do NOT prove: a wrong-owner
// call must be rejected INDISTINGUISHABLY from a genuinely nonexistent
// token_id. Both tests above only ever exercise wrong-owner against a real,
// existing token — an implementation that returns a distinguishable error
// (different string, or a different classifier class) for "no such token_id"
// versus "that token_id exists but isn't yours" would let any authenticated
// caller binary-search token_id space to learn which ids correspond to real,
// live credentials belonging to OTHER users — an IDOR-adjacent enumeration
// oracle. This is the exact property `DELETE /api/v1/tokens/{id}`
// (rest_api_v1.cpp:2619-2641) already enforces: missing-id and not-owner both
// return a byte-identical 404 body precisely so the endpoint can't be probed
// this way. The assertions below compare the two returned messages TO EACH
// OTHER, not to a hardcoded literal, so the test keeps holding regardless of
// which wording the implementer picks.

TEST_CASE("ApiTokenStore: rotate_token rejects a nonexistent token_id "
          "identically to another user's real, active token_id — no "
          "enumeration oracle",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: if rotate_token resolves the row by id FIRST (to
    // report a distinct "not found") and only THEN checks ownership (to
    // report a distinct "not yours"), an attacker who doesn't own ANY
    // tokens can still learn — one guess at a time, from the error alone —
    // which token_ids belong to real, active credentials of other users.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Rachel's PAT", "rachel-target", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string real_other_users_id = vt->token_id;

    auto against_nonexistent = store.rotate_token("0000000000000000deadbeef", kDefaultOverlapSecs,
                                                  now, "attacker", "", "");
    auto against_real_other =
        store.rotate_token(real_other_users_id, kDefaultOverlapSecs, now, "attacker", "", "");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_real_other.has_value());
    CHECK(against_nonexistent.error() == against_real_other.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_real_other.error()));

    // Neither call touched rachel's token.
    auto after = store.list_active_for_principal("rachel-target");
    REQUIRE(after.size() == 1);
    CHECK(after[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: rotate_token rejects a nonexistent token_id "
          "identically to another user's REVOKED token_id — the "
          "timing-independent sibling",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: a row that EXISTS but is revoked is a different
    // internal state than "no row at all" — an implementation that finds
    // the (revoked) row and reports something like "token revoked" or
    // "no active credential" distinct from a bare "not found" would let an
    // attacker distinguish "never existed" from "existed once, now dead"
    // for another user's token_id, which is still an enumeration oracle
    // (and, unlike the active-token case above, is NOT timing-equivalent to
    // a wrong-owner-of-a-live-token rejection, so it needs its own case).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Sam's dead PAT", "sam-target", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string revoked_id = vt->token_id;
    REQUIRE(store.revoke_token(revoked_id).value());

    auto against_nonexistent = store.rotate_token("1111111111111111deadbeef", kDefaultOverlapSecs,
                                                  now, "attacker", "", "");
    auto against_revoked =
        store.rotate_token(revoked_id, kDefaultOverlapSecs, now, "attacker", "", "");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_revoked.has_value());
    CHECK(against_nonexistent.error() == against_revoked.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_revoked.error()));
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a nonexistent "
          "successor_token_id identically to another user's real, "
          "PENDING successor_token_id — no enumeration oracle",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: same property as the rotate_token case above, on
    // the confirm path — an attacker who can distinguish "no such
    // successor_token_id" from "that id is a real, pending rotation
    // successor, but not yours to confirm" learns which token_ids
    // correspond to LIVE, in-flight rotations belonging to other users
    // (worse than the rotate case: it also confirms a rotation is
    // in-progress right now for that user).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Sam's PAT", "sam-pending", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string sam_predecessor_id = vt->token_id;
    auto rotated = store.rotate_token(sam_predecessor_id, kDefaultOverlapSecs, now, "sam-pending",
                                      "", "");
    REQUIRE(rotated.has_value());
    std::string sam_successor_id;
    for (const auto& tok : store.list_active_for_principal("sam-pending"))
        if (tok.supersedes_token_id == sam_predecessor_id)
            sam_successor_id = tok.token_id;
    REQUIRE_FALSE(sam_successor_id.empty());

    auto against_nonexistent = store.confirm_token_rotation(
        "2222222222222222deadbeef", "irrelevant-secret", "attacker", "", "");
    auto against_real_pending =
        store.confirm_token_rotation(sam_successor_id, "irrelevant-secret", "attacker", "", "");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_real_pending.has_value());
    CHECK(against_nonexistent.error() == against_real_pending.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_real_pending.error()));

    // Sam's pending pair is completely untouched.
    auto after = store.list_active_for_principal("sam-pending");
    REQUIRE(after.size() == 2);
    for (const auto& tok : after)
        CHECK(tok.confirmed_at == 0);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a nonexistent "
          "successor_token_id identically to another user's REVOKED "
          "(cut-over) predecessor token_id — the timing-independent sibling",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: the confirm path's own revoked-row shape — a
    // predecessor that WAS revoked by a completed confirm is a different
    // internal state than "id never existed", and (per the rotate-side
    // sibling above) needs its own case rather than assuming the
    // active-pending comparison covers it.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Tara's PAT", "tara-resolved", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string tara_predecessor_id = vt->token_id;
    auto rotated =
        store.rotate_token(tara_predecessor_id, kDefaultOverlapSecs, now, "tara-resolved", "", "");
    REQUIRE(rotated.has_value());
    std::string tara_successor_id;
    for (const auto& tok : store.list_active_for_principal("tara-resolved"))
        if (tok.supersedes_token_id == tara_predecessor_id)
            tara_successor_id = tok.token_id;
    REQUIRE_FALSE(tara_successor_id.empty());
    // The confirm revokes the predecessor.
    REQUIRE(store.confirm_token_rotation(tara_successor_id, *rotated, "tara-resolved", "", "")
                .has_value());

    auto against_nonexistent = store.confirm_token_rotation(
        "3333333333333333deadbeef", "irrelevant-secret", "attacker", "", "");
    auto against_revoked_predecessor = store.confirm_token_rotation(
        tara_predecessor_id, "irrelevant-secret", "attacker", "", "");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_revoked_predecessor.has_value());
    CHECK(against_nonexistent.error() == against_revoked_predecessor.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_revoked_predecessor.error()));
}

// ── Item 8: cache cutover on confirm ────────────────────────────────────

TEST_CASE("ApiTokenStore: confirm_token_rotation cuts the revoked "
          "predecessor over IMMEDIATELY — it must not keep validating from "
          "the 60s token cache (double revoke_generation_ bump, human arm)",
          "[pg][token][rotation][human]") {
    // Defect this catches: if confirm_token_rotation forgets the SECOND
    // revoke_generation_ bump (or the invalidate_cache(revoked_hash) call)
    // that confirm_rotation's own doc comment (#2188) requires for exactly
    // this reason, a validate_token call racing the commit could repopulate
    // the in-memory cache with the now-stale predecessor row AFTER the
    // invalidation ran, letting a revoked credential authenticate for up to
    // kTokenCacheTtl (60s) past an explicit operator-confirmed cutover —
    // exactly the immediate-cutover guarantee confirm exists to provide.
    // Reachable and asserted purely through the public API — no internals
    // touched.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("Cached PAT", "judy-cache", now + k90Days);
    REQUIRE(predecessor_raw.has_value());

    // Populate the 60s validate_token cache for the predecessor BEFORE
    // rotating — this is the entry that must not survive the confirm.
    auto pre_cache = store.validate_token(*predecessor_raw);
    REQUIRE(pre_cache.has_value());
    const std::string t_id = pre_cache->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "judy-cache", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("judy-cache"))
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    REQUIRE(
        store.confirm_token_rotation(successor_id, *rotated, "judy-cache", "", "").has_value());

    // The predecessor's raw token must be rejected NOW, not up to 60s from
    // now — proving the cache entry populated above was actually evicted,
    // not merely left to expire on its own TTL.
    auto post = store.validate_token(*predecessor_raw);
    CHECK_FALSE(post.has_value());
}

// ── #3015: confirm rotation proof-of-possession ─────────────────────────────

TEST_CASE("ApiTokenStore: confirm_token_rotation with the WRONG secret gets a distinct "
          "'rotation secret mismatch' outcome, never the not-found wording (#3015, human arm)",
          "[pg][token][rotation][human][confirm][pop]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto t = store.create_token("PoP PAT", "wendy", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "wendy", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("wendy"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Wrong secret, but every OTHER admission gate (ownership, pair-state,
    // token_id pin, initiator) passes — reachable ONLY because of that.
    auto wrong = store.confirm_token_rotation(successor_id, "not-the-real-secret", "wendy", "",
                                              "");
    REQUIRE_FALSE(wrong.has_value());
    CHECK(wrong.error().find("rotation secret mismatch") != std::string::npos);
    CHECK(classify_engine_store_error(wrong.error()) == E::SecretMismatch);
    // Distinct from the not-found/ownership-failure wording (e.g. a bogus
    // token_id) — never conflated into the same outcome.
    CHECK(wrong.error() != "no such token to confirm");

    // No mutation: neither credential touched by the rejected attempt.
    auto active = store.list_active_for_principal("wendy");
    REQUIRE(active.size() == 2);
    for (const auto& tok : active)
        CHECK(tok.confirmed_at == 0);

    // The correct secret still confirms afterward — the wrong attempt
    // consumed nothing.
    CHECK(store.confirm_token_rotation(successor_id, *rotated, "wendy", "", "").has_value());
}

TEST_CASE("ApiTokenStore: confirm_rotation with the WRONG secret gets a distinct "
          "'rotation secret mismatch' outcome, never the initiator-binding wording "
          "(#3015, engine arm)",
          "[pg][token][rotation][confirm][pop]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    const std::string principal = "engine:rotation-pop-mismatch";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto wrong = store.confirm_rotation(principal, successor_id, "not-the-real-secret", "admin");
    REQUIRE_FALSE(wrong.has_value());
    CHECK(wrong.error().find("rotation secret mismatch") != std::string::npos);
    CHECK(classify_engine_store_error(wrong.error()) == E::SecretMismatch);
    CHECK(wrong.error().find("different operator") == std::string::npos);

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    for (const auto& t : active)
        CHECK(t.confirmed_at == 0);

    CHECK(store.confirm_rotation(principal, successor_id, *rotated, "admin").has_value());
}

TEST_CASE("ApiTokenStore: a non-initiator presenting the CORRECT secret still gets the "
          "SAME non-disclosing outcome as a wrong operator with no secret at all — "
          "no cross-admin secret oracle (#3015, engine arm)",
          "[pg][token][rotation][confirm][pop][oracle]") {
    // The specific defect the PoP-checked-LAST ordering exists to close: if
    // PoP ran before the initiator-binding check, a non-initiator admin who
    // happened to also know (or guess) the correct secret could distinguish
    // "wrong secret" from "valid secret, not your rotation" — a live oracle
    // over WHO initiated a given rotation. With PoP last, both variants below
    // must produce the IDENTICAL "different operator" outcome.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-pop-oracle";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Non-initiator "mallory" presenting the CORRECT secret.
    auto with_correct_secret =
        store.confirm_rotation(principal, successor_id, *rotated, "mallory");
    // Non-initiator "mallory" presenting a WRONG secret.
    auto with_wrong_secret =
        store.confirm_rotation(principal, successor_id, "not-the-real-secret", "mallory");

    REQUIRE_FALSE(with_correct_secret.has_value());
    REQUIRE_FALSE(with_wrong_secret.has_value());
    // Byte-identical outcome regardless of secret correctness — never
    // "confirmed" and never the distinguishable "rotation secret mismatch".
    CHECK(with_correct_secret.error() == with_wrong_secret.error());
    CHECK(with_correct_secret.error().find("different operator") != std::string::npos);
    CHECK(with_correct_secret.error().find("rotation secret mismatch") == std::string::npos);

    // Nothing mutated by either attempt, and the real initiator can still
    // confirm afterward with the real secret.
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    for (const auto& t : active)
        CHECK(t.confirmed_at == 0);
    CHECK(store.confirm_rotation(principal, successor_id, *rotated, "admin").has_value());
}

TEST_CASE("ApiTokenStore: confirm_token_rotation with a missing/empty secret is a "
          "distinct 400-class validation error (#3015, human arm)",
          "[pg][token][rotation][human][confirm][pop]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto t = store.create_token("Empty-secret PAT", "xander", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated =
        store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "xander", "", "");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("xander"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto missing = store.confirm_token_rotation(successor_id, "", "xander", "", "");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == "secret required");
    CHECK(classify_engine_store_error(missing.error()) == E::ClientValidation);

    // No mutation, and the real secret still confirms afterward.
    auto active = store.list_active_for_principal("xander");
    REQUIRE(active.size() == 2);
    CHECK(store.confirm_token_rotation(successor_id, *rotated, "xander", "", "").has_value());
}

TEST_CASE("ApiTokenStore: confirm_token_rotation with the correct secret succeeds after "
          "a process restart — durable rotation_initiator + PoP, no RAM dependency "
          "(#3015, human arm)",
          "[pg][token][rotation][human][confirm][pop][restart]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    std::string successor_id;
    std::string raw_secret;
    {
        ApiTokenStore store{pool};
        REQUIRE(store.is_open());
        auto now = test_now_epoch();
        auto t = store.create_token("Restart PAT", "yara", now + k90Days);
        REQUIRE(t.has_value());
        auto vt = store.validate_token(*t);
        REQUIRE(vt.has_value());
        const std::string predecessor_id = vt->token_id;

        auto rotated =
            store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "yara", "", "");
        REQUIRE(rotated.has_value());
        raw_secret = *rotated;
        for (const auto& tok : store.list_active_for_principal("yara"))
            if (tok.supersedes_token_id == predecessor_id)
                successor_id = tok.token_id;
        REQUIRE_FALSE(successor_id.empty());
        // `store` (and its RAM-only rotation_grace_cache_/token_cache_) goes
        // out of scope here — the "restart".
    }

    // A FRESH store instance against the SAME database — its RAM caches
    // start genuinely empty, so any confirm success below is driven entirely
    // by DURABLE state (the rotation_initiator column + the persisted
    // token_hash PoP reads), never by anything cached in the prior
    // instance's RAM.
    ApiTokenStore restarted{pool};
    REQUIRE(restarted.is_open());
    CHECK(restarted.rotation_grace_cache_size() == 0);

    auto confirmed =
        restarted.confirm_token_rotation(successor_id, raw_secret, "yara", "", "");
    REQUIRE(confirmed.has_value());
    auto active = restarted.list_active_for_principal("yara");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
}

TEST_CASE("ApiTokenStore: revoke_for_principal scrubs the RAM-only rotation grace-cache "
          "entry — a re-serve no longer returns the secret after every credential is "
          "revoked (#2961 residual A)",
          "[pg][token][rotation][human][revoke][pop]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Grace-scrub PAT", "zack", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "zack", "", "");
    REQUIRE(rotated.has_value());

    // The mint above populated the RAM-only grace cache for this rotation's
    // group — confirm that ahead of the assertion this test exists for.
    REQUIRE(store.rotation_grace_cache_size() > 0);
    // And a same-operator re-serve within the grace window really does
    // return the cached raw secret right now (the behaviour this test does
    // NOT touch — #2961 residual B stays intact).
    auto reserve_before =
        store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "zack", "", "");
    REQUIRE(reserve_before.has_value());
    CHECK(*reserve_before == *rotated);

    // "Sign out everywhere" — revokes every active credential for zack,
    // which is BOTH sides of the in-flight pair.
    auto revoked = store.revoke_for_principal("zack");
    REQUIRE(revoked.has_value());
    CHECK(*revoked == 2);

    // The grace-cache entry for this rotation's group is gone — scrubbed,
    // not merely orphaned — so nothing in this store's RAM can re-serve the
    // secret past this point.
    CHECK(store.rotation_grace_cache_size() == 0);

    // Both credentials are genuinely revoked at the DB too.
    auto after = store.list_active_for_principal("zack");
    CHECK(after.empty());
}

// ── #2964 round 3 review finding 6/7: SweepResult::failed_pairs coverage ────
// (zero coverage before this — `grep -c failed_pairs tests/…` found nothing —
// which is exactly how the COMMIT-path counting gap survived review.)

TEST_CASE("ApiTokenStore::sweep_expired_rotations: failed_pairs counts a POOL-CONTENTION "
          "ACQUIRE failure on the per-pair transaction",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: `result.failed_pairs` must be
    // nonzero — not merely `result.revoked.empty()` — when every per-pair
    // `with_txn_for` call times out acquiring its own SECOND connection
    // while the sweep's own store-wide session lock pins the first (see the
    // method's own POOL-SIZE FLOOR doc comment). Reproduced against live
    // Postgres exactly this way in review: a size-2 pool, N eligible pairs,
    // and one unrelated caller holding a lease leaves nothing for any
    // per-pair transaction to acquire — `outcome=Ok revoked={} capped=false`
    // with NO other signal, until this field existed.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);

    constexpr int kPairs = 3;
    std::vector<std::string> predecessor_ids;
    for (int i = 0; i < kPairs; ++i) {
        const std::string principal = "acquire-fail-pair-" + std::to_string(i);
        REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
        const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
        auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
        REQUIRE(rotated.has_value());
        REQUIRE(store.validate_token(*rotated).has_value());
        force_overlap_expires_at(pool, pred_id, pg_now(pool) - 1);
        predecessor_ids.push_back(pred_id);
    }

    // Pin the pool's ONLY other connection so the sweep's own session-lock
    // lease and this held lease together exhaust the size-2 pool — no
    // connection is left for any per-pair `with_txn_for` call to acquire.
    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    auto swept = store.sweep_expired_rotations(now);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    CHECK(swept.revoked.empty());
    CHECK(swept.failed_pairs == static_cast<std::size_t>(kPairs));

    // Every predecessor is still live — lost to pool contention, not
    // silently and incorrectly auto-revoked.
    for (const auto& pred_id : predecessor_ids) {
        auto tok = store.get_token(pred_id);
        REQUIRE(tok.has_value());
        REQUIRE(tok->has_value());
        CHECK_FALSE((*tok)->revoked);
    }
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: failed_pairs counts a COMMIT failure that "
          "arrives AFTER the per-pair transaction's own work already succeeded (#2964 round 3 "
          "review finding 6)",
          "[pg][token][rotation][sweep][clock-guard]") {
    // THE ASSERTION THIS TEST EXISTS FOR: the ORIGINAL counting condition
    // (`pair_outcome == kFailed`) missed this path entirely — `with_txn_for`
    // can return `false` because COMMIT itself fails, AFTER the lambda
    // already ran both UPDATEs successfully and set `pair_outcome =
    // kRevoked` and returned `true`. That pair then entered neither
    // `result.revoked` (guarded by `if (ok)`) NOR the old `result.
    // failed_pairs` condition — silently vanishing from both. Reproduced
    // here with a DEFERRABLE INITIALLY DEFERRED constraint trigger that
    // raises on the predecessor's own UPDATE — fires at COMMIT, exactly the
    // point `pair_outcome` has already been set to `kRevoked`.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    anchor_sweep_guard(store, now);

    const std::string principal = "commit-fail-principal";
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    const std::string pred_id = store.list_active_for_principal(principal)[0].token_id;
    auto rotated = store.rotate_token(pred_id, kDay, now, principal, "", "");
    REQUIRE(rotated.has_value());
    REQUIRE(store.validate_token(*rotated).has_value());
    force_overlap_expires_at(pool, pred_id, pg_now(pool) - 1);

    // Install the deferred poison trigger, scoped to THIS predecessor's
    // token_id only (via a marker table, never a literal embedded in the
    // function body — avoids SQL-escaping the token_id string).
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        REQUIRE(PgResult{PQexec(lease.get(),
                                "CREATE TABLE IF NOT EXISTS api_token_store.test_commit_poison "
                                "(token_id TEXT PRIMARY KEY)")}
                    .ok());
        REQUIRE(PgResult{PQexec(lease.get(),
                                "CREATE OR REPLACE FUNCTION "
                                "api_token_store.test_commit_poison_fn() RETURNS trigger AS $$ "
                                "BEGIN "
                                "  IF EXISTS (SELECT 1 FROM api_token_store.test_commit_poison "
                                "WHERE token_id = NEW.token_id) THEN "
                                "    RAISE EXCEPTION 'test-induced commit-time failure (token_id="
                                "%)', NEW.token_id; "
                                "  END IF; "
                                "  RETURN NEW; "
                                "END; "
                                "$$ LANGUAGE plpgsql")}
                    .ok());
        REQUIRE(PgResult{PQexec(lease.get(),
                                "CREATE CONSTRAINT TRIGGER test_commit_poison_trigger "
                                "AFTER UPDATE ON api_token_store.api_tokens "
                                "DEFERRABLE INITIALLY DEFERRED "
                                "FOR EACH ROW EXECUTE FUNCTION "
                                "api_token_store.test_commit_poison_fn()")}
                    .ok());
        PgResult mark = pg::exec_params(
            lease.get(), "INSERT INTO api_token_store.test_commit_poison (token_id) VALUES ($1)",
            std::vector<std::string>{pred_id});
        REQUIRE(mark.status() == PGRES_COMMAND_OK);
    }

    auto swept = store.sweep_expired_rotations(now);
    REQUIRE(swept.outcome == ApiTokenStore::SweepOutcome::Ok);
    // THE FIELD THIS TEST PINS: the pair is counted as FAILED, not silently
    // dropped.
    CHECK(swept.revoked.empty());
    CHECK(swept.failed_pairs == 1);

    // The predecessor's revoke was rolled back along with the rest of the
    // failed COMMIT — still fully live, never half-applied.
    auto pred_after = store.get_token(pred_id);
    REQUIRE(pred_after.has_value());
    REQUIRE(pred_after->has_value());
    CHECK_FALSE((*pred_after)->revoked);
}
