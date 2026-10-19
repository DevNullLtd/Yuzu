/**
 * test_crypto_dashboard_layout_store.cpp -- Unit tests for CryptoDashboardLayoutStore
 * (born-on-Postgres, ADR-0071, schema `crypto_dashboard_layout_store`).
 *
 * Covers: the migration (on the migration-DDL macro), get/put round trip, per-user isolation,
 * replace-on-put, a stored empty layout vs no layout, the defence-in-depth argument bounds, a
 * corrupt stored row, and the closed-store / held-pool failure channel (never "no layout").
 */

#include "crypto_dashboard_layout_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate layout_tpl{"cryptolayout", [](const std::string& dsn) {
                                          PgPool pool{{.conninfo = dsn, .size = 1}};
                                          CryptoDashboardLayoutStore store{pool};
                                          if (!store.is_open())
                                              throw std::runtime_error(
                                                  "crypto layout template: store failed to migrate");
                                      }};

} // namespace

#define LAYOUT_STORE(store_var)                                                                    \
    YUZU_REQUIRE_PG_DB_TPL(layout_db_fx_, layout_tpl);                                             \
    PgPool layout_pool_fx_{{.conninfo = layout_db_fx_.dsn(), .size = 2}};                          \
    REQUIRE(layout_pool_fx_.valid());                                                              \
    CryptoDashboardLayoutStore store_var{layout_pool_fx_};                                         \
    REQUIRE(store_var.is_open())

TEST_CASE("CryptoDashboardLayoutStore: migration creates the schema and the table",
          "[crypto_dashboard_layout_store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    CryptoDashboardLayoutStore store{pool};
    REQUIRE(store.is_open());
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), "SELECT column_name FROM information_schema.columns WHERE "
                                  "table_schema = 'crypto_dashboard_layout_store' AND "
                                  "table_name = 'layouts' ORDER BY ordinal_position")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 3);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "username");
    CHECK(std::string(PQgetvalue(r.get(), 1, 0)) == "widget_ids");
    CHECK(std::string(PQgetvalue(r.get(), 2, 0)) == "updated_at");
    // Re-opening against an already-migrated schema is a no-op, still open.
    CryptoDashboardLayoutStore again{pool};
    CHECK(again.is_open());
}

TEST_CASE("CryptoDashboardLayoutStore: no stored layout reads as nullopt, not an error",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    const auto got = store.get("alice");
    REQUIRE(got.has_value());
    CHECK_FALSE(got->has_value());
}

TEST_CASE("CryptoDashboardLayoutStore: put then get round-trips the order; put replaces",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    REQUIRE(store.put("alice", {"ca.active", "lib.families_table", "ca.expiring_30d"}));
    auto got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK(**got == std::vector<std::string>{"ca.active", "lib.families_table", "ca.expiring_30d"});

    REQUIRE(store.put("alice", {"ca.revoked_7d"}));
    got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK(**got == std::vector<std::string>{"ca.revoked_7d"});
}

TEST_CASE("CryptoDashboardLayoutStore: layouts are per user", "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    REQUIRE(store.put("alice", {"ca.active"}));
    REQUIRE(store.put("bob", {"lib.families_table"}));
    auto a = store.get("alice");
    auto b = store.get("bob");
    auto c = store.get("carol");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(c.has_value());
    CHECK(**a == std::vector<std::string>{"ca.active"});
    CHECK(**b == std::vector<std::string>{"lib.families_table"});
    CHECK_FALSE(c->has_value());
}

TEST_CASE("CryptoDashboardLayoutStore: a stored empty layout differs from none",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    REQUIRE(store.put("alice", {}));
    const auto got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->empty());
}

TEST_CASE("CryptoDashboardLayoutStore: put refuses out-of-bounds arguments before any SQL",
          "[crypto_dashboard_layout_store][pg][negative]") {
    LAYOUT_STORE(store);
    CHECK_FALSE(store.put("", {"ca.active"}));
    CHECK_FALSE(store.put(std::string(CryptoDashboardLayoutStore::kMaxUsernameBytes + 1, 'u'), {}));
    CHECK_FALSE(store.put("alice", std::vector<std::string>(CryptoDashboardLayoutStore::kMaxIds + 1,
                                                            "ca.active")));
    CHECK_FALSE(store.put("alice", {std::string(CryptoDashboardLayoutStore::kMaxIdBytes + 1, 'x')}));
    CHECK_FALSE(store.put("alice", {""}));
    CHECK_FALSE(store.put("alice", {std::string("bad\xff", 4)}));
    CHECK_FALSE(store.get("").has_value());
    // Nothing was written by any refusal.
    const auto got = store.get("alice");
    REQUIRE(got.has_value());
    CHECK_FALSE(got->has_value());
}

TEST_CASE("CryptoDashboardLayoutStore: a corrupt stored row is an error, not a layout",
          "[crypto_dashboard_layout_store][pg][negative]") {
    LAYOUT_STORE(store);
    PgConn conn{PQconnectdb(layout_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(conn.get(),
                            "INSERT INTO crypto_dashboard_layout_store.layouts VALUES "
                            "('alice', '[1, 2]'::jsonb, 0)")}
                .status() == PGRES_COMMAND_OK);
    CHECK_FALSE(store.get("alice").has_value());
    // The CHECK constraint keeps a non-array out at the source.
    CHECK(PgResult{PQexec(conn.get(), "INSERT INTO crypto_dashboard_layout_store.layouts VALUES "
                                      "('bob', '{}'::jsonb, 0)")}
              .status() == PGRES_FATAL_ERROR);
}

TEST_CASE("CryptoDashboardLayoutStore: no connection in time is an error on both paths",
          "[crypto_dashboard_layout_store][pg][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, layout_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    CryptoDashboardLayoutStore store{pool};
    REQUIRE(store.is_open());
    store.set_acquire_timeout_for_test(std::chrono::milliseconds{50});
    auto held = pool.acquire(); // the only connection
    REQUIRE(held);
    CHECK_FALSE(store.get("alice").has_value());
    CHECK_FALSE(store.put("alice", {"ca.active"}).has_value());
}
