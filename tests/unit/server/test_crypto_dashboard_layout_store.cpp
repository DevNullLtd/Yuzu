/**
 * test_crypto_dashboard_layout_store.cpp -- Unit tests for CryptoDashboardLayoutStore
 * (born-on-Postgres, ADR-0071, schema `crypto_dashboard_layout_store`).
 *
 * Covers: the migrations (on the migration-DDL macro), get/put round trip with versions,
 * per-user isolation, the optimistic-concurrency conflict (two writers from one version, and
 * concurrent first writes resolving to one winner), a stored empty layout vs no layout, ids
 * stored verbatim, the defence-in-depth argument bounds (the 1024-byte username edge), a corrupt
 * stored row (kCorrupt, replaceable by its version), erase, a write whose connection is lost
 * (kOutcomeUnknown), and the closed-store / held-pool failure channel (never "no layout").
 */

#include "crypto_dashboard_layout_store.hpp"
#include "crypto_layout_erasure.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
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

using LKind = CryptoLayoutStoreError::Kind;

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
    REQUIRE(PQntuples(r.get()) == 4);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "username");
    CHECK(std::string(PQgetvalue(r.get(), 1, 0)) == "widget_ids");
    CHECK(std::string(PQgetvalue(r.get(), 2, 0)) == "updated_at");
    CHECK(std::string(PQgetvalue(r.get(), 3, 0)) == "version");
    PgResult ver{PQexec(conn.get(), "SELECT version FROM public.schema_meta WHERE store = "
                                    "'crypto_dashboard_layout_store'")};
    REQUIRE(ver.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(ver.get()) == 1);
    CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "2");
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

TEST_CASE("CryptoDashboardLayoutStore: put then get round-trips the order and the version",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    const auto v1 = store.put("alice", {"ca.active", "lib.families_table", "ca.expiring_30d"},
                              std::nullopt);
    REQUIRE(v1.has_value());
    CHECK(*v1 == 1);
    auto got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->widget_ids ==
          std::vector<std::string>{"ca.active", "lib.families_table", "ca.expiring_30d"});
    CHECK((*got)->version == 1);

    const auto v2 = store.put("alice", {"ca.revoked_7d"}, 1);
    REQUIRE(v2.has_value());
    CHECK(*v2 == 2);
    got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->widget_ids == std::vector<std::string>{"ca.revoked_7d"});
    CHECK((*got)->version == 2);
}

TEST_CASE("CryptoDashboardLayoutStore: ids are stored and returned verbatim, unknown ones included",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    // The store knows no catalogue: a widget id from a newer build survives unchanged.
    REQUIRE(store.put("alice", {"ca.active", "future.widget_v9"}, std::nullopt));
    const auto got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->widget_ids == std::vector<std::string>{"ca.active", "future.widget_v9"});
}

TEST_CASE("CryptoDashboardLayoutStore: a write from a stale version is a conflict, not an "
          "overwrite",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    REQUIRE(store.put("alice", {"ca.active"}, std::nullopt));
    // Two tabs both read version 1. The first save wins; the second gets kConflict.
    const auto first = store.put("alice", {"lib.families_table"}, 1);
    REQUIRE(first.has_value());
    CHECK(*first == 2);
    const auto second = store.put("alice", {"ca.revoked_7d"}, 1);
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().kind == LKind::kConflict);
    // A first write when a row already exists is a conflict too.
    const auto dup_first = store.put("alice", {"ca.revoked_7d"}, std::nullopt);
    REQUIRE_FALSE(dup_first.has_value());
    CHECK(dup_first.error().kind == LKind::kConflict);
    // A replace of a row that does not exist (erased since it was read) is a conflict.
    const auto ghost = store.put("bob", {"ca.active"}, 3);
    REQUIRE_FALSE(ghost.has_value());
    CHECK(ghost.error().kind == LKind::kConflict);
    // The winner's layout stands.
    const auto got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->widget_ids == std::vector<std::string>{"lib.families_table"});
    CHECK((*got)->version == 2);
    CHECK_FALSE(store.get("bob")->has_value());
}

TEST_CASE("CryptoDashboardLayoutStore: concurrent first writes resolve to exactly one winner",
          "[crypto_dashboard_layout_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, layout_tpl);
    constexpr int kWriters = 4;
    PgPool pool{{.conninfo = db.dsn(), .size = kWriters}};
    REQUIRE(pool.valid());
    CryptoDashboardLayoutStore store{pool};
    REQUIRE(store.is_open());
    for (int round = 0; round < 5; ++round) {
        const std::string user = "racer" + std::to_string(round);
        std::atomic<int> ready{0};
        std::atomic<int> wins{0};
        std::atomic<int> conflicts{0};
        std::vector<std::thread> writers;
        for (int w = 0; w < kWriters; ++w)
            writers.emplace_back([&, w] {
                ready.fetch_add(1);
                while (ready.load() < kWriters)
                    std::this_thread::yield();
                const auto r = store.put(user, {"w" + std::to_string(w)}, std::nullopt);
                if (r)
                    wins.fetch_add(1);
                else if (r.error().kind == LKind::kConflict)
                    conflicts.fetch_add(1);
            });
        for (auto& t : writers)
            t.join();
        CHECK(wins.load() == 1);
        CHECK(conflicts.load() == kWriters - 1);
        const auto got = store.get(user);
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->version == 1);
    }
}

TEST_CASE("CryptoDashboardLayoutStore: a stored empty layout differs from none",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    REQUIRE(store.put("alice", {}, std::nullopt));
    const auto got = store.get("alice");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->widget_ids.empty());
}

TEST_CASE("CryptoDashboardLayoutStore: erase removes the row; erasing nothing is not an error",
          "[crypto_dashboard_layout_store][pg]") {
    LAYOUT_STORE(store);
    REQUIRE(store.put("alice", {"ca.active"}, std::nullopt));
    REQUIRE(store.put("bob", {"ca.active"}, std::nullopt));
    const auto gone = store.erase("alice");
    REQUIRE(gone.has_value());
    CHECK(*gone);
    CHECK_FALSE(store.get("alice")->has_value());
    CHECK(store.get("bob")->has_value()); // only the named operator's row
    const auto again = store.erase("alice");
    REQUIRE(again.has_value());
    CHECK_FALSE(*again);
    // After an erase the operator starts over with a first write.
    const auto fresh = store.put("alice", {"lib.families_table"}, std::nullopt);
    REQUIRE(fresh.has_value());
    CHECK(*fresh == 1);
}

TEST_CASE("CryptoDashboardLayoutStore: argument bounds are kInvalidInput before any SQL",
          "[crypto_dashboard_layout_store][pg][negative]") {
    LAYOUT_STORE(store);
    auto invalid = [](const auto& r) {
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == LKind::kInvalidInput);
    };
    // The 1024-byte username edge: at the bound is stored; one byte over is refused on every
    // call (never reported as a degraded store).
    const std::string at_bound(CryptoDashboardLayoutStore::kMaxUsernameBytes, 'u');
    const std::string over(CryptoDashboardLayoutStore::kMaxUsernameBytes + 1, 'u');
    REQUIRE(store.put(at_bound, {"ca.active"}, std::nullopt));
    const auto at_bound_got = store.get(at_bound);
    REQUIRE(at_bound_got.has_value());
    CHECK(at_bound_got->has_value());
    invalid(store.put(over, {}, std::nullopt));
    invalid(store.get(over));
    invalid(store.erase(over));

    invalid(store.put("", {"ca.active"}, std::nullopt));
    invalid(store.put(std::string("bad\xff", 4), {"ca.active"}, std::nullopt));
    const std::vector<std::string> too_many(CryptoDashboardLayoutStore::kMaxIds + 1, "ca.active");
    invalid(store.put("alice", too_many, std::nullopt));
    invalid(store.put("alice", {std::string(CryptoDashboardLayoutStore::kMaxIdBytes + 1, 'x')},
                      std::nullopt));
    invalid(store.put("alice", {""}, std::nullopt));
    invalid(store.put("alice", {std::string("bad\xff", 4)}, std::nullopt));
    invalid(store.put("alice", {"ca.active"}, 0));
    invalid(store.get(""));
    invalid(store.erase(""));
    // Nothing was written by any refusal.
    const auto got = store.get("alice");
    REQUIRE(got.has_value());
    CHECK_FALSE(got->has_value());
}

TEST_CASE("CryptoDashboardLayoutStore: a corrupt stored row is kCorrupt and a put of its version "
          "replaces it",
          "[crypto_dashboard_layout_store][pg][negative]") {
    LAYOUT_STORE(store);
    PgConn conn{PQconnectdb(layout_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(conn.get(),
                            "INSERT INTO crypto_dashboard_layout_store.layouts "
                            "(username, widget_ids, updated_at, version) VALUES "
                            "('alice', '[\"ca.active\", 2]'::jsonb, 0, 7)")}
                .status() == PGRES_COMMAND_OK);
    const auto bad = store.get("alice");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().kind == LKind::kCorrupt);
    CHECK(bad.error().version == 7);
    // The dashboard's Reset: a put naming the corrupt row's version overwrites it.
    const auto reset = store.put("alice", {"ca.active"}, bad.error().version);
    REQUIRE(reset.has_value());
    CHECK(*reset == 8);
    const auto good = store.get("alice");
    REQUIRE(good.has_value());
    REQUIRE(good->has_value());
    CHECK((*good)->widget_ids == std::vector<std::string>{"ca.active"});
    // The CHECK constraint keeps a non-array out at the source.
    CHECK(PgResult{PQexec(conn.get(), "INSERT INTO crypto_dashboard_layout_store.layouts VALUES "
                                      "('bob', '{}'::jsonb, 0)")}
              .status() == PGRES_FATAL_ERROR);
}

TEST_CASE("CryptoDashboardLayoutStore: a write whose connection is lost mid-statement is "
          "kOutcomeUnknown",
          "[crypto_dashboard_layout_store][pg][negative]") {
    LAYOUT_STORE(store);
    REQUIRE(store.put("alice", {"ca.active"}, std::nullopt));
    // Hold alice's row so the replace blocks on it, then terminate the blocked backend: the
    // writer sees its connection die after the statement was sent.
    PgConn locker{PQconnectdb(layout_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(locker.get(), "BEGIN")}.status() == PGRES_COMMAND_OK);
    REQUIRE(PgResult{PQexec(locker.get(), "SELECT 1 FROM crypto_dashboard_layout_store.layouts "
                                          "WHERE username = 'alice' FOR UPDATE")}
                .status() == PGRES_TUPLES_OK);
    std::optional<std::expected<std::int64_t, CryptoLayoutStoreError>> result;
    std::thread writer([&] { result = store.put("alice", {"lib.families_table"}, 1); });
    PgConn killer{PQconnectdb(layout_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(killer.get()) == CONNECTION_OK);
    bool killed = false;
    for (int i = 0; i < 200 && !killed; ++i) {
        PgResult k{PQexec(killer.get(),
                          "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE "
                          "datname = current_database() AND wait_event_type = 'Lock' AND "
                          "query LIKE 'UPDATE crypto_dashboard_layout_store.layouts%'")};
        killed = k.status() == PGRES_TUPLES_OK && PQntuples(k.get()) == 1;
        if (!killed)
            std::this_thread::sleep_for(std::chrono::milliseconds{25});
    }
    writer.join();
    PgResult{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(killed);
    REQUIRE(result.has_value());
    REQUIRE_FALSE(result->has_value());
    CHECK(result->error().kind == LKind::kOutcomeUnknown);
    // The pool discarded the dead connection and still serves.
    const auto after = store.get("alice");
    REQUIRE(after.has_value());
    CHECK(after->has_value());
}

TEST_CASE("CryptoDashboardLayoutStore: no connection in time is kPoolAcquireTimeout on every path",
          "[crypto_dashboard_layout_store][pg][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, layout_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    CryptoDashboardLayoutStore store{pool};
    REQUIRE(store.is_open());
    store.set_acquire_timeout_for_test(std::chrono::milliseconds{50});
    {
        auto held = pool.acquire(); // the only connection
        REQUIRE(held);
        const auto g = store.get("alice");
        REQUIRE_FALSE(g.has_value());
        CHECK(g.error().kind == LKind::kPoolAcquireTimeout);
        const auto p = store.put("alice", {"ca.active"}, std::nullopt);
        REQUIRE_FALSE(p.has_value());
        CHECK(p.error().kind == LKind::kPoolAcquireTimeout);
        const auto e = store.erase("alice");
        REQUIRE_FALSE(e.has_value());
        CHECK(e.error().kind == LKind::kPoolAcquireTimeout);
    }
    // The pool still serves once the connection is back.
    CHECK(store.put("alice", {"ca.active"}, std::nullopt).has_value());
}

TEST_CASE("CryptoDashboardLayoutStore: a store that never opened is kNotOpen",
          "[crypto_dashboard_layout_store][pg][negative]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(PgResult{PQexec(conn.get(), "CREATE SCHEMA crypto_dashboard_layout_store")}
                    .status() == PGRES_COMMAND_OK);
        REQUIRE(PgResult{PQexec(conn.get(), "CREATE TABLE crypto_dashboard_layout_store.layouts "
                                            "(bogus int)")}
                    .status() == PGRES_COMMAND_OK);
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    CryptoDashboardLayoutStore store{pool};
    REQUIRE_FALSE(store.is_open());
    CHECK(store.get("alice").error().kind == LKind::kNotOpen);
    CHECK(store.put("alice", {}, std::nullopt).error().kind == LKind::kNotOpen);
    CHECK(store.erase("alice").error().kind == LKind::kNotOpen);
}

// ── Deprovision erasure: the erase-failure reason mapping (Gate 8 qe) ──────────────────────────

TEST_CASE("crypto layout erasure: every store failure maps to its closed counter reason",
          "[crypto_dashboard_layout_store][erasure]") {
    namespace cle = crypto_layout_erasure;
    CHECK_FALSE(cle::reason_for(LKind::kInvalidInput).has_value()); // owns no row: not a failure
    CHECK(cle::reason_for(LKind::kNotOpen) == cle::kStoreNotOpen);
    CHECK(cle::reason_for(LKind::kPoolAcquireTimeout) == cle::kPoolAcquireTimeout);
    CHECK(cle::reason_for(LKind::kOutcomeUnknown) == cle::kOutcomeUnknown);
    CHECK(cle::reason_for(LKind::kQueryError) == cle::kQueryError);
    CHECK(cle::reason_for(LKind::kConflict) == cle::kQueryError);
    CHECK(cle::reason_for(LKind::kCorrupt) == cle::kQueryError);
    // The pre-seeded set is exactly the five documented reasons, link_read_failed included
    // (R2-1: the SCIM seam's report, not a store kind).
    CHECK(cle::kReasons == std::array<std::string_view, 5>{"store_not_open", "pool_acquire_timeout",
                                                           "outcome_unknown", "query_error",
                                                           "link_read_failed"});
    CHECK(cle::kLinkReadFailed == kErasureLinkReadFailed);
    // Every mapped reason is pre-seeded.
    for (const auto k : {LKind::kNotOpen, LKind::kPoolAcquireTimeout, LKind::kOutcomeUnknown,
                         LKind::kQueryError, LKind::kConflict, LKind::kCorrupt})
        CHECK(std::ranges::find(cle::kReasons, *cle::reason_for(k)) != cle::kReasons.end());
}

TEST_CASE("crypto layout erasure: the emitter's metric name is the one the alert reads",
          "[crypto_dashboard_layout_store][erasure]") {
    // Tripwire: a renamed counter would leave YuzuCryptoLayoutEraseFailed (any reason) silent.
    std::ifstream in(std::string(YUZU_SERVER_SRC_DIR) + "/../../../docs/prometheus/yuzu-alerts.yml");
    REQUIRE(in.good());
    const std::string alerts{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const std::string expr = "sum by (reason) (increase(" +
                             std::string(crypto_layout_erasure::kMetric) + "[1h])) > 0";
    CHECK(alerts.find("alert: YuzuCryptoLayoutEraseFailed") != std::string::npos);
    CHECK(alerts.find(expr) != std::string::npos);
}
