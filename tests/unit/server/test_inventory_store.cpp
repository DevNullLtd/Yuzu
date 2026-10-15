// InventoryStore tests (ADR-0037): the generic per-source blob store's
// Postgres migration. Covers the authoritative read contract (degrade vs
// genuinely-absent vs found/empty), fail-soft ingest, delete_agent's
// empty-id guard, and the Postgres schema-migration-runner upgrade path
// (published v2 -> v5, repairing an incomplete v3 state, then dropping
// backfill_state at v5).
//
// No legacy-SQLite backfill test coverage: `InventoryStore::migrate_from_sqlite()` itself was
// retired (chore/retire-migrate-from-sqlite-batch-a, #3623, ADR-0037 Update, 2026-09-03) -- no
// production fleet has ever run a pre-Postgres build, so the one-time first-boot backfill never
// had real legacy data to protect. `server.cpp` now runs `legacy_sqlite_probe::warn_if_legacy_rows`
// over `inventory_data` instead. `delete_agent` no longer erases anything from a legacy file
// either; the kept schema-migration-runner test below now asserts `backfill_state`'s ABSENCE at
// v5 instead of using migrate_from_sqlite as a stamp mechanism.

#include <catch2/catch_test_macros.hpp>

#include "inventory_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using yuzu::server::InventoryQuery;
using yuzu::server::InventoryRecord;
using yuzu::server::InventoryStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// store-behaviour test clones an already-migrated database instead of
// re-running the migrations.
yuzu::test::PgTestTemplate inventory_tpl{"inventory", [](const std::string& dsn) {
                                             PgPool pool{{.conninfo = dsn, .size = 1}};
                                             InventoryStore store{pool};
                                             if (!store.is_open())
                                                 throw std::runtime_error(
                                                     "inventory template: store failed to migrate");
                                         }};

// One migrated clone and persistent pool for this file. Every case resets both
// mutable tables, avoiding repeated CREATE DATABASE and backend startup costs
// on the contended [pg] shard while preserving case isolation.
struct InventoryShared {
    yuzu::test::PostgresTestDb db{inventory_tpl};
    std::optional<PgPool> pool;
    InventoryShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};

InventoryShared& inventory_shared() {
    static InventoryShared shared;
    return shared;
}

void inventory_reset() {
    auto lease = inventory_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc =
        pg::exec_params(lease.get(),
                        "TRUNCATE inventory_store.inventory_data RESTART IDENTITY CASCADE",
                        std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define INVENTORY_SHARED(store, pool)                                                              \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    inventory_reset();                                                                             \
    [[maybe_unused]] PgPool& pool = *inventory_shared().pool;                                      \
    InventoryStore store{pool};                                                                    \
    REQUIRE(store.is_open())

// Wall-clock now, mirroring the store's internal `now_secs()` — used only to
// bound assertions on the store's own clamping, never to construct fixture
// data that would itself need clamping.
std::int64_t test_now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

TEST_CASE("InventoryStore degrades (not empty) on a broken pool", "[inventory]") {
    // No live PG needed: an unreachable conninfo → the store never opens, and
    // every read reports a degrade, never a silent empty.
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1 dbname=x user=x", .size = 1}};
    InventoryStore store{pool};
    REQUIRE(!store.is_open());

    CHECK(!store.list_tables().has_value());
    CHECK(!store.query({}).has_value());
    CHECK(!store.get_agent_inventory("a").has_value());
    CHECK(!store.count().has_value());

    // Governance M1: the `truncated` out-param must be reset on the early
    // degrade return, not left at whatever the caller pre-set it to — a
    // stale `true` here would wrongly tell a from-inventory-query caller
    // "capped, refuse to materialise" on top of the already-reported degrade.
    bool truncated = true;
    CHECK(!store.query({}, &truncated).has_value());
    CHECK_FALSE(truncated);
    auto g = store.get("a", "p");
    CHECK(!g.has_value());
    CHECK(g.error() == yuzu::server::InventoryReadError::kDegraded);
    CHECK_FALSE(store.delete_agent("a"));       // ingest/delete: fail-soft, false, no crash
    CHECK_FALSE(store.delete_source("app_usage")); // same, keyed on plugin instead of agent
    store.upsert("a", "p", "{}", 1);            // fail-soft: does not throw
}

TEST_CASE("InventoryStore upsert/get/query/list_tables/count round-trip", "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    store.upsert("agent-1", "installed_software", R"({"n":1})", 1000);
    store.upsert("agent-1", "device_ci", R"({"n":2})", 1000);
    store.upsert("agent-2", "installed_software", R"({"n":3})", 2000);

    SECTION("get: found, absent, degrade-free") {
        auto found = store.get("agent-1", "installed_software");
        REQUIRE(found.has_value());
        REQUIRE(found->has_value());
        CHECK((*found)->data_json == R"({"n":1})");
        CHECK((*found)->collected_at == 1000);

        auto absent = store.get("agent-1", "no-such-plugin");
        REQUIRE(absent.has_value());      // not a degrade
        CHECK_FALSE(absent->has_value()); // genuinely no row
    }

    SECTION("upsert replaces an existing (agent_id, plugin) row") {
        store.upsert("agent-1", "installed_software", R"({"n":99})", 5000);
        auto found = store.get("agent-1", "installed_software");
        REQUIRE(found.has_value());
        REQUIRE(found->has_value());
        CHECK((*found)->data_json == R"({"n":99})");
        CHECK((*found)->collected_at == 5000);
    }

    SECTION("query filters by agent_id and plugin") {
        InventoryQuery q;
        q.agent_id = "agent-1";
        auto by_agent = store.query(q);
        REQUIRE(by_agent.has_value());
        CHECK(by_agent->size() == 2);

        InventoryQuery q2;
        q2.plugin = "installed_software";
        auto by_plugin = store.query(q2);
        REQUIRE(by_plugin.has_value());
        CHECK(by_plugin->size() == 2);
    }

    SECTION("get_agent_inventory returns all of one agent's rows") {
        auto rows = store.get_agent_inventory("agent-1");
        REQUIRE(rows.has_value());
        CHECK(rows->size() == 2);
    }

    SECTION("list_tables aggregates per-plugin agent counts") {
        auto tables = store.list_tables();
        REQUIRE(tables.has_value());
        bool found_installed = false;
        for (const auto& t : *tables) {
            if (t.plugin == "installed_software") {
                found_installed = true;
                CHECK(t.agent_count == 2); // agent-1 + agent-2
            }
        }
        CHECK(found_installed);
    }

    SECTION("count reflects total rows") {
        auto c = store.count();
        REQUIRE(c.has_value());
        CHECK(*c == 3);
    }

    SECTION("upsert rejects a blank agent_id/plugin (GDPR orphan guard, IS5/UP-7)") {
        store.upsert("", "installed_software", R"({"x":1})", 1000);
        store.upsert("agent-blank-plugin", "  ", R"({"x":1})", 1000);
        auto blank_id = store.get("", "installed_software");
        REQUIRE(blank_id.has_value());
        CHECK_FALSE(blank_id->has_value()); // never written
        auto blank_plugin = store.get_agent_inventory("agent-blank-plugin");
        REQUIRE(blank_plugin.has_value());
        CHECK(blank_plugin->empty());
    }

    SECTION("upsert never lets an older report overwrite a newer row (stale guard, IS6/UP-8)") {
        // agent-1/installed_software is already seeded at collected_at=1000.
        store.upsert("agent-1", "installed_software", R"({"n":"older"})", 500); // older: rejected
        auto after_older = store.get("agent-1", "installed_software");
        REQUIRE(after_older.has_value());
        REQUIRE(after_older->has_value());
        CHECK((*after_older)->data_json == R"({"n":1})");
        CHECK((*after_older)->collected_at == 1000);

        store.upsert("agent-1", "installed_software", R"({"n":"same-instant"})",
                     1000); // equal: still updates
        auto after_equal = store.get("agent-1", "installed_software");
        REQUIRE(after_equal.has_value());
        REQUIRE(after_equal->has_value());
        CHECK((*after_equal)->data_json == R"({"n":"same-instant"})");

        store.upsert("agent-1", "installed_software", R"({"n":"newer"})", 2000); // newer: updates
        auto after_newer = store.get("agent-1", "installed_software");
        REQUIRE(after_newer.has_value());
        REQUIRE(after_newer->has_value());
        CHECK((*after_newer)->data_json == R"({"n":"newer"})");
        CHECK((*after_newer)->collected_at == 2000);
    }

    SECTION("delete_agent: empty-id guard, commit status, idempotent") {
        CHECK_FALSE(store.delete_agent(""));
        auto still_there = store.get_agent_inventory("agent-1");
        REQUIRE(still_there.has_value());
        CHECK(still_there->size() == 2);

        CHECK(store.delete_agent("agent-1"));
        auto gone = store.get_agent_inventory("agent-1");
        REQUIRE(gone.has_value());
        CHECK(gone->empty());

        // Idempotent: a 0-row delete of an already-erased agent still commits.
        CHECK(store.delete_agent("agent-1"));

        // The bystander is untouched.
        auto bystander = store.get_agent_inventory("agent-2");
        REQUIRE(bystander.has_value());
        CHECK(bystander->size() == 1);
    }
}

TEST_CASE("InventoryStore delete_source erases one plugin across all agents, leaves others intact",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    store.upsert("agent-1", "app_usage", R"({"n":1})", 1000);
    store.upsert("agent-2", "app_usage", R"({"n":2})", 1000);
    store.upsert("agent-1", "installed_software", R"({"n":3})", 1000);

    CHECK(store.delete_source("app_usage"));

    auto agent1 = store.get_agent_inventory("agent-1");
    REQUIRE(agent1.has_value());
    CHECK(agent1->size() == 1);
    CHECK((*agent1)[0].plugin == "installed_software");

    auto agent2 = store.get_agent_inventory("agent-2");
    REQUIRE(agent2.has_value());
    CHECK(agent2->empty());

    CHECK_FALSE(store.delete_source("")); // empty-name guard

    // Idempotent: a 0-row delete of an already-purged source still commits.
    CHECK(store.delete_source("app_usage"));
}

TEST_CASE("InventoryStore upsert clamps a far-future collected_at to server receipt "
          "time and does not freeze the row (H2)",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    const std::int64_t now_before = test_now_secs();
    const std::int64_t far_future = now_before + 10'000'000;

    store.upsert("agent-clamp", "installed_software", R"({"n":1})", far_future);
    const std::int64_t now_after = test_now_secs();

    // Read via both single-record `get` and the list-shaped
    // `get_agent_inventory` — the clamp must hold on both read paths.
    auto found = store.get("agent-clamp", "installed_software");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->data_json == R"({"n":1})");
    CHECK((*found)->collected_at >= now_before);
    CHECK((*found)->collected_at <= now_after); // clamped, NOT the far-future value supplied

    auto rows = store.get_agent_inventory("agent-clamp");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().collected_at <= now_after);

    // The pre-clamp defect: a future-skewed row pinned itself forever because
    // every later HONEST report failed the stale-overwrite conflict
    // predicate (its real collected_at could never reach the far-future
    // stored value). With the clamp, an honest report at ~now for the same
    // (agent, plugin) must still land.
    store.upsert("agent-clamp", "installed_software", R"({"n":2})", 0 /* now */);
    auto landed = store.get("agent-clamp", "installed_software");
    REQUIRE(landed.has_value());
    REQUIRE(landed->has_value());
    CHECK((*landed)->data_json == R"({"n":2})"); // lands — the regression net for the freeze bug
}

TEST_CASE("InventoryStore upsert: an older report after a fresh one is suppressed and "
          "counted stale (H2 observability)",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    store.upsert("agent-stale", "installed_software", R"({"n":"fresh"})", 10'000); // T
    store.upsert("agent-stale", "installed_software", R"({"n":"older"})", 9'900); // T-100: rejected

    auto row = store.get("agent-stale", "installed_software");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->data_json == R"({"n":"fresh"})"); // unchanged
    CHECK((*row)->collected_at == 10'000);

    CHECK(metrics.counter("yuzu_inventory_ingest_dropped_total", {{"reason", "stale"}}).value() ==
          1.0);
}

TEST_CASE("InventoryStore query: the truncated out-param signals a capped read (M1)",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    store.upsert("agent-t1", "installed_software", R"({"n":1})", 1000);
    store.upsert("agent-t2", "installed_software", R"({"n":2})", 2000);
    store.upsert("agent-t3", "installed_software", R"({"n":3})", 3000);

    SECTION("limit below the row count returns the cap and sets truncated=true") {
        InventoryQuery q;
        q.limit = 2;
        bool truncated = false;
        auto rows = store.query(q, &truncated);
        REQUIRE(rows.has_value());
        CHECK(rows->size() == 2);
        CHECK(truncated);
    }

    SECTION("limit at/above the row count returns everything and resets truncated=false") {
        InventoryQuery q;
        q.limit = 5;
        bool truncated = true; // pre-set true to prove query() resets it, not just leaves it
        auto rows = store.query(q, &truncated);
        REQUIRE(rows.has_value());
        CHECK(rows->size() == 3);
        CHECK_FALSE(truncated);
    }
}

TEST_CASE("InventoryStore query: aggregate blob bytes are bounded before libpq materialises them",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto seeded =
        pg::exec_params(lease.get(),
                        "INSERT INTO inventory_store.inventory_data "
                        "(agent_id, plugin, data_json, collected_at) "
                        "SELECT 'byte-agent-' || g, 'custom_large', repeat('x', 3145728), g "
                        "FROM generate_series(1, 3) AS g",
                        std::vector<std::string>{});
    REQUIRE(seeded.status() == PGRES_COMMAND_OK);
    lease.reset();

    InventoryQuery q;
    q.limit = 10;
    bool truncated = false;
    auto rows = store.query(q, &truncated);
    REQUIRE(rows.has_value());
    CHECK(truncated);
    CHECK(rows->size() == 2);
}

TEST_CASE("InventoryStore migration upgrades published v2 and repairs the incomplete v3 state, "
          "then drops backfill_state at v5",
          "[pg][inventory][migration]") {
    // Migration tests deliberately use one private database rather than the
    // pre-migrated shared fixture: both scenarios rewrite schema_meta and DDL.
    // Reusing that one database keeps this regression cheap on the [pg] shard.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());

    const auto seed_historical_schema = [&](int version) {
        auto lease = pool.acquire();
        REQUIRE(lease);
        const auto exec = [&](const char* sql) {
            auto result = pg::exec_params(lease.get(), sql, std::vector<std::string>{});
            REQUIRE(result.status() == PGRES_COMMAND_OK);
        };

        exec("CREATE TABLE IF NOT EXISTS public.schema_meta ("
             "store TEXT PRIMARY KEY, version INTEGER NOT NULL, upgraded_at BIGINT NOT NULL)");
        exec("CREATE SCHEMA inventory_store");
        exec("CREATE TABLE inventory_store.inventory_data ("
             "agent_id TEXT NOT NULL, plugin TEXT NOT NULL, data_json TEXT NOT NULL DEFAULT '{}', "
             "collected_at BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (agent_id, plugin))");
        exec("CREATE INDEX inventory_data_plugin_idx "
             "ON inventory_store.inventory_data (plugin)");
        exec("CREATE INDEX inventory_data_collected_idx "
             "ON inventory_store.inventory_data (collected_at)");
        // Exact backfill_state shape published by v2 at 55ba45d8.
        exec("CREATE TABLE inventory_store.backfill_state ("
             "id INT PRIMARY KEY, migrated_at BIGINT NOT NULL, "
             "legacy_rows BIGINT NOT NULL DEFAULT 0)");
        if (version == 3) {
            // c21e330b can commit this v3 before the later stamp fails because
            // skipped_bad is absent. V4 must repair that already-recorded state.
            exec("ALTER TABLE inventory_store.backfill_state "
                 "ADD COLUMN source_rows BIGINT NOT NULL DEFAULT 0, "
                 "ADD COLUMN conflicts BIGINT NOT NULL DEFAULT 0, "
                 "ADD COLUMN skipped_blank_key BIGINT NOT NULL DEFAULT 0, "
                 "ADD COLUMN skipped_typed BIGINT NOT NULL DEFAULT 0");
        }
        auto meta = pg::exec_params(lease.get(),
                                    "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                                    "VALUES ('inventory_store', $1::int, 0)",
                                    std::vector<std::string>{std::to_string(version)});
        REQUIRE(meta.status() == PGRES_COMMAND_OK);
    };

    // Construction alone now drives the full upgrade — migrate_from_sqlite (the previous
    // mechanism used here purely to trigger PgMigrationRunner::run a second time) was
    // retired (#3623); the migration ladder runs entirely inside the constructor.
    const auto require_upgrade = [&] {
        InventoryStore store{pool};
        REQUIRE(store.is_open());

        auto lease = pool.acquire();
        REQUIRE(lease);
        auto ver = pg::exec_params(
            lease.get(), "SELECT version FROM public.schema_meta WHERE store = 'inventory_store'",
            std::vector<std::string>{});
        REQUIRE(ver.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(ver.get()) == 1);
        CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "5");

        // v5 drops backfill_state (its sole writer, migrate_from_sqlite, is gone) — assert
        // absence rather than the pre-retirement id=1 row-presence check.
        auto tbl = pg::exec_params(
            lease.get(),
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = 'inventory_store' AND table_name = 'backfill_state'",
            std::vector<std::string>{});
        REQUIRE(tbl.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(tbl.get(), 0, 0)) == "0");
    };

    seed_historical_schema(2);
    require_upgrade();

    // Reuse the same ephemeral database for the second historical state. The
    // store and all leases above are already out of scope, so no session owns
    // an object in the schema while it is replaced.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto drop = pg::exec_params(lease.get(), "DROP SCHEMA inventory_store CASCADE",
                                    std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
        auto forget = pg::exec_params(
            lease.get(), "DELETE FROM public.schema_meta WHERE store = 'inventory_store'",
            std::vector<std::string>{});
        REQUIRE(forget.status() == PGRES_COMMAND_OK);
    }

    seed_historical_schema(3);
    require_upgrade();
}
