// ProductRegistryStore tests (ADR-0024 Decision 4/6): the born-on-Postgres
// canonical product registry — migration-at-construction, norm_key-keyed
// product upserts, alias links (upsert/resolve, first_matched_at semantics,
// FK cascade), and the authoritative-read posture (nullopt/kDegraded on a
// degrade, never a silent empty).

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "product_registry_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::ProductRegistryStore;
using yuzu::server::RegistryReadError;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// ── Shared pre-migrated fixture (behaviour-preserving DB-provisioning swap) ──
// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between tests instead of a fresh CREATE DATABASE + new pool per test (see
// test_software_inventory_store.cpp for the rationale). RESTART IDENTITY matters
// here — product_id is a minted sequence, so a reset must rewind it too.
// Behaviour-preserving: identical store calls + CHECKs; only the DB
// provisioning/isolation changes. At testRunEnded the pool is drained before
// the clone is dropped, leaving static destruction inert. CARVE-OUTS that DROP
// SCHEMA / wipe public.schema_meta are NOT converted — TRUNCATE cannot undo that
// DDL, so they keep their own per-test database (YUZU_REQUIRE_PG_DB).
yuzu::test::PgTestTemplate prod_tpl{"prodreg", [](const std::string& dsn) {
                                        PgPool pool{{.conninfo = dsn, .size = 1}};
                                        ProductRegistryStore store{pool};
                                        if (!store.is_open())
                                            throw std::runtime_error(
                                                "prodreg template: store failed to migrate");
                                    }};

struct ProdShared {
    yuzu::test::PostgresTestDb db{prod_tpl};
    std::optional<PgPool> pool;
    ProdShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
ProdShared& prod_shared() {
    static ProdShared s;
    return s;
}

// TRUNCATE both tables (RESTART IDENTITY rewinds the product_id sequence, CASCADE
// clears the FK-linked aliases); public.schema_meta is untouched so the per-test
// store ctor finds the clone migrated and skips migration.
void prod_reset() {
    auto lease = prod_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = pg::exec_params(lease.get(),
                                 "TRUNCATE product_registry_store.products, "
                                 "product_registry_store.product_aliases RESTART IDENTITY CASCADE",
                                 std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define PROD_SHARED(store, pool)                                                                   \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    prod_reset();                                                                                  \
    [[maybe_unused]] PgPool& pool = *prod_shared().pool;                                           \
    ProductRegistryStore store{pool};                                                              \
    REQUIRE(store.is_open())

} // namespace

TEST_CASE("ProductRegistryStore migrates at construction and reopens idempotently",
          "[pg][product_registry]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        ProductRegistryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    // A second construction against the already-migrated schema is a no-op
    // (versioned runner) — not a DDL re-run failure.
    ProductRegistryStore s2{pool};
    CHECK(s2.is_open());
    auto n = s2.count_products();
    REQUIRE(n.has_value());
    CHECK(*n == 0);
}

TEST_CASE("ProductRegistryStore upsert_product mints, is idempotent by norm_key, and refreshes",
          "[pg][product_registry]") {
    PROD_SHARED(store, pool);

    auto id1 = store.upsert_product("microsoft:sql server:standard", "microsoft", "sql server",
                                    "standard", "windows");
    REQUIRE(id1.has_value());
    CHECK(*id1 > 0);

    SECTION("the same norm_key returns the SAME id and refreshes the row") {
        auto id2 = store.upsert_product("microsoft:sql server:standard", "microsoft corp",
                                        "sql server db", "standard", "windows");
        REQUIRE(id2.has_value());
        CHECK(*id2 == *id1); // no duplicate row minted
        auto got = store.get_product("microsoft:sql server:standard");
        REQUIRE(got.has_value());  // not degraded
        REQUIRE(got->has_value()); // found
        CHECK((*got)->product_id == *id1);
        CHECK((*got)->vendor == "microsoft corp"); // refreshed
        CHECK((*got)->title == "sql server db");
        CHECK((*got)->edition == "standard");
        CHECK((*got)->platform == "windows");
        CHECK((*got)->created_at > 0);                   // seeded on insert
        CHECK((*got)->updated_at >= (*got)->created_at); // refreshed on conflict
    }

    SECTION("a different norm_key mints a different id; list is norm_key-sorted") {
        auto id2 = store.upsert_product("adobe:acrobat", "adobe", "acrobat", "", "");
        REQUIRE(id2.has_value());
        CHECK(*id2 != *id1);
        auto all = store.list_products(100);
        REQUIRE(all.has_value());
        REQUIRE(all->size() == 2);
        CHECK((*all)[0].norm_key == "adobe:acrobat");
        CHECK((*all)[1].norm_key == "microsoft:sql server:standard");
        auto n = store.count_products();
        REQUIRE(n.has_value());
        CHECK(*n == 2);
    }

    SECTION("an empty norm_key is a precondition miss → nullopt, no row") {
        CHECK_FALSE(store.upsert_product("", "v", "t", "", "").has_value());
        auto n = store.count_products();
        REQUIRE(n.has_value());
        CHECK(*n == 1);
    }
}

TEST_CASE("ProductRegistryStore alias upsert/resolve round-trip + re-point semantics",
          "[pg][product_registry]") {
    PROD_SHARED(store, pool);

    auto pid_a = store.upsert_product("acme:reader", "acme", "reader", "", "");
    auto pid_b = store.upsert_product("acme:reader:pro", "acme", "reader", "pro", "");
    REQUIRE(pid_a.has_value());
    REQUIRE(pid_b.has_value());

    SECTION("resolve on a cold registry → absent value (a miss, not a degrade)") {
        auto r = store.resolve_alias("software_licensing", "Acme Reader", "Acme Inc.");
        REQUIRE(r.has_value());      // read succeeded
        CHECK_FALSE(r->has_value()); // no link yet → the matcher should run
    }

    SECTION("upsert then resolve returns the linked product_id") {
        REQUIRE(store.upsert_alias("software_licensing", "Acme Reader", "Acme Inc.", *pid_a,
                                   "exact_norm", 1.0));
        auto r = store.resolve_alias("software_licensing", "Acme Reader", "Acme Inc.");
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        CHECK(**r == *pid_a);

        // The triple is the key: a different raw_publisher is a DIFFERENT link.
        auto other = store.resolve_alias("software_licensing", "Acme Reader", "Other Corp");
        REQUIRE(other.has_value());
        CHECK_FALSE(other->has_value());
    }

    SECTION("re-upsert re-points the link, keeps first_matched_at, bumps last_seen_at") {
        REQUIRE(store.upsert_alias("software_licensing", "Acme Reader", "Acme Inc.", *pid_a,
                                   "token_set", 0.8));
        // Backdate the stored timestamps so the refresh is observable without
        // sleeping (there is no clock seam on the store — go direct, the
        // sibling-suite precedent).
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult upd = pg::exec_params(
                lease.get(),
                "UPDATE product_registry_store.product_aliases "
                "SET first_matched_at = 1000, last_seen_at = 1000 WHERE raw_name = $1",
                std::vector<std::string>{"Acme Reader"});
            REQUIRE(upd.status() == PGRES_COMMAND_OK);
        }
        REQUIRE(store.upsert_alias("software_licensing", "Acme Reader", "Acme Inc.", *pid_b,
                                   "exact_norm", 1.0));
        auto r = store.resolve_alias("software_licensing", "Acme Reader", "Acme Inc.");
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        CHECK(**r == *pid_b); // re-pointed
        auto links = store.list_aliases(*pid_b);
        REQUIRE(links.has_value());
        REQUIRE(links->size() == 1);
        CHECK((*links)[0].method == "exact_norm");
        CHECK((*links)[0].confidence == 1.0);
        CHECK((*links)[0].first_matched_at == 1000); // preserved across the re-upsert
        CHECK((*links)[0].last_seen_at > 1000);      // refreshed
        // The old target no longer lists the link.
        auto old_links = store.list_aliases(*pid_a);
        REQUIRE(old_links.has_value());
        CHECK(old_links->empty());
    }

    SECTION("a dangling product_id fails the FK and returns false (fail-soft, no throw)") {
        CHECK_FALSE(store.upsert_alias("software_licensing", "Ghost", "Ghost Corp", 999999,
                                       "exact_norm", 1.0));
        auto r = store.resolve_alias("software_licensing", "Ghost", "Ghost Corp");
        REQUIRE(r.has_value());
        CHECK_FALSE(r->has_value()); // nothing stored
    }

    SECTION("deleting a product cascades its aliases (FK ON DELETE CASCADE)") {
        REQUIRE(store.upsert_alias("software_licensing", "Acme Reader", "Acme Inc.", *pid_a,
                                   "exact_norm", 1.0));
        REQUIRE(store.upsert_alias("installed_software", "Acme Reader 11", "Acme Inc.", *pid_a,
                                   "title_vendor", 0.9));
        auto n = store.count_aliases();
        REQUIRE(n.has_value());
        CHECK(*n == 2);
        { // curate the product away (no store-level delete API — direct SQL)
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult del = pg::exec_params(
                lease.get(),
                "DELETE FROM product_registry_store.products WHERE product_id = $1::bigint",
                std::vector<std::string>{std::to_string(*pid_a)});
            REQUIRE(del.status() == PGRES_COMMAND_OK);
        }
        auto after = store.count_aliases();
        REQUIRE(after.has_value());
        CHECK(*after == 0); // both links cascaded away
        auto r = store.resolve_alias("software_licensing", "Acme Reader", "Acme Inc.");
        REQUIRE(r.has_value());
        CHECK_FALSE(r->has_value());
    }
}

TEST_CASE("ProductRegistryStore reads are AUTHORITATIVE: degrade ≠ empty, and writes fail soft",
          "[pg][product_registry]") {
    YUZU_REQUIRE_PG_DB_TPL(db, prod_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ProductRegistryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    auto pid = store.upsert_product("acme:reader", "acme", "reader", "", "");
    REQUIRE(pid.has_value());

    SECTION("genuine zero-row reads are empty VALUES / absent, not degrades") {
        auto got = store.get_product("no:such:product");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
        auto links = store.list_aliases(*pid);
        REQUIRE(links.has_value());
        CHECK(links->empty());
        // Precondition misses are absent/empty too — not degrades.
        auto empty_key = store.get_product("");
        REQUIRE(empty_key.has_value());
        CHECK_FALSE(empty_key->has_value());
        auto bad_id = store.list_aliases(0);
        REQUIRE(bad_id.has_value());
        CHECK(bad_id->empty());
    }

    SECTION("a backend failure (schema dropped) degrades every read — never a silent empty") {
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult drop =
                pg::exec_params(lease.get(), "DROP SCHEMA product_registry_store CASCADE",
                                std::vector<std::string>{});
            REQUIRE(drop.status() == PGRES_COMMAND_OK);
        }
        auto got = store.get_product("acme:reader");
        REQUIRE_FALSE(got.has_value());
        CHECK(got.error() == RegistryReadError::kDegraded);
        auto r = store.resolve_alias("software_licensing", "Acme Reader", "Acme Inc.");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == RegistryReadError::kDegraded);
        CHECK_FALSE(store.list_products(100).has_value());
        CHECK_FALSE(store.list_aliases(*pid).has_value());
        CHECK_FALSE(store.count_products().has_value());
        CHECK_FALSE(store.count_aliases().has_value());
        // Writes fail SOFT: false/nullopt, never a throw across the API.
        CHECK_FALSE(store.upsert_product("acme:reader", "acme", "reader", "", "").has_value());
        CHECK_FALSE(store.upsert_alias("software_licensing", "Acme Reader", "Acme Inc.", *pid,
                                       "exact_norm", 1.0));
        // The shared read-degrade counter carries the registry source label
        // (#1675 convention) — 4 sampled reads above hit the query_error path
        // (the expected-returning reads + the two lists; counts log unsampled).
        CHECK(metrics
                  .counter("yuzu_inventory_read_degrade_total",
                           {{"reason", "query_error"}, {"source", "product_registry"}})
                  .value() == 4.0);
    }
}

TEST_CASE("ProductRegistryStore store_not_open: constructor failure degrades reads, is_open false",
          "[pg][product_registry]") {
    // Force open_=false via the sibling-suite recipe: wipe the schema_meta
    // version record so a fresh construction re-runs v1 DDL over the live
    // tables → migration fails → !is_open(), and every authoritative read
    // degrades (store_not_open reason).
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        ProductRegistryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult del = pg::exec_params(
            lease.get(), "DELETE FROM public.schema_meta WHERE store = 'product_registry_store'",
            std::vector<std::string>{});
        REQUIRE(del.status() == PGRES_COMMAND_OK);
    }
    ProductRegistryStore store{pool};
    REQUIRE_FALSE(store.is_open());
    CHECK_FALSE(store.list_products(10).has_value());
    CHECK_FALSE(store.get_product("x").has_value());
    CHECK_FALSE(store.resolve_alias("s", "n", "p").has_value());
    CHECK_FALSE(store.upsert_product("k", "v", "t", "", "").has_value());
    CHECK_FALSE(store.upsert_alias("s", "n", "p", 1, "m", 1.0));
    CHECK_FALSE(store.count_products().has_value());
}
