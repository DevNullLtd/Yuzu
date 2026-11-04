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
#include "software_normalization_pack.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
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
                                 "product_registry_store.product_aliases, "
                                 "product_registry_store.normalization_pack, "
                                 "product_registry_store.title_dimension, "
                                 "product_registry_store.curation_queue "
                                 "RESTART IDENTITY CASCADE",
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

// ── SAM.4 (schema v2): normalisation pack, title dimension, curation queue ───────────

namespace {
yuzu::server::ParsedPack seed_pack() {
    auto p = yuzu::server::parse_normalization_pack(yuzu::server::kSoftwareNormalizationSeed);
    REQUIRE(p.has_value());
    return std::move(*p);
}
} // namespace

TEST_CASE("existing writers keep working after v2 and pick up the new column defaults",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    const auto id = store.upsert_product("acme:widget", "acme", "widget", "", "");
    REQUIRE(id.has_value());
    auto row = store.get_product("acme:widget");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->origin == "matcher");
    CHECK((*row)->category == "other");
    CHECK((*row)->purl_type.empty());
}

TEST_CASE("load_pack_if_empty loads the pack products and aliases once and reports "
          "already_present on the second call",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    const auto pack = seed_pack();
    auto first = store.load_pack_if_empty(pack, "seed");
    REQUIRE(first.has_value());
    CHECK(*first == yuzu::server::PackLoadOutcome::loaded);
    const auto products = store.count_products();
    const auto aliases = store.count_aliases();
    REQUIRE(products.has_value());
    REQUIRE(aliases.has_value());
    CHECK(*products > 0);
    CHECK(*aliases == static_cast<std::int64_t>(pack.rows.size()));

    auto second = store.load_pack_if_empty(pack, "seed");
    REQUIRE(second.has_value());
    CHECK(*second == yuzu::server::PackLoadOutcome::already_present);
    CHECK(*store.count_products() == *products);
    CHECK(*store.count_aliases() == *aliases);

    // Pack products carry origin 'pack' and the row's category / cpe_product.
    auto pg_row = store.get_product("postgresql:postgresql");
    REQUIRE(pg_row.has_value());
    REQUIRE(pg_row->has_value());
    CHECK((*pg_row)->origin == "pack");
    CHECK((*pg_row)->category == "database");
    CHECK((*pg_row)->cpe_product == "postgresql");
}

TEST_CASE("read_normalization_aliases returns pack and curated rows for the requested alias keys "
          "and exact sources only",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    REQUIRE(store.load_pack_if_empty(seed_pack(), "seed").has_value());
    const auto pid = store.upsert_product("acme:widget", "acme", "widget", "", "");
    REQUIRE(pid.has_value());
    REQUIRE(store.upsert_alias("curated:windows", "7-zip", "", *pid, "curated", 1.0));
    // A matcher link on the same raw name must NOT be returned.
    REQUIRE(store.upsert_alias("installed_software", "7-zip", "", *pid, "exact_norm", 1.0));

    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    const std::vector<std::string_view> keys{"7-zip", "no such key"};
    const std::vector<std::string_view> sources{"pack:windows", "curated:windows", "pack:",
                                                "curated:"};
    auto rows = ProductRegistryStore::read_normalization_aliases(lease.get(), keys, sources);
    REQUIRE(rows.has_value());
    bool pack_row = false, curated_row = false;
    for (const auto& r : *rows) {
        CHECK(r.raw_name == "7-zip");
        CHECK((r.source.starts_with("pack:") || r.source.starts_with("curated:")));
        pack_row = pack_row || r.source == "pack:windows";
        curated_row = curated_row || r.source == "curated:windows";
        if (r.source == "pack:windows") {
            CHECK(r.product.vendor == "igor pavlov");
            CHECK(r.product.cpe_product == "7-zip");
        }
    }
    CHECK(pack_row);
    CHECK(curated_row);
    CHECK(rows->size() == 2);
    // The source filter is an EXACT match: another ecosystem's source, or the empty list, reads
    // nothing, and a single source reads only that tier.
    auto other_eco = ProductRegistryStore::read_normalization_aliases(
        lease.get(), keys, std::vector<std::string_view>{"pack:macos", "curated:macos"});
    REQUIRE(other_eco.has_value());
    CHECK(other_eco->empty());
    auto only_pack = ProductRegistryStore::read_normalization_aliases(
        lease.get(), keys, std::vector<std::string_view>{"pack:windows"});
    REQUIRE(only_pack.has_value());
    REQUIRE(only_pack->size() == 1);
    CHECK((*only_pack)[0].source == "pack:windows");
    auto no_sources = ProductRegistryStore::read_normalization_aliases(lease.get(), keys, {});
    REQUIRE(no_sources.has_value());
    CHECK(no_sources->empty());
    auto none = ProductRegistryStore::read_normalization_aliases(lease.get(), {}, sources);
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("read_products_by_norm_key returns exactly the products with the requested keys",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    REQUIRE(store.load_pack_if_empty(seed_pack(), "seed").has_value());
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    const std::vector<std::string_view> keys{"postgresql:postgresql", "no such:key"};
    auto rows = ProductRegistryStore::read_products_by_norm_key(lease.get(), keys);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].norm_key == "postgresql:postgresql");
    CHECK((*rows)[0].category == "database");
    CHECK((*rows)[0].cpe_product == "postgresql");
    CHECK((*rows)[0].origin == "pack");
    auto none = ProductRegistryStore::read_products_by_norm_key(lease.get(), {});
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("the v2 migration upgrades populated v1 rows with the matcher defaults and leaves them "
          "out of the normalisation read",
          "[pg][product_registry][normalization]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        ProductRegistryStore fresh{pool};
        REQUIRE(fresh.is_open());
    }
    const auto exec = [&](const char* stmt) {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(lease.get(), stmt, std::vector<std::string>{});
        CAPTURE(stmt);
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    };
    // Stage the v1 shape by hand (drop everything v2 added), populate it the way v1 writers did,
    // then rewind schema_meta so the next construction runs the v2 step over live rows.
    exec("DROP TABLE product_registry_store.title_dimension");
    exec("DROP TABLE product_registry_store.curation_queue");
    exec("DROP TABLE product_registry_store.normalization_pack");
    exec("ALTER TABLE product_registry_store.products DROP COLUMN purl_type, DROP COLUMN "
         "cpe_product, DROP COLUMN origin, DROP COLUMN category");
    exec("ALTER TABLE product_registry_store.product_aliases DROP COLUMN status, DROP COLUMN "
         "pack_version");
    exec("INSERT INTO product_registry_store.products (norm_key, vendor, title, edition, platform, "
         "created_at, updated_at) VALUES ('acme:widget', 'acme', 'widget', '', '', 11, 12)");
    exec("INSERT INTO product_registry_store.product_aliases (source, raw_name, raw_publisher, "
         "product_id, method, confidence, first_matched_at, last_seen_at) "
         "SELECT 'installed_software', 'widget', 'acme', product_id, 'exact_norm', 1.0, 11, 12 "
         "FROM product_registry_store.products WHERE norm_key = 'acme:widget'");
    exec("UPDATE public.schema_meta SET version = 1 WHERE store = 'product_registry_store'");

    ProductRegistryStore store{pool};
    REQUIRE(store.is_open());
    auto row = store.get_product("acme:widget");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->origin == "matcher");
    CHECK((*row)->category == "other");
    CHECK((*row)->purl_type.empty());
    CHECK((*row)->cpe_product.empty());
    CHECK((*row)->created_at == 11); // the v1 values survive untouched
    auto aliases = store.list_aliases((*row)->product_id);
    REQUIRE(aliases.has_value());
    REQUIRE(aliases->size() == 1);
    CHECK((*aliases)[0].status == "active");
    CHECK((*aliases)[0].pack_version.empty());

    // A matcher link is never a normalisation alias, whatever sources are asked for.
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    auto read = ProductRegistryStore::read_normalization_aliases(
        lease.get(), std::vector<std::string_view>{"widget"},
        std::vector<std::string_view>{"pack:", "curated:", "installed_software"});
    REQUIRE(read.has_value());
    CHECK(read->size() == 1); // the matcher link is returned only because its source was NAMED ...
    auto real = ProductRegistryStore::read_normalization_aliases(
        lease.get(), std::vector<std::string_view>{"widget"},
        std::vector<std::string_view>{"pack:", "curated:", "pack:windows", "curated:windows"});
    REQUIRE(real.has_value());
    CHECK(real->empty()); // ... and the sources the title dimension asks for never name it
}

TEST_CASE("ProductRegistryStore reports !is_open when a v2 column is missing although schema_meta "
          "is current",
          "[pg][product_registry][normalization]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        ProductRegistryStore intact{pool};
        REQUIRE(intact.is_open()); // control: the guard must not refuse a healthy schema
    }
    std::vector<std::pair<std::string, std::string>> columns; // (table, column)
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'product_registry_store' ORDER BY table_name, ordinal_position",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        for (int i = 0; i < PQntuples(r.get()); ++i)
            columns.emplace_back(PQgetvalue(r.get(), i, 0), PQgetvalue(r.get(), i, 1));
    }
    for (const char* table : {"products", "product_aliases", "normalization_pack",
                              "title_dimension", "curation_queue"}) {
        CAPTURE(table);
        REQUIRE(std::any_of(columns.begin(), columns.end(),
                            [&](const auto& c) { return c.first == table; }));
    }
    const auto alter = [&](const std::string& stmt) {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(lease.get(), stmt.c_str(), std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    };
    for (const auto& [table, column] : columns) {
        CAPTURE(table, column);
        const std::string prefix =
            "ALTER TABLE product_registry_store.\"" + table + "\" RENAME COLUMN \"";
        alter(prefix + column + "\" TO \"" + column + "_gone\"");
        {
            ProductRegistryStore broken{pool};
            CHECK_FALSE(broken.is_open());
        }
        alter(prefix + column + "_gone\" TO \"" + column + "\"");
        {
            ProductRegistryStore restored{pool};
            CHECK(restored.is_open());
        }
    }
}

TEST_CASE("title_dimension refuses an unknown norm_status or method or category",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    const auto insert = [&](const char* status, const char* method, const char* category) {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO product_registry_store.title_dimension (raw_name, raw_publisher, ecosystem, "
            "norm_status, method, category, pack_version, first_seen_at, updated_at) "
            "VALUES (gen_random_uuid()::text, '', '', $1, $2, $3, '2026.11.1', 1, 1)",
            std::vector<std::string>{status, method, category});
        return r.status() == PGRES_COMMAND_OK;
    };
    CHECK(insert("normalized", "pack", "database"));
    CHECK(insert("unnormalized", "", "other"));
    CHECK_FALSE(insert("maybe", "", "other"));
    CHECK_FALSE(insert("normalized", "guess", "other"));
    CHECK_FALSE(insert("normalized", "pack", "gadget"));
}

// ── SAM-28: curation queue, curate_alias, replace_pack, status ───────────────────────

namespace {

std::string curation_scalar(PgPool& pool, const std::string& sql) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

void curation_exec(PgPool& pool, const std::string& sql) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

void queue_row(PgPool& pool, const std::string& name, const std::string& pub,
               const std::string& eco, int devices, const std::string& status = "open") {
    curation_exec(pool, "INSERT INTO product_registry_store.curation_queue (raw_name, "
                        "raw_publisher, ecosystem, device_count, status, first_queued_at, "
                        "last_seen_at) VALUES ('" + name + "', '" + pub + "', '" + eco + "', " +
                            std::to_string(devices) + ", '" + status + "', 1, 2)");
}

// A fresh pack: the seed with a new version and its last data row dropped.
yuzu::server::ParsedPack next_pack(std::string_view version) {
    std::string csv{yuzu::server::kSoftwareNormalizationSeed};
    const auto v = csv.find("#pack_version:");
    REQUIRE(v != std::string::npos);
    const auto eol = csv.find('\n', v);
    csv.replace(v, eol - v, "#pack_version: " + std::string{version});
    while (!csv.empty() && csv.back() == '\n')
        csv.pop_back();
    csv.erase(csv.rfind('\n') + 1); // drop the last row
    auto p = yuzu::server::parse_normalization_pack(csv);
    REQUIRE(p.has_value());
    return std::move(*p);
}

} // namespace

TEST_CASE("list_curation_queue orders by device_count, filters by status, pages by keyset and caps",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    queue_row(pool, "b", "", "rpm", 5);
    queue_row(pool, "a", "", "rpm", 5);
    queue_row(pool, "z", "", "deb", 9);
    queue_row(pool, "rej", "", "deb", 7, "rejected");

    auto all = store.list_curation_queue("", 10, {});
    REQUIRE(all.has_value());
    REQUIRE(all->rows.size() == 4);
    CHECK_FALSE(all->has_more);
    CHECK(all->rows[0].raw_name == "z");   // 9 devices
    CHECK(all->rows[1].raw_name == "rej"); // 7
    CHECK(all->rows[2].raw_name == "a");   // 5, name ascending
    CHECK(all->rows[3].raw_name == "b");

    auto open = store.list_curation_queue("open", 10, {});
    REQUIRE(open.has_value());
    CHECK(open->rows.size() == 3);
    auto rejected = store.list_curation_queue("rejected", 10, {});
    REQUIRE(rejected.has_value());
    REQUIRE(rejected->rows.size() == 1);
    CHECK(rejected->rows[0].raw_name == "rej");

    // Keyset continuation: two per page, the second page starts after the first's last row.
    auto p1 = store.list_curation_queue("", 2, {});
    REQUIRE(p1.has_value());
    REQUIRE(p1->rows.size() == 2);
    CHECK(p1->has_more);
    const auto& last = p1->rows.back();
    yuzu::server::CurationCursor cur{true, last.device_count, last.raw_name, last.raw_publisher,
                                     last.ecosystem};
    auto p2 = store.list_curation_queue("", 2, cur);
    REQUIRE(p2.has_value());
    REQUIRE(p2->rows.size() == 2);
    CHECK_FALSE(p2->has_more);
    CHECK(p2->rows[0].raw_name == "a");
    CHECK(p2->rows[1].raw_name == "b");

    // The limit is clamped into 1..kCurationQueueMaxLimit, never unbounded or zero.
    auto zero = store.list_curation_queue("", 0, {});
    REQUIRE(zero.has_value());
    CHECK(zero->rows.size() == 1);
    CHECK(zero->has_more);
}

TEST_CASE("reject_curation transitions an open entry once and a later reconcile leaves it rejected",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    queue_row(pool, "x", "p", "rpm", 3);
    // The queue is not a resolution input: a dimension row present BEFORE the reject is untouched.
    curation_exec(pool, "INSERT INTO product_registry_store.title_dimension (raw_name, "
                        "raw_publisher, ecosystem, norm_status, pack_version, first_seen_at, "
                        "updated_at) VALUES ('q', '', 'rpm', 'unnormalized', '2026.11.1', 1, 1)");

    auto first = store.reject_curation("x", "p", "rpm");
    REQUIRE(first.has_value());
    CHECK(*first);
    auto again = store.reject_curation("x", "p", "rpm");
    REQUIRE(again.has_value());
    CHECK_FALSE(*again); // already rejected
    auto absent = store.reject_curation("nope", "", "rpm");
    REQUIRE(absent.has_value());
    CHECK_FALSE(*absent);
    CHECK(curation_scalar(pool, "SELECT status FROM product_registry_store.curation_queue") ==
          "rejected");
    CHECK(store.reject_curation("x", "p", "rpm").has_value());
    CHECK(curation_scalar(pool, "SELECT pack_version FROM "
                                "product_registry_store.title_dimension") == "2026.11.1");
}

TEST_CASE("curate_alias writes a curated product and edition-bearing alias and stales the dimension",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    curation_exec(pool, "INSERT INTO product_registry_store.title_dimension (raw_name, "
                        "raw_publisher, ecosystem, norm_status, pack_version, first_seen_at, "
                        "updated_at) VALUES ('q', '', 'windows', 'unnormalized', '2026.11.1', 1, 1)");

    const auto alias = yuzu::server::derive_curated_alias("windows", "SQL Server 2019 Standard",
                                                          "Microsoft Corporation", "Microsoft",
                                                          "SQL Server", "");
    REQUIRE(alias.has_value());
    auto pid = store.curate_alias("windows", *alias, "database", "sql_server");
    REQUIRE(pid.has_value());
    CHECK(*pid > 0);

    auto prod = store.get_product("microsoft:sql server:standard");
    REQUIRE(prod.has_value());
    REQUIRE(prod->has_value());
    CHECK((*prod)->origin == "curated");
    CHECK((*prod)->category == "database");
    CHECK((*prod)->cpe_product == "sql_server");

    CHECK(alias->source == "curated:windows");
    CHECK(alias->alias_key.ends_with(" standard")); // the edition is in the key, no wildcard
    auto resolved =
        store.resolve_alias(alias->source, alias->alias_key, alias->alias_publisher);
    REQUIRE(resolved.has_value());
    REQUIRE(resolved->has_value());
    CHECK(**resolved == *pid);
    CHECK(curation_scalar(pool, "SELECT method FROM product_registry_store.product_aliases") ==
          "curated");
    // The stale sentinel was written by the same call.
    CHECK(curation_scalar(pool, "SELECT pack_version FROM "
                                "product_registry_store.title_dimension") == "");

    // Re-curating converges on the same product and keeps its cpe_product.
    auto again = store.curate_alias("windows", *alias, "database", "");
    REQUIRE(again.has_value());
    CHECK(*again == *pid);
    CHECK(curation_scalar(pool, "SELECT cpe_product FROM product_registry_store.products "
                                "WHERE product_id = " + std::to_string(*pid)) == "sql_server");
}

TEST_CASE("replace_pack refuses the same version, retires dropped pack aliases and stales the "
          "dimension",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    const auto old_pack = seed_pack();
    REQUIRE(store.load_pack_if_empty(old_pack, "seed").has_value());
    const auto dropped = old_pack.rows.back();

    auto same = store.replace_pack(old_pack, "tester");
    REQUIRE(same.has_value());
    CHECK(*same == yuzu::server::PackReplaceOutcome::same_version);

    curation_exec(pool, "INSERT INTO product_registry_store.title_dimension (raw_name, "
                        "raw_publisher, ecosystem, norm_status, pack_version, first_seen_at, "
                        "updated_at) VALUES ('q', '', 'rpm', 'unnormalized', '" +
                            old_pack.pack_version + "', 1, 1)");
    const auto next = next_pack("2099.12.1");
    auto out = store.replace_pack(next, "tester");
    REQUIRE(out.has_value());
    CHECK(*out == yuzu::server::PackReplaceOutcome::replaced);

    CHECK(curation_scalar(pool, "SELECT pack_version || '/' || loaded_by FROM "
                                "product_registry_store.normalization_pack") ==
          "2099.12.1/tester");
    const auto src = "'pack:" + dropped.ecosystem + "'";
    const auto q = "' AND source = " + src + " AND raw_publisher = '" + dropped.raw_publisher + "'";
    CHECK(curation_scalar(pool, "SELECT status FROM product_registry_store.product_aliases "
                                "WHERE raw_name = '" + dropped.raw_name + q) == "inactive");
    CHECK(curation_scalar(pool, "SELECT count(*) FROM product_registry_store.product_aliases "
                                "WHERE status = 'active'") ==
          std::to_string(next.rows.size()));
    CHECK(curation_scalar(pool, "SELECT pack_version FROM "
                                "product_registry_store.title_dimension") == "");
}

TEST_CASE("normalization_status reports the pack and the dimension and queue counts",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    auto empty = store.normalization_status();
    REQUIRE(empty.has_value());
    CHECK(empty->pack_version.empty());
    CHECK(empty->queue_open == 0);

    REQUIRE(store.load_pack_if_empty(seed_pack(), "seed").has_value());
    queue_row(pool, "a", "", "rpm", 1);
    queue_row(pool, "b", "", "rpm", 1, "rejected");
    curation_exec(pool, "INSERT INTO product_registry_store.title_dimension (raw_name, "
                        "raw_publisher, ecosystem, norm_status, pack_version, first_seen_at, "
                        "updated_at) VALUES ('q', '', 'rpm', 'unnormalized', 'v', 1, 1)");
    auto st = store.normalization_status();
    REQUIRE(st.has_value());
    CHECK_FALSE(st->pack_version.empty());
    CHECK(st->loaded_by == "seed");
    CHECK(st->titles_unnormalized == 1);
    CHECK(st->titles_normalized == 0);
    CHECK(st->queue_open == 1);
    CHECK(st->queue_rejected == 1);
}

TEST_CASE("derive_curated_alias applies the pack parser's edition rules", "[normalization]") {
    using yuzu::server::derive_curated_alias;
    CHECK_FALSE(derive_curated_alias("rpm", "", "", "v", "p", "").has_value());
    CHECK_FALSE(derive_curated_alias("rpm", "n", "", "", "p", "").has_value());
    CHECK_FALSE(derive_curated_alias("rpm", "n", "", "v", "", "").has_value());
    CHECK_FALSE(derive_curated_alias("rpm", "n", "", "v", "p", "notanedition").has_value());
    CHECK_FALSE(derive_curated_alias("rpm", "x standard", "", "v", "p", "enterprise").has_value());
    const auto k = derive_curated_alias("rpm", "x standard", "Acme Inc", "Acme", "Thing", "");
    REQUIRE(k.has_value());
    CHECK(k->edition == "standard");
    CHECK(k->source == "curated:rpm");
    CHECK(k->norm_key == "acme:thing:standard");
}

TEST_CASE("curate_alias with no category keeps an existing product's category; a new one gets other",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    const auto a1 = yuzu::server::derive_curated_alias("windows", "SQL Server 2019 Standard",
                                                       "Microsoft Corporation", "Microsoft",
                                                       "SQL Server", "");
    REQUIRE(a1.has_value());
    REQUIRE(store.curate_alias("windows", *a1, "database", "sql_server").has_value());
    const auto a2 = yuzu::server::derive_curated_alias("windows", "SQL Server 2022 Standard",
                                                       "Microsoft Corporation", "Microsoft",
                                                       "SQL Server", "");
    REQUIRE(a2.has_value());
    REQUIRE(store.curate_alias("windows", *a2, "", "").has_value());
    auto prod = store.get_product("microsoft:sql server:standard");
    REQUIRE(prod.has_value());
    REQUIRE(prod->has_value());
    CHECK((*prod)->category == "database"); // not reset to other
    CHECK((*prod)->cpe_product == "sql_server");

    const auto b = yuzu::server::derive_curated_alias("windows", "Widget Pro", "", "Acme",
                                                      "Widget", "");
    REQUIRE(b.has_value());
    REQUIRE(store.curate_alias("windows", *b, "", "").has_value());
    auto fresh = store.get_product(b->norm_key);
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->has_value());
    CHECK((*fresh)->category == "other");
}

TEST_CASE("replace_pack leaves curated aliases active and a curated product's category alone",
          "[pg][product_registry][normalization]") {
    PROD_SHARED(store, pool);
    const auto old_pack = seed_pack();
    REQUIRE(store.load_pack_if_empty(old_pack, "seed").has_value());

    const auto alias = yuzu::server::derive_curated_alias("windows", "Contoso Studio Standard",
                                                          "Contoso Ltd", "Contoso", "Studio", "");
    REQUIRE(alias.has_value());
    REQUIRE(store.curate_alias("windows", *alias, "runtime", "").has_value());

    // A pack product a curator now owns: its category must survive the replace.
    const auto kept = old_pack.rows.front();
    const std::string want = kept.category == "runtime" ? "database" : "runtime";
    curation_exec(pool, "UPDATE product_registry_store.products SET origin = 'curated', "
                        "category = '" + want + "' WHERE norm_key = '" + kept.norm_key + "'");

    auto out = store.replace_pack(next_pack("2099.12.2"), "tester");
    REQUIRE(out.has_value());
    CHECK(*out == yuzu::server::PackReplaceOutcome::replaced);

    CHECK(curation_scalar(pool, "SELECT status FROM product_registry_store.product_aliases "
                                "WHERE source = 'curated:windows'") == "active");
    CHECK(curation_scalar(pool, "SELECT category FROM product_registry_store.products WHERE "
                                "norm_key = '" + kept.norm_key + "'") == want);
    CHECK(curation_scalar(pool, "SELECT origin FROM product_registry_store.products WHERE "
                                "norm_key = '" + kept.norm_key + "'") == "curated");
}
