// SAM.4 software-title normalisation: the PURE resolve_title decision ([normalization],
// no database) and the SoftwareTitleDimension cross-store owner ([pg], a two-store
// pre-migrated template with the embedded seed pack loaded).

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "product_registry_store.hpp"
#include "software_inventory_store.hpp"
#include "software_normalization_pack.hpp"
#include "software_title_dimension.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// ── pure helpers ──────────────────────────────────────────────────────────────

ProductRow prod(std::int64_t id, const std::string& vendor, const std::string& title,
                const std::string& edition = {}, const std::string& category = "other",
                const std::string& cpe = {}) {
    ProductRow p;
    p.product_id = id;
    p.vendor = vendor;
    p.title = title;
    p.edition = edition;
    p.category = category;
    p.cpe_product = cpe;
    p.norm_key = make_norm_key(vendor, title, edition);
    return p;
}

NormalizationAliasRow alias(const std::string& source, const std::string& raw_name,
                            const std::string& raw_publisher, const ProductRow& p,
                            const std::string& method = "pack") {
    NormalizationAliasRow a;
    a.source = source;
    a.raw_name = raw_name;
    a.raw_publisher = raw_publisher;
    a.method = method;
    a.product = p;
    return a;
}

// Mirrors the owner's keyed read: only the product whose norm_key equals
// norm_key(raw_name, raw_publisher) is handed to resolve_title.
TitleResolution resolve(const TitleKey& k, const std::vector<NormalizationAliasRow>& aliases,
                        const std::vector<ProductRow>& products, bool birth = false) {
    const std::string nk = norm_key(k.raw_name, k.raw_publisher);
    const auto it = std::find_if(products.begin(), products.end(),
                                 [&](const ProductRow& p) { return p.norm_key == nk; });
    return resolve_title(k, aliases, it == products.end() ? nullptr : &*it, birth);
}

ProductCandidate candidate_of(const ProductRow& p) {
    return {p.norm_key, p.title, p.vendor};
}

// ── pg helpers ────────────────────────────────────────────────────────────────

yuzu::test::PgTestTemplate titledim_tpl{
    "titledim", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        SoftwareInventoryStore inv{pool};
        ProductRegistryStore reg{pool};
        if (!inv.is_open() || !reg.is_open())
            throw std::runtime_error("titledim template: a store failed to migrate");
        const auto seed = parse_normalization_pack(kSoftwareNormalizationSeed);
        if (!seed)
            throw std::runtime_error("titledim template: seed invalid: " + seed.error());
        if (!reg.load_pack_if_empty(*seed, "test"))
            throw std::runtime_error("titledim template: seed load failed");
    }};

pg::PgResult sql(PgPool& pool, const std::string& stmt, const std::vector<std::string>& params = {}) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), stmt.c_str(), params);
    REQUIRE((r.status() == PGRES_TUPLES_OK || r.status() == PGRES_COMMAND_OK));
    return r;
}

std::string scalar(PgPool& pool, const std::string& stmt, const std::vector<std::string>& p = {}) {
    auto r = sql(pool, stmt, p);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

void triple(PgPool& pool, const std::string& name, const std::string& pub, const std::string& eco,
            int devices) {
    sql(pool,
        "INSERT INTO software_inventory_store.title_triples (name, publisher, ecosystem, "
        "device_count) VALUES ($1, $2, $3, $4::bigint) "
        "ON CONFLICT (name, publisher, ecosystem) DO UPDATE SET device_count = EXCLUDED.device_count",
        {name, pub, eco, std::to_string(devices)});
}

std::string dim(PgPool& pool, const std::string& name, const std::string& column) {
    return scalar(pool,
                  "SELECT " + column +
                      " FROM product_registry_store.title_dimension WHERE raw_name = $1",
                  {name});
}

} // namespace

// ═════════════════════════════ pure resolve_title ═════════════════════════════

TEST_CASE("resolve_title prefers a curated alias over a pack alias for the same key",
          "[normalization][title]") {
    const auto packed = prod(1, "igor pavlov", "7-zip");
    const auto curated = prod(2, "igor pavlov", "7-zip curated");
    const auto r = resolve({"7-Zip 23.01 (x64)", "Igor Pavlov", "windows"},
                           {alias("pack:windows", "7-zip", "igor pavlov", packed),
                            alias("curated:windows", "7-zip", "igor pavlov", curated, "curated")},
                           {packed, curated});
    CHECK(r.norm_status == "normalized");
    CHECK(r.method == "curated");
    CHECK(r.product_id == 2);
    CHECK(r.title_version == "23.01");
}

TEST_CASE("resolve_title prefers an ecosystem-specific alias over a wildcard and an exact "
          "publisher over a wildcard",
          "[normalization][title]") {
    const auto exact = prod(1, "v", "exact");
    const auto eco_any_pub = prod(2, "v", "eco-only");
    const auto any_eco_pub = prod(3, "v", "pub-only");
    const auto wild = prod(4, "v", "wild");
    const std::vector<ProductRow> products{exact, eco_any_pub, any_eco_pub, wild};
    std::vector<NormalizationAliasRow> aliases{
        alias("pack:", "tool", "", wild),
        alias("pack:", "tool", "acme", any_eco_pub),
        alias("pack:windows", "tool", "", eco_any_pub),
        alias("pack:windows", "tool", "acme", exact),
    };
    const TitleKey k{"Tool", "Acme Inc", "windows"};
    CHECK(resolve(k, aliases, products).product_id == 1);
    aliases.pop_back();
    CHECK(resolve(k, aliases, products).product_id == 2); // (eco,'') beats ('',pub)
    aliases.pop_back();
    CHECK(resolve(k, aliases, products).product_id == 3);
    aliases.pop_back();
    CHECK(resolve(k, aliases, products).product_id == 4);
    // A different ecosystem never matches an ecosystem-specific alias.
    CHECK(resolve({"Tool", "Acme", "macos"}, {alias("pack:windows", "tool", "", eco_any_pub)},
                  products)
              .norm_status == "unnormalized");
}

TEST_CASE("resolve_title resolves a Standard title and an Enterprise title to their two "
          "distinct products when both aliases are loaded",
          "[normalization][title]") {
    const auto std_p = prod(1, "microsoft", "sql server", "standard", "database", "sql_server");
    const auto ent_p = prod(2, "microsoft", "sql server", "enterprise", "database", "sql_server");
    const std::vector<NormalizationAliasRow> aliases{
        alias("pack:windows", "microsoft sql server standard", "", std_p),
        alias("pack:windows", "microsoft sql server enterprise", "", ent_p),
    };
    const auto a = resolve({"Microsoft SQL Server 2019 Standard (x64)", "Microsoft Corporation",
                            "windows"},
                           aliases, {std_p, ent_p});
    const auto b = resolve({"Microsoft SQL Server 2017 Enterprise", "Microsoft", "windows"},
                           aliases, {std_p, ent_p});
    CHECK(a.product_id == 1);
    CHECK(a.edition == "standard");
    CHECK(a.category == "database");
    CHECK(b.product_id == 2);
    CHECK(b.edition == "enterprise");
}

TEST_CASE("resolve_title with only a Standard alias labels an Enterprise title unnormalized and "
          "never reaches the matcher's cross-edition title_vendor hit",
          "[normalization][title]") {
    // The matcher relates editions of one product (title_vendor ignores the edition).
    const auto std_p = prod(1, "microsoft", "microsoft sql server", "standard");
    const std::vector<NormalizationAliasRow> aliases{
        alias("pack:windows", "microsoft sql server standard", "", std_p)};
    const TitleKey ent{"Microsoft SQL Server 2019 Enterprise", "Microsoft Corporation", "windows"};
    // Positive control: the matcher WOULD hit the Standard product for this title ...
    const auto hit = match_product(ent.raw_name, ent.raw_publisher, {candidate_of(std_p)});
    REQUIRE(hit.tier == MatchTier::title_vendor);
    // ... but the key the dimension reads by embeds the edition, so that product is never
    // the one handed to resolve_title.
    CHECK(norm_key(ent.raw_name, ent.raw_publisher) != std_p.norm_key);
    const auto r = resolve(ent, aliases, {std_p});
    CHECK(r.norm_status == "unnormalized");
    CHECK_FALSE(r.product_id.has_value());
    CHECK(r.edition == "enterprise");
    // The Standard title still resolves (alias tier).
    CHECK(resolve({"Microsoft SQL Server 2019 Standard", "Microsoft", "windows"}, aliases, {std_p})
              .product_id == 1);
}

TEST_CASE("resolve_title takes the exact-key product with method exact_norm",
          "[normalization][title]") {
    const auto exact = prod(1, "acme", "widget tool", {}, "database", "widget");
    const auto r = resolve({"Widget Tool 2.0", "Acme Inc", "windows"}, {}, {exact});
    CHECK(r.norm_status == "normalized");
    CHECK(r.method == "exact_norm");
    CHECK(r.product_id == 1);
    CHECK(r.cpe_product == "widget");
    CHECK(r.category == "database");
}

TEST_CASE("resolve_title never labels a merely similar product: a subset-title product is not "
          "taken and a companion title does not resolve to the main product",
          "[normalization][title]") {
    // The matcher's token_set tier would hit both of these; an identity must not guess.
    const auto subset = prod(2, "acme", "widget");
    const TitleKey widget_tool{"Widget Tool", "Acme", "windows"};
    REQUIRE(match_product(widget_tool.raw_name, widget_tool.raw_publisher, {candidate_of(subset)})
                .tier == MatchTier::token_set);
    const auto near = resolve(widget_tool, {}, {subset});
    CHECK(near.norm_status == "unnormalized");
    CHECK_FALSE(near.product_id.has_value());

    const auto chrome = prod(1, "google", "chrome", {}, "other", "chrome");
    const TitleKey companion{"Chrome Remote Desktop Host", "Google LLC", "windows"};
    REQUIRE(match_product(companion.raw_name, companion.raw_publisher, {candidate_of(chrome)})
                .tier == MatchTier::token_set);
    const auto r = resolve(companion, {}, {chrome});
    CHECK(r.norm_status == "unnormalized");
    CHECK(r.method.empty());
    CHECK_FALSE(r.product_id.has_value());
    CHECK(r.cpe_product.empty());
}

TEST_CASE("resolve_title with auto birth off labels an unmatched title unnormalized with a null "
          "product",
          "[normalization][title]") {
    const auto r = resolve({"Totally Unknown Thing 3.1 Pro", "Nobody Ltd", "rpm"}, {}, {});
    CHECK(r.norm_status == "unnormalized");
    CHECK(r.method.empty());
    CHECK_FALSE(r.product_id.has_value());
    CHECK(r.vendor == "nobody");
    CHECK(r.product == "totally unknown thing");
    CHECK(r.edition == "pro");
    CHECK(r.title_version == "3.1");
    CHECK(r.category == "other");
    CHECK(r.purl_type == "rpm");
    CHECK(r.cpe_product.empty());
}

TEST_CASE("resolve_title with auto birth on births only with a non-empty vendor and at least "
          "two tokens",
          "[normalization][title]") {
    CHECK(resolve({"Two Tokens", "Acme", "windows"}, {}, {}, true).method == "birth");
    CHECK(resolve({"Two Tokens", "", "windows"}, {}, {}, true).norm_status == "unnormalized");
    CHECK(resolve({"Single", "Acme", "windows"}, {}, {}, true).norm_status == "unnormalized");
    CHECK(resolve({"Two Tokens", "Acme", "windows"}, {}, {}, false).norm_status == "unnormalized");
    CHECK_FALSE(kAutoBirthEnabled);
}

TEST_CASE("resolve_title takes cpe_product from the product row only", "[normalization][title]") {
    const auto with_cpe = prod(1, "acme", "gizmo", {}, "other", "gizmo_cpe");
    const auto hit = resolve({"Gizmo", "Acme", "deb"},
                             {alias("pack:deb", "gizmo", "", with_cpe)}, {with_cpe});
    CHECK(hit.cpe_product == "gizmo_cpe");
    CHECK(hit.purl_type == "deb");
    // openssl is in the curated CPE map, but an unresolved title carries no cpe_product.
    CHECK(resolve({"openssl", "x", "deb"}, {}, {}).cpe_product.empty());
}

// ═════════════════════════════ owner ([pg]) ═════════════════════════════════

namespace {
#define TD_ENV(db, pool, inv, reg, metrics, owner)                                                 \
    YUZU_REQUIRE_PG_DB_TPL(db, titledim_tpl);                                                      \
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};                                                \
    REQUIRE(pool.valid());                                                                         \
    SoftwareInventoryStore inv{pool};                                                              \
    ProductRegistryStore reg{pool};                                                                \
    REQUIRE(inv.is_open());                                                                        \
    REQUIRE(reg.is_open());                                                                        \
    yuzu::MetricsRegistry metrics;                                                                 \
    SoftwareTitleDimension owner{pool, reg, inv, &metrics}
} // namespace

TEST_CASE("owner pass reports no_pack when no pack is loaded", "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    sql(pool, "DELETE FROM product_registry_store.normalization_pack");
    triple(pool, "Anything", "Pub", "windows", 1);
    CHECK(owner.run_pass().outcome == PassOutcome::no_pack);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "0");
}

TEST_CASE("owner pass writes one dimension row per candidate triple and is idempotent on replay",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip 23.01 (x64)", "Igor Pavlov", "windows", 5);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);

    const auto first = owner.run_pass();
    CHECK(first.outcome == PassOutcome::ok);
    CHECK(first.processed == 2);
    CHECK(first.normalized == 1);
    CHECK(first.unnormalized == 1);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "2");
    CHECK(dim(pool, "7-Zip 23.01 (x64)", "norm_status") == "normalized");
    CHECK(dim(pool, "7-Zip 23.01 (x64)", "vendor") == "igor pavlov");
    CHECK(dim(pool, "7-Zip 23.01 (x64)", "title_version") == "23.01");
    CHECK(dim(pool, "7-Zip 23.01 (x64)", "cpe_product") == "7-zip");
    CHECK(dim(pool, "7-Zip 23.01 (x64)", "pack_version") == "2026.11.1");
    CHECK(dim(pool, "7-Zip 23.01 (x64)", "product_id") != "");
    CHECK(dim(pool, "Mystery Tool", "norm_status") == "unnormalized");
    CHECK(dim(pool, "Mystery Tool", "product_id").empty()); // NULL, never guessed

    // updated_at is second-granular, so a sentinel is the only way to see a rewrite.
    sql(pool, "UPDATE product_registry_store.title_dimension SET updated_at = 1");
    const auto replay = owner.run_pass();
    CHECK(replay.outcome == PassOutcome::ok);
    CHECK(replay.processed == 0); // nothing pending or below the pack version
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension "
                       "WHERE updated_at <> 1") == "0"); // and nothing rewritten
}

TEST_CASE("owner pass leaves a companion title unnormalized although the main product is in the "
          "registry",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // Positive control: the product the matcher's token_set tier would have picked exists.
    REQUIRE(scalar(pool, "SELECT count(*) FROM product_registry_store.products "
                         "WHERE norm_key = 'google:chrome'") == "1");
    triple(pool, "Chrome Remote Desktop Host", "Google LLC", "windows", 3);
    triple(pool, "Google Chrome", "Google LLC", "windows", 9);
    REQUIRE(owner.run_pass().processed == 2);
    CHECK(dim(pool, "Chrome Remote Desktop Host", "norm_status") == "unnormalized");
    CHECK(dim(pool, "Chrome Remote Desktop Host", "product_id").empty());
    CHECK(dim(pool, "Google Chrome", "norm_status") == "normalized");
    CHECK(dim(pool, "Google Chrome", "cpe_product") == "chrome");
}

TEST_CASE("owner pass re-normalises every row when the pack version changes",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip", "Igor Pavlov", "windows", 5);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    REQUIRE(owner.run_pass().processed == 2);
    sql(pool, "UPDATE product_registry_store.normalization_pack SET pack_version = '2026.12.1'");
    const auto again = owner.run_pass();
    CHECK(again.processed == 2);
    CHECK(dim(pool, "Mystery Tool", "pack_version") == "2026.12.1");
    CHECK(owner.run_pass().processed == 0);
}

TEST_CASE("owner pass re-normalises a row whose pack_version is the empty stale sentinel",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip", "Igor Pavlov", "windows", 5);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    REQUIRE(owner.run_pass().processed == 2);
    sql(pool, "UPDATE product_registry_store.title_dimension SET pack_version = '' "
              "WHERE raw_name = 'Mystery Tool'");
    const auto again = owner.run_pass();
    CHECK(again.processed == 1);
    CHECK(dim(pool, "Mystery Tool", "pack_version") == "2026.11.1");
}

TEST_CASE("owner pass queues unnormalized titles with device counts and removes a title from the "
          "queue once it resolves",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    REQUIRE(owner.run_pass().unnormalized == 1);
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Mystery Tool'") == "7");

    // A curated alias lands (the contract: mark the affected dimension rows stale).
    const auto pid = reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "", "");
    REQUIRE(pid.has_value());
    REQUIRE(reg.upsert_alias("curated:windows", "mystery tool", "nobody", *pid, "curated", 1.0));
    sql(pool, "UPDATE product_registry_store.title_dimension SET pack_version = '' "
              "WHERE raw_name = 'Mystery Tool'");
    const auto again = owner.run_pass();
    CHECK(again.normalized == 1);
    CHECK(dim(pool, "Mystery Tool", "method") == "curated");
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "0");
}

TEST_CASE("owner pass preserves a rejected queue row", "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    REQUIRE(owner.run_pass().processed == 1);
    sql(pool, "UPDATE product_registry_store.curation_queue SET status = 'rejected'");
    triple(pool, "Mystery Tool", "Nobody", "windows", 11);
    sql(pool, "UPDATE product_registry_store.title_dimension SET pack_version = ''");
    REQUIRE(owner.run_pass().processed == 1);
    CHECK(scalar(pool, "SELECT status FROM product_registry_store.curation_queue") == "rejected");
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue") == "11");
}

TEST_CASE("owner pass skips when a peer holds the advisory lock",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    auto holder = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(holder);
    pg::PgResult begin{PQexec(holder.get(), "BEGIN")};
    REQUIRE(begin.status() == PGRES_COMMAND_OK);
    pg::PgResult lk{PQexec(holder.get(), "SELECT pg_advisory_xact_lock(hashtextextended("
                                         "'software_normalization', 0))")};
    REQUIRE(lk.status() == PGRES_TUPLES_OK);
    const auto r = owner.run_pass();
    CHECK(r.outcome == PassOutcome::skipped_peer);
    CHECK(r.processed == 0);
    CHECK(owner.reconcile_queue()); // a skip is success
    pg::PgResult rb{PQexec(holder.get(), "ROLLBACK")};
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "0");
}

TEST_CASE("owner pass re-normalises a row whose product was deleted",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip", "Igor Pavlov", "windows", 5);
    REQUIRE(owner.run_pass().normalized == 1);
    CHECK_FALSE(dim(pool, "7-Zip", "product_id").empty());
    // ON DELETE SET NULL on the dimension; the pack alias cascades away with its product.
    sql(pool, "DELETE FROM product_registry_store.products WHERE cpe_product = '7-zip'");
    CHECK(dim(pool, "7-Zip", "product_id").empty());
    CHECK(dim(pool, "7-Zip", "norm_status") == "normalized"); // stale until re-selected
    const auto again = owner.run_pass();
    CHECK(again.processed == 1);
    CHECK(again.unnormalized == 1);
    CHECK(dim(pool, "7-Zip", "norm_status") == "unnormalized");
}

TEST_CASE("owner pass rolls back and reports cancelled when the cancel flag trips mid-batch "
          "leaving no dimension rows",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip", "Igor Pavlov", "windows", 5);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    std::atomic<int> calls{0};
    // Call 1 is the resolve-loop check at title 0 (clear); call 2 is the pre-write check.
    const auto r = owner.run_pass([&] { return ++calls >= 2; });
    CHECK(r.outcome == PassOutcome::cancelled);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "0");
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "0");
    // The next uncancelled pass does the work.
    CHECK(owner.run_pass().processed == 2);
}

TEST_CASE("owner tick stops at a short page and reports processed counts",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip", "Igor Pavlov", "windows", 5);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    // A tick with the cancel flag already set does nothing, is not an error, and skips the
    // gauge refresh (no lease or title_triples join on the stop path).
    const auto c = owner.run_tick([] { return true; });
    CHECK(c.cancelled);
    CHECK_FALSE(c.errored);
    CHECK(c.processed == 0);
    CHECK(metrics.serialize().find("yuzu_software_titles") == std::string::npos);

    const auto t = owner.run_tick();
    CHECK_FALSE(t.errored);
    CHECK_FALSE(t.cancelled);
    CHECK_FALSE(t.capped);
    CHECK(t.passes == 1);
    CHECK(t.processed == 2);
    CHECK(metrics.serialize().find("yuzu_software_titles") != std::string::npos);
}

TEST_CASE("owner tick pages through a backlog, reports a capped tick, and a spent budget rolls "
          "back with nothing written",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // One more than a full page: every title unnormalized, so each pass queues its page.
    sql(pool, "INSERT INTO software_inventory_store.title_triples "
              "(name, publisher, ecosystem, device_count) "
              "SELECT 'Backlog Tool ' || g, 'Nobody', 'windows', 1 FROM generate_series(1, 2001) g");

    SECTION("the default cap drains the backlog in two passes and is not capped") {
        const auto t = owner.run_tick();
        CHECK_FALSE(t.errored);
        CHECK(t.passes == 2);
        CHECK(t.processed == 2001);
        CHECK_FALSE(t.capped); // the second page was short
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "2001");
    }
    SECTION("a one-pass cap on a full page reports capped and the next tick finishes") {
        const auto t = owner.run_tick({}, 1);
        CHECK_FALSE(t.errored);
        CHECK(t.capped);
        CHECK(t.passes == 1);
        CHECK(t.processed == 2000);
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "2000");
        const auto rest = owner.run_tick({}, 1);
        CHECK(rest.processed == 1);
        CHECK_FALSE(rest.capped); // a short page is never capped, even at the cap
    }
    SECTION("a spent wall budget rolls the pass back and reports timed_out") {
        const auto r = owner.run_pass({}, std::chrono::seconds{0});
        CHECK(r.outcome == PassOutcome::timed_out);
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "0");
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "0");
    }
}

TEST_CASE("owner tick reconciles open queue device counts against a refreshed title_triples and "
          "drops open rows whose title vanished while keeping rejected rows",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    triple(pool, "Gone Tool", "Nobody", "windows", 3);
    triple(pool, "Rejected Tool", "Nobody", "windows", 4);
    REQUIRE_FALSE(owner.run_tick().errored);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "3");
    sql(pool, "UPDATE product_registry_store.curation_queue SET status = 'rejected' "
              "WHERE raw_name = 'Rejected Tool'");

    // The next rollup: Mystery Tool grew, the other two titles left the fleet.
    triple(pool, "Mystery Tool", "Nobody", "windows", 9);
    sql(pool, "DELETE FROM software_inventory_store.title_triples "
              "WHERE name IN ('Gone Tool', 'Rejected Tool')");
    REQUIRE_FALSE(owner.run_tick().errored);

    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Mystery Tool'") == "9");
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Gone Tool'") == "0");
    CHECK(scalar(pool, "SELECT status FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Rejected Tool'") == "rejected");
}

TEST_CASE("owner tick re-queues an unknown title that returns to the fleet without touching its "
          "dimension row, and does not reopen a rejected row",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Gone Tool", "Nobody", "windows", 3);
    triple(pool, "Rejected Tool", "Nobody", "windows", 4);
    REQUIRE_FALSE(owner.run_tick().errored);
    sql(pool, "UPDATE product_registry_store.curation_queue SET status = 'rejected' "
              "WHERE raw_name = 'Rejected Tool'");

    // Both titles leave the fleet: the open row is pruned, the rejected one is kept; the
    // permanent dimension rows stay current-pack 'unnormalized'.
    sql(pool, "DELETE FROM software_inventory_store.title_triples");
    REQUIRE_FALSE(owner.run_tick().errored);
    REQUIRE(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue "
                         "WHERE raw_name = 'Gone Tool'") == "0");

    // Pin the dimension row's updated_at so any rewrite of it is visible without a clock.
    sql(pool, "UPDATE product_registry_store.title_dimension SET updated_at = 1");
    const std::string pack_before = dim(pool, "Gone Tool", "pack_version");

    // Both titles return with new device counts.
    triple(pool, "Gone Tool", "Nobody", "windows", 6);
    triple(pool, "Rejected Tool", "Nobody", "windows", 8);
    REQUIRE_FALSE(owner.run_tick().errored);

    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Gone Tool'") == "1");
    CHECK(scalar(pool, "SELECT status FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Gone Tool'") == "open");
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Gone Tool'") == "6");
    CHECK(dim(pool, "Gone Tool", "norm_status") == "unnormalized");
    CHECK(dim(pool, "Gone Tool", "pack_version") == pack_before);
    CHECK(dim(pool, "Gone Tool", "updated_at") == "1");
    CHECK(scalar(pool, "SELECT status FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Rejected Tool'") == "rejected");

    // A further tick is a no-op for the re-queued row: first_queued_at is pinned to a
    // sentinel, so a rewrite would show.
    sql(pool, "UPDATE product_registry_store.curation_queue SET first_queued_at = 1");
    REQUIRE_FALSE(owner.run_tick().errored);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Gone Tool'") == "1");
    CHECK(scalar(pool, "SELECT first_queued_at FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Gone Tool'") == "1");
    CHECK(dim(pool, "Gone Tool", "updated_at") == "1");
}

TEST_CASE("gauges report normalized unnormalized and pending titles and the device-weighted ratio",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip", "Igor Pavlov", "windows", 6);    // normalized, 6 devices
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);  // unnormalized, 2 devices
    REQUIRE_FALSE(owner.run_tick().errored);
    triple(pool, "Brand New", "Nobody", "windows", 2); // arrives after the tick: pending
    owner.refresh_gauges();

    const auto titles = [&](const char* s) {
        return metrics.gauge("yuzu_software_titles", {{"norm_status", s}}).value();
    };
    CHECK(titles("normalized") == 1);
    CHECK(titles("unnormalized") == 1);
    CHECK(titles("pending") == 1);
    CHECK(metrics.gauge("yuzu_software_unnormalized_ratio").value() == 0.4); // (2+2)/10
    CHECK(metrics.gauge("yuzu_software_normalization_curation_queue_size").value() == 1);
    CHECK(metrics.gauge("yuzu_software_normalization_pack_info", {{"pack_version", "2026.11.1"}})
              .value() == 1);
}
