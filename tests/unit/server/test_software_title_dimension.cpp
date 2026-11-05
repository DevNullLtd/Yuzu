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
#include "test_principal_lock_gate.hpp" // wait_for_lock_waiter

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <map>
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
                            const std::string& raw_publisher, const ProductRow& p) {
    NormalizationAliasRow a;
    a.source = source;
    a.raw_name = raw_name;
    a.raw_publisher = raw_publisher;
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
                            alias("curated:windows", "7-zip", "igor pavlov", curated)},
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

TEST_CASE("resolve_title given only the exact-key product and a Standard alias labels an Enterprise "
          "title unnormalized",
          "[normalization][title]") {
    // This pins resolve_title's contract over the candidates it is HANDED: the structural edition
    // guard is the owner's keyed read (it hands over only the product whose norm_key embeds the
    // title's edition), exercised end to end against the loaded seed by the [pg] case "owner pass
    // keeps the Standard and Enterprise editions of one product distinct".
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

TEST_CASE("resolve_title treats a name with no title token as unnormalized even when an alias is keyed "
          "on it",
          "[normalization][title]") {
    // "2019" and "(x64)" normalise to an empty title, "Pro" to an empty title plus an edition.
    // Positive control: an alias row keyed on exactly the key each would form would be adopted
    // by the alias loop, so the unnormalized result below is the explicit guard, not the absence
    // of a candidate.
    const auto p = prod(1, "acme", "anything");
    for (const char* raw : {"2019", "(x64)", "Pro", "Pro 2019 (x64)"}) {
        CAPTURE(raw);
        const NormalizedTitle nt = normalize_title(raw);
        REQUIRE(nt.title.empty());
        const std::string key = alias_key(nt); // "" or " pro"
        const auto r = resolve({raw, "", "windows"}, {alias("pack:", key, "", p)}, {p});
        CHECK(r.norm_status == "unnormalized");
        CHECK(r.method.empty());
        CHECK_FALSE(r.product_id.has_value());
        CHECK(r.product.empty());
    }
    // And a title that does have tokens still matches the same shaped alias.
    CHECK(resolve({"Anything 2019", "", "windows"}, {alias("pack:", "anything", "", p)}, {p})
              .norm_status == "normalized");
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

TEST_CASE("resolve_title reads a category outside the closed set as other and records the tier "
          "as the method",
          "[normalization][title]") {
    const auto bogus = prod(1, "acme", "gizmo", {}, "bogus");
    const auto r =
        resolve({"Gizmo", "Acme", "deb"}, {alias("pack:deb", "gizmo", "", bogus)}, {bogus});
    CHECK(r.norm_status == "normalized");
    CHECK(r.method == "pack");
    CHECK(r.category == "other");
    // Positive control: a category inside the set passes through unchanged.
    const auto db = prod(2, "acme", "gizmo", {}, "database");
    CHECK(resolve({"Gizmo", "Acme", "deb"}, {alias("pack:deb", "gizmo", "", db)}, {db}).category ==
          "database");
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

    // A curated alias lands. The writers follow the invalidation contract themselves (lock,
    // write and stale sentinel in one transaction), so no separate UPDATE is needed.
    const auto pid = reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "", "");
    REQUIRE(pid.has_value());
    REQUIRE(reg.upsert_alias("curated:windows", "mystery tool", "nobody", *pid, "curated", 1.0));
    CHECK(dim(pool, "Mystery Tool", "pack_version").empty());
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

TEST_CASE("owner tick pages through a backlog and reports a capped tick and a spent budget rolls "
          "back with nothing written",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    const std::string page = std::to_string(kPassLimit);
    const std::string page_plus_one = std::to_string(kPassLimit + 1);
    // One more than a full page: every title unnormalized, so each pass queues its page.
    sql(pool, "INSERT INTO software_inventory_store.title_triples "
              "(name, publisher, ecosystem, device_count) "
              "SELECT 'Backlog Tool ' || g, 'Nobody', 'windows', 1 FROM generate_series(1, " +
                  page_plus_one + ") g");

    SECTION("the default cap drains the backlog in two passes and is not capped") {
        const auto t = owner.run_tick();
        CHECK_FALSE(t.errored);
        CHECK(t.passes == 2);
        CHECK(t.processed == kPassLimit + 1);
        CHECK_FALSE(t.capped); // the second page was short
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") ==
              page_plus_one);
    }
    SECTION("a one-pass cap on a full page reports capped and the next tick finishes") {
        const auto t = owner.run_tick({}, 1);
        CHECK_FALSE(t.errored);
        CHECK(t.capped);
        CHECK(t.passes == 1);
        CHECK(t.processed == kPassLimit);
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == page);
        const auto rest = owner.run_tick({}, 1);
        CHECK(rest.processed == 1);
        CHECK_FALSE(rest.capped); // a short page is never capped, even at the cap
    }
    SECTION("an exhausted tick budget stops after the first full page and reports capped") {
        for (const auto budget :
             {std::chrono::seconds{0}, kMinLaterPassBudget - std::chrono::seconds{1}}) {
            INFO("tick budget " << budget.count() << " s");
            const auto t = owner.run_tick({}, kMaxPassesPerTick, budget);
            CHECK_FALSE(t.errored);
            CHECK(t.capped); // a full page ran and no later pass has the minimum left
            CHECK(t.passes == 1);
            CHECK(t.processed == kPassLimit);
            // the page is settled, so the next tick starts from the remainder
            CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") ==
                  page);
            sql(pool, "DELETE FROM product_registry_store.title_dimension");
            sql(pool, "DELETE FROM product_registry_store.curation_queue");
        }
        const auto rest = owner.run_tick();
        CHECK(rest.processed == kPassLimit + 1);
        CHECK_FALSE(rest.capped);
    }
    SECTION("a tick budget with the minimum left starts the later pass") {
        // Generous headroom over the minimum: the first page only has to finish well inside it.
        const auto t =
            owner.run_tick({}, kMaxPassesPerTick, kMinLaterPassBudget + std::chrono::seconds{30});
        CHECK_FALSE(t.errored);
        CHECK(t.passes == 2); // the second page is short: the backlog is gone
        CHECK(t.processed == kPassLimit + 1);
        CHECK_FALSE(t.capped);
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
          "dimension row and does not reopen a rejected row",
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

TEST_CASE("a title keyed under an empty publisher re-keys under its via: label: the open row is "
          "pruned, a rejected row stays and the label's row is queued open",
          "[pg][product_registry][normalization][vendor]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // Keyed on the raw (name, publisher, ecosystem) triple: a vendorless brew title is keyed ''.
    triple(pool, "Mystery Tool", "", "brew", 5);
    triple(pool, "Rejected Tool", "", "brew", 4);
    REQUIRE_FALSE(owner.run_tick().errored);
    REQUIRE(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue "
                         "WHERE raw_publisher = ''") == "2");
    sql(pool, "UPDATE product_registry_store.curation_queue SET status = 'rejected' "
              "WHERE raw_name = 'Rejected Tool'");

    // The rollup is rebuilt from the live inventory: the same two titles, now keyed `via:brew`.
    sql(pool, "DELETE FROM software_inventory_store.title_triples");
    triple(pool, "Mystery Tool", "via:brew", "brew", 5);
    triple(pool, "Rejected Tool", "via:brew", "brew", 4);
    REQUIRE_FALSE(owner.run_tick().errored);

    const auto queue = [&](const std::string& name, const std::string& publisher,
                           const std::string& column) {
        return scalar(pool,
                      "SELECT coalesce(max(" + column + ")::text, 'absent') FROM "
                      "product_registry_store.curation_queue WHERE raw_name = $1 AND "
                      "raw_publisher = $2",
                      {name, publisher});
    };
    // The open '' row left the queue with its triple; the label's row is queued open.
    CHECK(queue("Mystery Tool", "", "status") == "absent");
    CHECK(queue("Mystery Tool", "via:brew", "status") == "open");
    CHECK(queue("Mystery Tool", "via:brew", "device_count") == "5");
    // A rejected '' row stays, and the rejection is NOT carried over to the label's row.
    CHECK(queue("Rejected Tool", "", "status") == "rejected");
    CHECK(queue("Rejected Tool", "via:brew", "status") == "open");
    // Dimension rows are permanent: the old keys remain, the label keys are new unnormalized rows.
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension "
                       "WHERE raw_publisher = ''") == "2");
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension "
                       "WHERE raw_publisher = 'via:brew' AND norm_status = 'unnormalized'") == "2");
}

TEST_CASE("gauges report normalized unnormalized and pending titles and the install-weighted ratio",
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

TEST_CASE("owner pass keeps the Standard and Enterprise editions of one product distinct",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // Positive control: the seed carries the Standard product, which the matcher's
    // edition-blind title_vendor tier would also hand to an Enterprise or Datacenter title.
    REQUIRE(scalar(pool, "SELECT count(*) FROM product_registry_store.products "
                         "WHERE norm_key = 'microsoft:sql server:standard'") == "1");
    const std::string std_raw = "Microsoft SQL Server 2019 Standard (x64)";
    const std::string ent_raw = "Microsoft SQL Server 2017 Enterprise";
    const std::string dc_raw = "Microsoft SQL Server 2019 Datacenter";
    triple(pool, std_raw, "Microsoft Corporation", "windows", 4);
    triple(pool, ent_raw, "Microsoft", "windows", 3);
    triple(pool, dc_raw, "Microsoft", "windows", 2);
    REQUIRE(owner.run_pass().processed == 3);

    CHECK(dim(pool, std_raw, "norm_status") == "normalized");
    CHECK(dim(pool, std_raw, "edition") == "standard");
    CHECK(dim(pool, ent_raw, "norm_status") == "normalized");
    CHECK(dim(pool, ent_raw, "edition") == "enterprise");
    CHECK(dim(pool, std_raw, "product_id") != dim(pool, ent_raw, "product_id"));
    CHECK(dim(pool, std_raw, "category") == "database");
    // No Datacenter alias exists: it is labelled, never taken for a neighbouring edition.
    CHECK(dim(pool, dc_raw, "norm_status") == "unnormalized");
    CHECK(dim(pool, dc_raw, "product_id").empty());
    CHECK(dim(pool, dc_raw, "edition") == "datacenter");
}

TEST_CASE("owner pass keeps a rejected queue row when its title later resolves",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    REQUIRE(owner.run_pass().unnormalized == 1);
    sql(pool, "UPDATE product_registry_store.curation_queue SET status = 'rejected'");

    // A curated alias now resolves the title (the writers mark its dimension row stale).
    const auto pid = reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "", "");
    REQUIRE(pid.has_value());
    REQUIRE(reg.upsert_alias("curated:windows", "mystery tool", "nobody", *pid, "curated", 1.0));
    CHECK(dim(pool, "Mystery Tool", "pack_version").empty());
    const auto again = owner.run_pass();
    CHECK(again.normalized == 1);
    CHECK(dim(pool, "Mystery Tool", "method") == "curated");
    // A rejection is a curator decision: it outlives the title resolving.
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "1");
    CHECK(scalar(pool, "SELECT status FROM product_registry_store.curation_queue") == "rejected");
}

TEST_CASE("owner pass cancelled after the dimension write rolls back both tables",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    std::atomic<int> polls{0};
    // Poll 1 is the resolve loop at title 0, poll 2 the check before the dimension upsert (which
    // then runs and succeeds), poll 3 the check before the queue upsert: the trip lands AFTER
    // the first write, so only the transaction rollback keeps the two tables consistent.
    const auto r = owner.run_pass([&] { return ++polls >= 3; });
    CHECK(r.outcome == PassOutcome::cancelled);
    CHECK(polls.load() == 3);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension") == "0");
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "0");
    CHECK(owner.run_pass().processed == 1); // and the title is still a candidate
}

TEST_CASE("owner pass re-resolving a row moves updated_at and keeps first_seen_at and first_queued_at",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    REQUIRE(owner.run_pass().processed == 1);
    // Sentinels: any rewrite of these columns is visible without reading a clock.
    sql(pool, "UPDATE product_registry_store.title_dimension SET updated_at = 1, first_seen_at = 5, "
              "pack_version = ''");
    sql(pool, "UPDATE product_registry_store.curation_queue SET first_queued_at = 1");
    REQUIRE(owner.run_pass().processed == 1); // selected again through the stale sentinel
    CHECK(std::stoll(dim(pool, "Mystery Tool", "updated_at")) > 1); // the re-resolution is stamped
    CHECK(dim(pool, "Mystery Tool", "first_seen_at") == "5");       // the first sighting survives
    CHECK(dim(pool, "Mystery Tool", "pack_version") == "2026.11.1");
    CHECK(scalar(pool, "SELECT first_queued_at FROM product_registry_store.curation_queue") == "1");
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue") == "7");
}

TEST_CASE("owner pass selects the highest device counts first when a page is full",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // kPassLimit + 1 titles whose device count equals their number: the single title left out of
    // the first page must be the one with the fewest devices.
    sql(pool, "INSERT INTO software_inventory_store.title_triples "
              "(name, publisher, ecosystem, device_count) "
              "SELECT 'Order Tool ' || g, 'Nobody', 'windows', g FROM generate_series(1, " +
                  std::to_string(kPassLimit + 1) + ") g");
    const auto first = owner.run_pass();
    REQUIRE(first.processed == kPassLimit);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension "
                       "WHERE raw_name = 'Order Tool 1'") == "0");
    // The remainder is the next page.
    CHECK(owner.run_pass().processed == 1);
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension "
                       "WHERE raw_name = 'Order Tool 1'") == "1");
}

TEST_CASE("owner pass round-trips awkward names through the array writes",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // Quote, backslash, braces, comma, the word NULL (an array NULL element would violate NOT NULL
    // and fail the pass), a leading/trailing space and a 1024-byte value in name and publisher.
    const std::vector<std::pair<std::string, std::string>> titles{
        {"quo\"te", "pub\"lisher"},
        {"back\\slash", "back\\\\slash"},
        {"{brace}", "{pub,lisher}"},
        {"com,ma", "semi;colon"},
        {"NULL", "NULL"},
        {"null", ""},
        {std::string(1024, 'n'), std::string(1024, 'p')},
        {"comma, \"quote\" \\ {x}", "O'Brien"},
    };
    int devices = 100;
    for (const auto& [name, pub] : titles)
        triple(pool, name, pub, "windows", devices--);
    const auto r = owner.run_pass();
    REQUIRE(r.outcome == PassOutcome::ok);
    CHECK(r.processed == static_cast<int>(titles.size()));
    for (const auto& [name, pub] : titles) {
        CAPTURE(name.size(), pub.size());
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.title_dimension "
                           "WHERE raw_name = $1 AND raw_publisher = $2 AND ecosystem = 'windows'",
                     {name, pub}) == "1");
        CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue "
                           "WHERE raw_name = $1 AND raw_publisher = $2",
                     {name, pub}) == "1");
    }
}

TEST_CASE("owner pass reports source_pending only while the catalogue rollup has not filled "
          "title_triples",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // No installed software and no titles: nothing is pending anywhere - an ordinary clean pass.
    const auto idle = owner.run_pass();
    CHECK(idle.outcome == PassOutcome::ok);
    CHECK_FALSE(owner.run_tick().source_pending);

    // Installed software exists but the rollup has not produced title_triples yet.
    sql(pool, "INSERT INTO software_inventory_store.installed_software (agent_id, name) "
              "VALUES ('d1', 'Fresh Boot Tool')");
    REQUIRE(scalar(pool, "SELECT count(*) FROM software_inventory_store.title_triples") == "0");
    const auto pending = owner.run_pass();
    CHECK(pending.outcome == PassOutcome::source_pending);
    CHECK(pending.processed == 0);
    const auto tick = owner.run_tick();
    CHECK(tick.source_pending);
    CHECK_FALSE(tick.errored);
    CHECK_FALSE(tick.capped);

    // Once the rollup has filled the table the same state is an ordinary pass, and the
    // fully-settled steady state is not source_pending either.
    triple(pool, "Fresh Boot Tool", "", "", 1);
    CHECK(owner.run_pass().outcome == PassOutcome::ok);
    const auto settled = owner.run_tick();
    CHECK_FALSE(settled.source_pending);
    CHECK(owner.run_tick().processed == 0);
}

TEST_CASE("owner reconcile writes only queue rows whose count moved or that are a day stale",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Steady Tool", "Nobody", "windows", 2);
    triple(pool, "Stale Tool", "Nobody", "windows", 3);
    triple(pool, "Moved Tool", "Nobody", "windows", 4);
    REQUIRE_FALSE(owner.run_tick().errored);
    REQUIRE(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "3");

    const std::string fresh = scalar(pool, "SELECT (extract(epoch FROM now()))::bigint - 100");
    sql(pool, "UPDATE product_registry_store.curation_queue SET last_seen_at = $1::bigint "
              "WHERE raw_name IN ('Steady Tool', 'Moved Tool')",
        {fresh});
    sql(pool, "UPDATE product_registry_store.curation_queue SET last_seen_at = 1 "
              "WHERE raw_name = 'Stale Tool'");
    triple(pool, "Moved Tool", "Nobody", "windows", 9);

    REQUIRE(owner.reconcile_queue());
    const auto seen = [&](const char* name) {
        return std::stoll(scalar(pool,
                                 "SELECT last_seen_at FROM product_registry_store.curation_queue "
                                 "WHERE raw_name = $1",
                                 {name}));
    };
    CHECK(seen("Steady Tool") == std::stoll(fresh)); // same count, fresh stamp: not rewritten
    CHECK(seen("Stale Tool") > std::stoll(fresh));   // same count, a day old: re-stamped
    CHECK(seen("Moved Tool") > std::stoll(fresh));   // the count moved: updated and stamped
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Moved Tool'") == "9");
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue "
                       "WHERE raw_name = 'Steady Tool'") == "2");
}

TEST_CASE("owner reconcile skips while a peer holds the lock and catches up once it is released",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    REQUIRE_FALSE(owner.run_tick().errored);
    triple(pool, "Mystery Tool", "Nobody", "windows", 9); // the next rollup's figure

    auto holder = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(holder);
    pg::PgResult begin{PQexec(holder.get(), "BEGIN")};
    REQUIRE(begin.status() == PGRES_COMMAND_OK);
    pg::PgResult lk{PQexec(holder.get(), "SELECT pg_advisory_xact_lock(hashtextextended("
                                         "'software_normalization', 0))")};
    REQUIRE(lk.status() == PGRES_TUPLES_OK);
    CHECK(owner.reconcile_queue()); // a peer holds it: skipped, and a skip is success
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue") == "2");
    pg::PgResult rb{PQexec(holder.get(), "ROLLBACK")};
    REQUIRE(rb.status() == PGRES_COMMAND_OK);
    CHECK(owner.reconcile_queue());
    CHECK(scalar(pool, "SELECT device_count FROM product_registry_store.curation_queue") == "9");
}

TEST_CASE("gauges count a normalized row that lost its product as pending and keep last-good values "
          "when a read fails",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "7-Zip", "Igor Pavlov", "windows", 6);
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    REQUIRE_FALSE(owner.run_tick().errored);
    const auto titles = [&](const char* s) {
        return metrics.gauge("yuzu_software_titles", {{"norm_status", s}}).value();
    };
    REQUIRE(titles("normalized") == 1);

    // The product is deleted under the normalized row (ON DELETE SET NULL): until the pass
    // re-selects it, that title is pending, not normalized, and the ratio counts its installs.
    sql(pool, "DELETE FROM product_registry_store.products WHERE cpe_product = '7-zip'");
    owner.refresh_gauges();
    CHECK(titles("normalized") == 0);
    CHECK(titles("pending") == 1);
    CHECK(titles("unnormalized") == 1);
    CHECK(metrics.gauge("yuzu_software_unnormalized_ratio").value() == 1.0); // all 8 installs

    // A failing gauge read keeps the previous values rather than writing zeros.
    sql(pool, "ALTER TABLE product_registry_store.title_dimension RENAME TO title_dimension_gone");
    sql(pool, "INSERT INTO software_inventory_store.title_triples "
              "(name, publisher, ecosystem, device_count) VALUES ('Extra', 'x', 'windows', 50)");
    owner.refresh_gauges();
    CHECK(titles("pending") == 1);
    CHECK(titles("unnormalized") == 1);
    sql(pool, "ALTER TABLE product_registry_store.title_dimension_gone RENAME TO title_dimension");
    owner.refresh_gauges();
    CHECK(titles("pending") == 2);
}

TEST_CASE("gauges leave the ratio unset while the title source is empty and zero the old pack label "
          "on a pack change",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    // An empty title_triples is NOT "fully normalised": the ratio series is not exported at all,
    // while the count gauges read 0.
    owner.refresh_gauges();
    CHECK(metrics.serialize().find("yuzu_software_unnormalized_ratio") == std::string::npos);
    CHECK(metrics.gauge("yuzu_software_titles", {{"norm_status", "pending"}}).value() == 0);
    CHECK(metrics.gauge("yuzu_software_normalization_pack_info", {{"pack_version", "2026.11.1"}})
              .value() == 1);

    // A non-empty source sets it; emptying the source again leaves the last value (no false 0).
    triple(pool, "Mystery Tool", "Nobody", "windows", 2);
    REQUIRE_FALSE(owner.run_tick().errored);
    CHECK(metrics.gauge("yuzu_software_unnormalized_ratio").value() == 1.0);
    sql(pool, "DELETE FROM software_inventory_store.title_triples");
    owner.refresh_gauges();
    CHECK(metrics.gauge("yuzu_software_unnormalized_ratio").value() == 1.0);
    CHECK(metrics.gauge("yuzu_software_titles", {{"norm_status", "unnormalized"}}).value() == 0);

    // A new pack version moves the info series: the old label reads 0, the new one 1.
    sql(pool, "UPDATE product_registry_store.normalization_pack SET pack_version = '2026.12.1'");
    owner.refresh_gauges();
    CHECK(metrics.gauge("yuzu_software_normalization_pack_info", {{"pack_version", "2026.11.1"}})
              .value() == 0);
    CHECK(metrics.gauge("yuzu_software_normalization_pack_info", {{"pack_version", "2026.12.1"}})
              .value() == 1);
}

TEST_CASE("owner tick clears capped when the queue reconcile fails",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    sql(pool, "INSERT INTO software_inventory_store.title_triples "
              "(name, publisher, ecosystem, device_count) "
              "SELECT 'Backlog Tool ' || g, 'Nobody', 'windows', 1 FROM generate_series(1, " +
                  std::to_string(kPassLimit) + ") g");
    // A queue row for a title that is not in title_triples: the reconcile's prune must delete it,
    // and an injected failure on that delete makes the reconcile (not the pass) fail.
    sql(pool, "INSERT INTO product_registry_store.curation_queue (raw_name, raw_publisher, "
              "ecosystem, device_count, status, first_queued_at, last_seen_at) "
              "VALUES ('Vanished Tool', 'Nobody', 'windows', 1, 'open', 1, 1)");
    sql(pool, "CREATE FUNCTION product_registry_store.fail_queue_delete() RETURNS trigger "
              "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$");
    sql(pool, "CREATE TRIGGER fail_queue_delete BEFORE DELETE ON "
              "product_registry_store.curation_queue FOR EACH ROW EXECUTE FUNCTION "
              "product_registry_store.fail_queue_delete()");
    const auto t = owner.run_tick({}, 1); // one full page on the last allowed pass: would be capped
    CHECK(t.errored);
    CHECK_FALSE(t.capped); // a failed tick never asks for the short re-arm
    CHECK(t.passes == 1);
    CHECK(t.processed == kPassLimit);
}

TEST_CASE("owner pass resolves every shipped seed row from its stored alias key through the "
          "database",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    const auto pack = parse_normalization_pack(kSoftwareNormalizationSeed);
    REQUIRE(pack.has_value());
    // One installed title per seed row: the row's own key as the raw name, its publisher, and a
    // concrete ecosystem for the wildcard rows.
    std::vector<TitleKey> titles;
    for (const auto& r : pack->rows)
        titles.push_back({r.raw_name, r.raw_publisher, r.ecosystem.empty() ? "rpm" : r.ecosystem});
    for (const auto& t : titles)
        triple(pool, t.raw_name, t.raw_publisher, t.ecosystem, 1);
    const auto tick = owner.run_tick();
    REQUIRE_FALSE(tick.errored);
    CHECK(tick.processed == static_cast<int>(titles.size()));
    for (std::size_t i = 0; i < titles.size(); ++i) {
        CAPTURE(titles[i].raw_name, titles[i].ecosystem);
        const std::string key = scalar(
            pool,
            "SELECT COALESCE(p.norm_key, 'UNRESOLVED') FROM product_registry_store.title_dimension d "
            "LEFT JOIN product_registry_store.products p ON p.product_id = d.product_id "
            "WHERE d.raw_name = $1 AND d.raw_publisher = $2 AND d.ecosystem = $3",
            {titles[i].raw_name, titles[i].raw_publisher, titles[i].ecosystem});
        CHECK(key == pack->rows[i].norm_key);
    }
    CHECK(scalar(pool, "SELECT count(*) FROM product_registry_store.curation_queue") == "0");
}

// ═══════════════ registry writers and the dimension invalidation contract ═══════════════

namespace {
/// Run one statement on a held connection (the "pass in flight" in the tests below).
void held(PGconn* lease_conn, const char* stmt) {
    pg::PgResult r = pg::exec_params(lease_conn, stmt, std::vector<std::string>{});
    REQUIRE((r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK));
}
} // namespace

TEST_CASE("registry writers follow the invalidation contract: a change stales what it can change "
          "and a write that changes nothing marks nothing",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    triple(pool, "Other Gadget", "Elsewhere", "windows", 3);
    triple(pool, "Third Tool", "Nobody Three", "windows", 1); // no alias: unnormalized
    const auto p1 = reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "", "");
    const auto p2 =
        reg.upsert_product("elsewhere:other gadget", "elsewhere", "other gadget", "", "");
    REQUIRE(p1.has_value());
    REQUIRE(p2.has_value());
    REQUIRE(reg.upsert_alias("curated:windows", "mystery tool", "nobody", *p1, "curated", 1.0));
    REQUIRE(reg.upsert_alias("curated:windows", "other gadget", "elsewhere", *p2, "curated", 1.0));
    const auto settle = [&] {
        static_cast<void>(owner.run_pass());
        REQUIRE_FALSE(dim(pool, "Mystery Tool", "pack_version").empty());
        REQUIRE_FALSE(dim(pool, "Other Gadget", "pack_version").empty());
        REQUIRE_FALSE(dim(pool, "Third Tool", "pack_version").empty());
    };
    settle();
    REQUIRE(dim(pool, "Third Tool", "norm_status") == "unnormalized");

    // A write that changes nothing marks nothing (a caller that refreshes each cycle must not
    // re-queue the dimension): the same product, and the same link with a new confidence.
    REQUIRE(reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "", ""));
    REQUIRE(reg.upsert_alias("curated:windows", "other gadget", "elsewhere", *p2, "curated", 0.9));
    CHECK_FALSE(dim(pool, "Mystery Tool", "pack_version").empty());
    CHECK_FALSE(dim(pool, "Other Gadget", "pack_version").empty());
    CHECK_FALSE(dim(pool, "Third Tool", "pack_version").empty());

    // A product attribute edit: only the rows resolved to THAT product go stale.
    REQUIRE(reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "pro", ""));
    CHECK(dim(pool, "Mystery Tool", "pack_version").empty());
    CHECK_FALSE(dim(pool, "Other Gadget", "pack_version").empty());
    CHECK_FALSE(dim(pool, "Third Tool", "pack_version").empty());
    settle();

    // A NEW product can resolve an unnormalized title (the exact-key tier): the unnormalized
    // rows go stale, the normalized ones do not.
    REQUIRE(reg.upsert_product("nobody three:third tool", "nobody three", "third tool", "", ""));
    CHECK(dim(pool, "Third Tool", "pack_version").empty());
    CHECK_FALSE(dim(pool, "Mystery Tool", "pack_version").empty());
    CHECK_FALSE(dim(pool, "Other Gadget", "pack_version").empty());
    settle();

    // A link that is new or re-pointed: the alias key cannot be reproduced in SQL, so every row.
    REQUIRE(reg.upsert_alias("curated:windows", "other gadget", "elsewhere", *p1, "curated", 1.0));
    CHECK(dim(pool, "Mystery Tool", "pack_version").empty());
    CHECK(dim(pool, "Other Gadget", "pack_version").empty());
    CHECK(dim(pool, "Third Tool", "pack_version").empty());
}

TEST_CASE("each registry writer waits for a pass in flight and its invalidation survives the "
          "pass's stamp",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    triple(pool, "Mystery Tool", "Nobody", "windows", 7);
    REQUIRE(owner.run_pass().unnormalized == 1);
    const std::string current = scalar(
        pool, "SELECT pack_version FROM product_registry_store.normalization_pack WHERE id = 1");
    REQUIRE_FALSE(current.empty());
    // The product the alias will point at exists before the pass is parked, so the alias writer
    // is the only registry write in flight in its section.
    const auto existing =
        reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "", "");
    REQUIRE(existing.has_value());
    sql(pool, "UPDATE product_registry_store.title_dimension SET pack_version = '" + current + "'");

    // The writer under test is the ONLY registry write in each section, so each one has to take
    // the lock on its own.
    const auto section_writer = [&](const std::function<bool()>& writer) {
        // A pass in flight: this connection holds the normalisation lock inside an open
        // transaction.
        auto pass = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(pass);
        held(pass.get(), "BEGIN");
        held(pass.get(), ("SELECT pg_advisory_xact_lock(hashtextextended('" +
                          std::string(kNormalizationLockKey) + "', 0))")
                             .c_str());
        auto landed = std::async(std::launch::async, writer);
        // Wait until the writer is queued on the lock (the shared helper polls pg_stat_activity
        // for this database's advisory-lock waiters), then let the pass finish the way the race
        // does: it stamps the CURRENT version over the row it selected before the write landed,
        // and commits. COMMIT runs before any assertion so a failure cannot leave the writer
        // parked.
        const bool queued = yuzu::test::wait_for_lock_waiter(pool);
        held(pass.get(),
             ("UPDATE product_registry_store.title_dimension SET pack_version = '" + current + "'")
                 .c_str());
        held(pass.get(), "COMMIT");
        REQUIRE(queued);
        REQUIRE(landed.wait_for(std::chrono::seconds{20}) == std::future_status::ready);
        CHECK(landed.get());
        // The writer took the lock AFTER the pass: its sentinel is the last write, so it is not
        // lost.
        CHECK(dim(pool, "Mystery Tool", "pack_version").empty());
        CHECK(owner.run_pass().processed == 1);
    };

    SECTION("upsert_product") {
        // A changed attribute: the row resolved to the product goes stale. (Resolve the title
        // to the product first so a row exists to be marked.)
        REQUIRE(reg.upsert_alias("curated:windows", "mystery tool", "nobody", *existing, "curated",
                                 1.0));
        REQUIRE(owner.run_pass().processed == 1);
        sql(pool,
            "UPDATE product_registry_store.title_dimension SET pack_version = '" + current + "'");
        section_writer([&] {
            return reg.upsert_product("nobody:mystery tool", "nobody", "mystery tool", "pro", "")
                .has_value();
        });
    }
    SECTION("upsert_alias") {
        section_writer([&] {
            return reg.upsert_alias("curated:windows", "mystery tool", "nobody", *existing,
                                    "curated", 1.0);
        });
        CHECK(dim(pool, "Mystery Tool", "method") == "curated");
    }
}

TEST_CASE("a full inventory report from an agent named like the normalisation lock is not "
          "blocked by that lock",
          "[pg][product_registry][normalization]") {
    TD_ENV(db, pool, inv, reg, metrics, owner);
    auto pass = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(pass);
    held(pass.get(), "BEGIN");
    held(pass.get(), ("SELECT pg_advisory_xact_lock(hashtextextended('" +
                      std::string(kNormalizationLockKey) + "', 0))")
                         .c_str());

    // `software_normalization` is a valid agent id; its replace lock must be a different key.
    const std::vector<SoftwareEntry> rows = {{"Chrome", "119", "Google", "2026-01-01"}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    auto stored = std::async(std::launch::async, [&] {
        return inv.apply_installed_software("software_normalization", h, rows, 1000);
    });
    const auto st = stored.wait_for(std::chrono::seconds{20});
    held(pass.get(), "COMMIT"); // before any assertion, so a failure cannot leave it parked
    REQUIRE(st == std::future_status::ready);
    CHECK(stored.get() == InventoryIngestOutcome::kStored);
}
