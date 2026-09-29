// AgentDecommission cascade tests (ADR-0024 Decision 11 / roadmap D-3): the
// single decommission entry point that fans `delete_agent(agent_id)` across
// EVERY per-agent store, so an operator decommission durably erases a machine's
// stored rows — the GDPR-erasure path the per-store `delete_agent` methods could
// not deliver on their own (zero production callers before this seam).
//
// Two layers:
//   * pure fan-out logic ([decommission]) — order, counts, null-skip,
//     best-effort continue-on-throw AND continue-on-false (a non-throwing delete
//     that did not commit is Failed, not Deleted), empty-id guard — driven
//     through the `add_store` seam with recording/throwing/failing fakes (no
//     database needed);
//   * a real-store fan-out ([pg][decommission][software_licensing]) — populate
//     all six stores (all born-on-PG), decommission one agent, and assert its
//     rows are gone from EVERY store while a bystander survives, including the
//     software_licensing and app_usage stores.

#include <catch2/catch_test_macros.hpp>

#include "agent_decommission.hpp"

#include "app_perf_daily_store.hpp"
#include "device_inventory_store.hpp"
#include "inventory_ingest_outcome.hpp"
#include "inventory_store.hpp"
#include "software_inventory_store.hpp"
#include "software_licensing_store.hpp"
#include "app_usage_store.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using yuzu::server::AgentDecommission;
using yuzu::server::AgentDecommissionStores;
using yuzu::server::DecommissionOutcome;
using yuzu::server::DecommissionResult;
using yuzu::server::to_string;

namespace {

// Find one store's line in an aggregated result by name (registration order is
// asserted separately, but named lookups keep the per-store assertions legible).
const yuzu::server::DecommissionStoreResult* find_store(const DecommissionResult& r,
                                                        std::string_view name) {
    for (const auto& s : r.stores)
        if (s.store == name)
            return &s;
    return nullptr;
}

} // namespace

// ── Pure fan-out logic (no database) ─────────────────────────────────────────

TEST_CASE("AgentDecommission fans delete_agent across every registered target, in order",
          "[decommission]") {
    std::vector<std::string> seen_a;
    std::vector<std::string> seen_b;

    AgentDecommission cascade;
    cascade.add_store("alpha", [&](std::string_view id) {
        seen_a.emplace_back(id);
        return true;
    });
    cascade.add_store("beta", [&](std::string_view id) {
        seen_b.emplace_back(id);
        return true;
    });

    const auto result = cascade.decommission("agent-x");

    CHECK(result.agent_id == "agent-x");
    CHECK(result.deleted == 2);
    CHECK(result.skipped == 0);
    CHECK(result.failed == 0);
    CHECK(result.ok());

    // Every target was invoked with the right agent id.
    REQUIRE(seen_a.size() == 1);
    REQUIRE(seen_b.size() == 1);
    CHECK(seen_a[0] == "agent-x");
    CHECK(seen_b[0] == "agent-x");

    // Per-store lines are in registration order, all Deleted.
    REQUIRE(result.stores.size() == 2);
    CHECK(result.stores[0].store == "alpha");
    CHECK(result.stores[1].store == "beta");
    CHECK(result.stores[0].outcome == DecommissionOutcome::Deleted);
    CHECK(result.stores[1].outcome == DecommissionOutcome::Deleted);
}

TEST_CASE("AgentDecommission skips a null/unconfigured store without failing the others",
          "[decommission]") {
    int live_calls = 0;

    AgentDecommission cascade;
    cascade.add_store("live-before", [&](std::string_view) {
        ++live_calls;
        return true;
    });
    cascade.add_store("unconfigured", nullptr); // e.g. a store not present on this deployment
    cascade.add_store("live-after", [&](std::string_view) {
        ++live_calls;
        return true;
    });

    const auto result = cascade.decommission("agent-x");

    CHECK(result.deleted == 2);
    CHECK(result.skipped == 1);
    CHECK(result.failed == 0);
    CHECK(result.ok()); // a Skipped target is not a failure
    CHECK(live_calls == 2); // both live stores still ran

    const auto* skipped = find_store(result, "unconfigured");
    REQUIRE(skipped != nullptr);
    CHECK(skipped->outcome == DecommissionOutcome::Skipped);
    CHECK(skipped->error.empty());
}

TEST_CASE("AgentDecommission reports a single store failure but does not abort the rest",
          "[decommission]") {
    int after_calls = 0;

    SECTION("a std::exception is captured, later stores still run") {
        AgentDecommission cascade;
        cascade.add_store("ok-before", [](std::string_view) { return true; });
        cascade.add_store("boom",
                          [](std::string_view) -> bool { throw std::runtime_error("kaboom"); });
        cascade.add_store("ok-after", [&](std::string_view) {
            ++after_calls;
            return true;
        });

        const auto result = cascade.decommission("agent-x");

        CHECK(result.deleted == 2);
        CHECK(result.failed == 1);
        CHECK(result.skipped == 0);
        CHECK_FALSE(result.ok());
        CHECK(after_calls == 1); // the throw did NOT abort the fan-out

        const auto* boom = find_store(result, "boom");
        REQUIRE(boom != nullptr);
        CHECK(boom->outcome == DecommissionOutcome::Failed);
        CHECK(boom->error == "kaboom");
    }

    SECTION("a non-std throw is captured as an unknown exception") {
        AgentDecommission cascade;
        cascade.add_store("boom", [](std::string_view) -> bool { throw 42; });
        cascade.add_store("ok-after", [&](std::string_view) {
            ++after_calls;
            return true;
        });

        const auto result = cascade.decommission("agent-x");

        CHECK(result.failed == 1);
        CHECK(result.deleted == 1);
        CHECK(after_calls == 1);

        const auto* boom = find_store(result, "boom");
        REQUIRE(boom != nullptr);
        CHECK(boom->outcome == DecommissionOutcome::Failed);
        CHECK(boom->error == "unknown exception");
    }
}

// The failure mode the void-returning interface structurally could NOT express
// (and so had no test): a store whose delete_agent returns WITHOUT throwing but
// reports that the delete did not commit — the real-world transient-PG case,
// where `with_txn_for` rolls back and returns false. It MUST record Failed, not
// Deleted, so a DecommissionResult can never claim erasure that never happened.
TEST_CASE("AgentDecommission records a non-throwing false return as Failed, not Deleted",
          "[decommission]") {
    int after_calls = 0;

    AgentDecommission cascade;
    cascade.add_store("ok-before", [](std::string_view) { return true; });
    // No throw — just a truthful "the delete did not commit" (e.g. a rolled-back
    // transaction / a lease it never acquired). Under the old void interface this
    // returned normally and was unconditionally recorded Deleted.
    cascade.add_store("silent-fail", [](std::string_view) { return false; });
    cascade.add_store("ok-after", [&](std::string_view) {
        ++after_calls;
        return true;
    });

    const auto result = cascade.decommission("agent-x");

    CHECK(result.deleted == 2);
    CHECK(result.failed == 1);
    CHECK(result.skipped == 0);
    CHECK_FALSE(result.ok()); // a store that did not commit flips ok() to false
    CHECK(after_calls == 1);  // the false return did NOT abort the fan-out

    const auto* sf = find_store(result, "silent-fail");
    REQUIRE(sf != nullptr);
    CHECK(sf->outcome == DecommissionOutcome::Failed); // NOT Deleted
    CHECK_FALSE(sf->error.empty());                    // a diagnostic is recorded
}

TEST_CASE("AgentDecommission treats an empty agent_id as a no-op — nothing is invoked",
          "[decommission]") {
    int calls = 0;

    AgentDecommission cascade;
    cascade.add_store("a", [&](std::string_view) {
        ++calls;
        return true;
    });
    cascade.add_store("b", [&](std::string_view) {
        ++calls;
        return true;
    });

    const auto result = cascade.decommission("");

    CHECK(calls == 0); // never touch a store with an empty id (no WHERE agent_id = '')
    CHECK(result.deleted == 0);
    CHECK(result.failed == 0);
    CHECK(result.skipped == cascade.target_count());
    CHECK(result.ok());
    for (const auto& s : result.stores)
        CHECK(s.outcome == DecommissionOutcome::Skipped);
}

TEST_CASE("AgentDecommission null-store constructor registers every store as Skipped",
          "[decommission]") {
    // The all-null construction (a deployment that configured no per-agent
    // stores) fans to nothing but still audits one line per store.
    AgentDecommission cascade{AgentDecommissionStores{}};
    CHECK(cascade.target_count() == 6); // inventory + 5 typed projections

    const auto result = cascade.decommission("agent-x");
    CHECK(result.deleted == 0);
    CHECK(result.failed == 0);
    CHECK(result.skipped == 6);
    // The Decision-11 store is present in the audit even when unconfigured.
    const auto* sl = find_store(result, "software_licensing");
    REQUIRE(sl != nullptr);
    CHECK(sl->outcome == DecommissionOutcome::Skipped);
}

TEST_CASE("DecommissionOutcome renders stable audit tags", "[decommission]") {
    CHECK(std::string_view(to_string(DecommissionOutcome::Deleted)) == "deleted");
    CHECK(std::string_view(to_string(DecommissionOutcome::Skipped)) == "skipped");
    CHECK(std::string_view(to_string(DecommissionOutcome::Failed)) == "failed");
}

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp) covering every
// store this file's [pg] tests construct — a store-behaviour test clones an
// already-migrated database instead of re-running the migrations.
yuzu::test::PgTestTemplate decommission_tpl{"decommission", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::InventoryStore inventory{pool};
    yuzu::server::SoftwareInventoryStore software_inventory{pool};
    yuzu::server::AppPerfDailyStore app_perf_daily{pool};
    yuzu::server::DeviceInventoryStore device_inventory{pool};
    yuzu::server::SoftwareLicensingStore software_licensing{pool};
    yuzu::server::AppUsageStore app_usage{pool};
    if (!inventory.is_open() || !software_inventory.is_open() || !app_perf_daily.is_open() ||
        !device_inventory.is_open() || !software_licensing.is_open() || !app_usage.is_open())
        throw std::runtime_error("decommission template: a store failed to migrate");
}};
} // namespace

// Directly exercise InventoryStore::delete_agent's new empty-id guard and bool
// commit-status return. The cascade short-circuits an empty id to all-Skipped
// before any deleter runs, so this guard is the store-level belt-and-braces
// that is otherwise reached by no test.
TEST_CASE("InventoryStore::delete_agent guards an empty id and reports commit status",
          "[pg][decommission][inventory]") {
    YUZU_REQUIRE_PG_DB_TPL(db, decommission_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    yuzu::server::InventoryStore inv{pool};
    REQUIRE(inv.is_open());
    inv.upsert("agent-x", "installed_software", R"({"seed":"1"})", 1000);

    // Empty id: guarded — never a `WHERE agent_id = ''` — reports false (no
    // commit), and the real row is untouched.
    CHECK_FALSE(inv.delete_agent(""));
    auto got = inv.get_agent_inventory("agent-x");
    REQUIRE(got.has_value()); // store open + query OK, not a degrade
    CHECK_FALSE(got->empty());

    // A real delete commits → true, and the row is gone.
    CHECK(inv.delete_agent("agent-x"));
    got = inv.get_agent_inventory("agent-x");
    REQUIRE(got.has_value());
    CHECK(got->empty());

    // Idempotent: a 0-row delete of an already-erased agent still commits → true.
    CHECK(inv.delete_agent("agent-x"));
}

// ── Real-store fan-out (all born-on-Postgres) ────────────────────────────────

namespace {

std::int64_t today_utc_midnight() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return (now / 86400) * 86400;
}

// Populate one agent across all five stores. `tag` distinguishes the target
// agent from the bystander so the assertions can prove agent-scoping.
void seed_agent(const std::string& agent_id, yuzu::server::InventoryStore& inv,
                yuzu::server::SoftwareInventoryStore& soft,
                yuzu::server::AppPerfDailyStore& perf,
                yuzu::server::DeviceInventoryStore& dev,
                yuzu::server::SoftwareLicensingStore& lic,
                yuzu::server::AppUsageStore& usage) {
    using yuzu::server::AgentLicenseRow;
    using yuzu::server::AppPerfDailyRow;
    using yuzu::server::DeviceCiRecord;
    using yuzu::server::InventoryIngestOutcome;
    using yuzu::server::SoftwareEntry;

    // Generic SQLite inventory.
    inv.upsert(agent_id, "installed_software", R"({"seed":"1"})", 1000);

    // Typed installed-software projection.
    std::vector<SoftwareEntry> sw = {{"Chrome", "119", "Google", "2026-01-01"}};
    const std::string sh = yuzu::server::SoftwareInventoryStore::canonical_hash(sw);
    REQUIRE(soft.apply_installed_software(agent_id, sh, sw, 1000) ==
            InventoryIngestOutcome::kStored);

    // Per-device app-perf daily.
    const std::int64_t day = today_utc_midnight() - 86400; // completed day, within retention
    std::vector<AppPerfDailyRow> pr = {{.app_name = "chrome.exe",
                                        .version = "119.0.0.0",
                                        .day = day,
                                        .samples = 100,
                                        .instances_max = 8,
                                        .cpu_avg = 15.0,
                                        .cpu_max = 60.0,
                                        .ws_avg_bytes = 1000,
                                        .ws_max_bytes = 2000}};
    REQUIRE(perf.apply_daily(agent_id, pr));

    // Device-CI (1:1 per agent).
    DeviceCiRecord ci;
    ci.hostname = "host-" + agent_id;
    ci.system_uuid = "uuid-" + agent_id;
    REQUIRE(dev.apply_device_ci(agent_id, "cihash-" + agent_id,
                                std::optional<DeviceCiRecord>{ci}, 1000) ==
            InventoryIngestOutcome::kStored);

    // Detected licences — carrying the Decision-11 per-user `user_ref` row that
    // is the reason the cascade must reach this store.
    AgentLicenseRow lr;
    lr.product = "Office 365 ProPlus";
    lr.state = "licensed";
    lr.user_scope = "user";
    lr.user_ref = "a1b2c3d4e5f60718"; // keyed-HMAC pseudonym — personal data (Recital 26)
    REQUIRE(lic.replace_agent_licenses(agent_id, {lr}, "lichash-" + agent_id, "hash"));

    // Per-executable last-used app-usage row (Wave 7 PR7.2) — the sixth store.
    using yuzu::server::AgentLastUsedRow;
    AgentLastUsedRow ur;
    ur.exe_key = "chrome.exe";
    ur.first_seen = 1000;
    ur.last_seen = 2000;
    ur.run_count_30d = 5;
    ur.total_seconds_30d = 600;
    REQUIRE(usage.replace_agent_last_used(agent_id, {ur}, "usagehash-" + agent_id, 2000));
}

} // namespace

TEST_CASE("AgentDecommission erases an agent from every real store; a bystander survives",
          "[pg][decommission][software_licensing]") {
    YUZU_REQUIRE_PG_DB_TPL(db, decommission_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    REQUIRE(pool.valid());

    yuzu::server::InventoryStore inventory{pool};
    REQUIRE(inventory.is_open());

    yuzu::server::SoftwareInventoryStore software_inventory{pool};
    yuzu::server::AppPerfDailyStore app_perf_daily{pool};
    yuzu::server::DeviceInventoryStore device_inventory{pool};
    yuzu::server::SoftwareLicensingStore software_licensing{pool};
    yuzu::server::AppUsageStore app_usage{pool};
    REQUIRE(software_inventory.is_open());
    REQUIRE(app_perf_daily.is_open());
    REQUIRE(device_inventory.is_open());
    REQUIRE(software_licensing.is_open());
    REQUIRE(app_usage.is_open());

    seed_agent("agent-del", inventory, software_inventory, app_perf_daily, device_inventory,
               software_licensing, app_usage);
    seed_agent("agent-bystander", inventory, software_inventory, app_perf_daily, device_inventory,
               software_licensing, app_usage);

    AgentDecommission cascade{AgentDecommissionStores{
        .inventory = &inventory,
        .software_inventory = &software_inventory,
        .app_perf_daily = &app_perf_daily,
        .device_inventory = &device_inventory,
        .software_licensing = &software_licensing,
        .app_usage = &app_usage,
    }};

    const auto result = cascade.decommission("agent-del");

    // One decommission call fanned to all six stores, all Deleted.
    CHECK(result.deleted == 6);
    CHECK(result.skipped == 0);
    CHECK(result.failed == 0);
    CHECK(result.ok());
    const auto* sl = find_store(result, "software_licensing");
    REQUIRE(sl != nullptr);
    CHECK(sl->outcome == DecommissionOutcome::Deleted); // the SLE store IS included
    const auto* au = find_store(result, "app_usage");
    REQUIRE(au != nullptr);
    CHECK(au->outcome == DecommissionOutcome::Deleted); // the app_usage store IS included

    // agent-del is gone from EVERY store.
    auto inv_del = inventory.get_agent_inventory("agent-del");
    REQUIRE(inv_del.has_value()); // store open + query OK → empty value, not a degrade
    CHECK(inv_del->empty());

    auto soft_del = software_inventory.get_agent_software("agent-del");
    REQUIRE(soft_del.has_value()); // store open + query OK → empty value, not a degrade
    CHECK(soft_del->empty());

    auto perf_del = app_perf_daily.get_agent_app_perf("agent-del");
    REQUIRE(perf_del.has_value());
    CHECK(perf_del->empty());

    auto ci_del = device_inventory.get_device_ci("agent-del");
    REQUIRE(ci_del.has_value());        // no read degrade
    CHECK_FALSE(ci_del->has_value());   // record absent

    auto lic_del = software_licensing.agent_licenses("agent-del");
    REQUIRE(lic_del.has_value());
    CHECK(lic_del->empty());
    auto lic_hash = software_licensing.stored_hash("agent-del");
    REQUIRE(lic_hash.has_value());
    CHECK_FALSE(lic_hash->has_value()); // state row gone

    // The bystander is untouched in EVERY store (agent-scoped deletes).
    auto inv_by = inventory.get_agent_inventory("agent-bystander");
    REQUIRE(inv_by.has_value());
    CHECK_FALSE(inv_by->empty());

    auto soft_by = software_inventory.get_agent_software("agent-bystander");
    REQUIRE(soft_by.has_value());
    CHECK(soft_by->size() == 1);

    auto perf_by = app_perf_daily.get_agent_app_perf("agent-bystander");
    REQUIRE(perf_by.has_value());
    CHECK(perf_by->size() == 1);

    auto ci_by = device_inventory.get_device_ci("agent-bystander");
    REQUIRE(ci_by.has_value());
    CHECK(ci_by->has_value());

    auto lic_by = software_licensing.agent_licenses("agent-bystander");
    REQUIRE(lic_by.has_value());
    CHECK(lic_by->size() == 1);

    auto usage_del = app_usage.get_agent_last_used("agent-del");
    REQUIRE(usage_del.has_value());
    CHECK(usage_del->empty());
    auto usage_hash = app_usage.stored_hash("agent-del");
    REQUIRE(usage_hash.has_value());
    CHECK_FALSE(usage_hash->has_value()); // state row gone

    auto usage_by = app_usage.get_agent_last_used("agent-bystander");
    REQUIRE(usage_by.has_value());
    CHECK(usage_by->size() == 1);
}

TEST_CASE("AgentDecommission over real stores skips an unconfigured store, still erases the rest",
          "[pg][decommission][software_licensing]") {
    YUZU_REQUIRE_PG_DB_TPL(db, decommission_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    REQUIRE(pool.valid());

    yuzu::server::SoftwareLicensingStore software_licensing{pool};
    REQUIRE(software_licensing.is_open());

    yuzu::server::AgentLicenseRow lr;
    lr.product = "Office";
    lr.state = "licensed";
    lr.user_scope = "user";
    lr.user_ref = "deadbeefdeadbeef";
    REQUIRE(software_licensing.replace_agent_licenses("agent-del", {lr}, "h", "hash"));

    // A deployment with ONLY the licensing store configured (e.g. the other
    // per-agent stores are absent): every null store is skipped, the live one is
    // still erased, and the fan-out reports ok().
    AgentDecommission cascade{AgentDecommissionStores{
        .software_licensing = &software_licensing,
    }};

    const auto result = cascade.decommission("agent-del");
    CHECK(result.deleted == 1);
    CHECK(result.skipped == 5);
    CHECK(result.failed == 0);
    CHECK(result.ok());

    auto post = software_licensing.agent_licenses("agent-del");
    REQUIRE(post.has_value());
    CHECK(post->empty());
}

// ─────────────────────────── DRIFT GUARD (the root cause) ───────────────────────
//
// The erasure route's authorization gate is now the single, fixed securable
// `Decommission:Delete` (ADR-0024 Decision 9, amended Wave 7 PR7.2) — it no longer
// changes as stores are added, which is the whole point of the promotion. But the
// securable being fixed does NOT mean the blast radius is: adding a
// store still widens what ONE Decommission:Delete grant destroys, so this test
// ties the store list to the documented radius instead of to a conjunction.
//
// This test is the tie. It fails the moment a store joins AgentDecommissionStores,
// forcing whoever adds it to answer: is the new store's governing securable's READ
// listed in the blast-radius docs (sle_routes.hpp/.cpp, rest_api_v1.cpp's delete
// block, ADR-0024 Decisions 9/11, rest-api.md)?
//
// If you are here because this test failed:
//   1. Update kCascadeStoreCount below.
//   2. Add the store to the blast-radius lists in sle_routes.hpp/.cpp,
//      agent_decommission.hpp, the OpenAPI `delete` block in rest_api_v1.cpp, and
//      ADR-0024 Decisions 9/11 — naming the securable that governs its READ.
//   3. The gate itself (`Decommission:Delete`) does NOT change — that is the
//      reversal this promotion delivered.
TEST_CASE("decommission cascade: store list is pinned to the DELETE route's documented radius",
          "[decommission][authz]") {
    // Every store null → all registered targets report Skipped, so target_count()
    // is the cascade's registered-store count without needing a live store.
    AgentDecommission cascade{AgentDecommissionStores{}};

    constexpr std::size_t kCascadeStoreCount = 6; // inventory, software_inventory,
                                                  // app_perf_daily, device_inventory,
                                                  // software_licensing, app_usage
    CHECK(cascade.target_count() == kCascadeStoreCount);

    const auto result = cascade.decommission("agent-x");
    CHECK(result.skipped == kCascadeStoreCount);
    CHECK(result.deleted == 0);
    CHECK(result.failed == 0);
}
