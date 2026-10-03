/**
 * test_dex_perf_api.cpp — the SIXTH per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4), the DEX app-perf-over-time
 * sequel to `dex` (DEX signals, PR #4582). `LocalDexPerfApi` (dex_perf_api.cpp)
 * wraps the B1 (`AppPerfDailyStore`)/B2 (`AppPerfFleetStore`)/
 * `AppPerfGroupReader` reads behind the `DexPerfApi` seam. Each case asserts
 * PARITY with the direct store/pure-transform read it wraps, plus the
 * null-store degrade. Reached only through the public `DexPerfApi` interface +
 * the `make_local_dex_perf_api` factory (`LocalDexPerfApi` is private to
 * dex_perf_api.cpp).
 *
 * Coverage note (disclosed, not silent — mirrors the DEX signals seam's own
 * partial-coverage precedent): `apps`/`app_fleet_trend`/`app_version_devices`/
 * `device_app_perf_json`/`device_app_summaries`/`fleet_snapshot` are
 * parity-tested against seeded B1/B2 data. `group_trend`/`tag_trend` are
 * covered for the null-reader/null-store degrade AND, since the sec-1/qa-2
 * governance follow-up, for the REAL member-resolution + kDexCohortFloor
 * composition — seeding a live ManagementGroupStore/TagStore + AppPerfDailyStore
 * + AppPerfGroupReader through LocalDexPerfApi itself, proving a sub-floor
 * named group/tagged cohort is floored (count only) and an at-floor one is
 * not, at the SAME seam the route-level test double
 * (`test_dex_routes.cpp`'s "kDexCohortFloor suppresses a sub-floor point")
 * re-implements the floor over. `AppPerfGroupReader`'s own member-filter SQL
 * correctness (the ANY($1::text[]) filter, the histogram aggregate) stays
 * `test_app_perf_group_reader.cpp`'s job — not re-proven here.
 * The REST/MCP consumer rewire landed in the same change as this seam (see
 * `dex_perf_api.hpp`'s "Consumer rewire status" note); the dashboard
 * fragments were rewired in a follow-up (#4626, GAP-2 added
 * `device_app_summaries` for the dashboard's per-device drill). This file's
 * own scope is the seam's parity contract, not end-to-end REST/MCP/dashboard
 * coverage (that's `test_rest_dex_app_perf_devices.cpp` / `test_mcp_server.cpp`
 * / `test_dex_routes.cpp`, which exercise the rewired handlers).
 */

#include "dex_perf_api_local.hpp"

#include "app_perf_daily_store.hpp"
#include "app_perf_fleet_store.hpp"
#include "app_perf_group_reader.hpp"
#include "app_perf_rollup.hpp"
#include "dex_app_perf_builders.hpp" // app_perf_fleet_trend parity oracle
#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::AppPerfFleetStore;
using yuzu::server::AppPerfGroupReader;
using yuzu::server::AppPerfRollup;
using yuzu::server::DexPerfSnapshot;
using yuzu::server::make_local_dex_perf_api;
using yuzu::server::ManagementGroup;
using yuzu::server::ManagementGroupStore;
using yuzu::server::TagStore;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate dex_perf_api_tpl{"dexperfapi", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AppPerfDailyStore daily{pool};
    AppPerfFleetStore fleet{pool};
    AppPerfRollup rollup{pool};
    if (!daily.is_open() || !fleet.is_open())
        throw std::runtime_error("dexperfapi template: store failed to migrate");
    // Pre-migrated for the group_trend()/tag_trend() real-impl floor test
    // below (LocalDexPerfApi::group_trend resolves members via
    // ManagementGroupStore, tag_trend via TagStore, BEFORE the B1 aggregate
    // read) — additive, harmless to every other test using this template.
    ManagementGroupStore mgmt{pool};
    TagStore tags{pool};
    if (!mgmt.is_open() || !tags.is_open())
        throw std::runtime_error("dexperfapi template: mgmt/tag store failed to migrate");
}};

std::int64_t today_utc() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return (now / 86400) * 86400;
}

void seed_b1(AppPerfDailyStore& b1, const std::string& agent, const std::string& app,
            const std::string& ver, std::int64_t day, double cpu_avg, std::int64_t ws_avg) {
    std::vector<AppPerfDailyRow> rows = {{.app_name = app, .version = ver, .day = day,
                                         .samples = 10, .instances_max = 1, .cpu_avg = cpu_avg,
                                         .cpu_max = cpu_avg, .ws_avg_bytes = ws_avg,
                                         .ws_max_bytes = ws_avg}};
    REQUIRE(b1.apply_daily(agent, rows));
}

} // namespace

TEST_CASE("DexPerfApi apps() parity + null-store degrade", "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfFleetStore b2{pool};
    AppPerfRollup rollup{pool};
    REQUIRE(b1.is_open());
    REQUIRE(b2.is_open());

    const std::int64_t day = today_utc() - 86400;
    seed_b1(b1, "agent-1", "chrome.exe", "124.0.0.0", day, 5.0, 100000000);
    REQUIRE(rollup.roll_day(day));

    auto api = make_local_dex_perf_api({}, &b2, &b1, nullptr, nullptr, nullptr);

    bool truncated_direct = false, truncated_seam = false;
    auto direct = b2.list_apps(truncated_direct);
    auto seam = api->apps(truncated_seam);
    REQUIRE(direct.has_value());
    REQUIRE(seam.has_value());
    REQUIRE(seam->size() == direct->size());
    CHECK(truncated_seam == truncated_direct);
    REQUIRE(!seam->empty());
    CHECK((*seam)[0].app_name == (*direct)[0].app_name);
    CHECK((*seam)[0].versions == (*direct)[0].versions);
    CHECK((*seam)[0].last_day == (*direct)[0].last_day);

    // null-store degrade
    auto degraded = make_local_dex_perf_api({}, nullptr, nullptr, nullptr, nullptr, nullptr);
    bool t = false;
    CHECK_FALSE(degraded->apps(t).has_value());
}

TEST_CASE("DexPerfApi app_fleet_trend() parity + floor suppression + null-store degrade",
         "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfFleetStore b2{pool};
    AppPerfRollup rollup{pool};
    REQUIRE(b1.is_open());
    REQUIRE(b2.is_open());

    const std::int64_t day = today_utc() - 86400;
    // 2 devices — below kDexCohortFloor (10), so the seam's floor must suppress.
    seed_b1(b1, "agent-1", "chrome.exe", "124.0.0.0", day, 5.0, 100000000);
    seed_b1(b1, "agent-2", "chrome.exe", "124.0.0.0", day, 7.0, 120000000);
    REQUIRE(rollup.roll_day(day));

    auto api = make_local_dex_perf_api({}, &b2, &b1, nullptr, nullptr, nullptr);

    auto rows = b2.get_app_fleet_perf("chrome.exe", "124.0.0.0");
    REQUIRE(rows.has_value());
    auto direct = yuzu::server::app_perf_fleet_trend(*rows); // the exact PURE transform the seam wraps
    auto seam = api->app_fleet_trend("chrome.exe", "124.0.0.0");
    REQUIRE(seam.has_value());
    REQUIRE(seam->size() == direct.size());
    REQUIRE(!seam->empty());
    CHECK((*seam)[0].version == direct[0].version);
    CHECK((*seam)[0].device_count == direct[0].device_count);
    CHECK((*seam)[0].suppressed == direct[0].suppressed);
    // Below-floor: BOTH the direct transform and the seam must suppress —
    // proves the seam did not skip the floor gate.
    CHECK((*seam)[0].suppressed);
    CHECK((*seam)[0].device_count == 2);

    auto degraded = make_local_dex_perf_api({}, nullptr, nullptr, nullptr, nullptr, nullptr);
    CHECK_FALSE(degraded->app_fleet_trend("chrome.exe", "124.0.0.0").has_value());
}

TEST_CASE("DexPerfApi app_version_devices() parity (floor-free) + confinement + null-store",
         "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    REQUIRE(b1.is_open());

    const std::int64_t day = today_utc() - 86400;
    seed_b1(b1, "agent-1", "chrome.exe", "124.0.0.0", day, 9.0, 100000000);
    seed_b1(b1, "agent-2", "chrome.exe", "124.0.0.0", day, 3.0, 50000000);

    auto api = make_local_dex_perf_api({}, nullptr, &b1, nullptr, nullptr, nullptr);

    bool truncated_direct = false, truncated_seam = false;
    auto direct = b1.list_devices_for_version("chrome.exe", "124.0.0.0", std::nullopt,
                                              truncated_direct);
    auto seam = api->app_version_devices("chrome.exe", "124.0.0.0", std::nullopt, truncated_seam);
    REQUIRE(direct.has_value());
    REQUIRE(seam.has_value());
    REQUIRE(seam->size() == 2);
    REQUIRE(seam->size() == direct->size());
    CHECK((*seam)[0].agent_id == (*direct)[0].agent_id);
    CHECK((*seam)[0].cpu_avg == (*direct)[0].cpu_avg);

    // ADR-0017 confinement: an engaged, narrower visible set must restrict the
    // SQL, not post-filter — proves the seam threads visible_agent_ids through.
    bool t2 = false;
    auto confined = api->app_version_devices(
        "chrome.exe", "124.0.0.0", std::vector<std::string>{"agent-1"}, t2);
    REQUIRE(confined.has_value());
    REQUIRE(confined->size() == 1);
    CHECK((*confined)[0].agent_id == "agent-1");

    // present-but-empty = deny-all (ADR-0017), not unfiltered.
    bool t3 = false;
    auto denied = api->app_version_devices("chrome.exe", "124.0.0.0",
                                           std::vector<std::string>{}, t3);
    REQUIRE(denied.has_value());
    CHECK(denied->empty());

    auto degraded = make_local_dex_perf_api({}, nullptr, nullptr, nullptr, nullptr, nullptr);
    bool t4 = false;
    CHECK_FALSE(degraded->app_version_devices("chrome.exe", "124.0.0.0", std::nullopt, t4)
                    .has_value());
}

TEST_CASE("DexPerfApi device_app_perf_json() parity + null-store degrade", "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    REQUIRE(b1.is_open());

    const std::int64_t day = today_utc() - 86400;
    seed_b1(b1, "agent-1", "chrome.exe", "124.0.0.0", day, 9.0, 100000000);
    seed_b1(b1, "agent-1", "explorer.exe", "10.0.19045", day, 1.5, 20000000);

    auto api = make_local_dex_perf_api({}, nullptr, &b1, nullptr, nullptr, nullptr);

    auto rows = b1.get_agent_app_perf("agent-1");
    REQUIRE(rows.has_value());
    const auto direct_json = yuzu::server::dex_device_app_perf_json("agent-1", "", *rows);
    auto seam_json = api->device_app_perf_json("agent-1", "");
    REQUIRE(seam_json.has_value());
    CHECK(*seam_json == direct_json);

    // filtered
    const auto direct_filtered = yuzu::server::dex_device_app_perf_json("agent-1", "chrome.exe",
                                                                        *rows);
    auto seam_filtered = api->device_app_perf_json("agent-1", "chrome.exe");
    REQUIRE(seam_filtered.has_value());
    CHECK(*seam_filtered == direct_filtered);

    auto degraded = make_local_dex_perf_api({}, nullptr, nullptr, nullptr, nullptr, nullptr);
    CHECK_FALSE(degraded->device_app_perf_json("agent-1", "").has_value());
}

// GAP-2 (#4626): device_app_summaries() is the summary-shaped twin of
// device_app_perf_json above, added for the /fragments/dex/device/app-perf
// dashboard drill. Parity-tested against the SAME direct app_perf_device_summaries
// pure transform device_app_perf_json's own parity test uses for
// dex_device_app_perf_json — proving both seam methods agree with the pure
// reductions over the identical raw B1 read, never with each other directly.
TEST_CASE("DexPerfApi device_app_summaries() parity + null-store degrade", "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    REQUIRE(b1.is_open());

    const std::int64_t day = today_utc() - 86400;
    seed_b1(b1, "agent-1", "chrome.exe", "124.0.0.0", day, 9.0, 100000000);
    seed_b1(b1, "agent-1", "explorer.exe", "10.0.19045", day, 1.5, 20000000);

    auto api = make_local_dex_perf_api({}, nullptr, &b1, nullptr, nullptr, nullptr);

    auto rows = b1.get_agent_app_perf("agent-1");
    REQUIRE(rows.has_value());
    const auto direct = yuzu::server::app_perf_device_summaries(*rows);
    auto seam = api->device_app_summaries("agent-1");
    REQUIRE(seam.has_value());
    REQUIRE(seam->size() == direct.size());
    REQUIRE(seam->size() == 2);
    CHECK((*seam)[0].app_name == direct[0].app_name);
    CHECK((*seam)[0].peak_cpu_avg == direct[0].peak_cpu_avg);
    REQUIRE(!(*seam)[0].versions.empty());
    CHECK((*seam)[0].versions[0].cpu_avg == direct[0].versions[0].cpu_avg);

    auto degraded = make_local_dex_perf_api({}, nullptr, nullptr, nullptr, nullptr, nullptr);
    CHECK_FALSE(degraded->device_app_summaries("agent-1").has_value());
}

TEST_CASE("DexPerfApi fleet_snapshot() empty-DexPerfFn degrade", "[dex_perf_api]") {
    // No PG needed: fleet_snapshot's only behaviour is the null-DexPerfFn
    // degrade contract (an empty fn -> default DexPerfSnapshot{}), matching
    // the pre-seam handlers' own `dex_perf_fn ? dex_perf_fn(key) :
    // DexPerfSnapshot{}` tolerance.
    auto api = make_local_dex_perf_api({}, nullptr, nullptr, nullptr, nullptr, nullptr);
    const auto snap = api->fleet_snapshot("model");
    CHECK(snap.devices.empty());
    CHECK(snap.available_keys.empty());
}

TEST_CASE("DexPerfApi group_trend()/tag_trend() null-reader degrade", "[dex_perf_api]") {
    // The REAL group_trend()/tag_trend() composition (ManagementGroupStore/
    // TagStore member resolution + AppPerfGroupReader aggregate + the SAME
    // kDexCohortFloor gate app_fleet_trend uses) is exercised below, in
    // "DexPerfApi group_trend()/tag_trend() REAL member resolution +
    // kDexCohortFloor" — this case covers only the null-reader/null-store
    // degrade path.
    auto api = make_local_dex_perf_api({}, nullptr, nullptr, nullptr, nullptr, nullptr);
    CHECK_FALSE(api->group_trend("g1", "chrome.exe", "124.0.0.0").has_value());
    CHECK_FALSE(api->tag_trend("model", "laptop-x", "chrome.exe", "124.0.0.0").has_value());
}

// #1762: a degraded ManagementGroupStore member-resolution read must fail
// group_trend() closed to nullopt, never render as an empty trend
// (indistinguishable from a genuinely empty/unknown group). No live database
// needed — an invalid pool makes ManagementGroupStore::is_open() false, so
// get_members_checked() degrades before group_trend ever reaches the B1
// aggregate reader.
TEST_CASE("DexPerfApi group_trend() fails closed on a degraded member-resolution "
         "read (#1762)",
         "[dex_perf_api]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    ManagementGroupStore mgmt{pool};
    REQUIRE(!mgmt.is_open());
    AppPerfGroupReader reader{pool};

    auto api = make_local_dex_perf_api({}, nullptr, nullptr, &reader, &mgmt, nullptr);
    CHECK_FALSE(api->group_trend("g1", "chrome.exe", "124.0.0.0").has_value());
}

// Real-impl PG coverage for group_trend()/tag_trend() — the seam's OWN
// ManagementGroupStore::get_members()/TagStore::agents_with_tag() member
// resolution + AppPerfGroupReader::get_group_trend() aggregate + the SAME
// kDexCohortFloor gate app_fleet_trend applies, all exercised through
// LocalDexPerfApi (not a raw AppPerfGroupReader/store call, and not the
// FnDexPerfApi test double the route-level floor test
// (test_dex_routes.cpp's "kDexCohortFloor suppresses a sub-floor point")
// re-implements the floor over). Closes the gap sec-1/qa-2 flagged: the real
// LocalDexPerfApi::group_trend/tag_trend composition previously had zero PG
// coverage of its own.
TEST_CASE("DexPerfApi group_trend()/tag_trend() REAL member resolution + kDexCohortFloor",
         "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfGroupReader reader{pool};
    ManagementGroupStore mgmt{pool};
    TagStore tags{pool};
    REQUIRE(b1.is_open());
    REQUIRE(mgmt.is_open());
    REQUIRE(tags.is_open());

    auto api = make_local_dex_perf_api({}, nullptr, &b1, &reader, &mgmt, &tags);
    const std::int64_t day = today_utc() - 86400;

    SECTION("group_trend: sub-floor member count suppresses (count only, metrics withheld)") {
        ManagementGroup g;
        g.name = "SubFloorGroup";
        g.membership_type = "static";
        auto group_id = mgmt.create_group(g);
        REQUIRE(group_id.has_value());
        // 3 members — below kDexCohortFloor (10).
        for (const char* a : {"gsub-1", "gsub-2", "gsub-3"}) {
            REQUIRE(mgmt.add_member(*group_id, a).has_value());
            seed_b1(b1, a, "chrome.exe", "124.0.0.0", day, 5.0, 100000000);
        }
        auto trend = api->group_trend(*group_id, "chrome.exe", "124.0.0.0");
        REQUIRE(trend.has_value());
        REQUIRE(!trend->empty());
        CHECK((*trend)[0].device_count == 3);
        CHECK((*trend)[0].suppressed);
        // Suppressed clears the exact mean — the real single-device value
        // (5.0%) must never reach a caller for a sub-floor named group.
        CHECK((*trend)[0].cpu_mean == 0.0);
    }

    SECTION("group_trend: at-floor member count passes (real metrics visible)") {
        ManagementGroup g;
        g.name = "AtFloorGroup";
        g.membership_type = "static";
        auto group_id = mgmt.create_group(g);
        REQUIRE(group_id.has_value());
        // 10 members == kDexCohortFloor: passes, not suppressed.
        for (int i = 0; i < 10; ++i) {
            const std::string a = "gfloor-" + std::to_string(i);
            REQUIRE(mgmt.add_member(*group_id, a).has_value());
            seed_b1(b1, a, "chrome.exe", "124.0.0.0", day, 8.0, 100000000);
        }
        auto trend = api->group_trend(*group_id, "chrome.exe", "124.0.0.0");
        REQUIRE(trend.has_value());
        REQUIRE(!trend->empty());
        CHECK((*trend)[0].device_count == 10);
        CHECK_FALSE((*trend)[0].suppressed);
        CHECK((*trend)[0].cpu_mean > 0.0); // real mean survives once at floor
    }

    SECTION("tag_trend: sub-floor tagged cohort suppresses (count only, metrics withheld)") {
        for (const char* a : {"tsub-1", "tsub-2"}) {
            REQUIRE(tags.set_tag(a, "model", "Latitude5420").has_value());
            seed_b1(b1, a, "chrome.exe", "124.0.0.0", day, 6.0, 100000000);
        }
        auto trend = api->tag_trend("model", "Latitude5420", "chrome.exe", "124.0.0.0");
        REQUIRE(trend.has_value());
        REQUIRE(!trend->empty());
        CHECK((*trend)[0].device_count == 2);
        CHECK((*trend)[0].suppressed);
        CHECK((*trend)[0].cpu_mean == 0.0);
    }

    SECTION("tag_trend: at-floor tagged cohort passes (real metrics visible)") {
        for (int i = 0; i < 10; ++i) {
            const std::string a = "tfloor-" + std::to_string(i);
            REQUIRE(tags.set_tag(a, "model", "Latitude7420").has_value());
            seed_b1(b1, a, "chrome.exe", "124.0.0.0", day, 12.0, 100000000);
        }
        auto trend = api->tag_trend("model", "Latitude7420", "chrome.exe", "124.0.0.0");
        REQUIRE(trend.has_value());
        REQUIRE(!trend->empty());
        CHECK((*trend)[0].device_count == 10);
        CHECK_FALSE((*trend)[0].suppressed);
        CHECK((*trend)[0].cpu_mean > 0.0);
    }
}
