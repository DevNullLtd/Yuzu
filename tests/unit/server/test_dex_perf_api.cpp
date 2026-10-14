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
#include "dex_app_version_failures_owner.hpp"
#include "dex_window.hpp"
#include "guaranteed_state_store.hpp"
#include "management_group_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <libpq-fe.h>
#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::AppPerfFleetStore;
using yuzu::server::AppPerfGroupReader;
using yuzu::server::AppPerfRollup;
using yuzu::server::AppPerfVersionFailureRow;
using yuzu::server::DexAppVersionFailuresOwner;
using yuzu::server::GuaranteedStateEventRow;
using yuzu::server::GuaranteedStateStore;
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
    // The per-version failure read (DexAppVersionFailuresOwner) joins the crash and
    // hang observations in this store's schema with B1's.
    GuaranteedStateStore gss{pool};
    if (!gss.is_open())
        throw std::runtime_error("dexperfapi template: guaranteed-state store failed to migrate");
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

// ── Per-version crash and hang join (DexAppVersionFailuresOwner + app_fleet_report) ──

namespace {

using Catch::Approx;

// One ruleless crash or hang observation for `app` at `version` on `agent`.
void seed_obs(GuaranteedStateStore& gss, const std::string& id, const std::string& agent,
              const std::string& app, const std::string& version, const char* type,
              std::int64_t at_epoch) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = type;
    e.severity = "info";
    e.detail_json =
        nlohmann::json{{"subject", app}, {"version", version}, {"platform", "windows"}}.dump();
    e.timestamp = yuzu::server::dex_iso_at(at_epoch);
    REQUIRE(gss.insert_event(e));
}

std::string aid(int i) { return std::string("a") + (i < 10 ? "0" : "") + std::to_string(i); }

// The shared two-version fixture. Exposure (B1): a01..a15 on 125.0.0.0, a01..a12 on
// 124.0.0.0. Events on chrome.exe, all inside the window:
//   125: 10 crashes + 2 hangs, all on exposed devices a01..a07  (7 affected)
//   124: 4 crashes + 1 hang on exposed a01..a03, PLUS 3 crashes on x01/x02 and 1 hang on
//        x03, none of which have B1 rows                          (6 affected: x03 only hung)
// a01 and a02 both crashed and hung, so per-type device counts do not add up to the affected
// devices. a01 also has a second B1 day (exposure counts a device once) and exposed a10 has a
// decoy observation type. A decoy subject and a version outside the requested list also must
// not count.
// `today` is the caller's one reading of the UTC midnight, so a seed, a window cut
// and a rollup can never straddle a midnight between two clock reads.
void seed_two_version_fixture(AppPerfDailyStore& b1, GuaranteedStateStore& gss,
                              std::int64_t today) {
    const std::int64_t day = today - 86400;
    const std::int64_t at = today - 2 * 86400;
    for (int i = 1; i <= 15; ++i)
        seed_b1(b1, aid(i), "chrome.exe", "125.0.0.0", day, 5.0, 100000000);
    for (int i = 1; i <= 12; ++i)
        seed_b1(b1, aid(i), "chrome.exe", "124.0.0.0", day, 4.0, 90000000);
    seed_b1(b1, aid(1), "chrome.exe", "125.0.0.0", day - 86400, 5.0, 100000000);

    int n = 0;
    auto ev = [&](const std::string& agent, const std::string& app, const std::string& ver,
                  const char* type, std::int64_t when) {
        seed_obs(gss, "e" + std::to_string(++n), agent, app, ver, type, when);
    };
    for (int i = 1; i <= 7; ++i)
        ev(aid(i), "chrome.exe", "125.0.0.0", "process.crashed", at); // 7 crashes
    for (int i = 1; i <= 3; ++i)
        ev(aid(i), "chrome.exe", "125.0.0.0", "process.crashed", at + 60); // +3 = 10
    ev(aid(1), "chrome.exe", "125.0.0.0", "process.hung", at);
    ev(aid(2), "chrome.exe", "125.0.0.0", "process.hung", at); // 2 hangs

    ev(aid(1), "chrome.exe", "124.0.0.0", "process.crashed", at);
    ev(aid(1), "chrome.exe", "124.0.0.0", "process.crashed", at + 60);
    ev(aid(2), "chrome.exe", "124.0.0.0", "process.crashed", at);
    ev(aid(3), "chrome.exe", "124.0.0.0", "process.crashed", at); // 4 exposed crashes
    ev(aid(1), "chrome.exe", "124.0.0.0", "process.hung", at);    // 1 exposed hang
    ev("x01", "chrome.exe", "124.0.0.0", "process.crashed", at);
    ev("x01", "chrome.exe", "124.0.0.0", "process.crashed", at + 60);
    ev("x02", "chrome.exe", "124.0.0.0", "process.crashed", at); // 3 unexposed crashes
    ev("x03", "chrome.exe", "124.0.0.0", "process.hung", at);    // a hang-only, unexposed device
    ev(aid(10), "chrome.exe", "125.0.0.0", "process.started", at); // decoy observation type

    ev(aid(1), "other.exe", "125.0.0.0", "process.crashed", at);   // decoy subject
    ev(aid(1), "chrome.exe", "126.0.0.0", "process.crashed", at);  // version not requested
}

const AppPerfVersionFailureRow* find_row(const std::vector<AppPerfVersionFailureRow>& rows,
                                         const std::string& v) {
    for (const auto& r : rows)
        if (r.version == v)
            return &r;
    return nullptr;
}

} // namespace

TEST_CASE("DexAppVersionFailuresOwner counts exposed and unexposed events per version",
          "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    GuaranteedStateStore gss{pool};
    REQUIRE(b1.is_open());
    REQUIRE(gss.is_open());
    const std::int64_t today = today_utc();
    seed_two_version_fixture(b1, gss, today);
    // A repeat hang on an unexposed and on an exposed device: events exceed devices per type.
    seed_obs(gss, "h2", "x03", "chrome.exe", "124.0.0.0", "process.hung", today - 2 * 86400 + 60);
    seed_obs(gss, "h3", aid(1), "chrome.exe", "124.0.0.0", "process.hung", today - 2 * 86400 + 60);

    DexAppVersionFailuresOwner owner{pool, 0};
    const std::int64_t since_day = today - 30 * 86400;
    auto rows = owner.read("chrome.exe", {"124.0.0.0", "125.0.0.0"}, since_day, today,
                           yuzu::server::dex_iso_at(since_day));
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2); // the decoy subject and the unrequested version are absent

    const auto* v125 = find_row(*rows, "125.0.0.0");
    REQUIRE(v125);
    CHECK(v125->exposure_devices == 15);
    CHECK(v125->crashes == 10);
    CHECK(v125->hangs == 2);
    CHECK(v125->affected_devices == 7);
    CHECK(v125->exposed_crashes == 10);
    CHECK(v125->exposed_hangs == 2);

    const auto* v124 = find_row(*rows, "124.0.0.0");
    REQUIRE(v124);
    CHECK(v124->exposure_devices == 12);
    CHECK(v124->crashes == 7);   // 4 on exposed devices + 3 on unexposed ones
    CHECK(v124->hangs == 4);     // 2 more repeat hangs: events exceed devices
    CHECK(v124->affected_devices == 6); // a01-a03, x01, x02 crashed; x03 only hung
    CHECK(v124->exposed_crashes == 4); // only the exposed devices feed the rate
    CHECK(v124->exposed_hangs == 2);

    // A version list that names only one version returns only that one.
    auto only = owner.read("chrome.exe", {"125.0.0.0"}, since_day, today,
                           yuzu::server::dex_iso_at(since_day));
    REQUIRE(only.has_value());
    CHECK(only->size() == 1);
}

TEST_CASE("DexAppVersionFailuresOwner cuts events and exposure at the same window",
          "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    GuaranteedStateStore gss{pool};
    REQUIRE(b1.is_open());
    REQUIRE(gss.is_open());

    const std::int64_t today = today_utc();
    const std::int64_t since_day = today - 3 * 86400;
    const std::string since_iso = yuzu::server::dex_iso_at(since_day);
    DexAppVersionFailuresOwner owner{pool, 0};

    // Inside the window: one exposed device with one crash.
    seed_b1(b1, "in-1", "app.exe", "1.0.0.0", today - 86400, 3.0, 1000);
    seed_obs(gss, "w1", "in-1", "app.exe", "1.0.0.0", "process.crashed", today - 86400);
    // Events before the cut do not count.
    seed_obs(gss, "w2", "in-1", "app.exe", "1.0.0.0", "process.crashed", since_day - 86400);
    // Nor does a future-dated one, which the exposure side's upper bound would
    // otherwise leave unmatched in the numerator (a device clock running ahead).
    seed_obs(gss, "w4", "in-1", "app.exe", "1.0.0.0", "process.crashed", today + 2 * 86400);
    seed_obs(gss, "w5", "in-1", "app.exe", "1.0.0.0", "process.hung", today + 30 * 86400);
    // A device whose only B1 rows predate since_day is not exposed.
    seed_b1(b1, "old-1", "app.exe", "1.0.0.0", today - 5 * 86400, 3.0, 1000);
    // A forward-slack B1 day (tomorrow) must not count as exposure; the end day itself does.
    seed_b1(b1, "future-1", "app.exe", "1.0.0.0", today + 86400, 3.0, 1000);
    seed_b1(b1, "end-1", "app.exe", "1.0.0.0", today, 3.0, 1000);

    auto rows = owner.read("app.exe", {"1.0.0.0"}, since_day, today, since_iso);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().exposure_devices == 2); // in-1 and the device on the end day
    CHECK(rows->front().crashes == 1);
    CHECK(rows->front().hangs == 0);
    CHECK(rows->front().exposed_crashes == 1);
    CHECK(rows->front().exposed_hangs == 0);
    CHECK(rows->front().affected_devices == 1);

    // Unknown exposure: a version with events but no B1 rows is null, never zero.
    seed_obs(gss, "w3", "ghost-1", "app.exe", "9.0.0.0", "process.hung", today - 86400);
    auto ghost = owner.read("app.exe", {"9.0.0.0"}, since_day, today, since_iso);
    REQUIRE(ghost.has_value());
    REQUIRE(ghost->size() == 1);
    CHECK_FALSE(ghost->front().exposure_devices.has_value());
    CHECK(ghost->front().hangs == 1);
    CHECK(ghost->front().exposed_hangs == 0);

    // Exposure with no events still reports the version, with zero events.
    seed_b1(b1, "quiet-1", "app.exe", "2.0.0.0", today - 86400, 3.0, 1000);
    auto quiet = owner.read("app.exe", {"2.0.0.0"}, since_day, today, since_iso);
    REQUIRE(quiet.has_value());
    REQUIRE(quiet->size() == 1);
    CHECK(quiet->front().exposure_devices == 1);
    CHECK(quiet->front().crashes == 0);
    CHECK(quiet->front().affected_devices == 0);
}

TEST_CASE("DexAppVersionFailuresOwner separates an empty answer from a degrade",
          "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DexAppVersionFailuresOwner owner{pool, 0};
    const std::int64_t today = today_utc();
    const std::string iso = yuzu::server::dex_iso_at(today - 86400);

    // Preconditions that cannot match anything: engaged and empty, no query run.
    auto no_app = owner.read("", {"1.0.0.0"}, today - 86400, today, iso);
    REQUIRE(no_app.has_value());
    CHECK(no_app->empty());
    auto no_versions = owner.read("app.exe", {}, today - 86400, today, iso);
    REQUIRE(no_versions.has_value());
    CHECK(no_versions->empty());
    // A real query over an application with no rows is engaged and empty too.
    auto none = owner.read("nothing.exe", {"1.0.0.0"}, today - 86400, today, iso);
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("DexAppVersionFailuresOwner degrades to nullopt on an unreachable pool",
          "[dex_perf_api]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    REQUIRE_FALSE(pool.valid());
    DexAppVersionFailuresOwner owner{pool, 0};
    const std::int64_t today = today_utc();
    CHECK_FALSE(owner.read("app.exe", {"1.0.0.0"}, today - 86400, today,
                           yuzu::server::dex_iso_at(today - 86400))
                    .has_value());
}

TEST_CASE("DexAppVersionFailuresOwner degrades when no connection can be had",
          "[pg][dex_perf_api]") {
    // A saturated pool clamps the owner's bounded acquire to the pool's fast-fail
    // (pg_pool.hpp, Options::saturated_fast_fail), so the outcome is fixed while the
    // test holds the only lease: no sleep, no elapsed-time assertion; the read costs up to 0.5 s
    // waiting out that fast-fail.
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    DexAppVersionFailuresOwner owner{pool, 0};
    const std::int64_t today = today_utc();
    const std::string iso = yuzu::server::dex_iso_at(today - 86400);

    {
        auto held = pool.try_acquire_for(std::chrono::seconds(5));
        REQUIRE(held);
        CHECK_FALSE(owner.read("app.exe", {"1.0.0.0"}, today - 86400, today, iso).has_value());
    }
    // Lease returned: the same read is engaged again (empty, nothing seeded).
    auto after = owner.read("app.exe", {"1.0.0.0"}, today - 86400, today, iso);
    REQUIRE(after.has_value());
    CHECK(after->empty());
}

TEST_CASE("DexAppVersionFailuresOwner degrades when the statement is blocked",
          "[pg][dex_perf_api]") {
    // A second connection holds an ACCESS EXCLUSIVE lock on the exposure table and the
    // pool's lock_timeout is short, so the owner's SELECT fails with a real SQLSTATE
    // 55P03 (the approval-manager precedent: no sleep, no retry loop). The owner's own
    // 10 s SET LOCAL statement_timeout is deliberately NOT exercised: proving it fires
    // costs at least 10 s of wall clock per run, which the unit suites do not spend; it
    // is the same bounded-transaction idiom AppPerfRollup uses.
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    DexAppVersionFailuresOwner owner{pool, 0};
    const std::int64_t today = today_utc();
    const std::string iso = yuzu::server::dex_iso_at(today - 86400);

    yuzu::server::pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(),
                "LOCK TABLE app_perf_daily_store.app_perf_daily IN ACCESS EXCLUSIVE MODE",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    CHECK_FALSE(owner.read("app.exe", {"1.0.0.0"}, today - 86400, today, iso).has_value());

    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    locker.reset();
    CHECK(owner.read("app.exe", {"1.0.0.0"}, today - 86400, today, iso).has_value());
}

TEST_CASE("DexPerfApi app_fleet_report() passes the clamped window into the failure read",
          "[pg][dex_perf_api]") {
    // Retention 7 clamps the window to 6 days (one less than retention, so no counted day
    // has lost events to the reaper). A device and an event exactly at the cut count; one
    // a day earlier does not. A window one day wider, one day narrower or left unclamped
    // at 30 changes the counts below.
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfFleetStore b2{pool};
    AppPerfRollup rollup{pool};
    GuaranteedStateStore gss{pool};
    REQUIRE(b1.is_open());
    REQUIRE(b2.is_open());
    REQUIRE(gss.is_open());

    const std::int64_t today = today_utc();
    const std::int64_t since_day = today - 6 * 86400;
    seed_b1(b1, "at-cut", "app.exe", "1.0.0.0", since_day, 3.0, 1000);
    seed_obs(gss, "c1", "at-cut", "app.exe", "1.0.0.0", "process.crashed", since_day);
    seed_b1(b1, "before-cut", "app.exe", "1.0.0.0", since_day - 86400, 3.0, 1000);
    seed_obs(gss, "c2", "before-cut", "app.exe", "1.0.0.0", "process.crashed", since_day - 86400);
    seed_b1(b1, "future", "app.exe", "1.0.0.0", today + 86400, 3.0, 1000); // forward slack
    REQUIRE(rollup.roll_day(since_day)); // gives the report its one version

    DexAppVersionFailuresOwner owner{pool, 7};
    auto api = make_local_dex_perf_api({}, &b2, &b1, nullptr, nullptr, nullptr, &owner);
    auto rep = api->app_fleet_report("app.exe", "");
    // The production read takes its own clock: if the UTC day is unchanged after it, the read
    // and the seeding shared a day and the cut is exact; otherwise decline, do not assert.
    if (today_utc() != today)
        SKIP("UTC midnight passed between seeding and the read: the cut cannot be asserted");
    REQUIRE(rep.has_value());
    CHECK(rep->failure_window_days == 6);
    REQUIRE(rep->versions.size() == 1);
    const auto& v = rep->versions[0];
    CHECK(v.exposure_devices == 1);  // at-cut only
    CHECK(v.affected_devices == 1);  // the crash at the cut only
}

TEST_CASE("DexAppVersionFailuresOwner window clamps to the observation retention",
          "[dex_perf_api]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    CHECK(DexAppVersionFailuresOwner{pool, 0}.failure_window_days() == 30);
    CHECK(DexAppVersionFailuresOwner{pool, -1}.failure_window_days() == 30);
    CHECK(DexAppVersionFailuresOwner{pool, 1}.failure_window_days() == 0); // today only
    CHECK(DexAppVersionFailuresOwner{pool, 7}.failure_window_days() == 6);
    CHECK(DexAppVersionFailuresOwner{pool, 30}.failure_window_days() == 29);
    CHECK(DexAppVersionFailuresOwner{pool, 31}.failure_window_days() == 30);
    CHECK(DexAppVersionFailuresOwner{pool, 90}.failure_window_days() == 30);
}

TEST_CASE("DexPerfApi app_fleet_report() joins crashes and hangs and exposure per version",
          "[pg][dex_perf_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_perf_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfFleetStore b2{pool};
    AppPerfRollup rollup{pool};
    GuaranteedStateStore gss{pool};
    REQUIRE(b1.is_open());
    REQUIRE(b2.is_open());
    REQUIRE(gss.is_open());
    const std::int64_t today = today_utc();
    seed_two_version_fixture(b1, gss, today);
    const std::int64_t day = today - 86400;
    // A third version on only 3 devices: its performance point is suppressed and its
    // figures are published all the same (the join carries no device floor).
    for (int i = 1; i <= 3; ++i)
        seed_b1(b1, aid(i), "chrome.exe", "126.0.0.0", day, 2.0, 80000000);
    // A crash stamped in the future on an exposed 125 device must not enter any figure.
    seed_obs(gss, "fut1", aid(1), "chrome.exe", "125.0.0.0", "process.crashed",
             today + 2 * 86400);
    REQUIRE(rollup.roll_day(day));

    DexAppVersionFailuresOwner owner{pool, 0};
    auto api = make_local_dex_perf_api({}, &b2, &b1, nullptr, nullptr, nullptr, &owner);

    auto rep = api->app_fleet_report("chrome.exe", "");
    REQUIRE(rep.has_value());
    CHECK(rep->failure_window_days == 30);
    CHECK(rep->stat_failures == 0);
    REQUIRE(rep->versions.size() == 3);
    CHECK(rep->versions[0].perf.version == "126.0.0.0");
    CHECK(rep->versions[1].perf.version == "125.0.0.0");
    CHECK(rep->versions[2].perf.version == "124.0.0.0");

    // 126: 3 exposure devices; its one crash (a01) is published with its exposed
    // figure and rate, and the ratio against 125 stands, at any device count.
    const auto& v126 = rep->versions[0];
    CHECK(v126.perf.suppressed);
    CHECK(v126.perf.device_count == 3);
    CHECK(v126.exposure_devices == 3);
    CHECK(v126.affected_devices == 1);
    CHECK(v126.crashes == 1);
    CHECK(v126.hangs == 0);
    CHECK(v126.exposed_crashes == 1);
    CHECK(v126.exposed_hangs == 0);
    REQUIRE(v126.failure_rate.has_value());
    CHECK(v126.failure_rate->estimate == Approx(1.0 / 3.0));
    CHECK(v126.previous_version == "125.0.0.0");
    REQUIRE(v126.failure_rate_ratio.has_value());
    // (1/3) / (12/15): the 3-device arm is published, not withheld.
    CHECK(v126.failure_rate_ratio->estimate == Approx((1.0 / 3.0) / (12.0 / 15.0)));

    const auto& v125 = rep->versions[1];
    CHECK(v125.exposure_devices == 15);
    // Fleet-wide counts are always present; the future-dated crash is excluded.
    CHECK(v125.affected_devices == 7);
    CHECK(v125.crashes == 10);
    CHECK(v125.hangs == 2);
    CHECK(v125.exposed_crashes == 10);
    CHECK(v125.exposed_hangs == 2);
    REQUIRE(v125.failure_rate.has_value());
    // 12 exposed events over 15 exposed devices; exact Poisson bounds derived offline
    // from the CDFs (6.2005751 / 15 and 20.9615850 / 15).
    CHECK(v125.failure_rate->estimate == Approx(0.8));
    CHECK(v125.failure_rate->lower == Approx(0.4133717).epsilon(1e-3));
    CHECK(v125.failure_rate->upper == Approx(1.3974390).epsilon(1e-3));
    CHECK(v125.previous_version == "124.0.0.0");
    REQUIRE(v125.failure_rate_ratio.has_value());
    // (12/15) / (5/12) = 1.92; the 3 unexposed crashes on 124 do not enter the
    // denominator arm. Clopper-Pearson bounds derived offline.
    CHECK(v125.failure_rate_ratio->estimate == Approx(1.92));
    CHECK(v125.failure_rate_ratio->lower == Approx(0.6296367).epsilon(1e-3));
    CHECK(v125.failure_rate_ratio->upper == Approx(6.9567849).epsilon(1e-3));

    const auto& v124 = rep->versions[2];
    CHECK(v124.exposure_devices == 12);
    CHECK(v124.affected_devices == 6); // 3 exposed + 3 unexposed reporting devices
    CHECK(v124.crashes == 7);          // 4 exposed + 3 unexposed: published, not withheld
    CHECK(v124.hangs == 2);            // a01 (exposed) and the hang-only x03
    CHECK(v124.exposed_crashes == 4);
    CHECK(v124.exposed_hangs == 1);
    CHECK(v124.previous_version.empty());
    CHECK_FALSE(v124.failure_rate_ratio.has_value());

    // Parity: the points are exactly app_fleet_trend's, element for element.
    auto trend = api->app_fleet_trend("chrome.exe", "");
    REQUIRE(trend.has_value());
    REQUIRE(trend->size() == rep->points.size());
    for (std::size_t i = 0; i < trend->size(); ++i) {
        CHECK((*trend)[i].version == rep->points[i].version);
        CHECK((*trend)[i].day == rep->points[i].day);
        CHECK((*trend)[i].device_count == rep->points[i].device_count);
        CHECK((*trend)[i].suppressed == rep->points[i].suppressed);
    }

    // One exact version: a one-row report with no previous to compare.
    auto one = api->app_fleet_report("chrome.exe", "125.0.0.0");
    REQUIRE(one.has_value());
    REQUIRE(one->versions.size() == 1);
    CHECK(one->versions[0].previous_version.empty());
    CHECK_FALSE(one->versions[0].failure_rate_ratio.has_value());
    CHECK(one->versions[0].exposure_devices == 15);
}

TEST_CASE("DexPerfApi app_fleet_report() degrades without an owner while the trend still serves",
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
    seed_b1(b1, "agent-1", "chrome.exe", "124.0.0.0", day, 5.0, 100000000);
    REQUIRE(rollup.roll_day(day));

    auto api = make_local_dex_perf_api({}, &b2, &b1, nullptr, nullptr, nullptr);
    CHECK_FALSE(api->app_fleet_report("chrome.exe", "").has_value());
    CHECK(api->app_fleet_trend("chrome.exe", "").has_value());

    // The failure read itself degrading (an unreachable pool) degrades the report,
    // never a report with an empty versions list.
    PgPool dead{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    DexAppVersionFailuresOwner dead_owner{dead, 0};
    auto api2 = make_local_dex_perf_api({}, &b2, &b1, nullptr, nullptr, nullptr, &dead_owner);
    CHECK_FALSE(api2->app_fleet_report("chrome.exe", "").has_value());
    CHECK(api2->app_fleet_trend("chrome.exe", "").has_value());

    // A null B2 store degrades the report too.
    auto api3 = make_local_dex_perf_api({}, nullptr, &b1, nullptr, nullptr, nullptr, &dead_owner);
    CHECK_FALSE(api3->app_fleet_report("chrome.exe", "").has_value());
}
