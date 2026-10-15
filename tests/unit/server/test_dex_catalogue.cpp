/**
 * test_dex_catalogue.cpp — the Catalogue View 1 (family cards) read model,
 * `build_dex_catalogue_model` + `DexApi::catalogue` (ADR-0031 WS-A4 PR-1 /
 * catalogue decision): the first public REST/MCP resource for the per-family
 * health score / online-denominator coverage `render_dex_catalogue_fragment`
 * has always computed with no twin. Mirrors test_dex_api.cpp's template/seed
 * conventions (a separate PgTestTemplate instance per this file's own
 * convention).
 *
 * Cross-check section proves the PR-2 precondition directly: for a fixture
 * whose numbers the existing golden test (test_dex_dashboard_golden.cpp's
 * "App reliability card, window x os matrix") already pins, every value the
 * RENDERER prints for a family also appears on that family's row in the
 * MODEL — so PR-2 can render byte-identically from the model alone.
 */

#include "dex_api_local.hpp"
#include "dex_read_builders.hpp"
#include "dex_read_model.hpp"
#include "dex_routes.hpp" // render_dex_catalogue_fragment -- the cross-check oracle
#include "dex_window.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"
#include "test_dex_api_double.hpp"

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

using yuzu::server::DexFleet;
using yuzu::server::GuaranteedStateEventRow;
using yuzu::server::GuaranteedStateStore;
using yuzu::server::make_local_dex_api;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate dex_catalogue_tpl{"dexcatalogue", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("dexcatalogue template: store failed to migrate");
}};

void seed_signal(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                 const std::string& type, const std::string& detail_json, const std::string& ts) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = type;
    e.severity = "info";
    e.detail_json = detail_json;
    e.timestamp = ts;
    REQUIRE(store.insert_event(e));
}

void seed_crash(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                const std::string& proc, const std::string& plat, const std::string& ts) {
    seed_signal(store, id, agent, "process.crashed",
                "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\",\"symbolic\":"
                "\"ACCESS_VIOLATION\",\"component\":\"ntdll.dll\",\"platform\":\"" + plat + "\"}",
                ts);
}

void seed_hang(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
              const std::string& proc, const std::string& ts) {
    seed_signal(store, id, agent, "process.hung",
                "{\"subject\":\"" + proc + "\",\"symbolic\":\"NOT_RESPONDING\","
                "\"platform\":\"windows\"}",
                ts);
}

const std::string kTs = yuzu::server::dex_iso_since(2).substr(0, 10) + "T12:00:00Z";

} // namespace

// ── Builder unit tests ───────────────────────────────────────────────────────

TEST_CASE("build_dex_catalogue_model: null store degrades to zero families, honest os/window",
          "[pg][dex][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    const auto m = yuzu::server::build_dex_catalogue_model(/*store=*/nullptr, DexFleet{},
                                                            "windows", "7d");
    CHECK(m.os == "windows");
    CHECK(m.window == "7d");
    CHECK(m.total_types > 0);
    CHECK(m.monitored_types == 0);
    CHECK(m.families.empty());
    CHECK(m.uncatalogued.empty());
}

TEST_CASE("build_dex_catalogue_model: unknown/invalid os filter normalises to 'all'",
          "[pg][dex][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    const auto m =
        yuzu::server::build_dex_catalogue_model(/*store=*/nullptr, DexFleet{}, "solaris", "7d");
    CHECK(m.os == "all"); // dex_normalize_os_filter maps anything unrecognised to "" -> "all"
}

TEST_CASE("build_dex_catalogue_model: every family present exactly once, dex_signal_groups() order",
          "[pg][dex][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    const auto m = yuzu::server::build_dex_catalogue_model(&store, DexFleet{}, "all", "7d");
    REQUIRE(m.families.size() == yuzu::server::dex_signal_groups().size());
    for (std::size_t i = 0; i < m.families.size(); ++i)
        CHECK(m.families[i].name == yuzu::server::dex_signal_groups()[i].name);
}

TEST_CASE("build_dex_catalogue_model: uncatalogued lists an obs_type in no curated family",
          "[pg][dex][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    // A newer-agent obs_type not in any dex_signal_groups() family.
    seed_signal(store, "u1", "u1", "future.newsignal", "{\"platform\":\"windows\"}", kTs);

    const auto m = yuzu::server::build_dex_catalogue_model(&store, DexFleet{}, "all", "7d");
    REQUIRE(m.uncatalogued.size() == 1);
    CHECK(m.uncatalogued.front().obs_type == "future.newsignal");
    CHECK(yuzu::server::dex_family_index("future.newsignal") == -1);
}

// Fix 2 (WS-A4 PR-1 fix round, sec-5): a degraded fleet signal-summary read
// must never render as a healthy, zero-event catalogue (health 100). DROP
// TABLE forces the fleet-wide read to degrade while the store itself stays
// open — mirrors test_dex_routes.cpp's identically-shaped #4855 per-device
// degrade test.
TEST_CASE("build_dex_catalogue_model: a degraded fleet signal-summary read reports "
          "degraded=true, never a healthy zero-event catalogue",
          "[pg][dex][catalogue][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_observations")};
        REQUIRE(d.ok());
    }

    const auto m = yuzu::server::build_dex_catalogue_model(&store, DexFleet{}, "all", "7d");
    CHECK(m.degraded);
    CHECK(m.families.empty());
    CHECK(m.uncatalogued.empty());
}

TEST_CASE("DexApi::catalogue matches the shared builder (seam is a pure forward)",
          "[pg][dex][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "s1", "a1", "notepad.exe", "windows", kTs);

    const DexFleet fleet{1, 1, {"windows"}};
    auto api = make_local_dex_api(&store, [&]() { return fleet; });
    const auto via_api = api->catalogue("all", "7d");
    const auto via_builder = yuzu::server::build_dex_catalogue_model(&store, fleet, "all", "7d");
    CHECK(via_api.os == via_builder.os);
    CHECK(via_api.window == via_builder.window);
    CHECK(via_api.monitored_types == via_builder.monitored_types);
    CHECK(via_api.total_types == via_builder.total_types);
    REQUIRE(via_api.families.size() == via_builder.families.size());
    for (std::size_t i = 0; i < via_api.families.size(); ++i) {
        CHECK(via_api.families[i].events == via_builder.families[i].events);
        CHECK(via_api.families[i].health_score == via_builder.families[i].health_score);
    }
}

// ── FnDexApi double: unwired sentinel + wired passthrough ───────────────────

TEST_CASE("FnDexApi: unwired catalogue() mirrors the builder's null-store shape",
          "[dex][catalogue][double]") {
    yuzu::server::test::FnDexApi api; // every method unwired
    const auto m = api.catalogue("windows", "7d");
    CHECK(m.os == "windows");
    CHECK(m.window == "7d");
    CHECK(m.total_types > 0);
    CHECK(m.monitored_types == 0);
    CHECK(m.families.empty());
    CHECK(m.uncatalogued.empty());

    // The optional-returning methods default to the "not found/degraded" nullopt
    // sentinel, not a fabricated present value.
    CHECK_FALSE(api.observation("a1", "e1").has_value());
    CHECK_FALSE(api.catalogue_group("App reliability", "all", "7d").has_value());

    // device_score's unwired default is explicitly degraded (never a
    // fabricated healthy score) -- the ONE method whose model has a `degraded`
    // field for exactly this purpose.
    const auto score = api.device_score("a1", "7d");
    CHECK(score.score == -1);
    CHECK(score.degraded);
}

TEST_CASE("FnDexApi: wired catalogue() forwards args + result unchanged",
          "[dex][catalogue][double]") {
    yuzu::server::DexCatalogueModel canned;
    canned.os = "linux";
    canned.window = "24h";
    canned.monitored_types = 3;
    canned.total_types = 114;

    std::string seen_os, seen_window;
    yuzu::server::test::FnDexApi api(
        {}, {}, {}, {}, {},
        [&](const std::string& os, const std::string& window) {
            seen_os = os;
            seen_window = window;
            return canned;
        });
    const auto m = api.catalogue("linux", "24h");
    CHECK(seen_os == "linux");
    CHECK(seen_window == "24h");
    CHECK(m.monitored_types == 3);
    CHECK(m.total_types == 114);
}

// ── Cross-check: model carries every number the CURRENT renderer prints ─────
// (the PR-2 byte-identical-rendering precondition) — same fixture as
// test_dex_dashboard_golden.cpp's "App reliability card, window x os matrix"
// (D1 crashes twice, D2 hangs once), whose numbers (94/12-of-12/3-events on
// os=all,window=all; 2-of-12/no_data on os=linux) that golden test already
// pins independently.

TEST_CASE("DexCatalogueModel cross-check: every family-card number the renderer prints "
          "appears on the model, family-by-family",
          "[pg][dex][catalogue][crosscheck]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "c1", "dex-cc-1", "app1.exe", "windows", kTs);
    seed_crash(store, "c2", "dex-cc-1", "app1.exe", "windows",
              yuzu::server::dex_iso_since(6).substr(0, 10) + "T12:00:00Z"); // outside 24h, inside 7d/all
    seed_hang(store, "h1", "dex-cc-2", "app2.exe", kTs);

    DexFleet fleet;
    fleet.windows_online = 2;
    fleet.connected_os = {"windows"};

    auto family_row = [](const yuzu::server::DexCatalogueModel& m,
                         const std::string& name) -> const yuzu::server::DexCatalogueFamilyRow* {
        for (const auto& f : m.families)
            if (f.name == name)
                return &f;
        return nullptr;
    };

    SECTION("os=all, window=all -> health score 94, 3 events, top process.crashed") {
        const std::string html = yuzu::server::render_dex_catalogue_fragment(&store, "", 0, fleet, "all");
        REQUIRE(html.find("App reliability") != std::string::npos);
        REQUIRE(html.find("<div class=\"fev ok\">94</div>") != std::string::npos);
        REQUIRE(html.find("3 events") != std::string::npos);

        const auto m = yuzu::server::build_dex_catalogue_model(&store, fleet, "all", "all");
        const auto* row = family_row(m, "App reliability");
        REQUIRE(row != nullptr);
        CHECK(row->monitored == 12);
        CHECK(row->total == 12);
        CHECK(row->health_score == 94.0); // exact per the golden test's 12*1.0*(1/2)=6 deduction
        CHECK(row->events == 3);
        CHECK(row->top_obs_type == "process.crashed");
    }
    SECTION("os=linux -> monitored but no online denominator (no_data), score suppressed") {
        const std::string html =
            yuzu::server::render_dex_catalogue_fragment(&store, "", 0, fleet, "linux");
        REQUIRE(html.find("2 of 12 monitored") != std::string::npos);
        REQUIRE(html.find("no online agents reporting") != std::string::npos);

        const auto m = yuzu::server::build_dex_catalogue_model(&store, fleet, "linux", "all");
        const auto* row = family_row(m, "App reliability");
        REQUIRE(row != nullptr);
        CHECK(row->monitored == 2); // process.crashed/process.hung are Linux-collectible
        CHECK(row->health_score == -1.0); // no_data: monitored>0 but n_scoped (linux_online)==0
    }
}

// ── Overview additive-fields cross-check (connected_platforms, busiest_family,
//    busiest_family_events) — same "model carries what the renderer shows"
//    precondition, for DexOverviewModel's ADR-0031 WS-A4 PR-1 additions. ──

TEST_CASE("DexOverviewModel cross-check: connected_platforms + busiest_family match "
          "the renderer's coverage tile / Explore card",
          "[pg][dex][catalogue][crosscheck][overview]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_catalogue_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "o1", "dex-ov-1", "app1.exe", "windows", kTs);
    seed_crash(store, "o2", "dex-ov-1", "app1.exe", "windows", kTs);
    seed_hang(store, "o3", "dex-ov-2", "app2.exe", kTs);

    DexFleet fleet;
    fleet.windows_online = 2;
    fleet.connected_os = {"windows"};

    const std::string since = yuzu::server::dex_iso_since(7);
    const std::string html = yuzu::server::render_dex_overview_fragment(&store, since, 7, fleet);
    // The coverage tile's "N platform(s)" caption.
    REQUIRE(html.find("1 platform(s)") != std::string::npos);
    // The Explore card's busiest-family teaser (process.crashed=2 events beats
    // process.hung=1, so "App reliability" is the busiest family).
    REQUIRE(html.find("busiest <b>App reliability</b>") != std::string::npos);

    const auto m = yuzu::server::build_dex_overview_model(&store, fleet, "7d", 7, since,
                                                           /*visible=*/nullptr);
    CHECK(m.connected_platforms == 1);
    CHECK(m.busiest_family == "App reliability");
    // The busiest FAMILY's total events, not just its top single obs_type:
    // process.crashed (2) + process.hung (1), both "App reliability" members.
    CHECK(m.busiest_family_events == 3);
}
