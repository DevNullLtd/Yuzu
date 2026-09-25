/**
 * test_dex_api.cpp — the FIFTH per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4), copying the
 * `verify_api`/`test_verify_api.cpp` template. `LocalDexApi` (dex_api.cpp) is
 * the DEX signals/experience-score assembly moved behind the `DexApi` seam:
 * the 9 builder-backed resources forward to the shared `build_dex_*_model`
 * helpers (deriving `since`/`fleet` internally), and the 3 builder-less ones
 * (signals/scope/signal_detail) make the same raw store reads the handler
 * assembled inline. Each case asserts the seam is behaviour-preserving —
 * PARITY with the direct builder/store read it wraps — plus the null-store
 * degrade. Reached only through the public `DexApi` interface + the
 * `make_local_dex_api` factory, exactly as a real presentation/MCP caller
 * will use it (`LocalDexApi` is private to dex_api.cpp).
 */

#include "dex_api_local.hpp"

#include "dex_read_builders.hpp"        // build_dex_*_model parity oracles (store-reaching)
#include "dex_read_model.hpp"          // the pure model structs
#include "dex_routes.hpp"              // dex_iso_since / dex_window_to_days
#include "guaranteed_state_store.hpp"  // seed + direct-read parity oracles
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"              // PgConn/PgResult -- the DROP-TABLE degrade tests below

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

using yuzu::server::build_dex_device_score_model;
using yuzu::server::DexFleet;
using yuzu::server::GuaranteedStateEventRow;
using yuzu::server::GuaranteedStateStore;
using yuzu::server::make_local_dex_api;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate dex_api_tpl{"dexapi", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("dexapi template: store failed to migrate");
}};

void seed_crash(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                const std::string& proc, const std::string& plat, const std::string& ts) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = "process.crashed";
    e.severity = "info";
    e.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\",\"symbolic\":"
                    "\"ACCESS_VIOLATION\",\"component\":\"ntdll.dll\",\"platform\":\"" + plat +
                    "\"}";
    e.timestamp = ts;
    REQUIRE(store.insert_event(e));
}

// Seed dates anchored a few days back from *now* so they stay inside the
// default 7d window (same rationale as test_dex_routes.cpp's kDayA/kDayB).
const std::string kTs = yuzu::server::dex_iso_since(2).substr(0, 10) + "T12:00:00Z";

} // namespace

TEST_CASE("DexApi: null store is the honest degrade, never a throw", "[pg][dex_api]") {
    // The macro gates on PG availability (skip locally when unset), but this
    // case exercises the null-store path — no seeding needed.
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    auto api = make_local_dex_api(/*store=*/nullptr, /*fleet_fn=*/{});

    CHECK(api->signals("7d", "").empty());
    CHECK(api->scope("7d").empty());
    const auto detail = api->signal_detail("process.crashed", "7d", "", 50);
    CHECK(detail.subjects.empty());
    CHECK(detail.by_os.empty());
    CHECK(detail.devices.empty());
    CHECK(detail.by_day.empty());
    // Builder-backed degrade: score unavailable, empty model — never a crash.
    CHECK(api->device_score("a1", "7d").score == -1);
    CHECK(api->apps("7d").apps.empty());
}

TEST_CASE("DexApi: signals/scope/signal_detail match the direct store reads", "[pg][dex_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "e1", "a1", "notepad.exe", "windows", kTs);
    seed_crash(store, "e2", "a2", "notepad.exe", "windows", kTs);

    auto api = make_local_dex_api(&store, {});
    const std::string since = yuzu::server::dex_iso_since(yuzu::server::dex_window_to_days("7d"));

    // signals == store.dex_signal_summary(since, "")
    const auto via_api = api->signals("7d", "");
    const auto via_store = store.dex_signal_summary(since, "");
    REQUIRE(via_api.size() == via_store.size());
    REQUIRE_FALSE(via_api.empty());
    CHECK(via_api.front().obs_type == via_store.front().obs_type);
    CHECK(via_api.front().count == via_store.front().count);
    CHECK(via_api.front().distinct_devices == via_store.front().distinct_devices);

    // scope == store.dex_os_signal_scope(since)
    CHECK(api->scope("7d").size() == store.dex_os_signal_scope(since).size());

    // signal_detail bundles the four raw reads unchanged
    const auto detail = api->signal_detail("process.crashed", "7d", "", 50);
    CHECK(detail.subjects.size() == store.dex_signal_subjects("process.crashed", since, 50, "").size());
    CHECK(detail.devices.size() == store.dex_signal_devices("process.crashed", since, 50, "").size());
    CHECK(detail.by_day.size() == store.dex_signal_by_day("process.crashed", since, "").size());
    // notepad.exe crashed on two devices -> the most-affected list names both
    CHECK(detail.devices.size() == 2);
}

TEST_CASE("DexApi: device_score matches the shared builder (seam is a pure forward)",
          "[pg][dex_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "e1", "a1", "notepad.exe", "windows", kTs);

    auto api = make_local_dex_api(&store, {});
    const std::string since = yuzu::server::dex_iso_since(yuzu::server::dex_window_to_days("7d"));

    const auto via_api = api->device_score("a1", "7d");
    const auto via_builder = build_dex_device_score_model(&store, "a1", "7d", since);
    CHECK(via_api.agent_id == via_builder.agent_id);
    CHECK(via_api.window == via_builder.window);
    CHECK(via_api.score == via_builder.score);
    CHECK(via_api.signals.size() == via_builder.signals.size());
    CHECK_FALSE(via_api.degraded);
}

// #4855: a WIRED store whose signal-summary read DEGRADES (not merely
// null/unopened) must render score=-1, signals empty AND degraded=true —
// the pre-fix bug was exactly this case reading as a perfectly healthy
// score-100 with no signals. DROP TABLE on a second connection forces a
// genuine query-level failure while the store itself stays open (same
// technique test_guardian_routes.cpp uses for the Guardian census reads).
TEST_CASE("DexApi: device_score on a degraded signal-summary read reports "
          "score=-1 and degraded=true, never a fabricated healthy score",
          "[pg][dex_api][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "e1", "a1", "notepad.exe", "windows", kTs);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_observations")};
        REQUIRE(d.ok());
    }

    auto api = make_local_dex_api(&store, {});
    const auto via_api = api->device_score("a1", "7d");
    CHECK(via_api.score == -1);
    CHECK(via_api.signals.empty());
    CHECK(via_api.degraded);

    // The pure dex_device_score(...) oracle the health-fragment/overview
    // per-device loops call must ALSO report -1 on this same degrade, not
    // just the builder above (closing the same bug on the fleet-scale path).
    const std::string since = yuzu::server::dex_iso_since(yuzu::server::dex_window_to_days("7d"));
    CHECK(yuzu::server::dex_device_score(&store, "a1", since) == -1);
}

TEST_CASE("DexApi: fleet-dependent reads use the injected FleetFn", "[pg][dex_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    // A non-empty fleet denominator flows through health()/trends()/overview();
    // an empty FleetFn degrades to DexFleet{} (the honest no-data denominator).
    bool fleet_called = false;
    auto api = make_local_dex_api(&store, [&]() -> DexFleet {
        fleet_called = true;
        return DexFleet{1, 1, {"windows"}};
    });
    (void)api->overview("7d", /*visible=*/nullptr);
    CHECK(fleet_called); // the seam obtains the fleet from the injected FleetFn
}

// Direct DexApi-level parity for the remaining builder-backed methods — each
// seam method output equals the corresponding build_dex_*_model(store,...)
// output on the same seeded data (the [dex] REST suite covers these
// indirectly; this matches the verify template's method-level parity). The
// fleet-dependent methods use the SAME fixed DexFleet the builder is handed.
TEST_CASE("DexApi: builder-backed methods match their shared builders", "[pg][dex_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "e1", "a1", "notepad.exe", "windows", kTs);
    seed_crash(store, "e2", "a2", "notepad.exe", "windows", kTs);

    const DexFleet fleet{1, 1, {"windows"}};
    auto api = make_local_dex_api(&store, [&]() { return fleet; });
    const std::string w = "7d";
    const std::string since = yuzu::server::dex_iso_since(yuzu::server::dex_window_to_days(w));

    SECTION("device_history") {
        const auto a = api->device_history("a1", w);
        const auto b = yuzu::server::build_dex_device_history_model(&store, "a1", w, since);
        CHECK(a.agent_id == b.agent_id);
        CHECK(a.window == b.window);
        CHECK(a.history.size() == b.history.size());
    }
    SECTION("observation") {
        const auto a = api->observation("a1", "e1");
        const auto b = yuzu::server::build_dex_observation_model(&store, "a1", "e1");
        REQUIRE(a.has_value() == b.has_value());
        if (a)
            CHECK(a->event_id == b->event_id);
        // A foreign/absent event_id resolves to nullopt on both paths.
        CHECK_FALSE(api->observation("a2", "e1").has_value()); // e1 belongs to a1
    }
    SECTION("app") {
        const auto a = api->app("notepad.exe", w, /*visible=*/nullptr);
        const auto b = yuzu::server::build_dex_app_model(&store, "notepad.exe", w, since, nullptr);
        CHECK(a.process_name == b.process_name);
        CHECK(a.devices.size() == b.devices.size());
        CHECK(a.modules.size() == b.modules.size());
    }
    SECTION("catalogue_group") {
        // "App reliability" is a real dex_signal_groups() family (process.crashed
        // is a member), so both paths return a present model.
        const auto a = api->catalogue_group("App reliability", "all", w);
        const auto b = yuzu::server::build_dex_catalogue_group_model(&store, "App reliability",
                                                                     "all", fleet, w, since);
        REQUIRE(a.has_value() == b.has_value());
        if (a) {
            CHECK(a->group_name == b->group_name);
            CHECK(a->total_type_count == b->total_type_count);
        }
        // An unknown family is nullopt on both.
        CHECK_FALSE(api->catalogue_group("no-such-family", "all", w).has_value());
    }
    SECTION("health") {
        const auto a = api->health("default", w);
        const auto b = yuzu::server::build_dex_health_model(&store, fleet, "default", w, since);
        CHECK(a.score == b.score);
        CHECK(a.reporting == b.reporting);
        CHECK(a.band == b.band);
    }
    SECTION("trends") {
        const auto a = api->trends(w);
        const auto b = yuzu::server::build_dex_trends_model(&store, fleet, w, since);
        CHECK(a.window == b.window);
        CHECK(a.days.size() == b.days.size());
        CHECK(a.families.size() == b.families.size());
    }
}
