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

#include <algorithm>
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

// Like seed_crash, but any observation type and a reported app file version.
void seed_obs_v(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                const std::string& proc, const std::string& type, const std::string& version,
                const std::string& ts) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = type;
    e.severity = "info";
    e.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\",\"symbolic\":"
                    "\"ACCESS_VIOLATION\",\"component\":\"ntdll.dll\",\"platform\":\"windows\","
                    "\"version\":\"" + version + "\"}";
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
    CHECK(api->apps("7d").degraded); // a null store is a degrade, never an empty healthy list
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

// WS-A4 PR-1 Gate 7 fix round (arch-1/sec8-1/sec8-2,
// "aggregates GLOBAL-ONLY"): signal_detail's `visible` post-limit filter
// (ADR-0031 WS-A4 PR-1 decision 3) was REMOVED, permanently — there is no
// confinement-scope concept left on this method to engage or refuse.
// REST/MCP gate this resource on the bare `GuaranteedState:Read`
// permission (a global grant; with RBAC off, any authenticated non-service/non-engine session only; round-3 revert,
// never `fleet_read_fn`) plus their own service-scoped-token denial, since
// subjects/by_os/by_day stay fleet-wide aggregates a per-row devices[]
// filter can never confine (ADR-0017 INV-3). The former "confines
// devices[] to the visible set, post-limit" test asserted exactly the
// removed parameter and is gone with it — see dex_api.hpp's own doc
// comment on `signal_detail` for the full rationale.

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
    (void)api->overview("7d");
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
        const auto a = api->app("notepad.exe", w);
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

// ── Apps read: per application and per version ───────────────────────────────
//
// Seeded events (all platform windows, inside the 7d window), FleetFn
// windows_online = 20:
//   app.exe     1.0.0.0  a1: 1 crash + 1 hang     a2: 1 crash
//               2.0.0.0  a2: 1 crash   a3: 6 crashes (capped at 5)   a4: 1 crash
//   aardvark.exe 1.0     b1: 1 crash   (lexically first, least active)
// Hand-computed for app.exe: crashes 10, hangs 1, devices 4 (a2 is in both
// versions and counts once), capped crash sum 1+2+5+1 = 9, capped hangs 1.
// 2.0.0.0: 3 devices, 8 crashes, capped 1+5+1 = 7. 1.0.0.0: 2 devices,
// 2 crashes + 1 hang.
namespace {
void seed_apps_fixture(GuaranteedStateStore& store) {
    int n = 0;
    auto id = [&] { return "ap" + std::to_string(++n); };
    seed_obs_v(store, id(), "a1", "app.exe", "process.crashed", "1.0.0.0", kTs);
    seed_obs_v(store, id(), "a1", "app.exe", "process.hung", "1.0.0.0", kTs);
    seed_obs_v(store, id(), "a2", "app.exe", "process.crashed", "1.0.0.0", kTs);
    seed_obs_v(store, id(), "a2", "app.exe", "process.crashed", "2.0.0.0", kTs);
    for (int i = 0; i < 6; ++i)
        seed_obs_v(store, id(), "a3", "app.exe", "process.crashed", "2.0.0.0", kTs);
    seed_obs_v(store, id(), "a4", "app.exe", "process.crashed", "2.0.0.0", kTs);
    seed_obs_v(store, id(), "b1", "aardvark.exe", "process.crashed", "1.0", kTs);
}
} // namespace

TEST_CASE("DexApi: apps carries per-version figures, activity order and the population",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);

    auto api = make_local_dex_api(&store, [] {
        DexFleet f;
        f.windows_online = 20;
        return f;
    });
    const auto m = api->apps("7d");
    REQUIRE_FALSE(m.degraded);
    CHECK(m.population == std::optional<int64_t>{20});
    REQUIRE(m.apps.size() == 2);
    // Activity rank (11 events) beats lexical order ("aardvark.exe" sorts first).
    CHECK(m.apps[0].subject == "app.exe");
    CHECK(m.apps[1].subject == "aardvark.exe");

    const auto& app = m.apps[0];
    CHECK(app.figures.crashes == 10);
    CHECK(app.figures.hangs == 1);
    CHECK(app.figures.distinct_devices == 4);
    REQUIRE(app.figures.share_affected);
    CHECK(app.figures.share_affected->estimate == yuzu::server::dex_proportion(4, 20)->estimate);
    REQUIRE(app.figures.rate_per_1000);
    CHECK(app.figures.rate_per_1000->estimate == yuzu::server::dex_rate(11, 0.02)->estimate);
    yuzu::server::StabilityInputs in;
    in.reporting_devices = 20;
    in.devices_affected = 4;
    in.crash_events = 9;
    in.hang_events = 1;
    const auto expect = yuzu::server::compute_stability_score(in, 0);
    REQUIRE(app.figures.score.score);
    CHECK(*app.figures.score.score == *expect.score);

    REQUIRE(app.versions.size() == 2);
    CHECK(app.version_count == 2);
    CHECK_FALSE(app.versions_truncated);
    CHECK(app.versions[0].version == "2.0.0.0");
    CHECK(app.versions[0].figures.distinct_devices == 3);
    CHECK(app.versions[0].figures.crashes == 8);
    in.devices_affected = 3;
    in.crash_events = 7;
    in.hang_events = 0;
    CHECK(*app.versions[0].figures.score.score == *yuzu::server::compute_stability_score(in, 0).score);
    CHECK(app.versions[1].version == "1.0.0.0");
    CHECK(app.versions[1].figures.distinct_devices == 2);
    CHECK(app.versions[1].figures.crashes == 2);
    CHECK(app.versions[1].figures.hangs == 1);

    // One affected device, published with every figure and no floor field.
    CHECK(m.apps[1].figures.distinct_devices == 1);
    CHECK(m.apps[1].figures.share_affected);
    CHECK(m.apps[1].figures.score.score);
    CHECK(yuzu::server::dex_apps_json(m).find("below_floor") == std::string::npos);
}

TEST_CASE("DexApi: apps without a FleetFn has an unknown population, scores withheld",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    const auto m = make_local_dex_api(&store, {})->apps("7d");
    REQUIRE_FALSE(m.degraded);
    CHECK_FALSE(m.population);
    REQUIRE_FALSE(m.apps.empty());
    CHECK_FALSE(m.apps[0].figures.share_affected);
    CHECK_FALSE(m.apps[0].figures.rate_per_1000);
    CHECK(std::string(m.apps[0].figures.score.withheld) == "no_population");
}

TEST_CASE("DexApi: apps on a failed store read is degraded, never an empty list",
          "[pg][dex][apps_model][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_observations")};
        REQUIRE(d.ok());
    }
    const auto m = make_local_dex_api(&store, {})->apps("7d");
    CHECK(m.degraded);
    CHECK(m.apps.empty());
}

TEST_CASE("DexApi: apps caps versions at 20 and flags it", "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    std::vector<std::string> versions;
    for (int i = 1; i <= 21; ++i) {
        const std::string v = "1.0.0." + std::to_string(i);
        versions.push_back(v);
        seed_obs_v(store, "v" + std::to_string(i), "d" + std::to_string(i), "many.exe",
                   "process.crashed", v, kTs);
    }
    const auto m = make_local_dex_api(&store, {})->apps("7d");
    REQUIRE(m.apps.size() == 1);
    CHECK(m.apps[0].version_count == 21);
    CHECK(m.apps[0].versions_truncated);
    // Equal devices everywhere: the kept 20 are the lexically smallest, in order.
    std::sort(versions.begin(), versions.end());
    versions.resize(20);
    REQUIRE(m.apps[0].versions.size() == 20);
    for (std::size_t i = 0; i < 20; ++i)
        CHECK(m.apps[0].versions[i].version == versions[i]);
}
