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
#include "dex_score_policy_json.hpp"   // dex_policy_in_force_from_stored
#include "guaranteed_state_store.hpp"  // seed + direct-read parity oracles
#include "key_provider.hpp"            // FileKeyProvider -- the real RuntimeConfigStore below
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"              // PgConn/PgResult -- the DROP-TABLE degrade tests below
#include "pg/secret_codec.hpp"
#include "runtime_config_store.hpp"    // the real policy store behind the production reader

#include "../test_helpers.hpp"

#include <libpq-fe.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <expected>
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
    // Also carry the runtime_config schema (and the secrets schema its constructor
    // registers against), so a clone can open a real RuntimeConfigStore. Same recipe
    // as test_config_routes.cpp's cfgroutes template.
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    PgPool rc_pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::RuntimeConfigStore rc{rc_pool, codec};
    if (!rc.is_open())
        throw std::runtime_error("dexapi template: runtime config store failed to migrate");
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("dexapi template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("dexapi template: codec init failed");
    yuzu::server::pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("dexapi template: kek_meta reset failed");
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
                const std::string& ts, const std::string& platform = "windows") {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = type;
    e.severity = "info";
    e.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\",\"symbolic\":"
                    "\"ACCESS_VIOLATION\",\"component\":\"ntdll.dll\",\"platform\":\"" + platform + "\","
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

// An unavailable policy answers before the fleet snapshot is taken (no wasted work). No
// store is needed: the policy branch decides, so this runs in the non-Postgres suite.
TEST_CASE("DexApi: apps with an unavailable policy never takes the fleet snapshot",
          "[dex][dex_api]") {
    int fleet_calls = 0;
    auto api = make_local_dex_api(
        /*store=*/nullptr,
        [&fleet_calls] {
            ++fleet_calls;
            return yuzu::server::DexFleet{};
        },
        []() -> std::expected<yuzu::server::DexPolicyInForce, std::string> {
            return std::unexpected(std::string("store down"));
        });
    const auto m = api->apps("7d");
    CHECK(m.degraded);
    CHECK(m.degraded_reason == "score_policy_unavailable");
    CHECK(fleet_calls == 0);
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
// 20 Windows devices online: the population every Apps case below uses. The
// five fixture devices are among them, so their figures are online figures.
yuzu::server::DexFleet fleet20() {
    yuzu::server::DexFleet f;
    f.windows_online = 20;
    for (const char* id : {"a1", "a2", "a3", "a4", "b1"})
        f.connected_agents.emplace_back(id, "windows");
    for (int i = 0; i < 15; ++i)
        f.connected_agents.emplace_back("idle-" + std::to_string(i), "windows");
    f.total_online = 20;
    return f;
}

// fleet20's Windows devices plus two Linux (l1, l2) and one macOS (m1) device.
yuzu::server::DexFleet fleet23() {
    auto f = fleet20();
    f.connected_agents.emplace_back("l1", "linux");
    f.connected_agents.emplace_back("l2", "linux");
    f.connected_agents.emplace_back("m1", "macos");
    f.linux_online = 2;
    f.macos_online = 1;
    f.total_online = 23;
    return f;
}

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

    auto api = make_local_dex_api(&store, fleet20);
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
    // No fleet source: which affected devices are online is unknown, not zero.
    CHECK_FALSE(m.apps[0].figures.distinct_devices_online.has_value());
    CHECK_FALSE(m.apps[0].versions[0].figures.distinct_devices_online.has_value());
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
    // The lexically last version ("1.0.0.9") is the most affected: it must be
    // kept and listed first, so the cut ranks by devices, not by name.
    seed_obs_v(store, "v-extra", "d-extra", "many.exe", "process.crashed", "1.0.0.9", kTs);
    const auto m = make_local_dex_api(&store, {})->apps("7d");
    REQUIRE(m.apps.size() == 1);
    CHECK(m.apps[0].version_count == 21);
    CHECK(m.apps[0].versions_truncated);
    // Then equal devices: the kept 19 are the lexically smallest, in order.
    std::sort(versions.begin(), versions.end());
    versions.pop_back(); // "1.0.0.9", listed first
    versions.resize(19);
    versions.insert(versions.begin(), "1.0.0.9");
    REQUIRE(m.apps[0].versions.size() == 20);
    for (std::size_t i = 0; i < 20; ++i)
        CHECK(m.apps[0].versions[i].version == versions[i]);
}

// The injected score policy reaches the Apps read: a valid override moves one
// application's (and its version's) band and the model names the policy and the
// override; a stored document that is invalid scores under the shipped defaults
// and says so; an unreadable policy degrades the whole read with the store open,
// so the policy branch (not the null-store one) decides.
TEST_CASE("DexApi: apps uses the injected score policy and an unreadable one degrades",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    using yuzu::server::DexPolicyInForce;
    using yuzu::server::StabilityBand;

    // Default edges: app.exe scores 86.12 (Good, edge 90), its 2.0.0.0 scores 89.6.
    const auto base = make_local_dex_api(&store, fleet20)->apps("7d");
    REQUIRE(base.apps.size() == 2);
    REQUIRE(base.apps[0].figures.score.band);
    CHECK(*base.apps[0].figures.score.band == StabilityBand::Good);
    CHECK(base.policy.source == "default"); // an empty policy function is the shipped defaults
    CHECK(base.policy.fault.empty());

    const std::string lowered_doc = R"({"overrides":[{"image":"app.exe","tiers":{"edges":{"excellent":80}}}]})";
    auto lowered = [&]() -> std::expected<DexPolicyInForce, std::string> {
        return yuzu::server::dex_policy_in_force_from_stored(lowered_doc);
    };
    const auto m = make_local_dex_api(&store, fleet20, lowered)->apps("7d");
    REQUIRE_FALSE(m.degraded);
    REQUIRE(m.apps.size() == 2);
    CHECK(m.policy.source == "custom");
    CHECK(m.policy.revision == yuzu::server::dex_score_policy_revision(lowered_doc));
    REQUIRE(m.apps[0].figures.score.band);
    CHECK(*m.apps[0].figures.score.band == StabilityBand::Excellent);
    CHECK(m.apps[0].profile == yuzu::server::DexPolicyProfile::Override);
    REQUIRE(m.apps[0].versions.size() == 2);
    REQUIRE(m.apps[0].versions[0].figures.score.band);
    CHECK(*m.apps[0].versions[0].figures.score.band == StabilityBand::Excellent);
    // The override is per image: aardvark.exe keeps the default edges.
    REQUIRE(m.apps[1].figures.score.band);
    CHECK(*m.apps[1].figures.score.band == *base.apps[1].figures.score.band);
    CHECK(m.apps[1].profile == yuzu::server::DexPolicyProfile::Default);

    // A stored document with a duplicate override scores under the shipped defaults,
    // with the fault named, never half-applied.
    auto duplicated = []() -> std::expected<DexPolicyInForce, std::string> {
        return yuzu::server::dex_policy_in_force_from_stored(
            std::string(R"({"overrides":[{"image":"dup.exe"},{"image":"dup.exe"}]})"));
    };
    const auto refused = make_local_dex_api(&store, fleet20, duplicated)->apps("7d");
    REQUIRE_FALSE(refused.degraded);
    CHECK(refused.policy.source == "default");
    CHECK(refused.policy.fault == "override_key_duplicate at overrides[1].image");
    REQUIRE(refused.apps.size() == 2);
    CHECK(*refused.apps[0].figures.score.band == *base.apps[0].figures.score.band);

    // A policy that cannot be read is a degrade with its own reason, no apps.
    auto unreadable = []() -> std::expected<DexPolicyInForce, std::string> {
        return std::unexpected(std::string("store down"));
    };
    const auto bad = make_local_dex_api(&store, fleet20, unreadable)->apps("7d");
    CHECK(bad.degraded);
    CHECK(bad.degraded_reason == "score_policy_unavailable");
    CHECK(bad.apps.empty());
}

// The production wiring end to end, minus the server boot: a real RuntimeConfigStore
// holds the policy document under kDexScorePolicyKey (so the key is allow-listed and
// the literal in runtime_config_store.cpp matches the constant), the production reader
// maps the store's answer, the provider caches it on an injected clock, and the Apps
// read scores under it. Then the store loses the row, then becomes unreadable.
TEST_CASE("DexApi: the stored score policy reaches the Apps read through the production reader",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    PgPool rc_pool{{.conninfo = db.dsn(), .size = 2}};
    yuzu::server::RuntimeConfigStore rc{rc_pool, codec};
    REQUIRE(rc.is_open());

    using yuzu::server::DexScorePolicyProvider;
    using yuzu::server::StabilityBand;
    const std::string key(yuzu::server::kDexScorePolicyKey);
    const std::string lowered_doc =
        R"({"overrides":[{"image":"app.exe","tiers":{"edges":{"excellent":80}}}]})";
    REQUIRE(rc.set(key, lowered_doc, "test").has_value());

    std::int64_t now_ms = 1'000'000;
    DexScorePolicyProvider provider_under_test(yuzu::server::dex_score_policy_store_reader(rc),
                                               [&now_ms] { return now_ms; });
    auto api = make_local_dex_api(
        &store, fleet20, [&provider_under_test] { return provider_under_test.current(); });

    // A stored document is the policy in force: custom source, its revision, the
    // lowered edge moving app.exe's band (86.12 is Good under the default edges).
    const auto custom = api->apps("7d");
    REQUIRE_FALSE(custom.degraded);
    CHECK(custom.policy.source == "custom");
    CHECK(custom.policy.revision == yuzu::server::dex_score_policy_revision(lowered_doc));
    REQUIRE(custom.apps.size() == 2);
    REQUIRE(custom.apps[0].figures.score.band);
    CHECK(*custom.apps[0].figures.score.band == StabilityBand::Excellent);
    CHECK(custom.apps[0].profile == yuzu::server::DexPolicyProfile::Override);

    // Nothing stored is a good read of the shipped defaults, once the cache expires.
    REQUIRE(rc.remove(key));
    now_ms += yuzu::server::kDexPolicyRefreshMs;
    const auto cleared = api->apps("7d");
    REQUIRE_FALSE(cleared.degraded);
    CHECK(cleared.policy.source == "default");
    CHECK(cleared.policy.revision == "default");
    REQUIRE(cleared.apps[0].figures.score.band);
    CHECK(*cleared.apps[0].figures.score.band == StabilityBand::Good);
    const std::int64_t last_good_ms = now_ms;

    // The store becomes unreadable: the reader reports the error, the provider
    // serves the last good policy until its staleness bound, and past it the read
    // degrades.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE runtime_config_store.runtime_config")};
        REQUIRE(d.ok());
    }
    CHECK_FALSE(yuzu::server::dex_score_policy_store_reader(rc)().has_value());
    now_ms = last_good_ms + yuzu::server::kDexPolicyRefreshMs;
    const auto stale = api->apps("7d");
    REQUIRE_FALSE(stale.degraded);
    CHECK(stale.policy.source == "default");
    now_ms = last_good_ms + yuzu::server::kDexPolicyStaleCapMs + 1;
    const auto expired = api->apps("7d");
    CHECK(expired.degraded);
    CHECK(expired.degraded_reason == "score_policy_unavailable");
    CHECK(expired.apps.empty());
}

// The production WRITER binding against a real RuntimeConfigStore: the create, replace and
// remove arms each reach the policy key (observed through the production reader and the row's
// updated_by), and a stale expected text changes nothing.
TEST_CASE("DexApi: the production score policy writer binds the conditional writes to the "
          "policy key",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    PgPool rc_pool{{.conninfo = db.dsn(), .size = 2}};
    yuzu::server::RuntimeConfigStore rc{rc_pool, codec};
    REQUIRE(rc.is_open());

    const auto read = yuzu::server::dex_score_policy_store_reader(rc);
    const auto writes = yuzu::server::dex_score_policy_store_writer(rc);
    const std::string key(yuzu::server::kDexScorePolicyKey);
    auto updated_by = [&] {
        const auto e = rc.get(key);
        REQUIRE(e.has_value());
        REQUIRE(e->has_value());
        return (*e)->updated_by;
    };
    auto stored_text = [&]() -> std::optional<std::string> {
        const auto r = read();
        REQUIRE(r.has_value());
        return *r;
    };
    auto canonical_with_excellent = [](double e) {
        auto p = yuzu::server::dex_default_score_policy();
        p.tiers.edges.excellent = e;
        return yuzu::server::dex_score_policy_canonical(p);
    };
    const std::string first = canonical_with_excellent(95.0);
    const std::string second = canonical_with_excellent(96.0);

    // Create: nothing stored; a second create is stale and changes nothing.
    REQUIRE(writes.compare_and_set(std::nullopt, first, "alice").value());
    CHECK(stored_text() == first);
    CHECK(updated_by() == "alice");
    CHECK_FALSE(writes.compare_and_set(std::nullopt, second, "bob").value());
    CHECK(stored_text() == first);

    // Replace: only against the exact stored text.
    CHECK_FALSE(writes.compare_and_set(second, second, "bob").value());
    REQUIRE(writes.compare_and_set(first, second, "bob").value());
    CHECK(stored_text() == second);
    CHECK(updated_by() == "bob");

    // Remove: only the exact stored text; the reader then sees no row.
    CHECK_FALSE(writes.compare_and_remove(first).value());
    CHECK(stored_text() == second);
    REQUIRE(writes.compare_and_remove(second).value());
    CHECK_FALSE(stored_text().has_value());
}

// Counts are Windows-scoped: Linux and macOS rows never reach the numerator, and
// a subject seen only off Windows is not listed at all.
TEST_CASE("DexApi: apps counts Windows rows only", "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    seed_obs_v(store, "lx1", "a9", "app.exe", "process.crashed", "1.0.0.0", kTs, "linux");
    seed_obs_v(store, "lx2", "a9", "app.exe", "process.crashed", "3.0.0.0", kTs, "linux");
    for (int i = 1; i <= 3; ++i)
        seed_obs_v(store, "mc" + std::to_string(i), "m1", "linux-only.exe", "process.crashed", "1.0",
                   kTs, "macos");
    const auto m = make_local_dex_api(&store, fleet20)->apps("7d");
    REQUIRE(m.apps.size() == 2);
    CHECK(m.apps[0].subject == "app.exe");
    CHECK(m.apps[1].subject == "aardvark.exe");
    CHECK(m.apps[0].figures.crashes == 10);
    CHECK(m.apps[0].figures.hangs == 1);
    CHECK(m.apps[0].figures.distinct_devices == 4);
    CHECK(m.apps[0].version_count == 2);
}

// A platform scope answers over that scope's online devices only; the population
// and every figure move together.
TEST_CASE("DexApi: apps platform scope", "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    for (int i = 1; i <= 3; ++i)
        seed_obs_v(store, "lxo" + std::to_string(i), "l1", "linux-only.bin", "process.crashed", "1.0",
                   kTs, "linux");
    for (int i = 1; i <= 2; ++i)
        seed_obs_v(store, "mco" + std::to_string(i), "m1", "macos-only.app", "process.crashed", "1.0",
                   kTs, "macos");
    auto api = make_local_dex_api(&store, fleet23);

    const auto win = api->apps("7d");
    REQUIRE_FALSE(win.degraded);
    CHECK(win.population == 20);
    REQUIRE(win.apps.size() == 2);
    CHECK(win.apps[0].subject == "app.exe");
    CHECK(win.apps[1].subject == "aardvark.exe");

    const auto all = api->apps("7d", "all");
    REQUIRE_FALSE(all.degraded);
    CHECK(all.population == 23);
    CHECK(all.apps_total == 4);
    REQUIRE(all.apps.size() == 4);
    for (const auto& a : all.apps)
        if (a.subject == "linux-only.bin") {
            REQUIRE(a.figures.share_affected);
            CHECK(a.figures.share_affected->estimate == yuzu::server::dex_proportion(1, 23)->estimate);
        }

    const auto lin = api->apps("7d", "linux");
    REQUIRE_FALSE(lin.degraded);
    CHECK(lin.population == 2);
    REQUIRE(lin.apps.size() == 1);
    CHECK(lin.apps[0].subject == "linux-only.bin");

    const auto mac = api->apps("7d", "macos");
    REQUIRE_FALSE(mac.degraded);
    CHECK(mac.population == 1);
    REQUIRE(mac.apps.size() == 1);
    CHECK(mac.apps[0].subject == "macos-only.app");
}

TEST_CASE("DexApi: apps windows scope is byte-identical to the one-argument read",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    seed_obs_v(store, "lxo1", "l1", "linux-only.bin", "process.crashed", "1.0", kTs, "linux");
    auto api = make_local_dex_api(&store, fleet23);
    const auto implicit = api->apps("7d");
    const auto windows = api->apps("7d", "windows");
    REQUIRE_FALSE(windows.degraded);
    CHECK(yuzu::server::dex_apps_json(implicit) == yuzu::server::dex_apps_json(windows));
    CHECK(nlohmann::json::parse(yuzu::server::dex_apps_json(windows))["population_basis"] ==
          "windows_online");
    CHECK(nlohmann::json::parse(yuzu::server::dex_apps_json(api->apps("7d", "all")))["population_basis"] ==
          "all_online");
    // The additive key: the windows read (both spellings) carries one key, all carries three.
    const auto wj = nlohmann::json::parse(yuzu::server::dex_apps_json(windows));
    CHECK(wj["crash_source_coverage"] == nlohmann::json{{"windows", "complete"}});
    CHECK(nlohmann::json::parse(yuzu::server::dex_apps_json(implicit))["crash_source_coverage"] ==
          wj["crash_source_coverage"]);
    CHECK(nlohmann::json::parse(yuzu::server::dex_apps_json(api->apps("7d", "all")))["crash_source_coverage"] ==
          nlohmann::json{{"windows", "complete"}, {"linux", "partial"}, {"macos", "partial"}});
}

// A Linux or macOS scope with signals but no connected device in it: the subject is
// listed, nothing is shared or scored against a zero population.
TEST_CASE("DexApi: apps on an empty Linux fleet and an empty macOS fleet", "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    seed_obs_v(store, "lxe1", "l9", "linux-only.bin", "process.crashed", "1.0", kTs, "linux");
    seed_obs_v(store, "mce1", "m9", "macos-only.app", "process.crashed", "1.0", kTs, "macos");
    auto api = make_local_dex_api(&store, fleet20); // Windows devices only
    for (const auto& [scope, subject] :
         {std::pair<const char*, const char*>{"linux", "linux-only.bin"}, {"macos", "macos-only.app"}}) {
        const auto m = api->apps("7d", scope);
        REQUIRE_FALSE(m.degraded);
        CHECK(m.population == 0);
        REQUIRE(m.apps.size() == 1);
        CHECK(m.apps[0].subject == subject);
        CHECK(m.apps[0].figures.distinct_devices_online == 0);
        CHECK_FALSE(m.apps[0].figures.share_affected);
        CHECK_FALSE(m.apps[0].figures.rate_per_1000);
        CHECK(std::string(m.apps[0].figures.score.withheld) == "no_population");
    }
    CHECK(api->apps("7d", "windows").population == 20);
}

// Manual latency probe (hidden): `yuzu_server_tests "[apps_bench]"`. A 30,000-agent
// mixed-OS fleet (15k windows / 10k linux / 5k macos), 4 crash/hang rows per agent.
// Prints the medians; the time budget is applied by the reader, not asserted here.
TEST_CASE("DexApi: apps all vs windows on a 30k mixed-OS fleet (bench)", "[.][pg][dex][apps_bench]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "INSERT INTO guaranteed_state_store.guardian_observations "
            "(event_id, agent_id, observed_at, obs_type, subject, platform, version) "
            "SELECT 'b' || g || '-' || k, 'ag' || g, '" + kTs + "', "
            "CASE WHEN k < 4 THEN 'process.crashed' ELSE 'process.hung' END, "
            "'app' || ((g * k) % 200), "
            "CASE g % 6 WHEN 0 THEN 'windows' WHEN 1 THEN 'windows' WHEN 2 THEN 'windows' "
            "WHEN 3 THEN 'linux' WHEN 4 THEN 'linux' ELSE 'macos' END, "
            "'1.0.0.' || (k % 3) FROM generate_series(1, 30000) g, generate_series(1, 4) k";
        yuzu::server::pg::PgResult r{PQexec(conn.get(), sql.c_str())};
        REQUIRE(r.ok());
        // A bulk insert leaves the planner without statistics until autovacuum
        // gets to it; analyse now so no timed read straddles that change.
        yuzu::server::pg::PgResult an{
            PQexec(conn.get(), "ANALYZE guaranteed_state_store.guardian_observations")};
        REQUIRE(an.ok());
    }
    const auto fleet = [] {
        yuzu::server::DexFleet f;
        for (int g = 1; g <= 30000; ++g) {
            const char* os = (g % 6 <= 2) ? "windows" : (g % 6 <= 4) ? "linux" : "macos";
            f.connected_agents.emplace_back("ag" + std::to_string(g), os);
        }
        f.total_online = 30000;
        return f;
    };
    auto api = make_local_dex_api(&store, fleet);
    const auto median_ms = [&](const char* scope, int64_t population) {
        const auto warm = api->apps("7d", scope);
        REQUIRE_FALSE(warm.degraded);
        REQUIRE(warm.population == population);
        // Positive control: a fast read that returned nothing proves nothing.
        REQUIRE(warm.apps_total == 200);
        REQUIRE_FALSE(warm.apps.empty());
        std::vector<double> ms;
        for (int i = 0; i < 5; ++i) {
            const auto t0 = std::chrono::steady_clock::now();
            const auto m = api->apps("7d", scope);
            const auto t1 = std::chrono::steady_clock::now();
            REQUIRE_FALSE(m.degraded);
            ms.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
        }
        std::sort(ms.begin(), ms.end());
        return ms[2];
    };
    // all first, windows, all again: neither scope owns the cold-cache read.
    const double a1 = median_ms("all", 30000);
    const double w = median_ms("windows", 15000);
    const double a2 = median_ms("all", 30000);
    const double a = std::max(a1, a2);
    WARN("apps_bench windows_ms=" << w << " all_ms=" << a1 << "," << a2 << " ratio=" << (a / w));
}

TEST_CASE("DexApi: apps with an invalid scope is degraded before policy or fleet",
          "[dex][dex_api]") {
    int fleet_calls = 0;
    int policy_calls = 0;
    auto api = make_local_dex_api(
        /*store=*/nullptr,
        [&fleet_calls] {
            ++fleet_calls;
            return yuzu::server::DexFleet{};
        },
        [&policy_calls]() -> std::expected<yuzu::server::DexPolicyInForce, std::string> {
            ++policy_calls;
            return yuzu::server::DexPolicyInForce{};
        });
    for (const char* bad : {"", "darwin", "Windows"}) {
        const auto m = api->apps("7d", bad);
        CHECK(m.degraded);
        CHECK(m.degraded_reason == "invalid_scope");
    }
    CHECK(fleet_calls == 0);
    CHECK(policy_calls == 0);
}

TEST_CASE("DexApi: apps all scope without a FleetFn has an unknown population",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    const auto m = make_local_dex_api(&store, {})->apps("7d", "all");
    REQUIRE_FALSE(m.degraded);
    CHECK_FALSE(m.population);
    REQUIRE_FALSE(m.apps.empty());
    CHECK(std::string(m.apps[0].figures.score.withheld) == "no_population");
}

// 102 subjects: the top 100 by devices affected then activity are kept, ties fall
// to subject order, and the cut is made on that rank, not on name.
TEST_CASE("DexApi: apps keeps the top 100 applications by activity", "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    int n = 0;
    auto crashes = [&](const std::string& subject, int count) {
        for (int i = 0; i < count; ++i)
            seed_obs_v(store, "cap" + std::to_string(++n), "d" + subject, subject, "process.crashed",
                       "1.0", kTs);
    };
    crashes("zz-top.exe", 3);  // most active, lexically last
    crashes("a-least.exe", 1); // least active, lexically first
    for (int i = 1; i <= 100; ++i) {
        char name[16];
        std::snprintf(name, sizeof name, "m%03d.exe", i);
        crashes(name, 2); // a 100-wide tie that spans the cut
    }
    const auto m = make_local_dex_api(&store, fleet20)->apps("7d");
    REQUIRE_FALSE(m.degraded);
    REQUIRE(m.apps.size() == static_cast<std::size_t>(yuzu::server::kDexAppsLimit));
    CHECK(m.apps.front().subject == "zz-top.exe");
    CHECK(m.apps.back().subject == "m099.exe");
    for (const auto& a : m.apps) {
        CHECK(a.subject != "a-least.exe");
        CHECK(a.subject != "m100.exe");
    }
}

// An intact store with no observations is a successful empty read, not a degrade.
TEST_CASE("DexApi: apps on an intact empty store is a healthy empty list", "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    const auto m = make_local_dex_api(&store, {})->apps("7d");
    CHECK_FALSE(m.degraded);
    CHECK(m.apps.empty());
}

// One sick device crash-looping three applications must not displace an
// application on eight devices from the top-N cut: membership is the most
// devices affected, and apps_total/apps_truncated name the cut.
TEST_CASE("DexApi: apps top-N membership is devices affected, not raw events",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    int n = 0;
    for (const char* app : {"sick-a.exe", "sick-b.exe", "sick-c.exe"})
        for (int i = 0; i < 9; ++i)
            seed_obs_v(store, "sk" + std::to_string(++n), "sick", app, "process.crashed", "1.0", kTs);
    for (int i = 0; i < 8; ++i)
        seed_obs_v(store, "wd" + std::to_string(++n), "w" + std::to_string(i), "widespread.exe",
                   "process.crashed", "1.0", kTs);
    const auto rows = store.dex_app_stability_checked(yuzu::server::dex_iso_since(7), "windows",
                                                      /*app_limit=*/2, 20, 5, {});
    REQUIRE(rows);
    int totals = 0;
    bool widespread = false;
    for (const auto& r : *rows) {
        if (r.version)
            continue;
        ++totals;
        CHECK(r.apps_total == 4);
        widespread = widespread || r.subject == "widespread.exe";
    }
    CHECK(totals == 2);
    CHECK(widespread);
    const auto m = yuzu::server::dex_apps_model_from_rows("7d", yuzu::server::kDexAppsScopeWindows, *rows, 20,
                                                          yuzu::server::DexPolicyInForce{});
    CHECK(m.apps_total == 4);
    CHECK(m.apps_truncated);
}

// Store-level pins for the window, the per-device cap and last_seen.
TEST_CASE("DexApi: apps store read honours the window, the per-device cap and last_seen",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    const std::string later = yuzu::server::dex_iso_since(1).substr(0, 10) + "T12:00:00Z";
    const std::string old_ts = yuzu::server::dex_iso_since(40).substr(0, 10) + "T12:00:00Z";
    int n = 0;
    auto id = [&] { return "q" + std::to_string(++n); };
    // One device, 4 crashes in each of two versions: capped at 5 per device, 4 per version.
    for (int i = 0; i < 4; ++i) {
        seed_obs_v(store, id(), "c1", "cap.exe", "process.crashed", "1.0", kTs);
        seed_obs_v(store, id(), "c1", "cap.exe", "process.crashed", "2.0", i == 0 ? later : kTs);
    }
    for (int i = 0; i < 7; ++i)
        seed_obs_v(store, id(), "c2", "cap.exe", "process.hung", "1.0", kTs);
    seed_obs_v(store, id(), "c3", "cap.exe", "process.crashed", "2.0", old_ts); // outside 7d
    const std::vector<std::string> online{"c1", "c2", "c3"};
    auto total_of = [](const std::vector<yuzu::server::DexAppStabilityRow>& rows) {
        for (const auto& r : rows)
            if (!r.version)
                return r;
        FAIL("no total row");
        return yuzu::server::DexAppStabilityRow{};
    };
    const auto week =
        store.dex_app_stability_checked(yuzu::server::dex_iso_since(7), "windows", 10, 20, 5, online);
    REQUIRE(week);
    const auto t = total_of(*week);
    CHECK(t.crashes == 8);
    CHECK(t.capped_crashes == 5);
    CHECK(t.hangs == 7);
    CHECK(t.capped_hangs == 5);
    CHECK(t.affected_devices == 2);
    CHECK(t.affected_online == 2); // c3 is online but outside the window
    CHECK(t.crashes_online == 8);
    CHECK(t.hangs_online == 7);
    CHECK(t.last_seen == later);
    for (const auto& r : *week) // a version row caps its hangs per device too
        if (r.version == "1.0.0.0")
            CHECK(r.capped_hangs == 5);
    const auto all = store.dex_app_stability_checked("", "windows", 10, 20, 5, online);
    REQUIRE(all);
    CHECK(total_of(*all).affected_devices == 3);
    CHECK(total_of(*all).crashes == 9);
    for (const auto& r : *all) // a version row's last_seen is its newest observation
        if (r.version == "2.0.0.0")
            CHECK(r.last_seen == later);
}

// Membership and version cuts: each SECTION seeds its own small store and reads the
// statement directly, so a changed ORDER BY, COUNT or collation shows in the rows.
TEST_CASE("DexApi: apps store cuts rank by devices, then events, then byte-order name",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    int n = 0;
    auto obs = [&](const char* agent, const char* app, const char* type, const char* ver) {
        seed_obs_v(store, "mb" + std::to_string(++n), agent, app, type, ver, kTs);
    };
    const std::string since = yuzu::server::dex_iso_since(7);
    auto kept = [&](int app_limit, int version_limit, bool versions) {
        std::vector<std::string> out;
        const auto rows = store.dex_app_stability_checked(since, "windows", app_limit, version_limit, 5, {});
        REQUIRE(rows);
        for (const auto& r : *rows)
            if (r.version.has_value() == versions)
                out.push_back(r.subject + (r.version ? "@" + *r.version : ""));
        std::sort(out.begin(), out.end());
        return out;
    };
    using Names = std::vector<std::string>;
    SECTION("the version cut ranks by devices, not events, and breaks ties in byte order") {
        obs("d1", "v.exe", "process.crashed", "2.0.0.0");
        obs("d2", "v.exe", "process.crashed", "2.0.0.0");
        for (int i = 0; i < 3; ++i)
            obs("d3", "v.exe", "process.crashed", "1.0.0.9");
        CHECK(kept(10, 1, true) == Names{"v.exe@2.0.0.0"});
        // Under a locale collation that ignores dots "1.0.10.0" sorts before "1.0.1.9".
        obs("d4", "t.exe", "process.crashed", "1.0.10.0");
        obs("d5", "t.exe", "process.crashed", "1.0.1.9");
        CHECK(kept(10, 1, true) == Names{"t.exe@1.0.1.9", "v.exe@2.0.0.0"});
    }
    SECTION("membership counts a device once even when it spans versions") {
        for (const char* ver : {"1.0", "2.0"})
            for (int i = 0; i < 5; ++i)
                obs("sick", "sick.exe", "process.crashed", ver);
        obs("p1", "pair.exe", "process.crashed", "1.0");
        obs("p2", "pair.exe", "process.crashed", "1.0");
        CHECK(kept(1, 20, false) == Names{"pair.exe"});
    }
    SECTION("an equal-devices equal-crashes tie is broken by hangs, then byte-order name") {
        obs("d1", "a-plain.exe", "process.crashed", "1.0");
        obs("d2", "z-hang.exe", "process.crashed", "1.0");
        obs("d2", "z-hang.exe", "process.hung", "1.0");
        CHECK(kept(1, 20, false) == Names{"z-hang.exe"});
    }
    SECTION("an all-equal tie falls to byte order, not database collation") {
        obs("d1", "a.exe", "process.crashed", "1.0");
        obs("d2", "B.exe", "process.crashed", "1.0");
        CHECK(kept(1, 20, false) == Names{"B.exe"});
    }
    SECTION("apps_total names the cut exactly at app_limit and app_limit + 1") {
        for (const char* app : {"x.exe", "y.exe", "z.exe"})
            obs("d1", app, "process.crashed", "1.0");
        const yuzu::server::DexPolicyInForce policy;
        for (int limit : {3, 2}) {
            const auto rows = store.dex_app_stability_checked(since, "windows", limit, 20, 5, {});
            REQUIRE(rows);
            const auto m = yuzu::server::dex_apps_model_from_rows("7d", yuzu::server::kDexAppsScopeWindows, *rows, 20, policy);
            CHECK(m.apps_total == 3);
            CHECK(m.apps_truncated == (limit == 2));
        }
    }
}

// Churn: the share's numerator is the affected devices that are ONLINE, drawn in the
// statement from the same ids whose count is the population, so a device that crashed
// and went offline is in the window-wide counts and nowhere in the share.
TEST_CASE("DexApi: apps share numerator is the affected devices that are online",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    int n = 0;
    // Seven devices crash app.exe (2 versions for gone1) and go offline.
    for (int i = 1; i <= 7; ++i)
        seed_obs_v(store, "ch" + std::to_string(++n), "gone" + std::to_string(i), "app.exe",
                   "process.crashed", "1.0.0.0", kTs);
    seed_obs_v(store, "ch" + std::to_string(++n), "gone1", "app.exe", "process.hung", "2.0.0.0", kTs);
    // One online device crashes it too (twice), and one more hangs a different app.
    seed_obs_v(store, "ch" + std::to_string(++n), "up1", "app.exe", "process.crashed", "1.0.0.0", kTs);
    seed_obs_v(store, "ch" + std::to_string(++n), "up1", "app.exe", "process.crashed", "2.0.0.0", kTs);
    seed_obs_v(store, "ch" + std::to_string(++n), "up2", "other.exe", "process.hung", "1.0.0.0", kTs);

    yuzu::server::DexFleet fleet;
    fleet.windows_online = 999; // deliberately not the id count: the population follows the ids
    fleet.connected_agents.emplace_back("up1", "windows");
    fleet.connected_agents.emplace_back("up2", "windows");
    fleet.connected_agents.emplace_back("lin1", "linux"); // not Windows: never in the set
    for (int i = 0; i < 48; ++i)
        fleet.connected_agents.emplace_back("idle" + std::to_string(i), "windows");
    const auto m = make_local_dex_api(&store, [&] { return fleet; })->apps("7d");
    REQUIRE_FALSE(m.degraded);
    CHECK(m.population == std::optional<int64_t>{50});
    REQUIRE(m.apps.size() == 2);
    const auto& app = m.apps[0]; // 10 events beat other.exe's 1
    REQUIRE(app.subject == "app.exe");
    CHECK(app.figures.crashes == 9);
    CHECK(app.figures.hangs == 1);
    CHECK(app.figures.distinct_devices == 8);        // seven gone + up1
    CHECK(app.figures.distinct_devices_online == 1); // up1 alone
    REQUIRE(app.figures.share_affected);
    CHECK(app.figures.share_affected->estimate == yuzu::server::dex_proportion(1, 50)->estimate);
    REQUIRE(app.figures.rate_per_1000);
    CHECK(app.figures.rate_per_1000->estimate == yuzu::server::dex_rate(2, 0.05)->estimate);
    // Seven of the eight affected devices are offline: the score is withheld, not 99.
    CHECK_FALSE(app.figures.score.score);
    CHECK(std::string(app.figures.score.withheld) == "offline_affected");
    // Versions: 1.0.0.0 has eight devices (one online), 2.0.0.0 has two (one online).
    REQUIRE(app.versions.size() == 2);
    CHECK(app.versions[0].version == "1.0.0.0");
    CHECK(app.versions[0].figures.distinct_devices == 8);
    CHECK(app.versions[0].figures.distinct_devices_online == 1);
    CHECK(app.versions[1].figures.distinct_devices == 2);
    CHECK(app.versions[1].figures.distinct_devices_online == 1);
    // Version rows use the online figures too: each has one online device (up1) with one crash.
    for (const auto& v : app.versions) {
        REQUIRE(v.figures.share_affected);
        CHECK(v.figures.share_affected->estimate == yuzu::server::dex_proportion(1, 50)->estimate);
        REQUIRE(v.figures.rate_per_1000);
        CHECK(v.figures.rate_per_1000->estimate == yuzu::server::dex_rate(1, 0.05)->estimate);
        CHECK(std::string(v.figures.score.withheld) == "offline_affected");
    }
    // other.exe: its only device is online.
    CHECK(m.apps[1].figures.distinct_devices_online == 1);
}

// A fleet with no Windows device online has an empty set: counts stay, share is withheld.
TEST_CASE("DexApi: apps with nothing online keeps the counts and publishes no share",
          "[pg][dex][apps_model]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    const auto m = make_local_dex_api(&store, [] { return DexFleet{}; })->apps("7d");
    REQUIRE_FALSE(m.degraded);
    CHECK(m.population == std::optional<int64_t>{0});
    REQUIRE(m.apps.size() == 2);
    CHECK(m.apps[0].figures.distinct_devices == 4);
    CHECK(m.apps[0].figures.distinct_devices_online == 0);
    CHECK_FALSE(m.apps[0].figures.share_affected);
    CHECK(std::string(m.apps[0].figures.score.withheld) == "no_population");
}

// One Apps read holds a lease for seconds, so reads over the budget are refused at once
// as a degrade (the handler's retryable 503), never queued behind the pool or served empty.
TEST_CASE("DexApi: apps read over its concurrency budget is refused as a degrade",
          "[pg][dex][apps_model][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    yuzu::MetricsRegistry metrics; // declared before the store so it outlives it
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_apps_fixture(store);
    store.set_metrics(&metrics);
    const auto counter = [&] {
        return metrics
            .counter("yuzu_server_guardian_read_degrade_total",
                     {{"reason", "concurrency_budget"}, {"source", "guardian_state"}})
            .value();
    };
    CHECK(GuaranteedStateStore::kDexAppsConcurrentReads == 4); // the documented budget
    const auto api = make_local_dex_api(&store, fleet20);
    REQUIRE_FALSE(api->apps("7d").degraded);
    CHECK(counter() == 0.0);
    store.set_apps_read_budget_for_test(0);
    const auto refused = api->apps("7d");
    CHECK(refused.degraded);
    CHECK(refused.apps.empty());
    CHECK(counter() == 1.0); // counted once under the documented reason and source
    CHECK_FALSE(store.dex_app_stability_checked("", "windows", 10, 20, 5, {}));
    CHECK(counter() == 2.0);
    // A refusal releases its slot: with a budget of one, two reads in a row both serve,
    // and a leaked slot would refuse the first (the count would already be at the budget).
    store.set_apps_read_budget_for_test(1);
    CHECK_FALSE(api->apps("7d").degraded);
    CHECK_FALSE(api->apps("7d").degraded);
}
