/**
 * test_dex_perf_model.cpp — F2a fleet performance read model + renderers + routes.
 *
 *  - dex_perf_rules: forged-value posture (clamp pct lies, reject absurd-finite
 *    latency, nullopt on inf/nan/negative/garbage) + the nearest-rank pin
 *    (n=2 → p90 = MAX, the A4 grill fix — shared with recompute_metrics).
 *  - fleet_now: absent-not-zero (no reporters → nullopt stats, never 0).
 *  - cohorts: n≥10 floor suppression, "(untagged)" residual sorts last,
 *    population-descending order.
 *  - device_list: worst-first sort, not-reporting complement (Windows only),
 *    cohort filter incl. the untagged residual, limit cap.
 *  - renderers: real aggregations or honest placeholders; cohort values and
 *    agent ids are HTML-escaped (no stored XSS); suppression text renders.
 *  - routes: GuaranteedState:Read gate; honest "unavailable" without a provider.
 */
#include "agent_registry.hpp"
#include "dex_perf_model.hpp"
#include "dex_perf_rules.hpp"
#include "dex_routes.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "test_dex_perf_api_double.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <yuzu/metrics.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace rules = yuzu::server::detail;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own GuaranteedStateStore against a clone of this schema
// (ADR-0038 migration).
yuzu::test::PgTestTemplate guardian_pg_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

DexPerfDevice dev(const std::string& id, std::optional<double> cpu, std::optional<double> commit,
                  std::optional<double> lat, const std::string& cohort = "",
                  const std::string& os = "windows") {
    DexPerfDevice d;
    d.agent_id = id;
    d.os = os;
    d.cpu_pct = cpu;
    d.commit_pct = commit;
    d.disk_lat_ms = lat;
    d.cohort = cohort;
    return d;
}

/// A snapshot with `n` reporting devices in cohort "a" and `m` in cohort "b".
DexPerfSnapshot two_cohorts(int n, int m) {
    DexPerfSnapshot snap;
    snap.cohort_key = "model";
    snap.available_keys = {"model"};
    for (int i = 0; i < n; ++i)
        snap.devices.push_back(dev("a-" + std::to_string(i), 10.0 + i, 50.0, 1.0, "a"));
    for (int i = 0; i < m; ++i)
        snap.devices.push_back(dev("b-" + std::to_string(i), 40.0 + i, 70.0, 3.0, "b"));
    return snap;
}

} // namespace

// ── dex_perf_rules ───────────────────────────────────────────────────────────

TEST_CASE("perf tag parsing: forged-value posture", "[dex][perf][rules]") {
    // Normal values pass.
    CHECK(rules::parse_perf_cpu_pct("42.5") == 42.5);
    CHECK(rules::parse_perf_disk_lat_ms("3.25") == 3.25);
    // A >100% percentage is a lie, not an outlier — CLAMP.
    CHECK(rules::parse_perf_cpu_pct("250") == 100.0);
    // Latency has no semantic bound — absurd-but-finite is REJECTED (clamping
    // would still poison the average with the ceiling).
    CHECK_FALSE(rules::parse_perf_disk_lat_ms("1e308"));
    CHECK_FALSE(rules::parse_perf_disk_lat_ms("1000001"));
    // std::stod does NOT throw on inf/nan — both must be rejected.
    CHECK_FALSE(rules::parse_perf_cpu_pct("inf"));
    CHECK_FALSE(rules::parse_perf_cpu_pct("nan"));
    CHECK_FALSE(rules::parse_perf_cpu_pct("-1"));
    CHECK_FALSE(rules::parse_perf_cpu_pct(""));
    CHECK_FALSE(rules::parse_perf_cpu_pct("garbage"));
    // Over-long inputs are rejected before parsing.
    CHECK_FALSE(rules::parse_perf_cpu_pct(std::string(64, '1')));
}

TEST_CASE("nearest-rank percentile: n=2 p90 is the MAX, not the MIN",
          "[dex][perf][rules][pin]") {
    // The A4 grill fix: floor((n−1)·p) under-reports high percentiles in small
    // fleets. This pin holds for BOTH consumers (recompute_metrics gauges and
    // the F2a read model) because they share this one function.
    std::vector<double> two{1.0, 9.0};
    CHECK(rules::nearest_rank(two, 0.90) == 9.0);
    CHECK(rules::nearest_rank(two, 0.50) == 1.0);
    std::vector<double> one{5.0};
    CHECK(rules::nearest_rank(one, 0.90) == 5.0);
}

TEST_CASE("dex_perf_os_from_session: normalizes to the closed token set",
          "[dex][perf][rules][os]") {
    CHECK(rules::dex_perf_os_from_session("windows") == "windows");
    CHECK(rules::dex_perf_os_from_session("Windows 11") == "windows");
    CHECK(rules::dex_perf_os_from_session("linux") == "linux");
    CHECK(rules::dex_perf_os_from_session("Linux 6.8") == "linux");
    CHECK(rules::dex_perf_os_from_session("darwin") == "macos");
    CHECK(rules::dex_perf_os_from_session("Darwin 24.0") == "macos");
    CHECK(rules::dex_perf_os_from_session("macos") == "macos");
    // The bug this function fixes: "darwin" CONTAINS "win" — a substring
    // match would misclassify this as Windows.
    CHECK(rules::dex_perf_os_from_session("darwin") != "windows");
    CHECK(rules::dex_perf_os_from_session("freebsd").empty());
    CHECK(rules::dex_perf_os_from_session("").empty());
}

TEST_CASE("dex_perf_os_collects: only OSes with a real perf collector today",
          "[dex][perf][rules][os]") {
    CHECK(rules::dex_perf_os_collects("windows"));
    CHECK(rules::dex_perf_os_collects("linux"));
    CHECK_FALSE(rules::dex_perf_os_collects("macos")); // kPlanned, not yet real
    CHECK_FALSE(rules::dex_perf_os_collects(""));
}

// ── fleet_now ────────────────────────────────────────────────────────────────

TEST_CASE("fleet_now: absent-not-zero + honest denominators", "[dex][perf][model]") {
    DexPerfSnapshot snap;
    // Two online Windows agents, neither reporting; one mac agent.
    snap.devices.push_back(dev("w1", std::nullopt, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("w2", std::nullopt, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("m1", std::nullopt, std::nullopt, std::nullopt, "", "macos"));
    auto now = dex_perf_fleet_now(snap);
    CHECK_FALSE(now.cpu);
    CHECK_FALSE(now.commit);
    CHECK_FALSE(now.disk_lat);
    CHECK(now.reporting == 0);
    CHECK(now.windows_online == 2);

    // One reporter: stats exist, population is honest.
    snap.devices.push_back(dev("w3", 20.0, 60.0, 2.0));
    now = dex_perf_fleet_now(snap);
    REQUIRE(now.cpu);
    CHECK(now.cpu->n == 1);
    CHECK(now.cpu->avg == 20.0);
    CHECK(now.cpu->max == 20.0);
    CHECK(now.reporting == 1);
    CHECK(now.windows_online == 3);
}

TEST_CASE("fleet_now: per-OS online + reporting denominators", "[dex][perf][model][os]") {
    DexPerfSnapshot snap;
    // Two Windows (one reporting), one Linux (reporting), two macOS (neither
    // reporting — no collector yet), one unrecognized OS (online, never
    // reporting, never counted in any *_online bucket).
    snap.devices.push_back(dev("w1", 10.0, std::nullopt, std::nullopt, "", "windows"));
    snap.devices.push_back(dev("w2", std::nullopt, std::nullopt, std::nullopt, "", "windows"));
    snap.devices.push_back(dev("l1", 20.0, std::nullopt, std::nullopt, "", "linux"));
    snap.devices.push_back(dev("m1", std::nullopt, std::nullopt, std::nullopt, "", "macos"));
    snap.devices.push_back(dev("m2", std::nullopt, std::nullopt, std::nullopt, "", "macos"));
    snap.devices.push_back(dev("u1", std::nullopt, std::nullopt, std::nullopt, "", ""));
    auto now = dex_perf_fleet_now(snap);
    CHECK(now.windows_online == 2);
    CHECK(now.linux_online == 1);
    CHECK(now.macos_online == 2);
    CHECK(now.reporting == 2); // w1 + l1
    CHECK(now.reporting_windows == 1);
    CHECK(now.reporting_linux == 1);
    CHECK(now.reporting_macos == 0);
}

TEST_CASE("fleet_now: partial reporters count once, per-metric n varies",
          "[dex][perf][model]") {
    DexPerfSnapshot snap;
    snap.devices.push_back(dev("w1", 10.0, std::nullopt, std::nullopt)); // cpu only
    snap.devices.push_back(dev("w2", 30.0, 50.0, std::nullopt));         // cpu+commit
    auto now = dex_perf_fleet_now(snap);
    CHECK(now.reporting == 2);
    REQUIRE(now.cpu);
    CHECK(now.cpu->n == 2);
    CHECK(now.cpu->avg == 20.0);
    REQUIRE(now.commit);
    CHECK(now.commit->n == 1);
    CHECK_FALSE(now.disk_lat); // nobody reported it — absent
}

// ── cohorts ──────────────────────────────────────────────────────────────────

TEST_CASE("cohorts: floor suppression + untagged residual last + population sort",
          "[dex][perf][model][cohorts]") {
    auto snap = two_cohorts(12, 4); // "a" above floor, "b" below
    snap.devices.push_back(dev("u-1", 5.0, 40.0, 0.5, ""));
    snap.devices.push_back(dev("u-2", 6.0, 41.0, 0.6, ""));
    snap.devices.push_back(dev("idle", std::nullopt, std::nullopt, std::nullopt, "a"));

    auto rows = dex_perf_cohorts(snap);
    REQUIRE(rows.size() == 3);
    // Population-descending, untagged ALWAYS last.
    CHECK(rows[0].cohort == "a");
    CHECK(rows[0].devices == 12); // the non-reporting "idle" device is NOT counted
    CHECK_FALSE(rows[0].suppressed);
    REQUIRE(rows[0].cpu);
    CHECK(rows[0].cpu->n == 12);
    CHECK(rows[1].cohort == "b");
    CHECK(rows[1].devices == 4);
    CHECK(rows[1].suppressed); // below kDexCohortFloor — population shown, stats withheld
    CHECK_FALSE(rows[1].cpu);
    CHECK(rows[2].cohort == ""); // the residual
    CHECK(rows[2].devices == 2);
}

// ── device_list ──────────────────────────────────────────────────────────────

TEST_CASE("device_list: worst-first, cohort filter, untagged, limit",
          "[dex][perf][model][devices]") {
    auto snap = two_cohorts(3, 3); // cpu: a={10,11,12}, b={40,41,42}
    snap.devices.push_back(dev("u-1", 99.0, 1.0, 0.1, ""));

    auto rows = dex_perf_device_list(snap, DexPerfMetric::kCpu, false, std::nullopt, 50);
    REQUIRE(rows.size() == 7);
    CHECK(rows[0].agent_id == "u-1"); // worst first
    CHECK(rows[0].fleet_pctile == 100);
    CHECK(rows[6].agent_id == "a-0");

    // Cohort filter.
    rows = dex_perf_device_list(snap, DexPerfMetric::kCpu, false, std::string("b"), 50);
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].cpu_pct == 42.0);

    // The untagged residual is cohort_filter == "".
    rows = dex_perf_device_list(snap, DexPerfMetric::kCpu, false, std::string(""), 50);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].agent_id == "u-1");

    // Limit caps after sorting (the WORST survive).
    rows = dex_perf_device_list(snap, DexPerfMetric::kCpu, false, std::nullopt, 2);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].agent_id == "u-1");
}

TEST_CASE("device_list: not-reporting complement is Windows-only", "[dex][perf][model][devices]") {
    DexPerfSnapshot snap;
    snap.devices.push_back(dev("w-quiet", std::nullopt, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("w-loud", 10.0, 50.0, 1.0));
    snap.devices.push_back(dev("mac", std::nullopt, std::nullopt, std::nullopt, "", "macos"));
    auto rows = dex_perf_device_list(snap, DexPerfMetric::kCpu, true, std::nullopt, 50);
    REQUIRE(rows.size() == 1); // the mac is not EXPECTED to report — not listed
    CHECK(rows[0].agent_id == "w-quiet");
    CHECK(rows[0].fleet_pctile == -1); // no value for the sort metric
    CHECK(rows[0].os == "windows");
}

TEST_CASE("device_list: os field + not-reporting spans every collecting OS",
          "[dex][perf][model][devices][os]") {
    DexPerfSnapshot snap;
    snap.devices.push_back(dev("w-quiet", std::nullopt, std::nullopt, std::nullopt, "", "windows"));
    snap.devices.push_back(dev("l-quiet", std::nullopt, std::nullopt, std::nullopt, "", "linux"));
    snap.devices.push_back(dev("mac", std::nullopt, std::nullopt, std::nullopt, "", "macos"));
    auto rows = dex_perf_device_list(snap, DexPerfMetric::kCpu, true, std::nullopt, 50);
    // Both windows and linux collect today (dex_perf_os_collects); macos does not.
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].agent_id == "l-quiet"); // sorted by agent_id
    CHECK(rows[0].os == "linux");
    CHECK(rows[1].agent_id == "w-quiet");
    CHECK(rows[1].os == "windows");
}

TEST_CASE("metric token round-trip + unknown falls back to cpu", "[dex][perf][model]") {
    CHECK(dex_perf_metric_from_token("commit") == DexPerfMetric::kCommit);
    CHECK(dex_perf_metric_from_token("disk_lat") == DexPerfMetric::kDiskLat);
    CHECK(dex_perf_metric_from_token("bogus") == DexPerfMetric::kCpu);
    CHECK(std::string(dex_perf_metric_token(DexPerfMetric::kDiskLat)) == "disk_lat");
}

// ── renderers ────────────────────────────────────────────────────────────────

TEST_CASE("perf fragment: real aggregations, suppression text, Performance tab",
          "[dex][perf][render]") {
    auto snap = two_cohorts(12, 4);
    auto html = render_dex_perf_fragment(snap, 7);
    CHECK(html.find("Fleet performance") != std::string::npos);
    CHECK(html.find("Performance") != std::string::npos); // the 5th subnav tab
    CHECK(html.find("n too small") != std::string::npos); // cohort "b" suppressed
    CHECK(html.find("Windows and Linux") != std::string::npos); // coverage honesty (C1)
    CHECK(html.find("/fragments/dex/perf/devices?metric=cpu") != std::string::npos); // drill
}

TEST_CASE("perf fragment: App Performance is a top-level tab, and the buried "
          "inline CTA is now a plain cross-reference to it",
          "[dex][perf][render]") {
    auto snap = two_cohorts(1, 0);
    auto html = render_dex_perf_fragment(snap, 7);
    // The new sibling tab is present alongside "Performance" (not a replacement).
    CHECK(html.find("/fragments/dex/perf/apps") != std::string::npos);
    CHECK(html.find(">App Performance<") != std::string::npos);
    // The old buried special call-to-action wording is gone...
    CHECK(html.find("Open application performance over time") == std::string::npos);
    // ...replaced by a plain mention of the tab, not an actionable link of its own.
    CHECK(html.find("App Performance</b> tab above") != std::string::npos);
}

TEST_CASE("perf fragment: empty fleet renders honest placeholders, never zeros",
          "[dex][perf][render]") {
    DexPerfSnapshot snap; // nobody online, no tags
    auto html = render_dex_perf_fragment(snap, 7);
    CHECK(html.find("No perf telemetry yet") != std::string::npos);
    CHECK(html.find("No tags on the fleet yet") != std::string::npos);
}

TEST_CASE("perf fragment: cohort values are HTML-escaped (no stored XSS)",
          "[dex][perf][render][security]") {
    DexPerfSnapshot snap;
    snap.cohort_key = "model";
    snap.available_keys = {"model"};
    for (int i = 0; i < 12; ++i)
        snap.devices.push_back(
            dev("d-" + std::to_string(i), 10.0, 50.0, 1.0, "<script>alert(1)</script>"));
    auto html = render_dex_perf_fragment(snap, 7);
    CHECK(html.find("<script>alert(1)</script>") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
}

TEST_CASE("devices fragment: titles, escape, honest empty states", "[dex][perf][render]") {
    auto snap = two_cohorts(3, 0);
    snap.devices.push_back(dev("<img src=x>", 50.0, 50.0, 1.0, "a"));

    auto worst = render_dex_perf_devices_fragment(snap, DexPerfMetric::kCpu, false, std::nullopt,
                                                  50, 7);
    CHECK(worst.find("Worst devices by current CPU") != std::string::npos);
    CHECK(worst.find("<img src=x>") == std::string::npos); // agent_id escaped
    CHECK(worst.find("&lt;img") != std::string::npos);

    auto nr = render_dex_perf_devices_fragment(snap, DexPerfMetric::kCpu, true, std::nullopt,
                                               50, 7);
    CHECK(nr.find("Everyone is reporting") != std::string::npos); // honest empty complement
}

// ── routes ───────────────────────────────────────────────────────────────────

TEST_CASE("perf routes: perm gating + provider degradation", "[dex][perf][routes][rbac]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto noPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                     const std::string&) {
        res.status = 403;
        return false;
    };
    auto fleet = []() { return DexFleet{}; };
    std::string requested_key;
    DexPerfFn perf = [&](const std::string& key) {
        requested_key = key;
        return two_cohorts(12, 4);
    };

    SECTION("permitted: tab + devices drill render through the provider") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            perf, yuzu::server::test::FnDexPerfApi::Providers{});
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, {}, {}, {}, {}, {},
                               dex_perf_api);
        auto tab = sink.Get("/fragments/dex/perf");
        REQUIRE(tab);
        CHECK(tab->status == 200);
        CHECK(tab->body.find("Fleet performance") != std::string::npos);
        CHECK(requested_key == "model"); // the conventional default key

        auto drill = sink.Get(
            "/fragments/dex/perf/devices?metric=commit&cohort_key=model&cohort_value=a");
        REQUIRE(drill);
        CHECK(drill->status == 200);
        CHECK(drill->body.find("devices") != std::string::npos);

        // Grill pin: a card drill (no cohort params) still resolves the
        // DEFAULT key so the Cohort column shows real values — and does NOT
        // filter. Without this, every row read "(untagged)".
        requested_key.clear();
        auto card = sink.Get("/fragments/dex/perf/devices?metric=cpu");
        REQUIRE(card);
        CHECK(card->status == 200);
        CHECK(requested_key == "model");
        CHECK(card->body.find(">a<") != std::string::npos); // real cohort rendered
    }

    SECTION("an invalid ?key= falls back to the default, never reaches the provider") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            perf, yuzu::server::test::FnDexPerfApi::Providers{});
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, {}, {}, {}, {}, {},
                               dex_perf_api);
        auto tab = sink.Get("/fragments/dex/perf?key=not%20a%20valid%20key%21");
        REQUIRE(tab);
        CHECK(tab->status == 200);
        CHECK(requested_key == "model");
    }

    SECTION("denied without GuaranteedState:Read") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            perf, yuzu::server::test::FnDexPerfApi::Providers{});
        routes.register_routes(sink, okAuth, noPerm, nullptr, fleet, {}, {}, {}, {}, {},
                               dex_perf_api);
        auto tab = sink.Get("/fragments/dex/perf");
        REQUIRE(tab);
        CHECK(tab->status == 403);
    }

    SECTION("no provider wired → honest unavailable placeholder") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, {});
        auto tab = sink.Get("/fragments/dex/perf");
        REQUIRE(tab);
        CHECK(tab->status == 200);
        CHECK(tab->body.find("unavailable") != std::string::npos);
    }
}

// ── PR2: device context (percentile strips) ──────────────────────────────────

TEST_CASE("device_context: pctiles, cohort floor, honest absence", "[dex][perf][model][device]") {
    auto snap = two_cohorts(12, 4); // cpu: a={10..21}, b={40..43}

    SECTION("device in an above-floor cohort gets both comparisons") {
        auto ctx = dex_perf_device_context(snap, "a-11"); // cpu 21, top of cohort a
        CHECK(ctx.found);
        CHECK(ctx.reporting);
        CHECK(ctx.cohort == "a");
        CHECK(ctx.cohort_n == 12);
        REQUIRE(ctx.cpu.value);
        CHECK(*ctx.cpu.value == 21.0);
        REQUIRE(ctx.cpu.fleet);
        CHECK(ctx.cpu.fleet->n == 16);
        CHECK(ctx.cpu.fleet_pctile == 75); // 12 of 16 values <= 21
        CHECK(ctx.cpu.cohort_pctile == 100);
        REQUIRE(ctx.cpu.cohort);
        CHECK(ctx.cpu.cohort->n == 12);
    }
    SECTION("sub-floor cohort withholds the cohort comparison — floor applies everywhere") {
        auto ctx = dex_perf_device_context(snap, "b-0");
        CHECK(ctx.cohort == "b");
        CHECK(ctx.cohort_n == 4);
        CHECK(ctx.cpu.fleet_pctile > 0);
        CHECK(ctx.cpu.cohort_pctile == -1);
        CHECK_FALSE(ctx.cpu.cohort);
    }
    SECTION("offline device: found=false") {
        auto ctx = dex_perf_device_context(snap, "nope");
        CHECK_FALSE(ctx.found);
    }
    SECTION("floor boundary: n=9 withholds, n=10 grants (the off-by-one pin)") {
        auto nine = two_cohorts(9, 0);
        auto c9 = dex_perf_device_context(nine, "a-0");
        CHECK(c9.cohort_n == 9);
        CHECK(c9.cpu.cohort_pctile == -1);
        CHECK_FALSE(c9.cpu.cohort);
        CHECK(dex_perf_cohorts(nine)[0].suppressed);

        auto ten = two_cohorts(10, 0);
        auto c10 = dex_perf_device_context(ten, "a-0");
        CHECK(c10.cohort_n == 10);
        CHECK(c10.cpu.cohort_pctile >= 0);
        REQUIRE(c10.cpu.cohort);
        CHECK_FALSE(dex_perf_cohorts(ten)[0].suppressed);
    }
    SECTION("online but not reporting: found, not reporting, no pctiles") {
        snap.devices.push_back(dev("quiet", std::nullopt, std::nullopt, std::nullopt, "a"));
        auto ctx = dex_perf_device_context(snap, "quiet");
        CHECK(ctx.found);
        CHECK_FALSE(ctx.reporting);
        CHECK(ctx.cpu.fleet_pctile == -1);
    }
}

TEST_CASE("device context strips render: honest notes + cohort drill + escape",
          "[dex][perf][render][device]") {
    auto snap = two_cohorts(12, 0);
    SECTION("reporting device renders bands + fleet pctile + cohort link") {
        auto html = render_dex_device_perf_context(dex_perf_device_context(snap, "a-0"), "model",
                                                   "7d");
        CHECK(html.find("This device vs fleet") != std::string::npos);
        CHECK(html.find("th</b> pctile") != std::string::npos);
        CHECK(html.find("cohort_value=a") != std::string::npos); // drill to the cohort list
    }
    SECTION("not-reporting device gets an honest note, no fake bars") {
        snap.devices.push_back(dev("quiet", std::nullopt, std::nullopt, std::nullopt, "a"));
        auto html = render_dex_device_perf_context(dex_perf_device_context(snap, "quiet"),
                                                   "model", "7d");
        CHECK(html.find("No perf heartbeat") != std::string::npos);
        CHECK(html.find("pctile") == std::string::npos);
    }
    SECTION("device reporting ONLY cpu: other strips skip honestly, no fake bars") {
        auto part = two_cohorts(12, 0);
        part.devices.push_back(dev("cpu-only", 50.0, std::nullopt, std::nullopt, "a"));
        auto html = render_dex_device_perf_context(dex_perf_device_context(part, "cpu-only"),
                                                   "model", "7d");
        CHECK(html.find("CPU utilization") != std::string::npos);
        CHECK(html.find("Memory commit") == std::string::npos);   // no value → no bar
        CHECK(html.find("Disk I/O latency") == std::string::npos);
    }
    SECTION("sub-floor cohort: comparison withheld with the floor named") {
        // NB: not named `small` — windows headers #define small to char.
        auto tiny = two_cohorts(0, 4);
        tiny.devices.push_back(
            dev("solo", 50.0, 50.0, 1.0, "<i>x</i>")); // 1-device cohort, hostile value
        for (int i = 0; i < 12; ++i) // fleet context so fleet stats exist
            tiny.devices.push_back(dev("f-" + std::to_string(i), 10.0, 40.0, 1.0, "other"));
        auto html = render_dex_device_perf_context(dex_perf_device_context(tiny, "solo"),
                                                   "model", "7d");
        CHECK(html.find("Cohort comparison withheld") != std::string::npos);
        CHECK(html.find("<i>x</i>") == std::string::npos); // never unescaped
    }
}

// ── PR2: per-app parse + render ──────────────────────────────────────────────

TEST_CASE("procperf parse: schema-by-name, validation, clamps", "[dex][perf][procperf]") {
    const std::string ok =
        "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\n"
        "Teams.exe|2880|6|8.4|41.2|2040109465|3328599654|24\n"
        "chrome.exe|2880|14|5.3|36.7|2576980377|4294967296|24\n"
        "total|2\n";
    auto rows = parse_dex_procperf_output(ok);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "Teams.exe");
    CHECK(rows[0].samples == 2880);
    CHECK(rows[0].instances_max == 6);
    CHECK(rows[0].cpu_avg == 8.4);
    CHECK(rows[0].hours == 24);

    SECTION("error payload → empty") {
        CHECK(parse_dex_procperf_output("error|no such table").empty());
    }
    SECTION("wrong shape → refuse rather than guess") {
        CHECK(parse_dex_procperf_output("__schema__|name|bogus\nx|1\n").empty());
    }
    SECTION("forged rows are skipped per-field, valid rows survive") {
        const std::string forged =
            "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\n"
            "inf-cpu.exe|10|1|inf|5|100|100|1\n"  // non-finite → skipped
            "pb-ws.exe|10|1|5|5|9e15|9e15|1\n"    // >1 PiB working set → skipped
            "|10|1|5|5|100|100|1\n"               // empty name → skipped
            "ok.exe|10|1|250|5|100|100|1\n";      // >100% cpu → CLAMPED, kept
        auto r = parse_dex_procperf_output(forged);
        REQUIRE(r.size() == 1);
        CHECK(r[0].name == "ok.exe");
        CHECK(r[0].cpu_avg == 100.0);
    }
    SECTION("huge-but-finite count cells are rejected BEFORE the int64 cast (UB pin)") {
        // G3 BLOCKING (cpp-safety + cpp-expert): static_cast<int64_t>(1e30) is
        // UB per [conv.fpint]. cell_double's 1e15 ceiling must reject these —
        // this row crashing under UBSan is the regression signal.
        const std::string huge =
            "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\n"
            "ub.exe|1e30|1|5|5|100|100|1\n"  // samples unrepresentable in int64
            "ub2.exe|10|9e18|5|5|100|100|1\n" // instances likewise
            "ub3.exe|10|1|5|5|100|100|1e300\n" // hours likewise
            "ok.exe|10|1|5|5|100|100|1\n";
        auto r = parse_dex_procperf_output(huge);
        REQUIRE(r.size() == 1);
        CHECK(r[0].name == "ok.exe");
    }
    SECTION("trailing garbage in a numeric cell rejects the row (full-token stod)") {
        const std::string tail =
            "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\n"
            "tail.exe|10xyz|1|5|5|100|100|1\n"
            "ok.exe|10|1|5.5|5.5|100|100|1\n";
        auto r = parse_dex_procperf_output(tail);
        REQUIRE(r.size() == 1);
        CHECK(r[0].name == "ok.exe");
        CHECK(r[0].cpu_avg == 5.5);
    }
    SECTION("CRLF line endings parse identically (real Windows agent output)") {
        const std::string crlf =
            "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\r\n"
            "Teams.exe|10|1|5|5|100|100|1\r\n";
        auto r = parse_dex_procperf_output(crlf);
        REQUIRE(r.size() == 1);
        CHECK(r[0].name == "Teams.exe");
    }
    SECTION("reordered schema columns resolve by NAME, not position") {
        const std::string reordered =
            "__schema__|hours|name|ws_max|ws_avg|cpu_max|cpu_avg|instances_max|samples\n"
            "24|Teams.exe|200|100|9.9|5.5|3|480\n";
        auto r = parse_dex_procperf_output(reordered);
        REQUIRE(r.size() == 1);
        CHECK(r[0].name == "Teams.exe");
        CHECK(r[0].hours == 24);
        CHECK(r[0].samples == 480);
        CHECK(r[0].instances_max == 3);
        CHECK(r[0].cpu_avg == 5.5);
    }
    SECTION("row cap: only the first 100 valid rows are kept (DoS guard pin)") {
        std::string many = "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\n";
        for (int i = 0; i < 120; ++i)
            many += "app" + std::to_string(i) + ".exe|10|1|5|5|100|100|1\n";
        CHECK(parse_dex_procperf_output(many).size() == 100);
    }
}

TEST_CASE("perf tag parsing: full-token stod pin (trailing garbage + locale shield)",
          "[dex][perf][rules][pin]") {
    // G3 cpp-expert: stod("42.5xyz") returns 42.5; under a comma-decimal
    // locale "42.5" parses as 42 with pos < size. pos==size rejects both —
    // a mis-parse becomes a rejection, never a silent value distortion.
    CHECK_FALSE(rules::parse_perf_cpu_pct("42.5xyz"));
    CHECK_FALSE(rules::parse_perf_cpu_pct("1e3;DROP"));
    CHECK(rules::parse_perf_cpu_pct("42.5") == 42.5);
}

TEST_CASE("procperf render: app drill links + escape + the soft empty state",
          "[dex][perf][procperf][render]") {
    std::vector<DexProcPerfRow> rows(1);
    rows[0].name = "<img src=x>";
    rows[0].samples = 10;
    rows[0].cpu_avg = 5.0;
    rows[0].ws_avg_bytes = 2.0e9;
    rows[0].ws_max_bytes = 3.0e9;
    rows[0].hours = 24;
    auto html = render_dex_procperf_panel(rows, "7d");
    CHECK(html.find("<img src=x>") == std::string::npos); // agent bytes escaped
    CHECK(html.find("&lt;img") != std::string::npos);
    CHECK(html.find("/fragments/dex/app?name=") != std::string::npos); // cross-link
    CHECK(html.find("names only") != std::string::npos);

    // The SOFT truthful empty state: off-by-default OR no rollup yet — both said.
    auto empty = render_dex_procperf_panel({}, "7d");
    CHECK(empty.find("off by default") != std::string::npos);
    CHECK(empty.find("no hourly rollup has completed yet") != std::string::npos);
}

// ── PR3: per-cohort Prometheus export ────────────────────────────────────────

TEST_CASE("cohort gauge export: floor, untagged label, clipped visibility, absent on disable",
          "[dex][perf][export]") {
    yuzu::MetricsRegistry metrics;
    auto snap = two_cohorts(12, 4); // "a" exports, "b" is sub-floor
    for (int i = 0; i < 11; ++i)    // 11 untagged → above floor, exports as "(untagged)"
        snap.devices.push_back(dev("u-" + std::to_string(i), 5.0, 40.0, 0.5, ""));

    dex_perf_export_cohort_gauges(metrics, dex_perf_cohorts(snap));
    auto text = metrics.serialize();
    CHECK(text.find("yuzu_fleet_perf_cohort_cpu_pct{cohort=\"a\",stat=\"p50\"}") !=
          std::string::npos);
    CHECK(text.find("yuzu_fleet_perf_cohort_reporting{cohort=\"a\"} 12") != std::string::npos);
    CHECK(text.find("cohort=\"(untagged)\"") != std::string::npos);
    CHECK(text.find("cohort=\"b\"") == std::string::npos); // sub-floor — withheld
    CHECK(text.find("yuzu_fleet_perf_cohort_clipped 0") != std::string::npos); // measured zero

    SECTION("clear → every cohort series goes absent (never stale)") {
        dex_perf_clear_cohort_gauges(metrics);
        auto cleared = metrics.serialize();
        CHECK(cleared.find("cohort=\"a\"") == std::string::npos);
        CHECK(cleared.find("yuzu_fleet_perf_cohort_clipped 0") == std::string::npos);
    }
    SECTION("cap: top-N by population export, the rest are counted, not silent") {
        DexPerfSnapshot big;
        big.cohort_key = "model";
        // 7 cohorts of descending population (16..10), all above the floor.
        for (int c = 0; c < 7; ++c)
            for (int i = 0; i < 16 - c; ++i)
                big.devices.push_back(dev("c" + std::to_string(c) + "-" + std::to_string(i),
                                          10.0, 50.0, 1.0, "m" + std::to_string(c)));
        dex_perf_export_cohort_gauges(metrics, dex_perf_cohorts(big), /*cap=*/5);
        auto capped = metrics.serialize();
        CHECK(capped.find("cohort=\"m0\"") != std::string::npos); // biggest survives
        CHECK(capped.find("cohort=\"m4\"") != std::string::npos);
        CHECK(capped.find("cohort=\"m5\"") == std::string::npos); // clipped
        CHECK(capped.find("cohort=\"m6\"") == std::string::npos);
        CHECK(capped.find("yuzu_fleet_perf_cohort_clipped 2") != std::string::npos);
    }
}

// ── REST surface (/api/v1/dex/perf/*) ────────────────────────────────────────

namespace {

/// Registers RestApiV1 with every dep nulled except the perf provider — the
/// perf endpoints deliberately depend on nothing else.
struct RestPerfHarness {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    bool grant_perms{true};

    explicit RestPerfHarness(DexPerfFn perf) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            return auth::Session{};
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (grant_perms)
                return true;
            res.status = 403;
            return false;
        };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            return true;
        };
        // ADR-0031 WS-A4 (sixth family): the heartbeat-now routes now call the
        // DexPerfApi seam, not `dex_perf_fn` directly — wrap the SAME `perf`
        // provider (FnDexPerfApi, mirrors FnVerifyApi) so this harness's
        // "perf endpoints depend on nothing else" contract still holds.
        // Conditional, NOT unconditional: several existing tests construct
        // `RestPerfHarness(DexPerfFn{})` specifically to prove the "no
        // provider wired -> 503" path; an unconditionally-non-null seam would
        // make `fleet_snapshot()` degrade to an empty-but-PRESENT snapshot
        // instead (FnDexPerfApi's own null-fn contract), turning that 503
        // into a 200.
        std::shared_ptr<const yuzu::server::DexPerfApi> dex_perf_api_local;
        if (perf)
            dex_perf_api_local = std::make_shared<yuzu::server::test::FnDexPerfApi>(
                perf, yuzu::server::test::FnDexPerfApi::Providers{});
        api.register_routes(sink, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, nullptr,
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, {}, {},
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, {},
                            nullptr, nullptr, {}, {}, {}, std::move(perf),
                            /*network_api=*/nullptr, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{}, /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr, /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
                            /*exec_visible_fn=*/{}, /*list_read_fn=*/{}, /*fleet_read_fn=*/{},
                            /*agents_fn=*/{}, /*response_visible_set_fn=*/{},
                            /*dex_visible_fn=*/{}, /*verify_api=*/nullptr,
                            /*device_api=*/nullptr, /*dex_api=*/nullptr, dex_perf_api_local);
    }
};

} // namespace

TEST_CASE("REST /dex/perf/fleet: stats + denominators, absent metric is null",
          "[dex][perf][rest]") {
    DexPerfFn perf = [](const std::string&) {
        DexPerfSnapshot snap;
        snap.devices.push_back(dev("w1", 10.0, std::nullopt, std::nullopt));
        snap.devices.push_back(dev("w2", 30.0, std::nullopt, std::nullopt));
        snap.devices.push_back(dev("w3", std::nullopt, std::nullopt, std::nullopt));
        return snap;
    };
    RestPerfHarness h(perf);
    auto res = h.sink.Get("/api/v1/dex/perf/fleet");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["cpu_pct"]["n"] == 2);
    CHECK(j["data"]["cpu_pct"]["avg"] == 20.0);
    CHECK(j["data"]["cpu_pct"]["max"] == 30.0);
    CHECK(j["data"]["commit_pct"].is_null()); // nobody reported — null, never 0
    CHECK(j["data"]["reporting"] == 2);
    CHECK(j["data"]["windows_online"] == 3);
    // Additive per-OS fields (C1) — all-Windows fixture, so linux/macos are 0.
    CHECK(j["data"]["linux_online"] == 0);
    CHECK(j["data"]["macos_online"] == 0);
    CHECK(j["data"]["reporting_windows"] == 2);
    CHECK(j["data"]["reporting_linux"] == 0);
    CHECK(j["data"]["reporting_macos"] == 0);
}

TEST_CASE("REST /dex/perf/* A4 error bodies carry retry_after_ms + X-Correlation-Id (#1470)",
          "[dex][perf][rest][a4]") {
    DexPerfFn perf = [](const std::string&) { return DexPerfSnapshot{}; };

    SECTION("invalid cohort_key → 400 with A4 retry_after_ms:null + header") {
        RestPerfHarness h(perf);
        auto res = h.sink.Get("/api/v1/dex/perf/devices?cohort_key=not%20a%20key%21");
        REQUIRE(res);
        CHECK(res->status == 400);
        // Header present on every dex-perf response (success and error).
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        auto j = nlohmann::json::parse(res->body);
        // A4 envelope: code, correlation_id, and the always-present nullable field.
        CHECK(j["error"]["code"] == 400);
        CHECK(j["error"]["correlation_id"].get<std::string>().rfind("req-", 0) == 0);
        CHECK(j["error"]["retry_after_ms"].is_null());
    }

    SECTION("invalid limit → 400 with A4 retry_after_ms:null") {
        RestPerfHarness h(perf);
        auto res = h.sink.Get("/api/v1/dex/perf/devices?limit=0");
        REQUIRE(res);
        CHECK(res->status == 400);
        auto j = nlohmann::json::parse(res->body);
        CHECK(j["error"]["retry_after_ms"].is_null());
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    }

    SECTION("invalid tag key on /cohorts → 400 A4") {
        RestPerfHarness h(perf);
        auto res = h.sink.Get("/api/v1/dex/perf/cohorts?key=not%20a%20key%21");
        REQUIRE(res);
        CHECK(res->status == 400);
        auto j = nlohmann::json::parse(res->body);
        CHECK(j["error"]["correlation_id"].get<std::string>().rfind("req-", 0) == 0);
        CHECK(j["error"]["retry_after_ms"].is_null());
    }

    SECTION("no provider → 503 with a concrete retry_after_ms (warmup)") {
        RestPerfHarness h(DexPerfFn{}); // null provider
        auto res = h.sink.Get("/api/v1/dex/perf/devices");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        auto j = nlohmann::json::parse(res->body);
        CHECK(j["error"]["retry_after_ms"] == 5000); // non-null on a retryable condition
    }
}

TEST_CASE("REST /dex/perf/cohorts: floor + suppression + untagged in the JSON",
          "[dex][perf][rest]") {
    DexPerfFn perf = [](const std::string& key) {
        auto snap = two_cohorts(12, 4);
        snap.cohort_key = key;
        snap.devices.push_back(dev("u-1", 5.0, 40.0, 0.5, ""));
        for (int i = 0; i < 9; ++i) // 10 untagged total → above floor
            snap.devices.push_back(dev("u-" + std::to_string(i + 2), 5.0, 40.0, 0.5, ""));
        return snap;
    };
    RestPerfHarness h(perf);
    auto res = h.sink.Get("/api/v1/dex/perf/cohorts?key=model");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["key"] == "model");
    CHECK(j["data"]["floor"] == kDexCohortFloor);
    const auto& cohorts = j["data"]["cohorts"];
    REQUIRE(cohorts.size() == 3);
    CHECK(cohorts[0]["cohort"] == "a");
    CHECK(cohorts[0]["suppressed"] == false);
    CHECK(cohorts[0]["cpu_pct"]["n"] == 12);
    CHECK(cohorts[1]["cohort"] == "b");
    CHECK(cohorts[1]["suppressed"] == true); // population visible, stats withheld
    CHECK_FALSE(cohorts[1].contains("cpu_pct"));
    CHECK(cohorts[2]["cohort"] == ""); // the untagged residual, last
    CHECK(cohorts[2]["devices"] == 10);

    SECTION("invalid key → 400") {
        auto bad = h.sink.Get("/api/v1/dex/perf/cohorts?key=not%20valid%21");
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
}

TEST_CASE("REST /dex/perf/devices: sort, filters, validation", "[dex][perf][rest]") {
    DexPerfFn perf = [](const std::string&) { return two_cohorts(3, 3); };
    RestPerfHarness h(perf);

    auto res = h.sink.Get("/api/v1/dex/perf/devices?metric=cpu&limit=2");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].size() == 2);
    CHECK(j["data"][0]["agent_id"] == "b-2"); // worst first
    CHECK(j["data"][0]["fleet_pctile"] == 100);
    CHECK(j["data"][0]["cohort"] == "b"); // grill pin: default key resolves cohorts
    CHECK(j["data"][0]["os"] == "windows"); // additive (C1); two_cohorts' dev() default

    SECTION("cohort_key without cohort_value resolves display but does NOT filter") {
        auto all = h.sink.Get("/api/v1/dex/perf/devices?cohort_key=model");
        REQUIRE(all);
        auto ja = nlohmann::json::parse(all->body);
        CHECK(ja["data"].size() == 6); // both cohorts present — no implicit filter
    }
    SECTION("empty cohort_value present = the untagged residual filter") {
        auto none = h.sink.Get("/api/v1/dex/perf/devices?cohort_key=model&cohort_value=");
        REQUIRE(none);
        auto jn = nlohmann::json::parse(none->body);
        CHECK(jn["data"].empty()); // two_cohorts has no untagged devices
    }

    SECTION("invalid limit → 400") {
        auto bad = h.sink.Get("/api/v1/dex/perf/devices?limit=0");
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
    SECTION("invalid cohort_key → 400") {
        auto bad = h.sink.Get("/api/v1/dex/perf/devices?cohort_key=bad%20key");
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
    SECTION("perm denied → 403") {
        h.grant_perms = false;
        auto denied = h.sink.Get("/api/v1/dex/perf/fleet");
        REQUIRE(denied);
        CHECK(denied->status == 403);
    }
}

TEST_CASE("OpenAPI spec lists the perf endpoints (A2 discovery) and stays valid JSON",
          "[dex][perf][rest][discovery][a2]") {
    RestPerfHarness h({});
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // The spec literal is hand-maintained — parse the WHOLE document so an
    // edit that breaks JSON validity fails here, not in a client generator.
    REQUIRE_NOTHROW(nlohmann::json::parse(res->body));
    CHECK(res->body.find(R"("/dex/perf/fleet":)") != std::string::npos);
    CHECK(res->body.find(R"("/dex/perf/cohorts":)") != std::string::npos);
    CHECK(res->body.find(R"("/dex/perf/devices":)") != std::string::npos);
}

TEST_CASE("REST /dex/perf/*: no provider wired → 503", "[dex][perf][rest]") {
    RestPerfHarness h({});
    for (const char* path : {"/api/v1/dex/perf/fleet", "/api/v1/dex/perf/cohorts",
                             "/api/v1/dex/perf/devices"}) {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 503);
    }
}

TEST_CASE("procperf routes: own audit verb, Execute gate, result narrowing",
          "[dex][perf][procperf][routes]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    // Grants Read but denies Execution:Execute — the probed-Execute posture.
    auto readOnlyPerm = [](const httplib::Request&, httplib::Response& res,
                           const std::string& type, const std::string& op) {
        if (type == "Execution" && op == "Execute") {
            res.status = 403;
            return false;
        }
        return true;
    };
    auto fleet = []() { return DexFleet{}; };
    std::vector<std::string> audited;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string&,
                     const std::string&, const std::string& tid, const std::string&) -> bool {
        audited.push_back(a + "|" + tid);
        return true;
    };
    std::string dispatched_sql;
    DexRoutes::DispatchFn dispatch =
        [&](const std::string&, const std::string&, const std::vector<std::string>&,
            const std::string&, const std::unordered_map<std::string, std::string>& params)
        -> yuzu::server::ConfinedDispatchOutcome {
        auto it = params.find("sql");
        dispatched_sql = it != params.end() ? it->second : "";
        return {.sent = 1, .command_id = "tar-abc123"};
    };
    const std::string output =
        "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\n"
        "Teams.exe|2880|6|8.4|41.2|2040109465|3328599654|24\n";
    DexRoutes::ResponsesFn responses =
        [&](const std::string& command_id, const std::string& /*agent_id*/)
        -> std::vector<DexAgentResponse> {
        if (command_id == "tar-abc123")
            return {{"WS-1", 0, output, ""}};
        return {};
    };

    SECTION("dispatch fires the usage-class audit verb + the $ProcPerf_Hourly canned SQL") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, dispatch, responses);
        auto r = sink.Get("/fragments/dex/device/procperf?agent_id=WS-1&window=7d");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("/fragments/dex/device/procperf/result") != std::string::npos);
        REQUIRE(audited.size() == 1);
        CHECK(audited[0] == "dex.device.procperf.query|WS-1"); // NOT dex.device.perf.query
        CHECK(dispatched_sql.find("$ProcPerf_Hourly") != std::string::npos);
        CHECK(dispatched_sql.find("GROUP BY name") != std::string::npos);
    }
    SECTION("audit-persist failure → Sec-Audit-Failed header, panel still renders (#1549)") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        // A dropped evidence row on this usage-class dispatch must surface the gap.
        auto failAudit = [](const httplib::Request&, const std::string&, const std::string&,
                            const std::string&, const std::string&, const std::string&) -> bool {
            return false;
        };
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, failAudit, dispatch, responses);
        auto r = sink.Get("/fragments/dex/device/procperf?agent_id=WS-1&window=7d");
        REQUIRE(r);
        CHECK(r->status == 200); // HTML surface still renders
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    }
    SECTION("read-only operator gets the honest in-panel note, nothing dispatched/audited") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, readOnlyPerm, nullptr, fleet, audit, dispatch,
                               responses);
        auto r = sink.Get("/fragments/dex/device/procperf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Execute") != std::string::npos);
        CHECK(audited.empty());
        CHECK(dispatched_sql.empty());
    }
    SECTION("result route renders the parsed panel; non-tar command_ids are rejected") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, dispatch, responses);
        auto ok = sink.Get(
            "/fragments/dex/device/procperf/result?command_id=tar-abc123&agent_id=WS-1&window=7d");
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(ok->body.find("Teams.exe") != std::string::npos);
        auto bad = sink.Get(
            "/fragments/dex/device/procperf/result?command_id=cmd-abc123&agent_id=WS-1");
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
}

TEST_CASE("device fragment: strips + the own-click applications button ride along",
          "[pg][dex][perf][routes][device]") {
    // The device drill route feeds the strips from the perf snapshot; the
    // per-app button must carry its OWN route (not the machine-health one).
    auto snap = two_cohorts(12, 0);
    auto html = render_dex_device_fragment(nullptr, "a-0", "7d", &snap);
    // Null store → placeholder (store-gated), but the panel block isn't reached.
    CHECK(html.find("unavailable") != std::string::npos);

    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    GuaranteedStateStore store(pool);
    html = render_dex_device_fragment(&store, "a-0", "7d", &snap);
    CHECK(html.find("This device vs fleet") != std::string::npos);
    CHECK(html.find("/fragments/dex/device/procperf?agent_id=a-0") != std::string::npos);
    CHECK(html.find("Load applications") != std::string::npos);
    // Without a snapshot the strips are omitted, the button still renders.
    html = render_dex_device_fragment(&store, "a-0", "7d", nullptr);
    CHECK(html.find("This device vs fleet") == std::string::npos);
    CHECK(html.find("Load applications") != std::string::npos);
}

TEST_CASE("dex_cohort_export_key is an allowlisted runtime setting",
          "[dex][perf][export][pin]") {
    // UAT live-fire 2026-06-12 caught the settings POST 500ing because the
    // key was never added to RuntimeConfigStore's allowlist — the handler is
    // only as real as the store behind it. Pin every runtime_config key the
    // DEX settings handlers write.
    for (const char* key : {"dex_alert_routing", "dex_blast_min_devices",
                            "dex_blast_window_seconds", "dex_blast_cooldown_seconds",
                            "dex_cohort_export_key"})
        CHECK(RuntimeConfigStore::is_allowed_key(key));
}

TEST_CASE("tag-key alphabet stays pinned to TagStore::validate_key",
          "[dex][perf][routes][pin]") {
    // dex_routes.cpp validates ?key= with a local copy of the TagStore key
    // alphabet (to stay decoupled from the store). This pin breaks if either
    // side changes alone.
    CHECK(TagStore::validate_key("model"));
    CHECK(TagStore::validate_key("a.b:c-d_e"));
    CHECK_FALSE(TagStore::validate_key(""));
    CHECK_FALSE(TagStore::validate_key("has space"));
    CHECK_FALSE(TagStore::validate_key(std::string(65, 'a')));
}

TEST_CASE("the route's valid_tag_key copy AGREES with TagStore::validate_key (C-S3)",
          "[dex][perf][routes][pin]") {
    // The previous pin only exercised the TagStore side. Drive each alphabet
    // class through the FRAGMENT route and assert the provider received the
    // key iff the store would accept it — now drift in EITHER copy fails.
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    std::string requested_key;
    DexPerfFn perf = [&](const std::string& key) {
        requested_key = key;
        return DexPerfSnapshot{};
    };
    yuzu::server::test::TestRouteSink sink;
    DexRoutes routes;
    auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
        perf, yuzu::server::test::FnDexPerfApi::Providers{});
    routes.register_routes(sink, okAuth, okPerm, nullptr, []() { return DexFleet{}; }, {}, {},
                           {}, {}, {}, dex_perf_api);

    struct Case {
        const char* raw;     // urlencoded query value
        const char* decoded; // what the route sees
    };
    // Accepted classes: alnum, '_', '.', ':' (%3A), '-'
    for (const Case& c : {Case{"model", "model"}, Case{"a.b%3Ac-d_e", "a.b:c-d_e"},
                          Case{"UPPER9", "UPPER9"}}) {
        requested_key.clear();
        REQUIRE(sink.Get(std::string("/fragments/dex/perf?key=") + c.raw));
        CHECK(TagStore::validate_key(c.decoded));
        CHECK(requested_key == c.decoded); // route accepted exactly what the store would
    }
    // Rejected classes fall back to the default key.
    for (const char* raw : {"has%20space", "semi%3Bcolon", "slash%2Fkey",
                            // 65 chars — over the store's 64 cap
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}) {
        requested_key.clear();
        REQUIRE(sink.Get(std::string("/fragments/dex/perf?key=") + raw));
        CHECK(requested_key == kDexDefaultCohortKey);
    }
}

TEST_CASE("AgentHealthStore: perf_snapshot prunes to perf tags; reporting = any-of-three",
          "[dex][perf][health][pin]") {
    yuzu::server::detail::AgentHealthStore store;
    google::protobuf::Map<std::string, std::string> commit_only;
    commit_only["yuzu.perf_commit_pct"] = "50";
    commit_only["yuzu.os"] = "windows";
    commit_only["yuzu.commands_executed"] = "7";
    store.upsert("commit-only", commit_only);
    google::protobuf::Map<std::string, std::string> no_perf;
    no_perf["yuzu.os"] = "windows";
    store.upsert("no-perf", no_perf);

    SECTION("perf_snapshot carries ONLY the perf tags (heartbeat-mutex copy bound)") {
        auto snaps = store.perf_snapshot(std::chrono::seconds{90});
        REQUIRE(snaps.size() == 2);
        for (const auto& s : snaps) {
            CHECK_FALSE(s.status_tags.contains("yuzu.os"));
            CHECK_FALSE(s.status_tags.contains("yuzu.commands_executed"));
            if (s.agent_id == "commit-only") {
                CHECK(s.status_tags.contains("yuzu.perf_commit_pct"));
            } else {
                CHECK(s.status_tags.empty());
            }
        }
    }
    SECTION("C-S2: a commit-only reporter counts in yuzu_fleet_perf_reporting") {
        yuzu::MetricsRegistry metrics;
        store.recompute_metrics(metrics, std::chrono::seconds{90});
        auto text = metrics.serialize();
        CHECK(text.find("yuzu_fleet_perf_reporting 1") != std::string::npos);
        // The cpu family is absent (nobody reported cpu) — absent, not zero.
        CHECK(text.find("yuzu_fleet_perf_cpu_pct") == std::string::npos);
    }
}

// ── dex_perf_cohort_diff (F2c, BRD rows 99/103) ──────────────────────────────

namespace {
/// Two cohorts with CONSTANT per-cohort metrics, so each cohort's p50 equals
/// its constant and the A-vs-B deltas are exact integers (no float tolerance).
/// `na`/`nb` size the cohorts (vary them to cross the suppression floor).
DexPerfSnapshot diff_snap(int na, int nb) {
    DexPerfSnapshot snap;
    snap.cohort_key = "model";
    snap.available_keys = {"model"};
    for (int i = 0; i < na; ++i) // cohort "a": cpu 20, commit 50, disk 2
        snap.devices.push_back(dev("a-" + std::to_string(i), 20.0, 50.0, 2.0, "a"));
    for (int i = 0; i < nb; ++i) // cohort "b": cpu 40, commit 100, disk 4
        snap.devices.push_back(dev("b-" + std::to_string(i), 40.0, 100.0, 4.0, "b"));
    return snap;
}
} // namespace

TEST_CASE("cohort_diff: A-vs-B p50 deltas with B as baseline", "[dex][perf][cohort_diff]") {
    auto d = dex_perf_cohort_diff(diff_snap(12, 12), "a", "b"); // both above floor
    REQUIRE(d.found_a);
    REQUIRE(d.found_b);
    CHECK(d.a.cohort == "a");
    CHECK(d.b.cohort == "b");
    CHECK_FALSE(d.a.suppressed);
    CHECK_FALSE(d.b.suppressed);
    // delta = (A.p50 - B.p50) / B.p50 * 100; constants → exact.
    REQUIRE(d.cpu_delta_pct.has_value());
    REQUIRE(d.commit_delta_pct.has_value());
    REQUIRE(d.disk_lat_delta_pct.has_value());
    CHECK(*d.cpu_delta_pct == (20.0 - 40.0) / 40.0 * 100.0);    // -50
    CHECK(*d.commit_delta_pct == (50.0 - 100.0) / 100.0 * 100.0); // -50
    CHECK(*d.disk_lat_delta_pct == (2.0 - 4.0) / 4.0 * 100.0); // -50
}

TEST_CASE("cohort_diff: swapping A/B re-baselines the delta", "[dex][perf][cohort_diff]") {
    auto snap = diff_snap(12, 12);
    auto ba = dex_perf_cohort_diff(snap, "b", "a"); // A=b, baseline=a
    REQUIRE(ba.cpu_delta_pct.has_value());
    // (40-20)/20*100 = +100 — opposite sign AND different magnitude vs a-vs-b's -50,
    // because the baseline changed (it's not a mere sign flip).
    CHECK(*ba.cpu_delta_pct == (40.0 - 20.0) / 20.0 * 100.0);
}

TEST_CASE("cohort_diff: a missing cohort yields not-found and no deltas",
          "[dex][perf][cohort_diff]") {
    auto d = dex_perf_cohort_diff(diff_snap(12, 12), "a", "does-not-exist");
    CHECK(d.found_a);
    CHECK_FALSE(d.found_b);
    CHECK_FALSE(d.cpu_delta_pct.has_value());
    CHECK_FALSE(d.commit_delta_pct.has_value());
    CHECK_FALSE(d.disk_lat_delta_pct.has_value());
}

TEST_CASE("cohort_diff: a sub-floor cohort shows population but withholds deltas",
          "[dex][perf][cohort_diff]") {
    auto d = dex_perf_cohort_diff(diff_snap(12, 3), "a", "b"); // "b" below kDexCohortFloor
    REQUIRE(d.found_a);
    REQUIRE(d.found_b);
    CHECK_FALSE(d.a.suppressed);
    CHECK(d.b.suppressed);
    CHECK(d.b.devices == 3); // population still reported
    // b is suppressed (no stats) → no metric can diff.
    CHECK_FALSE(d.cpu_delta_pct.has_value());
    CHECK_FALSE(d.commit_delta_pct.has_value());
    CHECK_FALSE(d.disk_lat_delta_pct.has_value());
}

TEST_CASE("cohort_diff: A==B is degenerate but safe (zero deltas)", "[dex][perf][cohort_diff]") {
    auto d = dex_perf_cohort_diff(diff_snap(12, 12), "a", "a");
    REQUIRE(d.found_a);
    REQUIRE(d.found_b);
    REQUIRE(d.cpu_delta_pct.has_value());
    CHECK(*d.cpu_delta_pct == 0.0);
    CHECK(*d.commit_delta_pct == 0.0);
    CHECK(*d.disk_lat_delta_pct == 0.0);
}

// ── cohort_diff render ───────────────────────────────────────────────────────

TEST_CASE("cohort_diff render: comparison table + populated delta", "[dex][perf][cohort_diff][render]") {
    auto html = render_dex_perf_cohort_diff_fragment(diff_snap(12, 12), "a", "b", 7);
    CHECK(html.find("a (A)") != std::string::npos); // cohort A header
    CHECK(html.find("b (B)") != std::string::npos); // cohort B header
    CHECK(html.find("(B)") != std::string::npos);
    CHECK(html.find("CPU utilization") != std::string::npos);
    CHECK(html.find("Memory commit") != std::string::npos);
    CHECK(html.find("Disk I/O latency") != std::string::npos);
    CHECK(html.find("-50%") != std::string::npos);       // A(20) vs B(40) → -50%
    CHECK(html.find("12 reporting") != std::string::npos); // population in the note
}

TEST_CASE("cohort_diff render: suppressed cohort shows 'n too small', delta withheld",
          "[dex][perf][cohort_diff][render]") {
    auto html = render_dex_perf_cohort_diff_fragment(diff_snap(12, 3), "a", "b", 7);
    CHECK(html.find("n too small") != std::string::npos); // B below the floor
    CHECK(html.find("&mdash;") != std::string::npos);     // delta dash (no comparison)
}

TEST_CASE("Performance tab carries the CSP-safe 'Compare two cohorts' pickers",
          "[dex][perf][cohort_diff][render]") {
    auto html = render_dex_perf_fragment(diff_snap(12, 12), 7);
    CHECK(html.find("Compare two cohorts") != std::string::npos);
    CHECK(html.find("name=\"a\"") != std::string::npos);
    CHECK(html.find("name=\"b\"") != std::string::npos);
    // both selects pulled on change via the proven #id include form (the id
    // wraps both pickers); auto-load div fires on load — all htmx core attrs,
    // NO hx-on (the CSP eval path the dashboard forbids).
    CHECK(html.find("id=\"dex-cohort-pick\"") != std::string::npos);    // wraps both selects
    CHECK(html.find("hx-include=\"#dex-cohort-pick\"") != std::string::npos);
    CHECK(html.find("id=\"dex-cohort-diff\"") != std::string::npos);
    CHECK(html.find("hx-trigger=\"load\"") != std::string::npos);
    CHECK(html.find("hx-on") == std::string::npos);
}

// ── cohort_diff routes (dashboard fragment) ──────────────────────────────────

TEST_CASE("cohort_diff route: served comparison + perm gate + degraded provider",
          "[dex][perf][cohort_diff][routes][rbac]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto noPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                     const std::string&) {
        res.status = 403;
        return false;
    };
    auto fleet = []() { return DexFleet{}; };
    DexPerfFn perf = [](const std::string&) { return diff_snap(12, 12); };

    SECTION("permitted: serves the A-vs-B comparison with a populated delta") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            perf, yuzu::server::test::FnDexPerfApi::Providers{});
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, {}, {}, {}, {}, {},
                               dex_perf_api);
        auto r = sink.Get("/fragments/dex/perf/cohort-diff?key=model&a=a&b=b");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("-50%") != std::string::npos);
    }
    SECTION("denied without GuaranteedState:Read") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            perf, yuzu::server::test::FnDexPerfApi::Providers{});
        routes.register_routes(sink, okAuth, noPerm, nullptr, fleet, {}, {}, {}, {}, {},
                               dex_perf_api);
        auto r = sink.Get("/fragments/dex/perf/cohort-diff?key=model&a=a&b=b");
        REQUIRE(r);
        CHECK(r->status == 403);
    }
    SECTION("no provider wired → honest unavailable placeholder") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, {});
        auto r = sink.Get("/fragments/dex/perf/cohort-diff?key=model&a=a&b=b");
        REQUIRE(r);
        CHECK(r->status == 200);
    }
}

// ── cohort_diff REST (/api/v1/dex/perf/cohort-diff) ──────────────────────────

TEST_CASE("REST /dex/perf/cohort-diff: deltas, required params, missing cohort",
          "[dex][perf][cohort_diff][rest]") {
    DexPerfFn perf = [](const std::string&) { return diff_snap(12, 12); };
    RestPerfHarness h(perf);

    auto res = h.sink.Get("/api/v1/dex/perf/cohort-diff?key=model&a=a&b=b");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["found_a"] == true);
    CHECK(j["data"]["found_b"] == true);
    CHECK(j["data"]["a"]["cohort"] == "a");
    CHECK(j["data"]["a"]["cpu_pct"]["p50"] == 20.0);
    CHECK(j["data"]["b"]["cpu_pct"]["p50"] == 40.0);
    CHECK(j["data"]["delta_pct"]["cpu_pct"] == -50.0);   // A(20) vs B(40)
    CHECK(j["data"]["delta_pct"]["commit_pct"] == -50.0); // A(50) vs B(100)

    SECTION("missing a or b → 400 (a value of \"\" is the untagged residual, not 'missing')") {
        auto bad = h.sink.Get("/api/v1/dex/perf/cohort-diff?key=model&a=a");
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
    SECTION("invalid key → 400") {
        auto bad = h.sink.Get("/api/v1/dex/perf/cohort-diff?key=not%20valid%21&a=a&b=b");
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
    SECTION("a missing cohort → found_b false, b null, deltas null") {
        auto r = h.sink.Get("/api/v1/dex/perf/cohort-diff?key=model&a=a&b=does-not-exist");
        REQUIRE(r);
        CHECK(r->status == 200);
        auto jj = nlohmann::json::parse(r->body);
        CHECK(jj["data"]["found_b"] == false);
        CHECK(jj["data"]["b"].is_null());
        CHECK(jj["data"]["delta_pct"]["cpu_pct"].is_null());
    }
}
