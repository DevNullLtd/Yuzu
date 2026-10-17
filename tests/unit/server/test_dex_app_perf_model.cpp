/**
 * test_dex_app_perf_model.cpp — slice-2 DEX app-perf-over-time READ model.
 *
 * Pure, DB-free coverage of the ONE shared transform the REST endpoint, the MCP
 * tool, and the dashboard all render through (so they cannot disagree):
 *
 *  - percentile_from_hist: nearest-rank DIRECTION over fixed buckets; lower-edge
 *    representative; the OPEN top bucket flagged as a floor (lower_bound); nullopt
 *    on an empty population or a size/scheme mismatch (defence beneath the
 *    caller's hist_version gate).
 *  - app_perf_fleet_trend: EXACT fleet mean = sum/device_count (no divide at
 *    device_count==0); percentiles withheld + hist_stale on a wrong-scheme row;
 *    populated on a current-scheme row.
 */
#include "app_perf_daily_store.hpp" // AppPerfDailyRow (device drill)
#include "app_perf_fleet_store.hpp"
#include "app_perf_hist.hpp"
#include "dex_app_perf_model.hpp"
#include "dex_perf_model.hpp" // kDexCohortFloor

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// A valid CPU hist is 12 buckets (11 boundaries → 12). Helper builds one with the
// given per-bucket counts (zero-padded / truncated to the right length).
std::vector<std::int64_t> cpu_hist(std::vector<std::int64_t> counts) {
    counts.resize(app_perf_cpu_buckets().size() + 1, 0);
    return counts;
}

} // namespace

TEST_CASE("percentile_from_hist: size mismatch and empty population degrade", "[dex][app_perf]") {
    const auto& b = app_perf_cpu_buckets(); // 11 boundaries

    // Wrong length (a corrupt / wrong-scheme row) → nullopt, never a wrong read.
    CHECK_FALSE(percentile_from_hist(std::vector<std::int64_t>(5, 0), b, 0.5).has_value());

    // Right length but zero population → nullopt (absent, never a fabricated 0).
    CHECK_FALSE(percentile_from_hist(cpu_hist({}), b, 0.5).has_value());
}

TEST_CASE("percentile_from_hist: nearest-rank lands in the right bucket", "[dex][app_perf]") {
    const auto& b = app_perf_cpu_buckets();
    // 5 devices in bucket 1 = [0.5,1) (lower edge b[0]=0.5);
    // 5 devices in bucket 9 = [30,50) (lower edge b[8]=30). total = 10.
    auto h = cpu_hist({0, 5, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0});

    auto p50 = percentile_from_hist(h, b, 0.50);
    REQUIRE(p50.has_value());
    CHECK(p50->value == 0.5); // rank ceil(.5*10)=5 → still bucket 1
    CHECK_FALSE(p50->lower_bound);

    auto p95 = percentile_from_hist(h, b, 0.95);
    REQUIRE(p95.has_value());
    CHECK(p95->value == 30.0); // rank ceil(.95*10)=10 → bucket 9
    CHECK_FALSE(p95->lower_bound);

    // p0 floors at rank 1 → the lowest populated bucket; p100 → the highest.
    CHECK(percentile_from_hist(h, b, 0.0)->value == 0.5);
    CHECK(percentile_from_hist(h, b, 1.0)->value == 30.0);
}

TEST_CASE("percentile_from_hist: open top bucket is a floor, bottom is the metric floor",
          "[dex][app_perf]") {
    const auto& b = app_perf_cpu_buckets();
    const std::size_t top = b.size(); // bucket index 11 = [75, +inf)

    // All mass in the open top bucket → value is the last boundary, flagged floor.
    std::vector<std::int64_t> hi(b.size() + 1, 0);
    hi[top] = 7;
    auto p = percentile_from_hist(hi, b, 0.95);
    REQUIRE(p.has_value());
    CHECK(p->value == b.back()); // 75
    CHECK(p->lower_bound);       // render "≥ 75", never as an exact value

    // All mass in bucket 0 = [0, b[0]) → the metric floor 0, NOT flagged.
    std::vector<std::int64_t> lo(b.size() + 1, 0);
    lo[0] = 7;
    auto q = percentile_from_hist(lo, b, 0.5);
    REQUIRE(q.has_value());
    CHECK(q->value == 0.0);
    CHECK_FALSE(q->lower_bound);
}

TEST_CASE("app_perf_fleet_trend: exact mean, no divide-by-zero", "[dex][app_perf]") {
    AppPerfFleetRow row;
    row.app_name = "chrome.exe";
    row.version = "124.0.0.1";
    row.day = 1'700'000'000;
    row.device_count = 20; // >= kDexCohortFloor so the row is NOT floor-suppressed
    row.cpu_sum = 100.0;   // mean 5.0
    row.cpu_max = 9.0;
    row.ws_sum = 2000;     // mean 100
    row.ws_max = 250;
    row.hist_version = kAppPerfHistVersion;
    row.cpu_hist = cpu_hist({0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0}); // bucket 4
    row.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);
    row.ws_hist[3] = 20;

    auto trend = app_perf_fleet_trend({row});
    REQUIRE(trend.size() == 1);
    const auto& pt = trend[0];
    CHECK(pt.version == "124.0.0.1");
    CHECK(pt.cpu_mean == 5.0);
    CHECK(pt.ws_mean == 100);
    CHECK_FALSE(pt.hist_stale);
    REQUIRE(pt.cpu_p50.has_value());
    CHECK(pt.cpu_p50->value == app_perf_cpu_buckets()[3]); // bucket 4 lower edge = b[3]=3
    REQUIRE(pt.ws_p50.has_value());

    // device_count == 0 → zero means, no UB.
    AppPerfFleetRow empty;
    empty.device_count = 0;
    empty.cpu_sum = 99.0;
    empty.hist_version = kAppPerfHistVersion;
    empty.cpu_hist = cpu_hist({});
    empty.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);
    auto t2 = app_perf_fleet_trend({empty});
    REQUIRE(t2.size() == 1);
    CHECK(t2[0].cpu_mean == 0.0);
    CHECK(t2[0].ws_mean == 0);
    CHECK_FALSE(t2[0].cpu_p50.has_value()); // empty population → nullopt
}

TEST_CASE("app_perf_group_trend: sub-floor points suppress stats, keep device_count",
          "[dex][app_perf]") {
    // Two points: one above the floor, one below. Same app, two days.
    AppPerfFleetRow big;
    big.app_name = "chrome.exe";
    big.version = "124";
    big.day = 1'700'000'000;
    big.device_count = 25; // >= floor
    big.cpu_sum = 125.0;   // mean 5.0
    big.cpu_max = 9.0;
    big.ws_sum = 2500;
    big.ws_max = 200;
    big.hist_version = kAppPerfHistVersion;
    big.cpu_hist = cpu_hist({0, 0, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0});
    big.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);
    big.ws_hist[3] = 25;

    AppPerfFleetRow small = big;
    small.day = 1'700'086'400;
    small.device_count = 3; // < floor (10)
    small.cpu_sum = 15.0;   // would be mean 5.0 — but must be suppressed
    small.cpu_hist = cpu_hist({0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0});
    small.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);
    small.ws_hist[3] = 3;

    auto pts = app_perf_group_trend({big, small}, /*floor=*/10);
    REQUIRE(pts.size() == 2);

    // Above floor: full stats, not suppressed.
    CHECK_FALSE(pts[0].suppressed);
    CHECK(pts[0].device_count == 25);
    CHECK(pts[0].cpu_mean == 5.0);
    CHECK(pts[0].cpu_p50.has_value());

    // Below floor: suppressed, device_count honest, ALL stats cleared.
    CHECK(pts[1].suppressed);
    CHECK(pts[1].device_count == 3); // the only honest field
    CHECK(pts[1].cpu_mean == 0.0);
    CHECK(pts[1].cpu_max == 0.0);
    CHECK(pts[1].ws_mean == 0);
    CHECK_FALSE(pts[1].cpu_p50.has_value());
    CHECK_FALSE(pts[1].cpu_p95.has_value());
    CHECK_FALSE(pts[1].ws_p50.has_value());
    CHECK_FALSE(pts[1].ws_p95.has_value());
}

TEST_CASE("app_perf_fleet_trend: sub-floor points are suppressed (singling-out)",
          "[dex][app_perf]") {
    // A point on FEWER than kDexCohortFloor devices must not emit exact stats —
    // only the honest count survives. The floor is one device (maintainer ruling
    // 2026-10-14), so the only sub-floor point is an empty one; the fleet path
    // floors exactly like the group path.
    AppPerfFleetRow row;
    row.app_name = "niche.exe";
    row.version = "1.0";
    row.day = 1'700'000'000;
    row.device_count = kDexCohortFloor - 1; // below the floor: an empty point
    row.cpu_sum = 50.0;
    row.cpu_max = 40.0;
    row.ws_sum = 1000;
    row.ws_max = 800;
    row.hist_version = kAppPerfHistVersion;
    row.cpu_hist = cpu_hist({});
    row.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);

    auto trend = app_perf_fleet_trend({row});
    REQUIRE(trend.size() == 1);
    CHECK(trend[0].suppressed);
    CHECK(trend[0].device_count == kDexCohortFloor - 1); // the only honest field
    CHECK(trend[0].cpu_mean == 0.0);
    CHECK(trend[0].cpu_max == 0.0);
    CHECK(trend[0].ws_mean == 0);
    CHECK_FALSE(trend[0].cpu_p95.has_value());

    // At the floor → full stats, not suppressed.
    row.device_count = kDexCohortFloor;
    row.cpu_sum = static_cast<double>(kDexCohortFloor) * 5.0; // mean 5.0
    auto ok = app_perf_fleet_trend({row});
    REQUIRE(ok.size() == 1);
    CHECK_FALSE(ok[0].suppressed);
    CHECK(ok[0].cpu_mean == 5.0);

    // Three devices: published with the exact mean (withheld at the old floor of 10).
    row.device_count = 3;
    row.cpu_sum = 30.0;
    auto three = app_perf_fleet_trend({row});
    REQUIRE(three.size() == 1);
    CHECK_FALSE(three[0].suppressed);
    CHECK(three[0].cpu_mean == 10.0);
}

TEST_CASE("app_perf_version_summaries: groups by version, latest-day headline + chronological series",
          "[dex][app_perf]") {
    // version "124": two days (older then newer); version "125": one day. The
    // reducer keeps first-seen order, takes the LATEST day for the headline, and
    // collects the daily means chronologically for the sparkline.
    AppPerfTrendPoint a1;
    a1.version = "124";
    a1.day = 100;
    a1.device_count = 10;
    a1.cpu_mean = 4.0;
    a1.ws_mean = 1000;
    AppPerfTrendPoint a2;
    a2.version = "124";
    a2.day = 200; // newer
    a2.device_count = 12;
    a2.cpu_mean = 6.0;
    a2.cpu_max = 9.0;
    a2.ws_mean = 1200;
    a2.cpu_p95 = HistPctile{20.0, false};
    AppPerfTrendPoint b1;
    b1.version = "125";
    b1.day = 200;
    b1.device_count = 5;
    b1.cpu_mean = 11.0;
    b1.ws_mean = 2000;

    auto s = app_perf_version_summaries({a1, a2, b1});
    REQUIRE(s.size() == 2);
    CHECK(s[0].version == "124"); // first-seen order
    CHECK(s[0].day_count == 2);
    CHECK(s[0].latest_day == 200);
    CHECK(s[0].device_count == 12); // latest day's count
    CHECK(s[0].cpu_mean == 6.0);    // latest day's mean
    CHECK(s[0].ws_mean == 1200);
    REQUIRE(s[0].cpu_p95.has_value());
    CHECK(s[0].cpu_p95->value == 20.0);
    REQUIRE(s[0].cpu_series.size() == 2);
    CHECK(s[0].cpu_series[0] == 4.0); // chronological (older first)
    CHECK(s[0].cpu_series[1] == 6.0);
    CHECK(s[1].version == "125");
    CHECK(s[1].day_count == 1);
    CHECK(s[1].device_count == 5);
}

TEST_CASE("app_perf_version_summaries: suppressed latest day → count only, series skips it",
          "[dex][app_perf]") {
    AppPerfTrendPoint d1;
    d1.version = "124";
    d1.day = 100;
    d1.device_count = 10;
    d1.cpu_mean = 5.0; // a real day
    AppPerfTrendPoint d2;
    d2.version = "124";
    d2.day = 200;
    d2.device_count = 3;
    d2.suppressed = true; // cleared by the group path (mean already 0)

    auto s = app_perf_version_summaries({d1, d2});
    REQUIRE(s.size() == 1);
    CHECK(s[0].suppressed);           // latest day was suppressed
    CHECK(s[0].device_count == 3);    // honest count survives
    CHECK(s[0].cpu_mean == 0.0);      // mirrors the cleared trend point
    CHECK(s[0].day_count == 2);       // both days counted
    REQUIRE(s[0].cpu_series.size() == 1); // sparkline plots only the real day
    CHECK(s[0].cpu_series[0] == 5.0);
}

TEST_CASE("app_perf_version_summaries: reversed input still picks latest day + sorts series",
          "[dex][app_perf]") {
    AppPerfTrendPoint newer;
    newer.version = "1";
    newer.day = 200;
    newer.device_count = 12;
    newer.cpu_mean = 6.0;
    AppPerfTrendPoint older;
    older.version = "1";
    older.day = 100;
    older.device_count = 10;
    older.cpu_mean = 4.0;
    // Feed NEWER first (out of order): the reducer must still headline day 200 and
    // emit the sparkline ascending {4.0, 6.0}.
    auto s = app_perf_version_summaries({newer, older});
    REQUIRE(s.size() == 1);
    CHECK(s[0].latest_day == 200);
    CHECK(s[0].device_count == 12);
    CHECK(s[0].cpu_mean == 6.0);
    REQUIRE(s[0].cpu_series.size() == 2);
    CHECK(s[0].cpu_series[0] == 4.0); // chronological despite reversed input
    CHECK(s[0].cpu_series[1] == 6.0);
}

TEST_CASE("app_perf_version_summaries: all-suppressed version has empty series, honest count",
          "[dex][app_perf]") {
    AppPerfTrendPoint d1;
    d1.version = "1";
    d1.day = 100;
    d1.device_count = 2;
    d1.suppressed = true;
    AppPerfTrendPoint d2;
    d2.version = "1";
    d2.day = 200;
    d2.device_count = 3;
    d2.suppressed = true;
    auto s = app_perf_version_summaries({d1, d2});
    REQUIRE(s.size() == 1);
    CHECK(s[0].suppressed);
    CHECK(s[0].device_count == 3); // latest day's honest count survives
    CHECK(s[0].day_count == 2);
    CHECK(s[0].cpu_series.empty()); // every day suppressed → nothing to plot
}

TEST_CASE("app_perf_version_summaries: hist_stale latest day withholds p95", "[dex][app_perf]") {
    AppPerfTrendPoint d;
    d.version = "x";
    d.day = 10;
    d.device_count = 2;
    d.cpu_mean = 5.0;
    d.hist_stale = true; // trend point left cpu_p95 unset

    auto s = app_perf_version_summaries({d});
    REQUIRE(s.size() == 1);
    CHECK(s[0].hist_stale);
    CHECK(s[0].cpu_mean == 5.0); // exact mean survives
    CHECK_FALSE(s[0].cpu_p95.has_value());
}

TEST_CASE("app_perf_fleet_trend: a wrong-scheme row withholds percentiles", "[dex][app_perf]") {
    AppPerfFleetRow row;
    row.device_count = 14;                      // >= kDexCohortFloor (not floor-suppressed)
    row.cpu_sum = 70.0;                         // mean 5.0 — still exact
    row.hist_version = kAppPerfHistVersion + 1; // a DIFFERENT scheme
    row.cpu_hist = cpu_hist({0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    row.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);

    auto trend = app_perf_fleet_trend({row});
    REQUIRE(trend.size() == 1);
    CHECK(trend[0].hist_stale);
    CHECK(trend[0].cpu_mean == 5.0);          // exact stats survive
    CHECK_FALSE(trend[0].cpu_p50.has_value()); // percentiles withheld, not reinterpreted
    CHECK_FALSE(trend[0].cpu_p95.has_value());
    CHECK_FALSE(trend[0].ws_p50.has_value());
}

// ── Per-device drill: app_perf_device_summaries ───────────────────────────────

namespace {
AppPerfDailyRow daily(std::string app, std::string ver, std::int64_t day, std::int64_t samples,
                      double cpu_avg, double cpu_max, std::int64_t ws_avg, std::int64_t ws_max,
                      std::int64_t inst) {
    AppPerfDailyRow r;
    r.app_name = std::move(app);
    r.version = std::move(ver);
    r.day = day;
    r.samples = samples;
    r.instances_max = inst;
    r.cpu_avg = cpu_avg;
    r.cpu_max = cpu_max;
    r.ws_avg_bytes = ws_avg;
    r.ws_max_bytes = ws_max;
    return r;
}
} // namespace

TEST_CASE("app_perf_device_summaries: sample-weighted window means, maxima, chronological series",
          "[dex][app_perf]") {
    // chrome has two versions; 124 spans two days with DIFFERENT sample counts so
    // the window mean must be sample-weighted, not a flat average of daily means.
    std::vector<AppPerfDailyRow> rows = {
        daily("chrome.exe", "124", 100, 10, 4.0, 9.0, 1000, 1400, 3),
        daily("chrome.exe", "124", 200, 30, 6.0, 12.0, 1200, 1600, 4),
        daily("chrome.exe", "125", 300, 5, 12.0, 31.0, 1800, 2400, 8),
        daily("explorer.exe", "6.2", 300, 24, 1.2, 5.0, 240, 310, 1),
    };
    auto apps = app_perf_device_summaries(rows);
    REQUIRE(apps.size() == 2);

    // Ordered by peak window cpu_avg desc: chrome (peak 12.0) before explorer (1.2).
    CHECK(apps[0].app_name == "chrome.exe");
    CHECK(apps[1].app_name == "explorer.exe");

    const auto& chrome = apps[0];
    REQUIRE(chrome.versions.size() == 2);
    // Versions newest-day first: 125 (day 300) before 124 (day 200).
    CHECK(chrome.versions[0].version == "125");
    CHECK(chrome.versions[1].version == "124");

    const auto& v124 = chrome.versions[1];
    CHECK(v124.day_count == 2);
    CHECK(v124.latest_day == 200);
    CHECK(v124.cpu_avg == 5.5);  // (4·10 + 6·30)/40 — sample-weighted, NOT (4+6)/2=5
    CHECK(v124.cpu_max == 12.0); // window max of daily maxima
    CHECK(v124.ws_avg == 1150);  // (1000·10 + 1200·30)/40
    CHECK(v124.ws_max == 1600);
    CHECK(v124.instances_max == 4);
    REQUIRE(v124.cpu_series.size() == 2);
    CHECK(v124.cpu_series[0] == 4.0); // chronological (older day first)
    CHECK(v124.cpu_series[1] == 6.0);

    CHECK(chrome.peak_cpu_avg == 12.0); // ranks the app
}

TEST_CASE("app_perf_device_summaries: zero total samples falls back to an unweighted mean",
          "[dex][app_perf]") {
    // Malformed rows (samples=0) must still show an honest number, never 0 from a
    // divide-by-zero guard that drops the data.
    std::vector<AppPerfDailyRow> rows = {
        daily("app.exe", "1", 100, 0, 4.0, 8.0, 1000, 2000, 1),
        daily("app.exe", "1", 200, 0, 6.0, 9.0, 3000, 4000, 1),
    };
    auto apps = app_perf_device_summaries(rows);
    REQUIRE(apps.size() == 1);
    REQUIRE(apps[0].versions.size() == 1);
    CHECK(apps[0].versions[0].cpu_avg == 5.0); // (4+6)/2 unweighted fallback
    CHECK(apps[0].versions[0].ws_avg == 2000); // (1000+3000)/2
}

TEST_CASE("app_perf_device_summaries: reversed input still groups + sorts the series",
          "[dex][app_perf]") {
    // Feed the newer day first (out of order): the reducer must still group by
    // version and emit the sparkline ascending.
    std::vector<AppPerfDailyRow> rows = {
        daily("a.exe", "1", 200, 1, 6.0, 6.0, 0, 0, 1),
        daily("a.exe", "1", 100, 1, 4.0, 4.0, 0, 0, 1),
    };
    auto apps = app_perf_device_summaries(rows);
    REQUIRE(apps.size() == 1);
    REQUIRE(apps[0].versions.size() == 1);
    CHECK(apps[0].versions[0].latest_day == 200);
    REQUIRE(apps[0].versions[0].cpu_series.size() == 2);
    CHECK(apps[0].versions[0].cpu_series[0] == 4.0); // chronological despite reversed input
    CHECK(apps[0].versions[0].cpu_series[1] == 6.0);
}

TEST_CASE("app_perf_device_summaries: empty input → empty", "[dex][app_perf]") {
    CHECK(app_perf_device_summaries({}).empty());
}

TEST_CASE("app_perf_device_summaries: equal peak CPU → apps ordered alphabetically",
          "[dex][app_perf]") {
    // Both apps share peak window cpu_avg = 5.0, so the tiebreak (app_name asc) decides.
    std::vector<AppPerfDailyRow> rows = {
        daily("zebra.exe", "1", 100, 10, 5.0, 5.0, 100, 100, 1),
        daily("alpha.exe", "1", 100, 10, 5.0, 5.0, 100, 100, 1),
    };
    auto apps = app_perf_device_summaries(rows);
    REQUIRE(apps.size() == 2);
    CHECK(apps[0].app_name == "alpha.exe"); // equal peak_cpu_avg → app_name asc
    CHECK(apps[1].app_name == "zebra.exe");
}

TEST_CASE("app_perf_device_summaries: negative samples treated as zero weight",
          "[dex][app_perf]") {
    // Defense-in-depth: the store clamps samples>=0, but the pure reduction must not
    // assume that — a negative `samples` contributes 0 weight (never a negative
    // denominator). With all weights non-positive, the unweighted fallback applies.
    std::vector<AppPerfDailyRow> rows = {
        daily("a.exe", "1", 100, -5, 4.0, 4.0, 1000, 1000, 1),
        daily("a.exe", "1", 200, -3, 6.0, 6.0, 3000, 3000, 1),
    };
    auto apps = app_perf_device_summaries(rows);
    REQUIRE(apps.size() == 1);
    REQUIRE(apps[0].versions.size() == 1);
    CHECK(apps[0].versions[0].cpu_avg == 5.0); // (4+6)/2 unweighted (both weights ≤ 0)
    CHECK(apps[0].versions[0].ws_avg == 2000);
}

TEST_CASE("app_perf_device_summaries: many distinct keys group correctly (UP-1)",
          "[dex][app_perf]") {
    // Grouping is O(n log n) via std::map (was O(distinct²) linear-find — a DoS at
    // the kQueryRowCap). Build many distinct (app,version) rows and assert each
    // becomes its own version under its own app: correctness at adversarial scale.
    std::vector<AppPerfDailyRow> rows;
    for (int i = 0; i < 2000; ++i)
        rows.push_back(
            daily("app" + std::to_string(i) + ".exe", "1.0", 100, 10, 1.0, 1.0, 100, 100, 1));
    auto apps = app_perf_device_summaries(rows);
    CHECK(apps.size() == 2000); // every distinct app present exactly once
    for (const auto& a : apps)
        CHECK(a.versions.size() == 1);
}

TEST_CASE("app_perf_device_summaries: cpu_series capped to bound the sparkline (UP-2)",
          "[dex][app_perf]") {
    // A degenerate input (one version across > kMaxSeriesPoints distinct days, e.g. a
    // future-dating attack the store's day-bound also blocks) must not yield an
    // unbounded series → multi-MB SVG. The series keeps the MOST-RECENT points.
    std::vector<AppPerfDailyRow> rows;
    for (int d = 0; d < 1000; ++d)
        rows.push_back(daily("a.exe", "1", 100 + static_cast<std::int64_t>(d) * 86400, 10,
                             static_cast<double>(d), 5.0, 100, 100, 1));
    auto apps = app_perf_device_summaries(rows);
    REQUIRE(apps.size() == 1);
    REQUIRE(apps[0].versions.size() == 1);
    CHECK(apps[0].versions[0].cpu_series.size() == 400); // capped at kMaxSeriesPoints
    CHECK(apps[0].versions[0].cpu_series.back() == 999.0); // kept the most-recent day
}

TEST_CASE("app_perf_param_valid: rejects oversize + control/NUL, accepts empty + normal",
          "[dex][app_perf]") {
    CHECK(app_perf_param_valid(""));                            // all-versions sentinel
    CHECK(app_perf_param_valid("chrome.exe"));                  // normal
    CHECK(app_perf_param_valid(std::string(512, 'a')));         // at the cap
    CHECK_FALSE(app_perf_param_valid(std::string(513, 'a')));   // over the cap
    CHECK_FALSE(app_perf_param_valid(std::string("a\0b", 3)));  // embedded NUL (libpq truncation)
    CHECK_FALSE(app_perf_param_valid("a\tb"));                  // C0 control char
}
