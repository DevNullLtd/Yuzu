/**
 * test_dex_app_perf_version_table.cpp — the per-version crash and hang table on the
 * DEX application performance view.
 *
 * Pure renderer tests for every display rule of the table, one route-level case that
 * drives GET /fragments/dex/perf/app through the same DexPerfApi seam the REST twin
 * uses, and source pins on the renderer. The rules under test:
 *   - every rate carries its population (the exposed-device count beside it);
 *   - an unknown exposure is "unknown", never 0, and shows no rate;
 *   - no device floor: figures are published at any device count (9, 10, 11 and 1);
 *   - a ratio with no upper bound says so; a missing ratio says why;
 *   - the window, the sampled-not-census basis, the 20-version cap and a stat fault
 *     are all stated; a degraded read is a failed-read state, never an empty table;
 *   - nothing is labelled good or bad.
 */
#include "dex_app_perf_ui.hpp"
#include "dex_routes.hpp"
#include "test_dex_perf_api_double.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

bool has(const std::string& h, const std::string& needle) {
    return h.find(needle) != std::string::npos;
}

constexpr double kInf = std::numeric_limits<double>::infinity();

AppPerfVersionRow mk(const std::string& version, std::optional<std::int64_t> exposure,
                     std::int64_t crashes = 0, std::int64_t hangs = 0,
                     std::int64_t affected = 0) {
    AppPerfVersionRow r;
    r.perf.version = version;
    r.perf.day_count = 5;
    r.crashes = crashes;
    r.hangs = hangs;
    r.affected_devices = affected;
    r.exposure_devices = exposure;
    if (exposure) {
        r.exposed_crashes = crashes;
        r.exposed_hangs = hangs;
    }
    return r;
}

AppPerfFleetReport report_of(std::vector<AppPerfVersionRow> rows) {
    AppPerfFleetReport rep;
    rep.versions = std::move(rows);
    rep.failure_window_days = 29;
    return rep;
}

std::string table_of(const AppPerfFleetReport& rep) {
    return render_dex_app_perf_version_failures(
        "app.exe", 7, "", {DexVersionFailureView::State::Ready, &rep});
}

std::string read_ui_source() {
    std::ifstream input(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "dex_app_perf_ui.cpp");
    REQUIRE(input.is_open());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("version table: every rate carries its exposed-device population and interval",
          "[dex][app_perf][ui][version_table]") {
    auto r = mk("2.0.0.0", 400, 3, 2, 5);
    r.failure_rate = DexInterval{0.0125, 0.004, 0.029, false};
    const auto h = table_of(report_of({r}));

    CHECK(has(h, "<b>12.5</b> per 1,000 exposed devices"));
    CHECK(has(h, "95% interval <b>4.00</b> to <b>29.0</b>"));
    CHECK(has(h, "5 exposed events on 400 exposed devices")); // population beside the rate
    CHECK(has(h, "<td>3</td><td>2</td><td>5</td>"));          // crashes, hangs, affected
    CHECK(has(h, "<td>400</td>"));                            // exposure column
    CHECK(has(h, "seen on 5 days"));
}

TEST_CASE("version table: the reliable marker follows the flag and the interval stays on screen",
          "[dex][app_perf][ui][version_table]") {
    auto low = mk("2.0.0.0", 100, 4, 0, 4);
    low.failure_rate = DexInterval{0.04, 0.011, 0.1, false};
    const auto h_low = table_of(report_of({low}));
    CHECK(has(h_low, "<span class=\"dx-tag\">under 20 events</span>"));
    CHECK_FALSE(has(h_low, "<span class=\"dx-tag\">reliable</span>"));
    CHECK(has(h_low, "95% interval <b>11.0</b> to <b>100</b>"));

    auto high = mk("2.0.0.0", 100, 30, 0, 30);
    high.failure_rate = DexInterval{0.3, 0.2, 0.4, true};
    const auto h_high = table_of(report_of({high}));
    CHECK(has(h_high, "<span class=\"dx-tag\">reliable</span>"));
    CHECK_FALSE(has(h_high, "<span class=\"dx-tag\">under 20 events</span>"));
}

TEST_CASE("version table: no device floor, figures are published at 9, 10, 11 and 1 devices",
          "[dex][app_perf][ui][version_table]") {
    for (const std::int64_t n : {1, 9, 10, 11}) {
        auto r = mk("2.0.0.0", n, 1, 0, 1);
        r.failure_rate = DexInterval{1.0 / static_cast<double>(n), 0.0, 0.9, false};
        const auto h = table_of(report_of({r}));
        CHECK(has(h, std::to_string(n) + " exposed device"));
        CHECK(has(h, "per 1,000 exposed devices"));
        CHECK_FALSE(has(h, "fewer than"));
        CHECK_FALSE(has(h, "withheld"));
    }
}

TEST_CASE("version table: unknown exposure is distinct from zero and never shows a rate",
          "[dex][app_perf][ui][version_table]") {
    SECTION("null exposure reads unknown, with the failures-without-samples cue") {
        const auto h = table_of(report_of({mk("2.0.0.0", std::nullopt, 2, 1, 2)}));
        CHECK(has(h, "<td><span class=\"gp-mute\">unknown</span><div"));
        CHECK(has(h, "failures recorded, no samples for this version"));
        CHECK(has(h, "no rate: exposure unknown"));
        CHECK_FALSE(has(h, "exposed devices</div>")); // no population line without a rate
        CHECK_FALSE(has(h, "no exposed devices"));
        // The counts that ARE known stay visible.
        CHECK(has(h, "<td>2</td><td>1</td><td>2</td>"));
    }
    SECTION("zero exposure is a known 0 with its own wording, not unknown") {
        const auto h = table_of(report_of({mk("2.0.0.0", 0, 0, 0, 0)}));
        CHECK(has(h, "<td>0</td>"));
        CHECK(has(h, "no rate: no exposed devices"));
        CHECK_FALSE(has(h, "unknown"));
        CHECK_FALSE(has(h, "per 1,000"));
    }
    SECTION("a present zero crash and hang count is printed as 0, never blank") {
        auto r = mk("2.0.0.0", 50, 0, 0, 0);
        r.failure_rate = DexInterval{0.0, 0.0, 0.07, false};
        const auto h = table_of(report_of({r}));
        CHECK(has(h, "<td>0</td><td>0</td><td>0</td><td>50</td>"));
        CHECK(has(h, "<b>0.00</b> per 1,000 exposed devices"));
    }
}

TEST_CASE("version table: a ratio with no upper bound says so and invents no estimate",
          "[dex][app_perf][ui][version_table]") {
    auto cur = mk("2.0.0.0", 100, 4, 0, 4);
    cur.previous_version = "1.0.0.0";
    cur.failure_rate_ratio = DexInterval{kInf, 1.4, kInf, false};
    auto prev = mk("1.0.0.0", 200, 0, 0, 0);
    const auto h = table_of(report_of({cur, prev}));
    CHECK(has(h, "no upper bound"));
    CHECK(has(h, "95% interval from 1.40x"));
    CHECK(has(h, "100 vs 200 exposed devices"));
    CHECK(has(h, "vs <span style=\"font-family:var(--mono)\">1.0.0.0</span>"));
    CHECK_FALSE(has(h, "inf"));
    CHECK_FALSE(has(h, "nan"));
}

TEST_CASE("version table: a bounded ratio prints estimate, interval and the previous version",
          "[dex][app_perf][ui][version_table]") {
    auto cur = mk("2.0.0.0", 100, 21, 0, 21);
    cur.previous_version = "1.0.0.0";
    cur.failure_rate_ratio = DexInterval{2.1, 1.2, 3.4, true};
    auto prev = mk("1.0.0.0", 100, 10, 0, 10);
    const auto h = table_of(report_of({cur, prev}));
    CHECK(has(h, "<b>2.10x</b>"));
    CHECK(has(h, "95% interval 1.20x to 3.40x"));
    CHECK_FALSE(has(h, "no upper bound"));
}

TEST_CASE("version table: a missing ratio states why instead of a blank",
          "[dex][app_perf][ui][version_table]") {
    SECTION("the oldest listed version has nothing to compare with") {
        CHECK(has(table_of(report_of({mk("1.0.0.0", 100)})), "no older version listed"));
    }
    SECTION("the unknown-version bucket is never compared") {
        CHECK(has(table_of(report_of({mk("", 100)})), "not compared"));
    }
    SECTION("unknown or zero exposure on either arm") {
        auto cur = mk("2.0.0.0", 100, 1, 0, 1);
        cur.previous_version = "1.0.0.0";
        const auto unknown_prev = table_of(report_of({cur, mk("1.0.0.0", std::nullopt)}));
        CHECK(has(unknown_prev, "not shown: needs exposure on both versions"));
        const auto zero_prev = table_of(report_of({cur, mk("1.0.0.0", 0)}));
        CHECK(has(zero_prev, "not shown: needs exposure on both versions"));
    }
    SECTION("both arms exposed but neither saw an event") {
        auto cur = mk("2.0.0.0", 100);
        cur.previous_version = "1.0.0.0";
        const auto h = table_of(report_of({cur, mk("1.0.0.0", 100)}));
        CHECK(has(h, "no ratio: no exposed events on either version"));
    }
}

TEST_CASE("version table: window, sampled basis and the 20-version cap are all stated",
          "[dex][app_perf][ui][version_table]") {
    auto rep = report_of({mk("1.0.0.0", 10)});
    SECTION("window and basis") {
        const auto h = table_of(rep);
        CHECK(has(h, "<b>last 29 days</b>"));
        CHECK(has(h, "sampled devices, not a census"));
        CHECK(has(h, "<b>not per day of use</b>"));
        CHECK_FALSE(has(h, "Showing the 20 newest versions"));
    }
    SECTION("a one-day window is singular") {
        rep.failure_window_days = 1;
        CHECK(has(table_of(rep), "<b>last 1 day</b>"));
    }
    SECTION("an unset window never prints 'last 0 days'") {
        rep.failure_window_days = 0;
        const auto h = table_of(rep);
        CHECK(has(h, "<b>unknown</b>"));
        CHECK_FALSE(has(h, "last 0"));
    }
    SECTION("truncation names the cap") {
        rep.versions_truncated = true;
        CHECK(has(table_of(rep), "Showing the 20 newest versions"));
    }
}

TEST_CASE("version table: a non-zero stat_failures is shown as a fault, zero is silent",
          "[dex][app_perf][ui][version_table]") {
    auto rep = report_of({mk("1.0.0.0", 10)});
    CHECK_FALSE(has(table_of(rep), "Fault:"));
    CHECK_FALSE(has(table_of(rep), "gp-banner"));
    rep.stat_failures = 2;
    const auto h = table_of(rep);
    CHECK(has(h, "<div class=\"gp-banner\"><b>Fault:</b> 2 statistic(s)"));
    CHECK(has(h, "<table")); // the rows that did compute are still shown
}

TEST_CASE("version table: a degraded read is a failed-read state with a retry, never a table",
          "[dex][app_perf][ui][version_table]") {
    SECTION("ReadFailed") {
        const auto h = render_dex_app_perf_version_failures(
            "my app.exe", 30, "1.2.0.0", {DexVersionFailureView::State::ReadFailed, nullptr});
        CHECK(has(h, "Crash and hang figures unavailable"));
        CHECK(has(h, "Retry in a few seconds"));
        CHECK(has(h, "hx-get=\"/fragments/dex/perf/app?app=my%20app.exe&amp;window=30d"
                     "&amp;version=1.2.0.0\""));
        CHECK_FALSE(has(h, "<table"));
        CHECK_FALSE(has(h, "<td>0</td>"));
    }
    SECTION("Ready without a report is treated as failed, not as empty") {
        const auto h = render_dex_app_perf_version_failures(
            "a.exe", 7, "", {DexVersionFailureView::State::Ready, nullptr});
        CHECK(has(h, "Crash and hang figures unavailable"));
        CHECK_FALSE(has(h, "<table"));
    }
    SECTION("NotShown renders nothing at all") {
        CHECK(render_dex_app_perf_version_failures("a.exe", 7, "", {}).empty());
    }
    SECTION("a report with no version rows says so, never an empty table") {
        const auto h = table_of(report_of({}));
        CHECK(has(h, "No version rows to show"));
        CHECK_FALSE(has(h, "<table"));
    }
}

TEST_CASE("version table: nothing is labelled good or bad and agent strings are escaped",
          "[dex][app_perf][ui][version_table]") {
    auto cur = mk("<img src=x>", 100, 30, 0, 30);
    cur.failure_rate = DexInterval{0.3, 0.2, 0.4, true};
    cur.previous_version = "<b>old</b>";
    cur.failure_rate_ratio = DexInterval{9.0, 5.0, 12.0, true};
    auto prev = mk("<b>old</b>", 100, 1, 0, 1);
    const auto h = table_of(report_of({cur, prev}));

    CHECK_FALSE(has(h, "<img src=x>"));
    CHECK(has(h, "&lt;img src=x&gt;"));
    CHECK_FALSE(has(h, "<b>old</b></span>"));
    CHECK(has(h, "&lt;b&gt;old&lt;/b&gt;"));
    // Slate tokens only, and none of the judgement colours or verdict words.
    CHECK_FALSE(has(h, "--ok"));
    CHECK_FALSE(has(h, "--bad"));
    CHECK_FALSE(has(h, "--warn"));
    CHECK_FALSE(has(h, "gp-ok"));
    CHECK_FALSE(has(h, "gp-err"));
    CHECK_FALSE(has(h, "gp-drift"));
    CHECK_FALSE(has(h, "healthy"));
    CHECK_FALSE(has(h, "regress"));
}

TEST_CASE("trend fragment embeds the table for the fleet and explains its absence for a cohort",
          "[dex][app_perf][ui][version_table]") {
    AppPerfVersionSummary v;
    v.version = "2.0.0.0";
    v.latest_day = 200;
    v.device_count = 12;
    v.day_count = 5;
    auto rep = report_of({mk("2.0.0.0", 100, 1, 0, 1)});
    const DexVersionFailureView ready{DexVersionFailureView::State::Ready, &rep};

    const auto fleet = render_dex_app_perf_trend("a.exe", {v}, "", {}, 10, 7, "", {}, "", ready);
    CHECK(has(fleet, "Crashes and hangs by version"));
    CHECK(has(fleet, "last 29 days"));
    CHECK_FALSE(has(fleet, "deferred"));

    const auto failed = render_dex_app_perf_trend(
        "a.exe", {v}, "", {}, 10, 7, "", {}, "", {DexVersionFailureView::State::ReadFailed, nullptr});
    CHECK(has(failed, "Crash and hang figures unavailable"));
    CHECK(has(failed, "2.0.0.0")); // the performance table survives the failed join

    const auto group = render_dex_app_perf_trend("a.exe", {v}, "g1", {}, 10, 7);
    CHECK_FALSE(has(group, "Crashes and hangs by version"));
    CHECK(has(group, "shown for the whole fleet only"));
}

TEST_CASE("fragment route: the fleet view joins the failure read; a degraded join keeps the "
          "performance table and shows a failed read",
          "[dex][app_perf][routes][version_table]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };

    auto perf_row = []() {
        AppPerfFleetRow row;
        row.app_name = "chrome.exe";
        row.version = "125.0.0.0";
        row.day = 1'700'000'000;
        row.device_count = 12; // above the trend floor
        row.cpu_sum = 120.0;
        row.cpu_max = 40.0;
        row.hist_version = kAppPerfHistVersion;
        return row;
    };
    auto fleet_rows = [&](std::string_view,
                          std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
        return std::vector<AppPerfFleetRow>{perf_row()};
    };

    SECTION("healthy join renders the table with the merged-contract figures") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = fleet_rows;
        providers.failures = [](std::string_view, const std::vector<std::string>&, std::int64_t,
                                std::int64_t, std::string_view) {
            AppPerfVersionFailureRow f;
            f.version = "125.0.0.0";
            f.exposure_devices = 9; // no device floor: published at 9
            f.crashes = 2;
            f.hangs = 1;
            f.affected_devices = 3;
            f.exposed_crashes = 2;
            f.exposed_hangs = 1;
            return std::optional<std::vector<AppPerfVersionFailureRow>>{
                std::vector<AppPerfVersionFailureRow>{f}};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto api = std::make_shared<yuzu::server::test::FnDexPerfApi>(yuzu::server::DexPerfFn{},
                                                                      providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {}, api,
                               {});
        auto r = sink.Get("/fragments/dex/perf/app?app=chrome.exe");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(has(r->body, "Crashes and hangs by version"));
        CHECK(has(r->body, "<td>2</td><td>1</td><td>3</td><td>9</td>"));
        CHECK(has(r->body, "3 exposed events on 9 exposed devices"));
        CHECK(has(r->body, "sampled devices, not a census"));
        CHECK_FALSE(has(r->body, "Crash and hang figures unavailable"));
    }

    SECTION("degraded join: 200 with the performance table, a failed read and a retry") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = fleet_rows;
        providers.failures = [](std::string_view, const std::vector<std::string>&, std::int64_t,
                                std::int64_t, std::string_view) {
            return std::optional<std::vector<AppPerfVersionFailureRow>>{}; // typed degrade
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto api = std::make_shared<yuzu::server::test::FnDexPerfApi>(yuzu::server::DexPerfFn{},
                                                                      providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {}, api,
                               {});
        auto r = sink.Get("/fragments/dex/perf/app?app=chrome.exe");
        REQUIRE(r);
        CHECK(r->status == 200); // htmx drops non-2xx bodies; same convention as the siblings
        CHECK(has(r->body, "125.0.0.0"));
        CHECK(has(r->body, "Crash and hang figures unavailable"));
        CHECK(has(r->body, "Retry now"));
        CHECK_FALSE(has(r->body, "Crashes and hangs by version</div><div class=\"gp-note\">Window"));
        CHECK_FALSE(has(r->body, "per 1,000 exposed devices"));
    }

    SECTION("group scope never joins the fleet-wide failure read") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.group = [&](std::string_view, std::string_view,
                              std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            return std::vector<AppPerfFleetRow>{perf_row()};
        };
        bool failure_read_called = false;
        providers.failures = [&](std::string_view, const std::vector<std::string>&, std::int64_t,
                                 std::int64_t, std::string_view) {
            failure_read_called = true;
            return std::optional<std::vector<AppPerfVersionFailureRow>>{
                std::vector<AppPerfVersionFailureRow>{}};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto api = std::make_shared<yuzu::server::test::FnDexPerfApi>(yuzu::server::DexPerfFn{},
                                                                      providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {}, api,
                               {});
        auto r = sink.Get("/fragments/dex/perf/app?app=chrome.exe&group=G1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_FALSE(failure_read_called);
        CHECK_FALSE(has(r->body, "Crashes and hangs by version"));
        CHECK(has(r->body, "shown for the whole fleet only"));
    }
}

TEST_CASE("renderer source pins: no markup sinks, escaped agent strings, slate tokens only",
          "[dex][app_perf][ui][version_table]") {
    const auto src = read_ui_source();
    const auto begin = src.find("Per-version crash and hang table helpers");
    const auto end = src.find("std::string render_dex_app_perf_trend(");
    REQUIRE(begin != std::string::npos);
    REQUIRE(end != std::string::npos);
    REQUIRE(begin < end);
    // The helper block is followed by the picker and the table renderer; pin the
    // two regions the table owns.
    const auto helpers_end = src.find("} // namespace", begin);
    REQUIRE(helpers_end != std::string::npos);
    const auto region = src.substr(begin, helpers_end - begin) +
                        src.substr(src.find("std::string render_dex_app_perf_version_failures("),
                                   end - src.find("std::string render_dex_app_perf_version_failures("));

    for (const char* banned : {"hx-on", "innerHTML", "onclick", "<script", "javascript:", "--ok",
                               "--bad", "--warn", "gp-ok", "gp-err"})
        CHECK_FALSE(has(region, banned));
    // Every agent-controlled string goes through esc() or url_encode().
    CHECK(has(region, "esc(r.perf.version)"));
    CHECK(has(region, "esc(r.previous_version)"));
    CHECK(has(region, "url_encode(app_name)"));
    CHECK(has(region, "url_encode(active_version)"));
}
