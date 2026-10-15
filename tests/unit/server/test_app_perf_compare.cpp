/**
 * test_app_perf_compare.cpp — the PURE /auto VERIFY cohort-paired before/after
 * engine (app_perf_compare.{hpp,cpp}). DB-free; this is the heart of the feature,
 * so it carries the load-bearing invariants:
 *
 *  - reduce_version_window: per-machine-per-version window (most recent N days
 *    THIS machine ran the version), sample-weighted, unweighted fallback, cap.
 *  - compare: pair by agent_id; machines on only one version EXCLUDED + counted;
 *    nearest-rank percentiles + median delta; cpu direction split with the flat
 *    band; small_cohort flag (NOT suppression) + insufficient.
 *  - The staggered-upgrade case: two machines that transitioned at totally
 *    different absolute times still pair, because the window is per-machine, not
 *    today-anchored (the bug that would render a real rollout's panel empty).
 */
#include "app_perf_compare.hpp"
#include "dex_perf_model.hpp" // kDexCohortFloor

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <limits>
#include <string>
#include <vector>

using namespace yuzu::server;
using Catch::Approx;

namespace {
// {agent_id, version, day, samples, cpu_avg, ws_avg_bytes}
AppPerfCohortRow row(std::string a, std::string v, std::int64_t day, std::int64_t s, double cpu,
                     std::int64_t ws) {
    return {std::move(a), std::move(v), day, s, cpu, ws};
}
} // namespace

TEST_CASE("reduce_version_window: per-machine sample-weighted window mean", "[verify][compare]") {
    std::vector<AppPerfCohortRow> rows = {
        row("m1", "A", 10, 100, 2.0, 100),
        row("m1", "A", 11, 300, 6.0, 300), // weighted cpu = (2·100 + 6·300)/400 = 5.0
        row("m1", "B", 12, 100, 10.0, 1000),
    };
    auto a = reduce_version_window(rows, "A", 7);
    REQUIRE(a.size() == 1);
    CHECK(a[0].agent_id == "m1");
    CHECK(a[0].cpu == Approx(5.0));
    CHECK(a[0].ws == 250); // (100·100 + 300·300)/400 = 250
    CHECK(a[0].samples == 400);
    CHECK(a[0].day_count == 2);
    // version B isolated to its own scalar
    auto b = reduce_version_window(rows, "B", 7);
    REQUIRE(b.size() == 1);
    CHECK(b[0].cpu == Approx(10.0));
}

TEST_CASE("reduce_version_window: caps to the most recent window_days days", "[verify][compare]") {
    std::vector<AppPerfCohortRow> rows = {
        row("m1", "A", 10, 100, 1.0, 0),
        row("m1", "A", 11, 100, 2.0, 0),
        row("m1", "A", 12, 100, 9.0, 0),
        row("m1", "A", 13, 100, 11.0, 0),
    };
    auto a = reduce_version_window(rows, "A", 2); // days 13,12 → (11+9)/2 = 10
    REQUIRE(a.size() == 1);
    CHECK(a[0].cpu == Approx(10.0));
    CHECK(a[0].day_count == 2);
}

TEST_CASE("reduce_version_window: a zero-sample machine measured nothing → EXCLUDED",
          "[verify][compare]") {
    // Without a cohort floor, a canary whose only in-window day has zero samples
    // would otherwise pair on noise and swing the median. It carries no real scalar.
    std::vector<AppPerfCohortRow> rows = {
        row("m1", "A", 10, 0, 2.0, 1000),
        row("m1", "A", 11, 0, 6.0, 3000),
        row("m2", "A", 10, 50, 3.0, 1000), // a real machine still shows
    };
    auto a = reduce_version_window(rows, "A", 7);
    REQUIRE(a.size() == 1);
    CHECK(a[0].agent_id == "m2");
    CHECK(a[0].cpu == Approx(3.0));
    // A zero-sample candidate makes a machine unpaired (no candidate measurement),
    // NOT a 0%-CPU pair.
    std::vector<AppPerfCohortRow> mixed = {
        row("z", "A", 10, 100, 4.0, 1000), // real baseline
        row("z", "B", 11, 0, 9.0, 9000),   // zero-sample candidate → no scalar
    };
    auto c = compare(reduce_version_window(mixed, "A", 7), reduce_version_window(mixed, "B", 7), "A",
                     "B", 7);
    CHECK(c.paired == 0);
    CHECK(c.baseline_only == 1); // honestly: we measured baseline, not candidate
}

TEST_CASE("reduce/compare: cpu is clamped to [0,100] at the scalar boundary", "[verify][compare]") {
    // A future LIVE candidate could feed a finite-but-out-of-range cpu (e.g. 1e9);
    // it must not blow the means.
    std::vector<MachineVersionScalar> base = {{"m1", 5.0, 1000, 100, 1}};
    std::vector<MachineVersionScalar> cand = {{"m1", 1e9, 1500, 100, 1}}; // absurd
    auto c = compare(base, cand, "A", "B", 7);
    REQUIRE(c.paired == 1);
    CHECK(c.cpu_after_mean <= 100.0);
    CHECK(c.cpu_after_mean == Approx(100.0));
}

TEST_CASE("compare: staggered upgrades still pair — window is per-machine, not today-anchored",
          "[verify][compare]") {
    // m1 transitioned A→B around day 100; m2 around day 200 — totally different
    // absolute windows. A today-relative window would drop one of them; the
    // per-machine window pairs BOTH.
    std::vector<AppPerfCohortRow> rows = {
        row("m1", "A", 100, 100, 2.0, 1000), row("m1", "A", 101, 100, 2.0, 1000),
        row("m1", "B", 102, 100, 5.0, 1500), row("m1", "B", 103, 100, 5.0, 1500),
        row("m2", "A", 200, 100, 3.0, 1000), row("m2", "A", 201, 100, 3.0, 1000),
        row("m2", "B", 202, 100, 9.0, 2000), row("m2", "B", 203, 100, 9.0, 2000),
    };
    auto c = compare(reduce_version_window(rows, "A", 2), reduce_version_window(rows, "B", 2), "A",
                     "B", 2);
    CHECK(c.paired == 2);
    CHECK(c.baseline_only == 0);
    CHECK(c.candidate_only == 0);
    CHECK(c.moved_up == 2); // both heavier on B
}

TEST_CASE("compare: machines on only one version are excluded and counted", "[verify][compare]") {
    std::vector<AppPerfCohortRow> rows = {
        row("paired", "A", 10, 100, 2.0, 1000), row("paired", "B", 11, 100, 4.0, 1200),
        row("baseonly", "A", 10, 100, 2.0, 1000), // never ran B (e.g. failed install)
        row("candonly", "B", 11, 100, 4.0, 1200),  // never ran A (e.g. fresh install)
    };
    auto c = compare(reduce_version_window(rows, "A", 7), reduce_version_window(rows, "B", 7), "A",
                     "B", 7);
    CHECK(c.paired == 1);
    CHECK(c.baseline_only == 1);
    CHECK(c.candidate_only == 1);
    REQUIRE(c.pairs.size() == 1);
    CHECK(c.pairs[0].agent_id == "paired");
    CHECK(c.pairs[0].cpu_delta == Approx(2.0));
    CHECK(c.pairs[0].ws_delta == 200);
}

TEST_CASE("compare: cpu direction split honours the flat band", "[verify][compare]") {
    std::vector<AppPerfCohortRow> rows = {
        row("up", "A", 1, 100, 2.0, 0),   row("up", "B", 2, 100, 7.0, 0),   // +5 → up
        row("flat", "A", 1, 100, 2.0, 0), row("flat", "B", 2, 100, 2.1, 0), // +0.1 → flat
        row("down", "A", 1, 100, 9.0, 0), row("down", "B", 2, 100, 4.0, 0), // -5 → down
    };
    auto c = compare(reduce_version_window(rows, "A", 7), reduce_version_window(rows, "B", 7), "A",
                     "B", 7);
    CHECK(c.paired == 3);
    CHECK(c.moved_up == 1);
    CHECK(c.moved_flat == 1);
    CHECK(c.moved_down == 1);
}

TEST_CASE("compare: nearest-rank percentiles + median delta over the paired set",
          "[verify][compare]") {
    // five machines, before=2.0, after=2.0+i → deltas {0,1,2,3,4}, after {2,3,4,5,6}
    std::vector<AppPerfCohortRow> rows;
    for (int i = 0; i < 5; ++i) {
        const std::string a = "m" + std::to_string(i);
        rows.push_back(row(a, "A", 1, 100, 2.0, 1000));
        rows.push_back(row(a, "B", 2, 100, 2.0 + i, 1000));
    }
    auto c = compare(reduce_version_window(rows, "A", 7), reduce_version_window(rows, "B", 7), "A",
                     "B", 7);
    CHECK(c.paired == 5);
    CHECK(c.cpu_before_mean == Approx(2.0));
    CHECK(c.cpu_after_mean == Approx(4.0));               // mean{2,3,4,5,6}
    CHECK(c.cpu_delta_median == Approx(2.0));             // nearest-rank p50 of {0,1,2,3,4}: r=3 → 2
    CHECK(c.cpu_after_p95 == Approx(6.0));                // p95 of {2,3,4,5,6}: r=5 → 6
    REQUIRE(c.pairs.size() == 5);
    CHECK(c.pairs.front().agent_id == "m4");             // sorted by Δ desc
    CHECK(c.pairs.back().agent_id == "m0");
}

TEST_CASE("compare: small_cohort follows the one-device floor and never suppresses",
          "[verify][compare]") {
    SECTION("three paired machines: not small at the one-device floor, stats present") {
        std::vector<AppPerfCohortRow> rows;
        for (int i = 0; i < 3; ++i) {
            const std::string a = "m" + std::to_string(i);
            rows.push_back(row(a, "A", 1, 100, 2.0, 1000));
            rows.push_back(row(a, "B", 2, 100, 4.0, 1200));
        }
        auto c = compare(reduce_version_window(rows, "A", 7), reduce_version_window(rows, "B", 7),
                         "A", "B", 7);
        CHECK(c.paired == 3);
        CHECK_FALSE(c.small_cohort); // 3 >= kDexCohortFloor (1); was true at the old floor of 10
        CHECK_FALSE(c.insufficient);
        CHECK(c.cpu_after_mean == Approx(4.0)); // NOT suppressed — canaries are small
    }
    SECTION("no machine ran both → insufficient") {
        std::vector<AppPerfCohortRow> rows = {row("a", "A", 1, 100, 2.0, 0),
                                              row("b", "B", 2, 100, 4.0, 0)};
        auto c = compare(reduce_version_window(rows, "A", 7), reduce_version_window(rows, "B", 7),
                         "A", "B", 7);
        CHECK(c.paired == 0);
        CHECK(c.insufficient);
        CHECK_FALSE(c.small_cohort);
    }
    SECTION("at the floor → not small") {
        std::vector<AppPerfCohortRow> rows;
        for (int i = 0; i < static_cast<int>(kDexCohortFloor); ++i) {
            const std::string a = "m" + std::to_string(i);
            rows.push_back(row(a, "A", 1, 100, 2.0, 1000));
            rows.push_back(row(a, "B", 2, 100, 4.0, 1200));
        }
        auto c = compare(reduce_version_window(rows, "A", 7), reduce_version_window(rows, "B", 7),
                         "A", "B", 7);
        CHECK(c.paired == kDexCohortFloor);
        CHECK_FALSE(c.small_cohort);
    }
}

TEST_CASE("compare/reduce: empty inputs are safe", "[verify][compare]") {
    CHECK(reduce_version_window({}, "A", 7).empty());
    auto c = compare({}, {}, "A", "B", 7);
    CHECK(c.paired == 0);
    CHECK(c.insufficient);
    CHECK(c.pairs.empty());
}

TEST_CASE("build_comparison: the single assembly == reduce×2 + compare", "[verify][compare]") {
    std::vector<AppPerfCohortRow> rows = {
        row("m1", "A", 10, 100, 2.0, 1000), row("m1", "B", 11, 100, 5.0, 1500),
        row("m2", "A", 10, 100, 3.0, 1000), row("m2", "B", 11, 100, 4.0, 1100),
    };
    auto direct = compare(reduce_version_window(rows, "A", 7), reduce_version_window(rows, "B", 7),
                          "A", "B", 7);
    auto built = build_comparison(rows, "A", "B", 7);
    CHECK(built.paired == direct.paired);
    CHECK(built.paired == 2);
    CHECK(built.cpu_after_mean == Approx(direct.cpu_after_mean));
    CHECK(built.moved_up == direct.moved_up);
    REQUIRE(built.pairs.size() == direct.pairs.size());
    // pairs sorted by descending CPU delta (m1 Δ+3.0 before m2 Δ+1.0)
    REQUIRE(built.pairs.size() == 2);
    CHECK(built.pairs.front().agent_id == "m1");
    CHECK(built.pairs.front().cpu_delta >= built.pairs.back().cpu_delta);
}

TEST_CASE("reduce/compare: non-finite cpu is sanitized — no std::sort UB", "[verify][compare]") {
    // A hostile agent (or a future LIVE candidate bypassing the store clamp) could
    // present NaN/Inf cpu. The engine must sanitize to finite so the cpu_delta sorts
    // are valid strict-weak-orders (a NaN would be sort UB).
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();
    std::vector<AppPerfCohortRow> rows = {
        row("m1", "A", 10, 100, nan, 1000), row("m1", "B", 11, 100, inf, 1500),
        row("m2", "A", 10, 100, 2.0, 1000), row("m2", "B", 11, 100, 5.0, 1500),
    };
    for (const auto& s : reduce_version_window(rows, "A", 7))
        CHECK(std::isfinite(s.cpu));
    auto c = build_comparison(rows, "A", "B", 7); // must not UB-sort
    CHECK(c.paired == 2);
    for (const auto& p : c.pairs) {
        CHECK(std::isfinite(p.cpu_before));
        CHECK(std::isfinite(p.cpu_after));
        CHECK(std::isfinite(p.cpu_delta));
    }
    CHECK(std::isfinite(c.cpu_delta_median));
    CHECK(std::isfinite(c.cpu_after_mean));
}

TEST_CASE("reduce_version_window: window_days <= 0 is treated as 1", "[verify][compare]") {
    std::vector<AppPerfCohortRow> rows = {row("m1", "A", 10, 100, 1.0, 0),
                                          row("m1", "A", 11, 100, 9.0, 0)};
    auto a = reduce_version_window(rows, "A", 0); // → 1 day = most recent (day 11)
    REQUIRE(a.size() == 1);
    CHECK(a[0].day_count == 1);
    CHECK(a[0].cpu == Approx(9.0));
}

TEST_CASE("compare: a duplicate agent within one side takes the first (defence)",
          "[verify][compare]") {
    // {agent_id, cpu, ws, samples, day_count}
    std::vector<MachineVersionScalar> base = {{"m1", 2.0, 1000, 100, 1}, {"m1", 9.0, 9000, 100, 1}};
    std::vector<MachineVersionScalar> cand = {{"m1", 5.0, 1500, 100, 1}};
    auto c = compare(base, cand, "A", "B", 7);
    CHECK(c.paired == 1);
    REQUIRE(c.pairs.size() == 1);
    CHECK(c.pairs[0].cpu_before == Approx(2.0)); // first wins, not 9.0
}

TEST_CASE("cohort_no_data: accounts members with no data, clamped >= 0", "[verify][compare]") {
    PairedComparison c;
    c.paired = 3;
    c.baseline_only = 1;
    c.candidate_only = 1; // accounted = 5
    CHECK(cohort_no_data(c, 10) == 5);
    CHECK(cohort_no_data(c, 5) == 0);
    CHECK(cohort_no_data(c, 4) == 0); // negative clamps to 0
}
