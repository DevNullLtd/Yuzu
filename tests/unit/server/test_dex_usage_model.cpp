/**
 * test_dex_usage_model.cpp -- the PURE fleet usage read model behind the Digital
 * Employee Experience Apps list (dex_usage_model.hpp): matching and ambiguity,
 * cell assignment, the disclosure partition, the exposure rate, the assembly and
 * the builder over injected reads. No store, no PG, no clock, no I/O: every time
 * value derives from one fixed request instant.
 *
 * Hand-computed anchor (window 7d, 30-day usage of 1,080,000 run seconds, 4
 * crashes + 1 hang): hours = 1,080,000 x 7/30 / 3,600 = 70, so the estimate is
 * 5 / 70 events per process-hour, read at the policy's interval level.
 */
#include "dex_usage_model.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cmath>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using Catch::Approx;
using namespace yuzu::server;

namespace {

constexpr std::int64_t kNow = 1'700'000'000; // 2023-11-14T22:13:20Z

DexAppsModel apps_of(const std::vector<std::string>& subjects, const std::string& window = "7d",
                     const std::string& scope = "all") {
    DexAppsModel m;
    m.window = window;
    m.platform_scope = scope;
    m.population = 10;
    for (const auto& s : subjects) {
        DexAppStability a;
        a.subject = s;
        m.apps.push_back(a);
    }
    return m;
}

DexUsageCellRow cell_row(int subject, int cell, std::int64_t devices, std::int64_t exact,
                         std::int64_t trunc, std::int64_t launches = 0, std::int64_t seconds = 0) {
    return {subject, cell, devices, exact, trunc, launches, seconds};
}

const std::vector<DexUsageCellDef> kFleetDefs{{DexUsageCellKind::Named, "fleet"}};

DexUsageRawCell raw(DexUsageCellKind kind, const std::string& label, std::int64_t devices) {
    return {kind, label, devices, devices * 10, devices};
}

std::vector<std::pair<std::string, std::string>> pop_of(int n, const std::string& os = "windows") {
    std::vector<std::pair<std::string, std::string>> p;
    for (int i = 0; i < n; ++i)
        p.emplace_back("d" + std::to_string(i), os);
    return p;
}

// The disclosure invariants every published table must hold.
void check_invariants(const DexUsageDisclosed& d, const std::vector<DexUsageRawCell>& in,
                      std::int64_t floor) {
    std::int64_t in_devices = 0, in_seconds = 0, in_launches = 0;
    for (const auto& c : in) {
        in_devices += c.devices;
        in_seconds += c.run_seconds;
        in_launches += c.launches;
    }
    CHECK(d.devices == in_devices);
    if (!d.totals) {
        CHECK(d.cells.empty());
        return;
    }
    std::int64_t dev = 0, sec = 0, lau = 0;
    for (const auto& c : d.cells) {
        dev += c.devices;
        sec += c.totals.run_seconds_30d;
        lau += c.totals.launches_30d;
        CHECK(c.devices >= floor);
    }
    CHECK(dev == d.devices);
    CHECK(sec == d.totals->run_seconds_30d);
    CHECK(lau == d.totals->launches_30d);
    CHECK(sec == in_seconds);
    CHECK(lau == in_launches);
}

} // namespace

// ── Matching ─────────────────────────────────────────────────────────────────

TEST_CASE("usage match plan: exact key is the lowercased subject, trunc only above 15 bytes",
          "[dex][usage_model]") {
    const auto plan = dex_usage_match_plan({"Alpha.EXE", "sharedprefix123-a.exe", "sharedprefix123", ""});
    REQUIRE(plan.size() == 4);
    CHECK(plan[0].subject == 0);
    CHECK(plan[0].key == "alpha.exe");
    CHECK_FALSE(plan[0].trunc);
    CHECK(plan[1].subject == 1);
    CHECK(plan[1].key == "sharedprefix123-a.exe");
    CHECK_FALSE(plan[1].trunc);
    CHECK(plan[2].subject == 1);
    CHECK(plan[2].key == "sharedprefix123"); // 15 bytes
    CHECK(plan[2].trunc);
    // The 15-byte subject (index 2) has its exact key only; the empty subject (3) has no key.
    CHECK(plan[3].subject == 2);
    CHECK(plan[3].key == "sharedprefix123");
    CHECK_FALSE(plan[3].trunc);
}

TEST_CASE("usage ambiguity: a Linux prefix name reaching two longer images marks both",
          "[dex][usage_model]") {
    const auto plan = dex_usage_match_plan({"sharedprefix123-a.exe", "sharedprefix123-b.exe"});
    // One Linux device reported the 15-byte name: both images received it through the trunc key.
    const auto hit = dex_usage_ambiguous(plan, {cell_row(0, 0, 1, 0, 1), cell_row(1, 0, 1, 0, 1)}, 2);
    CHECK(hit[0] == 1);
    CHECK(hit[1] == 1);
    // The same shared prefix with no trunc rows marks neither: it fires only on actual usage.
    const auto none = dex_usage_ambiguous(plan, {cell_row(0, 0, 1, 1, 0)}, 2);
    CHECK(none[0] == 0);
    CHECK(none[1] == 0);
}

TEST_CASE("usage ambiguity: a 15-byte image and a longer image sharing it", "[dex][usage_model]") {
    const auto plan = dex_usage_match_plan({"sharedprefix123", "sharedprefix123-a.exe"});
    // The exact row of the short image and the trunc row of the long one: both marked.
    const auto both = dex_usage_ambiguous(plan, {cell_row(0, 0, 1, 1, 0), cell_row(1, 0, 1, 0, 1)}, 2);
    CHECK(both[0] == 1);
    CHECK(both[1] == 1);
    // Non-Linux exact rows alone leave the short image matched.
    const auto alone = dex_usage_ambiguous(plan, {cell_row(0, 0, 3, 3, 0)}, 2);
    CHECK(alone[0] == 0);
    CHECK(alone[1] == 0);
}

TEST_CASE("usage ambiguity: subjects differing only by case are both marked when usage exists",
          "[dex][usage_model]") {
    const auto plan = dex_usage_match_plan({"Alpha.exe", "alpha.exe"});
    const auto hit = dex_usage_ambiguous(plan, {cell_row(0, 0, 2, 2, 0), cell_row(1, 0, 2, 2, 0)}, 2);
    CHECK(hit[0] == 1);
    CHECK(hit[1] == 1);
    const auto none = dex_usage_ambiguous(plan, {}, 2);
    CHECK(none[0] == 0);
    CHECK(none[1] == 0);
}

// ── Cells ────────────────────────────────────────────────────────────────────

TEST_CASE("usage cells: fleet is one cell, platform sends an unknown os to other",
          "[dex][usage_model]") {
    const std::vector<std::pair<std::string, std::string>> pop{
        {"a", "windows"}, {"b", "linux"}, {"c", "macos"}, {"d", "other-os"}, {"e", ""}};
    const auto fleet = dex_usage_assign_cells(pop, {DexUsageSliceKind::Fleet, ""}, {}, {});
    REQUIRE(fleet.defs.size() == 1);
    CHECK(fleet.defs[0].label == "fleet");
    for (const int c : fleet.cell_of)
        CHECK(c == 0);

    const auto plat = dex_usage_assign_cells(pop, {DexUsageSliceKind::Platform, ""}, {}, {});
    CHECK(plat.defs[static_cast<std::size_t>(plat.cell_of[0])].label == "windows");
    CHECK(plat.defs[static_cast<std::size_t>(plat.cell_of[1])].label == "linux");
    CHECK(plat.defs[static_cast<std::size_t>(plat.cell_of[2])].label == "macos");
    CHECK(plat.defs[static_cast<std::size_t>(plat.cell_of[3])].kind == DexUsageCellKind::Other);
    CHECK(plat.cell_of[3] == plat.cell_of[4]);
}

TEST_CASE("usage cells: group splits members from the rest", "[dex][usage_model]") {
    const auto pop = pop_of(4);
    const auto a = dex_usage_assign_cells(pop, {DexUsageSliceKind::Group, "group-1"},
                                          {"d0", "d2", "not-online"}, {});
    REQUIRE(a.defs.size() == 2);
    CHECK(a.defs[0].label == "group-1");
    CHECK(a.defs[1].kind == DexUsageCellKind::Other);
    CHECK(a.cell_of == std::vector<int>{0, 1, 0, 1});
}

TEST_CASE("usage cells: tag puts absent and empty values in (untagged)", "[dex][usage_model]") {
    const auto pop = pop_of(4);
    const auto a = dex_usage_assign_cells(pop, {DexUsageSliceKind::Tag, "model"}, {},
                                          {{"d0", "model-a"}, {"d1", ""}, {"d2", "model-a"}});
    const auto& d0 = a.defs[static_cast<std::size_t>(a.cell_of[0])];
    CHECK(d0.label == "model-a");
    CHECK(d0.kind == DexUsageCellKind::Named);
    CHECK(a.cell_of[0] == a.cell_of[2]);
    for (const int i : {1, 3}) {
        const auto& u = a.defs[static_cast<std::size_t>(a.cell_of[static_cast<std::size_t>(i)])];
        CHECK(u.kind == DexUsageCellKind::Untagged);
        CHECK(u.label == "(untagged)");
    }
}

TEST_CASE("usage cells: more than 50 tag values keep the 50 largest and merge the rest into other",
          "[dex][usage_model]") {
    // v00..v53 hold one device each, v54 holds three: the cap keeps v54 and the first 49 labels.
    std::vector<std::pair<std::string, std::string>> pop;
    std::unordered_map<std::string, std::string> values;
    int id = 0;
    const auto add = [&](const std::string& v, int n) {
        for (int i = 0; i < n; ++i) {
            const std::string a = "d" + std::to_string(id++);
            pop.emplace_back(a, "windows");
            values[a] = v;
        }
    };
    for (int i = 0; i < 54; ++i)
        add((i < 10 ? "v0" : "v") + std::to_string(i), 1);
    add("v54", 3);
    const auto a = dex_usage_assign_cells(pop, {DexUsageSliceKind::Tag, "model"}, {}, values);

    std::size_t named = 0;
    for (const auto& d : a.defs)
        named += d.kind == DexUsageCellKind::Named ? 1 : 0;
    CHECK(named == static_cast<std::size_t>(kDexUsageCellCap));
    std::unordered_map<std::string, int> per_label;
    std::vector<std::int64_t> per_cell(a.defs.size(), 0);
    for (std::size_t i = 0; i < pop.size(); ++i) {
        REQUIRE(a.cell_of[i] >= 0);
        REQUIRE(static_cast<std::size_t>(a.cell_of[i]) < a.defs.size());
        ++per_cell[static_cast<std::size_t>(a.cell_of[i])];
    }
    std::int64_t total = 0;
    for (std::size_t c = 0; c < a.defs.size(); ++c) {
        total += per_cell[c];
        if (a.defs[c].kind == DexUsageCellKind::Named)
            per_label[a.defs[c].label] = static_cast<int>(per_cell[c]);
        if (a.defs[c].kind == DexUsageCellKind::Other)
            CHECK(per_cell[c] == 5); // v49..v53
    }
    CHECK(total == static_cast<std::int64_t>(pop.size())); // one cell per device, none lost
    CHECK(per_label.at("v54") == 3);
    CHECK(per_label.count("v48") == 1);
    CHECK(per_label.count("v49") == 0);
    CHECK(per_label.count("v53") == 0);
}

// ── Disclosure ───────────────────────────────────────────────────────────────

TEST_CASE("usage disclose at floor 10: a sub-floor cell merges and the smallest published folds in",
          "[dex][usage_model]") {
    const std::vector<DexUsageRawCell> in{raw(DexUsageCellKind::Named, "a", 12),
                                          raw(DexUsageCellKind::Named, "b", 11),
                                          raw(DexUsageCellKind::Named, "c", 3)};
    const auto d = dex_usage_disclose(in, 10);
    REQUIRE(d.cells.size() == 2);
    CHECK(d.cells[0].label == "a");
    CHECK(d.cells[0].devices == 12);
    CHECK(d.cells[1].kind == DexUsageCellKind::Other);
    CHECK(d.cells[1].devices == 14); // 3 merged, then 11 folded in so other is not itself a leak
    check_invariants(d, in, 10);
}

TEST_CASE("usage disclose at floor 10: all-small cells become one other", "[dex][usage_model]") {
    const std::vector<DexUsageRawCell> in{raw(DexUsageCellKind::Named, "a", 4),
                                          raw(DexUsageCellKind::Named, "b", 4),
                                          raw(DexUsageCellKind::Named, "c", 4)};
    const auto d = dex_usage_disclose(in, 10);
    REQUIRE(d.cells.size() == 1);
    CHECK(d.cells[0].kind == DexUsageCellKind::Other);
    CHECK(d.cells[0].devices == 12);
    check_invariants(d, in, 10);

    // A group of 12 with a rest of 3: the rest is below the floor, so the group folds into it.
    const std::vector<DexUsageRawCell> grp{raw(DexUsageCellKind::Named, "group-1", 12),
                                           raw(DexUsageCellKind::Other, "other", 3)};
    const auto g = dex_usage_disclose(grp, 10);
    REQUIRE(g.cells.size() == 1);
    CHECK(g.cells[0].kind == DexUsageCellKind::Other);
    CHECK(g.cells[0].devices == 15);
    check_invariants(g, grp, 10);
}

TEST_CASE("usage disclose at floor 10: the untagged residual", "[dex][usage_model]") {
    const std::vector<DexUsageRawCell> small{raw(DexUsageCellKind::Named, "x", 20),
                                             raw(DexUsageCellKind::Named, "y", 15),
                                             raw(DexUsageCellKind::Untagged, "(untagged)", 3)};
    const auto s = dex_usage_disclose(small, 10);
    REQUIRE(s.cells.size() == 2);
    CHECK(s.cells[0].label == "x");
    CHECK(s.cells[1].kind == DexUsageCellKind::Other);
    CHECK(s.cells[1].devices == 18); // the residual 3 plus y
    check_invariants(s, small, 10);

    const std::vector<DexUsageRawCell> big{raw(DexUsageCellKind::Untagged, "(untagged)", 15),
                                           raw(DexUsageCellKind::Named, "y", 15),
                                           raw(DexUsageCellKind::Named, "x", 20)};
    const auto b = dex_usage_disclose(big, 10);
    REQUIRE(b.cells.size() == 3);
    CHECK(b.cells[0].label == "x");
    CHECK(b.cells[1].label == "y");
    CHECK(b.cells[2].kind == DexUsageCellKind::Untagged); // after the named cells, at equal devices
    check_invariants(b, big, 10);
}

TEST_CASE("usage disclose at floor 10: a total below the floor publishes the device count only",
          "[dex][usage_model]") {
    const std::vector<DexUsageRawCell> in{raw(DexUsageCellKind::Named, "a", 4),
                                          raw(DexUsageCellKind::Named, "b", 3)};
    const auto d = dex_usage_disclose(in, 10);
    CHECK(d.devices == 7);
    CHECK(d.cells.empty());
    CHECK_FALSE(d.totals.has_value());
}

TEST_CASE("usage disclose invariants over a table of mixed cells", "[dex][usage_model]") {
    const std::vector<DexUsageRawCell> in{
        raw(DexUsageCellKind::Named, "m1", 40),        raw(DexUsageCellKind::Named, "m3", 25),
        raw(DexUsageCellKind::Named, "m2", 25),        raw(DexUsageCellKind::Named, "m4", 9),
        raw(DexUsageCellKind::Named, "m5", 2),         raw(DexUsageCellKind::Untagged, "(untagged)", 30),
        raw(DexUsageCellKind::Other, "other", 6),      raw(DexUsageCellKind::Named, "m6", 0)};
    const auto d = dex_usage_disclose(in, 10);
    REQUIRE(d.totals.has_value());
    check_invariants(d, in, 10);
    // devices descending then label ascending; untagged after the named; other last.
    REQUIRE(d.cells.size() == 5);
    CHECK(d.cells[0].label == "m1");
    CHECK(d.cells[1].label == "m2");
    CHECK(d.cells[2].label == "m3");
    CHECK(d.cells[3].kind == DexUsageCellKind::Untagged);
    CHECK(d.cells[4].kind == DexUsageCellKind::Other);
    CHECK(d.cells[4].devices == 17); // m4 9 + m5 2 + other 6
    for (const auto& c : d.cells)
        CHECK(c.label != "m6"); // a zero-device input never shows
}

TEST_CASE("usage disclose at the shipped floor publishes every non-empty cell", "[dex][usage_model]") {
    const std::vector<DexUsageRawCell> in{raw(DexUsageCellKind::Named, "a", 1),
                                          raw(DexUsageCellKind::Named, "b", 0),
                                          raw(DexUsageCellKind::Named, "c", 2)};
    const auto d = dex_usage_disclose(in, kDexCohortFloor);
    REQUIRE(d.cells.size() == 2);
    CHECK(d.cells[0].label == "c");
    CHECK(d.cells[1].label == "a");
    for (const auto& c : d.cells)
        CHECK(c.kind != DexUsageCellKind::Other); // no other cell is created
    check_invariants(d, in, kDexCohortFloor);
}

TEST_CASE("usage disclose flags small_cohort below 30 devices", "[dex][usage_model]") {
    const auto d = dex_usage_disclose({raw(DexUsageCellKind::Named, "a", 29),
                                       raw(DexUsageCellKind::Named, "b", 30)},
                                      1);
    REQUIRE(d.cells.size() == 2);
    CHECK(d.cells[0].label == "b");
    CHECK_FALSE(d.cells[0].small_cohort);
    CHECK(d.cells[1].small_cohort);
}

// ── Exposure rate ────────────────────────────────────────────────────────────

TEST_CASE("usage exposure: known answer scales 30-day usage to the window", "[dex][usage_model]") {
    const std::int64_t seconds = 1'080'000; // 300 hours over 30 days
    const auto w7 = dex_usage_exposure(4, 1, seconds, 7, 0, kDexStatsConfidence);
    REQUIRE(w7.rate.has_value());
    CHECK(w7.withheld.empty());
    CHECK(w7.rate->hours == Approx(70.0));
    CHECK(w7.rate->per_hour.estimate == Approx(5.0 / 70.0));
    const auto expect7 = dex_rate(5, 70.0, kDexStatsConfidence);
    REQUIRE(expect7.has_value());
    CHECK(w7.rate->per_hour.lower == Approx(expect7->lower));
    CHECK(w7.rate->per_hour.upper == Approx(expect7->upper));
    CHECK(w7.rate->crashes == 4);
    CHECK(w7.rate->hangs == 1);
    CHECK(std::string(w7.rate->basis) == "estimated_from_30_day_usage");

    const auto w30 = dex_usage_exposure(4, 1, seconds, 30, 0, kDexStatsConfidence);
    REQUIRE(w30.rate.has_value());
    CHECK(w30.rate->hours == Approx(300.0));
    CHECK(w30.rate->per_hour.estimate == Approx(5.0 / 300.0));
    CHECK(std::string(w30.rate->basis) == "estimated_from_30_day_usage");
}

TEST_CASE("usage exposure: window all and zero run time are withheld", "[dex][usage_model]") {
    CHECK(dex_usage_exposure(1, 0, 3600, 0, 0, kDexStatsConfidence).withheld == "unbounded_window");
    CHECK(dex_usage_exposure(1, 0, 0, 7, 0, kDexStatsConfidence).withheld == "zero_usage");
    CHECK_FALSE(dex_usage_exposure(1, 0, 0, 7, 0, kDexStatsConfidence).rate.has_value());
}

TEST_CASE("usage exposure: a window longer than the retention is withheld", "[dex][usage_model]") {
    const auto over = dex_usage_exposure(1, 0, 3600, 30, 7, kDexStatsConfidence);
    CHECK_FALSE(over.rate.has_value());
    CHECK(over.withheld == "window_exceeds_retention");
    CHECK(dex_usage_exposure(1, 0, 3600, 30, 30, kDexStatsConfidence).rate.has_value());
    CHECK(dex_usage_exposure(1, 0, 3600, 30, 0, kDexStatsConfidence).rate.has_value()); // unbounded
    CHECK(dex_usage_exposure(1, 0, 3600, 7, -1, kDexStatsConfidence).rate.has_value());
}

// ── Assembly ─────────────────────────────────────────────────────────────────

TEST_CASE("usage assembly: no usage, ambiguous and below-floor applications", "[dex][usage_model]") {
    const auto apps = apps_of({"alpha.exe", "sharedprefix123-a.exe", "sharedprefix123-b.exe"});
    const auto plan = dex_usage_match_plan({"alpha.exe", "sharedprefix123-a.exe", "sharedprefix123-b.exe"});
    DexUsageRead read;
    read.cells = {cell_row(1, 0, 1, 0, 1, 5, 500), cell_row(2, 0, 1, 0, 1, 5, 500)};
    const auto m = dex_usage_model_from_read(apps, kFleetDefs, plan, read, 7, 0, 1);
    REQUIRE(m.has_value());
    REQUIRE(m->apps.size() == 3);
    CHECK(m->apps[0].state == DexUsageState::NoUsage);
    CHECK(m->apps[0].rate_withheld == "no_usage");
    CHECK_FALSE(m->apps[0].totals.has_value());
    CHECK_FALSE(m->apps[0].rate.has_value());
    for (const int i : {1, 2}) {
        const auto& a = m->apps[static_cast<std::size_t>(i)];
        CHECK(a.state == DexUsageState::AmbiguousName);
        CHECK(a.rate_withheld == "ambiguous_name");
        CHECK_FALSE(a.totals.has_value());
        CHECK(a.cells.empty());
        CHECK_FALSE(a.rate.has_value());
    }

    // Below the floor: the device count only, and the rate says why.
    DexUsageRead small;
    small.cells = {cell_row(0, 0, 4, 4, 0, 40, 4000)};
    const auto b = dex_usage_model_from_read(apps, kFleetDefs, plan, small, 7, 0, 10);
    REQUIRE(b.has_value());
    CHECK(b->apps[0].state == DexUsageState::Matched);
    CHECK(b->apps[0].devices == 4);
    CHECK_FALSE(b->apps[0].totals.has_value());
    CHECK(b->apps[0].cells.empty());
    CHECK(b->apps[0].rate_withheld == "below_floor");
    CHECK(b->floor == 10);
}

TEST_CASE("usage assembly: aligned with the Apps rows, zero events still give a bounded rate",
          "[dex][usage_model]") {
    const std::vector<std::string> subjects{"alpha.exe", "beta.exe", "gamma.exe"};
    const auto apps = apps_of(subjects);
    const auto plan = dex_usage_match_plan(subjects);
    DexUsageRead read;
    read.cells = {cell_row(2, 0, 3, 3, 0, 9, 1'080'000), cell_row(0, 0, 2, 2, 0, 4, 1'080'000)};
    read.events = {{0, 4, 1}};
    const auto m = dex_usage_model_from_read(apps, kFleetDefs, plan, read, 7, 0, 1);
    REQUIRE(m.has_value());
    REQUIRE(m->apps.size() == 3);
    CHECK(m->apps[0].subject == "alpha.exe");
    CHECK(m->apps[1].subject == "beta.exe");
    CHECK(m->apps[2].subject == "gamma.exe");
    CHECK(m->apps[1].state == DexUsageState::NoUsage);
    CHECK(m->apps[0].devices == 2);
    CHECK(m->apps[0].totals->run_seconds_30d == 1'080'000);
    REQUIRE(m->apps[0].rate.has_value());
    CHECK(m->apps[0].rate->per_hour.estimate == Approx(5.0 / 70.0));
    // gamma has usage and no event row: a zero-event rate with a finite, positive upper bound.
    REQUIRE(m->apps[2].rate.has_value());
    CHECK(m->apps[2].rate->crashes == 0);
    CHECK(m->apps[2].rate->per_hour.estimate == 0.0);
    CHECK(m->apps[2].rate->per_hour.upper > 0.0);
    CHECK(std::isfinite(m->apps[2].rate->per_hour.upper));
}

TEST_CASE("usage assembly: the interval level comes from the Apps policy", "[dex][usage_model]") {
    auto apps = apps_of({"alpha.exe"});
    const auto plan = dex_usage_match_plan({"alpha.exe"});
    DexUsageRead read;
    read.cells = {cell_row(0, 0, 2, 2, 0, 4, 1'080'000)};
    read.events = {{0, 4, 1}};
    const auto at95 = dex_usage_model_from_read(apps, kFleetDefs, plan, read, 7, 0, 1);
    apps.policy.policy.interval_confidence = 0.80;
    const auto at80 = dex_usage_model_from_read(apps, kFleetDefs, plan, read, 7, 0, 1);
    REQUIRE(at95.has_value());
    REQUIRE(at80.has_value());
    REQUIRE(at95->apps[0].rate.has_value());
    REQUIRE(at80->apps[0].rate.has_value());
    CHECK(at80->apps[0].rate->per_hour.estimate == Approx(at95->apps[0].rate->per_hour.estimate));
    CHECK(at80->apps[0].rate->per_hour.upper < at95->apps[0].rate->per_hour.upper);
    CHECK(at80->apps[0].rate->per_hour.lower > at95->apps[0].rate->per_hour.lower);
}

TEST_CASE("usage assembly: coverage counts are carried and bad indices give no model",
          "[dex][usage_model]") {
    const auto apps = apps_of({"alpha.exe", "beta.exe"});
    const auto plan = dex_usage_match_plan({"alpha.exe", "beta.exe"});
    DexUsageRead ok;
    ok.reporting_devices = 7;
    ok.stale_devices = 2;
    const auto m = dex_usage_model_from_read(apps, kFleetDefs, plan, ok, 7, 0, 1);
    REQUIRE(m.has_value());
    CHECK(m->reporting_devices == 7);
    CHECK(m->stale_devices == 2);

    for (const int subject : {-1, 2}) { // below zero, and at the upper bound
        DexUsageRead bad;
        bad.cells = {cell_row(subject, 0, 1, 1, 0)};
        CHECK_FALSE(dex_usage_model_from_read(apps, kFleetDefs, plan, bad, 7, 0, 1).has_value());
        DexUsageRead bad_event;
        bad_event.events = {{subject, 1, 0}};
        CHECK_FALSE(dex_usage_model_from_read(apps, kFleetDefs, plan, bad_event, 7, 0, 1).has_value());
    }
    for (const int cell : {-1, 1}) { // kFleetDefs holds one cell
        DexUsageRead bad;
        bad.cells = {cell_row(0, cell, 1, 1, 0)};
        CHECK_FALSE(dex_usage_model_from_read(apps, kFleetDefs, plan, bad, 7, 0, 1).has_value());
    }
}

// ── Builder ──────────────────────────────────────────────────────────────────

namespace {

struct Calls {
    int read{0};
    int group{0};
    int tag{0};
    std::string tag_key;
    DexUsageQuery query;
};

DexUsageSources sources_of(Calls& c, std::optional<DexUsageRead> read = DexUsageRead{},
                           std::optional<std::vector<std::string>> members = std::vector<std::string>{},
                           std::optional<std::unordered_map<std::string, std::string>> values =
                               std::unordered_map<std::string, std::string>{}) {
    DexUsageSources s;
    s.read = [&c, read](const DexUsageQuery& q) {
        ++c.read;
        c.query = q;
        return read;
    };
    s.group_members = [&c, members](const std::string&) {
        ++c.group;
        return members;
    };
    s.tag_values = [&c, values](const std::string& key) {
        ++c.tag;
        c.tag_key = key;
        return values;
    };
    return s;
}

DexFleet fleet_of() {
    DexFleet f;
    f.connected_agents = {{"w1", "windows"}, {"l1", "linux"}, {"m1", "macos"}, {"w2", "windows"}};
    return f;
}

} // namespace

TEST_CASE("usage builder refuses a bad request with its token and calls no closure",
          "[dex][usage_model]") {
    Calls c;
    const auto src = sources_of(c);
    const auto fleet = fleet_of();
    const auto ok_apps = apps_of({"alpha.exe"});

    DexUsageRequest zero;
    zero.now_epoch = 0;
    auto r = build_dex_apps_usage_model(ok_apps, fleet, zero, src);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "invalid_request");

    DexUsageRequest req;
    req.now_epoch = kNow;
    auto degraded = ok_apps;
    degraded.degraded = true;
    r = build_dex_apps_usage_model(degraded, fleet, req, src);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "apps_degraded");

    auto no_pop = ok_apps;
    no_pop.population.reset();
    r = build_dex_apps_usage_model(no_pop, fleet, req, src);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "no_population");

    DexUsageRequest grp = req;
    grp.slice = {DexUsageSliceKind::Group, ""};
    r = build_dex_apps_usage_model(ok_apps, fleet, grp, src);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "invalid_slice");

    CHECK(c.read == 0);
    CHECK(c.group == 0);
    CHECK(c.tag == 0);
}

TEST_CASE("usage builder: a failed input is unavailable, never an empty model", "[dex][usage_model]") {
    const auto fleet = fleet_of();
    const auto apps = apps_of({"alpha.exe"});
    DexUsageRequest req;
    req.now_epoch = kNow;

    {
        Calls c;
        req.slice = {DexUsageSliceKind::Group, "group-1"};
        const auto r = build_dex_apps_usage_model(apps, fleet, req, sources_of(c, DexUsageRead{}, std::nullopt));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "group_unavailable");
        CHECK(c.read == 0); // membership completes first; the usage read never starts
    }
    {
        Calls c;
        req.slice = {DexUsageSliceKind::Tag, "model"};
        const auto r = build_dex_apps_usage_model(
            apps, fleet, req, sources_of(c, DexUsageRead{}, std::vector<std::string>{}, std::nullopt));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "tag_unavailable");
        CHECK(c.read == 0);
    }
    {
        Calls c;
        req.slice = {DexUsageSliceKind::Fleet, ""};
        const auto r = build_dex_apps_usage_model(apps, fleet, req, sources_of(c, std::nullopt));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "usage_unavailable");
        CHECK(c.read == 1);
    }
    {
        // An empty closure is a failed read too.
        Calls c;
        auto src = sources_of(c);
        src.read = nullptr;
        const auto r = build_dex_apps_usage_model(apps, fleet, req, src);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "usage_unavailable");
    }
    {
        // A row outside the Apps rows is a failed read, not a silently dropped row.
        Calls c;
        DexUsageRead bad;
        bad.cells = {cell_row(5, 0, 1, 1, 0)};
        const auto r = build_dex_apps_usage_model(apps, fleet, req, sources_of(c, bad));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "usage_unavailable");
    }
}

TEST_CASE("usage builder: an empty tag key resolves to the default key", "[dex][usage_model]") {
    Calls c;
    DexUsageRequest req;
    req.now_epoch = kNow;
    req.slice = {DexUsageSliceKind::Tag, ""};
    const auto r = build_dex_apps_usage_model(apps_of({"alpha.exe"}), fleet_of(), req, sources_of(c));
    REQUIRE(r.has_value());
    CHECK(c.tag_key == "model");
    CHECK(r->slice.key == "model");
    // Nobody carries a value, so every device is in the untagged residual.
    CHECK(c.query.cell_count == 2); // untagged + other (no named value)
}

TEST_CASE("usage builder: the query carries the scope, the cells and one instant", "[dex][usage_model]") {
    Calls c;
    DexUsageRequest req;
    req.now_epoch = kNow;
    req.slice = {DexUsageSliceKind::Platform, ""};
    const auto r = build_dex_apps_usage_model(apps_of({"Alpha.exe", "sharedprefix123-a.exe"}, "7d", "all"),
                                              fleet_of(), req, sources_of(c));
    REQUIRE(r.has_value());
    CHECK(c.read == 1);
    const auto& q = c.query;
    REQUIRE(q.devices.size() == 4);
    CHECK(q.devices[0].agent_id == "w1");
    CHECK(q.devices[1].agent_id == "l1");
    CHECK(q.devices[1].is_linux);
    CHECK_FALSE(q.devices[0].is_linux);
    CHECK_FALSE(q.devices[2].is_linux);
    CHECK(q.cell_count == 4); // windows, linux, macos, other
    for (const auto& d : q.devices) {
        CHECK(d.cell >= 0);
        CHECK(d.cell < q.cell_count);
    }
    CHECK(q.devices[0].cell == q.devices[3].cell); // both windows
    CHECK(q.devices[0].cell != q.devices[1].cell);
    REQUIRE(q.subjects.size() == 2);
    CHECK(q.subjects[0] == "Alpha.exe"); // raw subject, for the event join
    CHECK(q.keys.size() == 3);           // alpha exact, sharedprefix123-a.exe exact + trunc
    // Every cut derives from the one instant 1,700,000,000.
    CHECK(q.since_iso == "2023-11-07T22:13:20Z"); // 7 days back
    CHECK(q.until_iso == "2023-11-14T22:13:20Z");
    CHECK(q.fresh_since_epoch == kNow - 172800);
    CHECK(r->population == 4);
    CHECK(r->window == "7d");
    CHECK(r->platform_scope == "all");

    // 24h is one day back; window all has no lower bound.
    Calls c24;
    REQUIRE(build_dex_apps_usage_model(apps_of({"a"}, "24h"), fleet_of(), req, sources_of(c24)).has_value());
    CHECK(c24.query.since_iso == "2023-11-13T22:13:20Z");
    Calls call;
    const auto all = build_dex_apps_usage_model(apps_of({"a"}, "all"), fleet_of(), req, sources_of(call));
    REQUIRE(all.has_value());
    CHECK(call.query.since_iso.empty());
    CHECK(all->apps[0].state == DexUsageState::NoUsage);
}

TEST_CASE("usage builder: a platform scope limits the population", "[dex][usage_model]") {
    Calls c;
    DexUsageRequest req;
    req.now_epoch = kNow;
    const auto r = build_dex_apps_usage_model(apps_of({"alpha.exe"}, "7d", "windows"), fleet_of(), req,
                                              sources_of(c));
    REQUIRE(r.has_value());
    REQUIRE(c.query.devices.size() == 2);
    CHECK(c.query.devices[0].agent_id == "w1");
    CHECK(c.query.devices[1].agent_id == "w2");
    CHECK(r->population == 2);
}

TEST_CASE("usage builder: an Apps model with no rows still reads once", "[dex][usage_model]") {
    Calls c;
    DexUsageRead read;
    read.reporting_devices = 3;
    read.stale_devices = 1;
    DexUsageRequest req;
    req.now_epoch = kNow;
    const auto r = build_dex_apps_usage_model(apps_of({}), fleet_of(), req, sources_of(c, read));
    REQUIRE(r.has_value());
    CHECK(c.read == 1);
    CHECK(c.query.keys.empty());
    CHECK(r->apps.empty());
    CHECK(r->reporting_devices == 3);
    CHECK(r->stale_devices == 1);
}
