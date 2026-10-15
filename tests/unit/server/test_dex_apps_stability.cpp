/**
 * test_dex_apps_stability.cpp -- the PURE application and per-version stability
 * assembly behind GET /api/v1/dex/apps and list_dex_apps: figures, published
 * order, failure directions, policy handling and the shared JSON serializer.
 * No store, no PG, no I/O.
 *
 * Hand-computed anchor (population 50, application A: 7 devices affected,
 * 12 crashes + 3 hangs, per-device-capped sums 10 crashes / 3 hangs):
 *   share  7/50                         = 0.14
 *   rate   15 events / (50 / 1000)      = 300 per 1,000 devices
 *   score  100 - (60*7/50 + 20*10/(50*5) + 8*3/(50*5) + 0)
 *        = 100 - (8.4 + 0.8 + 0.096)     = 90.704 -> shown 90.7, excellent
 */
#include "dex_read_builders.hpp"
#include "dex_read_model.hpp"

#include <nlohmann/json.hpp>

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

using Catch::Approx;
using namespace yuzu::server;

namespace {

DexAppStabilityRow total_row(const std::string& subject, int64_t crashes, int64_t hangs, int64_t affected,
                             int64_t cc, int64_t ch, int64_t version_count = 1,
                             int64_t apps_total = 0) {
    DexAppStabilityRow r;
    r.subject = subject;
    r.crashes = crashes;
    r.hangs = hangs;
    r.affected_devices = affected;
    // Default fixture: every affected device is online, so the online figures
    // equal the window-wide ones; the churn cases below override them.
    r.affected_online = affected;
    r.crashes_online = crashes;
    r.hangs_online = hangs;
    r.capped_crashes = cc;
    r.capped_hangs = ch;
    r.version_count = version_count;
    r.apps_total = apps_total;
    r.last_seen = "2026-10-14T00:00:00Z";
    return r;
}

DexAppStabilityRow version_row(const std::string& subject, const std::string& version, int64_t crashes,
                               int64_t hangs, int64_t affected) {
    DexAppStabilityRow r = total_row(subject, crashes, hangs, affected, crashes, hangs, 0);
    r.version = version;
    return r;
}

const DexScorePolicy& def() {
    return dex_default_score_policy();
}

} // namespace

TEST_CASE("apps model: known-answer figures for one application", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", {total_row("a.exe", 12, 3, 7, 10, 3)}, 50, def());
    REQUIRE(m.apps.size() == 1);
    const auto& f = m.apps[0].figures;
    REQUIRE(f.share_affected);
    CHECK(f.share_affected->estimate == Approx(0.14));
    const auto wilson = dex_proportion(7, 50);
    CHECK(f.share_affected->lower == Approx(wilson->lower));
    CHECK(f.share_affected->upper == Approx(wilson->upper));
    REQUIRE(f.rate_per_1000);
    CHECK(f.rate_per_1000->estimate == Approx(300.0));
    const auto garwood = dex_rate(15, 1.0);
    CHECK(f.rate_per_1000->lower == Approx(garwood->lower * 20.0));
    CHECK(f.rate_per_1000->upper == Approx(garwood->upper * 20.0));
    REQUIRE(f.score.score);
    CHECK(*f.score.score == Approx(90.704));
    CHECK(stability_display_score(*f.score.score) == Approx(90.7));
    REQUIRE(f.score.band);
    CHECK(*f.score.band == StabilityBand::Excellent);
    REQUIRE(f.score.deductions.size() == 4);
    CHECK_FALSE(f.score.deductions[3].assessed); // regression: no sampled exposure here
    CHECK(m.population == std::optional<int64_t>{50});
}

TEST_CASE("apps model: published order is activity then name, not input order", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d",
        {total_row("alpha.exe", 2, 0, 1, 2, 0), total_row("beta.exe", 5, 0, 1, 5, 0),
         total_row("zeta.exe", 10, 0, 1, 5, 0), version_row("zeta.exe", "1.0", 1, 0, 1),
         version_row("zeta.exe", "2.0", 6, 0, 3), version_row("zeta.exe", "", 3, 0, 2)},
        100, def());
    REQUIRE(m.apps.size() == 3);
    CHECK(m.apps[0].subject == "zeta.exe");
    CHECK(m.apps[1].subject == "beta.exe");
    CHECK(m.apps[2].subject == "alpha.exe");
    const auto& v = m.apps[0].versions;
    REQUIRE(v.size() == 3);
    CHECK(v[0].version == "2.0"); // 3 devices
    CHECK(v[1].version == "");    // 2 devices; the unknown bucket is kept
    CHECK(v[2].version == "1.0"); // 1 device
}

TEST_CASE("apps model: equal activity breaks by subject, equal devices by version", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d",
        {total_row("b.exe", 3, 0, 2, 3, 0), total_row("a.exe", 3, 0, 2, 3, 0),
         version_row("a.exe", "2.0", 1, 0, 1), version_row("a.exe", "1.0", 1, 0, 1)},
        10, def());
    REQUIRE(m.apps.size() == 2);
    CHECK(m.apps[0].subject == "a.exe");
    CHECK(m.apps[0].versions[0].version == "1.0");
    CHECK(m.apps[0].versions[1].version == "2.0");
}

TEST_CASE("apps model: version cap is flagged from version_count", "[dex][apps_model]") {
    const auto capped = dex_apps_model_from_rows(
        "7d", {total_row("a.exe", 21, 0, 21, 21, 0, 21), version_row("a.exe", "1", 1, 0, 1)}, 100, def());
    CHECK(capped.apps[0].version_count == 21);
    CHECK(capped.apps[0].versions_truncated);
    const auto exact = dex_apps_model_from_rows("7d", {total_row("a.exe", 20, 0, 20, 20, 0, 20)}, 100, def());
    CHECK_FALSE(exact.apps[0].versions_truncated);
}

TEST_CASE("apps model: unknown or zero population gives no share, no rate, no score",
          "[dex][apps_model]") {
    for (const std::optional<int64_t> pop : {std::optional<int64_t>{}, std::optional<int64_t>{0}}) {
        const auto m = dex_apps_model_from_rows("7d", {total_row("a.exe", 2, 1, 2, 2, 1)}, pop, def());
        const auto& f = m.apps[0].figures;
        CHECK_FALSE(f.share_affected);
        CHECK_FALSE(f.rate_per_1000);
        CHECK_FALSE(f.score.score);
        CHECK(std::string(f.score.withheld) == "no_population");
        CHECK(f.score.deductions.empty());
    }
}

// The store draws the numerator from the online ids, so this cannot happen
// through the real read; a caller that breaks that contract is refused, not clamped.
TEST_CASE("apps model: more devices affected than online is a refusal, not a clamp",
          "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("30d", {total_row("a.exe", 9, 0, 9, 9, 0)}, 5, def());
    const auto& f = m.apps[0].figures;
    CHECK_FALSE(f.share_affected);
    CHECK_FALSE(f.rate_per_1000); // same denominator mismatch: no rate on a basis the row calls inconsistent
    CHECK(std::string(f.score.withheld) == "inconsistent");
    // Exactly the population affected is consistent: share and rate are published.
    const auto eq = dex_apps_model_from_rows("30d", {total_row("a.exe", 9, 0, 5, 9, 0)}, 5, def());
    CHECK(eq.apps[0].figures.share_affected);
    CHECK(eq.apps[0].figures.rate_per_1000);
    CHECK(eq.apps[0].figures.score.score);
}

TEST_CASE("apps model: apps_total and apps_truncated name the top-N cut", "[dex][apps_model]") {
    const auto cut = dex_apps_model_from_rows(
        "7d", {total_row("a.exe", 1, 0, 1, 1, 0, 1, 5), total_row("b.exe", 1, 0, 1, 1, 0, 1, 5),
               total_row("c.exe", 1, 0, 1, 1, 0, 1, 5)},
        10, def());
    CHECK(cut.apps_total == 5);
    CHECK(cut.apps_truncated);
    const auto whole = dex_apps_model_from_rows("7d", {total_row("a.exe", 1, 0, 1, 1, 0, 1, 1)}, 10, def());
    CHECK(whole.apps_total == 1);
    CHECK_FALSE(whole.apps_truncated);
}

TEST_CASE("apps model: order and assembly corners", "[dex][apps_model]") {
    // A version row fed before its total still attaches; the activity key
    // counts hangs; a version with fewer devices but more events sorts after
    // one with more devices.
    const auto m = dex_apps_model_from_rows(
        "7d",
        {version_row("a.exe", "1.0", 9, 0, 1), version_row("a.exe", "2.0", 1, 0, 2),
         total_row("a.exe", 10, 0, 2, 10, 0), total_row("b.exe", 4, 7, 1, 4, 5)},
        20, def());
    REQUIRE(m.apps.size() == 2);
    CHECK(m.apps[0].subject == "b.exe"); // 4 + 7 hangs beats 10 crashes
    REQUIRE(m.apps[1].versions.size() == 2);
    CHECK(m.apps[1].versions[0].version == "2.0");
    CHECK(m.apps[1].versions[1].version == "1.0");
    // The floor is one device: a population of 1 or 2 still scores.
    for (const int64_t pop : {1, 2}) {
        const auto s2 = dex_apps_model_from_rows("7d", {total_row("a.exe", 1, 0, 1, 1, 0)}, pop, def());
        CHECK(s2.apps[0].figures.score.score);
    }
}

TEST_CASE("apps model: a one-device application is published with no floor", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", {total_row("solo.exe", 1, 0, 1, 1, 0)}, 3, def());
    const auto& f = m.apps[0].figures;
    CHECK(f.share_affected);
    CHECK(f.rate_per_1000);
    CHECK(f.score.score);
    CHECK(f.share_affected->reliable == false); // under 20 events, marked not hidden
}

TEST_CASE("apps model: a per-image override changes one application's band only", "[dex][apps_model]") {
    DexScorePolicy p;
    DexScoreOverride o;
    o.image = "strict.exe";
    o.excellent = 95.0;
    p.overrides.push_back(o);
    REQUIRE_FALSE(dex_score_policy_fault(p));
    const auto m = dex_apps_model_from_rows(
        "7d",
        {total_row("Strict.EXE", 12, 3, 7, 10, 3), total_row("plain.exe", 12, 3, 7, 10, 3, 1),
         version_row("Strict.EXE", "1.0", 12, 3, 7)},
        50, p);
    for (const auto& a : m.apps) {
        REQUIRE(a.figures.score.band);
        if (a.subject == "Strict.EXE") {
            CHECK(*a.figures.score.band == StabilityBand::Good); // 90.7 < 95
            REQUIRE(a.versions.size() == 1);
            CHECK(*a.versions[0].figures.score.band == StabilityBand::Good);
        } else {
            CHECK(*a.figures.score.band == StabilityBand::Excellent);
        }
    }
}

// The invalid-policy arm needs an open store to discriminate, so it lives in
// test_dex_api.cpp; a null store degrades regardless of the policy.
TEST_CASE("apps builder: a null store degrades, never scores", "[dex][apps_model]") {
    const auto m = build_dex_apps_model(nullptr, "7d", "2026-10-07T00:00:00Z",
                                       std::vector<std::string>(50, "id"), def());
    CHECK(m.degraded);
    CHECK(m.apps.empty());
}

TEST_CASE("apps json: exact golden for the unknown-population model", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d", {total_row("a.exe", 2, 1, 2, 2, 1), version_row("a.exe", "1.0", 2, 1, 2)}, std::nullopt, def());
    const std::string fig =
        R"("crashes":2,"distinct_devices":2,"distinct_devices_online":2,"hangs":1,)"
        R"("last_seen":"2026-10-14T00:00:00Z",)"
        R"("rate_per_1000":null,"score":{"band":null,"deductions":[],"score":null,"withheld":"no_population"},)"
        R"("share_affected":null)";
    const std::string expect =
        R"({"apps":[{)" + fig + R"(,"subject":"a.exe","version_count":1,"versions":[{)" + fig +
        R"(,"version":"1.0"}],"versions_truncated":false}],"apps_total":0,"apps_truncated":false,"population":null,)"
        R"("population_basis":"windows_online","window":"7d"})";
    CHECK(dex_apps_json(m) == expect);
}

TEST_CASE("apps json: pre-existing keys survive and the key set is the documented one",
          "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", {total_row("a.exe", 12, 3, 7, 10, 3)}, 50, def());
    const auto j = nlohmann::json::parse(dex_apps_json(m));
    CHECK(j["window"] == "7d");
    CHECK(j["population"] == 50);
    CHECK(j["population_basis"] == "windows_online");
    CHECK(j["apps_total"] == 0);
    CHECK(j["apps_truncated"] == false);
    const auto& a = j["apps"][0];
    CHECK(a["subject"] == "a.exe");
    CHECK(a["crashes"] == 12);
    CHECK(a["hangs"] == 3);
    CHECK(a["distinct_devices"] == 7);
    CHECK(a["distinct_devices_online"] == 7);
    CHECK(a["last_seen"] == "2026-10-14T00:00:00Z");
    std::set<std::string> keys;
    for (auto it = a.begin(); it != a.end(); ++it)
        keys.insert(it.key());
    CHECK(keys == std::set<std::string>{"subject", "crashes", "hangs", "distinct_devices",
                                        "distinct_devices_online", "last_seen", "share_affected", "rate_per_1000", "score", "versions",
                                        "version_count", "versions_truncated"});
    CHECK(a["score"]["score"] == Approx(90.7));
    CHECK(a["score"]["band"] == "excellent");
    CHECK(a["score"]["deductions"].size() == 4);
    CHECK(dex_apps_json(m).find("below_floor") == std::string::npos);
}

TEST_CASE("apps json: a small rate is serialised at full precision", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", {total_row("a.exe", 1, 0, 1, 1, 0)}, 1'000'000, def());
    const auto j = nlohmann::json::parse(dex_apps_json(m));
    CHECK(j["apps"][0]["share_affected"]["estimate"].get<double>() == Approx(1e-6));
}

// The score takes the per-device-capped hang count, never the raw one.
TEST_CASE("apps model: the score uses capped hangs not raw hangs", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d", {total_row("a.exe", 12, 9, 7, 10, 5), total_row("b.exe", 12, 5, 7, 10, 5)}, 50, def());
    REQUIRE(m.apps.size() == 2);
    REQUIRE(m.apps[0].figures.score.score);
    REQUIRE(m.apps[1].figures.score.score);
    CHECK(*m.apps[0].figures.score.score == *m.apps[1].figures.score.score);
}

TEST_CASE("apps json: an empty model", "[dex][apps_model]") {
    DexAppsModel m;
    m.window = "7d";
    CHECK(dex_apps_json(m) ==
          R"({"apps":[],"apps_total":0,"apps_truncated":false,"population":null,)"
          R"("population_basis":"windows_online","window":"7d"})");
}

TEST_CASE("apps json: a populated row carries the score object, rate and both cap flags",
          "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d", {total_row("a.exe", 12, 3, 7, 10, 3, 21, 100), version_row("a.exe", "1.0", 12, 3, 7)}, 50, def());
    const auto j = nlohmann::json::parse(dex_apps_json(m));
    CHECK(j["apps_total"] == 100);
    CHECK(j["apps_truncated"] == true);
    const auto& a = j["apps"][0];
    CHECK(a["version_count"] == 21);
    CHECK(a["versions_truncated"] == true);
    CHECK(a["score"]["withheld"].is_null());
    CHECK(a["rate_per_1000"]["estimate"].get<double>() == Approx(300.0));
    CHECK(a["score"]["deductions"][0]["name"].is_string());
    CHECK(a["score"]["deductions"][0].at("points").get<double>() == Approx(8.4)); // 60 * 7 / 50
    CHECK(a["score"]["deductions"][0].at("assessed") == true);
    CHECK(a["versions"][0]["version"] == "1.0");
}

// Churn: seven devices crashed and went offline while fifty others are online.
// The counts keep the seven; the share, rate and score are over the online
// population, whose members none of the seven are, so they read zero affected.
TEST_CASE("apps model: devices that crashed and went offline are in the counts, not the share",
          "[dex][apps_model]") {
    auto r = total_row("a.exe", 12, 3, 7, 0, 0);
    r.affected_online = 0;
    r.crashes_online = 0;
    r.hangs_online = 0;
    const auto m = dex_apps_model_from_rows("7d", {r}, 50, def());
    const auto& f = m.apps[0].figures;
    CHECK(f.crashes == 12);
    CHECK(f.hangs == 3);
    CHECK(f.distinct_devices == 7);
    CHECK(f.distinct_devices_online == 0);
    REQUIRE(f.share_affected);
    CHECK(f.share_affected->estimate == Approx(0.0));
    REQUIRE(f.rate_per_1000);
    CHECK(f.rate_per_1000->estimate == Approx(0.0));
    REQUIRE(f.score.score);
    CHECK(*f.score.score == Approx(100.0));
}

TEST_CASE("apps model: share, rate and score use the online figures only", "[dex][apps_model]") {
    // 7 devices affected in the window; 2 of them are online, with 3 crashes + 1 hang.
    auto r = total_row("a.exe", 12, 3, 7, 3, 1);
    r.affected_online = 2;
    r.crashes_online = 3;
    r.hangs_online = 1;
    const auto m = dex_apps_model_from_rows("7d", {r}, 50, def());
    const auto& f = m.apps[0].figures;
    CHECK(f.distinct_devices == 7);
    CHECK(f.distinct_devices_online == 2);
    REQUIRE(f.share_affected);
    CHECK(f.share_affected->estimate == Approx(2.0 / 50.0));
    REQUIRE(f.rate_per_1000);
    CHECK(f.rate_per_1000->estimate == Approx(80.0)); // 4 events / (50 / 1000)
    // 100 - (60*2/50 + 20*3/(50*5) + 8*1/(50*5)) = 100 - (2.4 + 0.24 + 0.032)
    REQUIRE(f.score.score);
    CHECK(*f.score.score == Approx(97.328));
}
