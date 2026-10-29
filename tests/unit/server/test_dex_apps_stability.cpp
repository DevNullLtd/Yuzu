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
#include "dex_perf_rules.hpp"
#include "dex_read_builders.hpp"
#include "dex_read_model.hpp"

#include <nlohmann/json.hpp>

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <cstddef>
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

const DexPolicyInForce& def() {
    static const DexPolicyInForce d;
    return d;
}

constexpr const char* kDefaultPolicyBlock =
    R"("policy":{"fault":null,"revision":"default","source":"default","tiers":{)"
    R"("excellent":{"edge":90.0,"name":"excellent"},"fair":{"edge":60.0,"name":"fair"},)"
    R"("good":{"edge":75.0,"name":"good"},"poor":{"edge":0.0,"name":"poor"}}},)";

} // namespace

TEST_CASE("apps model: known-answer figures for one application", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("a.exe", 12, 3, 7, 10, 3)}, 50, def());
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
        "7d", kDexAppsScopeWindows,
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
        "7d", kDexAppsScopeWindows,
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
        "7d", kDexAppsScopeWindows, {total_row("a.exe", 21, 0, 21, 21, 0, 21), version_row("a.exe", "1", 1, 0, 1)}, 100, def());
    CHECK(capped.apps[0].version_count == 21);
    CHECK(capped.apps[0].versions_truncated);
    const auto exact = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("a.exe", 20, 0, 20, 20, 0, 20)}, 100, def());
    CHECK_FALSE(exact.apps[0].versions_truncated);
}

TEST_CASE("apps model: unknown or zero population gives no share, no rate, no score",
          "[dex][apps_model]") {
    for (const std::optional<int64_t> pop : {std::optional<int64_t>{}, std::optional<int64_t>{0}}) {
        const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("a.exe", 2, 1, 2, 2, 1)}, pop, def());
        const auto& f = m.apps[0].figures;
        CHECK_FALSE(f.share_affected);
        CHECK_FALSE(f.rate_per_1000);
        CHECK_FALSE(f.score.score);
        CHECK(std::string(f.score.withheld) == "no_population");
        CHECK(f.score.deductions.empty());
        // Zero online devices is a known empty set; no fleet source leaves membership unknown.
        CHECK(f.distinct_devices_online.has_value() == pop.has_value());
    }
}

// The store draws the numerator from the online ids, so this cannot happen
// through the real read; a caller that breaks that contract is refused, not clamped.
TEST_CASE("apps model: more devices affected than online is a refusal, not a clamp",
          "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("30d", kDexAppsScopeWindows, {total_row("a.exe", 9, 0, 9, 9, 0)}, 5, def());
    const auto& f = m.apps[0].figures;
    CHECK_FALSE(f.share_affected);
    CHECK_FALSE(f.rate_per_1000); // no rate beside a score the row withholds as inconsistent
    CHECK(std::string(f.score.withheld) == "inconsistent");
    // Exactly the population affected is consistent: share and rate are published.
    const auto eq = dex_apps_model_from_rows("30d", kDexAppsScopeWindows, {total_row("a.exe", 9, 0, 5, 9, 0)}, 5, def());
    CHECK(eq.apps[0].figures.share_affected);
    CHECK(eq.apps[0].figures.rate_per_1000);
    CHECK(eq.apps[0].figures.score.score);
}

TEST_CASE("apps model: apps_total and apps_truncated name the top-N cut", "[dex][apps_model]") {
    const auto cut = dex_apps_model_from_rows(
        "7d", kDexAppsScopeWindows, {total_row("a.exe", 1, 0, 1, 1, 0, 1, 5), total_row("b.exe", 1, 0, 1, 1, 0, 1, 5),
               total_row("c.exe", 1, 0, 1, 1, 0, 1, 5)},
        10, def());
    CHECK(cut.apps_total == 5);
    CHECK(cut.apps_truncated);
    const auto whole = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("a.exe", 1, 0, 1, 1, 0, 1, 1)}, 10, def());
    CHECK(whole.apps_total == 1);
    CHECK_FALSE(whole.apps_truncated);
}

TEST_CASE("apps model: order and assembly corners", "[dex][apps_model]") {
    // A version row fed before its total still attaches; the activity key
    // counts hangs; a version with fewer devices but more events sorts after
    // one with more devices.
    const auto m = dex_apps_model_from_rows(
        "7d", kDexAppsScopeWindows,
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
        const auto s2 = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("a.exe", 1, 0, 1, 1, 0)}, pop, def());
        CHECK(s2.apps[0].figures.score.score);
    }
}

TEST_CASE("apps model: a one-device application is published with no floor", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("solo.exe", 1, 0, 1, 1, 0)}, 3, def());
    const auto& f = m.apps[0].figures;
    CHECK(f.share_affected);
    CHECK(f.rate_per_1000);
    CHECK(f.score.score);
    CHECK(f.share_affected->reliable == false); // under 20 events, marked not hidden
}

TEST_CASE("apps model: a per-image override changes one application's band only", "[dex][apps_model]") {
    DexPolicyInForce in_force;
    DexScoreOverride o;
    o.image = "strict.exe";
    o.excellent = 95.0;
    in_force.policy.overrides.push_back(o);
    REQUIRE_FALSE(dex_score_policy_fault(in_force.policy));
    const auto m = dex_apps_model_from_rows(
        "7d", kDexAppsScopeWindows,
        {total_row("Strict.EXE", 12, 3, 7, 10, 3), total_row("plain.exe", 12, 3, 7, 10, 3, 1),
         version_row("Strict.EXE", "1.0", 12, 3, 7)},
        50, in_force);
    REQUIRE(m.apps.size() == 2); // the loops below must have both applications to check
    for (const auto& a : m.apps) {
        REQUIRE(a.figures.score.band);
        if (a.subject == "Strict.EXE") {
            CHECK(a.profile == DexPolicyProfile::Override);
            CHECK(*a.figures.score.band == StabilityBand::Good); // 90.7 < 95
            REQUIRE(a.versions.size() == 1);
            CHECK(*a.versions[0].figures.score.band == StabilityBand::Good);
        } else {
            CHECK(a.profile == DexPolicyProfile::Default);
            CHECK(*a.figures.score.band == StabilityBand::Excellent);
        }
    }
    // The profile marker is on the application row; its versions inherit it and
    // carry no marker of their own.
    const auto j = nlohmann::json::parse(dex_apps_json(m));
    REQUIRE(j["apps"].size() == 2);
    for (const auto& a : j["apps"]) {
        CHECK(a["profile"] == (a["subject"] == "Strict.EXE" ? "override" : "default"));
        for (const auto& v : a["versions"])
            CHECK_FALSE(v.contains("profile"));
    }
}

TEST_CASE("apps json: a custom policy's source and revision and fault appear verbatim",
          "[dex][apps_model]") {
    DexPolicyInForce f;
    f.policy.tiers.edges.excellent = 95.0;
    f.policy.tiers.names[0] = "Great";
    f.source = "custom";
    f.revision = "00112233aabbccdd";
    auto j = nlohmann::json::parse(dex_apps_json(dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {}, 50, f)));
    CHECK(j["policy"]["source"] == "custom");
    CHECK(j["policy"]["revision"] == "00112233aabbccdd");
    CHECK(j["policy"]["fault"].is_null());
    CHECK(j["policy"]["tiers"]["excellent"]["edge"].get<double>() == Approx(95.0));
    CHECK(j["policy"]["tiers"]["excellent"]["name"] == "Great");
    CHECK(j["policy"]["tiers"]["poor"]["edge"].get<double>() == Approx(0.0));

    DexPolicyInForce refused; // a refused stored document: defaults in force, fault named
    refused.revision = "ffffffffffffffff";
    refused.fault = "weight_invalid at weights";
    j = nlohmann::json::parse(dex_apps_json(dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {}, 50, refused)));
    CHECK(j["policy"]["source"] == "default");
    CHECK(j["policy"]["fault"] == "weight_invalid at weights");
}

TEST_CASE("apps builder: a hand-built invalid in-force policy still degrades", "[dex][apps_model]") {
    DexPolicyInForce f;
    f.policy.tiers.edges.good = 95.0; // not below excellent
    const auto m = build_dex_apps_model(nullptr, "7d", "2026-10-07T00:00:00Z", "windows",
                                        std::vector<std::string>(50, "id"), f);
    CHECK(m.degraded);
    CHECK(m.degraded_reason == "score_policy_invalid");
    CHECK(m.apps.empty());
}

// The invalid-policy arm needs an open store to discriminate, so it lives in
// test_dex_api.cpp; a null store degrades regardless of the policy.
TEST_CASE("apps builder: a null store degrades, never scores", "[dex][apps_model]") {
    const auto m = build_dex_apps_model(nullptr, "7d", "2026-10-07T00:00:00Z", "windows",
                                       std::vector<std::string>(50, "id"), def());
    CHECK(m.degraded);
    CHECK(m.apps.empty());
}

TEST_CASE("apps json: exact golden for the unknown-population model", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d", kDexAppsScopeWindows, {total_row("a.exe", 2, 1, 2, 2, 1), version_row("a.exe", "1.0", 2, 1, 2)}, std::nullopt, def());
    const std::string head =
        R"("crashes":2,"distinct_devices":2,"distinct_devices_online":null,"hangs":1,)"
        R"("last_seen":"2026-10-14T00:00:00Z",)";
    const std::string tail =
        R"("rate_per_1000":null,"score":{"band":null,"deductions":[],"score":null,"withheld":"no_population"},)"
        R"("share_affected":null)";
    const std::string expect =
        R"({"apps":[{)" + head + R"("profile":"default",)" + tail +
        R"(,"subject":"a.exe","version_count":1,"versions":[{)" + head + tail +
        R"(,"version":"1.0"}],"versions_truncated":false}],"apps_total":0,"apps_truncated":false,)" +
        R"("crash_source_coverage":{"windows":"complete"},)" + kDefaultPolicyBlock + R"("population":null,"population_basis":"windows_online","window":"7d"})";
    CHECK(dex_apps_json(m) == expect);
}

TEST_CASE("apps json: pre-existing keys survive and the key set is the documented one",
          "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("a.exe", 12, 3, 7, 10, 3)}, 50, def());
    const auto j = nlohmann::json::parse(dex_apps_json(m));
    CHECK(j["window"] == "7d");
    CHECK(j["population"] == 50);
    CHECK(j["population_basis"] == "windows_online");
    CHECK(j["crash_source_coverage"] == nlohmann::json{{"windows", "complete"}});
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
                                        "distinct_devices_online", "last_seen", "profile", "share_affected", "rate_per_1000", "score", "versions",
                                        "version_count", "versions_truncated"});
    CHECK(a["profile"] == "default");
    CHECK(j.contains("policy"));
    CHECK(a["score"]["score"] == Approx(90.7));
    CHECK(a["score"]["band"] == "excellent");
    CHECK(a["score"]["deductions"].size() == 4);
    CHECK(dex_apps_json(m).find("below_floor") == std::string::npos);
}

TEST_CASE("apps json: a small rate is serialised at full precision", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {total_row("a.exe", 1, 0, 1, 1, 0)}, 1'000'000, def());
    const auto j = nlohmann::json::parse(dex_apps_json(m));
    CHECK(j["apps"][0]["share_affected"]["estimate"].get<double>() == Approx(1e-6));
}

// The score takes the per-device-capped hang count, never the raw one.
TEST_CASE("apps model: the score uses capped hangs not raw hangs", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d", kDexAppsScopeWindows, {total_row("a.exe", 12, 9, 7, 10, 5), total_row("b.exe", 12, 5, 7, 10, 5)}, 50, def());
    REQUIRE(m.apps.size() == 2);
    REQUIRE(m.apps[0].figures.score.score);
    REQUIRE(m.apps[1].figures.score.score);
    CHECK(*m.apps[0].figures.score.score == *m.apps[1].figures.score.score);
}

TEST_CASE("apps json: an empty model", "[dex][apps_model]") {
    DexAppsModel m;
    m.window = "7d";
    CHECK(dex_apps_json(m) ==
          std::string(R"({"apps":[],"apps_total":0,"apps_truncated":false,)") +
              R"("crash_source_coverage":{"windows":"complete"},)" + kDefaultPolicyBlock +
              R"("population":null,"population_basis":"windows_online","window":"7d"})");
}

TEST_CASE("apps json: a populated row carries the score object, rate and both cap flags",
          "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows(
        "7d", kDexAppsScopeWindows, {total_row("a.exe", 12, 3, 7, 10, 3, 21, 100), version_row("a.exe", "1.0", 12, 3, 7)}, 50, def());
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
TEST_CASE("apps model: devices that crashed and went offline are in the counts and not the share",
          "[dex][apps_model]") {
    auto r = total_row("a.exe", 12, 3, 7, 0, 0);
    r.affected_online = 0;
    r.crashes_online = 0;
    r.hangs_online = 0;
    const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {r}, 50, def());
    const auto& f = m.apps[0].figures;
    CHECK(f.crashes == 12);
    CHECK(f.hangs == 3);
    CHECK(f.distinct_devices == 7);
    CHECK(f.distinct_devices_online == 0);
    REQUIRE(f.share_affected);
    CHECK(f.share_affected->estimate == Approx(0.0));
    REQUIRE(f.rate_per_1000);
    CHECK(f.rate_per_1000->estimate == Approx(0.0));
    // A healthy-looking 100 for an app that took its devices offline is the wrong answer.
    CHECK_FALSE(f.score.score);
    CHECK(std::string(f.score.withheld) == "offline_affected");
}

TEST_CASE("apps model: share and rate and score use the online figures only", "[dex][apps_model]") {
    // 7 devices affected in the window; 2 of them are online, with 3 crashes + 1 hang.
    auto r = total_row("a.exe", 12, 3, 7, 3, 1);
    r.affected_online = 2;
    r.crashes_online = 3;
    r.hangs_online = 1;
    const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {r}, 50, def());
    const auto& f = m.apps[0].figures;
    CHECK(f.distinct_devices == 7);
    CHECK(f.distinct_devices_online == 2);
    REQUIRE(f.share_affected);
    CHECK(f.share_affected->estimate == Approx(2.0 / 50.0));
    REQUIRE(f.rate_per_1000);
    CHECK(f.rate_per_1000->estimate == Approx(80.0)); // 4 events / (50 / 1000)
    // 5 of the 7 affected devices are offline: the score would be built from the other
    // 2 only, so it is withheld.
    CHECK_FALSE(f.score.score);
    CHECK(std::string(f.score.withheld) == "offline_affected");
}

TEST_CASE("apps scope: dex_normalize_apps_scope accepts the four tokens and nothing else",
          "[dex][apps_model]") {
    for (const char* s : {"all", "windows", "macos", "linux"})
        CHECK(dex_normalize_apps_scope(s) == s);
    for (const char* s : {"", "darwin", "Windows", "win"})
        CHECK(dex_normalize_apps_scope(s).empty());
}

TEST_CASE("apps scope: dex_apps_online_ids selects the connected agents of the scope",
          "[dex][apps_model]") {
    DexFleet f;
    f.connected_agents = {{"w1", "windows"}, {"l1", "linux"}, {"m1", "macos"}};
    CHECK(dex_apps_online_ids(f, "windows") == std::vector<std::string>{"w1"});
    CHECK(dex_apps_online_ids(f, "linux") == std::vector<std::string>{"l1"});
    CHECK(dex_apps_online_ids(f, "macos") == std::vector<std::string>{"m1"});
    CHECK(dex_apps_online_ids(f, "all") == std::vector<std::string>{"w1", "l1", "m1"});
    CHECK(dex_apps_online_ids(DexFleet{}, "all").empty());
}

TEST_CASE("apps scope: the population basis is the scope plus _online", "[dex][apps_model]") {
    CHECK(dex_apps_population_basis("windows") == "windows_online");
    CHECK(dex_apps_population_basis("all") == "all_online");
    CHECK(dex_apps_population_basis("linux") == "linux_online");
}

TEST_CASE("apps model: the score is published when every affected device is online",
          "[dex][apps_model]") {
    // The affected devices are all in the online set, so the online figures are the whole picture.
    auto r = total_row("a.exe", 4, 1, 2, 3, 1);
    r.affected_online = 2;
    r.crashes_online = 4;
    r.hangs_online = 1;
    const auto m = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {r}, 50, def());
    const auto& f = m.apps[0].figures;
    // 100 - (60*2/50 + 20*3/(50*5) + 8*1/(50*5)) = 100 - (2.4 + 0.24 + 0.032)
    REQUIRE(f.score.score);
    CHECK(*f.score.score == Approx(97.328));
    CHECK(f.score.withheld[0] == '\0');
    // An unknown population keeps its own reason, not offline_affected.
    auto o = r;
    o.affected_online = 1;
    const auto u = dex_apps_model_from_rows("7d", kDexAppsScopeWindows, {o}, std::nullopt, def());
    CHECK(std::string(u.apps[0].figures.score.withheld) == "no_population");
}

TEST_CASE("apps builder: an unrecognised or empty scope is degraded invalid_scope first",
          "[dex][apps_model]") {
    for (const char* bad : {"", "darwin", "Windows"}) {
        const auto m = build_dex_apps_model(nullptr, "7d", "2026-10-07T00:00:00Z", bad, std::nullopt, def());
        CHECK(m.degraded);
        CHECK(m.degraded_reason == "invalid_scope");
    }
    const auto ok = build_dex_apps_model(nullptr, "7d", "2026-10-07T00:00:00Z", "windows", std::nullopt, def());
    CHECK(ok.degraded);
    CHECK(ok.degraded_reason.empty());
}

TEST_CASE("apps model: from_rows carries the scope it is given", "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", "linux", {total_row("a.exe", 1, 0, 1, 1, 0)}, 4, def());
    CHECK(m.platform_scope == "linux");
    CHECK(nlohmann::json::parse(dex_apps_json(m))["population_basis"] == "linux_online");
}

TEST_CASE("apps json: crash_source_coverage per scope", "[dex][apps_model]") {
    const auto cov = [](const char* scope) {
        return nlohmann::json::parse(
            dex_apps_json(dex_apps_model_from_rows("7d", scope, {}, 1, def())))["crash_source_coverage"];
    };
    CHECK(cov("windows") == nlohmann::json{{"windows", "complete"}});
    CHECK(cov("linux") == nlohmann::json{{"linux", "partial"}});
    CHECK(cov("macos") == nlohmann::json{{"macos", "partial"}});
    CHECK(cov("all") == nlohmann::json{{"windows", "complete"}, {"linux", "partial"}, {"macos", "partial"}});
}

TEST_CASE("apps scope: a non-shipped darwin spelling reaches the macOS population",
          "[dex][apps_model]") {
    for (const char* os : {"darwin24.1", "Darwin", "macos14"}) {
        DexFleet f;
        f.connected_agents = {{"w1", "windows"}, {"m1", detail::dex_perf_os_from_session(os)}};
        CHECK(dex_apps_online_ids(f, "macos") == std::vector<std::string>{"m1"});
    }
    DexFleet f;
    f.connected_agents = {{"w1", "windows"}, {"h1", "haiku"}};
    CHECK(dex_apps_online_ids(f, "all").size() == 2);
    CHECK(dex_apps_online_ids(f, "windows") == std::vector<std::string>{"w1"});
    CHECK(dex_apps_online_ids(f, "linux").empty());
    CHECK(dex_apps_online_ids(f, "macos").empty());
}

TEST_CASE("apps model: a zero Linux or macOS population withholds no_population", "[dex][apps_model]") {
    for (const char* scope : {"linux", "macos"}) {
        const auto m = dex_apps_model_from_rows("7d", scope, {total_row("a.exe", 2, 1, 2, 2, 1)}, 0, def());
        REQUIRE(m.apps.size() == 1);
        const auto j = nlohmann::json::parse(dex_apps_json(m));
        CHECK(j["population"] == 0);
        CHECK(j["population_basis"] == std::string(scope) + "_online");
        CHECK(j["apps"][0]["share_affected"].is_null());
        CHECK(j["apps"][0]["rate_per_1000"].is_null());
        CHECK(j["apps"][0]["score"]["withheld"] == "no_population");
    }
}

// -- AP-2.17 model parameters --------------------------------------------------

namespace {
DexPolicyInForce policy_in_force(DexScorePolicy p) {
    DexPolicyInForce d;
    d.policy = std::move(p);
    d.source = "custom";
    d.revision = "0123456789abcdef";
    return d;
}

// The exact apps JSON the base build (before the model parameters) emitted for
// total_row("a.exe", 12, 3, 7, 10, 3) at a population of 50 under the default policy,
// captured from it and pinned as a literal.
constexpr const char* kBaseAppsJson =
    R"({"apps":[{"crashes":12,"distinct_devices":7,"distinct_devices_online":7,"hangs":3,"last_seen":"2026-10-14T00:00:00Z","profile":"default","rate_per_1000":{"estimate":300.0,"lower":167.9077226556663,"reliable":false,"upper":494.80437742971685},"score":{"band":"excellent","deductions":[{"assessed":true,"name":"breadth","points":8.4},{"assessed":true,"name":"crashes","points":0.8},{"assessed":true,"name":"hangs","points":0.096},{"assessed":false,"name":"regression","points":0.0}],"score":90.7,"withheld":null},"share_affected":{"estimate":0.14,"lower":0.06950833427016294,"reliable":false,"upper":0.2618619371058554},"subject":"a.exe","version_count":1,"versions":[],"versions_truncated":false}],"apps_total":0,"apps_truncated":false,"policy":{"fault":null,"revision":"default","source":"default","tiers":{"excellent":{"edge":90.0,"name":"excellent"},"fair":{"edge":60.0,"name":"fair"},"good":{"edge":75.0,"name":"good"},"poor":{"edge":0.0,"name":"poor"}}},"population":50,"population_basis":"windows_online","window":"7d"})";

// Structural JSON equality: keys, types, integers, strings and bools exact; floats at a
// 1e-12 relative tolerance. The rate and share bounds go through libm (lgamma/exp/log),
// which differs across platforms in the last digits, so a byte compare is not portable.
bool json_near(const nlohmann::json& a, const nlohmann::json& b) {
    if (a.is_number_float() && b.is_number_float()) {
        const double x = a.get<double>(), y = b.get<double>();
        return x == y || std::abs(x - y) <= 1e-12 * std::abs(y);
    }
    if (a.type() != b.type())
        return false;
    if (a.is_object()) {
        if (a.size() != b.size())
            return false;
        for (const auto& [k, v] : a.items())
            if (!b.contains(k) || !json_near(v, b.at(k)))
                return false;
        return true;
    }
    if (a.is_array()) {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i)
            if (!json_near(a[i], b[i]))
                return false;
        return true;
    }
    return a == b;
}
} // namespace

TEST_CASE("apps model: the default policy reproduces the base build's JSON byte for byte",
          "[dex][apps_model]") {
    const auto m = dex_apps_model_from_rows("7d", {total_row("a.exe", 12, 3, 7, 10, 3)}, 50, def());
    CHECK(json_near(nlohmann::json::parse(dex_apps_json(m)), nlohmann::json::parse(kBaseAppsJson)));
}

TEST_CASE("apps model: the policy's interval confidence sets the share and rate intervals",
          "[dex][apps_model]") {
    auto p = dex_default_score_policy();
    p.interval_confidence = 0.90;
    const auto m = dex_apps_model_from_rows("7d", {total_row("a.exe", 12, 3, 7, 10, 3)}, 50,
                                            policy_in_force(p));
    const auto base = dex_apps_model_from_rows("7d", {total_row("a.exe", 12, 3, 7, 10, 3)}, 50, def());
    const auto& f = m.apps[0].figures;
    const auto& b = base.apps[0].figures;
    REQUIRE((f.share_affected && f.rate_per_1000));
    const auto share = dex_proportion(7, 50, 0.90);
    CHECK(f.share_affected->lower == share->lower);
    CHECK(f.share_affected->upper == share->upper);
    CHECK(f.share_affected->lower > b.share_affected->lower); // narrower than at 95 percent
    CHECK(f.share_affected->upper < b.share_affected->upper);
    const auto rate = dex_rate(15, 50.0 / 1000.0, 0.90);
    CHECK(f.rate_per_1000->lower == rate->lower);
    CHECK(f.rate_per_1000->upper == rate->upper);
    CHECK(f.rate_per_1000->estimate == b.rate_per_1000->estimate);
    // The score is not an interval statistic: the same number and band.
    REQUIRE(f.score.score);
    CHECK(*f.score.score == Approx(90.704));
    CHECK(*f.score.band == StabilityBand::Excellent);
    CHECK(*f.score.score == *b.score.score);
}

TEST_CASE("apps model: a per-application regression start ratio marks the row an override",
          "[dex][apps_model]") {
    auto p = dex_default_score_policy();
    DexScoreOverride o;
    o.image = "a.exe";
    o.regression_start_ratio = 1.5;
    p.overrides.push_back(o);
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());
    const auto m = dex_apps_model_from_rows(
        "7d", {total_row("a.exe", 12, 3, 7, 10, 3), total_row("b.exe", 2, 0, 1, 2, 0)}, 50,
        policy_in_force(p));
    REQUIRE(m.apps.size() == 2);
    const auto& a = m.apps[0].subject == "a.exe" ? m.apps[0] : m.apps[1];
    const auto& other = m.apps[0].subject == "a.exe" ? m.apps[1] : m.apps[0];
    CHECK(a.profile == DexPolicyProfile::Override);
    CHECK(other.profile == DexPolicyProfile::Default);
    // Regression is not assessed on this read, so the score is the default one.
    REQUIRE(a.figures.score.score);
    CHECK(*a.figures.score.score == Approx(90.704));
}

TEST_CASE("apps model: a global per-device cap normalises the deductions and leaves the rest",
          "[dex][apps_model]") {
    auto p = dex_default_score_policy();
    p.model.per_device_event_cap = 10;
    const auto cap10 = dex_apps_model_from_rows("7d", {total_row("a.exe", 12, 3, 7, 10, 3)}, 50,
                                                policy_in_force(p));
    const auto base = dex_apps_model_from_rows("7d", {total_row("a.exe", 12, 3, 7, 10, 3)}, 50, def());
    const auto& f = cap10.apps[0].figures;
    const auto& b = base.apps[0].figures;
    // Raw counts and both intervals do not depend on the cap.
    CHECK(f.crashes == b.crashes);
    CHECK(f.hangs == b.hangs);
    CHECK(f.share_affected->lower == b.share_affected->lower);
    CHECK(f.share_affected->upper == b.share_affected->upper);
    CHECK(f.rate_per_1000->lower == b.rate_per_1000->lower);
    CHECK(f.rate_per_1000->upper == b.rate_per_1000->upper);
    // The capped sums come from the store rows; the normalisation n * cap comes from
    // the policy, so crashes and hangs deduct exactly half of their default points.
    REQUIRE((f.score.deductions.size() == 4 && b.score.deductions.size() == 4));
    CHECK(f.score.deductions[0].points == b.score.deductions[0].points); // breadth
    CHECK(f.score.deductions[1].points == Approx(b.score.deductions[1].points / 2.0));
    CHECK(f.score.deductions[2].points == Approx(b.score.deductions[2].points / 2.0));
    CHECK(f.score.deductions[1].points == Approx(0.4));
    CHECK(f.score.deductions[2].points == Approx(0.048));
}
