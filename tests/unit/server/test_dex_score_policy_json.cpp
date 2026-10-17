/**
 * test_dex_score_policy_json.cpp -- the PURE JSON mapping of the customer score
 * policy: strict parse with field paths, canonical text, revision token, the
 * fault-to-path mapping and the policy in force for a stored text. No store, no
 * I/O.
 */
#include "dex_score_policy_json.hpp"

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <optional>
#include <string>

using namespace yuzu::server;
using nlohmann::json;

namespace {

// A parse that must fail: returns the field path it names.
std::string refused_field(const std::string& text) {
    const auto r = dex_score_policy_from_json(json::parse(text));
    REQUIRE_FALSE(r);
    return r.error().field;
}

constexpr std::array<DexPolicyFault, 10> kAllFaults = {
    DexPolicyFault::EdgeOutOfRange,     DexPolicyFault::EdgeNotDisplayExact,
    DexPolicyFault::EdgesNotDescending, DexPolicyFault::EdgeGapBelowMinimum,
    DexPolicyFault::NameInvalid,        DexPolicyFault::WeightInvalid,
    DexPolicyFault::WeightSumAboveMaximum, DexPolicyFault::OverrideKeyInvalid,
    DexPolicyFault::OverrideKeyDuplicate,  DexPolicyFault::TooManyOverrides};

} // namespace

TEST_CASE("policy json: the default policy round-trips bit for bit and dumps stably",
          "[dex][policy_json]") {
    const DexScorePolicy& d = dex_default_score_policy();
    const std::string a = dex_score_policy_canonical(d);
    const std::string b = dex_score_policy_canonical(d);
    CHECK(a == b);
    const auto back = dex_score_policy_from_json(json::parse(a));
    REQUIRE(back);
    CHECK(back->tiers.edges.excellent == d.tiers.edges.excellent);
    CHECK(back->tiers.edges.good == d.tiers.edges.good);
    CHECK(back->tiers.edges.fair == d.tiers.edges.fair);
    CHECK(back->tiers.names == d.tiers.names);
    CHECK(back->weights.breadth == d.weights.breadth);
    CHECK(back->weights.crashes == d.weights.crashes);
    CHECK(back->weights.hangs == d.weights.hangs);
    CHECK(back->weights.regression == d.weights.regression);
    CHECK(back->overrides.empty());
    CHECK(dex_score_policy_canonical(*back) == a);
}

TEST_CASE("policy json: an override round-trips with only the fields it sets", "[dex][policy_json]") {
    DexScorePolicy p;
    DexScoreOverride o;
    o.image = "app.exe";
    o.excellent = 95.0;
    o.names[3] = "Bad";
    o.hangs = 5.0;
    p.overrides.push_back(o);
    const std::string text = dex_score_policy_canonical(p);
    const auto doc = json::parse(text);
    REQUIRE(doc["overrides"].size() == 1);
    const auto& oj = doc["overrides"][0];
    CHECK(oj["tiers"]["edges"].size() == 1);
    CHECK(oj["tiers"]["names"].size() == 1);
    CHECK_FALSE((oj.contains("weights") && oj["weights"].contains("breadth")));
    const auto back = dex_score_policy_from_json(doc);
    REQUIRE(back);
    REQUIRE(back->overrides.size() == 1);
    const auto& b = back->overrides[0];
    CHECK(b.excellent == std::optional<double>{95.0});
    CHECK_FALSE(b.good);
    CHECK(b.names[3] == std::optional<std::string>{"Bad"});
    CHECK_FALSE(b.names[0]);
    CHECK(b.hangs == std::optional<double>{5.0});
    CHECK_FALSE(b.breadth);
    CHECK(dex_score_policy_canonical(*back) == text);
}

TEST_CASE("policy json: an unknown key is refused with its exact field path", "[dex][policy_json]") {
    CHECK(refused_field(R"({"bogus":1})") == "bogus");
    CHECK(refused_field(R"({"tiers":{"edges":{"excellent":90,"great":80}}})") == "tiers.edges.great");
    CHECK(refused_field(R"({"tiers":{"colours":{}}})") == "tiers.colours");
    CHECK(refused_field(R"({"weights":{"speed":1}})") == "weights.speed");
    CHECK(refused_field(R"({"overrides":[{"image":"a.exe"},{"image":"b.exe"},)"
                        R"({"image":"c.exe","weights":{"crashes":1,"bogus":2}}]})") ==
          "overrides[2].weights.bogus");
    CHECK(refused_field(R"({"overrides":[{"image":"a.exe","extra":1}]})") == "overrides[0].extra");
}

TEST_CASE("policy json: a wrong type is refused with its field path, nothing partially parsed",
          "[dex][policy_json]") {
    CHECK(refused_field(R"({"tiers":{"edges":{"excellent":"90"}}})") == "tiers.edges.excellent");
    CHECK(refused_field(R"({"weights":{"breadth":null}})") == "weights.breadth");
    CHECK(refused_field(R"({"weights":{"breadth":true}})") == "weights.breadth");
    CHECK(refused_field(R"({"tiers":{"names":["a","b","c","d"]}})") == "tiers.names");
    CHECK(refused_field(R"({"tiers":{"names":{"excellent":7}}})") == "tiers.names.excellent");
    CHECK(refused_field(R"({"tiers":[]})") == "tiers");
    CHECK(refused_field(R"({"overrides":{}})") == "overrides");
    CHECK(refused_field(R"({"overrides":["a.exe"]})") == "overrides[0]");
    CHECK(refused_field(R"({"overrides":[{"tiers":{}}]})") == "overrides[0].image");
    CHECK(refused_field(R"({"overrides":[{"image":4}]})") == "overrides[0].image");
    CHECK(refused_field(R"({"overrides":[{"image":"a.exe","weights":{"hangs":"3"}}]})") ==
          "overrides[0].weights.hangs");
    CHECK(refused_field(R"([])") == "document");
    // A valid first half does not leak: the whole document is refused, no policy returned.
    const auto r = dex_score_policy_from_json(
        json::parse(R"({"tiers":{"edges":{"excellent":95}},"weights":{"crashes":"x"}})"));
    CHECK_FALSE(r);
}

TEST_CASE("policy json: an override image is ASCII-folded before validation", "[dex][policy_json]") {
    const auto r = dex_score_policy_from_json(json::parse(R"({"overrides":[{"image":"Outlook.EXE"}]})"));
    REQUIRE(r);
    REQUIRE(r->overrides.size() == 1);
    CHECK(r->overrides[0].image == "outlook.exe");
    CHECK_FALSE(dex_score_policy_fault(*r));
}

TEST_CASE("policy json: revision is a stable 16-hex content hash, default only when nothing stored",
          "[dex][policy_json]") {
    const std::string text = dex_score_policy_canonical(dex_default_score_policy());
    const std::string r1 = dex_score_policy_revision(text);
    CHECK(r1 == dex_score_policy_revision(text));
    CHECK(r1.size() == 16);
    CHECK(r1.find_first_not_of("0123456789abcdef") == std::string::npos);
    std::string changed = text;
    changed.back() = changed.back() == '}' ? ' ' : '}';
    CHECK(dex_score_policy_revision(changed) != r1);
    CHECK(dex_score_policy_revision("") == "default");
    // FNV-1a 64 of "a" (published test vector).
    CHECK(dex_score_policy_revision("a") == "af63dc4c8601ec8c");
    CHECK(r1 != "default");
}

TEST_CASE("policy json: in force resolution", "[dex][policy_json]") {
    SECTION("nothing stored, or an empty string, is the defaults with no fault") {
        const std::optional<std::string> stored_cases[] = {std::nullopt, std::string()};
        for (const auto& stored : stored_cases) {
            const auto f = dex_policy_in_force_from_stored(stored);
            CHECK(f.source == "default");
            CHECK(f.revision == "default");
            CHECK(f.fault.empty());
            CHECK(dex_score_policy_canonical(f.policy) ==
                  dex_score_policy_canonical(dex_default_score_policy()));
        }
    }
    SECTION("unparseable text is the defaults with a fault and the raw text's revision") {
        const std::string raw_cases[] = {"not json", R"({"bogus":1})"};
        for (const auto& raw : raw_cases) {
            const auto f = dex_policy_in_force_from_stored(raw);
            CHECK(f.source == "default");
            CHECK(f.fault.starts_with("unparseable at "));
            CHECK(f.revision == dex_score_policy_revision(raw));
            CHECK(dex_score_policy_canonical(f.policy) ==
                  dex_score_policy_canonical(dex_default_score_policy()));
        }
        CHECK(dex_policy_in_force_from_stored(std::string(R"({"bogus":1})")).fault ==
              "unparseable at bogus: unknown key");
    }
    SECTION("a parseable document failing the validator is the defaults and names the field") {
        const std::string raw = R"({"overrides":[{"image":"a.exe"},{"image":"a.exe"}]})";
        const auto f = dex_policy_in_force_from_stored(raw);
        CHECK(f.source == "default");
        CHECK(f.fault == "override_key_duplicate at overrides[1].image");
        CHECK(f.revision == dex_score_policy_revision(raw));
        CHECK(f.policy.overrides.empty()); // never half-applied
    }
    SECTION("a valid custom document is source custom") {
        DexScorePolicy p;
        p.tiers.edges.excellent = 95.0;
        p.tiers.names[0] = "Great";
        const std::string raw = dex_score_policy_canonical(p);
        const auto f = dex_policy_in_force_from_stored(raw);
        CHECK(f.source == "custom");
        CHECK(f.fault.empty());
        CHECK(f.revision == dex_score_policy_revision(raw));
        CHECK(f.policy.tiers.edges.excellent == 95.0);
        CHECK(f.policy.tiers.names[0] == "Great");
    }
}

TEST_CASE("policy json: every validator fault maps to a field path", "[dex][policy_json]") {
    auto at = [](DexPolicyFault f, std::size_t i) { return dex_policy_fault_field({f, i}); };
    constexpr auto G = kDexPolicyGlobalIndex;
    CHECK(at(DexPolicyFault::EdgeOutOfRange, G) == "tiers.edges");
    CHECK(at(DexPolicyFault::EdgeNotDisplayExact, G) == "tiers.edges");
    CHECK(at(DexPolicyFault::EdgesNotDescending, G) == "tiers.edges");
    CHECK(at(DexPolicyFault::EdgeGapBelowMinimum, G) == "tiers.edges");
    CHECK(at(DexPolicyFault::NameInvalid, G) == "tiers.names");
    CHECK(at(DexPolicyFault::WeightInvalid, G) == "weights");
    CHECK(at(DexPolicyFault::WeightSumAboveMaximum, G) == "weights");
    CHECK(at(DexPolicyFault::TooManyOverrides, G) == "overrides");
    CHECK(at(DexPolicyFault::EdgeOutOfRange, 3) == "overrides[3].tiers.edges");
    CHECK(at(DexPolicyFault::EdgeGapBelowMinimum, 3) == "overrides[3].tiers.edges");
    CHECK(at(DexPolicyFault::NameInvalid, 3) == "overrides[3].tiers.names");
    CHECK(at(DexPolicyFault::WeightInvalid, 3) == "overrides[3].weights");
    CHECK(at(DexPolicyFault::WeightSumAboveMaximum, 3) == "overrides[3].weights");
    CHECK(at(DexPolicyFault::OverrideKeyInvalid, 3) == "overrides[3].image");
    CHECK(at(DexPolicyFault::OverrideKeyDuplicate, 3) == "overrides[3].image");
    CHECK(at(DexPolicyFault::TooManyOverrides, 3) == "overrides");
    // Every fault yields a non-empty path at both index kinds.
    for (const auto f : kAllFaults) {
        CHECK_FALSE(at(f, G).empty());
        CHECK_FALSE(at(f, 7).empty());
    }
}
