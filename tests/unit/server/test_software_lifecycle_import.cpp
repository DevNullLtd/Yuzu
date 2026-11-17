/**
 * test_software_lifecycle_import.cpp - the pure lifecycle import parsers
 * (software_lifecycle_import.hpp): csv dispatch and CLE (ECMA-428 1.0.0).
 * No store, no I/O; every fixture is a raw string literal.
 *
 * The CLE fixture `kCleAnnexB` is the example document of ECMA-428 Annex B, verbatim
 * (https://github.com/Ecma-TC54/ECMA-428, spec.emu, "Example CLE document"). The other CLE
 * documents are built from it by hand to exercise one rule each and are marked DERIVED.
 */

#include "software_lifecycle_import.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace li = yuzu::server::lifecycle_import;

namespace {

constexpr const char* kRef = "https://example.com/policy";

// ECMA-428 Annex B, verbatim.
constexpr const char* kCleAnnexB = R"json(
{
  "$schema": "https://tc54.org/schemas/cle/cle-1.0.0.schema.json",
  "identifier": "pkg:npm/example-component",
  "updatedAt": "2021-01-15T00:00:00Z",
  "definitions": {
    "support": [
      {
        "id": "standard",
        "description": "Standard product support policy",
        "url": "https://example.com/support/standard"
      }
    ]
  },
  "events": [
    {
      "id": 5,
      "type": "withdrawn",
      "effective": "2021-01-15T00:00:00Z",
      "published": "2021-01-15T00:00:00Z",
      "eventId": 2,
      "reason": "The endOfSupport date was incorrect.",
      "references": [
        "https://example.com/support-correction"
      ]
    },
    {
      "id": 4,
      "type": "endOfSupport",
      "effective": "2021-01-01T00:00:00Z",
      "published": "2021-01-01T00:00:00Z",
      "versions": [
        {
          "range": "vers:npm/>=1.0.0|<2.0.0"
        }
      ],
      "supportId": "standard"
    },
    {
      "id": 3,
      "type": "componentRenamed",
      "effective": "2020-01-01T00:00:00Z",
      "published": "2020-01-01T00:00:00Z",
      "description": "Component renamed due to acquisition",
      "identifiers": [
        {
          "type": "PURL",
          "value": "pkg:npm/new-component"
        }
      ]
    },
    {
      "id": 2,
      "type": "endOfSupport",
      "effective": "2020-01-01T00:00:00Z",
      "published": "2020-01-01T00:00:00Z",
      "versions": [
        {
          "range": "vers:npm/>=1.0.0|<2.0.0"
        }
      ],
      "supportId": "standard"
    },
    {
      "id": 1,
      "type": "released",
      "effective": "2019-01-01T00:00:00Z",
      "published": "2019-01-01T00:00:00Z",
      "version": "1.0.0",
      "license": "MIT"
    }
  ]
}
)json";

constexpr const char* kSchema = "https://tc54.org/schemas/cle/cle-1.0.0.schema.json";

std::string doc_with(const std::string& identifier, const std::string& events,
                     const std::string& schema = kSchema) {
    return R"({"$schema":")" + schema + R"(","identifier":)" + identifier +
           R"(,"updatedAt":"2021-01-15T00:00:00Z","events":[)" + events + "]}";
}

std::string event(int id, const std::string& type, const std::string& ranges,
                  const std::string& effective = "2021-01-01T00:00:00Z") {
    return R"({"id":)" + std::to_string(id) + R"(,"type":")" + type + R"(","effective":")" +
           effective + R"(","published":"2021-01-01T00:00:00Z","versions":[)" + ranges +
           R"(],"supportId":"standard"})";
}

std::string range(const std::string& vers) { return R"({"range":")" + vers + R"("})"; }

std::string withdrawn(int id, int target) {
    return R"({"id":)" + std::to_string(id) + R"(,"type":"withdrawn","effective":"2021-01-15T00:00:00Z",)"
           R"("published":"2021-01-15T00:00:00Z","eventId":)" + std::to_string(target) + "}";
}

const std::string kNpmKey = product_lifecycle_key(norm_key("example-component", ""));

std::size_t skipped_count(const li::Parsed& p, std::string_view reason) {
    for (const auto& s : p.skipped)
        if (s.reason == reason)
            return s.count;
    return 0;
}

std::string reason_of(const std::expected<li::Parsed, li::ImportError>& r) {
    REQUIRE_FALSE(r.has_value());
    return r.error().reason;
}

/// A JSON array of `n` distinct PURL aliases (distinct keys, none a title-less name).
std::string many_identifiers(std::size_t n) {
    std::string out = "[";
    for (std::size_t i = 0; i < n; ++i) {
        std::string name;
        for (std::size_t v = i + 1; v > 0; v /= 26)
            name.insert(name.begin(), static_cast<char>('a' + (v - 1) % 26));
        out += (i ? ",\"" : "\"") + std::string{"pkg:generic/acme/"} + name + "\"";
    }
    return out + "]";
}

} // namespace

TEST_CASE("lifecycle import: parse_format accepts exactly the lower-case tokens",
          "[lifecycle][import]") {
    CHECK(li::parse_format("csv") == li::Format::csv);
    CHECK(li::parse_format("cle") == li::Format::cle);
    CHECK_FALSE(li::parse_format("openeox").has_value());
    CHECK_FALSE(li::parse_format("CSV").has_value());
    CHECK_FALSE(li::parse_format("Cle").has_value());
    CHECK_FALSE(li::parse_format("").has_value());
    CHECK_FALSE(li::parse_format("csv ").has_value());
    CHECK_FALSE(li::parse_format("json").has_value());
}

TEST_CASE("lifecycle import: the published CLE example reports its spec version and counts "
          "what the model cannot hold",
          "[lifecycle][import]") {
    const auto r = li::parse(li::Format::cle, kCleAnnexB, kRef);
    REQUIRE(r.has_value());
    CHECK(r->spec_version == "1.0.0");
    // Event 4 is a version range; events 1 and 3 are not end events; event 2 was withdrawn by 5
    // and is neither counted nor stored; the withdrawal itself is applied, not counted.
    CHECK(r->rules.empty());
    CHECK(skipped_count(*r, "version_range") == 1);
    CHECK(skipped_count(*r, "unmapped_event_type") == 2);
    CHECK(r->skipped.size() == 2);
}

TEST_CASE("lifecycle import: a whole-product CLE record becomes one imported rule",
          "[lifecycle][import]") {
    // DERIVED from Annex B: event 4 covers every version.
    const auto r = li::parse(
        li::Format::cle,
        doc_with(R"("pkg:npm/example-component")",
                 event(2, "endOfLife", range("vers:npm/*"), "2022-06-30T23:59:59-05:00") + "," +
                     event(1, "endOfSupport", range("vers:npm/*"))),
        kRef);
    REQUIRE(r.has_value());
    REQUIRE(r->rules.size() == 2);
    CHECK(r->skipped.empty());
    // Oldest event id first.
    CHECK(r->rules[0] == LifecycleRule{kNpmKey, "", LifecycleEvent::end_of_support, "2021-01-01",
                                       LifecycleSource::imported, kRef, 0});
    CHECK(r->rules[1] == LifecycleRule{kNpmKey, "", LifecycleEvent::end_of_life, "2022-06-30",
                                       LifecycleSource::imported, kRef, 0});
    for (const auto& rule : r->rules)
        CHECK_FALSE(validate_lifecycle_rule(rule).has_value());
}

TEST_CASE("lifecycle import: an exact version is counted and never stored as a prefix",
          "[lifecycle][import]") {
    const auto r = li::parse(
        li::Format::cle,
        doc_with(R"("pkg:npm/example-component")",
                 event(3, "endOfLife", range("vers:npm/*")) + "," +
                     event(2, "endOfSupport", range("vers:npm/3.8") + "," + range("vers:npm/=3.9|=4.0")) +
                     "," + event(1, "endOfLife", range("vers:npm/>=1.0.0|<2.0.0"))),
        kRef);
    REQUIRE(r.has_value());
    REQUIRE(r->rules.size() == 1);
    CHECK(r->rules[0].event == LifecycleEvent::end_of_life);
    CHECK(skipped_count(*r, "exact_version") == 2);
    CHECK(skipped_count(*r, "version_range") == 1);
    // The failure this guards: a "3.8" prefix would also claim 3.8.10.
    for (const auto& rule : r->rules)
        CHECK(rule.version_prefix.empty());
    const auto only_exact = li::parse(
        li::Format::cle,
        doc_with(R"("pkg:npm/example-component")", event(1, "endOfLife", range("vers:npm/3.8"))), kRef);
    REQUIRE(only_exact.has_value());
    CHECK(only_exact->rules.empty());
    CHECK(skipped_count(*only_exact, "exact_version") == 1);
}

TEST_CASE("lifecycle import: a vers scheme the version parser refuses still classifies",
          "[lifecycle][import]") {
    const auto r = li::parse(
        li::Format::cle,
        doc_with(R"("pkg:deb/debian/example-component")",
                 event(2, "endOfLife", range("vers:deb/*")) + "," +
                     event(1, "endOfSupport", range("vers:deb/>=1|<2"))),
        kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 1);
    CHECK(skipped_count(*r, "version_range") == 1);
}

TEST_CASE("lifecycle import: unmapped event types are counted and the rest still parse",
          "[lifecycle][import]") {
    const auto r = li::parse(
        li::Format::cle,
        doc_with(R"("pkg:npm/example-component")",
                 event(3, "endOfLife", range("vers:npm/*")) + "," +
                     event(2, "endOfDevelopment", range("vers:npm/*")) + "," +
                     event(1, "endOfDistribution", range("vers:npm/*"))),
        kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 1);
    CHECK(skipped_count(*r, "unmapped_event_type") == 2);
}

TEST_CASE("lifecycle import: a vers range is bounded by its constraint bytes, not its scheme",
          "[lifecycle][import]") {
    // `>=` and then digits: one interval constraint of exactly `n` bytes after the slash.
    const auto doc_for = [](std::size_t n) {
        return doc_with(R"("pkg:npm/example-component")",
                        event(1, "endOfLife", range("vers:npm/>=" + std::string(n - 2, '1'))));
    };
    constexpr auto kLimit = li::detail::kMaxVersConstraintBytes;
    const auto at_limit = li::parse(li::Format::cle, doc_for(kLimit), kRef);
    REQUIRE(at_limit.has_value());
    CHECK(skipped_count(*at_limit, "version_range") == 1);
    // One byte over is refused, and the reason names the limits it applies.
    const auto reason = reason_of(li::parse(li::Format::cle, doc_for(kLimit + 1), kRef));
    CHECK(reason.find("32 constraints") != std::string::npos);
    CHECK(reason.find(std::to_string(kLimit) + " constraint bytes") != std::string::npos);
}

TEST_CASE("lifecycle import: withdrawn events follow the specification", "[lifecycle][import]") {
    const auto id = R"("pkg:npm/example-component")";
    // A withdrawn event is ignored: no rule, nothing counted.
    auto r = li::parse(li::Format::cle,
                       doc_with(id, withdrawn(2, 1) + "," + event(1, "endOfLife", range("vers:npm/*"))),
                       kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.empty());
    CHECK(r->skipped.empty());
    // A withdrawn withdrawal never existed, so the original stands again.
    r = li::parse(li::Format::cle,
                  doc_with(id, withdrawn(3, 2) + "," + withdrawn(2, 1) + "," +
                                   event(1, "endOfLife", range("vers:npm/*"))),
                  kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 1);
    // A withdrawal must name an earlier event.
    CHECK_FALSE(li::parse(li::Format::cle, doc_with(id, withdrawn(1, 5) + "," + event(5, "endOfLife", range("vers:npm/*"))), kRef)
                    .has_value());
    // Publication order in the array does not matter: ids do.
    r = li::parse(li::Format::cle,
                  doc_with(id, event(1, "endOfLife", range("vers:npm/*")) + "," + withdrawn(2, 1)), kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.empty());
}

TEST_CASE("lifecycle import: identifier aliases", "[lifecycle][import]") {
    const auto ev = event(1, "endOfLife", range("vers:npm/*"));
    // Two aliases with different keys give a rule each; aliases with one key collapse.
    auto r = li::parse(li::Format::cle,
                       doc_with(R"(["pkg:npm/example-component","pkg:deb/debian/example-component",)"
                                R"("pkg:npm/example-component?arch=x#sub"])",
                                ev),
                       kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 2);
    CHECK(r->rules[0].product_key != r->rules[1].product_key);
    // Percent-encoded namespace and name decode before normalising.
    r = li::parse(li::Format::cle, doc_with(R"("pkg:npm/%40scope/example%2Dcomponent@1.2.3")", ev), kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 1);
    // An identifier that is not a PURL yields no key: the record is counted, not guessed.
    for (const char* bad : {R"("example-component")", R"("pkg:npm")", R"("pkg:npm/")",
                            R"("pkg:npm/%zz")", R"("")"}) {
        r = li::parse(li::Format::cle, doc_with(bad, ev), kRef);
        REQUIRE(r.has_value());
        CHECK(r->rules.empty());
        CHECK(skipped_count(*r, "empty_key") == 1);
    }
    // Rules follow the first-seen order of the aliases, and a repeat collapses.
    r = li::parse(li::Format::cle,
                  doc_with(R"(["pkg:npm/b-comp","pkg:npm/a-comp","pkg:npm/b-comp"])", ev), kRef);
    REQUIRE(r.has_value());
    REQUIRE(r->rules.size() == 2);
    CHECK(r->rules[0].product_key == product_lifecycle_key(norm_key("b-comp", "")));
    CHECK(r->rules[1].product_key == product_lifecycle_key(norm_key("a-comp", "")));
    CHECK(r->skipped.empty());
}

TEST_CASE("lifecycle import: a PURL name with no title token identifies nothing",
          "[lifecycle][import]") {
    // `norm_key` of these is ":" / "vendor:", never empty; the key `product::` would join
    // unrelated PURLs, so each is an unusable identifier, counted and not stored.
    const auto ev = event(1, "endOfLife", range("vers:npm/*"));
    for (const char* bare : {R"("pkg:npm/2019")", R"("pkg:generic/x64")",
                             R"("pkg:generic/enterprise")", R"("pkg:generic/acme/2019")"}) {
        const auto r = li::parse(li::Format::cle, doc_with(bare, ev), kRef);
        REQUIRE(r.has_value());
        CHECK(r->rules.empty());
        CHECK(skipped_count(*r, "empty_key") == 1);
    }
}

TEST_CASE("lifecycle import: every unusable alias is counted once per mapped event",
          "[lifecycle][import]") {
    const auto whole = range("vers:npm/*");
    // One usable and one unusable alias: the rule is stored, the unusable alias is counted.
    auto r = li::parse(li::Format::cle,
                       doc_with(R"(["pkg:npm/example-component","not-a-purl"])",
                                event(1, "endOfLife", whole)),
                       kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 1);
    CHECK(skipped_count(*r, "empty_key") == 1);
    // Two unusable aliases are two; the unit is the alias, whatever the event's versions.
    r = li::parse(li::Format::cle,
                  doc_with(R"(["not-a-purl","pkg:npm/2019"])", event(1, "endOfLife", whole)), kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.empty());
    CHECK(skipped_count(*r, "empty_key") == 2);
    // Per mapped event: two mapped events count 2, an unmapped event counts nothing here.
    r = li::parse(li::Format::cle,
                  doc_with(R"(["pkg:npm/example-component","not-a-purl"])",
                           event(3, "endOfSupport", range("vers:npm/>=1|<2")) + "," +
                               event(2, "endOfLife", whole) + "," +
                               event(1, "endOfDevelopment", whole)),
                  kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 1);
    CHECK(skipped_count(*r, "empty_key") == 2);
    CHECK(skipped_count(*r, "unmapped_event_type") == 1);
}

TEST_CASE("lifecycle import: a key the rule model refuses is counted once per whole-product event",
          "[lifecycle][import]") {
    // `%01` decodes to a control byte, which the rule model refuses as not printable.
    const auto ids = R"(["pkg:generic/a%01b","pkg:generic/c%01d","pkg:npm/example-component"])";
    const auto whole = range("vers:npm/*");
    const auto both = event(2, "endOfLife", whole) + "," + event(1, "endOfSupport", whole);
    auto r = li::parse(li::Format::cle, doc_with(ids, both), kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.size() == 2); // the valid key, once per event
    CHECK(skipped_count(*r, "invalid_key") == 4);
    CHECK(skipped_count(*r, "empty_key") == 0);
    // Only invalid keys: the event is not an empty_key; its exact entries are still counted, and
    // invalid_key is counted only where a rule would have been stored.
    const auto bad_key = R"("pkg:generic/a%01b")";
    r = li::parse(li::Format::cle,
                  doc_with(bad_key, event(1, "endOfLife", range("vers:npm/=1.0"))), kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.empty());
    CHECK(skipped_count(*r, "exact_version") == 1);
    CHECK(skipped_count(*r, "invalid_key") == 0);
    CHECK(skipped_count(*r, "empty_key") == 0);
    r = li::parse(li::Format::cle, doc_with(bad_key, event(1, "endOfLife", whole)), kRef);
    REQUIRE(r.has_value());
    CHECK(r->rules.empty());
    CHECK(skipped_count(*r, "invalid_key") == 1);
}

TEST_CASE("lifecycle import: one event can hold a whole-product entry and counted entries",
          "[lifecycle][import]") {
    const auto r = li::parse(
        li::Format::cle,
        doc_with(R"("pkg:npm/example-component")",
                 event(1, "endOfLife",
                       range("vers:npm/*") + "," + range("vers:npm/=1.0") + "," +
                           range("vers:npm/>=2|<3"))),
        kRef);
    REQUIRE(r.has_value());
    REQUIRE(r->rules.size() == 1);
    CHECK(r->rules[0].version_prefix.empty());
    CHECK(skipped_count(*r, "exact_version") == 1);
    CHECK(skipped_count(*r, "version_range") == 1);
    CHECK(r->skipped.size() == 2);
}

TEST_CASE("lifecycle import: CLE refusals are distinct and produce no rules",
          "[lifecycle][import]") {
    const auto good_event = event(1, "endOfLife", range("vers:npm/*"));
    const auto id = R"("pkg:npm/example-component")";
    std::set<std::string> reasons;
    const auto refused = [&](const std::string& body) {
        const auto r = li::parse(li::Format::cle, body, kRef);
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(r.error().reason.empty());
        reasons.insert(r.error().reason);
    };
    refused(doc_with(id, good_event, "https://tc54.org/schemas/cle/cle-2.0.0.schema.json")); // version
    refused(R"({"$schema":)");                                                                   // JSON
    refused(R"(["not","an","object"])");                                                         // shape
    refused(std::string{"{\"$schema\":\""} + kSchema + "\"}");                                   // missing
    refused(std::string{"{\"$schema\":\""} + kSchema +
            R"(","identifier":"pkg:npm/a","updatedAt":"x","events":"none"})");                 // events type
    refused(doc_with("42", good_event));                                                         // identifier type
    refused(doc_with(id, R"({"id":"1","type":"endOfLife","effective":"2021-01-01T00:00:00Z","published":"x","versions":[]})")); // id type
    refused(doc_with(id, event(1, "endOfLife", range("vers:npm/*"), "2021-02-30T00:00:00Z")));   // date
    refused(doc_with(id, event(1, "endOfLife", range("not a vers"))));                           // vers
    refused(doc_with(id, event(1, "endOfLife", "")));                                            // versions empty
    refused(doc_with(id, good_event + "," + good_event));                                        // duplicate id
    refused(doc_with(id, event(2, "endOfLife", range("vers:npm/*")) + "," +
                             event(1, "endOfLife", range("vers:npm/*"), "2020-01-01T00:00:00Z"))); // duplicate rule
    refused(doc_with(id, good_event).insert(2, "\xff\xfe"));                                     // UTF-8
    // Thirteen different defects, thirteen different reasons.
    CHECK(reasons.size() == 13);
}

TEST_CASE("lifecycle import: oversized, deep and wide bodies are refused by their budgets",
          "[lifecycle][import]") {
    const auto big = li::parse(li::Format::cle, std::string(li::kImportMaxBytes + 1, ' '), kRef);
    CHECK(reason_of(big).find("exceeds") != std::string::npos);
    const auto big_csv = li::parse(li::Format::csv, std::string(li::kImportMaxBytes + 1, '#'), kRef);
    CHECK(reason_of(big_csv).find(std::to_string(li::kImportMaxBytes)) != std::string::npos);
    // Exactly the cap is read, not refused for size (and then fails as JSON).
    CHECK(reason_of(li::parse(li::Format::cle, std::string(li::kImportMaxBytes, ' '), kRef)).find("exceeds") ==
          std::string::npos);

    // 200,000 nested arrays: refused by the depth budget before any tree is built.
    const auto deep = li::parse(li::Format::cle, std::string(200'000, '['), kRef);
    CHECK(reason_of(deep).find("nests deeper") != std::string::npos);
    const auto deep_in_field = li::parse(
        li::Format::cle,
        doc_with(R"("pkg:npm/example-component")", event(1, "endOfLife", range("vers:npm/*"))).replace(1, 0,
            R"("x":)" + std::string(100, '[') + std::string(100, ']') + ","),
        kRef);
    CHECK(reason_of(deep_in_field).find("nests deeper") != std::string::npos);

    // A flat array of 250,000 values stays under the byte cap and over the value budget.
    std::string wide = "[0";
    for (int i = 0; i < 250'000; ++i)
        wide += ",0";
    wide += "]";
    CHECK(wide.size() < li::kImportMaxBytes);
    CHECK(reason_of(li::parse(li::Format::cle, wide, kRef)).find("values") != std::string::npos);
}

TEST_CASE("lifecycle import: 5,000 rules pass and 5,001 are refused", "[lifecycle][import]") {
    // Two mapped events over N aliases store 2N rules: 2,500 aliases land on the cap and 2,501 are
    // refused. Exactly 5,001 CLE rules cannot be built (rules = aliases x at most two events, aliases
    // capped at 5,000), so the CLE boundary is 5,000 pass / 5,002 refused; the exact 5,001 case is csv.
    const auto both = event(2, "endOfLife", range("vers:npm/*")) + "," +
                      event(1, "endOfSupport", range("vers:npm/*"));
    const auto at_cap = li::parse(li::Format::cle, doc_with(many_identifiers(2500), both), kRef);
    REQUIRE(at_cap.has_value());
    CHECK(at_cap->rules.size() == 5000);
    const auto over = li::parse(li::Format::cle, doc_with(many_identifiers(2501), both), kRef);
    CHECK(reason_of(over) == "more than 5000 rules");
}

TEST_CASE("lifecycle import: 5,000 identifier aliases pass and 5,001 are refused",
          "[lifecycle][import]") {
    const auto ev = event(1, "endOfLife", range("vers:npm/*"));
    const auto at_cap = li::parse(li::Format::cle, doc_with(many_identifiers(5000), ev), kRef);
    REQUIRE(at_cap.has_value());
    CHECK(at_cap->rules.size() == 5000);
    const auto over = li::parse(li::Format::cle, doc_with(many_identifiers(5001), ev), kRef);
    CHECK(reason_of(over) == "identifier lists more than 5000 aliases");
    // The cap counts array entries, so repeats of one key do not slip under it.
    std::string repeats = "[";
    for (int i = 0; i < 5001; ++i)
        repeats += (i ? ",\"pkg:npm/same\"" : "\"pkg:npm/same\"");
    repeats += "]";
    CHECK(reason_of(li::parse(li::Format::cle, doc_with(repeats, ev), kRef)) ==
          "identifier lists more than 5000 aliases");
}

TEST_CASE("lifecycle import: csv through parse equals parse_lifecycle_rules_csv with the "
          "reference overwritten",
          "[lifecycle][import]") {
    const std::string csv =
        "# comment\n"
        "product_key,version_prefix,event,date,source_reference\n"
        "product:acme:widget,3.8,end_of_life,2026-01-31,original\n"
        "product:acme:widget,,end_of_support,2025-06-30,original\n";
    const auto direct = parse_lifecycle_rules_csv(csv, LifecycleSource::imported);
    REQUIRE(direct.has_value());
    const auto r = li::parse(li::Format::csv, csv, kRef);
    REQUIRE(r.has_value());
    REQUIRE(r->rules.size() == direct->size());
    CHECK(r->skipped.empty());
    CHECK(r->spec_version.empty());
    for (std::size_t i = 0; i < direct->size(); ++i) {
        auto expect = (*direct)[i];
        expect.source_ref = kRef;
        CHECK(r->rules[i] == expect);
        CHECK(r->rules[i].source == LifecycleSource::imported);
    }
    // csv keeps its own prefix column.
    CHECK(r->rules[0].version_prefix == "3.8");
}

TEST_CASE("lifecycle import: csv keeps its own limits and errors", "[lifecycle][import]") {
    const std::string header = std::string{kLifecycleCsvHeader} + "\n";
    const auto rows = [&](std::size_t n) {
        std::string s = header;
        for (std::size_t i = 0; i < n; ++i)
            s += "product:acme:p" + std::to_string(i) + ",,end_of_life,2026-01-31,r\n";
        return s;
    };
    CHECK(li::parse(li::Format::csv, rows(5000), kRef).has_value());
    CHECK(reason_of(li::parse(li::Format::csv, rows(5001), kRef)).find("5000") != std::string::npos);
    // 256 KiB is the csv grammar's own cap, below the 4 MiB import cap.
    CHECK(reason_of(li::parse(li::Format::csv, std::string(kLifecycleCsvMaxBytes + 1, '#'), kRef))
              .find(std::to_string(kLifecycleCsvMaxBytes)) != std::string::npos);
    CHECK(reason_of(li::parse(li::Format::csv, "a,b\n", kRef)).find("header") != std::string::npos);
}

TEST_CASE("lifecycle import: a source_reference the rule model refuses is refused for every format",
          "[lifecycle][import]") {
    for (const auto format : {li::Format::csv, li::Format::cle}) {
        CHECK_FALSE(li::parse(format, kCleAnnexB, std::string(300, 'x')).has_value());
        CHECK_FALSE(li::parse(format, kCleAnnexB, "tab\there").has_value());
    }
}
