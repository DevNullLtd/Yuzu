/**
 * test_software_lifecycle_rules.cpp - the pure lifecycle model (software_lifecycle_rules.hpp):
 * source precedence, version-prefix specificity, declared-fact currency and supersession, the
 * conflict flag, the state derivation, the strict rule-file parser and the embedded seed.
 * No store, no I/O.
 */

#include "software_lifecycle_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr std::int64_t kNow = 10'000'000;
constexpr std::int64_t kWindow = 172800;
constexpr const char* kToday = "2026-11-14";
const std::string kKey = "product:postgresql:postgresql";

LifecycleRule rule(LifecycleSource src, std::string prefix, LifecycleEvent ev, std::string date,
                   std::string ref = "ref") {
    return LifecycleRule{kKey, std::move(prefix), ev, std::move(date), src, std::move(ref), 0};
}

DeclaredFact fact(std::string version, LifecycleEvent ev, std::string date, std::int64_t seen) {
    return DeclaredFact{kKey, std::move(version), ev, std::move(date), seen};
}

LifecycleEvaluation eval(const std::string& version, const std::vector<LifecycleRule>& rules,
                         const std::vector<DeclaredFact>& declared = {}) {
    return evaluate_lifecycle(kKey, version, rules, declared, kToday, kNow, kWindow);
}

constexpr LifecycleEvent kEos = LifecycleEvent::end_of_support;
constexpr LifecycleEvent kEol = LifecycleEvent::end_of_life;

} // namespace

TEST_CASE("lifecycle: no rule and no fact is unknown, never supported", "[lifecycle][rules]") {
    const auto e = eval("16.2", {});
    CHECK(e.state == LifecycleState::unknown);
    CHECK_FALSE(e.end_of_support.has_value());
    CHECK_FALSE(e.end_of_life.has_value());
    CHECK_FALSE(e.conflict);
    CHECK(e.status == LifecycleStatus::current);
    CHECK_FALSE(e.declared_collected);
    // A rule for another product or a version outside its prefix does not count either.
    LifecycleRule other = rule(LifecycleSource::shipped, "", kEol, "2020-01-01");
    other.product_key = "product:other";
    CHECK(eval("16.2", {other, rule(LifecycleSource::shipped, "15", kEol, "2020-01-01")}).state ==
          LifecycleState::unknown);
}

TEST_CASE("lifecycle: dates decide the state", "[lifecycle][rules]") {
    SECTION("a future end of support is supported and the date is reported") {
        const auto e = eval("16", {rule(LifecycleSource::shipped, "16", kEos, "2027-01-01", "r1")});
        CHECK(e.state == LifecycleState::supported);
        REQUIRE(e.end_of_support.has_value());
        CHECK(e.end_of_support->date == "2027-01-01");
        CHECK(e.end_of_support->source == LifecycleSource::shipped);
        CHECK(e.source_ref == "r1");
    }
    SECTION("an expired end of support is end_of_support") {
        const auto e = eval("16", {rule(LifecycleSource::shipped, "16", kEos, "2026-11-14", "r1"),
                                   rule(LifecycleSource::shipped, "16", kEol, "2030-01-01", "r2")});
        CHECK(e.state == LifecycleState::end_of_support);
        CHECK(e.source_ref == "r1");
    }
    SECTION("an expired end of life wins over end of support") {
        const auto e = eval("16", {rule(LifecycleSource::shipped, "16", kEos, "2025-01-01", "r1"),
                                   rule(LifecycleSource::shipped, "16", kEol, "2026-01-01", "r2")});
        CHECK(e.state == LifecycleState::end_of_life);
        CHECK(e.source_ref == "r2");
    }
    SECTION("a future end of life alone is supported") {
        CHECK(eval("16", {rule(LifecycleSource::shipped, "16", kEol, "2030-01-01")}).state ==
              LifecycleState::supported);
    }
}

TEST_CASE("lifecycle: current declared beats external beats imported beats shipped",
          "[lifecycle][rules]") {
    const auto shipped = rule(LifecycleSource::shipped, "", kEol, "2026-01-01");
    const auto imported = rule(LifecycleSource::imported, "", kEol, "2026-02-01");
    const auto external = rule(LifecycleSource::external, "", kEol, "2026-03-01");
    const auto declared = fact("16.2", kEol, "2026-04-01", kNow - 10);

    CHECK(eval("16.2", {shipped, imported, external}, {declared}).end_of_life->source ==
          LifecycleSource::declared);
    CHECK(eval("16.2", {shipped, imported, external}).end_of_life->source ==
          LifecycleSource::external);
    CHECK(eval("16.2", {shipped, imported}).end_of_life->source == LifecycleSource::imported);
    CHECK(eval("16.2", {shipped}).end_of_life->source == LifecycleSource::shipped);

    SECTION("a stale declared fact loses to any rule") {
        const auto stale = fact("16.2", kEol, "2026-04-01", kNow - kWindow - 1);
        const auto e = eval("16.2", {shipped}, {stale});
        CHECK(e.end_of_life->source == LifecycleSource::shipped);
        CHECK(e.end_of_life->date == "2026-01-01");
        CHECK_FALSE(e.conflict); // a superseded stale fact never raises conflict
        CHECK(e.status == LifecycleStatus::current);
    }
    SECTION("a fact repeated exactly at the window edge is still current") {
        const auto edge = fact("16.2", kEol, "2026-04-01", kNow - kWindow);
        CHECK(eval("16.2", {shipped}, {edge}).end_of_life->source == LifecycleSource::declared);
    }
    SECTION("a declared fact for another version does not apply") {
        CHECK(eval("16.3", {shipped}, {declared}).end_of_life->source == LifecycleSource::shipped);
    }
}

TEST_CASE("lifecycle: sources that disagree are flagged and the losers listed",
          "[lifecycle][rules]") {
    const auto e = eval("16", {rule(LifecycleSource::shipped, "", kEol, "2026-01-01", "s"),
                               rule(LifecycleSource::external, "", kEol, "2027-01-01", "x"),
                               rule(LifecycleSource::imported, "", kEol, "2027-01-01", "i")});
    REQUIRE(e.end_of_life.has_value());
    CHECK(e.end_of_life->source == LifecycleSource::external);
    CHECK(e.end_of_life->date == "2027-01-01");
    CHECK(e.conflict);
    // Only the shipped tier differs from the winning date; imported agrees with it.
    CHECK(e.conflicting_sources == std::vector<LifecycleSource>{LifecycleSource::shipped});
    CHECK(e.state == LifecycleState::supported);

    SECTION("sources that agree raise no conflict") {
        const auto same = eval("16", {rule(LifecycleSource::shipped, "", kEol, "2027-01-01"),
                                      rule(LifecycleSource::external, "", kEol, "2027-01-01")});
        CHECK_FALSE(same.conflict);
        CHECK(same.conflicting_sources.empty());
    }
    SECTION("a declared winner against a rule lists the rule's source") {
        const auto d = eval("16", {rule(LifecycleSource::shipped, "", kEol, "2027-01-01")},
                            {fact("16", kEol, "2026-06-01", kNow)});
        CHECK(d.conflict);
        CHECK(d.conflicting_sources == std::vector<LifecycleSource>{LifecycleSource::shipped});
        CHECK(d.source_ref.empty());
    }
}

TEST_CASE("lifecycle: the longest version prefix wins inside a tier", "[lifecycle][rules]") {
    const std::vector<LifecycleRule> rules{
        rule(LifecycleSource::shipped, "", kEol, "2030-01-01", "all"),
        rule(LifecycleSource::shipped, "3", kEol, "2029-01-01", "major"),
        rule(LifecycleSource::shipped, "3.8", kEol, "2024-10-07", "minor")};
    CHECK(eval("3.8.10", rules).end_of_life->source_ref == "minor");
    CHECK(eval("3.8", rules).end_of_life->source_ref == "minor");
    CHECK(eval("3.80", rules).end_of_life->source_ref == "major"); // 3.8 does not match 3.80
    CHECK(eval("3.9.1", rules).end_of_life->source_ref == "major");
    CHECK(eval("4.0", rules).end_of_life->source_ref == "all");
    // Specificity inside one tier is not a disagreement.
    CHECK_FALSE(eval("3.8.10", rules).conflict);

    SECTION("a broader prefix in a higher tier still wins over a longer one in a lower tier") {
        const auto e = eval("3.8.10", {rule(LifecycleSource::external, "3", kEol, "2031-01-01", "x"),
                                       rule(LifecycleSource::shipped, "3.8.10", kEol, "2024-01-01",
                                            "s")});
        CHECK(e.end_of_life->source == LifecycleSource::external);
        CHECK(e.conflict);
    }
}

TEST_CASE("lifecycle: current declared dates and supersession", "[lifecycle][rules]") {
    SECTION("two current dates: the earliest wins and hosts disagree") {
        const auto e = eval("16", {},
                            {fact("16", kEol, "2026-12-01", kNow - 100),
                             fact("16", kEol, "2026-08-01", kNow - 200)});
        CHECK(e.end_of_life->date == "2026-08-01");
        CHECK(e.conflict);
        CHECK(e.conflicting_sources == std::vector<LifecycleSource>{LifecycleSource::declared});
        CHECK(e.state == LifecycleState::end_of_life);
    }
    SECTION("a corrected date supersedes the old one once the old one is stale") {
        const auto old_fact = fact("16", kEol, "2026-08-01", kNow - kWindow - 5);
        const auto corrected = fact("16", kEol, "2026-12-01", kNow - 5);
        const auto e = eval("16", {}, {old_fact, corrected});
        CHECK(e.end_of_life->date == "2026-12-01");
        CHECK_FALSE(e.conflict);
        CHECK(e.status == LifecycleStatus::current);
        CHECK(e.state == LifecycleState::supported);
        // The old date never wins again, whatever order the rows arrive in.
        CHECK(eval("16", {}, {corrected, old_fact}) == e);
    }
    SECTION("the two events resolve independently") {
        const auto e = eval("16", {}, {fact("16", kEos, "2026-01-01", kNow),
                                       fact("16", kEol, "2027-01-01", kNow)});
        CHECK(e.state == LifecycleState::end_of_support);
        CHECK(e.end_of_support->date == "2026-01-01");
        CHECK(e.end_of_life->date == "2027-01-01");
    }
}

TEST_CASE("lifecycle: only stale declared facts and no rule is unconfirmed", "[lifecycle][rules]") {
    const auto older = fact("16", kEol, "2026-01-01", kNow - kWindow - 500);
    const auto newer = fact("16", kEol, "2026-06-01", kNow - kWindow - 100);
    const auto e = eval("16", {}, {older, newer});
    REQUIRE(e.end_of_life.has_value());
    CHECK(e.end_of_life->date == "2026-06-01"); // the most recently seen wins
    CHECK(e.end_of_life->source == LifecycleSource::declared);
    CHECK(e.status == LifecycleStatus::unconfirmed);
    CHECK_FALSE(e.conflict);
    CHECK(e.state == LifecycleState::end_of_life);

    SECTION("equal last_seen: the earliest date wins") {
        const auto a = fact("16", kEol, "2026-09-01", kNow - kWindow - 1);
        const auto b = fact("16", kEol, "2026-03-01", kNow - kWindow - 1);
        CHECK(eval("16", {}, {a, b}).end_of_life->date == "2026-03-01");
    }
}

TEST_CASE("lifecycle: dates are strict calendar dates", "[lifecycle][rules]") {
    CHECK(is_lifecycle_date("2024-02-29"));
    CHECK_FALSE(is_lifecycle_date("2023-02-29"));
    CHECK_FALSE(is_lifecycle_date("2023-04-31"));
    CHECK_FALSE(is_lifecycle_date("2023-13-01"));
    CHECK_FALSE(is_lifecycle_date("2023-1-01"));
    CHECK_FALSE(is_lifecycle_date("2023/01/01"));
    CHECK_FALSE(is_lifecycle_date("1969-12-31"));
    CHECK_FALSE(is_lifecycle_date(""));
    CHECK(lifecycle_date_from_epoch(0) == "1970-01-01");
    CHECK(lifecycle_date_from_epoch(86399) == "1970-01-01");
    CHECK(lifecycle_date_from_epoch(86400) == "1970-01-02");
    CHECK(lifecycle_date_from_epoch(1'763'078'400) == "2025-11-14");
}

TEST_CASE("lifecycle: keys", "[lifecycle][rules]") {
    CHECK(product_lifecycle_key("postgresql:postgresql") == "product:postgresql:postgresql");
    CHECK(product_lifecycle_key("").empty());
    CHECK(os_lifecycle_key("linux", "Ubuntu") == "os:ubuntu");
    CHECK(os_lifecycle_key("linux", "").empty());
    CHECK(os_lifecycle_key("Windows", "") == "os:windows");
    CHECK(os_lifecycle_key("macos", "ignored") == "os:macos");
    CHECK(os_lifecycle_key("plan9", "x").empty());
}

namespace {
const std::string kHeader{kLifecycleCsvHeader};
std::string csv(const std::string& rows) { return "# comment\n\n" + kHeader + "\n" + rows; }
} // namespace

TEST_CASE("lifecycle csv: a well-formed file parses", "[lifecycle][rules][csv]") {
    const auto r = parse_lifecycle_rules_csv(
        csv("os:ubuntu,22.04,end_of_life,2027-04-01,https://example.test/a\r\n"
            "product:x:y,,end_of_support,2026-01-31,\n"),
        LifecycleSource::imported);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 2);
    CHECK((*r)[0].product_key == "os:ubuntu");
    CHECK((*r)[0].version_prefix == "22.04");
    CHECK((*r)[0].event == kEol);
    CHECK((*r)[0].source == LifecycleSource::imported);
    CHECK((*r)[0].source_ref == "https://example.test/a");
    CHECK((*r)[1].version_prefix.empty());
    CHECK((*r)[1].event == kEos);
}

TEST_CASE("lifecycle csv: each defect refuses the whole file with a reason", "[lifecycle][rules][csv]") {
    const auto refused = [](const std::string& text) {
        const auto r = parse_lifecycle_rules_csv(text, LifecycleSource::shipped);
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(r.error().empty());
        return r.error();
    };
    SECTION("bad date") { CHECK(refused(csv("a,,end_of_life,2026-02-30,r\n")).find("date") != std::string::npos); }
    SECTION("unknown event") {
        CHECK(refused(csv("a,,retired,2026-02-01,r\n")).find("event") != std::string::npos);
    }
    SECTION("duplicate key") {
        CHECK(refused(csv("a,1,end_of_life,2026-02-01,r\na,1,end_of_life,2027-02-01,r\n"))
                  .find("duplicate") != std::string::npos);
    }
    SECTION("same key with a different event or prefix is not a duplicate") {
        CHECK(parse_lifecycle_rules_csv(csv("a,1,end_of_life,2026-02-01,r\n"
                                            "a,1,end_of_support,2026-01-01,r\n"
                                            "a,2,end_of_life,2026-02-01,r\n"),
                                        LifecycleSource::shipped)
                  .has_value());
    }
    SECTION("oversize file") {
        refused(csv(std::string(kLifecycleCsvMaxBytes, 'x')));
    }
    SECTION("too many rows") {
        std::string rows;
        for (std::size_t i = 0; i <= kLifecycleCsvMaxRows; ++i)
            rows += "k" + std::to_string(i) + ",,end_of_life,2026-02-01,r\n";
        CHECK(refused(csv(rows)).find("rows") != std::string::npos);
    }
    SECTION("control byte") {
        refused(csv("a,,end_of_life,2026-02-01,r\x01x\n"));
        refused(csv("a,,end_of_life,2026-02-01,r\tx\n"));
        refused(csv(std::string("a,,end_of_life,2026-02-01,r") + '\0' + "x\n"));
    }
    SECTION("invalid UTF-8") { refused(csv("a,,end_of_life,2026-02-01,r\xc3\x28\n")); }
    SECTION("field over 256 bytes") {
        refused(csv("a,,end_of_life,2026-02-01," + std::string(257, 'r') + "\n"));
    }
    SECTION("wrong column count") {
        refused(csv("a,end_of_life,2026-02-01,r\n"));
        refused(csv("a,,end_of_life,2026-02-01,r,extra\n"));
    }
    SECTION("empty product key") { refused(csv(",,end_of_life,2026-02-01,r\n")); }
    SECTION("prefix that starts or ends with a dot") {
        refused(csv("a,3.,end_of_life,2026-02-01,r\n"));
        refused(csv("a,.3,end_of_life,2026-02-01,r\n"));
    }
    SECTION("wrong or missing header") {
        refused("product_key,version,event,date,source_reference\na,,end_of_life,2026-02-01,r\n");
        refused("# only a comment\n");
        refused("");
    }
}

TEST_CASE("lifecycle csv: the embedded seed parses and every row names its policy",
          "[lifecycle][rules][csv][seed]") {
    const auto seed = parse_lifecycle_rules_csv(kSoftwareLifecycleSeed, LifecycleSource::shipped);
    REQUIRE(seed.has_value());
    CHECK_FALSE(seed->empty());
    for (const auto& r : *seed) {
        INFO(r.product_key << " " << r.version_prefix << " " << to_string(r.event));
        CHECK_FALSE(r.source_ref.empty());
        CHECK((r.product_key.starts_with("product:") || r.product_key.starts_with("os:")));
    }
}
