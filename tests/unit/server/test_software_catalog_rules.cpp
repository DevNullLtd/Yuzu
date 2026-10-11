/**
 * test_software_catalog_rules.cpp — pure coverage for software_catalog_rules.hpp (M.9 PR-1):
 * grain mask, OS-family CASE generation, the catalogue's TRANSITIVE version order, the
 * tie rule, the streaming fleet-newest fold, search hygiene. No
 * store, no libpq, no clock.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_catalog_rules.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace yuzu::server::software_catalog;

TEST_CASE("grain_mask maps every filter combination to PG GROUPING bits",
          "[server][software_catalog]") {
    // bit 2 = kind, bit 1 = ecosystem, bit 0 = source; set = not fixed.
    for (int m = 0; m < 8; ++m) {
        const std::string_view kind = (m & 4) ? "" : "package";
        const std::string_view eco = (m & 2) ? "" : "brew";
        const std::string_view src = (m & 1) ? "" : "pkg_inventory.packages";
        REQUIRE(grain_mask(kind, eco, src) == m);
    }
    REQUIRE(kGrainTitle == 7);
    REQUIRE(kGrainEcosystem == 5);
    REQUIRE(grain_mask("", "rpm", "") == kGrainEcosystem);
}

TEST_CASE("os_family_case_sql is generated from the same table",
          "[server][software_catalog]") {
    const std::string sql = os_family_case_sql();
    std::size_t whens = 0;
    for (std::size_t pos = 0; (pos = sql.find(" WHEN '", pos)) != std::string::npos; ++pos)
        ++whens;
    REQUIRE(whens == kEcosystemFamilies.size());
    REQUIRE(sql.ends_with(" ELSE 'other' END"));
    for (const auto& e : kEcosystemFamilies) {
        const std::string needle = "WHEN '" + std::string(e.ecosystem) + "' THEN '" +
                                   std::string(e.family) + "'";
        REQUIRE(sql.find(needle) != std::string::npos);
    }
}

TEST_CASE("catalog_version_compare orders the documented examples", "[server][software_catalog]") {
    REQUIRE(catalog_version_compare("1.10", "1.9") > 0);
    REQUIRE(catalog_version_compare("2.0", "2.0-rc1") > 0);
    REQUIRE(catalog_version_compare("9.8p1", "9.8") > 0);
    REQUIRE(catalog_version_compare("1.0.2a", "1.0.2") > 0);
    REQUIRE(catalog_version_compare("1.0.1", "1.0") > 0);
    REQUIRE(catalog_version_compare("1.0", "1.0.0") == 0);
    REQUIRE(catalog_version_compare("1:2.3", "2.3") == 0);
    REQUIRE(catalog_version_compare("1.0-pre", "1.0-preview") == 0);
    REQUIRE(catalog_version_compare("1.0-RC1", "1.0-rc1") == 0);
    REQUIRE(catalog_version_compare("1.0-alpha", "1.0-beta") < 0);
    // 40-digit tokens compare by value, no overflow
    const std::string big(40, '9');
    REQUIRE(catalog_version_compare(big, "1" + std::string(40, '0')) < 0);
    REQUIRE(catalog_version_compare("0000" + big, big) == 0);
    // F1 cycle triple
    REQUIRE(catalog_version_compare("1.0rc", "1.0") < 0);
    REQUIRE(catalog_version_compare("1.0", "1.0a") < 0);
    REQUIRE(catalog_version_compare("1.0rc", "1.0a") < 0);
    for (auto [x, y] : {std::pair{"1.0rc", "1.0"}, {"1.0", "1.0a"}, {"1.0rc", "1.0a"}})
        REQUIRE(catalog_version_compare(x, y) == -catalog_version_compare(y, x));
}

TEST_CASE("catalog_version_compare is transitive and antisymmetric", "[server][software_catalog]") {
    const std::vector<std::string> vs{"1.0",   "1.0a",   "1.0rc", "1.0.0",  "1.0-rc1",
                                      "1.0-beta", "1.0.1", "1.0.2a", "1.0.2k", "9.8",
                                      "9.8p1", "1:2.3",  "2.3",   "10.0",   ""};
    for (const auto& a : vs)
        for (const auto& b : vs) {
            REQUIRE(catalog_version_compare(a, b) == -catalog_version_compare(b, a));
            for (const auto& c : vs)
                if (catalog_version_compare(a, b) <= 0 && catalog_version_compare(b, c) <= 0)
                    REQUIRE(catalog_version_compare(a, c) <= 0);
        }
}

TEST_CASE("newer_than applies compare then the total tie rule", "[server][software_catalog]") {
    REQUIRE(newer_than("1.10", 1, "1.9", 50));
    REQUIRE(newer_than("2.0", 1, "2.0-rc1", 50));
    REQUIRE(newer_than("1:2.4", 1, "2.3", 50));
    // equivalent spellings: more installs wins, then the greater string
    REQUIRE(newer_than("1.0", 5, "1.0.0", 3));
    REQUIRE_FALSE(newer_than("1.0", 3, "1.0.0", 5));
    REQUIRE(newer_than("1.0.0", 4, "1.0", 4)); // "1.0.0" > "1.0" lexicographically
    REQUIRE_FALSE(newer_than("1.0", 4, "1.0.0", 4));
    for (auto [a, ai, b, bi] : {std::tuple{"1.0", 4, "1.0.0", 4}, {"1.0", 5, "1.0.0", 3},
                                {"2.0", 1, "1.0", 9}})
        REQUIRE_FALSE((newer_than(a, ai, b, bi) && newer_than(b, bi, a, ai)));
}

TEST_CASE("NewestFold picks per title and survives batch boundaries",
          "[server][software_catalog]") {
    struct Row {
        std::string name, version;
        std::int64_t installs;
    };
    const std::vector<Row> rows{{"a", "1.0", 3}, {"a", "1.10", 1}, {"a", "1.9", 7},
                                {"b", "", 4},    {"b", "", 2},     {"c", "2.0-rc1", 5},
                                {"c", "2.0", 1}};
    NewestFold whole;
    std::vector<NewestPick> out;
    for (const auto& r : rows)
        whole.feed(r.name, r.version, r.installs, out);
    whole.finish(out);
    REQUIRE(out.size() == 2); // b has only '' versions -> no pick
    REQUIRE(out[0].name == "a");
    REQUIRE(out[0].version == "1.10");
    REQUIRE(out[0].installs == 1);
    REQUIRE(out[1].name == "c");
    REQUIRE(out[1].version == "2.0");
    // Two feed batches with finish-free carry: same picks whether the cut falls on a title
    // boundary or mid-title (the fold never resets between feeds).
    for (std::size_t cut = 1; cut < rows.size(); ++cut) {
        NewestFold fold;
        std::vector<NewestPick> first;
        std::vector<NewestPick> second;
        for (std::size_t i = 0; i < cut; ++i)
            fold.feed(rows[i].name, rows[i].version, rows[i].installs, first);
        for (std::size_t i = cut; i < rows.size(); ++i)
            fold.feed(rows[i].name, rows[i].version, rows[i].installs, second);
        fold.finish(second);
        first.insert(first.end(), second.begin(), second.end());
        REQUIRE(first.size() == out.size());
        for (std::size_t i = 0; i < out.size(); ++i) {
            REQUIRE(first[i].name == out[i].name);
            REQUIRE(first[i].version == out[i].version);
            REQUIRE(first[i].installs == out[i].installs);
        }
    }
}

TEST_CASE("NewestFold on the F1 cycle triple is order independent", "[server][software_catalog]") {
    std::array<std::pair<std::string, std::int64_t>, 3> v{
        {{"1.0", 5}, {"1.0a", 2}, {"1.0rc", 9}}};
    std::sort(v.begin(), v.end());
    do {
        NewestFold fold;
        std::vector<NewestPick> out;
        for (const auto& [ver, n] : v)
            fold.feed("t", ver, n, out);
        fold.finish(out);
        REQUIRE(out.size() == 1);
        REQUIRE(out[0].version == "1.0a");
        REQUIRE(out[0].installs == 2);
    } while (std::next_permutation(v.begin(), v.end()));
}

TEST_CASE("like_escape escapes backslash percent and underscore", "[server][software_catalog]") {
    REQUIRE(like_escape("100%_x\\y") == "100\\%\\_x\\\\y");
    REQUIRE(like_escape("plain") == "plain");
    REQUIRE(like_escape("").empty());
}

TEST_CASE("clamp_utf8 cuts at a codepoint start with no ellipsis", "[server][software_catalog]") {
    REQUIRE(clamp_utf8("short", 128) == "short");
    REQUIRE(clamp_utf8("abcdef", 3) == "abc");
    // U+20AC is 3 bytes (E2 82 AC); a cut inside it drops the whole sequence
    const std::string s = "ab\xE2\x82\xAC";
    REQUIRE(clamp_utf8(s, 4) == "ab");
    REQUIRE(clamp_utf8(s, 3) == "ab");
    REQUIRE(clamp_utf8(s, 2) == "ab");
    REQUIRE(clamp_utf8(s, 5) == s);
    std::string multi;
    for (int i = 0; i < 100; ++i)
        multi += "\xE2\x82\xAC";
    const auto c = clamp_utf8(multi, kSearchMaxBytes);
    REQUIRE(c.size() <= kSearchMaxBytes);
    REQUIRE(c.size() % 3 == 0);
}
