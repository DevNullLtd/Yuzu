/**
 * test_software_catalog_rules.cpp — pure coverage for software_catalog_rules.hpp (M.9 PR-1):
 * grain mask, OS-family CASE generation, the catalogue's TRANSITIVE version order, the
 * tie rule, the streaming fleet-newest fold, search hygiene. No
 * store, no libpq, no clock.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_catalog_rules.hpp"

#include <nlohmann/json.hpp>

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

TEST_CASE("expand_ecosystem_tokens: each token form expands from the table",
          "[server][software_catalog][ecosystem]") {
    std::vector<std::string> table;
    for (const auto& e : kEcosystemFamilies)
        table.emplace_back(e.ecosystem);

    SECTION("ENUM is the table, in table order") {
        const auto j = nlohmann::json::parse(
            expand_ecosystem_tokens(R"({"enum":["@@ECOSYSTEM_ENUM@@"]})"), nullptr, false);
        REQUIRE_FALSE(j.is_discarded());
        CHECK(j["enum"].get<std::vector<std::string>>() == table);
    }
    SECTION("ENUM_OR_EMPTY is the empty string then the table") {
        const auto j = nlohmann::json::parse(
            expand_ecosystem_tokens(R"({"enum":["@@ECOSYSTEM_ENUM_OR_EMPTY@@"]})"), nullptr, false);
        REQUIRE_FALSE(j.is_discarded());
        auto expected = table;
        expected.insert(expected.begin(), "");
        CHECK(j["enum"].get<std::vector<std::string>>() == expected);
    }
    SECTION("LIST is the pipe list") {
        const std::string out = expand_ecosystem_tokens("x (@@ECOSYSTEM_LIST@@)");
        CHECK(out == "x (" + ecosystem_pipe_list() + ")");
        CHECK(std::ranges::count(out, '|') ==
              static_cast<std::ptrdiff_t>(kEcosystemFamilies.size()) - 1);
    }
}

TEST_CASE("expand_ecosystem_tokens: repeats and mixed kinds; no-op and empty input",
          "[server][software_catalog][ecosystem]") {
    const std::string tmpl = R"(a "@@ECOSYSTEM_ENUM@@" b "@@ECOSYSTEM_ENUM_OR_EMPTY@@" c )"
                             R"("@@ECOSYSTEM_ENUM@@" d @@ECOSYSTEM_LIST@@ e @@ECOSYSTEM_LIST@@)";
    const std::string out = expand_ecosystem_tokens(tmpl);
    const auto count = [&out](const std::string& needle) {
        std::size_t n = 0;
        for (auto p = out.find(needle); p != std::string::npos; p = out.find(needle, p + 1))
            ++n;
        return n;
    };
    CHECK(out.find("@@") == std::string::npos);
    CHECK(count("\"\", ") == 1);
    CHECK(count(ecosystem_pipe_list()) == 2);
    CHECK(count(ecosystem_json_enum_items()) == 3);

    const std::string plain = R"({"kind":{"enum":["package","app"]}} no tokens)";
    CHECK(expand_ecosystem_tokens(plain) == plain);
    CHECK(expand_ecosystem_tokens("").empty());
}

TEST_CASE("expand_ecosystem_tokens: the quoted contract leaves malformed tokens for the guard",
          "[server][software_catalog][ecosystem]") {
    // The consumer's guard (build_catalogue's boot refusal) decides; the expander never invents
    // a substitution for a token it cannot match exactly.
    for (const char* bad : {"[@@ECOSYSTEM_ENUM@@]", "[\"@ECOSYSTEM_ENUM@@\"]",
                            "[\"@@ECOSYSTEM_ENM@@\"]", "[\"@@ECOSYSTEM_ENUM_OR_EMPTY@@]"}) {
        INFO(bad);
        CHECK(expand_ecosystem_tokens(bad) == bad);
    }
    CHECK(expand_ecosystem_tokens("\"@@ECOSYSTEM_LIST@@\"") == "\"" + ecosystem_pipe_list() + "\"");
    CHECK(expand_ecosystem_tokens("@@ECOSYSTEM_LIST@@") == ecosystem_pipe_list());
}

TEST_CASE("expand_ecosystem_tokens: one exact-size allocation",
          "[server][software_catalog][ecosystem]") {
    std::string tmpl(300, 'x');
    for (int i = 0; i < 3; ++i) {
        tmpl += R"( "@@ECOSYSTEM_ENUM@@" )";
        tmpl += std::string(100, 'y');
        tmpl += " @@ECOSYSTEM_LIST@@ ";
    }
    const std::string out = expand_ecosystem_tokens(tmpl);
    REQUIRE(out.find("@@") == std::string::npos);
    // reserve(peak) on an empty string never doubles: allocator rounding only.
    CHECK(out.capacity() - out.size() < 64);
}

TEST_CASE("kSoftwareKinds and kSoftwareSources: UI vocabulary tables",
          "[server][software_catalog][ui_vocab]") {
    SECTION("kinds are exactly app, pkg, package, feat, in order") {
        std::vector<std::string> values;
        for (const auto& k : kSoftwareKinds)
            values.emplace_back(k.value);
        CHECK(values == std::vector<std::string>{"app", "pkg", "package", "feat"});
    }
    SECTION("the pkg tooltip names the MSI, snap and flatpak products it covers") {
        const auto it = std::find_if(kSoftwareKinds.begin(), kSoftwareKinds.end(),
                                     [](const auto& k) { return k.value == "pkg"; });
        REQUIRE(it != kSoftwareKinds.end());
        CHECK(it->tooltip.find("MSI") != std::string_view::npos);
        CHECK(it->tooltip.find("snap") != std::string_view::npos);
        CHECK(it->tooltip.find("flatpak") != std::string_view::npos);
    }
    SECTION("sources are exactly the six collector sources, in order") {
        std::vector<std::string> values;
        for (const auto& s : kSoftwareSources)
            values.emplace_back(s.value);
        CHECK(values == std::vector<std::string>{
                            "installed_apps.list_inventory", "pkg_inventory.managers",
                            "pkg_inventory.packages", "pkg_inventory.store_packages",
                            "windows_optional_features.list", "msi_packages.list_inventory"});
    }
}
