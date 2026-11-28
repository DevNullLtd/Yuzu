/**
 * test_vers_range.cpp - pure coverage for vers_range.hpp (SAM-43): the `vers:` parser, the
 * normaliser, the VERS containment algorithm and the shared `in_interval` core. No store, no
 * libpq, no clock, no network.
 */

#include <catch2/catch_test_macros.hpp>

#include "nvd_version.hpp"
#include "software_catalog_rules.hpp"
#include "vers_range.hpp"

#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr auto kCatalogCmp = [](std::string_view a, std::string_view b) {
    return software_catalog::catalog_version_compare(a, b);
};

// Parse + normalise under the catalogue comparator, as the lookup parser does.
vers::Range make(const std::string& text) {
    auto r = vers::parse(text);
    REQUIRE(r);
    const auto n = vers::normalize(*r, kCatalogCmp);
    REQUIRE(n);
    return std::move(*r);
}

// The 400 message of text that must be refused (a parse or a normalise error).
std::string refusal(const std::string& text) {
    auto r = vers::parse(text);
    if (!r)
        return r.error();
    const auto n = vers::normalize(*r, kCatalogCmp);
    REQUIRE_FALSE(n);
    return n.error();
}

bool in(const vers::Range& r, std::string_view v) { return vers::contains(r, v, kCatalogCmp); }

} // namespace

TEST_CASE("vers parse: a single interval and a bare version", "[server][vers]") {
    const auto r = make("vers:generic/>=2.0|<2.17");
    CHECK_FALSE(r.all);
    REQUIRE(r.constraints.size() == 2);
    CHECK(r.constraints[0].op == vers::Op::kGe);
    CHECK(r.constraints[0].version == "2.0");
    CHECK(r.constraints[1].op == vers::Op::kLt);
    CHECK(r.constraints[1].version == "2.17");

    const auto eq = make("vers:npm/1.2.3");
    REQUIRE(eq.constraints.size() == 1);
    CHECK(eq.constraints[0].op == vers::Op::kEq); // a bare version means =
    const auto explicit_eq = make("vers:npm/=1.2.3");
    CHECK(explicit_eq.constraints[0].op == vers::Op::kEq);

    for (const char* scheme : {"generic", "semver", "maven", "npm", "pypi", "nuget"}) {
        CAPTURE(scheme);
        CHECK(vers::parse(std::string("vers:") + scheme + "/>=1"));
    }
}

TEST_CASE("vers contains: one interval", "[server][vers]") {
    const auto r = make("vers:generic/>=2.0|<2.17");
    CHECK(in(r, "2.0"));
    CHECK(in(r, "2.16"));
    CHECK(in(r, "2.9")); // numeric, not lexicographic: 2.9 < 2.17
    CHECK_FALSE(in(r, "2.17"));
    CHECK_FALSE(in(r, "1.9"));
    CHECK_FALSE(in(r, "3.0"));
    // The open ends: one comparator alone.
    CHECK(in(make("vers:generic/<1.0"), "0.5"));
    CHECK_FALSE(in(make("vers:generic/<1.0"), "1.0"));
    CHECK(in(make("vers:generic/<=1.0"), "1.0"));
    CHECK(in(make("vers:generic/>1.0"), "1.1"));
    CHECK_FALSE(in(make("vers:generic/>1.0"), "1.0"));
    CHECK(in(make("vers:generic/>=1.0"), "1.0"));
}

TEST_CASE("vers contains: several intervals, the open ends and a hole", "[server][vers]") {
    const auto r = make("vers:npm/<1.0|>=2.0|<3.0|>=4.0");
    CHECK(in(r, "0.5"));
    CHECK_FALSE(in(r, "1.5"));
    CHECK(in(r, "2.5"));
    CHECK_FALSE(in(r, "3.5"));
    CHECK(in(r, "9.0"));
    CHECK(in(r, "4.0"));
    CHECK_FALSE(in(r, "3.0"));

    const auto mixed = make("vers:generic/1.5|!=2.5|>=2.0|<3.0");
    CHECK(in(mixed, "1.5"));       // = wins
    CHECK_FALSE(in(mixed, "2.5")); // != punches a hole in [2.0, 3.0)
    CHECK(in(mixed, "2.6"));
    CHECK_FALSE(in(mixed, "1.6"));
}

TEST_CASE("vers contains: =, != and * on their own", "[server][vers]") {
    const auto eq = make("vers:generic/1.0|2.0");
    CHECK(in(eq, "1.0"));
    CHECK(in(eq, "1.0.0")); // equal under the comparator
    CHECK(in(eq, "2.0"));
    CHECK_FALSE(in(eq, "1.5"));

    const auto ne = make("vers:generic/!=1.0");
    CHECK_FALSE(in(ne, "1.0"));
    CHECK(in(ne, "1.1"));
    CHECK(in(ne, "0.1"));

    const auto both = make("vers:generic/1.0|!=2.0");
    CHECK(in(both, "1.0"));
    CHECK_FALSE(in(both, "2.0"));
    CHECK_FALSE(in(both, "3.0")); // an = list without a match is not "everything else"

    const auto all = make("vers:pypi/*");
    CHECK(all.all);
    CHECK(in(all, "0"));
    CHECK(in(all, "anything-at-all"));
    CHECK(vers::parse("vers:pypi/*")->constraints.empty());
}

TEST_CASE("vers normalise: unsorted constraints are sorted; duplicates and non-alternating bounds are refused",
          "[server][vers]") {
    const auto unsorted = make("vers:generic/>=4.0|<1.0|<3.0|>=2.0");
    REQUIRE(unsorted.constraints.size() == 4);
    CHECK(unsorted.constraints[0].version == "1.0");
    CHECK(unsorted.constraints[1].version == "2.0");
    CHECK(unsorted.constraints[2].version == "3.0");
    CHECK(unsorted.constraints[3].version == "4.0");
    CHECK(in(unsorted, "0.5"));
    CHECK_FALSE(in(unsorted, "1.5"));

    constexpr std::string_view kBad = "vers constraints are not a valid interval list";
    CHECK(refusal("vers:generic/1.0|1.0") == kBad);
    CHECK(refusal("vers:generic/1.0|1.0.0") == kBad); // equal under the comparator
    CHECK(refusal("vers:generic/>=1.0|<=1.0") == kBad);
    CHECK(refusal("vers:generic/>=1|>=2") == kBad);   // two lower bounds in a row
    CHECK(refusal("vers:generic/>1|>=2") == kBad);
    CHECK(refusal("vers:generic/<1|<=2") == kBad);   // two upper bounds in a row
    CHECK(refusal("vers:generic/<1|>=2|>=3") == kBad);
    // = and != stand outside the alternation.
    const auto with_eq = make("vers:generic/>=1|=1.5|<2");
    CHECK(in(with_eq, "1.2"));
    CHECK_FALSE(in(with_eq, "2.0"));
}

TEST_CASE("vers refusals: deb and rpm by name, any other scheme unknown, never an unbounded match",
          "[server][vers]") {
    CHECK(refusal("vers:deb/>=1.0") == "vers scheme deb is not supported yet");
    CHECK(refusal("vers:rpm/>=1.0") == "vers scheme rpm is not supported yet");
    CHECK(refusal("vers:rpm/*") == "vers scheme rpm is not supported yet"); // even for *
    CHECK(refusal("vers:nope/>=1.0") == "unknown vers scheme");
    CHECK(refusal("vers:golang/>=1.0") == "unknown vers scheme");
    // The unknown scheme is never echoed.
    CHECK(refusal("vers:nope/>=1.0").find("nope") == std::string::npos);
    for (const char* ok : {"generic", "semver", "maven", "npm", "pypi", "nuget"}) {
        CAPTURE(ok);
        CHECK(vers::parse(std::string("vers:") + ok + "/>=1"));
    }
    // Scheme names are case-sensitive, and an empty one is unknown.
    CHECK(refusal("vers:Generic/>=1") == "unknown vers scheme");
    CHECK(refusal("vers:/>=1") == "unknown vers scheme");
}

TEST_CASE("vers parse: malformed shapes are refused", "[server][vers]") {
    for (const char* bad : {"",
                            "generic/>=1",         // no vers: prefix
                            "VERS:generic/>=1",    // prefix is lower case
                            "vers:generic",        // no constraints part
                            "vers:generic/",       // empty constraint list
                            "vers:/>=1",           // empty scheme
                            "vers:Generic/>=1",    // scheme names are lower case
                            "vers:gen_eric/>=1",
                            "vers:generic/>=",     // comparator with no version
                            "vers:generic/>=1||<2",// empty constraint between bars
                            "vers:generic/>=1|",   // trailing bar
                            "vers:generic/|>=1",   // leading bar
                            "vers:generic/==1",    // a version cannot start with a comparator
                            "vers:generic/=>1",
                            "vers:generic/!1",
                            "vers:generic/*|>=1",  // * stands alone
                            "vers:generic/>=1|*",
                            "vers:generic/**"}) {
        CAPTURE(bad);
        CHECK_FALSE(vers::parse(bad));
    }
    // The error never carries caller text.
    CHECK(vers::parse("vers:generic/>=SECRET%zz").error().find("SECRET") == std::string::npos);
}

TEST_CASE("vers parse: bounds on size, constraint count, an over-long scheme and bytes",
          "[server][vers]") {
    // Input size: 1024 bytes is accepted, 1025 refused.
    const std::string head = "vers:generic/=";
    CHECK(vers::parse(head + std::string(vers::kMaxInputBytes - head.size(), '1')));
    CHECK_FALSE(vers::parse(head + std::string(vers::kMaxInputBytes - head.size() + 1, '1')));
    CHECK(vers::parse(head + std::string(vers::kMaxInputBytes - head.size() + 1, '1')).error() ==
          "vers too long");
    CHECK_FALSE(vers::parse(std::string(100000, 'x')));

    // Constraint count: 32 accepted, 33 refused.
    auto many = [](int n) {
        std::string t = "vers:generic/";
        for (int i = 0; i < n; ++i)
            t += (i ? "|=" : "=") + std::to_string(i);
        return t;
    };
    CHECK(vers::parse(many(static_cast<int>(vers::kMaxConstraints))));
    const auto over = vers::parse(many(static_cast<int>(vers::kMaxConstraints) + 1));
    REQUIRE_FALSE(over);
    CHECK(over.error() == "vers has too many constraints");

    // An over-long scheme is just an unknown one, and is never echoed.
    const std::string long_scheme = refusal("vers:" + std::string(512, 'Q') + "/>=1");
    CHECK(long_scheme == "unknown vers scheme");
    CHECK(long_scheme.find('Q') == std::string::npos);

    // Control bytes, NUL and spaces anywhere are refused, raw or after a percent escape.
    for (const std::string& bad : {std::string("vers:generic/>=1\n"), std::string("vers:generic/>=1\t"),
                                   std::string("vers:generic/>=1 .0"), std::string("vers:generic/>=1\x7f"),
                                   std::string("vers:generic/>=1\0.0", 18), std::string("vers:\x01generic/>=1"),
                                   std::string("vers:generic/>=1%00"), std::string("vers:generic/>=1%0a"),
                                   std::string("vers:generic/>=1%7f")}) {
        CAPTURE(bad);
        CHECK_FALSE(vers::parse(bad));
    }
}

TEST_CASE("vers parse: versions are percent-decoded", "[server][vers]") {
    const auto r = vers::parse("vers:generic/=1%2B2|=a%7Cb|=%41");
    REQUIRE(r);
    REQUIRE(r->constraints.size() == 3);
    CHECK(r->constraints[0].version == "1+2");
    CHECK(r->constraints[1].version == "a|b"); // an encoded bar is part of the version
    CHECK(r->constraints[2].version == "A");
    CHECK(vers::parse("vers:generic/=%2b")->constraints[0].version == "+"); // hex is case-insensitive
    for (const char* bad : {"vers:generic/=%", "vers:generic/=%2", "vers:generic/=%zz",
                            "vers:generic/=%2g", "vers:generic/=1%"}) {
        CAPTURE(bad);
        CHECK_FALSE(vers::parse(bad));
    }
}

TEST_CASE("vers from_bounds: the version_min/version_max pair is one range and min above max is empty",
          "[server][vers]") {
    const auto both = vers::from_bounds("1.9", "2.0-rc1");
    CHECK(in(both, "1.9"));
    CHECK(in(both, "1.10"));
    CHECK(in(both, "2.0-rc1"));
    CHECK_FALSE(in(both, "2.0"));
    CHECK_FALSE(in(both, "1.8"));
    CHECK(in(vers::from_bounds("2.0", ""), "99"));
    CHECK_FALSE(in(vers::from_bounds("2.0", ""), "1.9"));
    CHECK(in(vers::from_bounds("", "1.0"), "0.1"));
    CHECK_FALSE(in(vers::from_bounds("", "1.0"), "1.1"));
    // Built, not sorted: min above max matches nothing (it never became a union of two rays).
    const auto inverted = vers::from_bounds("2.0", "1.0");
    for (const char* v : {"0.5", "1.0", "1.5", "2.0", "3.0"}) {
        CAPTURE(v);
        CHECK_FALSE(in(inverted, v));
    }
    // Equal bounds are the single version.
    const auto point = vers::from_bounds("1.5", "1.5");
    CHECK(in(point, "1.5"));
    CHECK_FALSE(in(point, "1.6"));
    // The same set as the equivalent vers: text.
    const auto text = make("vers:generic/>=1.9|<=2.0-rc1");
    for (const char* v : {"1.8", "1.9", "1.10", "2.0-rc1", "2.0", "3"}) {
        CAPTURE(v);
        CHECK(in(both, v) == in(text, v));
    }
}

TEST_CASE("vers in_interval: the open/closed bound matrix under both comparators", "[server][vers]") {
    struct Row {
        const char* v;
        bool incl_incl;
        bool excl_excl;
        bool incl_excl;
        bool excl_incl;
    };
    // Interval between 2.0 and 3.0.
    const Row rows[] = {
        {"1.9", false, false, false, false}, {"2.0", true, false, true, false},
        {"2.5", true, true, true, true},     {"3.0", true, false, false, true},
        {"3.1", false, false, false, false},
    };
    auto check = [&](auto&& cmp) {
        for (const Row& r : rows) {
            CAPTURE(r.v);
            CHECK(vers::in_interval(r.v, "2.0", true, "3.0", true, cmp) == r.incl_incl);
            CHECK(vers::in_interval(r.v, "2.0", false, "3.0", false, cmp) == r.excl_excl);
            CHECK(vers::in_interval(r.v, "2.0", true, "3.0", false, cmp) == r.incl_excl);
            CHECK(vers::in_interval(r.v, "2.0", false, "3.0", true, cmp) == r.excl_incl);
        }
        // An empty bound is open on that side, whatever its inclusivity flag.
        CHECK(vers::in_interval("0.1", "", true, "3.0", true, cmp));
        CHECK(vers::in_interval("0.1", "", false, "3.0", false, cmp));
        CHECK(vers::in_interval("99", "2.0", true, "", true, cmp));
        CHECK(vers::in_interval("99", "2.0", false, "", false, cmp));
        CHECK(vers::in_interval("anything", "", true, "", true, cmp)); // no bound at all
    };
    check(kCatalogCmp);
    check(nvd_version_compare);
}

TEST_CASE("vers in_interval: the comparator is the caller's (a reversed order flips the answer)",
          "[server][vers]") {
    // in_interval applies whichever comparator it is handed. The same call under the catalogue
    // order and under its reverse must therefore give opposite answers; a build that ignored the
    // callback (or swapped its argument order) would answer both alike.
    const auto reversed = [](std::string_view a, std::string_view b) {
        return kCatalogCmp(b, a);
    };
    CHECK(vers::in_interval("1.10", "1.9", true, "2.0", false, kCatalogCmp));
    CHECK_FALSE(vers::in_interval("1.10", "1.9", true, "2.0", false, reversed));
    // Orders the catalogue and NVD comparators both give: the argument order is the caller's.
    CHECK(vers::in_interval("1.10", "1.9", true, "2.0", false, nvd_version_compare));
    CHECK_FALSE(vers::in_interval("1.8", "1.9", true, "2.0", false, kCatalogCmp));
    CHECK_FALSE(vers::in_interval("2.0", "1.9", true, "2.0", false, nvd_version_compare));
}
