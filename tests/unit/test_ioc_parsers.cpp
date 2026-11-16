/**
 * test_ioc_parsers.cpp — pure /etc/hosts domain matching (ioc_parsers.hpp).
 */

#include "ioc_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using yuzu::ioc::hosts_contains_domain;

namespace {
bool has(const std::vector<std::string>& lines, std::string_view d) {
    return hosts_contains_domain(lines, d);
}
} // namespace

TEST_CASE("ioc hosts: an exact hostname is found", "[ioc]") {
    CHECK(has({"10.0.0.5 bad.example.test"}, "bad.example.test"));
}

TEST_CASE("ioc hosts: an alias in a later column is found", "[ioc]") {
    CHECK(has({"10.0.0.5 host.example.test alias.example.test"}, "alias.example.test"));
}

TEST_CASE("ioc hosts: the match ignores ASCII case and one trailing dot", "[ioc]") {
    CHECK(has({"10.0.0.5 Bad.Example.Test."}, "bad.example.test"));
    CHECK(has({"10.0.0.5 bad.example.test"}, "BAD.example.test."));
}

TEST_CASE("ioc hosts: a longer hostname containing the domain is not a match", "[ioc]") {
    CHECK_FALSE(has({"10.0.0.5 notbad.example.test.org"}, "bad.example.test"));
    CHECK_FALSE(has({"10.0.0.5 xbad.example.test"}, "bad.example.test"));
}

TEST_CASE("ioc hosts: a domain that is a prefix label of another hostname is not a match", "[ioc]") {
    CHECK_FALSE(has({"10.0.0.5 bad.example.test.internal"}, "bad.example.test"));
}

TEST_CASE("ioc hosts: the address column is never matched", "[ioc]") {
    CHECK_FALSE(has({"10.0.0.5 other.example.test"}, "10.0.0.5"));
}

TEST_CASE("ioc hosts: a commented-out entry and a trailing comment are ignored", "[ioc]") {
    CHECK_FALSE(has({"# 10.0.0.5 bad.example.test"}, "bad.example.test"));
    CHECK_FALSE(has({"10.0.0.5 other.example.test # bad.example.test"}, "bad.example.test"));
}

TEST_CASE("ioc hosts: tabs and repeated spaces separate columns", "[ioc]") {
    CHECK(has({"10.0.0.5\t\tother.example.test  \t bad.example.test"}, "bad.example.test"));
}

TEST_CASE("ioc hosts: an empty domain matches nothing", "[ioc]") {
    CHECK_FALSE(has({"10.0.0.5 bad.example.test", ""}, ""));
    CHECK_FALSE(has({"10.0.0.5 bad.example.test"}, "."));
}
