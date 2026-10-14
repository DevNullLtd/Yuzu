/**
 * test_scope_attribute_guard.cpp — the pure attribute allow-check behind
 * expression-targeted Send (operate-extras E-1, REVIEW G1/S4).
 *
 * The first case is the reason the guard exists: it pins, against the REAL
 * evaluator, that an unknown attribute under `!=` or NOT matches every agent.
 * If the evaluator ever changes so that case flips, the guard's premise is
 * gone and this file says so.
 */

#include "scope_attribute_guard.hpp"

#include "agent_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

std::vector<std::string> catalog_kinds() {
    std::vector<std::string> kinds;
    for (const auto& k : yuzu::server::detail::scope_kind_catalog())
        kinds.push_back(k.kind);
    return kinds;
}

std::optional<std::string> unknown_in(const std::string& text) {
    auto parsed = yuzu::scope::parse(text);
    REQUIRE(parsed.has_value());
    return first_unknown_scope_attribute(*parsed, catalog_kinds());
}

} // namespace

TEST_CASE("scope attribute guard: premise, an unknown attribute under != or NOT matches everyone",
          "[scope][attribute_guard]") {
    // The resolver answers "" for anything it does not know.
    const yuzu::scope::AttributeResolver resolver = [](std::string_view attr) -> std::string {
        return attr == "ostype" ? "windows" : "";
    };
    auto neq = yuzu::scope::parse(R"(ostyp != "windows")");
    auto neg_eq = yuzu::scope::parse(R"(NOT os == "windows")");
    auto eq = yuzu::scope::parse(R"(ostyp == "windows")");
    REQUIRE(neq.has_value());
    REQUIRE(neg_eq.has_value());
    REQUIRE(eq.has_value());
    CHECK(yuzu::scope::evaluate(*neq, resolver));     // widens
    CHECK(yuzu::scope::evaluate(*neg_eq, resolver));  // widens
    CHECK_FALSE(yuzu::scope::evaluate(*eq, resolver)); // == merely matches nothing
}

TEST_CASE("scope attribute guard: every catalogued attribute is accepted",
          "[scope][attribute_guard]") {
    CHECK_FALSE(unknown_in(R"(ostype == "windows")"));
    CHECK_FALSE(unknown_in(R"(hostname LIKE "WIN-%")"));
    CHECK_FALSE(unknown_in(R"(arch == "x86_64")"));
    CHECK_FALSE(unknown_in(R"(agent_version == "0.12.0")"));
    CHECK_FALSE(unknown_in(R"(tag:department == "finance")"));
    CHECK_FALSE(unknown_in(R"(props.owner == "jdoe")"));
    CHECK_FALSE(unknown_in(R"(EXISTS from_result_set:rs_01H8X3ZQK7YB2)"));
    CHECK_FALSE(unknown_in(R"((ostype == "linux" OR ostype == "darwin") AND NOT tag:env == "prod")"));
}

TEST_CASE("scope attribute guard: a typo or foreign name is reported, in every position",
          "[scope][attribute_guard]") {
    // The drawn design's own attribute name.
    CHECK(unknown_in(R"(os == "windows")") == "os");
    CHECK(unknown_in(R"(ostyp != "windows")") == "ostyp");
    CHECK(unknown_in(R"(NOT os == "linux")") == "os");
    CHECK(unknown_in(R"(ostype == "windows" AND (tag:a == "b" OR hostnam == "x"))") == "hostnam");
    // Case matters: the resolver compares exact names.
    CHECK(unknown_in(R"(OSTYPE == "windows")") == "OSTYPE");
}

TEST_CASE("scope attribute guard: synthetic LEN and STARTSWITH forms are decoded",
          "[scope][attribute_guard]") {
    CHECK_FALSE(unknown_in(R"(LEN(hostname) > 5)"));
    CHECK_FALSE(unknown_in(R"(STARTSWITH(hostname, "WIN-"))"));
    CHECK(unknown_in(R"(LEN(hostnam) > 5)") == "hostnam");
    CHECK(unknown_in(R"(STARTSWITH(os, "w"))") == "os");
}

TEST_CASE("scope attribute guard: a prefix kind needs a non-empty suffix",
          "[scope][attribute_guard]") {
    CHECK(scope_attribute_known("tag:env", catalog_kinds()));
    CHECK_FALSE(scope_attribute_known("tag:", catalog_kinds()));
    CHECK_FALSE(scope_attribute_known("props.", catalog_kinds()));
    CHECK_FALSE(scope_attribute_known("from_result_set:", catalog_kinds()));
    CHECK_FALSE(scope_attribute_known("tagx", catalog_kinds()));
    CHECK_FALSE(scope_attribute_known("", catalog_kinds()));
    // A made-up prefix that merely shares a leading letter.
    CHECK_FALSE(scope_attribute_known("properties.x", catalog_kinds()));
}
