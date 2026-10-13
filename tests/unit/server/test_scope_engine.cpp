/**
 * test_scope_engine.cpp — Unit tests for the scope expression engine
 *
 * Covers: parser (16), evaluator (10), performance (2).
 */

#include "scope_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <unordered_map>

using namespace yuzu::scope;

// ── Helper ─────────────────────────────────────────────────────────────────

static AttributeResolver make_resolver(const std::unordered_map<std::string, std::string>& attrs) {
    return [&attrs](std::string_view key) -> std::string {
        auto it = attrs.find(std::string(key));
        return it != attrs.end() ? it->second : std::string{};
    };
}

// ── Parser tests ───────────────────────────────────────────────────────────

TEST_CASE("ScopeEngine: parse simple equality", "[scope][parser]") {
    auto result = parse(R"(ostype == "Windows")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse inequality", "[scope][parser]") {
    auto result = parse(R"(ostype != "Linux")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse AND", "[scope][parser]") {
    auto result = parse(R"(ostype == "Windows" AND arch == "x86_64")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse OR", "[scope][parser]") {
    auto result = parse(R"(ostype == "Windows" OR ostype == "Linux")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse NOT", "[scope][parser]") {
    auto result = parse(R"(NOT ostype == "Linux")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse parenthesized", "[scope][parser]") {
    auto result = parse(R"((ostype == "Windows" OR ostype == "Linux") AND arch == "x86_64")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse LIKE", "[scope][parser]") {
    auto result = parse(R"(hostname LIKE "web-*")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse IN", "[scope][parser]") {
    auto result = parse(R"(ostype IN ("Windows", "Linux", "Darwin"))");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse CONTAINS", "[scope][parser]") {
    auto result = parse(R"(hostname CONTAINS "prod")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse comparison operators", "[scope][parser]") {
    REQUIRE(parse(R"(version > "1.0")").has_value());
    REQUIRE(parse(R"(version < "2.0")").has_value());
    REQUIRE(parse(R"(version >= "1.0")").has_value());
    REQUIRE(parse(R"(version <= "2.0")").has_value());
}

TEST_CASE("ScopeEngine: parse tag attribute", "[scope][parser]") {
    auto result = parse(R"(tag:env == "prod")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse complex nested", "[scope][parser]") {
    auto result = parse(
        R"((ostype == "Windows" AND arch == "x86_64") OR (tag:env == "staging" AND NOT tag:locked == "true"))");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse error on empty", "[scope][parser]") {
    auto result = parse("");
    REQUIRE(!result.has_value());
}

TEST_CASE("ScopeEngine: parse error on bad syntax", "[scope][parser]") {
    auto result = parse(R"(ostype ==)");
    REQUIRE(!result.has_value());
}

TEST_CASE("ScopeEngine: parse parenthesized expression", "[scope][parser]") {
    // Use string literal to avoid raw string delimiter collision with parens
    auto result = parse("(ostype == \"Windows\")");
    REQUIRE(result.has_value());

    // Extra whitespace inside parens
    auto spaced = parse("( ostype == \"Windows\" )");
    REQUIRE(spaced.has_value());
}

TEST_CASE("ScopeEngine: parse error on unmatched paren", "[scope][parser]") {
    auto unmatched = parse("(ostype == \"Windows\"");
    REQUIRE(!unmatched.has_value());
}

TEST_CASE("ScopeEngine: parse error on max depth", "[scope][parser]") {
    // Build deeply nested expression
    std::string expr;
    for (int i = 0; i < 12; ++i)
        expr += "(";
    expr += R"(ostype == "Windows")";
    for (int i = 0; i < 12; ++i)
        expr += ")";

    auto result = parse(expr);
    REQUIRE(!result.has_value());
}

// ── Evaluator tests ────────────────────────────────────────────────────────

TEST_CASE("ScopeEngine: eval equality match", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"ostype", "Windows"},
                                                          {"arch", "x86_64"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval equality mismatch", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"ostype", "Linux"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == false);
}

TEST_CASE("ScopeEngine: eval case insensitive", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"ostype", "windows"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval AND", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"ostype", "Windows"},
                                                          {"arch", "x86_64"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows" AND arch == "x86_64")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);

    auto expr2 = parse(R"(ostype == "Windows" AND arch == "aarch64")");
    REQUIRE(expr2.has_value());
    CHECK(evaluate(*expr2, resolver) == false);
}

TEST_CASE("ScopeEngine: eval OR", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"ostype", "Linux"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows" OR ostype == "Linux")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval NOT", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"ostype", "Windows"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(NOT ostype == "Linux")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval LIKE wildcard", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "web-prod-01"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname LIKE "web-*")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);

    auto expr2 = parse(R"(hostname LIKE "db-*")");
    REQUIRE(expr2.has_value());
    CHECK(evaluate(*expr2, resolver) == false);
}

TEST_CASE("ScopeEngine: eval IN", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"ostype", "Linux"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype IN ("Windows", "Linux", "Darwin"))");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);

    std::unordered_map<std::string, std::string> attrs2 = {{"ostype", "FreeBSD"}};
    auto resolver2 = make_resolver(attrs2);
    CHECK(evaluate(*expr, resolver2) == false);
}

TEST_CASE("ScopeEngine: eval CONTAINS", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "web-prod-01"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname CONTAINS "prod")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval numeric comparison", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"version", "2.5"}};
    auto resolver = make_resolver(attrs);

    auto gt = parse(R"(version > "1.0")");
    REQUIRE(gt.has_value());
    CHECK(evaluate(*gt, resolver) == true);

    auto lt = parse(R"(version < "1.0")");
    REQUIRE(lt.has_value());
    CHECK(evaluate(*lt, resolver) == false);
}

// ── Extended operator tests (Phase 3.9) ────────────────────────────────────

TEST_CASE("ScopeEngine: parse MATCHES", "[scope][parser]") {
    auto result = parse(R"(hostname MATCHES "^web-\d+$")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: eval MATCHES regex match", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "web-042"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname MATCHES "^web-\d+$")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval MATCHES regex mismatch", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "db-primary"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname MATCHES "^web-\d+$")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == false);
}

TEST_CASE("ScopeEngine: eval MATCHES invalid regex returns false", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "test"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname MATCHES "[invalid")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == false);
}

TEST_CASE("ScopeEngine: eval MATCHES over-cap pattern returns false", "[scope][eval]") {
    // Over kMaxRegexPattern the evaluator refuses to compile, even where the
    // pattern would match; at the cap it still runs.
    std::unordered_map<std::string, std::string> attrs = {{"hostname", std::string(300, 'a')}};
    auto resolver = make_resolver(attrs);

    auto at_cap = parse("hostname MATCHES \"" + std::string(kMaxRegexPattern, 'a') + "\"");
    REQUIRE(at_cap.has_value());
    CHECK(evaluate(*at_cap, resolver) == true);
    auto over_cap = parse("hostname MATCHES \"" + std::string(kMaxRegexPattern + 1, 'a') + "\"");
    REQUIRE(over_cap.has_value());
    CHECK(evaluate(*over_cap, resolver) == false);
}

TEST_CASE("ScopeEngine: validate_regex mirrors what evaluate can run", "[scope][eval]") {
    CHECK(validate_regex("^web-\\d+$").has_value());
    CHECK(validate_regex(std::string(kMaxRegexPattern, 'a')).has_value());
    CHECK_FALSE(validate_regex(std::string(kMaxRegexPattern + 1, 'a')).has_value());
    CHECK_FALSE(validate_regex("[invalid").has_value());
}

TEST_CASE("ScopeEngine: eval MATCHES case insensitive", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "WEB-PROD-01"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname MATCHES "web-prod-\\d+")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: parse EXISTS", "[scope][parser]") {
    auto result = parse(R"(EXISTS tag:env)");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: eval EXISTS present", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"tag:env", "prod"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(EXISTS tag:env)");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval EXISTS absent", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"tag:team", "infra"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(EXISTS tag:env)");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == false);
}

TEST_CASE("ScopeEngine: eval EXISTS empty string is absent", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"tag:env", ""}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(EXISTS tag:env)");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == false);
}

TEST_CASE("ScopeEngine: parse LEN()", "[scope][parser]") {
    auto result = parse(R"(LEN(hostname) > 5)");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: eval LEN() greater than", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "web-prod-01"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(LEN(hostname) > 5)");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval LEN() equal", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "abc"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(LEN(hostname) == 3)");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);

    auto expr2 = parse(R"(LEN(hostname) == 5)");
    REQUIRE(expr2.has_value());
    CHECK(evaluate(*expr2, resolver) == false);
}

TEST_CASE("ScopeEngine: eval LEN() on missing attribute", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(LEN(hostname) == 0)");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: parse STARTSWITH()", "[scope][parser]") {
    auto result = parse(R"(STARTSWITH(hostname, "web-"))");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: eval STARTSWITH() match", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "web-prod-01"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(STARTSWITH(hostname, "web-"))");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval STARTSWITH() mismatch", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "db-primary"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(STARTSWITH(hostname, "web-"))");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == false);
}

TEST_CASE("ScopeEngine: eval STARTSWITH() case insensitive", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "WEB-PROD-01"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(STARTSWITH(hostname, "web-"))");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: combined extended operators", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"hostname", "web-prod-01"}, {"tag:env", "production"}, {"ostype", "Linux"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(EXISTS tag:env AND hostname MATCHES "^web-" AND LEN(tag:env) > 3)");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: STARTSWITH and MATCHES in OR", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {{"hostname", "db-replica-03"}};
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(STARTSWITH(hostname, "web-") OR hostname MATCHES "^db-replica-\d+$")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: parse error on LEN missing paren", "[scope][parser]") {
    auto result = parse(R"(LEN hostname > 5)");
    REQUIRE(!result.has_value());
}

TEST_CASE("ScopeEngine: parse error on STARTSWITH missing comma", "[scope][parser]") {
    auto result = parse(R"(STARTSWITH(hostname "web-"))");
    REQUIRE(!result.has_value());
}

// ── Performance tests ──────────────────────────────────────────────────────

TEST_CASE("ScopeEngine: parse performance", "[scope][perf]") {
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 10000; ++i) {
        auto result = parse(R"((ostype == "Windows" AND arch == "x86_64") OR tag:env == "prod")");
        REQUIRE(result.has_value());
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    REQUIRE(ms < 5000); // 10k parses should take less than 5s
}

TEST_CASE("ScopeEngine: eval performance", "[scope][perf]") {
    auto expr = parse(
        R"((ostype == "Windows" AND arch == "x86_64") OR (tag:env == "prod" AND NOT tag:locked == "true"))");
    REQUIRE(expr.has_value());

    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Windows"}, {"arch", "x86_64"}, {"tag:env", "prod"}, {"tag:locked", "false"}};
    auto resolver = make_resolver(attrs);

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 100000; ++i) {
        evaluate(*expr, resolver);
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    REQUIRE(ms < 5000); // 100k evals should take less than 5s
}

// ── from_result_set: (scope walking, capability §30) ─────────────────────────

TEST_CASE("ScopeEngine: parse from_result_set bare atom", "[scope][parser][result_set]") {
    auto result = parse("from_result_set:rs_01hxyzdeadbeef");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: from_result_set composes with attribute predicate",
          "[scope][parser][result_set]") {
    auto result = parse(R"(from_result_set:rs_01hxyz AND ostype == "Windows")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: from_result_set evaluates membership via resolver",
          "[scope][eval][result_set]") {
    auto expr = parse(R"(from_result_set:rs_abc AND ostype == "Windows")");
    REQUIRE(expr.has_value());

    // make_resolver captures its argument by reference, so the attr maps must
    // outlive the evaluate() calls — keep them as named locals (not temporaries).
    std::unordered_map<std::string, std::string> member_win_attrs = {
        {"from_result_set:rs_abc", "true"}, {"ostype", "Windows"}};
    std::unordered_map<std::string, std::string> member_lin_attrs = {
        {"from_result_set:rs_abc", "true"}, {"ostype", "Linux"}};
    std::unordered_map<std::string, std::string> non_member_attrs = {{"ostype", "Windows"}};

    // Member + Windows → match.
    auto member_win = make_resolver(member_win_attrs);
    CHECK(evaluate(*expr, member_win));

    // Member + Linux → no match (predicate refines the set).
    auto member_lin = make_resolver(member_lin_attrs);
    CHECK_FALSE(evaluate(*expr, member_lin));

    // Non-member (resolver returns empty → EXISTS false) → no match.
    auto non_member = make_resolver(non_member_attrs);
    CHECK_FALSE(evaluate(*expr, non_member));
}
