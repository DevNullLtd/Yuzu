// Unit tests for guardian::preflight_rule_scopes (#5610): the fan-out resolves every rule scope
// up front and aborts on a transient failure instead of omitting the scoped rule.

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "guardian_rule_scope_preflight.hpp"

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif

using yuzu::server::ScopeEvalError;
using yuzu::server::guardian::preflight_rule_scopes;

namespace {

struct Row {
    std::string scope_expr;
};

using Members = std::expected<std::vector<std::string>, ScopeEvalError>;

} // namespace

TEST_CASE("preflight_rule_scopes: resolves each distinct scope once and answers membership",
          "[guardian][scope_preflight]") {
    const std::vector<Row> rules{{"ostype == \"linux\""}, {""}, {"ostype == \"linux\""},
                                 {"hostname == \"a\""}};
    int calls = 0;
    auto out = preflight_rule_scopes(rules, [&](const yuzu::scope::Expression&) -> Members {
        ++calls;
        return std::vector<std::string>{"agent-1", "agent-2"};
    });
    REQUIRE(out.has_value());
    CHECK(calls == 2);  // one per DISTINCT non-empty expression
    CHECK(out->distinct_scopes() == 2);
    CHECK(out->contains("ostype == \"linux\"", "agent-1"));
    CHECK_FALSE(out->contains("ostype == \"linux\"", "agent-9"));
    CHECK_FALSE(out->contains("", "agent-1"));  // an empty scope is never looked up here
    CHECK_FALSE(out->contains("never resolved", "agent-1"));
}

TEST_CASE("preflight_rule_scopes: a degraded store read aborts the whole preflight",
          "[guardian][scope_preflight][failclosed]") {
    // The first scope resolves, the second hits a degraded store: the caller must get the
    // error (and send nothing), never a map with the scoped rule quietly empty.
    const std::vector<Row> rules{{"ostype == \"linux\""}, {"tag:env == \"prod\""}};
    auto out = preflight_rule_scopes(rules, [&](const yuzu::scope::Expression& e) -> Members {
        const auto* cond = std::get_if<yuzu::scope::Condition>(&e);
        if (cond != nullptr && cond->attribute.starts_with("tag:"))
            return std::unexpected(ScopeEvalError{ScopeEvalError::Kind::StoreDegraded, "tag store down"});
        return std::vector<std::string>{"agent-1"};
    });
    REQUIRE_FALSE(out.has_value());
    CHECK(out.error().scope_expr == "tag:env == \"prod\"");
    CHECK(out.error().error.kind == ScopeEvalError::Kind::StoreDegraded);
}

TEST_CASE("preflight_rule_scopes: every non-Unresolvable error kind aborts",
          "[guardian][scope_preflight][failclosed]") {
    for (const auto kind : {ScopeEvalError::Kind::StoreDegraded,
                            ScopeEvalError::Kind::PrincipalUnresolved,
                            ScopeEvalError::Kind::OwnerCheckFailed,
                            ScopeEvalError::Kind::PresenceDegraded}) {
        const std::vector<Row> rules{{"ostype == \"linux\""}};
        auto out = preflight_rule_scopes(rules, [&](const yuzu::scope::Expression&) -> Members {
            return std::unexpected(ScopeEvalError{kind, "x"});
        });
        REQUIRE_FALSE(out.has_value());
        CHECK(out.error().error.kind == kind);
    }
}

TEST_CASE("preflight_rule_scopes: an Unresolvable or unparseable scope is out of scope for everyone",
          "[guardian][scope_preflight]") {
    // A permanent property of the expression text, not a transient failure: the rule is
    // omitted from every agent's push exactly as before, and the preflight does not abort.
    const std::vector<Row> rules{{"props.owner == \"x\""}, {"((( not a scope"}};
    auto out = preflight_rule_scopes(rules, [&](const yuzu::scope::Expression&) -> Members {
        return std::unexpected(ScopeEvalError{ScopeEvalError::Kind::Unresolvable, "no props store"});
    });
    REQUIRE(out.has_value());
    CHECK(out->distinct_scopes() == 2);
    CHECK_FALSE(out->contains("props.owner == \"x\"", "agent-1"));
    CHECK_FALSE(out->contains("((( not a scope", "agent-1"));
}

// The wiring lives inside ServerImpl, which no unit test constructs, so pin it as source text:
// the fan-out must resolve the rule scopes through the preflight BEFORE anything is built or
// sent, and must not collapse a scope read failure to an empty set again (#5610).
TEST_CASE("guardian_push_fn_ resolves rule scopes through the preflight before any send",
          "[guardian][scope_preflight][wiring]") {
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp", std::ios::binary);
    REQUIRE(in.is_open());
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const auto start = src.find("guardian_push_fn_ = [this]");
    REQUIRE(start != std::string::npos);
    const auto end = src.find("return sent;", start);
    REQUIRE(end != std::string::npos);
    const std::string body = src.substr(start, end - start);

    CHECK(body.find("value_or(std::vector<std::string>{})") == std::string::npos);
    const auto pre = body.find("guardian::preflight_rule_scopes(");
    const auto build = body.find("guardian::build_agent_push(");
    const auto send = body.find("send_system_reserved(");
    REQUIRE(pre != std::string::npos);
    REQUIRE(build != std::string::npos);
    REQUIRE(send != std::string::npos);
    CHECK(pre < build);
    CHECK(pre < send);
    // Both the target resolution and the preflight answer a degraded read with the -2 sentinel.
    CHECK(body.find("target scope read degraded") != std::string::npos);
    CHECK(body.find("rule scope read degraded") != std::string::npos);
}
