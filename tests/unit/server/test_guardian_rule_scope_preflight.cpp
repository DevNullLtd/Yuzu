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

struct EnabledRow {
    std::string scope_expr;
    bool enabled;
};

using Members = std::expected<std::vector<std::string>, ScopeEvalError>;

// `src` with every // and /* */ comment replaced by a space. String and character literals are
// copied through untouched (a "//" inside one is not a comment), so a phrase that survives only
// in a comment cannot satisfy a presence check below.
std::string strip_comments(const std::string& src) {
    std::string out;
    out.reserve(src.size());
    for (std::size_t i = 0; i < src.size();) {
        const char c = src[i];
        if (c == '"' || c == '\'') {
            out += c;
            ++i;
            while (i < src.size() && src[i] != c) {
                if (src[i] == '\\' && i + 1 < src.size())
                    out += src[i++];
                out += src[i++];
            }
            if (i < src.size())
                out += src[i++];
        } else if (c == '/' && i + 1 < src.size() && src[i + 1] == '/') {
            while (i < src.size() && src[i] != '\n')
                ++i;
            out += ' ';
        } else if (c == '/' && i + 1 < src.size() && src[i + 1] == '*') {
            const auto close = src.find("*/", i + 2);
            i = close == std::string::npos ? src.size() : close + 2;
            out += ' ';
        } else {
            out += c;
            ++i;
        }
    }
    return out;
}

// True when the first `return` after `literal` in `body` is `return -2;` and no block closes
// between the two: the degrade warning and the -2 sentinel sit in the same block.
bool degrade_warning_returns_minus_two(const std::string& body, const std::string& literal) {
    const auto at = body.find(literal);
    if (at == std::string::npos)
        return false;
    const auto ret = body.find("return", at);
    if (ret == std::string::npos)
        return false;
    // A `}` closes a block unless it is the end of a `{}` format placeholder.
    for (std::size_t k = at; k < ret; ++k)
        if (body[k] == '}' && (k == 0 || body[k - 1] != '{'))
            return false;
    std::size_t i = ret + std::string("return").size();
    while (i < body.size() && (body[i] == ' ' || body[i] == '\t'))
        ++i;
    return body.compare(i, 3, "-2;") == 0;
}

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

TEST_CASE("preflight_rule_scopes: a disabled rule's scope is neither read nor able to abort",
          "[guardian][scope_preflight]") {
    // A disabled rule is never pushed, so a degraded read of its scope must not abort the push.
    const std::vector<EnabledRow> rules{{"ostype == \"linux\"", true},
                                        {"tag:env == \"prod\"", false}};
    int calls = 0;
    auto out = preflight_rule_scopes(rules, [&](const yuzu::scope::Expression& e) -> Members {
        ++calls;
        const auto* cond = std::get_if<yuzu::scope::Condition>(&e);
        if (cond != nullptr && cond->attribute.starts_with("tag:"))
            return std::unexpected(ScopeEvalError{ScopeEvalError::Kind::StoreDegraded, "tag store down"});
        return std::vector<std::string>{"agent-1"};
    });
    REQUIRE(out.has_value());
    CHECK(calls == 1);
    CHECK(out->distinct_scopes() == 1);
    CHECK_FALSE(out->resolved("tag:env == \"prod\""));
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
    const std::string body = strip_comments(src.substr(start, end - start));

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
    // A group: scope's membership is read through the checked accessor, whose failure is
    // distinguishable from an empty group; the unchecked one would narrow the cohort silently.
    CHECK(body.find("get_members_checked(") != std::string::npos);
    CHECK(body.find("->get_members(") == std::string::npos);
    CHECK(body.find("group member read degraded") != std::string::npos);
    // Every degrade warning is followed, in the same block, by `return -2;`: a warning that
    // fell through to the send would narrow the fan-out instead of aborting it.
    for (const char* literal :
         {"policy-generation read degraded", "list_rules degraded",
          "deployed_member_rule_ids degraded", "group member read degraded",
          "target scope read degraded", "rule scope read degraded"}) {
        INFO(literal);
        CHECK(degrade_warning_returns_minus_two(body, literal));
    }
}

TEST_CASE("strip_comments keeps literals and drops comments (the wiring pin's own tooling)",
          "[guardian][scope_preflight][wiring]") {
    CHECK(strip_comments("a // return -2;\nb") == "a  \nb");
    CHECK(strip_comments("a /* get_members_checked( */ b") == "a   b");
    CHECK(strip_comments("\"x // y\" z") == "\"x // y\" z");
    CHECK(degrade_warning_returns_minus_two("warn(\"w\"); return -2;", "w"));
    CHECK_FALSE(degrade_warning_returns_minus_two("warn(\"w\"); } return -2;", "w"));
    CHECK(degrade_warning_returns_minus_two("warn(\"w ({})\", x); return -2;", "w"));
    CHECK_FALSE(degrade_warning_returns_minus_two("warn(\"w\"); return sent;", "w"));
    CHECK_FALSE(degrade_warning_returns_minus_two("warn(\"w\");", "w"));
}
