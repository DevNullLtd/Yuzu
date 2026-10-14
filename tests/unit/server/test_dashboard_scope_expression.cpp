/**
 * test_dashboard_scope_expression.cpp — operate-extras E-1: the optional
 * `scope_expression` field on `POST /api/dashboard/execute`.
 *
 * WHAT IS BOUND HERE (each case fails if the matching guard is deleted):
 *   rule 1  an absent field leaves the route byte-for-byte as it was,
 *   rule 2  `scope` AND `scope_expression` together is a 400, never a silent
 *           pick (the Console's hidden `scope=__all__` is why the UI must omit
 *           it — see the JS pin in test_operate_extras_ui.cpp),
 *   rule 3  a SUPPLIED but empty expression is refused, never widened to the
 *           fleet,
 *   rule 4  an over-long expression is refused (kExecInstrScopeMaxLen),
 *   rule 5  a valid expression reaches the dispatch seam as `scope_expr`, and
 *           the Destructive targeting gate still refuses it (a scope is not a
 *           named agent),
 *   rule 7  an attribute outside scope_kind_catalog() is a 400 and NOTHING is
 *           dispatched. The typo-under-`!=` case is the mutation test: delete
 *           the attribute check and `ostyp != "windows"` reaches every agent.
 *
 * `TestRouteSink` trap (CLAUDE.md → Test conventions): every POST goes through
 * `post()`, which sets application/x-www-form-urlencoded so `req.params` is
 * populated and the production (decoded-param) branch is the one driven.
 */

#include "dashboard_routes.hpp"
#include "test_route_sink.hpp"

#include "dispatch_destructive_gate.hpp"
#include "dispatch_target_shape.hpp"
#include "mcp_input_bounds.hpp"
#include "test_real_capability_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kPath = "/api/dashboard/execute";
constexpr std::pair<const char*, const char*> kReadOnly{"os_info", "os_version"};
constexpr std::pair<const char*, const char*> kDestructive{"tar", "purge_source"};

struct DispatchCall {
    std::string plugin, action, scope_expr;
    std::vector<std::string> agent_ids;
};
struct AuditRow {
    std::string action, result, detail;
};

// Member order is load-bearing: `sink` last so it is destroyed first.
struct Harness {
    yuzu::MetricsRegistry metrics;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    std::pair<std::string, std::string> resolve_to{kReadOnly.first, kReadOnly.second};

    Harness() {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "expr-op";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string&, const std::string&, const std::string& d) {
            audits.push_back({a, r, d});
        };
        DashboardRoutes::DispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string& scope,
                   const std::unordered_map<std::string, std::string>&,
                   const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
            calls.push_back({plugin, action, scope, ids});
            return {.sent = 3, .command_id = "cmd-" + std::to_string(calls.size())};
        };
        routes.register_routes(
            sink, auth_fn, perm_fn, audit_fn, /*response_store=*/nullptr, /*mg=*/nullptr,
            /*registry=*/nullptr, /*tag_store=*/nullptr, /*event_bus=*/nullptr,
            [] { return std::string{"[]"}; }, dispatch,
            [](const httplib::Request&) -> yuzu::server::DispatchCaller {
                return yuzu::server::DispatchCaller{.principal = "expr-op",
                                                    .exec_visible = std::nullopt};
            },
            [this](const std::string&) { return resolve_to; }, &metrics,
            /*instruction_store=*/nullptr);
        routes.set_capability_classify_fn(yuzu::test::real_classify_fn());
    }

    std::unique_ptr<httplib::Response> post(const std::string& body) {
        std::unordered_map<std::string, std::string> headers{
            {"Host", "yuzu.example:8080"}, {"Origin", "https://yuzu.example:8080"}};
        auto res = sink.dispatch("POST", kPath, body, "application/x-www-form-urlencoded", headers);
        REQUIRE(res != nullptr);
        return res;
    }

    int denied_with(const std::string& needle) const {
        int n = 0;
        for (const auto& a : audits)
            if (a.result == "denied" && a.detail.find(needle) != std::string::npos)
                ++n;
        return n;
    }
};

// application/x-www-form-urlencoded encoding for the characters an expression uses.
std::string enc(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            c == '_' || c == '-' || c == '.' || c == ':')
            out += static_cast<char>(c);
        else {
            static const char* hex = "0123456789ABCDEF";
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("scope_expression rule 1: an absent field leaves the route unchanged",
          "[server][dashboard][execute][scope_expression]") {
    SECTION("explicit __all__ still broadcasts by name") {
        Harness h;
        auto res = h.post("instruction=version&scope=__all__");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].scope_expr == "__all__");
        CHECK(res->status == 200);
    }
    SECTION("a single agent still dispatches by id") {
        Harness h;
        h.post("instruction=version&scope=agent-1");
        REQUIRE(h.calls.size() == 1);
        CHECK(h.calls[0].scope_expr.empty());
        REQUIRE(h.calls[0].agent_ids.size() == 1);
        CHECK(h.calls[0].agent_ids[0] == "agent-1");
    }
}

TEST_CASE("scope_expression rule 5: a valid expression reaches dispatch as scope_expr",
          "[server][dashboard][execute][scope_expression]") {
    Harness h;
    const std::string expr = R"(ostype == "windows" AND tag:role == "web")";
    auto res = h.post("instruction=version&scope_expression=" + enc(expr));

    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].scope_expr == expr);
    CHECK(h.calls[0].agent_ids.empty());
    // The audit row says the target was an expression.
    bool saw = false;
    for (const auto& a : h.audits)
        if (a.action == "command.dispatch" && a.result == "success" &&
            contains(a.detail, "scope_expression="))
            saw = true;
    CHECK(saw);
}

TEST_CASE("scope_expression rule 5: a percent-encoded field NAME is still recognised",
          "[server][dashboard][execute][scope_expression][security]") {
    Harness h;
    // `scope%5Fexpression` decodes to `scope_expression` in req.params; a
    // raw-byte scan alone would miss it and fall through to the fleet.
    auto res = h.post("instruction=version&scope%5Fexpression=" + enc(R"(ostype == "linux")"));
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].scope_expr == R"(ostype == "linux")");
    CHECK(res->status == 200);
}

TEST_CASE("scope_expression rule 2: scope together with scope_expression is a 400",
          "[server][dashboard][execute][scope_expression][security]") {
    Harness h;
    const auto expr = enc(R"(ostype == "windows")");

    SECTION("the Console's hidden scope=__all__") {
        auto res = h.post("instruction=version&scope=__all__&scope_expression=" + expr);
        CHECK(res->status == 400);
        CHECK(contains(res->body, "target_conflict"));
    }
    SECTION("a supplied but empty scope still conflicts") {
        auto res = h.post("instruction=version&scope=&scope_expression=" + expr);
        CHECK(res->status == 400);
        CHECK(contains(res->body, "target_conflict"));
    }
    SECTION("a single agent id conflicts too") {
        auto res = h.post("instruction=version&scope=agent-1&scope_expression=" + expr);
        CHECK(res->status == 400);
    }
    CHECK(h.calls.empty()); // never picked one silently
    CHECK(h.denied_with("target_conflict") == 1);
}

TEST_CASE("scope_expression rule 3: a supplied but empty expression is refused, never the fleet",
          "[server][dashboard][execute][scope_expression][security]") {
    Harness h;
    auto res = h.post("instruction=version&scope_expression=");
    CHECK(res->status == 400);
    CHECK(contains(res->body, "scope_expression_empty"));
    CHECK(h.calls.empty());
}

TEST_CASE("scope_expression rule 4: an over-long expression is refused",
          "[server][dashboard][execute][scope_expression]") {
    // httplib caps a urlencoded body at 8192 bytes before the handler runs, so the route's own
    // bound is reached only through a body httplib does not parse into params (the raw-body
    // fallback). Drive that path: text/plain carrying the form text.
    Harness h;
    std::string expr = "ostype == \"" + std::string(mcp::kExecInstrScopeMaxLen, 'a') + "\"";
    std::unordered_map<std::string, std::string> headers{
        {"Host", "yuzu.example:8080"}, {"Origin", "https://yuzu.example:8080"}};
    auto res = h.sink.dispatch("POST", kPath, "instruction=version&scope_expression=" + expr,
                               "text/plain", headers);
    REQUIRE(res != nullptr);
    CHECK(res->status == 400);
    CHECK(contains(res->body, "scope_expression_too_long"));
    CHECK(h.calls.empty());
}

TEST_CASE("scope_expression: a malformed expression is refused before dispatch",
          "[server][dashboard][execute][scope_expression]") {
    Harness h;
    for (const char* bad : {"ostype ==", "tag:finance", "__all__", "group:eng", "(ostype == \"a\""}) {
        INFO("expression: " << bad);
        auto res = h.post("instruction=version&scope_expression=" + enc(bad));
        CHECK(res->status == 400);
        CHECK(contains(res->body, "scope_expression_invalid"));
    }
    CHECK(h.calls.empty());
}

TEST_CASE("scope_expression rule 7 (mutation test): a typo attribute under != or NOT is refused "
          "and never dispatched",
          "[server][dashboard][execute][scope_expression][security]") {
    // These three MATCH EVERY AGENT if they reach the resolver (REVIEW G1):
    // an unknown attribute resolves to "", and `!=` / NOT invert "matches
    // nothing" into "matches everyone". Delete the attribute check and this
    // case dispatches fleet-wide.
    Harness h;
    for (const char* bad : {R"(ostyp != "windows")", R"(NOT os == "windows")",
                            R"(os != "linux")"}) {
        INFO("expression: " << bad);
        auto res = h.post("instruction=version&scope_expression=" + enc(bad));
        CHECK(res->status == 400);
        CHECK(contains(res->body, "scope_unknown_attribute"));
    }
    CHECK(h.calls.empty());
    CHECK(h.denied_with("scope_unknown_attribute") == 3);
}

TEST_CASE("scope_expression rule 7: every catalogued attribute is accepted",
          "[server][dashboard][execute][scope_expression]") {
    Harness h;
    int n = 0;
    for (const char* ok : {R"(ostype != "windows")", R"(hostname LIKE "WIN-%")", R"(arch == "arm64")",
                           R"(agent_version >= "0.12.0")", R"(tag:env != "prod")",
                           R"(props.owner == "jdoe")", R"(EXISTS from_result_set:rs_abc)",
                           R"(NOT ostype == "darwin")"}) {
        INFO("expression: " << ok);
        auto res = h.post("instruction=version&scope_expression=" + enc(ok));
        CHECK(res->status == 200);
        ++n;
    }
    CHECK(h.calls.size() == static_cast<std::size_t>(n));
}

TEST_CASE("scope_expression rule 5: the Destructive targeting gate still refuses an expression",
          "[server][dashboard][execute][scope_expression][destructive][security]") {
    Harness h;
    h.resolve_to = {kDestructive.first, kDestructive.second};
    auto res = h.post("instruction=purge&scope_expression=" + enc(R"(ostype == "windows")"));
    CHECK(h.calls.empty());
    CHECK(contains(res->body, std::string(yuzu::server::kDestructiveUntargetedMessage)));
}
