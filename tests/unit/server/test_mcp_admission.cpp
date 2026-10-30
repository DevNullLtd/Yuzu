/**
 * test_mcp_admission.cpp - /mcp/v1/ credential-class admission (#4309).
 *
 * /mcp/v1/ refuses every credential whose Session::mcp_tier is empty. The unit
 * under test is mcp_admission.hpp: the predicate (requires_tiered_credential), the
 * decision (admit), which performs the refusal (audit row + counter + A4 response)
 * and returns whether the request is admitted, and the factory production uses
 * (make_admission_auth_fn). The last cases register the REAL McpServer routes with a
 * factory-built auth hook over a stub session resolver and drive POST, GET and
 * DELETE. That the production server.cpp builds its hook with the factory is pinned
 * by a source check in test_mcp_route_registration.cpp; the live stack by
 * scripts/e2e-mcp-test.sh.
 */

#include "mcp_admission.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using yuzu::server::mcp::admit;
using yuzu::server::mcp::bounded_auth_source;
using yuzu::server::mcp::requires_tiered_credential;
using yuzu::server::mcp::write_tier_required;

namespace {

yuzu::server::auth::Session make_session(const std::string& auth_source, const std::string& tier,
                                          const std::string& principal_kind = "human") {
    yuzu::server::auth::Session s;
    s.username = "alice";
    s.auth_source = auth_source;
    s.mcp_tier = tier;
    s.principal_kind = principal_kind;
    return s;
}

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct Harness {
    httplib::Request req;
    httplib::Response res;
    yuzu::MetricsRegistry metrics;
    std::vector<AuditCall> audits;
    bool audit_ok{true};

    bool run(const yuzu::server::auth::Session& s) {
        auto audit = [this](const httplib::Request&, const std::string& action,
                            const std::string& result, const std::string& target_type,
                            const std::string& target_id, const std::string& detail) -> bool {
            audits.push_back({action, result, target_type, target_id, detail});
            return audit_ok;
        };
        return admit(s, req, res, audit, &metrics);
    }
};

constexpr const char* kCounterLine = "yuzu_mcp_admission_refused_total{reason=\"tier_required\"}";

} // namespace

TEST_CASE("mcp admission: predicate matrix", "[mcp][a5][authz][4309]") {
    SECTION("tierless credentials are refused") {
        CHECK(requires_tiered_credential(make_session("local", "")));
        CHECK(requires_tiered_credential(make_session("oidc", "")));
        CHECK(requires_tiered_credential(make_session("saml", "")));
        CHECK(requires_tiered_credential(make_session("api_token", "")));
        // Unreachable-state control: engine tokens are store-locked to readonly at mint, so a
        // tierless engine row is corrupt; refusing it is fail-closed.
        CHECK(requires_tiered_credential(make_session("engine_token", "", "engine")));
        // The principal kind does not exempt a tierless session either.
        CHECK(requires_tiered_credential(make_session("local", "", "engine")));
    }
    SECTION("tiered credentials are admitted") {
        for (const char* tier : {"readonly", "operator", "supervised"}) {
            CAPTURE(tier);
            CHECK_FALSE(requires_tiered_credential(make_session("mcp_token", tier)));
        }
        CHECK_FALSE(requires_tiered_credential(make_session("api_token", "operator")));
        CHECK_FALSE(requires_tiered_credential(make_session("engine_token", "readonly", "engine")));
    }
}

TEST_CASE("mcp admission: auth_source is bounded to the closed set", "[mcp][a5][authz][4309]") {
    for (const char* known : {"local", "oidc", "saml", "api_token", "mcp_token", "engine_token"}) {
        CAPTURE(known);
        CHECK(bounded_auth_source(known) == known);
    }
    CHECK(bounded_auth_source("") == "other");
    CHECK(bounded_auth_source("ldap") == "other");
    CHECK(bounded_auth_source("local\nforged=1") == "other");
    CHECK(bounded_auth_source("LOCAL") == "other");
}

TEST_CASE("mcp admission: a tierless session is refused with the exact envelope, audit row and "
          "counter",
          "[mcp][a5][authz][4309]") {
    Harness h;
    REQUIRE_FALSE(h.run(make_session("local", "")));

    // Response
    CHECK(h.res.status == 403);
    CHECK(h.res.get_header_value("Content-Type").find("application/json") != std::string::npos);
    const auto body = nlohmann::json::parse(h.res.body);
    CHECK(body.at("jsonrpc") == "2.0");
    CHECK(body.at("id").is_null());
    const auto& err = body.at("error");
    CHECK(err.at("code") == -32003);
    CHECK(err.at("code") == yuzu::server::mcp::kPermissionDenied);
    CHECK(err.at("message") == "/mcp/v1/ requires an MCP-tier bearer token");
    const auto& data = err.at("data");
    REQUIRE(data.contains("correlation_id"));
    REQUIRE(data.at("correlation_id").is_string());
    const std::string cid = data.at("correlation_id").get<std::string>();
    CHECK_FALSE(cid.empty());
    CHECK(data.at("retry_after_ms").is_null());
    CHECK(data.at("remediation") ==
          "mint an API token with mcp_tier readonly, operator or supervised (POST /api/v1/tokens "
          "with expires_at, or Settings > API tokens) and send it as Authorization: Bearer; do "
          "not send a session cookie with it");
    // Service-scope clause 5: no .permission field that would claim a false self-remediation.
    CHECK_FALSE(data.contains("permission"));
    CHECK_FALSE(err.contains("permission"));
    CHECK_FALSE(body.contains("permission"));

    // Audit: exactly one row, exact fields, cid equal to the one on the wire.
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "mcp.session.reject");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].target_type == "McpSession");
    CHECK(h.audits[0].target_id.empty());
    CHECK(h.audits[0].detail == "reason=tier_required auth_source=local cid=" + cid);

    // Counter: exactly once, exact label.
    const auto text = h.metrics.serialize();
    CHECK(text.find(std::string{kCounterLine} + " 1\n") != std::string::npos);
    CHECK(text.find("yuzu_mcp_admission_refused_total{reason=") ==
          text.rfind("yuzu_mcp_admission_refused_total{reason="));
}

TEST_CASE("mcp admission: every tierless principal class is refused and audited with its "
          "bounded auth_source",
          "[mcp][a5][authz][4309]") {
    struct Row {
        const char* source;
        const char* kind;
        const char* expect;
    };
    for (const auto& row : {Row{"local", "human", "local"}, Row{"oidc", "human", "oidc"},
                            Row{"saml", "human", "saml"}, Row{"api_token", "human", "api_token"},
                            Row{"engine_token", "engine", "engine_token"},
                            Row{"mystery", "human", "other"}}) {
        CAPTURE(row.source);
        Harness h;
        CHECK_FALSE(h.run(make_session(row.source, "", row.kind)));
        CHECK(h.res.status == 403);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].detail.rfind(std::string{"reason=tier_required auth_source="} + row.expect +
                                           " cid=",
                                       0) == 0);
    }
}

TEST_CASE("mcp admission: an admitted session writes nothing", "[mcp][a5][authz][4309]") {
    for (const auto& s : {make_session("mcp_token", "readonly"), make_session("mcp_token", "operator"),
                          make_session("mcp_token", "supervised"),
                          make_session("api_token", "operator"),
                          make_session("engine_token", "readonly", "engine")}) {
        CAPTURE(s.auth_source, s.mcp_tier);
        Harness h;
        h.res.status = 200; // sentinel: admit must not touch the response
        h.res.set_content("untouched", "text/plain");
        const auto before = h.metrics.serialize();
        CHECK(h.run(s));
        CHECK(h.audits.empty());
        CHECK(h.metrics.serialize() == before);
        CHECK(h.res.status == 200);
        CHECK(h.res.body == "untouched");
        CHECK(h.res.get_header_value("Content-Type") == "text/plain");
    }
}

TEST_CASE("mcp admission: a failed audit write does not change the refusal (set-and-proceed)",
          "[mcp][a5][authz][4309]") {
    SECTION("audit callback returns false") {
        Harness h;
        h.audit_ok = false;
        CHECK_FALSE(h.run(make_session("oidc", "")));
        CHECK(h.res.status == 403);
        CHECK(h.audits.size() == 1);
        CHECK(h.metrics.serialize().find(std::string{kCounterLine} + " 1\n") != std::string::npos);
    }
    SECTION("audit callback throws") {
        httplib::Request req;
        httplib::Response res;
        yuzu::MetricsRegistry metrics;
        auto throwing = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("audit store down");
        };
        CHECK_FALSE(admit(make_session("saml", ""), req, res, throwing, &metrics));
        CHECK(res.status == 403);
        CHECK(metrics.serialize().find(std::string{kCounterLine} + " 1\n") != std::string::npos);
    }
    SECTION("no audit hook wired") {
        httplib::Request req;
        httplib::Response res;
        yuzu::MetricsRegistry metrics;
        const std::function<bool(const httplib::Request&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&)>
            none;
        CHECK_FALSE(admit(make_session("local", ""), req, res, none, &metrics));
        CHECK(res.status == 403);
    }
}

TEST_CASE("mcp admission: a null metrics registry does not change the refusal",
          "[mcp][a5][authz][4309]") {
    Harness h;
    auto audit = [&h](const httplib::Request&, const std::string& a, const std::string& r,
                      const std::string& tt, const std::string& ti, const std::string& d) -> bool {
        h.audits.push_back({a, r, tt, ti, d});
        return true;
    };
    CHECK_FALSE(admit(make_session("local", ""), h.req, h.res, audit, nullptr));
    CHECK(h.res.status == 403);
    CHECK(h.audits.size() == 1);
}

TEST_CASE("mcp admission: repeated refusals each count once and carry distinct correlation ids",
          "[mcp][a5][authz][4309]") {
    Harness h;
    h.run(make_session("local", ""));
    const auto cid1 = nlohmann::json::parse(h.res.body)["error"]["data"]["correlation_id"];
    h.run(make_session("local", ""));
    const auto cid2 = nlohmann::json::parse(h.res.body)["error"]["data"]["correlation_id"];
    CHECK(cid1 != cid2);
    CHECK(h.audits.size() == 2);
    CHECK(h.metrics.serialize().find(std::string{kCounterLine} + " 2\n") != std::string::npos);
}

TEST_CASE("mcp admission: write_tier_required alone writes the 403 envelope",
          "[mcp][a5][authz][4309]") {
    httplib::Response res;
    write_tier_required(res, "cid-fixed");
    CHECK(res.status == 403);
    const auto body = nlohmann::json::parse(res.body);
    CHECK(body["error"]["data"]["correlation_id"] == "cid-fixed");
    CHECK(body["error"]["code"] == -32003);
}

TEST_CASE("mcp admission: an unknown non-empty tier is admitted (tier_allows decides downstream)",
          "[mcp][a5][authz][4309]") {
    Harness h;
    CHECK_FALSE(requires_tiered_credential(make_session("mcp_token", "bogus")));
    CHECK(h.run(make_session("mcp_token", "bogus")));
    CHECK(h.audits.empty());
    CHECK(h.metrics.serialize().find(kCounterLine) == std::string::npos);
}

TEST_CASE("mcp admission: a hostile auth_source never reaches the audit detail",
          "[mcp][a5][authz][4309]") {
    Harness h;
    const std::string hostile = std::string(70000, 'A') + "\nreason=forged cid=evil";
    CHECK_FALSE(h.run(make_session(hostile, "")));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].detail.rfind("reason=tier_required auth_source=other cid=", 0) == 0);
    CHECK(h.audits[0].detail.find('\n') == std::string::npos);
    CHECK(h.audits[0].detail.size() < 200);
    CHECK(bounded_auth_source(hostile) == "other");
}

// ═══════════════════════════════════════════════════════════════════════════
// Behavioural: the REAL McpServer routes behind the production factory.
//
// The cases above prove admit() in isolation, which says nothing about whether
// the gate is applied to every verb and ahead of every tool. These register the
// real handlers (streaming ON, so GET and DELETE are live) with an auth hook
// built by make_admission_auth_fn over a stub resolver, then drive each verb.
// McpTestServer deliberately does NOT build its hook this way.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

struct RoutesHarness {
    yuzu::MetricsRegistry metrics;
    yuzu::server::mcp::McpSessionRegistry sessions{{.per_principal_cap = 8, .global_cap = 32}};
    yuzu::server::mcp::McpServer mcp;
    bool mcp_disabled{false};
    bool read_only{false};
    bool streaming_disabled{false};

    /// What the stub resolver returns; nullopt makes it behave as an unauthenticated caller.
    std::optional<yuzu::server::auth::Session> resolved;
    int resolver_calls{0};
    /// perm_fn invocations: a tool handler reaches it (list_agents asks Infrastructure:Read)
    /// only after admission, so 0 here proves no tool ran for a refused caller.
    int tool_gate_calls{0};
    /// Audit rows plus the value of the X-Test-Req header on the request the hook was handed,
    /// so a test can prove the SAME request object reached the audit hook.
    struct Row {
        AuditCall call;
        std::string marker;
    };
    std::vector<Row> audits;

    yuzu::server::test::TestRouteSink sink; // LAST: handlers capture this struct's members

    void wire() {
        yuzu::server::mcp::AdmissionAuthFn resolver =
            [this](const httplib::Request&, httplib::Response& res)
            -> std::optional<yuzu::server::auth::Session> {
            ++resolver_calls;
            if (!resolved) {
                res.status = 401;
                res.set_content(R"({"error":"unauthorized"})", "application/json");
                return std::nullopt;
            }
            return resolved;
        };
        yuzu::server::mcp::AdmissionAuditFn audit =
            [this](const httplib::Request& req, const std::string& action, const std::string& result,
                   const std::string& target_type, const std::string& target_id,
                   const std::string& detail) -> bool {
            audits.push_back({{action, result, target_type, target_id, detail},
                              req.get_header_value("X-Test-Req")});
            return true;
        };
        yuzu::server::mcp::McpServer::AuthFn auth_fn =
            yuzu::server::mcp::make_admission_auth_fn(resolver, audit, &metrics);
        yuzu::server::mcp::McpServer::PermFn perm_fn =
            [this](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) -> bool {
            ++tool_gate_calls;
            return true;
        };
        yuzu::server::mcp::McpServer::AgentsJsonFn agents_fn = []() -> nlohmann::json {
            return nlohmann::json::array();
        };
        mcp.register_routes(
            sink, auth_fn, perm_fn, audit, agents_fn, /*rbac_store=*/nullptr,
            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr, /*audit_store=*/nullptr, /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr, /*policy_store=*/nullptr, /*mgmt_store=*/nullptr,
            /*approval_manager=*/nullptr, /*schedule_engine=*/nullptr, read_only, mcp_disabled,
            /*dispatch_fn=*/nullptr, /*ca_store=*/nullptr, /*publish_crl_fn=*/nullptr,
            /*guaranteed_state_store=*/nullptr, /*dex_perf_fn=*/{}, /*network_api=*/nullptr,
            /*response_scope_fn=*/{}, /*software_inventory_store=*/nullptr, &metrics,
            /*quarantine_store=*/nullptr, /*tag_push_fn=*/{}, /*agent_registry=*/nullptr,
            /*scoped_perm_fn=*/{}, &sessions, &streaming_disabled);
    }

    std::unique_ptr<httplib::Response> send(const std::string& method, const std::string& marker,
                                            const std::string& body = {},
                                            std::unordered_map<std::string, std::string> hdrs = {}) {
        hdrs["X-Test-Req"] = marker;
        return sink.dispatch(method, "/mcp/v1/", body, "application/json", hdrs);
    }
};

constexpr const char* kToolsCallBody =
    R"({"jsonrpc":"2.0","method":"tools/call","id":7,"params":{"name":"list_agents","arguments":{}}})";
constexpr const char* kInitializeBody =
    R"({"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2025-06-18"}})";

} // namespace

TEST_CASE("mcp admission: a tierless session is refused on POST, GET and DELETE through the real "
          "routes, ahead of any tool",
          "[mcp][a5][authz][4309]") {
    struct Case {
        const char* verb;
        const char* body;
    };
    const Case cases[] = {{"POST", kToolsCallBody},
                          {"POST", kInitializeBody},
                          {"GET", ""},
                          {"DELETE", ""}};
    for (const char* source : {"local", "oidc", "saml", "api_token"}) {
        for (const auto& c : cases) {
            CAPTURE(source, c.verb, c.body);
            RoutesHarness h;
            h.wire();
            h.resolved = make_session(source, "");

            // Two requests: the counter and the audit row are per request.
            for (int n = 1; n <= 2; ++n) {
                CAPTURE(n);
                const std::string marker = std::string{c.verb} + "-" + std::to_string(n);
                auto res = h.send(c.verb, marker, c.body);
                REQUIRE(res != nullptr);
                CHECK(res->status == 403);
                const auto body = nlohmann::json::parse(res->body);
                CHECK(body.at("error").at("code") == -32003);
                CHECK(body.at("error").at("message") == "/mcp/v1/ requires an MCP-tier bearer token");
                CHECK(body.at("id").is_null());
                CHECK_FALSE(body.at("error").at("data").contains("permission"));
                const std::string cid = body.at("error").at("data").at("correlation_id");

                // Exactly one admission row per request, from THIS request.
                REQUIRE(h.audits.size() == static_cast<std::size_t>(n));
                const auto& row = h.audits.back();
                CHECK(row.marker == marker);
                CHECK(row.call.action == "mcp.session.reject");
                CHECK(row.call.result == "failure");
                CHECK(row.call.target_type == "McpSession");
                CHECK(row.call.target_id.empty());
                CHECK(row.call.detail ==
                      std::string{"reason=tier_required auth_source="} + source + " cid=" + cid);

                CHECK(h.metrics.serialize().find(std::string{kCounterLine} + " " +
                                                 std::to_string(n) + "\n") != std::string::npos);
            }
            // No tool ran, no session was minted.
            CHECK(h.tool_gate_calls == 0);
            CHECK(h.sessions.active_count() == 0);
            CHECK(h.resolver_calls == 2);
        }
    }
}

TEST_CASE("mcp admission: an unauthenticated request keeps the resolver's own 401 and writes no "
          "admission row",
          "[mcp][a5][authz][4309]") {
    for (const char* verb : {"POST", "GET", "DELETE"}) {
        CAPTURE(verb);
        RoutesHarness h;
        h.wire();
        h.resolved.reset();
        auto res = h.send(verb, "unauth", std::string{verb} == "POST" ? kToolsCallBody : "");
        REQUIRE(res != nullptr);
        CHECK(res->status == 401);
        CHECK(h.audits.empty());
        CHECK(h.metrics.serialize().find(kCounterLine) == std::string::npos);
    }
}

TEST_CASE("mcp admission: a tiered session is admitted through the real routes and writes no "
          "admission audit or counter",
          "[mcp][a5][authz][4309]") {
    for (const char* tier : {"readonly", "operator", "supervised", "bogus"}) {
        CAPTURE(tier);
        RoutesHarness h;
        h.wire();
        h.resolved = make_session("mcp_token", tier);

        auto init = h.send("POST", "init", kInitializeBody);
        REQUIRE(init != nullptr);
        CHECK(init->status == 200);
        const auto sid = init->get_header_value("Mcp-Session-Id");
        REQUIRE(sid.size() == 32);
        CHECK(h.sessions.active_count() == 1);

        auto call = h.send("POST", "call", kToolsCallBody, {{"Mcp-Session-Id", sid}});
        REQUIRE(call != nullptr);
        CHECK(call->status == 200);

        // Admission wrote nothing: no tier_required row, no counter.
        for (const auto& row : h.audits)
            CHECK(row.call.detail.find("reason=tier_required") == std::string::npos);
        CHECK(h.metrics.serialize().find(kCounterLine) == std::string::npos);
    }
}

TEST_CASE("mcp admission: the tiered control reaches the tool (so the refusal cases are not "
          "vacuous)",
          "[mcp][a5][authz][4309]") {
    RoutesHarness h;
    h.wire();
    h.resolved = make_session("mcp_token", "readonly");
    auto init = h.send("POST", "init", kInitializeBody);
    REQUIRE(init != nullptr);
    const auto sid = init->get_header_value("Mcp-Session-Id");
    auto call = h.send("POST", "call", kToolsCallBody, {{"Mcp-Session-Id", sid}});
    REQUIRE(call != nullptr);
    CHECK(call->status == 200);
    CHECK(h.tool_gate_calls >= 1);
}
