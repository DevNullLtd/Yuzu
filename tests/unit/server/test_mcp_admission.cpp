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
#include "step_up_gate.hpp" // step_up_source_label: the sibling closed list (C1 lock below)
#include "test_route_sink.hpp"

#include "../test_log_capture.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
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
                                          const std::string& principal_kind = "human",
                                          const std::string& username = "alice") {
    yuzu::server::auth::Session s;
    s.username = username;
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
    /// The audit-row budget's injected clock (ms): tests move it, never sleep. The numbers are
    /// the factory's: 10 rows per key per 10 s window, 64 keys.
    std::int64_t now_ms{1'000};
    yuzu::server::DenialAuditBudget budget{yuzu::server::kDefaultAuditMaxRows,
                                           yuzu::server::kDefaultAuditWindowMs,
                                           [this] { return now_ms; },
                                           yuzu::server::kDefaultAuditMaxKeys};

    /// yuzu_mcp_admission_audit_suppressed_total as exported.
    std::size_t suppressed_count() {
        return static_cast<std::size_t>(
            metrics.counter("yuzu_mcp_admission_audit_suppressed_total").value());
    }

    bool run(const yuzu::server::auth::Session& s) {
        auto audit = [this](const httplib::Request&, const std::string& action,
                            const std::string& result, const std::string& target_type,
                            const std::string& target_id, const std::string& detail) -> bool {
            audits.push_back({action, result, target_type, target_id, detail});
            return audit_ok;
        };
        return admit(s, req, res, audit, &metrics, budget);
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
          "This credential has no MCP tier and retrying will not help. A human operator must mint "
          "an API token with mcp_tier readonly, operator or supervised (the lowest tier that "
          "covers the tools needed) and an expires_at at most 90 days out (unix seconds), via "
          "Settings > API Tokens or POST /api/v1/tokens; then configure this client to send only "
          "Authorization: Bearer <token>, with no session cookie.");
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
        yuzu::server::DenialAuditBudget budget;
        auto throwing = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("audit store down");
        };
        CHECK_FALSE(admit(make_session("saml", ""), req, res, throwing, &metrics, budget));
        CHECK(res.status == 403);
        CHECK(metrics.serialize().find(std::string{kCounterLine} + " 1\n") != std::string::npos);
    }
    SECTION("no audit hook wired") {
        httplib::Request req;
        httplib::Response res;
        yuzu::MetricsRegistry metrics;
        yuzu::server::DenialAuditBudget budget;
        const std::function<bool(const httplib::Request&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&)>
            none;
        CHECK_FALSE(admit(make_session("local", ""), req, res, none, &metrics, budget));
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
    CHECK_FALSE(admit(make_session("local", ""), h.req, h.res, audit, nullptr, h.budget));
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
    /// The factory's audit-budget clock (ms), injected so a test moves the window by hand.
    std::int64_t now_ms{1'000};
    /// Audit rows plus the value of the X-Test-Req header on the request the hook was handed,
    /// so a test can prove the SAME request object reached the audit hook.
    struct Row {
        AuditCall call;
        std::string marker;
    };
    std::vector<Row> audits;

    std::size_t suppressed_count() {
        return static_cast<std::size_t>(
            metrics.counter("yuzu_mcp_admission_audit_suppressed_total").value());
    }

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
            yuzu::server::mcp::make_admission_auth_fn(resolver, audit, &metrics,
                                                      [this] { return now_ms; });
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

// ═══════════════════════════════════════════════════════════════════════════
// C1: bounded_auth_source and step_up_source_label are two copies of one closed list.
// Extending one without the other makes the same credential read as a different source in the
// audit row and in the step-up metrics; this locks them together (step_up_* is not edited).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("mcp admission: bounded_auth_source agrees with step_up_source_label",
          "[mcp][a5][authz][4309]") {
    for (const char* source : {"local", "oidc", "saml", "api_token", "mcp_token", "engine_token",
                               "", "ldap", "LOCAL", "mystery", "local\nforged=1", "other"}) {
        CAPTURE(source);
        CHECK(bounded_auth_source(source) == yuzu::server::step_up_source_label(source));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit-row budget. The refusal and the counter are never sampled; only the mcp.session.reject
// row is bounded, per key `tier_required|<auth_source>|<principal>`: 10 rows per key per 10 s
// window, 64 live keys, overflow in `tier_required|*` (DenialAuditBudget defaults).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("mcp admission budget: a flood from one principal writes at most max_rows audit rows "
          "but is refused and counted every time",
          "[mcp][a5][authz][4309]") {
    Harness h;
    constexpr int kFlood = 25;
    for (int n = 1; n <= kFlood; ++n) {
        CAPTURE(n);
        CHECK_FALSE(h.run(make_session("local", "")));
        CHECK(h.res.status == 403);
        CHECK(h.res.body.find("-32003") != std::string::npos);
    }
    // Rows are bounded, the counter is not.
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxRows);
    CHECK(h.metrics.serialize().find(std::string{kCounterLine} + " 25\n") != std::string::npos);
    CHECK(h.budget.suppressed_total() == kFlood - yuzu::server::kDefaultAuditMaxRows);
    // Every suppressed row is counted, so rows + suppressed == refusals.
    CHECK(h.suppressed_count() == kFlood - yuzu::server::kDefaultAuditMaxRows);
    CHECK(h.audits.size() + h.suppressed_count() == static_cast<std::size_t>(kFlood));
}

TEST_CASE("mcp admission budget: the first refusal of a key (below the key bound) writes its "
          "row with the exact tuple",
          "[mcp][a5][authz][4309]") {
    Harness h;
    // Exhaust alice/local, then ask for a fresh key.
    for (int n = 0; n < 15; ++n)
        (void)h.run(make_session("local", ""));
    const auto before = h.audits.size();
    REQUIRE(before == yuzu::server::kDefaultAuditMaxRows);
    CHECK_FALSE(h.run(make_session("oidc", "", "human", "bob")));
    REQUIRE(h.audits.size() == before + 1);
    const auto cid = nlohmann::json::parse(h.res.body)["error"]["data"]["correlation_id"]
                         .get<std::string>();
    const auto& row = h.audits.back();
    CHECK(row.action == "mcp.session.reject");
    CHECK(row.result == "failure");
    CHECK(row.target_type == "McpSession");
    CHECK(row.target_id.empty());
    CHECK(row.detail == "reason=tier_required auth_source=oidc cid=" + cid);
}

TEST_CASE("mcp admission budget: one principal's flood cannot starve another's row; the "
          "auth_source is part of the key",
          "[mcp][a5][authz][4309]") {
    Harness h;
    for (int n = 0; n < 40; ++n)
        (void)h.run(make_session("local", "", "human", "mallory"));
    const auto mallory_rows = h.audits.size();
    CHECK(mallory_rows == yuzu::server::kDefaultAuditMaxRows);

    CHECK_FALSE(h.run(make_session("local", "", "human", "alice")));
    CHECK(h.audits.size() == mallory_rows + 1);
    // Same user through a different credential class is a different key.
    CHECK_FALSE(h.run(make_session("api_token", "", "human", "mallory")));
    CHECK(h.audits.size() == mallory_rows + 2);
    // Mallory's own key is still spent.
    CHECK_FALSE(h.run(make_session("local", "", "human", "mallory")));
    CHECK(h.audits.size() == mallory_rows + 2);
}

TEST_CASE("mcp admission budget: the next window re-admits (injected clock, no sleeps)",
          "[mcp][a5][authz][4309]") {
    Harness h;
    for (int n = 0; n < 20; ++n)
        (void)h.run(make_session("local", ""));
    REQUIRE(h.audits.size() == yuzu::server::kDefaultAuditMaxRows);

    h.now_ms += yuzu::server::kDefaultAuditWindowMs - 1; // still inside the window
    (void)h.run(make_session("local", ""));
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxRows);

    h.now_ms += 1; // window elapsed
    (void)h.run(make_session("local", ""));
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxRows + 1);
    // Every refusal was still counted: 20 + 1 + 1.
    CHECK(h.metrics.serialize().find(std::string{kCounterLine} + " 22\n") != std::string::npos);
}

TEST_CASE("mcp admission budget: distinct principals beyond the key bound share the overflow "
          "bucket (no first-row guarantee), and memory stays bounded",
          "[mcp][a5][authz][4309]") {
    Harness h;
    // 64 distinct principals fill the key table, one row each.
    for (std::size_t i = 0; i < yuzu::server::kDefaultAuditMaxKeys; ++i)
        (void)h.run(make_session("local", "", "human", "user" + std::to_string(i)));
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxKeys);
    // Past the bound, 30 new principals share `tier_required|*`: 10 rows, 20 suppressed.
    for (int i = 0; i < 30; ++i)
        (void)h.run(make_session("local", "", "human", "late" + std::to_string(i)));
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxKeys + yuzu::server::kDefaultAuditMaxRows);
    CHECK(h.budget.live_keys() <= 2 * yuzu::server::kDefaultAuditMaxKeys + 1);
    // Every refusal counted; the 20 late principals past the overflow bucket's 10 rows are
    // suppressed (their first refusal wrote no row), and the suppressed counter says so.
    CHECK(h.metrics.serialize().find(std::string{kCounterLine} + " 94\n") != std::string::npos);
    CHECK(h.suppressed_count() == 20);
    CHECK(h.audits.size() + h.suppressed_count() == 94);
}

TEST_CASE("mcp admission budget: the key is bounded for any username or source",
          "[mcp][a5][authz][4309]") {
    auto s = make_session(std::string(70'000, 'x'), "", "human", std::string(70'000, 'u'));
    const auto key = yuzu::server::mcp::admission_budget_key(s);
    // "tier_required|other|" is 20 bytes, plus the principal cut to 64.
    CHECK(key.size() == 84);
    CHECK(key.rfind("tier_required|other|", 0) == 0);
    // The longest legitimate source label ("engine_token") gives the longest key: 27 + 64 = 91,
    // inside the budget's own 96-byte bound, so the budget never cuts into the principal.
    auto t = make_session("engine_token", "", "engine", std::string(200, 'e'));
    CHECK(yuzu::server::mcp::admission_budget_key(t).size() == 91);
}

TEST_CASE("mcp admission budget: an admitted request never touches the budget",
          "[mcp][a5][authz][4309]") {
    Harness h;
    for (int n = 0; n < 50; ++n)
        CHECK(h.run(make_session("mcp_token", "readonly")));
    CHECK(h.budget.live_keys() == 0);
    CHECK(h.budget.suppressed_total() == 0);
    CHECK(h.audits.empty());
}

TEST_CASE("mcp admission budget: through the real routes a flood is refused and counted every "
          "time, rows are bounded, and the next window re-admits",
          "[mcp][a5][authz][4309]") {
    RoutesHarness h;
    h.wire();
    h.resolved = make_session("local", "");
    constexpr int kFlood = 30;
    for (int n = 1; n <= kFlood; ++n) {
        CAPTURE(n);
        auto res = h.send("POST", "flood-" + std::to_string(n), kToolsCallBody);
        REQUIRE(res != nullptr);
        CHECK(res->status == 403);
    }
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxRows);
    CHECK(h.metrics.serialize().find(std::string{kCounterLine} + " 30\n") != std::string::npos);
    CHECK(h.tool_gate_calls == 0);
    CHECK(h.sessions.active_count() == 0);

    // A different principal on a different verb still gets its own first row.
    h.resolved = make_session("local", "", "human", "bob");
    auto get = h.send("GET", "bob-get");
    REQUIRE(get != nullptr);
    CHECK(get->status == 403);
    REQUIRE(h.audits.size() == yuzu::server::kDefaultAuditMaxRows + 1);
    CHECK(h.audits.back().marker == "bob-get");

    // The same budget serves all three verbs: alice stays spent on DELETE.
    h.resolved = make_session("local", "");
    auto del = h.send("DELETE", "alice-del");
    REQUIRE(del != nullptr);
    CHECK(del->status == 403);
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxRows + 1);

    // One millisecond short of the factory's window: still spent (pins the factory's own
    // window, not just the primitive's).
    h.now_ms += yuzu::server::kDefaultAuditWindowMs - 1;
    auto short_of = h.send("POST", "alice-short", kToolsCallBody);
    REQUIRE(short_of != nullptr);
    CHECK(short_of->status == 403);
    CHECK(h.audits.size() == yuzu::server::kDefaultAuditMaxRows + 1);
    // Every refusal so far is either a row or a counted suppression: 30 + 1 + 1 + 1.
    CHECK(h.audits.size() + h.suppressed_count() == 33);

    // Next window: alice writes again.
    h.now_ms += 1;
    auto again = h.send("POST", "alice-again", kToolsCallBody);
    REQUIRE(again != nullptr);
    CHECK(again->status == 403);
    REQUIRE(h.audits.size() == yuzu::server::kDefaultAuditMaxRows + 2);
    CHECK(h.audits.back().marker == "alice-again");
}

TEST_CASE("mcp admission budget: the next window's first refusal logs one aggregate count line "
          "with no caller content",
          "[mcp][a5][authz][4309]") {
    Harness h;
    const auto session = make_session("oidc", "", "human", "zz_distinct_principal");
    // 15 refusals: 10 rows, 5 suppressed. No line is logged inside the window.
    yuzu::test::LogCapture cap;
    for (int n = 0; n < 15; ++n)
        (void)h.run(session);
    cap.stop();
    CHECK(cap.text().find("audit rows suppressed") == std::string::npos);

    // The line comes from the refusal that OPENS the next window, not from the burst's end.
    h.now_ms += yuzu::server::kDefaultAuditWindowMs;
    yuzu::test::LogCapture cap2;
    (void)h.run(session);
    cap2.stop();
    const std::string text = cap2.text();
    CHECK(text.find("5 tier_required audit rows suppressed in the last window") !=
          std::string::npos);
    // A count only: no principal, no auth_source, no correlation id.
    CHECK(text.find("zz_distinct_principal") == std::string::npos);
    CHECK(text.find("oidc") == std::string::npos);
    CHECK(text.find("cid=") == std::string::npos);
    CHECK(text.find("tier_required|") == std::string::npos);
}

TEST_CASE("mcp admission budget: a budget that throws never turns the refusal into an exception",
          "[mcp][a5][authz][4309]") {
    httplib::Request req;
    httplib::Response res;
    yuzu::MetricsRegistry metrics;
    // try_admit reads the clock first, so a throwing clock is a throwing budget.
    yuzu::server::DenialAuditBudget budget(
        yuzu::server::kDefaultAuditMaxRows, yuzu::server::kDefaultAuditWindowMs,
        []() -> std::int64_t { throw std::runtime_error("clock failed"); });
    int audit_calls = 0;
    auto audit = [&audit_calls](const httplib::Request&, const std::string&, const std::string&,
                                const std::string&, const std::string&,
                                const std::string&) -> bool {
        ++audit_calls;
        return true;
    };
    bool admitted = true;
    REQUIRE_NOTHROW(admitted = admit(make_session("local", ""), req, res, audit, &metrics, budget));
    CHECK_FALSE(admitted);
    CHECK(res.status == 403);
    CHECK(audit_calls == 0); // not admitted: no row
    CHECK(metrics.serialize().find(std::string{kCounterLine} + " 1\n") != std::string::npos);
    // The suppressed counter accounts for the row that was not written.
    CHECK(metrics.counter("yuzu_mcp_admission_audit_suppressed_total").value() == 1.0);
}
