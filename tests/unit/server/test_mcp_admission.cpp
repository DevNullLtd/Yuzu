/**
 * test_mcp_admission.cpp - /mcp/v1/ credential-class admission (#4309).
 *
 * /mcp/v1/ refuses every credential whose Session::mcp_tier is empty. The unit
 * under test is mcp_admission.hpp: the predicate (requires_tiered_credential) and
 * the single entry point (admit), which performs the refusal (audit row + counter
 * + A4 response) and returns whether the request is admitted. The server.cpp
 * wiring is pinned separately by a source tripwire in
 * test_mcp_route_registration.cpp; the live GET/POST/DELETE behaviour by
 * scripts/e2e-mcp-test.sh.
 */

#include "mcp_admission.hpp"
#include "mcp_jsonrpc.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <stdexcept>
#include <string>
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
