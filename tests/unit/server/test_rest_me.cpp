/**
 * test_rest_me.cpp — session self-description on GET /api/v1/me and the pure
 * admin-gate verdict it reports as `can_access_settings`.
 *
 * No store, no process: routes are registered with every store null and an
 * injected auth_fn, so a case runs in microseconds on any host.
 */
#include "admin_gate.hpp"
#include "dashboard_api_routes.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <regex>
#include <string>

using namespace yuzu::server;
using nlohmann::json;
namespace chr = std::chrono;

namespace {

auth::Session make_session(auth::Role role, bool elevated = false, std::string mcp_tier = {},
                           std::string scope_service = {}) {
    auth::Session s;
    s.username = "alice";
    s.role = role;
    s.mcp_tier = std::move(mcp_tier);
    s.token_scope_service = std::move(scope_service);
    if (elevated) {
        s.steady_elevated_until = chr::steady_clock::now() + chr::hours(1);
        s.elevated_until = chr::system_clock::now() + chr::hours(1);
    }
    return s;
}

json get_me(const auth::Session& session, std::string* cache_control = nullptr) {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    auto auth_fn = [&](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        return session;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) { return true; };
    api.register_routes(sink, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, nullptr,
                        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    auto r = sink.Get("/api/v1/me");
    REQUIRE(r);
    REQUIRE(r->status == 200);
    if (cache_control)
        *cache_control = r->get_header_value("Cache-Control");
    return json::parse(r->body)["data"];
}

} // namespace

TEST_CASE("admin_gate_verdict: truth table", "[server][authz][admin_gate]") {
    using authz::AdminGate;
    using authz::admin_gate_verdict;
    CHECK(admin_gate_verdict(make_session(auth::Role::admin)) == AdminGate::Admit);
    CHECK(admin_gate_verdict(make_session(auth::Role::user)) == AdminGate::NotAdmin);
    // JIT elevation counts: the effective role, not the persisted one.
    CHECK(admin_gate_verdict(make_session(auth::Role::user, true)) == AdminGate::Admit);
    // MCP and service-scoped tokens never reach admin routes, even an admin's.
    CHECK(admin_gate_verdict(make_session(auth::Role::admin, false, "operator")) ==
          AdminGate::McpTier);
    CHECK(admin_gate_verdict(make_session(auth::Role::admin, false, "", "finance")) ==
          AdminGate::ServiceScoped);
    // Service scope is checked first, as require_admin always did.
    CHECK(admin_gate_verdict(make_session(auth::Role::admin, false, "operator", "finance")) ==
          AdminGate::ServiceScoped);
}

TEST_CASE("GET /api/v1/me: legacy admin", "[server][routes][rest_me]") {
    std::string cc;
    auto d = get_me(make_session(auth::Role::admin), &cc);
    CHECK(d["role"] == "admin");
    CHECK(d["effective_role"] == "admin");
    CHECK(d["elevated"] == false);
    CHECK_FALSE(d.contains("elevated_until"));
    CHECK(d["can_access_settings"] == true);
    CHECK(cc == "no-store, private");
}

TEST_CASE("GET /api/v1/me: legacy user cannot access settings", "[server][routes][rest_me]") {
    auto d = get_me(make_session(auth::Role::user));
    CHECK(d["role"] == "user");
    CHECK(d["effective_role"] == "user");
    CHECK(d["elevated"] == false);
    CHECK(d["can_access_settings"] == false);
}

TEST_CASE("GET /api/v1/me: elevated user reports the window and may open settings",
          "[server][routes][rest_me]") {
    auto d = get_me(make_session(auth::Role::user, true));
    CHECK(d["role"] == "user"); // persisted role is never the elevated view
    CHECK(d["effective_role"] == "admin");
    CHECK(d["elevated"] == true);
    REQUIRE(d.contains("elevated_until"));
    CHECK(std::regex_match(d["elevated_until"].get<std::string>(),
                           std::regex(R"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)")));
    CHECK(d["can_access_settings"] == true);
}

TEST_CASE("GET /api/v1/me: MCP-tier and service-scoped tokens cannot access settings",
          "[server][routes][rest_me]") {
    CHECK(get_me(make_session(auth::Role::admin, false, "supervised"))["can_access_settings"] ==
          false);
    CHECK(get_me(make_session(auth::Role::user, false, "", "finance"))["can_access_settings"] ==
          false);
}

TEST_CASE("GET /api/me and GET /api/v1/me carry identical keys and values (the twin cannot drift)",
          "[server][routes][rest_me]") {
    const auto legacy = [](const auth::Session& session) {
        yuzu::server::test::TestRouteSink sink;
        yuzu::server::dashboard_api::register_dashboard_api_routes(
            sink, yuzu::server::dashboard_api::Deps{
                      .auth_fn = [&session](const httplib::Request&, httplib::Response&)
                          -> std::optional<auth::Session> { return session; },
                      .perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                                    const std::string&) { return true; },
                      .visible_agents_json_fn = [](const std::string&) { return json::array(); },
                  });
        auto r = sink.Get("/api/me");
        REQUIRE(r);
        return json::parse(r->body);
    };
    for (const auto& session :
         {make_session(auth::Role::admin), make_session(auth::Role::user, true),
          make_session(auth::Role::user), make_session(auth::Role::admin, false, "readonly"),
          make_session(auth::Role::user, false, "", "finance")}) {
        CHECK(legacy(session) == get_me(session));
    }
}
