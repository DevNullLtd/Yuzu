/**
 * test_rest_me.cpp — session self-description on GET /api/v1/me and the pure
 * admin-gate verdict it reports as `can_access_settings`.
 *
 * Most cases need no store and no process: routes are registered with every store null
 * and an injected auth_fn, so a case runs in microseconds on any host. The [pg] cases at
 * the end wire a real RbacStore to exercise the principal-namespace choice and the checked
 * read against the real accessor.
 */
#include "admin_gate.hpp"
#include "dashboard_api_routes.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_principal_lock_gate.hpp" // yuzu::test::GrantReadFault (real-store fault)
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
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

auth::Session make_engine_session() {
    auth::Session s = make_session(auth::Role::user);
    s.username = "engine:indexer";
    s.principal_kind = "engine";
    s.auth_source = "engine_token";
    return s;
}

json get_me(const auth::Session& session, std::string* cache_control = nullptr,
            RbacStore* rbac = nullptr) {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    auto auth_fn = [&](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        return session;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) { return true; };
    api.register_routes(sink, auth_fn, perm_fn, audit_fn, rbac, nullptr, nullptr, nullptr,
                        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    auto r = sink.Get("/api/v1/me");
    REQUIRE(r);
    REQUIRE(r->status == 200);
    if (cache_control)
        *cache_control = r->get_header_value("Cache-Control");
    return json::parse(r->body)["data"];
}

/// Legacy GET /api/me (raw body, no envelope) for the same session and store.
json get_legacy_me(const auth::Session& session, RbacStore* rbac = nullptr) {
    yuzu::server::test::TestRouteSink sink;
    yuzu::server::dashboard_api::register_dashboard_api_routes(
        sink, yuzu::server::dashboard_api::Deps{
                  .auth_fn = [&session](const httplib::Request&, httplib::Response&)
                      -> std::optional<auth::Session> { return session; },
                  .perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                                const std::string&) { return true; },
                  .visible_agents_json_fn = [](const std::string&) { return json::array(); },
                  .rbac_store = rbac,
              });
    auto r = sink.Get("/api/me");
    REQUIRE(r);
    REQUIRE(r->status == 200);
    return json::parse(r->body);
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
    // Elevation never outranks a token confinement: an elevated user's MCP or
    // service-scoped credential is still refused (the token checks run first).
    CHECK(admin_gate_verdict(make_session(auth::Role::user, true, "operator")) ==
          AdminGate::McpTier);
    CHECK(admin_gate_verdict(make_session(auth::Role::user, true, "", "finance")) ==
          AdminGate::ServiceScoped);
    // A LAPSED elevation window is not admin: the effective role, not a stale
    // wall-clock field, decides.
    {
        auto lapsed = make_session(auth::Role::user);
        lapsed.steady_elevated_until = chr::steady_clock::now() - chr::seconds(1);
        lapsed.elevated_until = chr::system_clock::now() - chr::seconds(1);
        CHECK(admin_gate_verdict(lapsed) == AdminGate::NotAdmin);
    }
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
    for (const auto& session :
         {make_session(auth::Role::admin), make_session(auth::Role::user, true),
          make_session(auth::Role::user), make_session(auth::Role::admin, false, "readonly"),
          make_session(auth::Role::user, false, "", "finance"), make_engine_session()}) {
        CHECK(get_legacy_me(session) == get_me(session));
    }
}

TEST_CASE("GET /api/v1/me and GET /api/me: invalid UTF-8 in the session is replaced, status 200",
          "[server][routes][rest_me]") {
    auto session = make_session(auth::Role::user);
    session.username = std::string("ab\xC3\x28");
    session.display_name = std::string("\xFF\xFE");
    // get_me / get_legacy_me REQUIRE status 200 and parse the body, so a throwing dump (a
    // bodyless 500) or an invalid-UTF-8 body fails here rather than being swallowed.
    const auto v1 = get_me(session);
    CHECK(v1["username"].get<std::string>() == "ab\xEF\xBF\xBD(");
    CHECK(v1["display_name"].get<std::string>() == "\xEF\xBF\xBD\xEF\xBF\xBD");
    CHECK(get_legacy_me(session) == v1);
}

TEST_CASE("GET /api/v1/me: reports the principal and credential facts", "[server][routes][rest_me]") {
    auto d = get_me(make_session(auth::Role::user));
    CHECK(d["principal_kind"] == "human");
    CHECK(d["auth_source"] == "local");
    CHECK(d["mcp_tier"] == "");
    CHECK(d["scope_service"] == "");
    CHECK(d["rbac_roles_resolved"] == true);

    auto tok = get_me(make_session(auth::Role::user, false, "readonly", "finance"));
    CHECK(tok["mcp_tier"] == "readonly");
    CHECK(tok["scope_service"] == "finance");
}

TEST_CASE("GET /api/v1/me: an engine principal is not labelled Viewer or Administrator",
          "[server][routes][rest_me]") {
    // No store wired (RBAC off): an engine session carries no rbac_role at all, and
    // the legacy `role` stays the persisted value.
    auto d = get_me(make_engine_session());
    CHECK(d["username"] == "engine:indexer");
    CHECK(d["principal_kind"] == "engine");
    CHECK(d["auth_source"] == "engine_token");
    CHECK(d["role"] == "user");
    CHECK_FALSE(d.contains("rbac_role"));
    CHECK(d["rbac_roles"].is_array());
    CHECK(d["rbac_roles"].empty());
    CHECK(d["rbac_roles_resolved"] == true);
}

// ── Real RbacStore ([pg]) ──────────────────────────────────────────────────
namespace {
// Pre-migrated RbacStore template; unique key, nothing else needs this exact single-store setup.
yuzu::test::PgTestTemplate rest_me_rbac_tpl{"restmerbac", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("restmerbac template: store failed to migrate");
}};
} // namespace

// Every case above passes a null store, so none exercises the principal-namespace choice or the
// checked read against the real accessor.

TEST_CASE("GET /api/v1/me: reads grants under the namespace of the session kind, not the "
          "username prefix",
          "[pg][server][routes][rest_me]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rest_me_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    // Engines cannot hold built-in roles, so the engine grant is a custom role. RbacStore
    // refuses a ('user', 'engine:...') row, so this is the only row carrying the id.
    REQUIRE(rbac.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(rbac.assign_role({"engine", "engine:shared", "EngineReader"}).has_value());

    SECTION("a human named engine:shared is a user lookup and does not see the engine grant") {
        auto s = make_session(auth::Role::user);
        s.username = "engine:shared";
        const auto d = get_me(s, nullptr, &rbac);
        CHECK(d["rbac_enabled"] == true);
        CHECK(d["rbac_role"] == "Viewer"); // legacy fallback for a human with no user grant
        CHECK(d["rbac_roles"].empty());
        CHECK(d["rbac_roles_resolved"] == true);
        CHECK(get_legacy_me(s, &rbac) == d);
    }
    SECTION("an engine principal is an engine lookup") {
        auto s = make_engine_session();
        s.username = "engine:shared";
        const auto d = get_me(s, nullptr, &rbac);
        CHECK(d["rbac_role"] == "EngineReader");
        CHECK(d["rbac_roles"] == json::array({"EngineReader"}));
        CHECK(d["rbac_roles_resolved"] == true);
        CHECK(get_legacy_me(s, &rbac) == d);
    }
    SECTION("an engine with no engine grant gets no rbac_role, not Viewer") {
        auto s = make_engine_session();
        s.username = "engine:ungranted";
        const auto d = get_me(s, nullptr, &rbac);
        CHECK(d["rbac_enabled"] == true);
        CHECK_FALSE(d.contains("rbac_role"));
        CHECK(d["rbac_roles"].empty());
        CHECK(d["rbac_roles_resolved"] == true);
        CHECK(get_legacy_me(s, &rbac) == d);
    }
    SECTION("a human with direct roles reports them; rbac_role is the role_name-first") {
        // Viewer is assigned first so insertion order differs from role_name order.
        REQUIRE(rbac.assign_role({"user", "alice", "Viewer"}).has_value());
        REQUIRE(rbac.assign_role({"user", "alice", "PlatformEngineer"}).has_value());
        const auto s = make_session(auth::Role::user);
        const auto d = get_me(s, nullptr, &rbac);
        CHECK(d["rbac_role"] == "PlatformEngineer");
        CHECK(d["rbac_roles"] == json::array({"PlatformEngineer", "Viewer"}));
        CHECK(get_legacy_me(s, &rbac) == d);
    }
    SECTION("real store fault: principal_roles unreadable is a 200 with rbac_roles_resolved:false") {
        const auto s = make_session(auth::Role::admin);
        yuzu::test::GrantReadFault fault(pool);
        fault.arm();
        const auto d = get_me(s, nullptr, &rbac);
        const auto legacy = get_legacy_me(s, &rbac);
        fault.repair();
        CHECK(d["rbac_enabled"] == true);
        CHECK(d["rbac_roles_resolved"] == false);
        CHECK_FALSE(d.contains("rbac_role"));
        CHECK_FALSE(d.contains("rbac_roles"));
        CHECK(legacy == d);
    }
}
