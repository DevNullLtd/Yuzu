/**
 * test_upload_grants_service_scope.cpp -- GET /api/v1/upload-grants refuses a service-scoped
 * token, driven through the REAL AuthRoutes (real token resolution, real
 * `deny_service_scoped_session`, real `authorize_list_read` resolver) over a real Postgres
 * RbacStore, ManagementGroupStore, ApiTokenStore, TagStore and UploadGrantStore.
 *
 * The list route's only other gate is `list_read_fn(session->username)`, which evaluates the
 * MINTER's username. Without the service-scope refusal a service token therefore inherits its
 * minter's UploadGrant:Read view (everything, when the minter holds a global grant). The same
 * minter's ordinary session must keep seeing exactly the rows it saw before.
 *
 * It also pins the engine-principal default-deny on the same route: an engine session is
 * RBAC-only, so with RBAC off, or on with no UploadGrant:Read grant, it lists nothing, and the
 * REST answer matches the `require_permission` gate the MCP `list_upload_grants` twin runs first.
 */

#include "audit_store.hpp"
#include "engine_principal_store.hpp"
#include "file_retrieval_routes.hpp"
#include "pg/pg_pool.hpp"
#include "tag_store.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "upload_grant_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

using namespace yuzu::server;

namespace {

struct UploadGrantScopeRig {
    yuzu::test::ResponseExecutionAuthzPgRig rig;
    TagStore tags;
    UploadGrantStore store;
    // A real AuditStore on its own pool over the same clone (its own `audit_store` schema),
    // so the denial row the shared closure writes is observable. The server.cpp line that
    // wires `deny_service_scoped_fn` into this module's Deps cannot be pinned by this rig,
    // because `make_deps` below builds its own Deps rather than using server.cpp's.
    yuzu::server::pg::PgPool audit_pool;
    AuditStore audit_store;
    std::unique_ptr<AuthRoutes> ar; // same stores + a TagStore: service tokens resolve
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};

    explicit UploadGrantScopeRig(const std::string& dsn)
        : rig{dsn}, tags{rig.pool}, store{rig.pool}, audit_pool{{.conninfo = dsn, .size = 2}},
          audit_store{audit_pool} {
        REQUIRE(tags.is_open());
        REQUIRE(store.is_open());
        REQUIRE(audit_store.is_open());
        // gary: GLOBAL UploadGrant:Read and :Write, so his list view is AdmitAll.
        REQUIRE(rig.rbac.create_role({"UploadGrantOperator3526", "", false, 0}).has_value());
        REQUIRE(rig.rbac.set_permission({"UploadGrantOperator3526", "UploadGrant", "Read",
                                         "allow"})
                    .has_value());
        REQUIRE(rig.rbac.set_permission({"UploadGrantOperator3526", "UploadGrant", "Write",
                                         "allow"})
                    .has_value());
        REQUIRE(rig.rbac.assign_role({"user", "gary", "UploadGrantOperator3526"}).has_value());
        REQUIRE(rig.auth_mgr.upsert_user("gary", "correct-horse-battery-staple",
                                         auth::Role::user));
        ar = std::make_unique<AuthRoutes>(rig.cfg, rig.auth_mgr, &rig.rbac, rig.api_tokens.get(),
                                          &audit_store, &rig.mgmt, &tags,
                                          /*analytics_store=*/nullptr, rig.oidc_mu,
                                          rig.oidc_provider);
    }

    /// Wired as server.cpp wires the operator routes: real auth, real permission gate, the
    /// real `authorize_list_read` resolver and the real shared service-scope deny closure.
    Deps make_deps(bool wire_deny) {
        Deps deps;
        AuthRoutes* routes = ar.get();
        deps.auth_fn = [routes](const httplib::Request& req,
                                httplib::Response& res) -> std::optional<auth::Session> {
            return routes->require_auth(req, res);
        };
        deps.perm_fn = [routes](const httplib::Request& req, httplib::Response& res,
                                const std::string& t, const std::string& o) -> bool {
            return routes->require_permission(req, res, t, o);
        };
        deps.list_read_fn = [this](const std::string& username) -> UploadGrantListAuthorization {
            UploadGrantListAuthorization out;
            auto authz =
                rig.rbac.authorize_list_read(username, "UploadGrant", "Read", &rig.mgmt);
            switch (authz.decision) {
            case ListReadDecision::AdmitAll:
                out.decision = UploadGrantListDecision::kAdmitAll;
                break;
            case ListReadDecision::AdmitScoped:
                out.decision = UploadGrantListDecision::kAdmitScoped;
                out.visible_agents = std::move(authz.visible_agents);
                break;
            case ListReadDecision::DenyAll:
                break;
            }
            return out;
        };
        if (wire_deny) {
            deps.deny_service_scoped_fn =
                [routes](const httplib::Request& req, httplib::Response& res,
                         const std::string& action, const std::string& message,
                         const std::string& target_type, const std::string& target_id) -> bool {
                return routes->deny_service_scoped_session(req, res, action, message,
                                                           target_type, target_id);
            };
        }
        deps.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {
            return true;
        };
        deps.store = &store;
        deps.blob_root = blob_dir.path;
        deps.tls_enabled = true;
        return deps;
    }

    std::string mint_token(const std::string& scope_service) {
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto t = rig.api_tokens->create_token("upload-grants-scope", "gary", expires,
                                              scope_service);
        REQUIRE(t.has_value());
        return *t;
    }
};

std::set<std::string> agent_ids(const nlohmann::json& body) {
    std::set<std::string> out;
    for (const auto& row : body["data"])
        out.insert(row["agent_id"].get<std::string>());
    return out;
}

} // namespace

TEST_CASE("upload-grants list: a service-scoped token is refused and the minter's own session "
          "is unaffected",
          "[pg][authz][service_scope][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    UploadGrantScopeRig r{db.dsn()};
    yuzu::server::test::TestRouteSink sink;
    register_file_retrieval_routes(sink, r.make_deps(/*wire_deny=*/true));

    const auto ordinary = r.mint_token("");
    const auto svc = r.mint_token("printers");
    const std::unordered_map<std::string, std::string> ordinary_hdrs{
        {"Authorization", "Bearer " + ordinary}};
    const std::unordered_map<std::string, std::string> svc_hdrs{
        {"Authorization", "Bearer " + svc}};

    for (const char* agent : {"agent-A", "agent-B"}) {
        auto minted = sink.dispatch(
            "POST", "/api/v1/upload-grants",
            nlohmann::json{{"agent_id", agent}, {"declared_max_size", 100}}.dump(),
            "application/json", ordinary_hdrs);
        REQUIRE(minted);
        REQUIRE(minted->status == 201);
    }

    // The ordinary session sees every row, exactly as before this gate existed.
    {
        auto res = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json",
                                 ordinary_hdrs);
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        CHECK(agent_ids(body) == std::set<std::string>{"agent-A", "agent-B"});
        CHECK(body["data"].size() == 2);
        CHECK(body["meta"]["api_version"] == "v1");
    }

    // The service token, minted by that same gary, is refused: 403, no rows, and no
    // `permission` field (no grant would admit it).
    auto res = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json", svc_hdrs);
    REQUIRE(res);
    CHECK(res->status == 403);
    auto body = nlohmann::json::parse(res->body);
    CHECK_FALSE(body.contains("data"));
    CHECK(res->body.find("service-scoped tokens may not list upload grants") !=
          std::string::npos);
    CHECK(res->body.find("\"permission\"") == std::string::npos);
    CHECK(res->body.find("agent-A") == std::string::npos);
    CHECK(res->body.find("grant_id") == std::string::npos);

    // Exactly one denial row is written, by the shared closure (the route's own `audit_fn`
    // is a stub here and did not produce it): action `upload_grant.list.access_denied`,
    // result `denied`, target type `UploadGrant`. The ordinary session's list wrote none.
    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    std::size_t denied_rows = 0;
    for (const auto& row : *rows) {
        if (row.action != "upload_grant.list.access_denied")
            continue;
        ++denied_rows;
        CHECK(row.result == "denied");
        CHECK(row.target_type == "UploadGrant");
    }
    CHECK(denied_rows == 1);
}

// Needs no database: the guard runs before anything else in the public function, so a Deps with
// no store and no closures is enough, and the case runs when YUZU_TEST_POSTGRES_DSN is unset.
TEST_CASE("upload-grants list: an unwired service-scope deny is refused at registration, "
          "before any route is added",
          "[authz][service_scope][upload]") {
    yuzu::server::test::TestRouteSink sink;
    CHECK_THROWS_AS(register_file_retrieval_routes(sink, Deps{}), std::invalid_argument);
    try {
        register_file_retrieval_routes(sink, Deps{});
    } catch (const std::invalid_argument& e) {
        CHECK(std::string{e.what()} ==
              "register_file_retrieval_routes: deps.deny_service_scoped_fn must be bound");
    }
    // Nothing was registered: neither the list route nor the operator routes before it.
    CHECK(sink.dispatch("GET", "/api/v1/upload-grants") == nullptr);
    CHECK(sink.dispatch("POST", "/api/v1/upload-grants", "{}") == nullptr);
}

// A BOUND deny closure that returns false without writing a response must still refuse a
// service-scoped session: the route's own generic 403 is the fail-closed fallback, and no
// grant row reaches the body. (An unbound closure never gets this far: registration throws.)
TEST_CASE("upload-grants list: a bound service-scope deny that writes nothing still refuses "
          "with a 403 and no rows",
          "[pg][authz][service_scope][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    UploadGrantScopeRig r{db.dsn()};
    yuzu::server::test::TestRouteSink sink;
    auto deps = r.make_deps(/*wire_deny=*/true);
    int deny_calls = 0;
    deps.deny_service_scoped_fn = [&deny_calls](const httplib::Request&, httplib::Response&,
                                                const std::string&, const std::string&,
                                                const std::string&, const std::string&) -> bool {
        ++deny_calls;
        return false; // writes no response and claims the route need not return
    };
    register_file_retrieval_routes(sink, std::move(deps));

    const auto ordinary = r.mint_token("");
    const auto svc = r.mint_token("printers");
    const std::unordered_map<std::string, std::string> ordinary_hdrs{
        {"Authorization", "Bearer " + ordinary}};
    const std::unordered_map<std::string, std::string> svc_hdrs{
        {"Authorization", "Bearer " + svc}};

    auto minted = sink.dispatch("POST", "/api/v1/upload-grants",
                                nlohmann::json{{"agent_id", "agent-A"}, {"declared_max_size", 100}}
                                    .dump(),
                                "application/json", ordinary_hdrs);
    REQUIRE(minted);
    REQUIRE(minted->status == 201);

    auto res = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json", svc_hdrs);
    REQUIRE(res);
    CHECK(deny_calls == 1);
    CHECK(res->status == 403);
    CHECK(res->body.find("agent-A") == std::string::npos);
    CHECK(res->body.find("grant_id") == std::string::npos);
    CHECK(res->body.find("\"data\"") == std::string::npos);
}

// ---------------------------------------------------------------------------------------------
// Engine principals: default-deny on the list route (the username-keyed list-admit resolver
// admits everyone when RBAC is off, so the route must clear the engine gate first).
// ---------------------------------------------------------------------------------------------

namespace {

constexpr const char* kEnginePrincipal = "engine:vuln";

struct EngineListRig {
    UploadGrantScopeRig& r;
    EnginePrincipalStore engines;
    std::string engine_token;
    std::string gary_token;

    explicit EngineListRig(UploadGrantScopeRig& rig_) : r{rig_}, engines{rig_.rig.pool} {
        REQUIRE(engines.is_open());
        REQUIRE(engines
                    .create("Vuln Sync", "gary", "upload-grants engine gate", "internal", "admin",
                            kEnginePrincipal)
                    .has_value());
        r.rig.api_tokens->set_engine_referent_check(
            [this](const std::string& id) { return engines.get_for_auth(id).status; });
        r.ar->set_engine_principal_store(&engines);
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto et = r.rig.api_tokens->create_token("engine-token", kEnginePrincipal, expires, "",
                                                 "readonly", "engine");
        REQUIRE(et.has_value());
        engine_token = *et;
        gary_token = r.mint_token("");
        // Two rows, minted by gary under RBAC-on (his global UploadGrant:Write).
        for (const char* agent : {"agent-A", "agent-B"}) {
            auto minted = sink_dispatch("POST", nlohmann::json{{"agent_id", agent},
                                                               {"declared_max_size", 100}}
                                                    .dump(),
                                        gary_token);
            REQUIRE(minted);
            REQUIRE(minted->status == 201);
        }
    }

    std::unique_ptr<httplib::Response> sink_dispatch(const std::string& method,
                                                     const std::string& body,
                                                     const std::string& token) {
        yuzu::server::test::TestRouteSink sink;
        register_file_retrieval_routes(sink, r.make_deps(/*wire_deny=*/true));
        return sink.dispatch(method, "/api/v1/upload-grants", body, "application/json",
                             {{"Authorization", "Bearer " + token}});
    }

    /// What `require_permission(UploadGrant, Read)` answers for this token: the gate the MCP
    /// `list_upload_grants` twin runs before it resolves the list-admit decision.
    int mcp_gate_status(const std::string& token) {
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + token);
        httplib::Response res;
        const bool admitted = r.ar->require_permission(req, res, "UploadGrant", "Read");
        return admitted ? 200 : res.status;
    }
};

} // namespace

TEST_CASE("upload-grants list: an engine principal is default-deny, through the same gate as the "
          "MCP list tool",
          "[pg][authz][engine_principal][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    UploadGrantScopeRig r{db.dsn()};
    EngineListRig e{r};

    const auto expect_denied = [](const std::unique_ptr<httplib::Response>& res, int status) {
        REQUIRE(res);
        CHECK(res->status == status);
        CHECK(res->body.find("\"data\"") == std::string::npos);
        CHECK(res->body.find("agent-A") == std::string::npos);
        CHECK(res->body.find("grant_id") == std::string::npos);
    };

    SECTION("RBAC off (the default posture), zero grants: 403 and no rows") {
        r.rig.rbac.set_rbac_enabled(false);
        REQUIRE_FALSE(r.rig.rbac.is_rbac_enabled());
        expect_denied(e.sink_dispatch("GET", {}, e.engine_token), 403);
        // The REST denial is audited and attributed to the engine (the REST reference states
        // this). Counted BEFORE the direct gate call below, which writes the same row itself.
        auto audit_rows = r.audit_store.query({});
        REQUIRE(audit_rows.has_value());
        std::size_t engine_denials = 0;
        for (const auto& row : *audit_rows) {
            if (row.action != "auth.permission_required" || row.result != "denied" ||
                row.principal != kEnginePrincipal)
                continue;
            ++engine_denials;
            CHECK(row.principal_class == "engine");
        }
        CHECK(engine_denials >= 1);
        CHECK(e.mcp_gate_status(e.engine_token) == 403);
        // The human minter is unchanged: RBAC off admits the whole list.
        auto res = e.sink_dispatch("GET", {}, e.gary_token);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(agent_ids(nlohmann::json::parse(res->body)) ==
              std::set<std::string>{"agent-A", "agent-B"});
    }

    SECTION("RBAC on, no grant: 403 and no rows") {
        REQUIRE(r.rig.rbac.is_rbac_enabled());
        auto res = e.sink_dispatch("GET", {}, e.engine_token);
        expect_denied(res, 403);
        // The engine gate names the missing permission; the list-admit deny does not, so this
        // shows the denial came from the engine gate rather than only from the resolver.
        CHECK(res->body.find("UploadGrant:Read") != std::string::npos);
        CHECK(e.mcp_gate_status(e.engine_token) == 403);
    }

    SECTION("RBAC on, explicit UploadGrant:Read grant: 200 with every row") {
        REQUIRE(r.rig.rbac.create_role({"EngineUploadReader6204", "", false, 0}).has_value());
        REQUIRE(r.rig.rbac.set_permission({"EngineUploadReader6204", "UploadGrant", "Read",
                                           "allow"})
                    .has_value());
        REQUIRE(r.rig.rbac.assign_role({"engine", kEnginePrincipal, "EngineUploadReader6204"})
                    .has_value());
        auto res = e.sink_dispatch("GET", {}, e.engine_token);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(agent_ids(nlohmann::json::parse(res->body)) ==
              std::set<std::string>{"agent-A", "agent-B"});
        CHECK(e.mcp_gate_status(e.engine_token) == 200);
    }

    SECTION("RBAC store unavailable: 503 and no rows") {
        // A second AuthRoutes with no RbacStore models the unavailable store; the list-admit
        // resolver still points at the open store, so only the engine gate can refuse here.
        AuthRoutes degraded(r.rig.cfg, r.rig.auth_mgr, /*rbac_store=*/nullptr,
                            r.rig.api_tokens.get(), &r.audit_store, &r.rig.mgmt, &r.tags,
                            /*analytics_store=*/nullptr, r.rig.oidc_mu, r.rig.oidc_provider);
        degraded.set_engine_principal_store(&e.engines);
        auto deps = r.make_deps(/*wire_deny=*/true);
        deps.auth_fn = [&degraded](const httplib::Request& req,
                                   httplib::Response& res) -> std::optional<auth::Session> {
            return degraded.require_auth(req, res);
        };
        deps.perm_fn = [&degraded](const httplib::Request& req, httplib::Response& res,
                                   const std::string& t, const std::string& o) -> bool {
            return degraded.require_permission(req, res, t, o);
        };
        yuzu::server::test::TestRouteSink sink;
        register_file_retrieval_routes(sink, std::move(deps));
        auto res = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json",
                                 {{"Authorization", "Bearer " + e.engine_token}});
        expect_denied(res, 503);
    }

    SECTION("an unwired perm_fn refuses an engine (fail closed), never lists") {
        auto deps = r.make_deps(/*wire_deny=*/true);
        deps.perm_fn = nullptr;
        r.rig.rbac.set_rbac_enabled(false);
        REQUIRE_FALSE(r.rig.rbac.is_rbac_enabled());
        yuzu::server::test::TestRouteSink sink;
        register_file_retrieval_routes(sink, std::move(deps));
        auto res = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json",
                                 {{"Authorization", "Bearer " + e.engine_token}});
        expect_denied(res, 403);
    }
}

TEST_CASE("upload-grants list: a human session with no grant is still refused, one with a global "
          "grant still sees every row, and RBAC off still admits a human",
          "[pg][authz][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    UploadGrantScopeRig r{db.dsn()};
    yuzu::server::test::TestRouteSink sink;
    register_file_retrieval_routes(sink, r.make_deps(/*wire_deny=*/true));

    const auto gary = r.mint_token("");
    for (const char* agent : {"agent-A", "agent-B"}) {
        auto minted = sink.dispatch(
            "POST", "/api/v1/upload-grants",
            nlohmann::json{{"agent_id", agent}, {"declared_max_size", 100}}.dump(),
            "application/json", {{"Authorization", "Bearer " + gary}});
        REQUIRE(minted);
        REQUIRE(minted->status == 201);
    }

    REQUIRE(r.rig.auth_mgr.upsert_user("nogrant", "correct-horse-battery-staple",
                                       auth::Role::user));
    const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count() +
                         3600;
    auto nogrant = r.rig.api_tokens->create_token("no-grant", "nogrant", expires, "");
    REQUIRE(nogrant.has_value());

    auto denied = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json",
                                {{"Authorization", "Bearer " + *nogrant}});
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(denied->body.find("agent-A") == std::string::npos);

    auto ok = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json",
                            {{"Authorization", "Bearer " + gary}});
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(agent_ids(nlohmann::json::parse(ok->body)) ==
          std::set<std::string>{"agent-A", "agent-B"});

    // RBAC off is the state in which the engine gate differs from the human path: a human with
    // no grant is still admitted by the unchanged list-admit resolver.
    r.rig.rbac.set_rbac_enabled(false);
    REQUIRE_FALSE(r.rig.rbac.is_rbac_enabled());
    auto legacy = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json",
                                {{"Authorization", "Bearer " + *nogrant}});
    REQUIRE(legacy);
    CHECK(legacy->status == 200);
    CHECK(agent_ids(nlohmann::json::parse(legacy->body)) ==
          std::set<std::string>{"agent-A", "agent-B"});
}
