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
 */

#include "audit_store.hpp"
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

TEST_CASE("upload-grants list: an unwired service-scope deny still refuses a service token",
          "[pg][authz][service_scope][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    UploadGrantScopeRig r{db.dsn()};
    yuzu::server::test::TestRouteSink sink;
    register_file_retrieval_routes(sink, r.make_deps(/*wire_deny=*/false));

    const auto svc = r.mint_token("printers");
    auto res = sink.dispatch("GET", "/api/v1/upload-grants", {}, "application/json",
                             {{"Authorization", "Bearer " + svc}});
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("\"permission\"") == std::string::npos);
    CHECK(res->body.find("\"data\"") == std::string::npos);
}
