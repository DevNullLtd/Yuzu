/**
 * test_fleet_read_ceiling_routes_authz.cpp -- the ITServiceOwner authority ceiling that
 * AuthRoutes::require_fleet_read applies on its service axis, driven through THREE real
 * routes that all gate on ("Execution", "Read") via fleet_read_fn, over a real Postgres
 * RbacStore, ManagementGroupStore, ApiTokenStore, TagStore and ExecutionTracker.
 *
 * The table-driven chokepoint cases in test_authz_gates.cpp call require_fleet_read directly,
 * so they cannot see a route handing the gate the wrong securable string. Each route here is
 * admitted under the seeded defaults and refused (403, the ceiling's own body) once the pair
 * is revoked from ITServiceOwner, so a route that passed some other pair to the gate fails.
 */

#include "enrollment_directory_routes.hpp"
#include "execution_routes.hpp"
#include "execution_tracker.hpp"
#include "rest_api_v1.hpp"
#include "tag_store.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

struct CeilingRouteRig {
    yuzu::test::ResponseExecutionAuthzPgRig rig;
    ExecutionTracker tracker;
    TagStore tags;
    std::unique_ptr<AuthRoutes> svc_auth; // same stores + a TagStore: service tokens resolve
    std::string x_bob;

    explicit CeilingRouteRig(const std::string& dsn)
        : rig{dsn}, tracker{rig.pool}, tags{rig.pool} {
        REQUIRE(tracker.is_open());
        REQUIRE(tags.is_open());
        // gary: GLOBAL Execution:Read, the minter of the service token below.
        REQUIRE(rig.rbac.assign_role({"user", "gary", "ExecutionReader1634"}).has_value());
        REQUIRE(rig.auth_mgr.upsert_user("gary", "correct-horse-battery-staple",
                                         auth::Role::user));
        REQUIRE(tags.set_tag("bob-agent", "service", "printers").has_value());
        svc_auth = std::make_unique<AuthRoutes>(rig.cfg, rig.auth_mgr, &rig.rbac,
                                                rig.api_tokens.get(), /*audit_store=*/nullptr,
                                                &rig.mgmt, &tags, /*analytics_store=*/nullptr,
                                                rig.oidc_mu, rig.oidc_provider);
        Execution e;
        e.definition_id = "def-ceiling-routes";
        e.dispatched_by = "carol";
        e.status = "completed";
        e.dispatched_at = 1735689600;
        e.agents_targeted = 1;
        auto id = tracker.create_execution(e);
        REQUIRE(id.has_value());
        x_bob = *id;
        AgentExecStatus a;
        a.agent_id = "bob-agent";
        a.status = "success";
        a.completed_at = 1735689660;
        tracker.update_agent_status(x_bob, a);
    }

    std::string mint_service(const std::string& user, const std::string& service) {
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto t = rig.api_tokens->create_token("ceiling-routes", user, expires, service);
        REQUIRE(t.has_value());
        return *t;
    }
};

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// The suffix only require_fleet_read's ceiling writes on its 403.
constexpr const char* kCeilingSuffix = "(the ITServiceOwner role does not hold it)";

/// The three callbacks every route module takes, bound to one real AuthRoutes.
struct GateFns {
    RestApiV1::AuthFn auth_fn;
    RestApiV1::PermFn perm_fn;
    RestApiV1::FleetReadFn fleet_fn;
    RestApiV1::AuditFn audit_fn;
};

GateFns make_gate_fns(AuthRoutes& ar) {
    GateFns g;
    g.auth_fn = [&ar](const httplib::Request& req,
                      httplib::Response& res) -> std::optional<auth::Session> {
        return ar.require_auth(req, res);
    };
    g.perm_fn = [&ar](const httplib::Request& req, httplib::Response& res, const std::string& t,
                      const std::string& o) -> bool { return ar.require_permission(req, res, t, o); };
    g.fleet_fn = [&ar](const httplib::Request& req, httplib::Response& res, const std::string& t,
                       const std::string& o) -> authz::FleetReadGate {
        auto result = ar.require_fleet_read(req, res, t, o);
        if (!result)
            return {};
        return {true, result->visible_for_query()};
    };
    g.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };
    return g;
}

} // namespace

// ITServiceOwner holds Execution CRUD under the seeded defaults, so every route admits the
// service token; after the pair is revoked from ITServiceOwner (RbacStore::remove_permission,
// the operator revoke) every route answers the ceiling's 403 although the minter still holds
// a GLOBAL Execution:Read.
TEST_CASE("fleet-read routes real gate: revoking Execution:Read from ITServiceOwner refuses a "
          "service token on the detail fragment and legacy /api/executions and the v1 list",
          "[pg][workflow][executions][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    CeilingRouteRig r{db.dsn()};
    AuthRoutes& ar = *r.svc_auth;
    yuzu::server::test::TestRouteSink sink;

    auto auth_fn = [&ar](const httplib::Request& req,
                         httplib::Response& res) -> std::optional<auth::Session> {
        return ar.require_auth(req, res);
    };
    auto perm_fn = [&ar](const httplib::Request& req, httplib::Response& res,
                         const std::string& t, const std::string& o) -> bool {
        return ar.require_permission(req, res, t, o);
    };
    auto fleet_fn = [&ar](const httplib::Request& req, httplib::Response& res,
                          const std::string& t, const std::string& o) -> authz::FleetReadGate {
        auto result = ar.require_fleet_read(req, res, t, o);
        if (!result)
            return {};
        return {true, result->visible_for_query()};
    };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };

    WorkflowRoutes wf;
    WorkflowRoutes::Deps wd;
    wd.auth_fn = auth_fn;
    wd.perm_fn = perm_fn;
    wd.fleet_read_fn = fleet_fn;
    wd.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                     const std::string&, const std::string&, const std::string&) {};
    wd.execution_tracker = &r.tracker;
    wf.register_routes(sink, std::move(wd));

    execution::Deps ed;
    ed.execution_tracker = &r.tracker;
    ed.perm_fn = perm_fn;
    ed.fleet_read_fn = fleet_fn;
    ed.resolve_session_fn = [&ar](const httplib::Request& req) -> std::optional<auth::Session> {
        return ar.resolve_session(req);
    };
    ed.audit_fn = audit_fn;
    ed.emit_event_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                          const nlohmann::json&) {};
    execution::register_execution_routes(sink, ed);

    RestApiV1 api;
    api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                        /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
                        /*instruction_store=*/nullptr, &r.tracker, /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                        /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                        /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                        /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                        /*metrics_registry=*/nullptr, /*session_revoke_fn=*/{},
                        /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                        /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
                        /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
                        /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
                        /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{},
                        /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                        /*auth_db=*/nullptr, /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
                        /*exec_visible_fn=*/{}, /*list_read_fn=*/{},
                        /*fleet_read_fn=*/fleet_fn);

    const auto svc = r.mint_service("gary", "printers");
    const std::unordered_map<std::string, std::string> hdrs{{"Authorization", "Bearer " + svc}};
    const std::string detail = "/fragments/executions/" + r.x_bob + "/detail";
    const std::vector<std::string> paths = {detail, "/api/executions", "/api/v1/executions"};
    const auto status_of = [&](const std::string& path) {
        auto res = sink.dispatch("GET", path, {}, "application/json", hdrs);
        REQUIRE(res);
        return std::pair{res->status, res->body};
    };

    for (const auto& path : paths) {
        INFO("seeded defaults: " << path);
        CHECK(status_of(path).first == 200);
    }
    REQUIRE(r.rig.rbac.remove_permission("ITServiceOwner", "Execution", "Read").has_value());
    for (const auto& path : paths) {
        INFO("after revoke: " << path);
        auto [code, body] = status_of(path);
        CHECK(code == 403);
        CHECK(has(body, "service-scoped token does not grant Execution:Read"));
        // The suffix only the fleet-read ceiling writes: attributes the 403 to the ceiling,
        // not to require_permission's identical prefix.
        CHECK(has(body, "(the ITServiceOwner role does not hold it)"));
    }
}

// Enrollment:Read is the one pair ITServiceOwner does NOT hold under the seeded defaults, so a
// service token is refused with the ceiling's own body until an operator grants it. The
// minter's ordinary (non-service) token is unaffected throughout.
TEST_CASE("fleet-read routes real gate: Enrollment:Read is refused to a service token under the "
          "seeded defaults and admitted past the ceiling once ITServiceOwner holds it",
          "[pg][enrollment][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    CeilingRouteRig r{db.dsn()};
    REQUIRE(r.rig.rbac.create_role({"EnrollmentReader3526", "", false, 0}).has_value());
    REQUIRE(r.rig.rbac.set_permission({"EnrollmentReader3526", "Enrollment", "Read", "allow"})
                .has_value());
    REQUIRE(r.rig.rbac.assign_role({"user", "gary", "EnrollmentReader3526"}).has_value());

    GateFns g = make_gate_fns(*r.svc_auth);
    yuzu::server::test::TestRouteSink sink;
    EnrollmentDirectoryRoutes routes;
    routes.register_routes(sink, g.auth_fn, g.perm_fn, g.audit_fn, /*directory_sync=*/nullptr,
                           /*auto_approve=*/nullptr, &r.rig.auth_mgr, &r.rig.cfg, r.rig.oidc_mu,
                           g.fleet_fn);

    const auto svc = r.mint_service("gary", "printers");
    const auto ordinary = r.mint_service("gary", "");
    const auto get = [&](const std::string& token) {
        auto res = sink.dispatch("GET", "/api/v1/enrollment/pending-agents", {},
                                 "application/json", {{"Authorization", "Bearer " + token}});
        REQUIRE(res);
        return std::pair{res->status, res->body};
    };

    {
        auto [code, body] = get(svc);
        CHECK(code == 403);
        CHECK(has(body, "service-scoped token does not grant Enrollment:Read"));
        CHECK(has(body, kCeilingSuffix));
        CHECK_FALSE(has(body, "\"permission\""));
    }
    // Admitted by the gate. This rig wires no enrollment store, so the handler's own read
    // answers "enrollment store unavailable" (503); what matters here is that it is neither
    // the ceiling's 403 nor a 401.
    {
        auto [code, body] = get(ordinary);
        CHECK(code == 503);
        CHECK(has(body, "enrollment store unavailable"));
    }

    REQUIRE(r.rig.rbac.set_permission({"ITServiceOwner", "Enrollment", "Read", "allow"})
                .has_value());
    {
        auto [code, body] = get(svc);
        CHECK(code == 503);
        CHECK(has(body, "enrollment store unavailable"));
        CHECK_FALSE(has(body, kCeilingSuffix));
    }
}

// One real route per remaining fleet-read securable that is cheap to construct. Each route
// answers the ceiling's 403 (naming exactly its own pair) after THAT pair alone is revoked
// from ITServiceOwner, and keeps passing the ceiling while only other pairs are revoked, so a
// call site that hands the gate the wrong securable string turns this red.
TEST_CASE("fleet-read routes real gate: each route answers the ceiling for exactly its own "
          "securable",
          "[pg][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    CeilingRouteRig r{db.dsn()};
    REQUIRE(r.rig.rbac.create_role({"FleetReader3526", "", false, 0}).has_value());
    for (const char* securable : {"Response", "Inventory", "Infrastructure", "GuaranteedState"})
        REQUIRE(r.rig.rbac.set_permission({"FleetReader3526", securable, "Read", "allow"})
                    .has_value());
    REQUIRE(r.rig.rbac.assign_role({"user", "gary", "FleetReader3526"}).has_value());

    GateFns g = make_gate_fns(*r.svc_auth);
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    api.register_routes(sink, g.auth_fn, g.perm_fn, g.audit_fn,
                        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                        /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
                        /*instruction_store=*/nullptr, &r.tracker, /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                        /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                        /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                        /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                        /*metrics_registry=*/nullptr, /*session_revoke_fn=*/{},
                        /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                        /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
                        /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
                        /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
                        /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{},
                        /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                        /*auth_db=*/nullptr, /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
                        /*exec_visible_fn=*/{}, /*list_read_fn=*/{},
                        /*fleet_read_fn=*/g.fleet_fn);

    struct Site {
        const char* securable;
        std::string path;
    };
    // Every gate call sits before the route's own store/registry null check, so these answer
    // a non-ceiling status (a 503 for the unwired store) while the ceiling admits.
    const std::vector<Site> sites = {
        {"Response", "/api/v1/executions/x1/responses"},
        {"Inventory", "/api/v1/inventory/software"},
        {"Infrastructure", "/api/v1/devices"},
        {"GuaranteedState", "/api/v1/dex/perf/app/devices?app=a&version=1.0"},
    };
    const auto svc = r.mint_service("gary", "printers");
    const std::unordered_map<std::string, std::string> hdrs{{"Authorization", "Bearer " + svc}};
    const auto get = [&](const Site& site) {
        auto res = sink.dispatch("GET", site.path, {}, "application/json", hdrs);
        REQUIRE(res);
        return std::pair{res->status, res->body};
    };
    const auto ceiling_refused = [&](const Site& site) {
        auto [code, body] = get(site);
        return code == 403 && has(body, kCeilingSuffix);
    };

    for (const auto& site : sites) {
        INFO("seeded defaults: " << site.path);
        CHECK_FALSE(ceiling_refused(site));
        CHECK(get(site).first != 401);
    }
    for (size_t i = 0; i < sites.size(); ++i) {
        REQUIRE(r.rig.rbac.remove_permission("ITServiceOwner", sites[i].securable, "Read")
                    .has_value());
        for (size_t j = 0; j < sites.size(); ++j) {
            INFO("revoked through " << sites[i].securable << ", probing " << sites[j].path);
            if (j <= i) {
                auto [code, body] = get(sites[j]);
                CHECK(code == 403);
                CHECK(has(body, std::string("service-scoped token does not grant ") +
                                    sites[j].securable + ":Read"));
                CHECK(has(body, kCeilingSuffix));
            } else {
                CHECK_FALSE(ceiling_refused(sites[j]));
            }
        }
    }
}
