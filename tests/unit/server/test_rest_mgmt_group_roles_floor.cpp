/**
 * test_rest_mgmt_group_roles_floor.cpp — #2376, the THIRD surface found emitting
 * authorization topology under a securable outside the floor.
 *
 * `GET /api/v1/management-groups/{id}/roles` returns, for every assignment in the
 * group, `{group_id, principal_type, principal_id, role_name}` — i.e. who holds
 * what role. That is authorization topology in exactly the sense the #2376 floor
 * exists to protect, and the whole body is topology: unlike
 * `/api/v1/discover/permissions` there is no taxonomy half to preserve.
 *
 * It was gated ONLY on `ManagementGroup:Read`, which is deliberately NOT floored
 * (it gates ordinary group metadata and member lists; flooring it would be the
 * too-coarse mistake the floor avoids with `Security:Read`). So on an RBAC-off
 * install — the default — the legacy Read-allow handed the scoped role-assignment
 * graph to any authenticated session.
 *
 * Found by Hermes (pre-submission security pass) AFTER a 14-agent governance run
 * and a two-model adversarial panel had both passed the change. It is the third
 * instance of one shape: the floor SET was derived from "which securables gate the
 * routes this change touches" rather than "which routes emit authorization
 * topology". The fix is a second REQUIRED permission — the floored
 * `UserManagement:Read`, which already gates the equivalent `/api/v1/rbac/roles`.
 *
 * PG-gated: ManagementGroupStore is a Postgres store (ADR-0042), so the helper
 * SKIPs when YUZU_TEST_POSTGRES_DSN is unset and FAILs when it is set but broken.
 */

#include "management_group_store.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp" // PG-backed RbacStore (ADR-0041)
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

using namespace yuzu::server;

namespace {

struct GroupRolesHarness {
    yuzu::test::ManagementGroupStorePg mgmt_bundle; // SKIPs without a PG DSN
    yuzu::test::RbacStorePg rbac_bundle;             // SKIPs without a PG DSN
    RbacStore& rbac = *rbac_bundle;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    /// Deny a specific (securable, operation) while leaving every other gate
    /// intact — `grant everything` cannot express "route gate yes, second gate no".
    std::function<bool(const std::string&, const std::string&)> perm_override{};

    /// guardian-confinement-2298 PR3 §3e sweep finding: empty ⇒ an ordinary
    /// session; a test sets this to prove the ITServiceOwner-of-this-group
    /// fallback is skipped for a service-scoped token.
    std::string mock_token_scope_service;

    GroupRolesHarness() {
        REQUIRE(rbac.is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::user;
            s.token_scope_service = mock_token_scope_service;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            if (perm_override && !perm_override(type, op)) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&,
                           const std::string&) -> bool { return true; };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/&rbac,
                            /*mgmt_store=*/&*mgmt_bundle,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr);
    }
};

} // namespace

TEST_CASE("GET /management-groups/{id}/roles requires the floored UserManagement:Read",
          "[pg][rest][mgmt_group][authz][floor]") {
    GroupRolesHarness h;

    // A group id must match the route's [a-f0-9]+ pattern.
    ManagementGroup g;
    g.name = "floor-test";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;

    SECTION("denied without UserManagement:Read, even holding ManagementGroup:Read") {
        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !(securable == "UserManagement" && op == "Read");
        };
        auto res = h.sink.Get("/api/v1/management-groups/" + gid + "/roles");
        REQUIRE(res);
        // This is the assertion that closes the leak: the route's own
        // ManagementGroup:Read is satisfied, and it still refuses.
        CHECK(res->status == 403);
    }

    SECTION("allowed when the caller holds both") {
        auto res = h.sink.Get("/api/v1/management-groups/" + gid + "/roles");
        REQUIRE(res);
        CHECK(res->status == 200);
    }

    SECTION("ITServiceOwner OF THIS GROUP is allowed without UserManagement:Read") {
        // Hermes pass 2 caught this as a regression the first fix introduced:
        // ITServiceOwner is the GROUP-SCOPED admin and holds ManagementGroup:Read but
        // no UserManagement grant at all, while the POST/DELETE handlers on this same
        // path already let it MUTATE assignments via an ITServiceOwner fallback. A
        // read-denied/write-allowed posture is both a broken workflow and incoherent.
        auto assigned = h.mgmt_bundle->assign_role(
            GroupRoleAssignment{gid, "user", "tester", "ITServiceOwner"});
        REQUIRE(assigned.has_value());

        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !(securable == "UserManagement" && op == "Read");
        };
        auto res = h.sink.Get("/api/v1/management-groups/" + gid + "/roles");
        REQUIRE(res);
        CHECK(res->status == 200);
    }

    SECTION("a non-owner is still denied even when someone ELSE owns the group") {
        // The fallback must be scoped to the CALLER, not merely to the group having
        // an owner — otherwise any group with an ITServiceOwner would be world-readable.
        auto assigned = h.mgmt_bundle->assign_role(
            GroupRoleAssignment{gid, "user", "someone-else", "ITServiceOwner"});
        REQUIRE(assigned.has_value());

        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !(securable == "UserManagement" && op == "Read");
        };
        auto res = h.sink.Get("/api/v1/management-groups/" + gid + "/roles");
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    SECTION("still denied when the route's OWN gate fails — the first gate is unchanged") {
        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !(securable == "ManagementGroup" && op == "Read");
        };
        auto res = h.sink.Get("/api/v1/management-groups/" + gid + "/roles");
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    SECTION("guardian-confinement-2298 §3e: ITServiceOwner OF THIS GROUP does NOT "
             "save a service-scoped token") {
        auto assigned = h.mgmt_bundle->assign_role(
            GroupRoleAssignment{gid, "user", "tester", "ITServiceOwner"});
        REQUIRE(assigned.has_value());

        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !(securable == "UserManagement" && op == "Read");
        };
        h.mock_token_scope_service = "printers";
        auto res = h.sink.Get("/api/v1/management-groups/" + gid + "/roles");
        REQUIRE(res);
        CHECK(res->status == 403);
    }
}

// ---------------------------------------------------------------------------
// guardian-confinement-2298 PR3 §3e sweep finding: POST/DELETE on this same
// path had ZERO existing test coverage and used a direct
// rbac_store->check_permission call bypassing require_permission (the §3a
// flip) entirely. Fixed to route through perm_fn's probe-response form
// (matching the GET handler above), with the ITServiceOwner-of-this-group
// fallback skipped for a service-scoped token — same reasoning as GET's new
// section above.
// ---------------------------------------------------------------------------

TEST_CASE("POST /management-groups/{id}/roles: fleet-wide ManagementGroup:Write "
          "grant is sufficient (regression)",
          "[pg][rest][mgmt_group][authz][security_scope]") {
    GroupRolesHarness h;
    ManagementGroup g;
    g.name = "floor-test-post";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;

    auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                           R"({"principal_id":"someone","role_name":"Viewer"})");
    REQUIRE(res);
    CHECK(res->status == 201);
}

TEST_CASE("POST /management-groups/{id}/roles: ITServiceOwner OF THIS GROUP is "
          "allowed without ManagementGroup:Write (regression)",
          "[pg][rest][mgmt_group][authz][security_scope]") {
    GroupRolesHarness h;
    ManagementGroup g;
    g.name = "floor-test-post2";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;
    auto assigned = h.mgmt_bundle->assign_role(
        GroupRoleAssignment{gid, "user", "tester", "ITServiceOwner"});
    REQUIRE(assigned.has_value());

    h.perm_override = [](const std::string& securable, const std::string& op) {
        return !(securable == "ManagementGroup" && op == "Write");
    };
    auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                           R"({"principal_id":"someone","role_name":"Viewer"})");
    REQUIRE(res);
    CHECK(res->status == 201);
}

TEST_CASE("POST /management-groups/{id}/roles: a service-scoped token is denied "
          "even as ITServiceOwner of the group",
          "[pg][rest][mgmt_group][authz][security_scope]") {
    GroupRolesHarness h;
    ManagementGroup g;
    g.name = "floor-test-post3";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;
    auto assigned = h.mgmt_bundle->assign_role(
        GroupRoleAssignment{gid, "user", "tester", "ITServiceOwner"});
    REQUIRE(assigned.has_value());

    h.perm_override = [](const std::string& securable, const std::string& op) {
        return !(securable == "ManagementGroup" && op == "Write");
    };
    h.mock_token_scope_service = "printers";
    auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                           R"({"principal_id":"someone","role_name":"Viewer"})");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("DELETE /management-groups/{id}/roles: fleet-wide ManagementGroup:Write "
          "grant is sufficient (regression)",
          "[pg][rest][mgmt_group][authz][security_scope]") {
    GroupRolesHarness h;
    ManagementGroup g;
    g.name = "floor-test-del";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;
    auto assigned = h.mgmt_bundle->assign_role(
        GroupRoleAssignment{gid, "user", "someone", "Viewer"});
    REQUIRE(assigned.has_value());

    // TestRouteSink's Delete() convenience wrapper takes no body; the
    // handler parses one, so dispatch() is called directly (mirrors Post/Put).
    auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/roles",
                               R"({"principal_id":"someone","role_name":"Viewer"})",
                               "application/json");
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("DELETE /management-groups/{id}/roles: a service-scoped token is denied "
          "even as ITServiceOwner of the group",
          "[pg][rest][mgmt_group][authz][security_scope]") {
    GroupRolesHarness h;
    ManagementGroup g;
    g.name = "floor-test-del3";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;
    auto assigned = h.mgmt_bundle->assign_role(
        GroupRoleAssignment{gid, "user", "tester", "ITServiceOwner"});
    REQUIRE(assigned.has_value());

    h.perm_override = [](const std::string& securable, const std::string& op) {
        return !(securable == "ManagementGroup" && op == "Write");
    };
    h.mock_token_scope_service = "printers";
    auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/roles",
                               R"({"principal_id":"tester","role_name":"ITServiceOwner"})",
                               "application/json");
    REQUIRE(res);
    CHECK(res->status == 403);
}
