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
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePgShared
#include "test_mgmt_group_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp" // PG-backed RbacStore (ADR-0041)
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>

using namespace yuzu::server;

namespace {

struct GroupRolesHarness {
    yuzu::test::ManagementGroupStorePg mgmt_bundle; // SKIPs without a PG DSN
    yuzu::test::RbacStorePg rbac_bundle;             // SKIPs without a PG DSN
    RbacStore& rbac = *rbac_bundle;
    /// Only the token-mint cases wire a token store (CRUD-only, so the process-wide shared clone
    /// is enough); every other case leaves the route's token_store null as before.
    std::optional<yuzu::test::ApiTokenStorePgShared> api_tokens;
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

    /// Owner-arm eligibility inputs (mgmt_group_owner_gate.hpp): the MCP tier and the
    /// principal class the mock session carries. Defaults are an ordinary human session.
    std::string mock_mcp_tier;
    std::string mock_principal_kind{"human"};

    explicit GroupRolesHarness(bool with_token_store = false) {
        REQUIRE(rbac.is_open());
        if (with_token_store)
            api_tokens.emplace();

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::user;
            s.token_scope_service = mock_token_scope_service;
            s.mcp_tier = mock_mcp_tier;
            s.principal_kind = mock_principal_kind;
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
                            /*token_store=*/api_tokens ? api_tokens->get() : nullptr,
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

TEST_CASE("POST /management-groups/{id}/roles: ForensicsAnalyst is refused at group scope exactly "
          "like the other fleet-only roles (#4990)",
          "[pg][rest][mgmt_group][authz][security_scope][forensics_analyst]") {
    GroupRolesHarness h;
    ManagementGroup g;
    g.name = "floor-test-fa";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;

    // The refusal is the same status as every other non-delegable role, and nothing is stored.
    for (const char* role : {"ForensicsAnalyst", "Reviewer", "Administrator"}) {
        INFO(role);
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                               std::string(R"({"principal_id":"someone","role_name":")") + role +
                                   R"("})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body.find("only Operator and Viewer roles can be delegated") != std::string::npos);
    }
    CHECK(h.mgmt_bundle->get_group_roles(gid).empty());

    // Operator is still delegable, so the refusal above is the role and not the route.
    auto ok = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                          R"({"principal_id":"someone","role_name":"Operator"})");
    REQUIRE(ok);
    CHECK(ok->status == 201);
}

// The group-scope allow-list is the ONLY thing keeping a management-group-scoped Forensics:Read
// grant from being authored through this route: nothing else can author a group-scoped grant of a
// role that holds it. The Forensics response-read resolver has no scoped branch (#4990), so this
// pin guards the older per-device scoped Forensics gate (app_usage_routes.cpp and the MCP
// get_agent_app_usage tool), a different consumer outside that finding. This case derives the
// answer from the real handler and the real seeded role list, so widening the list fails here by
// name rather than passing because a hand-copied list in a test moved with it.
TEST_CASE("POST /management-groups/{id}/roles: the group-scope allow-list is exactly "
          "{Operator, Viewer}; widening it makes the per-device scoped Forensics:Read gate reachable "
          "(re-review that gate, #4990)",
          "[pg][rest][mgmt_group][authz][security_scope][forensics_analyst]") {
    GroupRolesHarness h;
    ManagementGroup g;
    g.name = "floor-test-allowlist";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;

    // Every seeded role, plus names that are not roles at all.
    std::set<std::string> names;
    for (const auto& r : h.rbac.list_roles())
        names.insert(r.name);
    REQUIRE(names.contains("ForensicsAnalyst"));
    REQUIRE(names.contains("Administrator"));
    names.insert({"NoSuchRole", "operator", "VIEWER"});

    std::set<std::string> accepted;
    int n = 0;
    for (const auto& role : names) {
        INFO(role);
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                               R"({"principal_id":"p)" + std::to_string(n++) +
                                   R"(","role_name":")" + role + R"("})");
        REQUIRE(res);
        if (res->status == 201)
            accepted.insert(role);
        else
            CHECK(res->status == 403);
    }
    CHECK(accepted == std::set<std::string>{"Operator", "Viewer"});
    CHECK(h.mgmt_bundle->get_group_roles(gid).size() == 2);
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

// ---------------------------------------------------------------------------
// One owner-arm predicate (mgmt_group_owner_gate.hpp): the ITServiceOwner-of-this-group
// fallback on GET/POST/DELETE refuses MCP-tier and engine-classed sessions, and DELETE limits
// a caller admitted ONLY by that arm to the roles POST can delegate.
// ---------------------------------------------------------------------------

namespace {

struct OwnerArmFixture {
    GroupRolesHarness h;
    std::string gid;

    OwnerArmFixture(const char* group_name, bool caller_is_owner = true,
                    bool with_token_store = false)
        : h(with_token_store) {
        ManagementGroup g;
        g.name = group_name;
        g.membership_type = "static";
        g.created_by = "tester";
        auto grp = h.mgmt_bundle->create_group(g);
        REQUIRE(grp.has_value());
        gid = *grp;
        if (caller_is_owner) {
            REQUIRE(h.mgmt_bundle
                        ->assign_role(GroupRoleAssignment{gid, "user", "tester", "ITServiceOwner"})
                        .has_value());
        }
    }

    // The fleet-wide arm is denied for every case below, so only the owner arm can admit.
    void deny_fleet_wide() {
        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !((securable == "ManagementGroup" && op == "Write") ||
                     (securable == "UserManagement" && op == "Read"));
        };
    }

    std::unique_ptr<httplib::Response> del(const std::string& body) {
        return h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/roles", body,
                               "application/json");
    }
};

constexpr const char* kViewerRow = R"({"principal_id":"someone","role_name":"Viewer"})";

} // namespace

TEST_CASE("management-group roles routes: the owner arm refuses an MCP-tier session on REST",
          "[pg][rest][mgmt_group][authz][owner_gate]") {
    OwnerArmFixture f("owner-gate-tier");
    f.deny_fleet_wide();
    f.h.mock_mcp_tier = "readonly";

    auto get = f.h.sink.Get("/api/v1/management-groups/" + f.gid + "/roles");
    REQUIRE(get);
    CHECK(get->status == 403);

    auto post = f.h.sink.Post("/api/v1/management-groups/" + f.gid + "/roles", kViewerRow);
    REQUIRE(post);
    CHECK(post->status == 403);

    auto del = f.del(kViewerRow);
    REQUIRE(del);
    CHECK(del->status == 403);
    CHECK(f.h.mgmt_bundle->get_group_roles(f.gid).size() == 1); // only the owner row

    // The same caller without a tier is still admitted: the refusal is the tier.
    f.h.mock_mcp_tier.clear();
    auto ok = f.h.sink.Get("/api/v1/management-groups/" + f.gid + "/roles");
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("management-group roles routes: the owner arm refuses an engine-classed session",
          "[pg][rest][mgmt_group][authz][owner_gate]") {
    OwnerArmFixture f("owner-gate-engine");
    f.deny_fleet_wide();
    f.h.mock_principal_kind = "engine";

    auto get = f.h.sink.Get("/api/v1/management-groups/" + f.gid + "/roles");
    REQUIRE(get);
    CHECK(get->status == 403);

    auto post = f.h.sink.Post("/api/v1/management-groups/" + f.gid + "/roles", kViewerRow);
    REQUIRE(post);
    CHECK(post->status == 403);

    auto del = f.del(kViewerRow);
    REQUIRE(del);
    CHECK(del->status == 403);
    CHECK(f.h.mgmt_bundle->get_group_roles(f.gid).size() == 1);
}

TEST_CASE("DELETE /management-groups/{id}/roles: an owner-arm caller removes only Operator and "
          "Viewer rows",
          "[pg][rest][mgmt_group][authz][owner_gate]") {
    OwnerArmFixture f("owner-gate-delete");
    REQUIRE(f.h.mgmt_bundle->assign_role(GroupRoleAssignment{f.gid, "user", "peer", "ITServiceOwner"})
                .has_value());
    REQUIRE(f.h.mgmt_bundle->assign_role(GroupRoleAssignment{f.gid, "user", "op1", "Operator"})
                .has_value());
    f.deny_fleet_wide();

    // A peer owner row is refused with removal wording (not POST's "delegated" text);
    // nothing is removed.
    auto refused = f.del(R"({"principal_id":"peer","role_name":"ITServiceOwner"})");
    REQUIRE(refused);
    CHECK(refused->status == 403);
    CHECK(refused->body.find("can remove only Operator and Viewer roles") != std::string::npos);
    CHECK(refused->body.find("can be delegated") == std::string::npos);
    CHECK(f.h.mgmt_bundle->get_group_roles(f.gid).size() == 3);

    // An Operator row is removed.
    auto removed = f.del(R"({"principal_id":"op1","role_name":"Operator"})");
    REQUIRE(removed);
    CHECK(removed->status == 200);
    CHECK(f.h.mgmt_bundle->get_group_roles(f.gid).size() == 2);
}

TEST_CASE("DELETE /management-groups/{id}/roles: a fleet-wide ManagementGroup:Write holder may "
          "still remove an ITServiceOwner row",
          "[pg][rest][mgmt_group][authz][owner_gate]") {
    OwnerArmFixture f("owner-gate-delete-fleet", /*caller_is_owner=*/false);
    REQUIRE(f.h.mgmt_bundle->assign_role(GroupRoleAssignment{f.gid, "user", "peer", "ITServiceOwner"})
                .has_value());

    auto res = f.del(R"({"principal_id":"peer","role_name":"ITServiceOwner"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.h.mgmt_bundle->get_group_roles(f.gid).empty());
}

TEST_CASE("GET /management-groups/{id}/roles: a human session without a tier is still admitted "
          "by the owner arm (positive pin)",
          "[pg][rest][mgmt_group][authz][owner_gate]") {
    OwnerArmFixture f("owner-gate-positive");
    f.deny_fleet_wide();
    auto res = f.h.sink.Get("/api/v1/management-groups/" + f.gid + "/roles");
    REQUIRE(res);
    CHECK(res->status == 200);
}

// ---------------------------------------------------------------------------
// The REST service-scoped token mint (POST /api/v1/tokens with scope_service) decides the SAME
// owner arm, against the "Service: <name>" group, with the fleet-wide ManagementGroup:Write
// denied. The arm is reached only with RBAC enabled.
// ---------------------------------------------------------------------------

namespace {

constexpr const char* kServiceGroup = "Service: payroll";

struct MintFixture : OwnerArmFixture {
    explicit MintFixture(bool caller_is_owner = true)
        : OwnerArmFixture(kServiceGroup, caller_is_owner, /*with_token_store=*/true) {
        REQUIRE(h.rbac.set_rbac_enabled(true).has_value());
        deny_fleet_wide();
    }
};

auto mint_service_token(MintFixture& f) {
    const auto expires_at = static_cast<std::int64_t>(std::time(nullptr)) + 3600;
    return f.h.sink.Post("/api/v1/tokens",
                         R"({"name":"owner-gate-mint","scope_service":"payroll","expires_at":)" +
                             std::to_string(expires_at) + "}");
}

} // namespace

TEST_CASE("POST /tokens: an ITServiceOwner of the service group mints a service-scoped token",
          "[pg][rest][token][authz][owner_gate]") {
    MintFixture f;
    auto res = mint_service_token(f);
    REQUIRE(res);
    CHECK(res->status == 201);
    const auto tokens = f.h.api_tokens.value()->list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 1);
}

TEST_CASE("POST /tokens: a caller who does not own the service group is refused",
          "[pg][rest][token][authz][owner_gate]") {
    MintFixture f(/*caller_is_owner=*/false);
    auto res = mint_service_token(f);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("ITServiceOwner authority required") != std::string::npos);
    const auto tokens = f.h.api_tokens.value()->list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->empty());
}

TEST_CASE("POST /tokens: the owner arm refuses an MCP-tier session on REST",
          "[pg][rest][token][authz][owner_gate]") {
    MintFixture f;
    f.h.mock_mcp_tier = "readonly";
    auto res = mint_service_token(f);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("ITServiceOwner authority required") != std::string::npos);

    // The same caller without a tier is admitted: the refusal above is the tier.
    f.h.mock_mcp_tier.clear();
    auto ok = mint_service_token(f);
    REQUIRE(ok);
    CHECK(ok->status == 201);
}

TEST_CASE("POST /tokens: the owner arm refuses an engine-classed session",
          "[pg][rest][token][authz][owner_gate]") {
    MintFixture f;
    f.h.mock_principal_kind = "engine";
    auto res = mint_service_token(f);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("ITServiceOwner authority required") != std::string::npos);
}
