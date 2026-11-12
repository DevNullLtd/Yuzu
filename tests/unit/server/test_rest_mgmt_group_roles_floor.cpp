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

#include "mgmt_group_error.hpp"
#include "management_group_store.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp" // PG-backed RbacStore (ADR-0041)
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <functional>
#include <regex>
#include <sstream>
#include <optional>
#include <set>
#include <string>
#include <vector>

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

    /// Every audit row the routes wrote, in order (the audit callback always reports success).
    struct AuditRow {
        std::string action;
        std::string result;
        std::string target_id;
        std::string detail;
    };
    std::vector<AuditRow> audits;

    /// Number of recorded rows for `action` with the given `result`.
    [[nodiscard]] std::size_t audit_count(const std::string& action,
                                          const std::string& result) const {
        std::size_t n = 0;
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                ++n;
        return n;
    }

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
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audits.push_back({action, result, target_id, detail});
            return true;
        };

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
// Member and role writes: text validation first, then the store result decides the answer.
// A NUL or other control byte in an identifier is a 400 with a denied audit row and no change;
// a store error is a 503 with a failure audit row; the success row and the 2xx body appear only
// after the store call reported success.
// ---------------------------------------------------------------------------

namespace {

/// Create a static group for a test and return its id.
std::string make_group(GroupRolesHarness& h, const std::string& name) {
    ManagementGroup g;
    g.name = name;
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    return *grp;
}

/// Drop one table of the per-test management-group schema so the next write to it fails.
void drop_mgmt_table(GroupRolesHarness& h, const char* qualified_table) {
    yuzu::server::pg::PgConn conn{PQconnectdb(h.mgmt_bundle.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult d{
        PQexec(conn.get(), (std::string("DROP TABLE ") + qualified_table).c_str())};
    REQUIRE(d.ok());
}

} // namespace

TEST_CASE("POST /management-groups/{id}/members: a control byte in agent_id is refused 400 with a "
          "denied row and no member added",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-add");

    for (const char* body : {R"({"agent_id":"a\u0000b"})", R"({"agent_id":"a\tb"})",
                             R"({"agent_id":"a\u001bb"})", R"({"agent_id":"a\u007fb"})"}) {
        INFO(body);
        h.audits.clear();
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/members", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("\"added\":true") == std::string::npos);
        CHECK(h.mgmt_bundle->get_members(gid).empty());

        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "management_group.add_member");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == gid);
        CHECK(h.audits[0].detail == "invalid_agent_id");
    }
}

TEST_CASE("POST /management-groups/{id}/members: a clean agent_id is added and audited as success",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-add-ok");

    auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/members",
                           R"({"agent_id":"agent-1"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->body.find("\"added\":true") != std::string::npos);
    CHECK(h.mgmt_bundle->get_members(gid).size() == 1);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "management_group.add_member");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_id == gid);
    CHECK(h.audits[0].detail == "agent-1");
}

TEST_CASE("POST /management-groups/{id}/members: a store error answers 503 with a failure row, "
          "never the added body or a success row",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-add-fault");
    drop_mgmt_table(h, "management_group_store.management_group_members");

    auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/members",
                           R"({"agent_id":"agent-1"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("\"added\":true") == std::string::npos);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_number());

    CHECK(h.audit_count("management_group.add_member", "success") == 0);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "management_group.add_member");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].target_id == gid);
    CHECK(h.audits[0].detail == "store_error");
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: a control byte in the agent id is "
          "refused 400 with a denied row and the member is kept",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-remove");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());

    const std::vector<std::string> ids = {
        std::string("agent") + '\0' + "x" + "1",
        std::string("agent") + '\t' + "1",
        std::string("agent") + '\x1b' + "1",
        std::string("agent") + '\x7f' + "1",
    };
    for (const auto& id : ids) {
        INFO("agent id length " << id.size());
        h.audits.clear();
        auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/members/" + id);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("\"removed\":true") == std::string::npos);
        CHECK(h.mgmt_bundle->get_members(gid).size() == 1);

        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "management_group.remove_member");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == gid);
        CHECK(h.audits[0].detail == "invalid_agent_id");
    }

    // A clean id removes the member and audits success.
    h.audits.clear();
    auto ok = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/members/agent-1");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->body.find("\"removed\":true") != std::string::npos);
    CHECK(h.mgmt_bundle->get_members(gid).empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: a store error answers 503 with a "
          "failure row, never the removed body or a success row",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-remove-fault");
    drop_mgmt_table(h, "management_group_store.management_group_members");

    auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/members/agent-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("\"removed\":true") == std::string::npos);

    CHECK(h.audit_count("management_group.remove_member", "success") == 0);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "management_group.remove_member");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].target_id == gid);
    CHECK(h.audits[0].detail == "store_error");
}

TEST_CASE("DELETE /management-groups/{id}/roles: a control byte in a field is refused 400 with a "
          "denied row and the grant is kept",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-unassign");
    REQUIRE(h.mgmt_bundle->assign_role(GroupRoleAssignment{gid, "user", "someone", "Viewer"})
                .has_value());

    struct Case {
        const char* body;
        const char* detail;
    };
    const Case cases[] = {
        {R"({"principal_id":"someone","role_name":"View\u0000er"})", "invalid_role_name"},
        {R"({"principal_id":"someone","role_name":"View\ter"})", "invalid_role_name"},
        {R"({"principal_id":"some\u0000one","role_name":"Viewer"})", "invalid_principal_id"},
        {R"({"principal_id":"some\u001bone","role_name":"Viewer"})", "invalid_principal_id"},
        {R"({"principal_type":"us\u0000er","principal_id":"someone","role_name":"Viewer"})",
         "invalid_principal_type"},
    };
    for (const auto& c : cases) {
        INFO(c.body);
        h.audits.clear();
        auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/roles", c.body,
                                   "application/json");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("\"unassigned\":true") == std::string::npos);
        CHECK(h.mgmt_bundle->get_group_roles(gid).size() == 1);

        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "management_group.unassign_role");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == gid);
        CHECK(h.audits[0].detail == c.detail);
    }

    // A clean request removes the grant and audits success.
    h.audits.clear();
    auto ok = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/roles",
                              R"({"principal_id":"someone","role_name":"Viewer"})",
                              "application/json");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->body.find("\"unassigned\":true") != std::string::npos);
    CHECK(h.mgmt_bundle->get_group_roles(gid).empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail == "someone:Viewer");
}

TEST_CASE("DELETE /management-groups/{id}/roles: a store error answers 503 with a failure row, "
          "never the unassigned body or a success row",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-unassign-fault");
    drop_mgmt_table(h, "management_group_store.management_group_roles");

    auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/roles",
                               R"({"principal_id":"someone","role_name":"Viewer"})",
                               "application/json");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("\"unassigned\":true") == std::string::npos);

    CHECK(h.audit_count("management_group.unassign_role", "success") == 0);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "management_group.unassign_role");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].target_id == gid);
    CHECK(h.audits[0].detail == "store_error");
}

TEST_CASE("POST /management-groups/{id}/roles: a control byte in principal_id is refused 400 with "
          "a denied row and nothing is stored",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-assign");

    for (const char* body : {R"({"principal_id":"some\u0000one","role_name":"Viewer"})",
                             R"({"principal_id":"some\tone","role_name":"Viewer"})",
                             R"({"principal_id":"some\u007fone","role_name":"Operator"})"}) {
        INFO(body);
        h.audits.clear();
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("\"assigned\":true") == std::string::npos);
        CHECK(h.mgmt_bundle->get_group_roles(gid).empty());

        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "management_group.assign_role");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == gid);
        CHECK(h.audits[0].detail == "invalid_principal_id");
    }

    // The clean control still assigns and audits success.
    h.audits.clear();
    auto ok = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                          R"({"principal_id":"someone","role_name":"Viewer"})");
    REQUIRE(ok);
    CHECK(ok->status == 201);
    CHECK(h.mgmt_bundle->get_group_roles(gid).size() == 1);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
}

// ---------------------------------------------------------------------------
// A well-formed id that names no group is a 404 (the caller's mistake), not a retryable 503,
// and it writes no failure row. Ids that are not valid UTF-8 are refused 400 before the store.
// ---------------------------------------------------------------------------

TEST_CASE("POST /management-groups/{id}/members: a group id naming no group answers 404 with no "
          "audit row and no retry hint",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;

    auto res = h.sink.Post("/api/v1/management-groups/deadbeef0000/members",
                           R"({"agent_id":"agent-1"})");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("\"added\":true") == std::string::npos);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["message"] == "group not found");
    CHECK_FALSE(body["error"]["retry_after_ms"].is_number());

    CHECK(h.audits.empty());
    CHECK(h.mgmt_bundle->get_members("deadbeef0000").empty());
}

TEST_CASE("POST /management-groups/{id}/roles: a group id naming no group answers 404 with no "
          "audit row and no retry hint",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;

    auto res = h.sink.Post("/api/v1/management-groups/deadbeef0000/roles",
                           R"({"principal_id":"someone","role_name":"Viewer"})");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("\"assigned\":true") == std::string::npos);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["message"] == "group not found");
    CHECK_FALSE(body["error"]["retry_after_ms"].is_number());

    CHECK(h.audits.empty());
    CHECK(h.mgmt_bundle->get_group_roles("deadbeef0000").empty());
}

TEST_CASE("POST /management-groups/{id}/roles: a store error on an existing group still answers "
          "503 with a failure row",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-assign-fault");
    drop_mgmt_table(h, "management_group_store.management_group_roles");

    auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                           R"({"principal_id":"someone","role_name":"Viewer"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("\"assigned\":true") == std::string::npos);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_number());

    CHECK(h.audit_count("management_group.assign_role", "success") == 0);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "management_group.assign_role");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].target_id == gid);
    CHECK(h.audits[0].detail == "store_error");
}

TEST_CASE("POST /management-groups/{id}/roles: a role name with a control byte is refused 400 "
          "with a denied row, not a 403",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-assign-role");

    for (const char* body : {R"({"principal_id":"someone","role_name":"View\u0000er"})",
                             R"({"principal_id":"someone","role_name":"View\ter"})",
                             R"({"principal_id":"someone","role_name":"View\u001ber"})"}) {
        INFO(body);
        h.audits.clear();
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("role name must be valid text without control characters") !=
              std::string::npos);
        CHECK(h.mgmt_bundle->get_group_roles(gid).empty());

        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "management_group.assign_role");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == gid);
        CHECK(h.audits[0].detail == "invalid_role_name");
    }
}

TEST_CASE("POST /management-groups/{id}/members: a body that is not valid UTF-8 JSON is refused "
          "400 and nothing is added",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-add-utf8");

    const std::string body = std::string(R"({"agent_id":"a)") + "\xff" + R"(b"})";
    auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/members", body);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("\"added\":true") == std::string::npos);
    CHECK(h.mgmt_bundle->get_members(gid).empty());
    CHECK(h.audit_count("management_group.add_member", "success") == 0);
    CHECK(h.audit_count("management_group.add_member", "failure") == 0);
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: an agent id that is not valid UTF-8 is "
          "refused 400 with a denied row and the member is kept",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-validate-remove-utf8");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());

    const std::vector<std::string> ids = {
        std::string("agent") + "\xff" + "1",         // stray byte
        std::string("agent") + "\xc0\x80" + "1",     // overlong NUL
        std::string("agent") + "\xed\xa0\x80" + "1", // surrogate
        std::string("agent") + "\xf4\x90\x80\x80",   // above U+10FFFF
    };
    for (const auto& id : ids) {
        INFO("agent id length " << id.size());
        h.audits.clear();
        auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/members/" + id);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("\"removed\":true") == std::string::npos);
        CHECK(h.mgmt_bundle->get_members(gid).size() == 1);

        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "management_group.remove_member");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == gid);
        CHECK(h.audits[0].detail == "invalid_agent_id");
    }
}

// Dave's review of #7376, item 1: the audit write for a refused value comes AFTER the permission
// gate on every management-group mutation, so a caller with no rights on the group adds no
// audit rows for it. Each case sends a value the handler would otherwise refuse and audit.
TEST_CASE("management-group mutations: a caller without ManagementGroup:Write gets 403 and no "
          "audit row, whatever the body holds",
          "[pg][rest][mgmt_group][validation][authz]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-gate-before-audit");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());
    REQUIRE(h.mgmt_bundle->assign_role(GroupRoleAssignment{gid, "user", "someone", "Viewer"})
                .has_value());
    h.perm_override = [](const std::string& securable, const std::string& op) {
        return !(securable == "ManagementGroup" && op == "Write");
    };

    SECTION("assign role: a role name with a control byte") {
        for (const char* body : {R"({"principal_id":"someone","role_name":"View\u0000er"})",
                                 R"({"principal_id":"some\u0000one","role_name":"Viewer"})",
                                 R"({"principal_type":"us\u0000er","principal_id":"someone",)"
                                 R"("role_name":"Viewer"})"}) {
            INFO(body);
            auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles", body);
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(h.audits.empty());
        }
    }

    SECTION("unassign role: a field with a control byte") {
        for (const char* body : {R"({"principal_id":"someone","role_name":"View\u0000er"})",
                                 R"({"principal_id":"some\u0000one","role_name":"Viewer"})"}) {
            INFO(body);
            auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/roles",
                                       body, "application/json");
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(h.audits.empty());
        }
        CHECK(h.mgmt_bundle->get_group_roles(gid).size() == 1);
    }

    SECTION("add member: an agent id with a control byte") {
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/members",
                               R"({"agent_id":"a\u0000b"})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.audits.empty());
    }

    SECTION("remove member: an agent id that is not valid UTF-8") {
        auto res = h.sink.dispatch("DELETE", "/api/v1/management-groups/" + gid + "/members/agent" +
                                                 std::string("\xff") + "1");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.audits.empty());
        CHECK(h.mgmt_bundle->get_members(gid).size() == 1);
    }

    SECTION("an ITServiceOwner of the group still gets the 400 and the denied row") {
        REQUIRE(h.mgmt_bundle->assign_role(GroupRoleAssignment{gid, "user", "tester", "ITServiceOwner"})
                    .has_value());
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                               R"({"principal_id":"someone","role_name":"View\u0000er"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].detail == "invalid_role_name");
    }
}

// Dave's review of #7376, item 2: RbacStore::validate_assignment echoes the caller's
// principal_type, so a value holding the word "failed" must be a 400 with no store-fault row.
TEST_CASE("POST /management-groups/{id}/roles: a principal_type containing 'failed' is a 400, "
          "never a retryable 503 with a failure row",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-classifier");

    for (const char* type : {"failed", "unfailed", "login failed"}) {
        INFO(type);
        h.audits.clear();
        const std::string body = std::string(R"({"principal_type":")") + type +
                                 R"(","principal_id":"someone","role_name":"Viewer"})";
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        // The route's own closed-set check answered, not the store's echo of the value.
        CHECK(res->body.find("principal_type must be user or group") != std::string::npos);
        CHECK(res->body.find(type) == std::string::npos);
        CHECK(h.mgmt_bundle->get_group_roles(gid).empty());
        CHECK(h.audits.empty());
    }

    SECTION("engine passes the route's check and is refused by the store with a 400") {
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                               R"({"principal_type":"engine","principal_id":"engine:x",)"
                               R"("role_name":"Viewer"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("engine principals cannot hold scoped role assignments") !=
              std::string::npos);
        CHECK(h.mgmt_bundle->get_group_roles(gid).empty());
        CHECK(h.audit_count("management_group.assign_role", "failure") == 0);
    }
}

// The classifier REST and MCP share. Pure (no database).
TEST_CASE("mgmt_group_error: store faults are the fixed messages, matched at the start",
          "[rest][mcp][mgmt_group][validation][mgmt_group_error]") {
    using yuzu::server::mgmt_group_error_is_store_fault;

    SECTION("every store fault message is a fault") {
        for (const char* msg : {"database not open", "pool acquire timed out",
                                "failed to resolve ancestor chain (store degraded)",
                                "failed to create group: connection lost", "query failed: boom",
                                "update failed: boom", "delete failed: boom",
                                "add_member failed: boom", "remove_member failed: boom",
                                "assign_role failed: boom", "unassign_role failed: boom"}) {
            INFO(msg);
            CHECK(mgmt_group_error_is_store_fault(msg));
        }
    }

    SECTION("a validation message is not, even when it echoes the word failed") {
        for (const char* msg : {"unrecognized principal_type 'failed'",
                                "unrecognized principal_type 'assign_role failed: x'",
                                "unrecognized principal_type 'database not open'",
                                "group name cannot be empty", "parent group not found",
                                "maximum hierarchy depth (5) exceeded",
                                "re-parenting would create a cycle",
                                "engine principals cannot hold scoped role assignments in this "
                                "release",
                                "principal_id in the reserved 'engine:' namespace may only be "
                                "assigned under principal_type=\"engine\"",
                                "engine principals cannot be granted the admin/full-access role "
                                "'failed' — no admin, ever (design §4.2)",
                                "group not found", "a group with that name already exists", ""}) {
            INFO(msg);
            CHECK_FALSE(mgmt_group_error_is_store_fault(msg));
        }
    }
}

// Tripwire, closed-world: every string literal handed to std::unexpected in
// management_group_store.cpp is either classified as a store fault by the shared classifier or is
// named below as a validation message / a read-path fault no classifier call site reaches. A new
// message of ANY wording written as a literal here therefore forces a decision. (A message built another way,
// std::format or a named constant, is not seen by the scan; the floors below fail the test if
// the literal shapes change enough to drop the scan's coverage.)
TEST_CASE("mgmt_group_error: every std::unexpected literal in management_group_store.cpp is "
          "classified or named",
          "[rest][mcp][mgmt_group][validation][mgmt_group_error]") {
    namespace fs = std::filesystem;
    std::ifstream in(fs::path(YUZU_SERVER_SRC_DIR) / "management_group_store.cpp",
                     std::ios::binary);
    REQUIRE(in);
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string src = ss.str();

    // Validation answers: the caller's mistake, never retryable.
    const std::set<std::string> validation = {
        "group name cannot be empty",
        "group cannot be its own parent",
        "parent group not found",
        "maximum hierarchy depth (5) exceeded",
        "re-parenting would create a cycle",
        "group not found",
        "cannot delete root group",
        "engine principals cannot hold scoped role assignments in this release",
        "a group with that name already exists",
    };
    // Faults of the read paths (get_assignments_for_principal, get_member_agents_in_subtrees),
    // which count their own degrade metric and never reach the REST/MCP write classifier.
    const std::set<std::string> read_path_faults = {
        "management group store not open",
        "management group store: pool acquire timed out",
    };

    const std::regex re(R"re(std::unexpected\(\s*(?:std::string\()?\s*"((?:[^"\\]|\\.)*)")re");
    std::size_t seen = 0, faults = 0, validations = 0, reads = 0;
    for (std::sregex_iterator it(src.begin(), src.end(), re), end; it != end; ++it) {
        const std::string lit = (*it)[1].str();
        ++seen;
        INFO("literal: " << lit);
        if (yuzu::server::mgmt_group_error_is_store_fault(lit)) {
            ++faults;
        } else if (validation.count(lit) != 0) {
            ++validations;
        } else if (read_path_faults.count(lit) != 0) {
            ++reads;
        } else {
            FAIL_CHECK("an unclassified store message: add its prefix to mgmt_group_error.hpp "
                       "or name it in this test");
        }
    }
    // The file holds 46 literals today (28 faults, 14 validation occurrences of 9 distinct
    // messages, 4 read-path). Minimum floors equal to those counts, so a change in literal shape
    // cannot silently shrink what the scan sees. Messages RbacStore::validate_assignment returns
    // through `v.error()` are not literals in this file and are outside the scan.
    CHECK(seen >= 46);
    CHECK(faults >= 28);
    CHECK(validations >= 14);
    CHECK(reads >= 4);
}

// Dave's review of #7376, item 2 (the REST pre-validation of principal_type): a body field of
// the wrong JSON type must answer 400 before the gate, never throw out of the accessor as a 500,
// and never degrade to the default (a numeric principal_type must not become "user").
TEST_CASE("POST /management-groups/{id}/roles: a wrong-typed or non-object body is a 400 with no "
          "audit row and nothing assigned",
          "[pg][rest][mgmt_group][validation]") {
    GroupRolesHarness h;
    const std::string gid = make_group(h, "mg-body-types");

    for (const char* body : {R"({"principal_type":5,"principal_id":"someone","role_name":"Viewer"})",
                             R"({"principal_type":null,"principal_id":"someone","role_name":"Viewer"})",
                             R"({"principal_type":["user"],"principal_id":"someone",)"
                             R"("role_name":"Viewer"})",
                             R"({"principal_id":7,"role_name":"Viewer"})",
                             R"({"principal_id":"someone","role_name":{"a":1}})",
                             R"(["user"])", R"("user")", "5", "null"}) {
        INFO(body);
        h.audits.clear();
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.mgmt_bundle->get_group_roles(gid).empty());
        CHECK(h.audits.empty());
    }

    SECTION("a caller without rights gets the same 400 for a body that is not an object") {
        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !(securable == "ManagementGroup" && op == "Write");
        };
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles", R"(["user"])");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.audits.empty());
    }

    SECTION("a well-typed body is unchanged") {
        auto res = h.sink.Post("/api/v1/management-groups/" + gid + "/roles",
                               R"({"principal_id":"someone","role_name":"Viewer"})");
        REQUIRE(res);
        CHECK(res->status == 201);
        CHECK(h.mgmt_bundle->get_group_roles(gid).size() == 1);
    }
}
