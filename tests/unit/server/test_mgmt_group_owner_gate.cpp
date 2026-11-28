/**
 * test_mgmt_group_owner_gate.cpp — the ONE management-group owner-arm predicate
 * (`mgmt_group_owner_gate.hpp`).
 *
 * Pure: no store, no network, no Postgres. The thin shell that reads a group's
 * assignment rows (`group_owner_admits`) is exercised end to end by the [pg]
 * cases in test_rest_mgmt_group_roles_floor.cpp and test_mcp_server.cpp.
 */

#include "mgmt_group_owner_gate.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using yuzu::server::GroupRoleAssignment;
using yuzu::server::holds_group_owner_role;
using yuzu::server::owner_arm_eligible;
using yuzu::server::RbacAdminSurface;

namespace {

yuzu::server::auth::Session make_session(std::string tier, std::string scope_service,
                                         bool engine_by_kind, bool engine_by_source) {
    yuzu::server::auth::Session s;
    s.username = "alice";
    s.mcp_tier = std::move(tier);
    s.token_scope_service = std::move(scope_service);
    if (engine_by_kind)
        s.principal_kind = "engine";
    if (engine_by_source)
        s.auth_source = "engine_token";
    return s;
}

GroupRoleAssignment row(std::string type, std::string principal, std::string role) {
    GroupRoleAssignment g;
    g.group_id = "g1";
    g.principal_type = std::move(type);
    g.principal_id = std::move(principal);
    g.role_name = std::move(role);
    return g;
}

} // namespace

TEST_CASE("owner_arm_eligible: REST refuses service-scoped, any MCP tier and engine sessions",
          "[server][mgmt_group][owner_gate]") {
    CHECK(owner_arm_eligible(make_session("", "", false, false), RbacAdminSurface::kRest));
    for (const char* tier : {"readonly", "operator", "supervised"}) {
        CAPTURE(tier);
        CHECK_FALSE(owner_arm_eligible(make_session(tier, "", false, false),
                                       RbacAdminSurface::kRest));
    }
    CHECK_FALSE(owner_arm_eligible(make_session("", "svc", false, false),
                                   RbacAdminSurface::kRest));
    CHECK_FALSE(owner_arm_eligible(make_session("", "", true, false), RbacAdminSurface::kRest));
    CHECK_FALSE(owner_arm_eligible(make_session("", "", false, true), RbacAdminSurface::kRest));
}

TEST_CASE("owner_arm_eligible: MCP leaves the tier to the tool ladder, refuses service-scoped "
          "and engine sessions",
          "[server][mgmt_group][owner_gate]") {
    // Every /mcp/v1/ session carries a non-empty tier, so a tier rule here would delete the
    // documented owner arm of both MCP tools.
    for (const char* tier : {"", "readonly", "operator", "supervised"}) {
        CAPTURE(tier);
        CHECK(owner_arm_eligible(make_session(tier, "", false, false), RbacAdminSurface::kMcp));
    }
    CHECK_FALSE(owner_arm_eligible(make_session("operator", "svc", false, false),
                                   RbacAdminSurface::kMcp));
    // Both engine discriminators count, on their own.
    CHECK_FALSE(owner_arm_eligible(make_session("operator", "", true, false),
                                   RbacAdminSurface::kMcp));
    CHECK_FALSE(owner_arm_eligible(make_session("operator", "", false, true),
                                   RbacAdminSurface::kMcp));
}

TEST_CASE("holds_group_owner_role matches only a user principal holding ITServiceOwner",
          "[server][mgmt_group][owner_gate]") {
    CHECK(holds_group_owner_role({row("user", "alice", "ITServiceOwner")}, "alice"));
    CHECK(holds_group_owner_role(
        {row("user", "bob", "Viewer"), row("user", "alice", "ITServiceOwner")}, "alice"));

    CHECK_FALSE(holds_group_owner_role({}, "alice"));
    CHECK_FALSE(holds_group_owner_role({row("group", "alice", "ITServiceOwner")}, "alice"));
    CHECK_FALSE(holds_group_owner_role({row("engine", "alice", "ITServiceOwner")}, "alice"));
    CHECK_FALSE(holds_group_owner_role({row("user", "alice", "Operator")}, "alice"));
    CHECK_FALSE(holds_group_owner_role({row("user", "alice", "Viewer")}, "alice"));
    CHECK_FALSE(holds_group_owner_role({row("user", "bob", "ITServiceOwner")}, "alice"));
    // A name that merely contains the username is not the username.
    CHECK_FALSE(holds_group_owner_role({row("user", "alice2", "ITServiceOwner")}, "alice"));
}
