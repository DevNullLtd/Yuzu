#pragma once

/// @file mgmt_group_error.hpp
/// The one answer to "is this ManagementGroupStore error message a store fault?", shared by the
/// REST create and assign-role routes (rest_api_v1.cpp), the Settings create form
/// (settings_routes.cpp) and the four MCP management-group write tools (mcp_server.cpp: create,
/// update, add member, assign role), so those three cannot drift. The other REST group routes
/// (update, delete, add and remove member) map store errors on their own and are NOT routed
/// through it. The create audit token (`create_failure_token`, below) is shared by the same three
/// create surfaces.
///
/// The store returns `std::expected<..., std::string>`. A fault of the store itself (not open, no
/// pool connection, a failed query) carries one of the FIXED messages below, always at the START
/// of the string. Every other message is a validation answer, and some of those echo caller text
/// (`RbacStore::validate_assignment` writes "unrecognized principal_type '<value>'"). Matching
/// the word "failed" anywhere in the message let a caller value holding that word turn a client
/// error into a retryable 503 with a failure audit row, so the match is on the fixed prefix only
/// and caller text can never be at the start of a message.
///
/// A NEW message in management_group_store.cpp forces a decision: the tests tagged
/// `[mgmt_group_error]` (tests/unit/server/test_rest_mgmt_group_roles_floor.cpp) scan the store
/// source for every string literal passed to `std::unexpected` and fail unless it is either
/// classified as a fault here or named in the test's own list of validation messages (or of the
/// read-path faults that never reach a classifier). A message built any other way (`std::format`,
/// a named constant) is not seen by the scan.

#include <array>
#include <string_view>

namespace yuzu::server {

[[nodiscard]] constexpr bool mgmt_group_error_is_store_fault(std::string_view msg) noexcept {
    constexpr std::array<std::string_view, 2> kExact = {"database not open",
                                                        "pool acquire timed out"};
    constexpr std::array<std::string_view, 9> kPrefix = {
        "failed to resolve ancestor chain",
        "failed to create group: ",
        "query failed: ",
        "update failed: ",
        "delete failed: ",
        "add_member failed: ",
        "remove_member failed: ",
        "assign_role failed: ",
        "unassign_role failed: ",
    };
    for (const auto e : kExact)
        if (msg == e)
            return true;
    for (const auto p : kPrefix)
        if (msg.starts_with(p))
            return true;
    return false;
}

/// The text `ManagementGroupStore::create_group` returns for a duplicate group name. A named
/// constant is not seen by the literal scan above, so the store's literal and this constant are
/// pinned equal by a test (`[mgmt-audit-first]`, test_rest_mgmt_group_audit_first.cpp); the
/// scan's own list names the same text as a validation message.
inline constexpr std::string_view kMgmtGroupNameConflict = "a group with that name already exists";

/// The FIXED audit token for a failed group create: `name_conflict` (a duplicate name),
/// `store_error` (a store fault) or `validation_refused` (any other store answer, e.g. a parent
/// that vanished after the pre-check). Never the store's own text, which can carry database
/// output. The REST create route, the MCP `create_management_group` tool and the Settings create
/// form all use this one function.
[[nodiscard]] constexpr std::string_view create_failure_token(std::string_view err) noexcept {
    if (err == kMgmtGroupNameConflict)
        return "name_conflict";
    if (mgmt_group_error_is_store_fault(err))
        return "store_error";
    return "validation_refused";
}

} // namespace yuzu::server
