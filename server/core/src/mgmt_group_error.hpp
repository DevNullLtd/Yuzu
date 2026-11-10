#pragma once

/// @file mgmt_group_error.hpp
/// The one answer to "is this ManagementGroupStore error message a store fault?", shared by the
/// REST routes (rest_api_v1.cpp) and the MCP tools (mcp_server.cpp) so the two cannot drift.
///
/// The store returns `std::expected<..., std::string>`. A fault of the store itself (not open, no
/// pool connection, a failed query) carries one of the FIXED messages below, always at the START
/// of the string. Every other message is a validation answer, and some of those echo caller text
/// (`RbacStore::validate_assignment` writes "unrecognized principal_type '<value>'"). Matching
/// the word "failed" anywhere in the message let a caller value holding that word turn a client
/// error into a retryable 503 with a failure audit row, so the match is on the fixed prefix only
/// and caller text can never be at the start of a message.
///
/// A NEW store-fault message in management_group_store.cpp needs its prefix added here; the test
/// `mgmt_group_error` (tests/unit/server/test_rest_mgmt_group_roles_floor.cpp) scans the store
/// source for every message that says "failed" or names the pool or an open store and fails when
/// this function does not classify it as a fault.

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

} // namespace yuzu::server
