#pragma once

/// @file mgmt_group_limits.hpp
/// The ONE bound-and-clean-text check for the free-text values a management-group write routes
/// to a text bind and into its audit rows: a group NAME, a member AGENT ID, a PARENT group id.
/// Shared by the REST routes (rest_api_v1.cpp), the Settings create form (settings_routes.cpp)
/// and the MCP tools (mcp_server.cpp) so the three surfaces cannot drift.
///
/// WHY at the handler: the create and member writes are audit-first (ADR-0033 section 9), so a
/// value that the store later refuses would already have burned an `attempted` row, and each
/// value lands in two audit rows (attempted + outcome). A value that no check bounded was
/// limited only by the 4 MiB request-body cap. A name too large for the unique index on `name`
/// would surface as a store fault, a retryable 503, though the caller caused it. The refusal is
/// made before any audit row and without a store read.
///
/// The clean-text rule is the one in rbac_text.hpp (no byte below 0x20, no DEL) plus well-formed
/// UTF-8 (the exact set PostgreSQL's UTF8 accepts, `yuzu::utf8_sequence_length`). It is the same
/// rule the member and role id fields were already held to.
///
/// EXTEND this file, never copy it into a handler. No store, no I/O, no wire types.

#include <yuzu/log_token.hpp> // yuzu::utf8_sequence_length
#include <yuzu/server/auth.hpp> // auth::kMaxAgentIdLength

#include <cstddef>
#include <string_view>

#include "rbac_text.hpp"

namespace yuzu::server {

/// Longest group name, in bytes. Equals the MCP schema bound (`kMgmtGroupNameMaxLen`,
/// mcp_input_bounds.hpp); mcp_server.cpp static_asserts the two agree.
inline constexpr std::size_t kMgmtGroupNameMaxBytes = 256;

/// Longest agent id a membership write accepts: the same cap every other agent-id entry point
/// uses.
inline constexpr std::size_t kMgmtGroupAgentIdMaxBytes = auth::kMaxAgentIdLength;

/// Longest group id a write accepts (a parent id in a create body, a group id in a member route
/// path). A generated group id is 12 lowercase hex characters; 256 matches the MCP `group_id`
/// bound (`kMgmtGroupIdMaxLen`).
inline constexpr std::size_t kMgmtGroupIdMaxBytes = 256;

/// True when `s` holds no control byte, no DEL and only well-formed UTF-8. An empty string is
/// clean. This is the single predicate behind the REST and MCP `mgmt_text_ok`.
[[nodiscard]] inline bool mgmt_group_text_is_clean(std::string_view s) noexcept {
    if (!rbac_text_is_clean(s))
        return false;
    for (std::size_t i = 0; i < s.size();) {
        if (static_cast<unsigned char>(s[i]) < 0x80) {
            ++i;
            continue;
        }
        const std::size_t len = ::yuzu::utf8_sequence_length(s, i);
        if (len == 0)
            return false;
        i += len;
    }
    return true;
}

/// A group name a create may carry: at most kMgmtGroupNameMaxBytes and clean text. An EMPTY name
/// passes here (the store's own empty-name refusal and the handlers' `name required` answers
/// stay where they were).
[[nodiscard]] inline bool mgmt_group_name_ok(std::string_view s) noexcept {
    return s.size() <= kMgmtGroupNameMaxBytes && mgmt_group_text_is_clean(s);
}

/// A group id a write may carry: at most kMgmtGroupIdMaxBytes and clean text. An id that fails
/// this cannot name a group, so a handler answers it as an unknown group (a create's parent id:
/// `parent group not found`; a member route's path id: 404).
[[nodiscard]] inline bool mgmt_group_id_ok(std::string_view s) noexcept {
    return s.size() <= kMgmtGroupIdMaxBytes && mgmt_group_text_is_clean(s);
}

/// The length half of the agent id rule, for the member routes, which already hold the id to the
/// clean-text rule separately (so an unclean id keeps its `denied` row).
[[nodiscard]] constexpr bool mgmt_group_agent_id_length_ok(std::string_view s) noexcept {
    return s.size() <= kMgmtGroupAgentIdMaxBytes;
}

/// The fixed refusal texts (never an echo of the caller's value), shared so the surfaces agree.
inline constexpr std::string_view kMgmtGroupNameInvalidText =
    "group name must be at most 256 bytes and must not contain control characters or invalid "
    "UTF-8";
inline constexpr std::string_view kMgmtGroupAgentIdTooLongText =
    "agent_id must be at most 256 bytes";

// Boundary pins.
static_assert(kMgmtGroupNameMaxBytes == 256);
static_assert(kMgmtGroupAgentIdMaxBytes == 256);
static_assert(kMgmtGroupIdMaxBytes == 256);
static_assert(mgmt_group_agent_id_length_ok(std::string_view{}));

} // namespace yuzu::server
