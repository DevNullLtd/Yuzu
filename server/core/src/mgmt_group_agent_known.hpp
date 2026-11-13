#pragma once

/// @file mgmt_group_agent_known.hpp
/// "Does the server hold an enrolment record for this agent id?", for the add-member surfaces: the REST
/// route POST /api/v1/management-groups/{id}/members (rest_api_v1.cpp) and the MCP tool
/// add_management_group_member (mcp_server.cpp). Both call `lookup_agent_known` and record the
/// same `agent_known` audit suffix, so the two cannot drift (#7074, #6967).
///
/// The source is `AuthDB::pending_status`: the durable enrolment table, which lists a device
/// whether or not it is connected and keeps it after the device is decommissioned. It is read
/// AFTER the group-exists check and BEFORE the `attempted` audit row; it is a read and never
/// changes whether the add happens.
///
/// The answer is recorded on the success audit row ONLY. It is NEVER returned in a REST or MCP
/// response: a response field would tell any ManagementGroup:Write holder whether an arbitrary
/// agent id has an enrolment record, even one their management-group scope hides, which makes the
/// route an enrolment-existence oracle. The audit row is read only through AuditLog:Read.
///
/// An unknown id is ACCEPTED, never refused: an operator may stage a membership before the
/// device first appears. The flag only RECORDS it. The three outcomes are deliberately distinct:
///   Known       an enrolment row exists (any status: pending, approved or denied).
///   Unknown     the table answered and has no such id, or the store refused the id as input it
///               cannot hold (`StoreError::InvalidInput`: a comma, an over-long id). A caller-input
///               outcome, not an outage.
///   Unreadable  the lookup could not be made (store outage, any other error, or no AuthDB wired).
///               It is NEVER recorded as Unknown: "could not check" must not read as "checked, and
///               not there".
/// Matching is exact: a case-only mismatch of a known id is Unknown (case-insensitive handling is
/// out of scope here).
///
/// Audit suffix rule, for anyone reading the `management_group.add_member` success row: its
/// detail is `<raw agent_id> agent_known=<1|0|unreadable>`. The raw id is caller text and may
/// itself contain spaces or the text " agent_known=1", so the id is never parsed; the
/// authoritative flag is the LAST space-delimited token, which an id cannot forge because the
/// suffix is always appended after it. The `attempted` row keeps the bare raw id, and failure rows
/// keep their fixed tokens.

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <exception>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

enum class AgentKnown { Known, Unknown, Unreadable };

/// Map the three-state `AuthDB::pending_status` answer (value / absent / error). Only
/// `StoreError::InvalidInput` is read as "not a known id"; every other error, including any value
/// this function does not know about, is Unreadable.
[[nodiscard]] inline AgentKnown
classify_agent_known(const std::expected<std::optional<auth::PendingStatus>, StoreError>& r) noexcept {
    if (r.has_value())
        return r->has_value() ? AgentKnown::Known : AgentKnown::Unknown;
    return r.error() == StoreError::InvalidInput ? AgentKnown::Unknown : AgentKnown::Unreadable;
}

/// The one lookup: a null `auth_db` (never wired) is Unreadable, never a throw and never
/// "unknown". The pointer a handler holds is never nulled at shutdown: the lifetime contract is
/// that the HTTP listener is joined (or the process `_Exit`s) before `auth_db_` is reset, so no
/// handler can run against a destroyed store (server.cpp, `ServerImpl::stop()`).
[[nodiscard]] inline AgentKnown lookup_agent_known(AuthDB* auth_db,
                                                   const std::string& agent_id) noexcept {
    if (auth_db == nullptr)
        return AgentKnown::Unreadable;
    try {
        return classify_agent_known(auth_db->pending_status(agent_id));
    } catch (...) { // noexcept: a non-std exception must not terminate the process
        return AgentKnown::Unreadable; // never refuse the add on a lookup fault
    }
}

/// The value of the trailing audit flag: `1`, `0` or `unreadable`.
[[nodiscard]] constexpr std::string_view agent_known_flag_value(AgentKnown k) noexcept {
    switch (k) {
    case AgentKnown::Known:
        return "1";
    case AgentKnown::Unknown:
        return "0";
    case AgentKnown::Unreadable:
        break;
    }
    return "unreadable";
}

/// The `management_group.add_member` success row's detail: `<raw agent_id> agent_known=<flag>`
/// (see the file banner for how a reader takes the flag).
[[nodiscard]] inline std::string add_member_success_detail(std::string_view agent_id,
                                                           AgentKnown k) {
    std::string out;
    out.reserve(agent_id.size() + 24);
    out.append(agent_id);
    out.append(" agent_known=");
    out.append(agent_known_flag_value(k));
    return out;
}

} // namespace yuzu::server
