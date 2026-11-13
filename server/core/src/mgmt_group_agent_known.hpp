#pragma once

/// @file mgmt_group_agent_known.hpp
/// "Is this agent id a device the server has enrolled?", for the add-member surfaces: the REST
/// route POST /api/v1/management-groups/{id}/members (rest_api_v1.cpp) and the MCP tool
/// add_management_group_member (mcp_server.cpp). Both call `lookup_agent_known` and answer the
/// same `known` field and the same audit suffix, so the two cannot drift (#7074, #6967).
///
/// The source is `AuthDB::pending_status`: the durable enrolment table, which lists a device
/// whether or not it is connected and keeps it after the device is decommissioned. It is read
/// AFTER the group-exists check and BEFORE the `attempted` audit row; it is a read and never
/// changes whether the add happens.
///
/// An unknown id is ACCEPTED, never refused: an operator may stage a membership before the
/// device first appears. The answer only FLAGS it. The three outcomes are deliberately distinct:
///   Known       an enrolment row exists (any status: pending, approved or denied).
///   Unknown     the table answered and has no such id, or the store refused the id as input it
///               cannot hold (`StoreError::InvalidInput`: a comma, an over-long id). A caller-input
///               outcome, not an outage.
///   Unreadable  the lookup could not be made (store outage, any other error, or no AuthDB wired).
///               It is NEVER reported as Unknown: "could not check" must not read as "checked, and
///               not there". The REST and MCP answers OMIT `known` for it.
/// The lookup runs for every caller (the audit flag needs it), but the ANSWER is shown only to a
/// caller who may read enrolment status for that agent id (`caller_may_see_agent_known` below):
/// otherwise `known` is OMITTED, the same omission as Unreadable, so an omitted `known` means
/// either "could not check" or "not permitted to know" and the response does not say which.
/// Showing it to every ManagementGroup:Write holder would let one probe arbitrary ids for
/// enrolment, even for a device their management-group scope hides.
/// Matching is exact: a case-only mismatch of a known id is Unknown (case-insensitive handling is
/// out of scope here).
///
/// Audit suffix rule, for anyone reading the `management_group.add_member` success row: its
/// detail is `<raw agent_id> agent_known=<1|0|unreadable>`. The raw id is caller text and may
/// itself contain spaces or the text " agent_known=1", so the id is never parsed; the
/// authoritative flag is the LAST space-delimited token, which an id cannot forge because the
/// suffix is always appended after it. The `attempted` row keeps the bare raw id, and failure rows
/// keep their fixed tokens. The audit row is NOT gated: it records the real flag for every caller
/// and is read only through AuditLog:Read.

#include "authz_gates.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <httplib.h>

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

/// The one lookup: a null `auth_db` (no store wired, or shutdown) is Unreadable, never a throw
/// and never "unknown".
[[nodiscard]] inline AgentKnown lookup_agent_known(AuthDB* auth_db,
                                                   const std::string& agent_id) noexcept {
    if (auth_db == nullptr)
        return AgentKnown::Unreadable;
    try {
        return classify_agent_known(auth_db->pending_status(agent_id));
    } catch (const std::exception&) {
        return AgentKnown::Unreadable; // never refuse the add on a lookup fault
    }
}

/// May this caller be told whether `agent_id` is an enrolled device? The same decision the
/// enrolment read `GET /api/v1/enrollment/pending-agents` makes for a row: the fleet-read check
/// for Enrollment:Read (`fleet_read_fn`, the injected `AuthRoutes::require_fleet_read`), ADMITTED
/// and the id inside the composed scope (`authz::in_scope`). Fails CLOSED: an unwired check, a
/// refusal, a degraded answer (the check itself answers 503) and an exception are all `false`.
///
/// Call it once, with this one pair; never swap in a bare permission check, which would admit
/// every global holder for every id. The gate renders its 401/403/503 into a scratch response (the
/// route's own answer is the add-member one), but it still writes its own denial audit row
/// (`auth.fleet_read_required`) for a refused caller, as it does on any route.
template <class FleetReadFn>
[[nodiscard]] bool caller_may_see_agent_known(const FleetReadFn& fleet_read_fn,
                                              const httplib::Request& req,
                                              const std::string& agent_id) noexcept {
    if (!fleet_read_fn)
        return false;
    try {
        httplib::Response scratch; // the gate's own error body never reaches the caller
        const authz::FleetReadGate gate = fleet_read_fn(req, scratch, "Enrollment", "Read");
        return gate.admitted && authz::in_scope(gate.scope, agent_id);
    } catch (...) {
        return false; // never reveal on a fault in the check
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
