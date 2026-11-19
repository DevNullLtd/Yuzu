#pragma once

/// @file software_sync_status.hpp
/// How a "Sync now" run is going, shared by both surfaces that answer it:
/// `GET /api/v1/hardware/sync/{execution_id}` and the MCP tool `get_software_sync_status`. The
/// visibility rule and the body live here once, so neither surface can drift from the other.
///
/// The caller does the surface's own gate (Execution:Execute), resolves its session, and reads
/// the tracker row; this function decides what that row may show. No I/O.

#include "execution_tracker.hpp"     // Execution
#include "software_sync_decision.hpp" // kSyncDefinitionId

#include <yuzu/server/auth.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server::software_sync {

/// One tracker row by id: `unexpected` = the read degraded; an empty optional = no such execution.
using StatusReadFn = std::function<std::expected<std::optional<Execution>, std::string>(
    const std::string& execution_id)>;
/// Does the session hold an unfiltered Execution:Execute (it may read any sync run, not only its
/// own)? Empty answers no.
using UnfilteredFn = std::function<bool(const auth::Session&)>;

enum class SyncStatusFault {
    kNotFound,    ///< unknown id, a run somebody else started, or an execution that is not a sync run
    kUnavailable, ///< the tracker read degraded: retryable, never an empty answer
};

/// The run's progress body: `execution_id, state, targeted, acknowledged, failed, dispatched_at,
/// delay_max_s, estimated_completion_at`. `targeted` is the frames the registry accepted,
/// `acknowledged` the agents that armed the sync and `failed` the agents that answered with a
/// failure: an agent answers when it ARMS the sync, not when its report lands, so this counts
/// requests taken up, not reports received. `estimated_completion_at` is an estimate: the
/// dispatch time plus the spread.
///
/// Visibility is ownership, or an `unfiltered` Execution:Execute. `owned` is whether the caller's
/// execution owner key owns the row (`execution_owner_key(session).owns(row)`: a service-scoped
/// session owns nothing); each surface evaluates it in its own handler, where the owner-key
/// tripwire (tests/test_execution_owner_key_tripwire.py) reviews that spelling. An unknown id, a
/// run somebody else started and an execution that is not a sync run all answer kNotFound, so the
/// answer is not an oracle for ids.
[[nodiscard]] inline std::expected<nlohmann::json, SyncStatusFault>
sync_status(const std::expected<std::optional<Execution>, std::string>& read, bool owned,
            bool unfiltered) {
    if (!read)
        return std::unexpected(SyncStatusFault::kUnavailable);
    if (!*read || (*read)->definition_id != kSyncDefinitionId || !(unfiltered || owned))
        return std::unexpected(SyncStatusFault::kNotFound);
    const Execution& e = **read;
    std::int64_t delay_max_s = 0;
    const auto params = nlohmann::json::parse(e.parameter_values, nullptr, false);
    if (params.is_object())
        if (const auto it = params.find("delay_max_s");
            it != params.end() && it->is_number_integer() && it->get<std::int64_t>() > 0)
            delay_max_s = it->get<std::int64_t>();
    return nlohmann::json{{"execution_id", e.id},
                          {"state", e.status},
                          {"targeted", e.agents_targeted},
                          {"acknowledged", e.agents_success},
                          {"failed", e.agents_failure},
                          {"dispatched_at", e.dispatched_at},
                          {"delay_max_s", delay_max_s},
                          {"estimated_completion_at", e.dispatched_at + delay_max_s}};
}

} // namespace yuzu::server::software_sync
