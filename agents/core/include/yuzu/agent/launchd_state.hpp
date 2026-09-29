#pragma once

/**
 * launchd_state.hpp -- resolve a launchd service's run state from a decoded
 * `launchctl list` snapshot.
 *
 * Lives in agents/core (not agents/shared/launchctl_list.hpp, which this
 * depends on) because agents/shared/ is a deliberate zero-dependency leaf
 * (owner decision, A0 governance fix round) and this function needs
 * yuzu::agent::ServiceRunState from spark.hpp. A2's macOS launchd Spark
 * mechanism (agents/core/src/spark_service_launchd.hpp, a separate branch)
 * is this function's first real caller and re-points its include here when
 * that branch merges onto this one.
 */

#include <launchctl_list.hpp>   // yuzu::shared::LaunchctlRow (agents/shared/launchctl_list.hpp)
#include <yuzu/agent/spark.hpp> // yuzu::agent::ServiceRunState

#include <span>
#include <string_view>

namespace yuzu::agent {

/// Resolve the run state of one label from a set of decoded rows: listed
/// with a pid -> Running; listed without a pid, or the label is absent from
/// `rows` entirely -> Stopped. Never Paused -- see yuzu/agent/spark.hpp's
/// ServiceRunState doc comment's macOS mapping line for why.
///
/// Precondition: `rows` must be a COMPLETE, exit-0 `launchctl list` snapshot
/// (yuzu::shared::parse_launchctl_list's LaunchctlParseResult with
/// `malformed == false`) -- a truncated/failed capture that the caller feeds
/// in anyway is indistinguishable here from "every service absent", so a
/// caller MUST check `malformed` itself before calling this and must never
/// treat a malformed snapshot's Stopped answers as real service state.
[[nodiscard]] inline yuzu::agent::ServiceRunState
launchd_state_for(std::span<const yuzu::shared::LaunchctlRow> rows, std::string_view label) noexcept {
    for (const auto& row : rows) {
        if (row.label == label)
            return row.pid.has_value() ? yuzu::agent::ServiceRunState::Running
                                        : yuzu::agent::ServiceRunState::Stopped;
    }
    return yuzu::agent::ServiceRunState::Stopped; // absent from the snapshot -- not running
}

} // namespace yuzu::agent
