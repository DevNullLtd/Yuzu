#pragma once

/**
 * echo_wts_sessions.hpp -- agent-core's bounded Terminal Services read as Echo's `user`
 * snapshot. Pure, with no Windows type, so it is unit-tested on every OS
 * (tests/unit/test_echo_capture_status.cpp).
 */

#include "echo_capture_status.hpp" // IncompleteCaptureError
#include "echo_collectors.hpp"     // UserSession

#include <yuzu/agent/win_wts_sessions.hpp> // WtsSessionsRead and its completeness contract

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::echo {

// The WTS_CONNECTSTATE_CLASS values of a logged-on session (static_asserted against the SDK in
// echo_user_collector.cpp).
inline constexpr std::uint32_t kWtsStateActive = 0;
inline constexpr std::uint32_t kWtsStateDisconnected = 4;

/// The logged-on sessions (active or disconnected, with a user name) of one session read. THROWS
/// IncompleteCaptureError unless the list is complete: an unanswered, capped or failed read
/// diffed against the last complete baseline would record logouts that never happened.
inline std::vector<UserSession>
user_sessions_from_wts(const yuzu::agent::win::WtsSessionsRead& read) {
    if (read.status != yuzu::agent::BoundedStatus::Completed)
        throw IncompleteCaptureError("ECHO: user session read " +
                                     std::string{yuzu::agent::bounded_cause(read.status)});
    if (read.truncated)
        throw IncompleteCaptureError("ECHO: user session read hit the session cap");
    if (!read.enumerated)
        throw IncompleteCaptureError(
            "ECHO: user session read failed (rc=" + std::to_string(read.win_error) + ")");

    std::vector<UserSession> sessions;
    for (const auto& s : read.sessions) {
        if (s.state != kWtsStateActive && s.state != kWtsStateDisconnected)
            continue;
        if (s.user.empty())
            continue;

        UserSession us;
        us.user = s.user;
        us.domain = s.domain.empty() ? "local" : s.domain;
        us.session_id = std::to_string(s.session_id);
        us.disconnected = s.state == kWtsStateDisconnected;

        // Determine logon type from session name
        if (s.station_name.find("RDP") != std::string::npos ||
            s.station_name.find("rdp") != std::string::npos) {
            us.logon_type = "remote";
        } else {
            us.logon_type = "interactive";
        }

        sessions.push_back(std::move(us));
    }
    return sessions;
}

} // namespace yuzu::echo
