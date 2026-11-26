#pragma once

/**
 * win_wts_sessions.hpp -- bounded read of the Windows Terminal Services session list.
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * The WTS calls are RPCs to the Terminal Services service with no deadline. Bounding the wait
 * needs a detached worker, whose code must not live in a plugin the agent can unload (see
 * bounded_single_flight.hpp). Plugins call the exported functions only.
 *
 * One read is in flight process-wide. A second caller waits for a healthy read inside its own
 * deadline; after a deadline hit, callers are answered Abandoned until the blocked worker returns.
 * Every other field of the result is meaningful only when status == Completed.
 *
 * COMPLETENESS (what a consumer may rely on)
 * ------------------------------------------
 * `sessions` is the complete session list ONLY when status == Completed, enumerated is true and
 * truncated is false. A consumer that diffs the list or stores it as a baseline must refuse
 * anything else. A consumer that only reports rows must mark a truncated list CONSTRAINED +
 * PARTIAL. A change to a field or to this contract is made here, never worked around in a
 * consumer.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <yuzu/agent/bounded_status.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent::win {

// The WTS_CONNECTSTATE_CLASS values consumers decide on (static_asserted against the SDK in
// win_wts_sessions.cpp).
inline constexpr std::uint32_t kWtsActive = 0;
inline constexpr std::uint32_t kWtsConnected = 1;
inline constexpr std::uint32_t kWtsDisconnected = 4;
inline constexpr std::uint32_t kWtsIdle = 5;
inline constexpr std::uint32_t kWtsListen = 6;

/// One session. Text is UTF-8 and empty when its query failed or the session has no value.
struct WtsSession {
    std::uint32_t session_id = 0;
    std::uint32_t state = 0; ///< the WTS_CONNECTSTATE_CLASS value
    std::string station_name;
    std::string user;
    std::string domain;
    std::string client_name;
};

struct WtsSessionsRead {
    BoundedStatus status = BoundedStatus::Rejected;
    bool enumerated = false;     ///< the enumeration succeeded; otherwise win_error says why
    std::uint32_t win_error = 0; ///< Win32 error of a failed enumeration
    bool truncated = false;      ///< more than kMaxWtsSessions sessions; the rest were not read
    std::vector<WtsSession> sessions;
};

inline constexpr std::chrono::milliseconds kWtsSessionsDeadline{5000};
inline constexpr std::size_t kMaxWtsSessions = 4096;

/// Every session of the local server, in ONE bounded call. Non-Windows builds answer Completed
/// with enumerated = false and win_error = 120 (ERROR_CALL_NOT_IMPLEMENTED). Out-of-line
/// (agent-core only).
YUZU_EXPORT WtsSessionsRead read_wts_sessions(std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT WtsSessionsRead read_wts_sessions_for_test(
    std::chrono::milliseconds deadline, const std::function<WtsSessionsRead()>& reader);

} // namespace yuzu::agent::win
