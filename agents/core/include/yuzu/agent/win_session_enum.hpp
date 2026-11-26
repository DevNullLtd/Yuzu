#pragma once

/**
 * win_session_enum.hpp -- bounded read of the SMB sessions into this host's shares
 * (NetSessionEnum).
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * NetSessionEnum is an RPC to the Server service with no deadline. Bounding the wait needs a
 * detached worker, whose code must not live in a plugin the agent can unload (see
 * bounded_single_flight.hpp). Plugins call the exported functions only.
 *
 * One read is in flight process-wide. A second caller waits for a healthy read inside its own
 * deadline; after a deadline hit, callers are answered Abandoned until the blocked worker returns.
 * Every other field of the result is meaningful only when status == Completed.
 */

#include <yuzu/agent/bounded_status.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace yuzu::agent::win {

/// One session. Text is UTF-8; at least one of the two is non-empty.
struct SmbSession {
    std::string client;
    std::string user;
};

struct SmbSessionsRead {
    BoundedStatus status = BoundedStatus::Rejected;
    std::uint32_t nerr = 0;   ///< status of a failed call, else 0; never 234 (ERROR_MORE_DATA)
    bool no_progress = false; ///< the pages stopped advancing, or reached the page cap
    bool truncated = false;   ///< more than max_entries sessions; the rest were dropped
    std::vector<SmbSession> sessions;
};

/// For the whole drain.
inline constexpr std::chrono::milliseconds kSmbSessionsDeadline{5000};

/// Drains NetSessionEnum at level 502 or 10 (every page, in ONE bounded call), keeping at most
/// `max_entries` sessions. `sessions` is complete only when status is Completed, nerr is 0 and
/// neither no_progress nor truncated is set. Any other level answers nerr 124
/// (ERROR_INVALID_LEVEL) without a call.
/// Non-Windows builds answer Completed with nerr 120 (ERROR_CALL_NOT_IMPLEMENTED). Out-of-line
/// (agent-core only).
YUZU_EXPORT SmbSessionsRead read_smb_sessions(int level, std::size_t max_entries,
                                              std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT SmbSessionsRead
read_smb_sessions_for_test(int level, std::size_t max_entries, std::chrono::milliseconds deadline,
                           const std::function<SmbSessionsRead(int, std::size_t)>& reader);

} // namespace yuzu::agent::win
