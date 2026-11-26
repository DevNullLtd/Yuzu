#pragma once

/**
 * win_join_info.hpp -- bounded read of the Windows domain / workgroup join information.
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * NetGetJoinInformation is an RPC to the Workstation service with no deadline. Bounding the wait
 * needs a detached worker, whose code must not live in a plugin the agent can unload (see
 * bounded_single_flight.hpp). Plugins call the exported functions only.
 *
 * One read is in flight process-wide. A second caller waits for a healthy read inside its own
 * deadline; after a deadline hit, callers are answered Abandoned until the blocked worker returns.
 * Every other field of the result is meaningful only when status == Completed.
 */

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>

#include <yuzu/agent/bounded_status.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent::win {

struct JoinInfoRead {
    BoundedStatus status = BoundedStatus::Rejected;
    std::uint32_t nerr = 0; ///< the NET_API_STATUS of the call; 0 (NERR_Success) means it answered
    bool has_name = false;  ///< the call returned a name buffer
    std::string name;       ///< the domain or workgroup name, UTF-8
    std::uint32_t join_status = 0; ///< the NETSETUP_JOIN_STATUS value
};

inline constexpr std::chrono::milliseconds kJoinInfoDeadline{5000};

/// The local machine's join information, in one bounded call. Non-Windows builds answer Completed
/// with nerr = 120 (ERROR_CALL_NOT_IMPLEMENTED). Out-of-line (agent-core only).
YUZU_EXPORT JoinInfoRead read_join_info(std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT JoinInfoRead read_join_info_for_test(std::chrono::milliseconds deadline,
                                                 const std::function<JoinInfoRead()>& reader);

} // namespace yuzu::agent::win
