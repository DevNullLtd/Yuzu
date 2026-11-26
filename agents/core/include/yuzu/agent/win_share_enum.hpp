#pragma once

/**
 * win_share_enum.hpp -- bounded read of one NetShareEnum page (the live SMB shares).
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * NetShareEnum is an RPC to the Server service with no deadline. Bounding the wait needs a
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
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace yuzu::agent::win {

/// One share. Text is UTF-8. No remark (free text) and no ACL.
struct ShareRec {
    std::string name;
    std::string path;       ///< empty at level 1 (SHARE_INFO_1 carries none)
    std::uint32_t type = 0; ///< SHARE_INFO_*.shi*_type
};

struct SharePage {
    BoundedStatus status = BoundedStatus::Rejected;
    std::uint32_t nerr = 0;   ///< NET_API_STATUS of the call
    std::uint32_t total = 0;  ///< the call's totalentries
    std::uint32_t resume = 0; ///< the resume handle to pass for the next page
    std::vector<ShareRec> shares;
};

/// Per page.
inline constexpr std::chrono::milliseconds kShareEnumDeadline{5000};

/// One NetShareEnum call at level 1 or 2, from resume handle `resume` (0 starts a level's
/// enumeration), asking for 64 KiB. Any other level answers nerr 124 (ERROR_INVALID_LEVEL)
/// without a call. Non-Windows builds answer Completed with nerr 120
/// (ERROR_CALL_NOT_IMPLEMENTED). Out-of-line (agent-core only).
YUZU_EXPORT SharePage read_share_page(int level, std::uint32_t resume,
                                      std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT SharePage
read_share_page_for_test(int level, std::uint32_t resume, std::chrono::milliseconds deadline,
                         const std::function<SharePage(int, std::uint32_t)>& reader);

} // namespace yuzu::agent::win
