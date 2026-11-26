#pragma once

/**
 * win_account_enum.hpp -- bounded reads of the local accounts and of a local group's members.
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * The NetAPI calls are RPCs with no deadline. Bounding the wait needs a detached worker, whose
 * code must not live in a plugin the agent can unload (see bounded_single_flight.hpp). Plugins
 * call the exported functions only.
 *
 * Each function has its own slot: one read in flight process-wide. A second caller waits for a
 * healthy read inside its own deadline; after a deadline hit, callers are answered Abandoned until
 * the blocked worker returns. Every other field of a result is meaningful only when
 * status == Completed.
 *
 * HOW A READ ENDS
 * ---------------
 * nerr is 0 when the pages ran out, when the list was cut at kMaxLocalAccounts (truncated: the
 * entry past the cap, or a more-data page that fills it) and when the pages stopped advancing (a
 * page with no entries, or the 4,096th page: no_progress), so ERROR_MORE_DATA (234) is never a
 * terminal nerr. Any other status is in nerr, with the entries of earlier pages kept. The page
 * bound means a provider that keeps answering ERROR_MORE_DATA cannot spin the worker after its
 * caller has timed out. A list is complete ONLY when status == Completed, nerr is 0 and neither
 * truncated nor no_progress is set.
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

/// One local account (NetUserEnum level 2). Text is UTF-8.
struct LocalUser {
    std::string name;
    std::string comment;
    std::uint32_t flags = 0;      ///< usri2_flags (UF_*)
    std::uint32_t last_logon = 0; ///< seconds since 1970 UTC; 0 = no recorded logon
};

struct LocalUsersRead {
    BoundedStatus status = BoundedStatus::Rejected;
    std::uint32_t nerr = 0;       ///< NET_API_STATUS of a failed call, else 0
    bool truncated = false;       ///< cut at kMaxLocalAccounts (see HOW A READ ENDS)
    bool no_progress = false;     ///< the pages stopped advancing before the end of the list
    std::vector<LocalUser> users; ///< every account collected, whatever nerr says
};

/// One member of a local group (NetLocalGroupGetMembers level 2).
struct GroupMember {
    std::string domain_and_name; ///< UTF-8
    std::uint32_t sid_usage = 0; ///< the SID_NAME_USE value
};

struct GroupMembersRead {
    BoundedStatus status = BoundedStatus::Rejected;
    std::uint32_t nerr = 0;           ///< NET_API_STATUS of a failed call, else 0
    bool truncated = false;           ///< cut at kMaxLocalAccounts (see HOW A READ ENDS)
    bool no_progress = false;         ///< the pages stopped advancing before the end of the list
    std::vector<GroupMember> members; ///< every member collected, whatever nerr says
};

inline constexpr std::chrono::milliseconds kLocalUsersDeadline{10000};
inline constexpr std::chrono::milliseconds kGroupMembersDeadline{5000};
/// Cap on the entries one read collects, for accounts and for group members alike.
inline constexpr std::size_t kMaxLocalAccounts = 16384;

/// Every normal account of the local machine, in ONE bounded call. Non-Windows builds answer
/// Completed with nerr = 120 (ERROR_CALL_NOT_IMPLEMENTED). Out-of-line (agent-core only).
YUZU_EXPORT LocalUsersRead read_local_users(std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT LocalUsersRead read_local_users_for_test(std::chrono::milliseconds deadline,
                                                     const std::function<LocalUsersRead()>& reader);

/// The direct members of the local group `group_utf8`, in ONE bounded call. Non-Windows builds
/// answer Completed with nerr = 120. Out-of-line (agent-core only).
YUZU_EXPORT GroupMembersRead read_local_group_members(const std::string& group_utf8,
                                                      std::chrono::milliseconds deadline);

/// Test seam for read_local_group_members; same rules as read_local_users_for_test.
YUZU_EXPORT GroupMembersRead read_local_group_members_for_test(
    std::chrono::milliseconds deadline, const std::function<GroupMembersRead()>& reader);

} // namespace yuzu::agent::win
