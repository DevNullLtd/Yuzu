#pragma once

/**
 * device_identity_win.hpp -- the Windows `domain` decision, pure so every host tests it. The OS
 * read is agent-core's (yuzu/agent/win_join_info.hpp).
 */

#include <cstdint>
#include <string>
#include <vector>

#include <yuzu/agent/win_join_info.hpp>

namespace yuzu::device_identity::win {

/// NetSetupDomainName in NETSETUP_JOIN_STATUS; the plugin static_asserts it against the SDK.
inline constexpr std::uint32_t kJoinStatusDomain = 3;

struct DomainAnswer {
    std::vector<std::string> rows;
    int rc = 0;
};

/// An unanswered read gives no rows and rc 1: daily sync requires `domain`, so it skips the cycle
/// instead of storing N/A / false as a real answer. An answered failure reads N/A / false.
inline DomainAnswer domain_answer(const yuzu::agent::win::JoinInfoRead& read) {
    if (read.status != yuzu::agent::BoundedStatus::Completed)
        return {{}, 1};
    const bool named = read.nerr == 0 && read.has_name;
    const bool joined = named && read.join_status == kJoinStatusDomain;
    return {{"domain|" + (named && !read.name.empty() ? read.name : std::string{"N/A"}),
             joined ? "joined|true" : "joined|false"},
            0};
}

} // namespace yuzu::device_identity::win
