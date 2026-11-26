// win_account_enum.cpp -- bounded reads of the local accounts and group members. See
// yuzu/agent/win_account_enum.hpp for why this lives in agent-core.

#include <yuzu/agent/win_account_enum.hpp>

#include "win_bounded_run.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <lm.h>

#include <memory>
#include <utility>

#include "win_str.hpp" // yuzu::win::from_wide / to_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight per function.
SingleFlightSlot& g_users_slot = detail::new_slot();
SingleFlightSlot& g_members_slot = detail::new_slot();

#ifdef _WIN32

/// RAII owner of a buffer the NetAPI allocated.
struct NetFree {
    void operator()(void* p) const noexcept { ::NetApiBufferFree(p); }
};

LocalUsersRead read_users_raw() {
    DWORD resume = 0;
    auto drained = detail::drain_net_pages<LocalUser>(kMaxLocalAccounts, [&resume] {
        LPUSER_INFO_2 raw = nullptr;
        DWORD got = 0;
        DWORD total = 0;
        detail::NetPage<LocalUser> page;
        // The API takes LPBYTE* and writes a pointer to an array of the level-2 struct `raw` is
        // typed for, owned by the unique_ptr right after the call.
        page.status =
            ::NetUserEnum(nullptr, 2, FILTER_NORMAL_ACCOUNT, reinterpret_cast<LPBYTE*>(&raw),
                          MAX_PREFERRED_LENGTH, &got, &total, &resume);
        const std::unique_ptr<USER_INFO_2, NetFree> owned{raw};
        if (page.status != NERR_Success && page.status != ERROR_MORE_DATA)
            return page;
        page.raw_count = got;
        for (DWORD i = 0; i < got; ++i) {
            const USER_INFO_2& u = raw[i];
            page.entries.push_back({yuzu::win::from_wide(u.usri2_name),
                                    yuzu::win::from_wide(u.usri2_comment), u.usri2_flags,
                                    u.usri2_last_logon});
        }
        return page;
    });
    return {.nerr = drained.nerr,
            .truncated = drained.truncated,
            .no_progress = drained.no_progress,
            .users = std::move(drained.items)};
}

GroupMembersRead read_members_raw(const std::string& group_utf8) {
    const std::wstring group = yuzu::win::to_wide(group_utf8);
    DWORD_PTR resume = 0;
    auto drained = detail::drain_net_pages<GroupMember>(kMaxLocalAccounts, [&group, &resume] {
        LPLOCALGROUP_MEMBERS_INFO_2 raw = nullptr;
        DWORD got = 0;
        DWORD total = 0;
        detail::NetPage<GroupMember> page;
        // The API takes LPBYTE* and writes a pointer to an array of the level-2 struct `raw` is
        // typed for, owned by the unique_ptr right after the call.
        page.status =
            ::NetLocalGroupGetMembers(nullptr, group.c_str(), 2, reinterpret_cast<LPBYTE*>(&raw),
                                      MAX_PREFERRED_LENGTH, &got, &total, &resume);
        const std::unique_ptr<LOCALGROUP_MEMBERS_INFO_2, NetFree> owned{raw};
        if (page.status != NERR_Success && page.status != ERROR_MORE_DATA)
            return page;
        page.raw_count = got;
        for (DWORD i = 0; i < got; ++i) {
            const LOCALGROUP_MEMBERS_INFO_2& m = raw[i];
            page.entries.push_back({yuzu::win::from_wide(m.lgrmi2_domainandname),
                                    static_cast<std::uint32_t>(m.lgrmi2_sidusage)});
        }
        return page;
    });
    return {.nerr = drained.nerr,
            .truncated = drained.truncated,
            .no_progress = drained.no_progress,
            .members = std::move(drained.items)};
}

#else

constexpr std::uint32_t kNotImplemented = 120; // ERROR_CALL_NOT_IMPLEMENTED: no NetAPI on this OS

LocalUsersRead read_users_raw() {
    LocalUsersRead out;
    out.nerr = kNotImplemented;
    return out;
}

GroupMembersRead read_members_raw(const std::string&) {
    GroupMembersRead out;
    out.nerr = kNotImplemented;
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

LocalUsersRead read_local_users(std::chrono::milliseconds deadline) {
    return detail::run_bounded_read<LocalUsersRead>(g_users_slot, deadline, "local_users",
                                                    [] { return read_users_raw(); });
}

LocalUsersRead read_local_users_for_test(std::chrono::milliseconds deadline,
                                         const std::function<LocalUsersRead()>& reader) {
    return detail::run_bounded_read<LocalUsersRead>(g_users_slot, deadline, "local_users", reader);
}

GroupMembersRead read_local_group_members(const std::string& group_utf8,
                                          std::chrono::milliseconds deadline) {
    // The name is copied into the worker, which may outlive this call. Init-capture: a plain copy
    // capture of a const& makes a const member, whose "move" can throw (the driver refuses it).
    return detail::run_bounded_read<GroupMembersRead>(
        g_members_slot, deadline, "local_group_members",
        [group = group_utf8] { return read_members_raw(group); });
}

GroupMembersRead
read_local_group_members_for_test(std::chrono::milliseconds deadline,
                                  const std::function<GroupMembersRead()>& reader) {
    return detail::run_bounded_read<GroupMembersRead>(g_members_slot, deadline,
                                                      "local_group_members", reader);
}

} // namespace yuzu::agent::win
