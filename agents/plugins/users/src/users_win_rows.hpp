// users_win_rows.hpp -- pure row builders for the Windows account and session legs.
//
// Windows-headers-free and I/O-free by design (same split as users_win_events.hpp): agent-core
// owns the bounded WTS / NetAPI calls and hands back plain records; every row decision lives here,
// with declare_partial (the one write, to the result status), unit-testable on every host
// (test_users_win_rows.cpp). The SDK constants declared below are static_asserted against the real
// headers in users_plugin.cpp; the session states are agent-core's (win_wts_sessions.hpp).
//
// A read whose status is not Completed carries no answer, so every list builder returns no rows
// for it; unanswered_local_user_row is the one row local_users writes instead.
#pragma once

#include <cstdint>
#include <format>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/agent/win_account_enum.hpp>
#include <yuzu/agent/win_wts_sessions.hpp>
#include <yuzu/plugin.hpp>

namespace yuzu::users_win {

using yuzu::agent::win::kWtsActive;
using yuzu::agent::win::kWtsConnected;
using yuzu::agent::win::kWtsDisconnected;
using yuzu::agent::win::kWtsIdle;
using yuzu::agent::win::kWtsListen;
// USER_INFO_2 flags
inline constexpr std::uint32_t kUfAccountDisable = 2;
// SID_NAME_USE
inline constexpr std::uint32_t kSidTypeUser = 1;
inline constexpr std::uint32_t kSidTypeGroup = 2;
inline constexpr std::uint32_t kSidTypeAlias = 4;
inline constexpr std::uint32_t kSidTypeWellKnownGroup = 5;

inline const char* sid_type_name(std::uint32_t sid_usage) {
    switch (sid_usage) {
    case kSidTypeUser:
        return "user";
    case kSidTypeGroup:
        return "group";
    case kSidTypeWellKnownGroup:
        return "well_known_group";
    case kSidTypeAlias:
        return "alias";
    default:
        return "unknown";
    }
}

/// logged_on: active and disconnected sessions that have a user name.
inline std::vector<std::string> logged_on_rows(const yuzu::agent::win::WtsSessionsRead& read) {
    std::vector<std::string> rows;
    if (read.status != yuzu::agent::BoundedStatus::Completed)
        return rows;
    for (const auto& s : read.sessions) {
        if (s.state != kWtsActive && s.state != kWtsDisconnected)
            continue;
        if (s.user.empty())
            continue;
        const bool rdp = s.station_name.find("RDP") != std::string::npos ||
                         s.station_name.find("rdp") != std::string::npos;
        rows.push_back(std::format("user|{}|{}|{}|{}", s.user,
                                   s.domain.empty() ? "local" : s.domain, rdp ? "RDP" : "console",
                                   s.session_id));
    }
    return rows;
}

/// sessions: every session that has a user name. Idle time is not decoded: always 0.
inline std::vector<std::string> session_rows(const yuzu::agent::win::WtsSessionsRead& read) {
    std::vector<std::string> rows;
    if (read.status != yuzu::agent::BoundedStatus::Completed)
        return rows;
    for (const auto& s : read.sessions) {
        if (s.user.empty())
            continue;
        const char* state = "Other";
        switch (s.state) {
        case kWtsActive:
            state = "Active";
            break;
        case kWtsConnected:
            state = "Connected";
            break;
        case kWtsDisconnected:
            state = "Disconnected";
            break;
        case kWtsIdle:
            state = "Idle";
            break;
        case kWtsListen:
            state = "Listen";
            break;
        default:
            break;
        }
        rows.push_back(std::format("session|{}|{}|{}|{}|0", s.session_id, s.user, state,
                                   s.client_name.empty() ? "-" : s.client_name));
    }
    return rows;
}

/// Why an answered read is not the whole list; empty when it is. no_progress wins.
inline std::string_view incomplete_token(bool truncated, bool no_progress) {
    if (no_progress)
        return "no_progress";
    return truncated ? "row_cap" : "";
}

/// The provenance `<prefix>:<incomplete_token>`; empty for a whole list.
inline std::string incomplete_provenance(std::string_view prefix, bool truncated,
                                         bool no_progress) {
    const auto token = incomplete_token(truncated, no_progress);
    return token.empty() ? std::string{} : std::format("{}:{}", prefix, token);
}

/// The provenance of a session read that completed with less than the whole list: the listing
/// failed (which must never read as "nobody is logged on"), or it was cut at the cap. Empty for a
/// whole list, and for a read that did not complete (forward_bounded_failure reports that).
inline std::string wts_degraded_provenance(const yuzu::agent::win::WtsSessionsRead& read) {
    if (read.status != yuzu::agent::BoundedStatus::Completed)
        return {};
    if (!read.enumerated)
        return std::format("windows:users:wts_sessions:enum_failed:{}", read.win_error);
    return incomplete_provenance("windows:users:wts_sessions", read.truncated, false);
}

/// Declares an answered read that is not the whole list. Empty provenance: nothing to declare.
inline void declare_partial(yuzu::CommandContext& ctx, std::string_view provenance) {
    if (!provenance.empty())
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              provenance);
}

/// local_users: every account collected, whatever the final NetAPI status. `format_last_logon`
/// renders a non-zero logon time; zero is "Never".
inline std::vector<std::string>
local_user_rows(const yuzu::agent::win::LocalUsersRead& read,
                const std::function<std::string(std::uint32_t)>& format_last_logon) {
    std::vector<std::string> rows;
    if (read.status != yuzu::agent::BoundedStatus::Completed)
        return rows;
    for (const auto& u : read.users) {
        const bool enabled = !(u.flags & kUfAccountDisable);
        rows.push_back(
            std::format("local_user|{}|{}|{}|{}", u.name, enabled ? "true" : "false",
                        u.last_logon != 0 ? format_last_logon(u.last_logon) : std::string{"Never"},
                        u.comment.empty() ? "-" : u.comment));
    }
    return rows;
}

/// local_users: the error row for a read that did not answer; `enabled` and `last_logon` unread.
inline std::string unanswered_local_user_row(std::string_view cause) {
    return std::format("local_user|error|unknown|unknown|{}", cause);
}

/// local_admins: rows only when no call failed, so a failure after earlier pages never leaves a
/// partial list reading as the list.
inline std::vector<std::string> admin_rows(const yuzu::agent::win::GroupMembersRead& read) {
    std::vector<std::string> rows;
    if (read.status != yuzu::agent::BoundedStatus::Completed || read.nerr != 0)
        return rows;
    for (const auto& m : read.members) {
        // Split domain\name
        std::string domain = "local";
        std::string member_name = m.domain_and_name;
        const auto backslash = m.domain_and_name.find('\\');
        if (backslash != std::string::npos) {
            domain = m.domain_and_name.substr(0, backslash);
            member_name = m.domain_and_name.substr(backslash + 1);
        }
        rows.push_back(
            std::format("admin|{}|{}|{}", member_name, sid_type_name(m.sid_usage), domain));
    }
    return rows;
}

/// group_members: rows only when no call failed.
inline std::vector<std::string> group_member_rows(const yuzu::agent::win::GroupMembersRead& read,
                                                  std::string_view group) {
    std::vector<std::string> rows;
    if (read.status != yuzu::agent::BoundedStatus::Completed || read.nerr != 0)
        return rows;
    for (const auto& m : read.members) {
        const auto backslash = m.domain_and_name.find('\\');
        const std::string member_name = backslash == std::string::npos
                                            ? m.domain_and_name
                                            : m.domain_and_name.substr(backslash + 1);
        rows.push_back(
            std::format("group_member|{}|{}|{}", member_name, group, sid_type_name(m.sid_usage)));
    }
    return rows;
}

} // namespace yuzu::users_win
