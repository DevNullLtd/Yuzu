/**
 * echo_user_collector.cpp -- User session enumeration for Echo plugin
 *
 * Enumerates active user sessions and returns them as structured
 * UserSession records for diff-based change detection (login/logout).
 *
 * Platform support:
 *   Windows -- WTSEnumerateSessionsW + WTSQuerySessionInformationW
 *   Linux   -- /var/run/utmp (struct utmp)
 *   macOS   -- who command output
 */

#include "echo_collectors.hpp"

#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#ifdef __linux__
#include <utmp.h>
#endif

#ifdef __APPLE__
#include <utmpx.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <wtsapi32.h>
#endif

namespace yuzu::echo {

// -- Windows implementation ---------------------------------------------------
#ifdef _WIN32

namespace {

// wide->UTF-8 conversion now via the shared win_str.hpp (#1681); from_wide is
// behaviour-identical to the old NUL-terminated wide_to_utf8_user for valid input.
using yuzu::win::from_wide;

} // namespace

std::vector<UserSession> enumerate_users() {
    std::vector<UserSession> sessions;

    WTS_SESSION_INFOW* wts_sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &wts_sessions, &count))
        return sessions;

    for (DWORD i = 0; i < count; ++i) {
        if (wts_sessions[i].State != WTSActive && wts_sessions[i].State != WTSDisconnected)
            continue;

        LPWSTR user_buf = nullptr;
        DWORD user_len = 0;
        LPWSTR domain_buf = nullptr;
        DWORD domain_len = 0;

        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, wts_sessions[i].SessionId,
                                    WTSUserName, &user_buf, &user_len);
        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, wts_sessions[i].SessionId,
                                    WTSDomainName, &domain_buf, &domain_len);

        auto user = from_wide(user_buf);
        auto domain = from_wide(domain_buf);

        if (user_buf)
            WTSFreeMemory(user_buf);
        if (domain_buf)
            WTSFreeMemory(domain_buf);

        if (user.empty())
            continue;

        UserSession us;
        us.user = user;
        us.domain = domain.empty() ? "local" : domain;
        us.session_id = std::to_string(wts_sessions[i].SessionId);
        us.disconnected = wts_sessions[i].State == WTSDisconnected;

        // Determine logon type from session name
        auto station_name = from_wide(wts_sessions[i].pWinStationName);
        if (station_name.find("RDP") != std::string::npos ||
            station_name.find("rdp") != std::string::npos) {
            us.logon_type = "remote";
        } else {
            us.logon_type = "interactive";
        }

        sessions.push_back(std::move(us));
    }
    WTSFreeMemory(wts_sessions);
    return sessions;
}

// -- Linux implementation -----------------------------------------------------
#elif defined(__linux__)

std::vector<UserSession> enumerate_users() {
    std::vector<UserSession> sessions;

    // Ends the login-database session on every exit path, including a throwing push_back (#6903).
    struct UtmpSession {
        UtmpSession() { setutent(); }
        ~UtmpSession() { endutent(); }
        UtmpSession(const UtmpSession&) = delete;
        UtmpSession& operator=(const UtmpSession&) = delete;
    } utmp_session;
    struct utmp* entry = nullptr;
    while ((entry = getutent()) != nullptr) {
        if (entry->ut_type != USER_PROCESS)
            continue;

        // Bounded field reads and the remote-vs-interactive rule live in the shared conversion
        // (echo_collectors.hpp), which the unit tests drive with hand-built records.
        sessions.push_back(user_session_from_utmp(*entry));
    }
    return sessions;
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

std::vector<UserSession> enumerate_users() {
    std::vector<UserSession> sessions;

    // Use utmpx API instead of parsing `who` output for reliable field extraction. The session
    // ends on every exit path, including a throwing push_back (#6903).
    struct UtmpxSession {
        UtmpxSession() { setutxent(); }
        ~UtmpxSession() { endutxent(); }
        UtmpxSession(const UtmpxSession&) = delete;
        UtmpxSession& operator=(const UtmpxSession&) = delete;
    } utmpx_session;
    struct utmpx* entry = nullptr;
    while ((entry = getutxent()) != nullptr) {
        if (entry->ut_type != USER_PROCESS)
            continue;

        // Every Terminal.app tab is a ttysNNN, so the line name is no evidence of a remote
        // session: the shared conversion classifies on ut_host (echo_collectors.hpp).
        sessions.push_back(user_session_from_utmp(*entry));
    }
    return sessions;
}

#else
// Unsupported platform
std::vector<UserSession> enumerate_users() {
    return {};
}
#endif

} // namespace yuzu::echo
