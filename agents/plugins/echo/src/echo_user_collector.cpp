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

    setutent();
    struct utmp* entry = nullptr;
    while ((entry = getutent()) != nullptr) {
        if (entry->ut_type != USER_PROCESS)
            continue;

        UserSession us;
        // ut_user/ut_line/ut_host are fixed-width and not NUL-terminated when full: read them
        // bounded (std::string(char*) would run past the field into the next one).
        us.user = utmp_text(entry->ut_user, sizeof(entry->ut_user));
        us.session_id = utmp_text(entry->ut_line, sizeof(entry->ut_line));

        std::string host = utmp_text(entry->ut_host, sizeof(entry->ut_host));
        us.domain = host.empty() ? "local" : host;

        // Remote when a host is recorded and it is not an X display. The tty name is no evidence:
        // a local terminal emulator is a pts too.
        us.logon_type = logon_type_from_host(host);

        sessions.push_back(std::move(us));
    }
    endutent();
    return sessions;
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

std::vector<UserSession> enumerate_users() {
    std::vector<UserSession> sessions;

    // Use utmpx API instead of parsing `who` output for reliable field extraction
    setutxent();
    struct utmpx* entry = nullptr;
    while ((entry = getutxent()) != nullptr) {
        if (entry->ut_type != USER_PROCESS)
            continue;

        UserSession us;
        // Fixed-width fields, not NUL-terminated when full: read them bounded.
        us.user = utmp_text(entry->ut_user, sizeof(entry->ut_user));
        us.session_id = utmp_text(entry->ut_line, sizeof(entry->ut_line));

        std::string host = utmp_text(entry->ut_host, sizeof(entry->ut_host));
        us.domain = host.empty() ? "local" : host;

        // Remote when a host is recorded and it is not an X display. Every Terminal.app tab is a
        // ttysNNN, so the line name classified local sessions as remote.
        us.logon_type = logon_type_from_host(host);

        sessions.push_back(std::move(us));
    }
    endutxent();
    return sessions;
}

#else
// Unsupported platform
std::vector<UserSession> enumerate_users() {
    return {};
}
#endif

} // namespace yuzu::echo
