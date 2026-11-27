/**
 * echo_user_collector.cpp -- User session enumeration for Echo plugin
 *
 * Enumerates active user sessions and returns them as structured
 * UserSession records for diff-based change detection (login/logout).
 *
 * Platform support:
 *   Windows -- the Terminal Services session list, read bounded by agent-core
 *              (yuzu/agent/win_wts_sessions.hpp)
 *   Linux   -- /var/run/utmp (struct utmp)
 *   macOS   -- who command output
 */

#include "echo_collectors.hpp"
#include "echo_wts_sessions.hpp" // user_sessions_from_wts (the Windows leg's conversion)

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

namespace yuzu::echo {

// -- Windows implementation ---------------------------------------------------
#ifdef _WIN32

std::vector<UserSession> enumerate_users() {
    return user_sessions_from_wts(
        yuzu::agent::win::read_wts_sessions(yuzu::agent::win::kWtsSessionsDeadline));
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
