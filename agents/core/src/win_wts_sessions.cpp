// win_wts_sessions.cpp -- bounded read of the Terminal Services session list. See
// yuzu/agent/win_wts_sessions.hpp for why this lives in agent-core.

#include <yuzu/agent/win_wts_sessions.hpp>

#include "win_bounded_run.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wtsapi32.h>

#include <algorithm>
#include <memory>

#include "win_str.hpp" // yuzu::win::from_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight.
SingleFlightSlot& g_wts_slot = detail::new_slot();

#ifdef _WIN32

/// RAII owner of a buffer the WTS API allocated.
struct WtsFree {
    void operator()(void* p) const noexcept { ::WTSFreeMemory(p); }
};

std::string query_text(DWORD session_id, WTS_INFO_CLASS what) {
    LPWSTR raw = nullptr;
    DWORD bytes = 0;
    const BOOL ok =
        ::WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, what, &raw, &bytes);
    const std::unique_ptr<wchar_t, WtsFree> owned{raw};
    return ok ? yuzu::win::from_wide(owned.get()) : std::string{};
}

WtsSessionsRead read_raw() {
    WtsSessionsRead out;
    PWTS_SESSION_INFOW raw = nullptr;
    DWORD count = 0;
    if (!::WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &raw, &count)) {
        out.win_error = ::GetLastError();
        return out;
    }
    const std::unique_ptr<WTS_SESSION_INFOW, WtsFree> list{raw};
    out.enumerated = true;
    out.truncated = count > kMaxWtsSessions;
    const std::size_t n = std::min<std::size_t>(count, kMaxWtsSessions);
    out.sessions.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        const WTS_SESSION_INFOW& s = raw[i];
        out.sessions.push_back(
            {s.SessionId, static_cast<std::uint32_t>(s.State),
             yuzu::win::from_wide(s.pWinStationName), query_text(s.SessionId, WTSUserName),
             query_text(s.SessionId, WTSDomainName), query_text(s.SessionId, WTSClientName)});
    }
    return out;
}

#else

WtsSessionsRead read_raw() {
    WtsSessionsRead out;
    out.win_error = 120; // ERROR_CALL_NOT_IMPLEMENTED: no Terminal Services on this OS
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

WtsSessionsRead read_wts_sessions(std::chrono::milliseconds deadline) {
    return detail::run_bounded_read<WtsSessionsRead>(g_wts_slot, deadline, "wts_sessions",
                                                     [] { return read_raw(); });
}

WtsSessionsRead read_wts_sessions_for_test(std::chrono::milliseconds deadline,
                                           const std::function<WtsSessionsRead()>& reader) {
    return detail::run_bounded_read<WtsSessionsRead>(g_wts_slot, deadline, "wts_sessions", reader);
}

} // namespace yuzu::agent::win
