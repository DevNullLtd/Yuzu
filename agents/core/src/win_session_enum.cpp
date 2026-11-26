// win_session_enum.cpp -- bounded read of the SMB sessions into this host's shares. See
// yuzu/agent/win_session_enum.hpp for why this lives in agent-core.

#include <yuzu/agent/win_session_enum.hpp>

#include "win_bounded_run.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <lm.h> // NetSessionEnum / NetApiBufferFree / SESSION_INFO_10 / SESSION_INFO_502

#include <memory>

#include "win_str.hpp" // yuzu::win::from_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight.
SingleFlightSlot& g_smb_slot = detail::new_slot();

#ifdef _WIN32

/// RAII owner of a buffer the NetApi functions allocated.
struct NetApiFree {
    void operator()(void* p) const noexcept { ::NetApiBufferFree(p); }
};

/// Every page of one level (MAX_PREFERRED_LENGTH usually returns everything in one call, but
/// the API may still page). The loop, the cap and the progress backstop are drain_net_pages'.
template <class Info>
SmbSessionsRead drain(DWORD level, std::size_t max_entries, LPWSTR Info::*client,
                      LPWSTR Info::*user) {
    DWORD resume = 0; // NetSessionEnum's resume_handle is LPDWORD, not DWORD_PTR
    auto drained = detail::drain_net_pages<SmbSession>(max_entries, [&] {
        LPBYTE raw = nullptr;
        DWORD read = 0;
        DWORD total = 0;
        const NET_API_STATUS status = ::NetSessionEnum(
            nullptr, nullptr, nullptr, level, &raw, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        const std::unique_ptr<BYTE, NetApiFree> buf{raw};
        detail::NetPage<SmbSession> page;
        page.status = static_cast<std::uint32_t>(status);
        page.raw_count = static_cast<std::uint32_t>(read);
        if ((status == NERR_Success || status == ERROR_MORE_DATA) && buf) {
            // The API allocated and aligned buf as an array of `read` Info entries; the strings
            // they point at live in the same buffer, which `buf` owns to the end of this page,
            // and every string is copied out first.
            const auto* entries = reinterpret_cast<const Info*>(buf.get());
            for (DWORD i = 0; i < read; ++i) {
                SmbSession s{yuzu::win::from_wide(entries[i].*client),
                             yuzu::win::from_wide(entries[i].*user)};
                if (!s.client.empty() || !s.user.empty())
                    page.entries.push_back(std::move(s));
            }
        }
        return page;
    });
    SmbSessionsRead out;
    out.nerr = drained.nerr;
    out.truncated = drained.truncated;
    out.no_progress = drained.no_progress;
    out.sessions = std::move(drained.items);
    return out;
}

SmbSessionsRead read_raw(int level, std::size_t max_entries) {
    if (level == 502)
        return drain<SESSION_INFO_502>(502, max_entries, &SESSION_INFO_502::sesi502_cname,
                                       &SESSION_INFO_502::sesi502_username);
    if (level == 10)
        return drain<SESSION_INFO_10>(10, max_entries, &SESSION_INFO_10::sesi10_cname,
                                      &SESSION_INFO_10::sesi10_username);
    SmbSessionsRead out;
    out.nerr = ERROR_INVALID_LEVEL;
    return out;
}

#else

SmbSessionsRead read_raw(int, std::size_t) {
    SmbSessionsRead out;
    out.nerr = 120; // ERROR_CALL_NOT_IMPLEMENTED: no Server service on this OS
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

SmbSessionsRead read_smb_sessions(int level, std::size_t max_entries,
                                  std::chrono::milliseconds deadline) {
    return detail::run_bounded_read<SmbSessionsRead>(
        g_smb_slot, deadline, "smb_sessions",
        [level, max_entries] { return read_raw(level, max_entries); });
}

SmbSessionsRead
read_smb_sessions_for_test(int level, std::size_t max_entries, std::chrono::milliseconds deadline,
                           const std::function<SmbSessionsRead(int, std::size_t)>& reader) {
    // An init-capture, so the copy the worker owns is not const (the lambda stays movable).
    return detail::run_bounded_read<SmbSessionsRead>(
        g_smb_slot, deadline, "smb_sessions",
        [owned = reader, level, max_entries] { return owned(level, max_entries); });
}

} // namespace yuzu::agent::win
