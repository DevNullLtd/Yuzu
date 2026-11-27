// win_share_enum.cpp -- bounded read of one NetShareEnum page. See
// yuzu/agent/win_share_enum.hpp for why this lives in agent-core.

#include <yuzu/agent/win_share_enum.hpp>

#include "win_bounded_run.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <lm.h> // NetShareEnum / NetApiBufferFree / SHARE_INFO_1 / SHARE_INFO_2

#include <memory>
#include <type_traits>

#include "win_str.hpp" // yuzu::win::from_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight.
SingleFlightSlot& g_share_slot = detail::new_slot();

#ifdef _WIN32

/// RAII owner of a buffer the NetApi functions allocated.
struct NetApiFree {
    void operator()(void* p) const noexcept { ::NetApiBufferFree(p); }
};

/// The size asked for per call (prefmaxlen is a request, not a guarantee). Well above the
/// largest SHARE_INFO_2 entry under the LAN Manager limits (NNLEN, MAXCOMMENTSZ, MAX_PATH), so
/// a page normally holds many entries.
constexpr DWORD kWinPageBytes = 64 * 1024;

/// One NetShareEnum call at the level `Info` names (SHARE_INFO_1 or SHARE_INFO_2). `path` is
/// null for level 1. `resume` is the API's resume handle: NetShareEnum advances it on
/// ERROR_MORE_DATA.
template <class Info>
SharePage one_page(DWORD resume, LPWSTR Info::*name, LPWSTR Info::*path, DWORD Info::*type) {
    static_assert(std::is_same_v<Info, SHARE_INFO_1> || std::is_same_v<Info, SHARE_INFO_2>);
    constexpr DWORD level = std::is_same_v<Info, SHARE_INFO_2> ? 2 : 1;
    LPBYTE raw = nullptr;
    DWORD read = 0;
    DWORD total = 0;
    const NET_API_STATUS status =
        ::NetShareEnum(nullptr, level, &raw, kWinPageBytes, &read, &total, &resume);
    const std::unique_ptr<BYTE, NetApiFree> buf{raw};
    SharePage page;
    page.nerr = static_cast<std::uint32_t>(status);
    page.total = static_cast<std::uint32_t>(total);
    page.resume = static_cast<std::uint32_t>(resume);
    if ((status == NERR_Success || status == ERROR_MORE_DATA) && buf) {
        // buf is an array of `read` Info entries (aligned by NetApiBufferAllocate); the strings
        // the entries point at live in the same buffer.
        const auto* entries = reinterpret_cast<const Info*>(buf.get());
        page.shares.reserve(read);
        for (DWORD i = 0; i < read; ++i) {
            ShareRec rec;
            rec.name = yuzu::win::from_wide(entries[i].*name);
            if (path != nullptr)
                rec.path = yuzu::win::from_wide(entries[i].*path);
            rec.type = static_cast<std::uint32_t>(entries[i].*type);
            page.shares.push_back(std::move(rec));
        }
    }
    return page;
}

SharePage read_raw(int level, std::uint32_t resume) {
    if (level == 2)
        return one_page<SHARE_INFO_2>(resume, &SHARE_INFO_2::shi2_netname, &SHARE_INFO_2::shi2_path,
                                      &SHARE_INFO_2::shi2_type);
    if (level == 1)
        return one_page<SHARE_INFO_1>(resume, &SHARE_INFO_1::shi1_netname, nullptr,
                                      &SHARE_INFO_1::shi1_type);
    SharePage out;
    out.nerr = ERROR_INVALID_LEVEL;
    return out;
}

#else

SharePage read_raw(int, std::uint32_t) {
    SharePage out;
    out.nerr = 120; // ERROR_CALL_NOT_IMPLEMENTED: no Server service on this OS
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

SharePage read_share_page(int level, std::uint32_t resume, std::chrono::milliseconds deadline) {
    return detail::run_bounded_read<SharePage>(g_share_slot, deadline, "share_enum",
                                               [level, resume] { return read_raw(level, resume); });
}

SharePage read_share_page_for_test(int level, std::uint32_t resume,
                                   std::chrono::milliseconds deadline,
                                   const std::function<SharePage(int, std::uint32_t)>& reader) {
    // An init-capture, so the copy the worker owns is not const (the lambda stays nothrow movable).
    return detail::run_bounded_read<SharePage>(
        g_share_slot, deadline, "share_enum",
        [owned = reader, level, resume] { return owned(level, resume); });
}

} // namespace yuzu::agent::win
