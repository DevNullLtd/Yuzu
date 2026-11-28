// win_join_info.cpp -- bounded read of the join information. See
// yuzu/agent/win_join_info.hpp for why this lives in agent-core.

#include <yuzu/agent/win_join_info.hpp>

#include "win_bounded_run.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <lm.h> // NetGetJoinInformation, NetApiBufferFree

#include <memory>

#include "win_str.hpp" // yuzu::win::from_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight.
SingleFlightSlot& g_join_slot = detail::new_slot();

#ifdef _WIN32

/// RAII owner of a buffer the NetApi functions allocated.
struct NetFree {
    void operator()(void* p) const noexcept { ::NetApiBufferFree(p); }
};

JoinInfoRead read_raw() {
    JoinInfoRead out;
    LPWSTR raw = nullptr;
    NETSETUP_JOIN_STATUS join_status{};
    out.nerr = ::NetGetJoinInformation(nullptr, &raw, &join_status);
    const std::unique_ptr<wchar_t, NetFree> name{raw};
    if (out.nerr != NERR_Success)
        return out;
    out.has_name = name != nullptr;
    out.name = yuzu::win::from_wide(name.get());
    out.join_status = static_cast<std::uint32_t>(join_status);
    return out;
}

#else

JoinInfoRead read_raw() {
    JoinInfoRead out;
    out.nerr = 120; // ERROR_CALL_NOT_IMPLEMENTED: no join information on this OS
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

JoinInfoRead read_join_info(std::chrono::milliseconds deadline) {
    return detail::run_bounded_read<JoinInfoRead>(g_join_slot, deadline, "join_info",
                                                  [] { return read_raw(); });
}

JoinInfoRead read_join_info_for_test(std::chrono::milliseconds deadline,
                                     const std::function<JoinInfoRead()>& reader) {
    return detail::run_bounded_read<JoinInfoRead>(g_join_slot, deadline, "join_info", reader);
}

} // namespace yuzu::agent::win
