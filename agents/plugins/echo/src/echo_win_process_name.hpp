#pragma once

/**
 * echo_win_process_name.hpp -- Windows-only: the owning process's basename for a pid.
 * Include ONLY inside `#ifdef _WIN32`, after <windows.h>.
 *
 * Shared by the ETW consumers that name the process behind an event (the module
 * image consumer and the registry attribution leg) so the OpenProcess handle has one
 * RAII owner instead of a copy per translation unit.
 */

#include <guard_win_handle.hpp> // yuzu::agent::detail::ScopedWinHandle (agents/core/src)
#include <win_str.hpp>          // yuzu::win::from_wide

#include <cstdint>
#include <string>

namespace yuzu::echo {

/// Best-effort owning-process basename for a (usually still-alive) pid. Callers cache
/// it by pid so QueryFullProcessImageName runs ~once per pid. "" for protected or
/// exited processes, and on any failure.
///
/// `event_ts100ns` (0 = unchecked) is the FILETIME of the event the pid came from: a
/// process created after it cannot have produced it, so the pid was reused and "" is
/// returned. A pid reused by a process that was already running at the event, or that
/// is looked up from a cache after it was reused, is not detected.
inline std::string process_basename_for_pid(std::uint32_t pid, std::int64_t event_ts100ns = 0) {
    yuzu::agent::detail::ScopedWinHandle<&yuzu::agent::detail::close_handle_> proc{
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!proc)
        return {};
    if (event_ts100ns != 0) {
        // The event's stamp comes from the coarse system clock, which ticks every ~15.6 ms,
        // and the consumer sees the event some time after the kernel stamped it. A process
        // that wrote within its first moments must not read as created after its own event:
        // 100 ms is six clock ticks of margin for that gap.
        constexpr std::int64_t kClockSlack100ns = 1'000'000; // 100 ms
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(proc.get(), &created, &exited, &kernel, &user))
            return {};
        const auto created_at = static_cast<std::int64_t>(
           (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime);
        if (created_at > event_ts100ns + kClockSlack100ns)
            return {};
    }
    wchar_t buf[MAX_PATH];
    DWORD len = MAX_PATH;
    if (!QueryFullProcessImageNameW(proc.get(), 0, buf, &len) || len == 0)
        return {};
    const std::wstring path(buf, len);
    const auto pos = path.find_last_of(L"\\/");
    return yuzu::win::from_wide((pos == std::wstring::npos ? path : path.substr(pos + 1)).c_str());
}

} // namespace yuzu::echo
