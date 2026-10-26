#pragma once

/**
 * tar_win_process_name.hpp -- Windows-only: the owning process's basename for a pid.
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

namespace yuzu::tar {

/// Best-effort owning-process basename for a (usually still-alive) pid. Callers cache
/// it by pid so QueryFullProcessImageName runs ~once per pid. "" for protected or
/// exited processes, and on any failure.
inline std::string process_basename_for_pid(std::uint32_t pid) {
    yuzu::agent::detail::ScopedWinHandle<&yuzu::agent::detail::close_handle_> proc{
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!proc)
        return {};
    wchar_t buf[MAX_PATH];
    DWORD len = MAX_PATH;
    if (!QueryFullProcessImageNameW(proc.get(), 0, buf, &len) || len == 0)
        return {};
    const std::wstring path(buf, len);
    const auto pos = path.find_last_of(L"\\/");
    return yuzu::win::from_wide((pos == std::wstring::npos ? path : path.substr(pos + 1)).c_str());
}

} // namespace yuzu::tar
