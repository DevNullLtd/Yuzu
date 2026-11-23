// win_thread_error_mode.hpp -- the thread-scoped error-mode guard, in one place.
//
// RAII: sets the calling thread's error mode on construction and restores the previous one on scope exit.
// It suppresses the session-0 hard-error dialog around a query against a not-ready removable or
// BitLocker-locked volume, which would otherwise block a bounded dispatch-pool worker. Thread-scoped,
// never the process-wide SetErrorMode, which would race other workers in the same pool.
//
// This is the promotion that disk_actions_win.cpp's local copy calls for; the older copies (disk_actions,
// disk_space_plugin, filesystem_posture_win) are not migrated here.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty elsewhere.
#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace yuzu::win {

class ThreadErrorModeGuard {
public:
    explicit ThreadErrorModeGuard(DWORD mode) noexcept { ::SetThreadErrorMode(mode, &prev_); }
    ~ThreadErrorModeGuard() { ::SetThreadErrorMode(prev_, nullptr); }
    ThreadErrorModeGuard(const ThreadErrorModeGuard&) = delete;
    ThreadErrorModeGuard& operator=(const ThreadErrorModeGuard&) = delete;

private:
    DWORD prev_ = 0;
};

} // namespace yuzu::win

#endif // _WIN32
