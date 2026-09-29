#pragma once

/// @file hard_exit.hpp
/// The single shared "leave now, no unwinding" primitive (ADR-0021 rung 7.6,
/// the F3 orphan-exit obligation - see guardian_io_executor.hpp's "ORPHAN
/// PROCESS-EXIT CONTRACT"). main.cpp's signal handlers already needed this
/// exact `#ifdef _WIN32 TerminateProcess #else _exit #endif` pattern twice
/// before this file existed; extracted here so a third call site (the F3
/// orphan-worker check) doesn't duplicate it a third time, and so
/// service_win.cpp's SCM path can share it too.
///
/// WHY TerminateProcess, NOT ::_exit(), ON WINDOWS: ::_exit() routes through
/// ExitProcess, which runs DLL_PROCESS_DETACH for every loaded plugin DLL -
/// taking the loader lock a wedged thread may already hold. TerminateProcess
/// runs no DllMain and takes no loader lock.
///
/// WHY ::_exit(), NOT std::exit(), ON POSIX: exit_group(2) is async-signal-
/// safe - no atexit handlers, no static/DSO destructors, cannot block. That
/// is the entire point: a caller reaching for hard_exit() has already decided
/// normal C++ teardown is not safe to run (a wedged shutdown, or - F3 - a
/// detached Guardian I/O worker that may still be executing library code
/// through it).
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <thread>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace yuzu::agent {

/// The F3 orphan-drain grace, shared by every OrphanExitGuard construction and
/// explicit orphan check (main.cpp x2, service_win.cpp x2) - previously 4
/// independent `std::chrono::seconds(3)` literals with nothing tying them
/// together, so a future edit to one without the others would silently
/// desync the guard's fallback grace from the explicit check's grace (sre
/// Gate 3 finding, this PR). Not yet a CLI/config knob - the motivating case
/// (a slow FUSE/network mount) is exactly the kind of thing an SRE would want
/// to tune per-fleet without a redeploy; tracked as a rung-7.7 follow-up.
inline constexpr std::chrono::seconds kOrphanDrainGrace{3};

/// Terminates the process immediately: no unwinding, no atexit handlers, no
/// static/DSO destructors. `code` should be nonzero for every F3/orphan-
/// triggered call so systemd Restart=/Docker/the Windows SCM see a real
/// failure instead of a silently-successful shutdown - a hard_exit() during
/// what would otherwise be a clean run() return must never look like
/// EXIT_SUCCESS. Not marked [[noreturn]]: TerminateProcess's declared return
/// type does not let the compiler prove that on Windows, and main.cpp's
/// existing call sites (predating this header) rely on the same plain-void
/// shape.
///
/// EXCEPTION (test harness only, #3507 AC1): tests/unit/test_runner_main.cpp
/// calls hard_exit(result) on Windows and macOS where a passing Catch2 run means
/// result == 0 - a deliberate, reviewed departure from the "never look like
/// EXIT_SUCCESS" rule above, argued at that call site. This sentence remains
/// binding for every F3/orphan-triggered call (main.cpp, service_win.cpp);
/// it does not extend to that one test-harness use.
inline void hard_exit(int code) noexcept {
#ifdef _WIN32
    ::TerminateProcess(::GetCurrentProcess(), code);
#else
    ::_exit(code);
#endif
}

/// Polls `active_workers()` until it reports zero or `grace` elapses. Returns
/// true iff it reached zero within the grace period - the pure, testable
/// half of the F3 orphan-exit obligation. The caller decides what "still
/// nonzero after grace" means; main()/service_win.cpp call hard_exit() with a
/// nonzero code rather than let normal process exit run C++ teardown
/// concurrently with a still-running detached I/O worker.
///
/// Templated rather than `std::function<std::size_t()>`: a call site is one
/// or two lines away from hard_exit() on the "not drained" path, and a
/// std::function CONVERSION can itself allocate and throw, which would skip
/// hard_exit() entirely and fall through to the normal teardown this whole
/// mechanism exists to avoid racing (Sol rung-7.6 review finding 2).
template <typename ActiveWorkersFn>
bool wait_for_workers_to_drain(ActiveWorkersFn&& active_workers,
                               std::chrono::milliseconds grace,
                               std::chrono::milliseconds poll_interval =
                                   std::chrono::milliseconds(20)) {
    const auto deadline = std::chrono::steady_clock::now() + grace;
    while (active_workers() > 0) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(poll_interval);
    }
    return true;
}

/// A fail-closed backstop for the F3 orphan-exit check. Construct this
/// immediately BEFORE calling run() - run() itself is not noexcept and has a
/// substantial throwing surface, so a guard armed only after it returns would
/// miss an exception thrown from run() itself - and before any other
/// operation that could throw and unwind past the caller's own explicit check
/// (report_status, a logger flush, a mutex acquisition under resource
/// exhaustion). Call disarm()
/// once that explicit check has run to completion on the normal path. If
/// something throws before disarm() is reached, this guard's destructor
/// performs the SAME check during unwinding, before the caller's own `Agent`
/// is destroyed - otherwise an unrelated exception on that path could skip
/// F3 entirely and let normal C++ teardown run while a Guardian I/O worker
/// is still active, which is precisely what F3 exists to prevent (Sol
/// rung-7.6 review round 3, finding 2: this is NOT the same class of concern
/// as the OOM-cascade findings scoped out of the rung 7.5 series - F3 is a
/// NEW safety guarantee, and a pre-existing exception path silently
/// defeating it is a regression this mechanism introduces, not one it
/// inherits).
///
/// Deliberately does not log: the destructor path exists precisely because
/// logging (among other things) can itself throw, so it must not depend on
/// it succeeding. The caller's own explicit, logged check is what provides
/// diagnostics on the (overwhelmingly common) non-exceptional path.
///
/// Declare this AFTER the caller's `Agent` local so reverse-declaration-order
/// destruction runs it BEFORE the Agent's own destructor on every exit path,
/// exactly like main.cpp's pre-existing `shutdown_watcher`/`AgentUnpublisher`
/// pattern.
template <typename ActiveWorkersFn>
class OrphanExitGuard {
public:
    OrphanExitGuard(ActiveWorkersFn active_workers, std::chrono::milliseconds grace,
                    int hard_exit_code) noexcept
        : active_workers_(std::move(active_workers)), grace_(grace), code_(hard_exit_code) {}

    OrphanExitGuard(const OrphanExitGuard&) = delete;
    OrphanExitGuard& operator=(const OrphanExitGuard&) = delete;

    /// Call once the caller's own explicit orphan check has completed - makes
    /// the destructor below a no-op on the normal path.
    void disarm() noexcept { armed_ = false; }

    ~OrphanExitGuard() noexcept {
        if (!armed_)
            return;
        // Firewalled: wait_for_workers_to_drain()'s std::this_thread::sleep_for
        // is not standard-guaranteed noexcept. Left unguarded, a throw here
        // would still be fail-closed at the language level (an exception
        // escaping a noexcept destructor calls std::terminate()) - but
        // std::terminate() is NOT the same as hard_exit(): on Windows it can
        // still run CRT abort handling, which is closer to the DLL_PROCESS_
        // DETACH/loader-lock hazard hard_exit()'s TerminateProcess call exists
        // specifically to avoid. Catch and route to the intended path instead.
        try {
            if (active_workers_() > 0 && !wait_for_workers_to_drain(active_workers_, grace_))
                hard_exit(code_);
        } catch (...) {
            hard_exit(code_);
        }
    }

private:
    ActiveWorkersFn active_workers_;
    std::chrono::milliseconds grace_;
    int code_;
    bool armed_{true};
};

} // namespace yuzu::agent
