#pragma once

/// @file service_completion.hpp
/// Platform-neutral completion-handshake pair for the Windows service shutdown race
/// (#4666 PR-2): service_main() runs on an SCM-spawned thread and reports SERVICE_STOPPED
/// before it finishes its own cleanup, so the SCM's dispatcher can return while
/// service_main is still logging - racing main()'s teardown on a different thread.
/// wait_for_service_main_completion() is the bounded, never-throwing wait main()'s
/// run_service() performs on `done` once the dispatcher returns, before proceeding into
/// teardown; see SemaphoreReleaseGuard's own comment for how `done` gets released.
#include <chrono>
#include <semaphore>

namespace yuzu::agent {

/// RAII guard: releases the given binary semaphore in its destructor, noexcept. Intended
/// to be constructed as the FIRST statement of a function whose semaphore-release must
/// happen after every other local's destructor and every catch-block in that function -
/// declaring it first means (by C++'s reverse-declaration-order destruction) it runs LAST.
class SemaphoreReleaseGuard {
public:
    explicit SemaphoreReleaseGuard(std::binary_semaphore& sem) noexcept : sem_(sem) {}

    ~SemaphoreReleaseGuard() {
        try {
            sem_.release();
        } catch (...) {
            // A semaphore release should not throw in practice, but this guard runs during
            // shutdown and must never propagate.
        }
    }

    SemaphoreReleaseGuard(const SemaphoreReleaseGuard&) = delete;
    SemaphoreReleaseGuard& operator=(const SemaphoreReleaseGuard&) = delete;

private:
    std::binary_semaphore& sem_;
};

/// Waits up to `grace` for `done` to be released. Returns true if it was released within
/// that time, false on timeout. Never throws (any exception from the standard library call
/// is treated as a timeout - false). Does not itself hard-exit; the caller decides what a
/// false return means.
[[nodiscard]] inline bool wait_for_service_main_completion(
    std::binary_semaphore& done, std::chrono::milliseconds grace) noexcept {
    try {
        return done.try_acquire_for(grace);
    } catch (...) {
        return false;
    }
}

} // namespace yuzu::agent
