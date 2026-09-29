#pragma once

/**
 * guardian_joined_thread_role.hpp - marks the threads GuardianEngine::stop() joins
 * while holding mtx_ (#2298 Gate 4).
 *
 * GuardianEngine::stop() holds mtx_ across its whole body AND joins both the
 * ConvergenceScheduler lanes and the outbox drain worker inside it. Any mtx_
 * acquisition on ANY of those threads is a lock-vs-join deadlock: a hung agent
 * shutdown, fleet-wide.
 *
 * The invariant is therefore about a CLASS of threads, not one worker. C0 first
 * shipped it as a drain-worker-only guard, which left the scheduler's four lane
 * threads carrying the identical hazard with nothing checking them - an asymmetry
 * that reads as "the scheduler must be safe" when nobody had established that.
 *
 * A thread-local marker, rather than comparing against a thread id held by the
 * engine: an engine-side pointer would have to be read before the engine's own
 * mutex is held (an unsynchronised cross-thread read) and can dangle across wiring
 * rollback - which is how the first version of this guard became a data race and a
 * potential use-after-free in the very device meant to prevent a hang.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent {

// EXPORTED functions over a header-inline thread_local, deliberately. An
// `inline thread_local` in a header gets a SEPARATE instance in each module that
// includes it: the worker loop inside libyuzu_agent_core.so would set the library's
// copy while a test binary read its own, and the guard would silently never fire.
// The flag lives in one TU; everyone goes through these.

/// Mark/unmark the calling thread. Use GuardianJoinedThreadRole, not this directly.
YUZU_EXPORT void set_guardian_joined_thread(bool on) noexcept;

/// True IFF the calling thread is one GuardianEngine::stop() joins while holding
/// mtx_. GuardianEngine::WorkerHostileMutex aborts on this rather than deadlocking.
[[nodiscard]] YUZU_EXPORT bool on_guardian_joined_thread() noexcept;

/// RAII marker for a worker loop body. Clears on every exit path, including an
/// exception escaping the loop - which nothing should do, since every pass is
/// firewalled, but the marker must not outlive the role even then.
class GuardianJoinedThreadRole {
public:
    GuardianJoinedThreadRole() noexcept { set_guardian_joined_thread(true); }
    ~GuardianJoinedThreadRole() { set_guardian_joined_thread(false); }
    GuardianJoinedThreadRole(const GuardianJoinedThreadRole&) = delete;
    GuardianJoinedThreadRole& operator=(const GuardianJoinedThreadRole&) = delete;
};

} // namespace yuzu::agent
