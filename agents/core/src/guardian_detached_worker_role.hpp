#pragma once

/**
 * guardian_detached_worker_role.hpp - marks the DETACHED GuardianIoExecutor worker
 * threads (rung 9c R5.1), the second role GuardianEngine::WorkerHostileMutex aborts on.
 *
 * A different hazard class from guardian_joined_thread_role.hpp's lock-vs-JOIN
 * deadlock. A GuardianIoExecutor worker is detached at creation and can never be
 * joined; it may outlive GuardianEngine::stop() and, past the F3 orphan grace, the
 * process itself (hard_exit.hpp). Blocking such a worker on GuardianEngine::mtx_ is a
 * lock-vs-LIFETIME fault: either it stalls inside the orphan grace until hard_exit()
 * kills the process with work half done, or the lock is granted after stop() and the
 * worker resumes into an engine that is being torn down. Everything a worker runs -
 * the backend call fn(), the publish critical section, and the on_abandoned /
 * on_complete callbacks the consumer injects - must therefore stay off that lock.
 * Review used to be the only enforcement; this marker makes it fail loudly in debug and
 * sanitizer builds instead (design doc §R5.1).
 *
 * Same shape as the joined-thread marker for the same reason: a thread-local flag set
 * by the worker itself, never a thread id or pointer read across threads.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent {

// EXPORTED functions over a header-inline thread_local, deliberately (see
// guardian_joined_thread_role.hpp): an `inline thread_local` in a header gets a SEPARATE
// instance per module, so the worker inside libyuzu_agent_core.so would set the
// library's copy while a test binary read its own and the guard would silently never
// fire. The flag lives in one TU (guardian_detached_worker_role.cpp); everyone goes
// through these.

/// Mark/unmark the calling thread. Use GuardianDetachedWorkerRole, not this directly.
YUZU_EXPORT void set_guardian_detached_worker_thread(bool on) noexcept;

/// True IFF the calling thread is a detached GuardianIoExecutor worker (either dispatch
/// form, including while its consumer-injected callback runs).
/// GuardianEngine::WorkerHostileMutex aborts on this rather than wedging.
[[nodiscard]] YUZU_EXPORT bool on_guardian_detached_worker_thread() noexcept;

/// RAII marker for a worker lambda body. The executor constructs it as the FIRST
/// statement of the worker and destroys its owned user callables inside the marked
/// scope, so fn(), the callbacks, and their capture destructors all run marked. Clears
/// on every exit path.
class GuardianDetachedWorkerRole {
public:
    GuardianDetachedWorkerRole() noexcept { set_guardian_detached_worker_thread(true); }
    ~GuardianDetachedWorkerRole() { set_guardian_detached_worker_thread(false); }
    GuardianDetachedWorkerRole(const GuardianDetachedWorkerRole&) = delete;
    GuardianDetachedWorkerRole& operator=(const GuardianDetachedWorkerRole&) = delete;
};

} // namespace yuzu::agent
