#pragma once

/**
 * offline_hive_mutex.hpp -- process-wide serialization for the Windows
 * per-user registry-hive offline-mount path (#2771 code-review CFX-1).
 *
 * agents/shared/win_profiles.hpp's with_user_hive() enables
 * SeBackupPrivilege/SeRestorePrivilege on the PROCESS token before an offline
 * RegLoadKeyW mount and restores the token's prior attributes on the way out.
 * Five plugins load this ladder into the SAME agent process -- autoruns,
 * registry, installed_apps, license_scan, tar -- and tar's collectors run on
 * a background thread, so two overlapping offline-mount attempts race the
 * shared process token: A enables it, B enables it (recording A's now-enabled
 * state as "previous"), A's scope exits and restores to B's recorded
 * "previous" -- silently disabling it out from under B, mid-mount.
 *
 * A std::mutex defined as a plain `inline`/header-local static in
 * win_profiles.hpp does NOT solve this: each plugin .dll/.so file is a
 * SEPARATE dynamically loaded module, and a function-local static in a
 * header is instantiated once PER TRANSLATION UNIT THAT LINKS IT IN -- in
 * practice, once per plugin binary. Five plugins therefore got five
 * independent mutexes, not one process-wide lock (confirmed: each plugin DLL
 * exports exactly its one required `yuzu_plugin_descriptor` symbol and
 * nothing else -- the mutex was never shared).
 *
 * The fix is the one this codebase already uses for the identical problem --
 * see fork_lock.hpp's global_fork_lock(): define the mutex ONCE in
 * agents/core (compiled into the single yuzu_agent_core shared library every
 * plugin links against) and export it via YUZU_EXPORT, so every plugin's
 * import resolves to the SAME address in the SAME already-loaded module.
 *
 * Scope: covers the whole offline arm (privilege enable -> RegLoadKeyW -> fn
 * -> unload -> restore), not just the RegLoadKeyW call itself -- see
 * win_profiles.hpp's with_user_hive() for where it is taken. The live-hive
 * path (the common case) never takes this lock.
 *
 * INSTRUMENTATION: this one process-wide lock serialises the offline arm
 * for FIVE plugins via with_user_hive() -- autoruns, installed_apps,
 * license_scan, registry, tar -- plus a SIXTH, execution_artifacts's
 * AmCache leg (execution_artifacts_win.cpp), which calls the lock directly
 * as `ScopedOfflineHiveLock("execution_artifacts")` rather than through
 * with_user_hive() -- so a long hold by any one of the six blocks the
 * other five with no prior visibility into it. `ScopedOfflineHiveLock`
 * wraps the acquire/release with a wait-time and hold-time log (spdlog,
 * this codebase's existing agent-side logging mechanism) so an unusually
 * long wait or hold is visible without
 * instrumenting every call site by hand. Both lines log together from the
 * destructor, after the mutex is released, so logging itself never extends
 * another caller's wait. Prefer it over a bare
 * `std::lock_guard<std::mutex>(offline_hive_mutex())` for any new caller;
 * today with_user_hive() (agents/shared/win_profiles.hpp) is the only call
 * site, serving the five plugins above.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <mutex>

namespace yuzu::agent {

/**
 * The process-global offline-hive-mount lock. Prefer `ScopedOfflineHiveLock`
 * below over taking this directly -- see the file header for the full
 * contract.
 */
YUZU_EXPORT std::mutex& offline_hive_mutex();

/**
 * RAII guard around offline_hive_mutex() that logs how long this call
 * waited to acquire the lock and how long it held it -- see the file
 * header's INSTRUMENTATION note. `caller` is a short, static string
 * identifying the call site (e.g. "with_user_hive", "execution_artifacts")
 * for attributing contention; it is never freed, so pass a string literal.
 */
class YUZU_EXPORT ScopedOfflineHiveLock {
public:
    explicit ScopedOfflineHiveLock(const char* caller);
    ~ScopedOfflineHiveLock();

    ScopedOfflineHiveLock(const ScopedOfflineHiveLock&) = delete;
    ScopedOfflineHiveLock& operator=(const ScopedOfflineHiveLock&) = delete;

private:
    const char* caller_;
    // std::unique_lock, never a bare lock()/unlock() pair on the raw mutex
    // (docs/cpp-conventions.md's Concurrency section) -- constructed
    // std::defer_lock so the constructor can still measure wait time around
    // the explicit lock() call below.
    std::unique_lock<std::mutex> lock_;
    std::chrono::steady_clock::time_point acquired_at_;
    // Measured in the constructor, logged in the destructor (after unlock) --
    // see offline_hive_mutex.cpp.
    std::chrono::milliseconds waited_{};
};

} // namespace yuzu::agent
