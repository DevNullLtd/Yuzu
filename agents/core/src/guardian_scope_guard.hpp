#pragma once

// Terminate-safe rollback guard shared by GuardianEngine and GuardianSparkRuntime
// (ADR-0021 rung 7.7b, PR-1 item 3 / Sol B3 / Fable review).
//
// A rollback fires precisely when something ELSE already threw - very often a
// std::bad_alloc mid-unwind. Its cleanup (index removal that copies a key, a
// backend disarm that reaches a mechanism unwatch) can itself allocate and throw.
// A plain `~ScopeExit` is implicitly noexcept, so a throw from its cleanup during
// unwinding calls std::terminate and kills the whole agent daemon. This guard
// swallows a cleanup throw instead: surviving with a possible leak (e.g. an
// undisarmed watcher) beats crashing every plugin, the heartbeat, and every other
// rule. Swallowed failures are counted for observability (the agent has no /metrics;
// item 9 surfaces this via the heartbeat).

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <functional>

namespace yuzu::agent {

/// Process-wide count of rollback cleanups that threw during unwinding and were
/// swallowed to avoid std::terminate. A nonzero value means a rollback could not
/// fully undo its mutation under memory pressure - a real (if rare) leak signal.
/// YUZU_EXPORT so the test binary can link it against the agent core .so.
[[nodiscard]] YUZU_EXPORT std::uint64_t guardian_rollback_cleanup_failures() noexcept;

/// A committed-or-rollback scope guard whose destructor NEVER propagates an
/// exception. Default-construct it, set `fn` to the undo action, and set
/// `committed = true` on the success path. NON-COPYABLE: a copy would run `fn` twice
/// (double cleanup / double-disarm) - a real footgun now that it is a shared reusable
/// type, so it is deleted rather than left implicitly copyable (cpp-safety + cpp-expert
/// Gate 3). It is therefore not an aggregate; construct-then-assign `g.fn`, never
/// `GuardianRollback g{fn}`.
struct YUZU_EXPORT GuardianRollback {
    std::function<void()> fn;
    bool committed{false};

    GuardianRollback() = default;
    ~GuardianRollback();
    GuardianRollback(const GuardianRollback&) = delete;
    GuardianRollback& operator=(const GuardianRollback&) = delete;
};

} // namespace yuzu::agent
