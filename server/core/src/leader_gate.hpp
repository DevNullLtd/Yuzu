#pragma once

/// @file leader_gate.hpp
/// WS-3 slice 3.2 (ADR-2002 §3/§6): the runtime consumer of WS-10's background-
/// job classification. `background_jobs.hpp` decides, at COMPILE TIME, which
/// passes are `FencedLeaderOnly`; this header turns that decision into the loop
/// gate — a `FencedLeaderOnly` pass runs only while THIS process holds fenced
/// leadership (`LeaderElector::is_leader()`); everything else runs regardless.
///
/// ANTI-DRIFT — the whole point. The gate reads the SAME `kBackgroundJobs`
/// classification that the `YUZU_ASSERT_BACKGROUND_JOB` site assertion pins, via
/// `background_job_class()`. Re-classifying a pass in `background_jobs.hpp` moves
/// its runtime gate with it; there is no second list of "which loops are leader-
/// only" to fall out of step — that drift is exactly what this seam removes (the
/// same failure mode `dispatch_confined_arms`, `authz_topology_floor`, and
/// `body_cap_policy` each exist to prevent for their own chokepoints).
///
/// THIS IS THE ATTEMPT GATE, NOT THE CORRECTNESS FENCE (§6; ws3-plan §5).
/// `is_leader()` gates whether a loop ATTEMPTS its side effect; a momentarily-
/// stale leader can still pass it. The guarantee against a paused ex-leader is
/// the `epoch_fence_sql()` predicate embedded in each LEADER-DRIVEN claim's
/// WRITE (slice 3.3's command outbox), NOT this gate. Operator-synchronous
/// claims (slice 3.4's remediation) use their own plain guarded CAS instead —
/// see TWO DISPATCH PLANES below. On the single-replica deployment this gate is
/// operationally inert: the sole replica is always the leader once it acquires,
/// so every `FencedLeaderOnly` loop runs exactly as before.
///
/// TWO DISPATCH PLANES (§Decision 1). This gate is for LEADER-DRIVEN BACKGROUND
/// loops only. An operator-triggered SYNCHRONOUS path (e.g. `PolicyEvaluator::
/// remediate`, the operator revoke that publishes a CRL) runs on whichever
/// replica received the request and MUST NOT be gated — arbitrated by its own
/// per-occurrence CAS. Gate the background tick site, never the shared primitive
/// the operator path also calls.
///
/// `DisabledUntilFixed` maps to "run" here ON PURPOSE. Those passes (nvd_sync,
/// the concurrency-claims reconciler) must keep running on today's single
/// replica; a `DisabledUntilFixed` pass is held back by the DEPLOYMENT safe-to-
/// scale gate — no 2nd replica until its named fix lands — never by this runtime
/// gate. Only `FencedLeaderOnly` consults the elector; making this branch deny
/// would silently disable those passes on the single replica (a regression).

#include "background_jobs.hpp"
#include "leader_elector.hpp"

namespace yuzu::server {

/// Pure decision (unit-testable without Postgres): may a pass of class `cls` run
/// this tick, given whether this replica currently leads? Only `FencedLeaderOnly`
/// requires leadership; `ReplicaSafe` and `DisabledUntilFixed` run regardless
/// (see the `DisabledUntilFixed` note above).
[[nodiscard]] constexpr bool background_pass_may_run(BackgroundJobClass cls,
                                                     bool is_leader) noexcept {
    return cls != BackgroundJobClass::FencedLeaderOnly || is_leader;
}

/// Call-site gate. `Cls` is `background_job_class("pass")` — a consteval lookup,
/// so applying the gate to an unclassified pass is a build failure (fail-closed).
/// The `if constexpr` calls `is_leader()` ONLY for a `FencedLeaderOnly` pass, so
/// a `ReplicaSafe`/`DisabledUntilFixed` site pays nothing and never touches the
/// elector. `is_leader()` is a lock-free read (see `leader_elector.hpp`), so a
/// stalled election loop can never block a worker tick asking whether it may run.
/// A null `elector` (never wired) denies a `FencedLeaderOnly` pass — fail-closed.
template <BackgroundJobClass Cls>
[[nodiscard]] bool leader_gate_permits(const LeaderElector* elector) noexcept {
    if constexpr (Cls == BackgroundJobClass::FencedLeaderOnly)
        return elector != nullptr && elector->is_leader();
    else
        return true;
}

} // namespace yuzu::server
