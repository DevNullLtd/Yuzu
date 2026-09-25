#pragma once

/// @file shutdown_drain_rules.hpp
/// HA WS-8 (ADR-2002 §12 "Draining: fail /readyz, let the fronting layer
/// drain, then stop"): the PURE decision behind `ServerImpl::stop()`'s drain
/// wait, and the one home of its bounds. `stop()` sets `draining_` (so `/readyz`
/// answers 503 `draining`) and then keeps the listener open while
/// `keep_draining()` says so. Everything else keeps serving during the wait —
/// the load balancer has not removed this replica yet, and in-flight requests
/// must still succeed.
///
/// Two independent reasons to wait:
///   1. `--shutdown-drain-seconds N` — a MINIMUM wait, so a load balancer
///      polling `/readyz` sees the 503 and stops routing here BEFORE the
///      socket closes. Without it, a replica with nothing in flight closed its
///      listener immediately and the LB learned about it from refused
///      connections. Default 0 (single-node shutdown unchanged).
///   2. In-flight executions — the pre-existing wait, capped at
///      `kExecutionDrainCap` from drain start.
///
/// Total wait is therefore max(N, time for executions to finish), normally at
/// most max(N, kExecutionDrainCap). Residual: the executions query runs on a
/// pooled connection with no client-side deadline, so against a FROZEN primary
/// one query can overrun the cap. (Skipping the query while the reachability
/// probe is not Ready was tried and reverted: a probe false-negative then ended
/// the drain while executions were still completing.)
///
/// WHAT THIS DOES TO THE STOP BUDGET — and what it does not claim. The grace ADDS
/// up to N seconds to the front of a stacked shutdown whose other stages (the
/// gRPC drain, the web-thread wait, the delivery-queue quiesce, and the app-perf
/// + catalogue roll-up joins the shipped 210s `stop_grace_period` /
/// `TimeoutStopSec` was sized for) are unchanged. There is no fixed total this
/// header can promise, so the operator rule is the plain one: raise the
/// orchestrator's stop timeout by N when setting N (docs/user-manual/
/// server-admin.md, "Load balancers and shutdown drain"). To keep the grace from
/// ENLARGING those later stages, stop() stops both roll-ups from starting new
/// work when draining begins — an hourly recompute can no longer begin inside
/// the grace and then run its full statement budget after it.
/// `kMaxShutdownDrainSeconds` (60) bounds how much an operator can add in one
/// setting; it is not derived from the 210s budget.

#include <chrono>

namespace yuzu::server::shutdown_drain {

inline constexpr int kMaxShutdownDrainSeconds = 60;
inline constexpr std::chrono::seconds kExecutionDrainCap{30};

/// True while `stop()` should keep the listener open.
constexpr bool keep_draining(std::chrono::steady_clock::duration elapsed,
                             std::chrono::seconds min_grace, bool executions_running) noexcept {
    if (elapsed < min_grace)
        return true;
    return executions_running && elapsed < kExecutionDrainCap;
}

} // namespace yuzu::server::shutdown_drain
