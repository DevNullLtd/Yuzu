#pragma once

/**
 * guardian_emit_decider.hpp - the shared per-rule compliant-edge + drift-debounce
 * decision tail for the Guardian spark consumer (ADR-0021 Stage 2 rung 2 slice 2b).
 *
 * Every guard's emit path ends the same way: decide whether an observation is a
 * compliant edge (emit guard.compliant once), steady compliant (silent), or a
 * drift (emit now, or fold into a debounce-collapsed count). The legacy guards
 * each carry their own copy of that tail (guard_file `report`/`report_compliant`,
 * guard_registry's inline emit lambda, service_classify_edge, systemd_decide_emit).
 * The spark consumer evaluates all three types through ONE handler, so it shares
 * ONE decision tail here instead of three copies. The legacy IGuard classes keep
 * theirs (the --spark-disable path); this is the spark tail only.
 *
 * Generalized from the proven systemd_decide_emit commit rule (guard_systemd.hpp)
 * over a plain compliant-bool, so it is type-agnostic: File / Registry / Service
 * consumer evals compute `compliant` their own way, then feed it here.
 *
 * PURE and clock-injected (pass `now`), so it is fully unit-tested off-platform.
 * Header-only inline: no state crosses a DLL boundary, and the state struct lives
 * per-rule inside the consumer.
 *
 * Dedup note: unlike systemd_decide_emit this carries NO last-terminal-state
 * NoChange dedup. It is not needed at the consumer - the Service mechanism already
 * emits one event per terminal edge, and File/Registry re-read on each change with
 * the debounce window folding rapid repeats - so a plain compliant-bool suffices.
 */

#include <chrono>
#include <cstdint>
#include <optional>

namespace yuzu::agent {

/// What decide_emit decided for one observation.
enum class EmitKind {
    Silent,        ///< steady compliant, OR a debounce-suppressed drift (folded into the count)
    CompliantEdge, ///< transition INTO compliant - emit guard.compliant ONCE
    Drift,         ///< emit drift.detected now; collapsed_count carries the folded suppressed count
};

struct EmitResult {
    EmitKind kind{EmitKind::Silent};
    std::uint64_t collapsed_count{0}; ///< meaningful only when kind == Drift
};

/// Mutable per-rule dedup + debounce state. One instance lives per rule_id in the
/// consumer. `last_compliant == nullopt` means the rule has never been evaluated
/// (so the first compliant observation is an edge). `last_emit`/`suppressed`
/// implement the H3/#1209 collapse-with-count debounce.
struct EmitDeciderState {
    std::optional<bool> last_compliant;
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed{0};
};

/// Decide what to emit for one observation of `compliant`, mutating `state`.
///
/// - `emit_compliant_edge` true: a transition into compliant yields CompliantEdge
///   (File / Registry / Windows-Service behaviour). false: compliant is always
///   Silent (legacy systemd parity - it never emitted guard.compliant).
/// - Drift debounce: within `debounce_ms` of the last drift EMIT, fold into
///   `suppressed` and stay Silent; otherwise emit Drift carrying the folded count.
///   The first drift (no prior emit) always emits.
///
/// Commit rule (mirrors systemd_decide_emit, load-bearing): `last_compliant`
/// commits on every evaluation; `last_emit`/`suppressed` move ONLY on an actual
/// Drift emit - never on a suppressed drift - so a unit that flaps back into the
/// same drift resurfaces (with its collapsed_count) instead of being lost.
[[nodiscard]] inline EmitResult decide_emit(bool compliant, EmitDeciderState& state,
                                            std::uint64_t debounce_ms,
                                            std::chrono::steady_clock::time_point now,
                                            bool emit_compliant_edge = true) {
    if (compliant) {
        const bool edge = (state.last_compliant != true);
        state.last_compliant = true;
        if (edge && emit_compliant_edge)
            return {EmitKind::CompliantEdge, 0};
        return {EmitKind::Silent, 0};
    }
    state.last_compliant = false;
    if (state.last_emit && (now - *state.last_emit) < std::chrono::milliseconds(debounce_ms)) {
        ++state.suppressed; // fold; do NOT move last_emit (so the drift can resurface)
        return {EmitKind::Silent, 0};
    }
    const std::uint64_t collapsed = state.suppressed;
    state.suppressed = 0;
    state.last_emit = now;
    return {EmitKind::Drift, collapsed};
}

} // namespace yuzu::agent
