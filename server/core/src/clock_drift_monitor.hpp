#pragma once

/**
 * clock_drift_monitor.hpp -- backward wall-clock drift detector (HA WS-1/1a,
 * ADR-2002 §4 mitigation (a)).
 *
 * The durable-session design authors and validates lifetime/JIT/MFA deadlines on
 * the WALL clock, so a backward wall-clock step — or a STOPPED / slowly-slewed-
 * backward clock — un-expires sessions and extends live privilege windows. This
 * detector is the "monitor for backward movement; alert" mitigation the ADR
 * requires.
 *
 * It compares the wall clock against a MONOTONIC reference (steady_clock) by
 * tracking the OFFSET (wall - steady) against a retained baseline, and
 * accumulates sub-threshold divergence rather than resetting each observation —
 * so an arbitrarily large total anomaly built from small per-sample steps (a
 * stopped clock: each sample diverges by only the sampling interval) is still
 * caught (adversarial-round #2/#3 C1: a per-sample tolerance that re-baselines
 * every tick is blind to a stopped clock).
 *
 * Pure decision code (no I/O, no clock reads of its own — the caller injects both
 * readings), so it is unit-testable deterministically without the maintenance
 * thread. `observe()` returns true exactly when a backward drift exceeding the
 * tolerance is detected on this observation.
 */

#include <cstdint>

namespace yuzu::server {

class ClockDriftMonitor {
public:
    explicit ClockDriftMonitor(std::int64_t tolerance_ms) : tolerance_ms_(tolerance_ms) {}

    /// Feed one paired reading of the wall clock and a monotonic clock (same
    /// unit, milliseconds). Returns true iff the wall clock has fallen behind the
    /// monotonic reference, cumulatively, by more than the tolerance since the
    /// last baseline — i.e. a backward step, stall, or slow negative slew.
    ///
    /// - A HEALTHY clock keeps `offset = wall - steady` ~constant → never fires.
    /// - A scheduling delay advances BOTH by the delay → offset constant → no fire.
    /// - A backward step / stop / slew LOWERS the offset; once the cumulative drop
    ///   crosses the tolerance it fires and re-baselines (so a persistent stall
    ///   keeps firing once per tolerance-worth of drift, not once per sample).
    /// - A forward wall jump RAISES the offset; the baseline adopts the new high
    ///   so a later backward drift is measured from it (forward jumps are not a
    ///   window-extension hazard and are handled by the reap forward-skew decline).
    [[nodiscard]] bool observe(std::int64_t wall_ms, std::int64_t steady_ms) {
        const std::int64_t offset = wall_ms - steady_ms;
        if (!valid_) {
            baseline_offset_ = offset;
            valid_ = true;
            return false;
        }
        const std::int64_t backward_drift = baseline_offset_ - offset; // >0: wall behind monotonic
        if (backward_drift > tolerance_ms_) {
            baseline_offset_ = offset; // re-baseline: count each tolerance-worth once
            return true;
        }
        if (offset > baseline_offset_)
            baseline_offset_ = offset; // forward jump: adopt the new higher baseline
        return false;
    }

private:
    std::int64_t tolerance_ms_;
    std::int64_t baseline_offset_ = 0;
    bool valid_ = false;
};

} // namespace yuzu::server
