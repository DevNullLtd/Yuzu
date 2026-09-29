// Rotation successor-unused warning: which signals fire on THIS tick.
//
// The rotation sweep re-observes the same stuck pair every tick (60s), and the
// three signals it can emit do NOT share a cadence. Keeping that decision here
// rather than inline in the sweep driver is what makes it testable at all —
// the driver lives in a thread lambda inside `ServerImpl` and has never had a
// test, which is how an un-throttled audit write reached review.
//
// The cadences, and why each is what it is:
//
//   * LOG          — every tick once the window has ELAPSED. That pair is a
//                    live, indefinite condition an operator greps for, and
//                    logs rotate, so repetition is free. Nothing is logged
//                    before the window elapses: the pair is still on schedule.
//   * COUNT + AUDIT — ONCE per pair per state, and they share that cadence
//                     DELIBERATELY. The audit row is the SOC 2 evidence, and
//                     evidence records that the decline HAPPENED, not how many
//                     times it was re-observed: at a 60s tick an un-throttled
//                     row is ~1440/day for ONE stuck pair, written into a
//                     store whose retention pass caps at 25 000 deletions, so
//                     a few indefinitely-stuck pairs would outpace real
//                     operator activity and push genuine evidence out of the
//                     window. The counter is held to the same cadence so the
//                     series keeps ONE meaning — an event count. Making it
//                     per-tick would turn the same series into a rate for
//                     elapsed pairs and leave it an event count for
//                     pre-elapse ones, which no alert can read.
//
// That leaves a persistently-stuck pair with no alertable RATE — only a log
// line. That gap is real and pre-existing (issue #2964: no rotation failure
// mode is alertable today), and closing it belongs there, as a deliberate new
// signal reviewed by `sre`, not as a silent semantic change to an existing
// counter made in passing by an audit-volume fix.
//
// PRE-ELAPSE and ELAPSED are tracked SEPARATELY and deliberately not folded
// into one set. The elapsed branch must bypass the pre-elapse de-dup (that is
// the whole point of warning past the window), so a shared set would either
// make the elapsed audit inherit the de-dup it exists to skip, or silence the
// lead-time warning once the pair elapsed. Two states, two sets.
//
// PROCESS-LOCAL, by the same precedent as `ApiTokenStore`'s rotation grace
// cache: a restart forfeits the state and re-emits once. That is correct
// rather than merely tolerable — the new process holds no record that it ever
// declined, so a fresh evidence row is the honest output. It does mean N
// replicas emit N times; the rotation consent record has the same property and
// is tracked as issue #2961.

#pragma once

#include <cstddef>
#include <string>
#include <unordered_set>

namespace yuzu::server {

/// What the sweep driver should emit for one pair on one tick.
struct RotationWarnSignals {
    /// spdlog line — elapsed pairs only, every tick.
    bool log = false;
    /// Metric increment AND audit row — once per pair per state. One flag,
    /// not two, because they share a cadence by design (see the header note):
    /// two fields would imply an independence that does not exist and invite
    /// a later change to drift them apart without deciding to.
    bool record_event = false;
};

/// Per-tick de-duplication for the successor-unused warning. Not thread-safe:
/// owned by, and only ever touched from, the single rotation-sweep thread.
class RotationWarnDedup {
public:
    /// Decide this tick's signals for `rotation_group`, and record the
    /// decision. Call exactly once per pair per tick — it mutates state.
    ///
    /// `elapsed` is `predecessor.overlap_expires_at <= now`: the pair is past
    /// its overlap window and `sweep_expired_rotations` has WITHHELD
    /// auto-revoke on it because the successor was never presented — a
    /// per-pair eligibility gate, not the SAME "declined" as
    /// `ApiTokenStore::SweepOutcome::Declined` (the sweep's tick-level clock
    /// guard verdict, #2964) — the two are deliberately worded differently
    /// in every caller-facing log/audit string so they read as distinct
    /// concepts, which they are.
    RotationWarnSignals observe(const std::string& rotation_group, bool elapsed) {
        RotationWarnSignals out;
        if (elapsed) {
            out.log = true;
            out.record_event = audited_elapsed_.insert(rotation_group).second;
        } else {
            // Pre-elapse: one heads-up per rotation attempt, unchanged from
            // the behaviour that shipped before the elapsed state existed.
            out.record_event = warned_pre_elapse_.insert(rotation_group).second;
        }
        return out;
    }

    /// The pair resolved (revoked, confirmed, or the successor was finally
    /// used), so a later rotation on the same principal warns again. `prune`
    /// would catch this on the next tick regardless; this is the prompt path.
    void resolve(const std::string& rotation_group) {
        warned_pre_elapse_.erase(rotation_group);
        audited_elapsed_.erase(rotation_group);
    }

    /// Drop state for every group not in `still_present` — the authoritative
    /// per-tick reconcile, so a pair that vanishes for any reason frees its
    /// slot without the driver having to name the reason.
    void prune(const std::unordered_set<std::string>& still_present) {
        std::erase_if(warned_pre_elapse_,
                      [&](const std::string& g) { return !still_present.contains(g); });
        std::erase_if(audited_elapsed_,
                      [&](const std::string& g) { return !still_present.contains(g); });
    }

    /// Test/diagnostic accessors — the tracked-group counts, never identities.
    std::size_t tracked_pre_elapse() const noexcept { return warned_pre_elapse_.size(); }
    std::size_t tracked_elapsed() const noexcept { return audited_elapsed_.size(); }

private:
    std::unordered_set<std::string> warned_pre_elapse_;
    std::unordered_set<std::string> audited_elapsed_;
};

} // namespace yuzu::server
