#pragma once

/// @file audit_retention_rules.hpp
/// The decision rule of the audit retention clock guard (#2360), as a pure
/// function.
///
/// Split out of `AuditStore` deliberately, following the convention the other
/// server stores use for exactly this problem (`preflight_parse.hpp`,
/// `deployment_parse.hpp`, `network_perf_rules.hpp`, `compliance_eval.hpp`): a
/// pure decision function lives in its own header so it can be pinned by a
/// table test with no database, no clock and no fixture, WITHOUT widening the
/// store's public class surface. No sibling store exposes a public static, and
/// `AuditStore` should not be the first.
///
/// Why it is worth isolating: the retention guard's precedence went unpinned
/// long enough for two separate mutations to survive, because reaching it meant
/// standing up a seeded multi-pass integration test. As a free function it is
/// five bools in, one enum out.

#include <cstdint>

namespace yuzu::server::audit_retention {

/// What the guard can conclude about one retention pass, in precedence order.
enum class Anomaly {
    None,     ///< Nothing to report; the pass may delete (paced by the cap).
    NoAnchor, ///< No usable previous reading, and there is data to lose (#2579).
    Wipe,     ///< This pass would expire every datable row.
    Step,     ///< The gap since the previous pass exceeds the absolute threshold.
    BadState, ///< The persisted clock reading cannot be used at all.
};

/// The five independent facts one pass observes. An AGGREGATE rather than five
/// positional bools: the parameter order deliberately does not match the
/// precedence order, so a call-site transposition of `would_wipe` and `big_step`
/// used to compile silently while the exhaustive table below stayed green -- the
/// table tests the FUNCTION, not the call. Designated initialisers make that
/// transposition a compile error.
///
/// Equality is the guard's deduplication key. It compares the whole fact SET,
/// not the classified enum, because `classify` collapses five facts onto one
/// value: a `Wipe` arriving underneath an already-reported `BadState` classifies
/// as `BadState` both times and is invisible to an enum comparison. That is not
/// hypothetical -- it is the dead-CMOS-then-NTP sequence, which silently deleted
/// the entire audit trail in one pass.
struct Facts {
    bool has_expired = false;
    bool would_wipe = false;
    bool big_step = false;
    bool prev_unusable = false;
    /// No pass has yet reached a VERDICT with a usable previous reading
    /// (#2579). Deliberately NOT "the anchor is missing right now":
    /// `cleanup_once` re-anchors before it probes, so deriving it from the
    /// anchor lets a pass that failed its probes spend the trigger without ever
    /// classifying anything. The audit store passes `!bootstrap_settled` here --
    /// a durable `audit_retention_meta` row settled at the verdict, not a
    /// per-process flag, because N replicas sweep one table and a process-local
    /// trigger would be spent by whichever booted first (`audit_store.cpp`).
    ///
    /// The in-pass sanitiser sets `prev_unusable`, which outranks, so corrupt
    /// durable state reports as corruption whether or not this is ALSO set --
    /// the two are not mutually exclusive, and a verdict-less pass can leave
    /// both true on a later one.
    bool no_anchor = false;

    friend constexpr bool operator==(const Facts&, const Facts&) noexcept = default;
};

/// True when the clock moved by at least `floor` seconds BETWEEN the two
/// readings, in either direction.
///
/// Overflow-free for every representable pair, which matters because `from` can
/// be deeply negative (a dead CMOS reads 1969) while `to` is a corrected
/// present-day reading: the signed difference of those two overflows, but the
/// magnitude always fits in a `uint64_t`. Ordering the operands first makes the
/// unsigned subtraction the true distance rather than a wrapped one.
[[nodiscard]] constexpr bool moved_at_least(std::int64_t from, std::int64_t to,
                                            std::int64_t floor) noexcept {
    const bool ascending = to >= from;
    const auto hi = static_cast<std::uint64_t>(ascending ? to : from);
    const auto lo = static_cast<std::uint64_t>(ascending ? from : to);
    return (hi - lo) >= static_cast<std::uint64_t>(floor);
}

/// Classify one pass. PURE: no state, no side effects, so each condition can be
/// reasoned about and tested alone.
///
/// Precedence is BadState > Step > Wipe > NoAnchor. A reading that cannot be
/// trusted makes the others unreliable, an elapsed-time step explains a wipe
/// better than the wipe explains itself, and having no reading at all is the
/// weakest statement of the four -- it says only that nothing can be ruled out.
///
/// The BadState/Step edge is REACHABLE, so the ordering is load-bearing rather
/// than decorative. `prev_unusable` has three carriers and only two of them
/// disengage the previous reading; the load-time flag does not, and is not
/// consumed on a probe-failure pass. Corrupt stored meta, then a probe failure,
/// then a pass eight days later arrives with both facts true. (An earlier
/// version of this comment claimed the edge was unreachable, while the truth
/// table in the sibling test pinned that exact combination.)
///
/// `!has_expired` short-circuits to None: with nothing to delete there is
/// nothing to hold back, and the only thing still worth reporting is an unusable
/// reading, which is why `prev_unusable` is tested first.
///
/// `no_anchor` is tested LAST, and that placement is the whole of #2579's fix.
/// Before it existed, a pass with no comparison point rested entirely on the
/// outcome test, so a host already skewed FORWARD -- whose post-skew rows are
/// still inside the window, defeating `would_wipe` -- deleted with every
/// detector false. Sitting last, it cannot mask a more specific verdict: a wipe
/// or a step still reports as itself, and it only speaks when nothing else did.
/// Sitting AFTER `!has_expired` is what keeps it quiet on the case that made
/// this a judgement call at all -- a fresh install has no anchor and nothing to
/// delete, so it never declines, and the trigger costs an operator nothing until
/// there is actually data at risk.
///
/// It needs no anti-latch special case, unlike the parallel implementation that
/// carried this trigger on another line: deduplication compares the whole fact
/// SET, so the next pass -- which has re-anchored, and therefore differs in this
/// very field -- is a different set and reports on its own merits.
[[nodiscard]] constexpr Anomaly classify(const Facts& f) noexcept {
    if (f.prev_unusable)
        return Anomaly::BadState;
    if (!f.has_expired)
        return Anomaly::None;
    if (f.big_step)
        return Anomaly::Step;
    if (f.would_wipe)
        return Anomaly::Wipe;
    return f.no_anchor ? Anomaly::NoAnchor : Anomaly::None;
}

} // namespace yuzu::server::audit_retention
