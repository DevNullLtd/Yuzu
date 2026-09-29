#pragma once

/// @file gateway_route_reap_rules.hpp
/// HA WS-4 slice 4.2a — the PURE decision half of
/// `GatewayRouteStore::reap_stale_routes()` (PR #4299 round-3 review).
///
/// WHY THIS FILE EXISTS (the marker-obligation class). `reap_stale_routes()`
/// had THREE rounds of the SAME defect: one terminal/decline path forgetting
/// to decide what happens to the persisted `reap_declined_anchor_ms` marker
/// (LEAVE it, CLEAR it, or ARM it). Each round hand-patched the one path that
/// was wrong and left the class open for a fourth. This header closes the
/// class structurally by SPLITTING decide-from-apply: every reap outcome is a
/// `ReapDecision` whose `marker` field is a `MarkerAction` with NO default
/// constructor, so a future branch that forgets the marker decision is a
/// COMPILE error (the same discipline `command_capability.hpp`'s `ExecuteGate`
/// uses to make an omitted gate a build failure).
///
/// PURE (server-local, NOT common/include/ — this is server-trust-boundary
/// reap policy, not shared decision code). No DB, no `now()`, no I/O: the
/// caller performs the three reads (DB `now()`, the persisted `reap_anchor_ms`
/// anchor, the `reap_declined_anchor_ms` marker) and hands `decide_reap` the
/// raw SELECTed text; `decide_reap` returns what to do, and the caller's ONE
/// apply tail executes it. This makes every decision unit-testable with no
/// Postgres at all (see tests/unit/server/test_gateway_route_reap_rules.cpp).
///
/// ROUND 4 (PR #4299, reading-continuity recovery window). The skew-recovery
/// branch no longer recovers on a bare (anchor, direction) match: the marker now
/// carries a THIRD field, `first_now_ms` (the `now()` reading the anomaly was
/// first observed at), and recovery fires only when the anomaly has PERSISTED a
/// real-time-plausible interval — `delta = now_ms - first_now_ms` in
/// `[min_recovery_gap_ms, max_recovery_gap_ms]`. Below the floor it re-declines
/// preserving the original reading; above the ceiling (or a negative delta) it
/// re-declines as a NEW distinct anomaly against the current reading. The floor
/// is load-bearing for the multi-replica future: without it an ε-later
/// second-replica pass would recover with zero persistence evidence. See
/// docs/clock-guarded-retention.md's GatewayRouteStore entry.
///
/// The round-3 semantics still hold underneath: the bad-`now()` branch CLEARs
/// the marker (it used to LEAVE it), so a distinct anomaly never leaves a stale
/// recovery identity behind.
/// (The ONE other in-diff change is input hardening, not decision semantics:
/// `parse_reap_i64` was tightened past a bare `strtoll` to full-consumption +
/// canonical round-trip, so a non-canonical STORED numeric — "007", "-0", "+5",
/// leading/trailing space — that the old parser accepted is now treated as
/// absent/corrupt. Safe direction: a corrupt persisted anchor self-heals and a
/// malformed marker re-declines rather than false-matching.)

#include <algorithm> // std::max — anchor advance (parenthesised for the MSVC <windows.h> macro)
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// Checked parse of a Postgres bigint text value, hardened past a bare
/// `strtoll` (PR #4299 round-3 review): `std::from_chars` + FULL consumption
/// (`ptr == end`) + a canonical round-trip (`std::to_string(v) == input`),
/// following `leader_elector.cpp`'s `parse_i64`. The round-trip rejects the
/// non-canonical forms `strtoll` silently accepted — leading/trailing space,
/// a leading `+`, zero-padding (`007`), and `-0` — so a value is parseable
/// here ONLY if this store could itself have written it. A garbled-but-
/// otherwise-numeric stored value therefore reads as absent (→ re-decline),
/// never as a spurious match. Empty, unparseable, or trailing-garbage → nullopt.
inline std::optional<std::int64_t> parse_reap_i64(std::string_view val) {
    std::int64_t v = 0;
    const char* begin = val.data();
    const char* end = begin + val.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    // Canonical round-trip: from_chars already rejects a leading '+' and
    // leading whitespace, but accepts '007' and '-0'; the round-trip closes
    // those so "written by this store" is checkable.
    if (std::to_string(v) != val)
        return std::nullopt;
    return v;
}

/// A parsed `reap_declined_anchor_ms` marker: the frozen anchor, the anomaly
/// direction, and the `now()` reading of the FIRST pass that observed this
/// anomaly (`first_now_ms`). The first reading is what bounds recovery to a
/// plausible persistence window (PR #4299 round 4) — see `decide_reap`.
struct DeclinedMarker {
    std::int64_t anchor{0};
    std::string direction;         ///< "forward" | "backward"
    std::int64_t first_now_ms{0};  ///< now() at the FIRST decline of this anomaly
};

/// Parses the `reap_declined_anchor_ms` marker, format
/// `"<anchor>:<direction>:<first_now_ms>"` (direction ∈ {"forward","backward"};
/// THREE fields — PR #4299 round 4 added `first_now_ms`, the reading the anomaly
/// was first observed at, so recovery can bound persistence, not just match a
/// frozen (anchor, direction) pair). The decline/recovery pair is judged on the
/// FULL fact set (frozen anchor AND anomaly direction AND first reading), never
/// the anchor alone (docs/clock-guarded-retention.md part 4; PR #4299 round-2
/// external review + round 4). Direction is NEVER sign-encoded — a negative
/// value is the tamper signal `parse_reap_i64` already rejects, so it stays a
/// literal field, not an arithmetic trick.
///
/// Requires EXACTLY three fields; ANY other shape is absent (→ nullopt):
///  - fewer than two `:` (a 2-field LEGACY/old-binary marker, or a garbled
///    value with no colon at all),
///  - more than two `:` (a 4+-field value — the trailing field then carries a
///    `:` that `parse_reap_i64` rejects as non-numeric),
///  - an unrecognised direction token,
///  - an unparseable / non-canonical / negative anchor or `first_now_ms` half.
///
/// Absent is always safe — every call site treats it as "no prior decline",
/// which re-arms in the new 3-field format and declines once more rather than
/// granting an unearned recovery. This keeps a MIXED-VERSION rollout safe in
/// BOTH directions: a NEW binary reading an OLD 2-field `"<int>:<dir>"` value
/// sees only one colon → absent → re-arms in the 3-field format; an OLD binary
/// reading this store's new 3-field value hands the whole string to its own
/// bare `parse_reap_i64` (or its own 2-field parser), which rejects the extra
/// field(s) → it too treats the marker as absent and declines.
inline std::optional<DeclinedMarker> parse_declined_marker(std::string_view val) {
    const auto c1 = val.find(':');
    if (c1 == std::string_view::npos)
        return std::nullopt;
    const auto c2 = val.find(':', c1 + 1);
    if (c2 == std::string_view::npos)
        return std::nullopt; // fewer than three fields (legacy/old-binary marker)
    const std::string_view direction = val.substr(c1 + 1, c2 - (c1 + 1));
    if (direction != "forward" && direction != "backward")
        return std::nullopt;
    auto anchor = parse_reap_i64(val.substr(0, c1));
    if (!anchor || *anchor < 0)
        return std::nullopt;
    // A 4+-field value leaves a `:` in this trailing half, which parse_reap_i64
    // rejects as trailing garbage — so "exactly three fields" is enforced here
    // without a separate colon count.
    auto first_now_ms = parse_reap_i64(val.substr(c2 + 1));
    if (!first_now_ms || *first_now_ms < 0)
        return std::nullopt;
    return DeclinedMarker{*anchor, std::string(direction), *first_now_ms};
}

/// What a reap pass must do to the persisted `reap_declined_anchor_ms` marker.
/// Deliberately has NO public default constructor, so every `ReapDecision`
/// MUST name one of `clear()` / `arm(...)`: a future reap branch that forgets
/// the marker decision is a COMPILE error, not a silently-wrong runtime path
/// (the ExecuteGate discipline — this is the whole point of the decide/apply
/// split, PR #4299 round-3 review). `LEAVE` is deliberately NOT expressible:
/// every lock-holding pass that COMMITS writes the marker exactly once (ARM or
/// CLEAR); LEAVE only ever applied to passes that never read `now()` (the
/// lock-skip early return) or that roll back — neither reaches `decide_reap`.
class MarkerAction {
public:
    enum class Kind {
        Clear, ///< DELETE reap_declined_anchor_ms
        Arm,   ///< upsert reap_declined_anchor_ms = "<anchor>:<direction>:<first_now_ms>"
    };

    /// Clear the marker (accepted pass, recovery, self-heal, bad-now decline).
    static MarkerAction clear() { return MarkerAction(Kind::Clear, 0, "", 0); }

    /// Arm/re-arm the marker against this pass's (anchor, direction) anomaly,
    /// recording `first_now_ms` — the `now()` reading this anomaly is being
    /// pinned to (the CURRENT reading for a fresh/new anomaly, or the PRESERVED
    /// original for a not-yet-persisted repeat; see `decide_reap`).
    static MarkerAction arm(std::int64_t anchor, std::string_view direction,
                            std::int64_t first_now_ms) {
        return MarkerAction(Kind::Arm, anchor, std::string(direction), first_now_ms);
    }

    [[nodiscard]] Kind kind() const { return kind_; }
    [[nodiscard]] std::int64_t anchor() const { return anchor_; }
    [[nodiscard]] const std::string& direction() const { return direction_; }
    [[nodiscard]] std::int64_t first_now_ms() const { return first_now_ms_; }

private:
    MarkerAction(Kind k, std::int64_t a, std::string d, std::int64_t f)
        : kind_(k), anchor_(a), direction_(std::move(d)), first_now_ms_(f) {}

    Kind kind_;
    std::int64_t anchor_;
    std::string direction_;
    std::int64_t first_now_ms_;
};

/// The outcome of `decide_reap`. `marker` is MANDATORY (no default) — see
/// `MarkerAction`. `new_anchor` is `nullopt` to LEAVE `reap_anchor_ms`
/// untouched (a skew decline/arm never advances it), or the value to upsert.
///
/// COMPILE-ENFORCEMENT SCOPE: only `marker` is compiler-mandatory (its no-default
/// ctor makes an omitting aggregate-init ill-formed — the discipline that closes
/// the recurring forget-the-marker class). The trailing `bool`/`optional` fields
/// below are ordinary aggregate members: an omitted one silently value-initialises
/// (false / nullopt). EVERY branch in `decide_reap` MUST therefore name all five
/// explicitly — a future branch that omits e.g. `.clock_anomaly` compiles with a
/// silent `false` (an unreported decline). Keep them named, not defaulted.
struct ReapDecision {
    MarkerAction marker;                    ///< mandatory — every branch names one
    std::optional<std::int64_t> new_anchor; ///< nullopt = leave reap_anchor_ms untouched
    bool run_sweeps;                        ///< run both capped sweeps this pass
    bool clock_anomaly;                     ///< this pass was DECLINED on a clock-guard anomaly
    bool recovered;                         ///< ran via the decline-once/drain-on-repeat recovery
};

/// PURE reap decision. `now_raw` is the DB `now()` epoch-ms text; `anchor_raw`
/// the persisted `reap_anchor_ms` (nullopt if no row); `marker_raw` the
/// persisted `reap_declined_anchor_ms` (nullopt if no row). Returns the exact,
/// exhaustive five-decision set (each constructs a MarkerAction):
///
///  - **bad now_raw** (unparseable OR negative): CLEAR, leave anchor, no
///    sweeps, clock_anomaly. A distinct anomaly CLEARs the stale recovery
///    identity so a later same-direction skew is judged fresh (the round-3
///    fix — this path used to LEAVE the marker).
///  - **anchor_raw present but unparseable/negative** (corrupt-anchor
///    self-heal): CLEAR, re-anchor to now_ms, no sweeps, clock_anomaly. This
///    method is the anchor's sole writer, so a bad stored value is
///    corruption/tampering — re-anchor rather than wedge every future pass.
///  - **anchor_raw absent** (first/no-anchor pass): CLEAR, anchor = now_ms,
///    run sweeps.
///  - **valid anchor, skew present** (forward: now_ms-anchor>max_skew;
///    backward: now_ms<anchor):
///      - **marker matches** (declined anchor == anchor AND declined
///        direction == this pass's direction) — the persistence window is then
///        judged from `delta = now_ms - marker.first_now_ms` (PR #4299 round 4):
///          - `delta < 0` OR `delta > max_recovery_gap_ms`: a NEW, distinct
///            anomaly (a discontinuous forward jump, or a further-backward
///            step) — **ARM(anchor, dir, now_ms)** + decline. It gets its own
///            decline-once against THIS reading, not a free recovery.
///          - `0 <= delta < min_recovery_gap_ms`: not yet persisted long
///            enough — **ARM(anchor, dir, marker.first_now_ms /* PRESERVED */)**
///            + decline. The original first reading is preserved, NEVER reset,
///            or offset replicas ticking every few seconds would reset it
///            forever = a wedge.
///          - `min_recovery_gap_ms <= delta <= max_recovery_gap_ms`: the SAME
///            anomaly genuinely persisted a real-time-plausible interval —
///            CLEAR, anchor = now_ms UNCONDITIONALLY, run sweeps, recovered.
///      - **else** (no marker / different anchor / different direction /
///        unparseable marker): ARM(anchor, direction, now_ms), leave anchor, no
///        sweeps, clock_anomaly — a fresh anomaly, decline-once against this
///        reading.
///  - **valid anchor, NO skew** (clean): CLEAR, anchor = max(anchor, now_ms),
///    run sweeps.
///
/// `min_recovery_gap_ms` / `max_recovery_gap_ms` bound the recovery persistence
/// window; both are clamped to >= 0 at entry (defensive, like
/// `max_plausible_skew_ms`). The production values are `kMinReapRecoveryGapMs` /
/// `kMaxReapRecoveryGapMs` (gateway_route_store.hpp), with the FLOOR load-bearing
/// for the multi-replica future this slice exists for: without it, an ε-later
/// second-replica pass would recover with zero persistence evidence.
inline ReapDecision decide_reap(std::string_view now_raw,
                                std::optional<std::string_view> anchor_raw,
                                std::optional<std::string_view> marker_raw,
                                std::int64_t max_plausible_skew_ms,
                                std::int64_t min_recovery_gap_ms,
                                std::int64_t max_recovery_gap_ms) {
    // DEFENSIVE: the sole production caller passes a positive compile-time
    // constant (kMaxPlausibleSkewMs), but this is now a public pure helper — a
    // future/mis-wired NEGATIVE bound would invert the clean path (every
    // now_ms >= anchor would read as forward-skew → perpetual decline/recover).
    // Clamp to 0: a zero bound degrades SAFELY (any forward delta is treated as
    // a skew, never the reverse), so the parameter can never flip clean → skew.
    if (max_plausible_skew_ms < 0)
        max_plausible_skew_ms = 0;
    // Same defensive clamp for the recovery-window bounds (PR #4299 round 4):
    // the production caller passes positive compile-time constants whose
    // ordering a static_assert enforces, but this is a public pure helper.
    if (min_recovery_gap_ms < 0)
        min_recovery_gap_ms = 0;
    if (max_recovery_gap_ms < 0)
        max_recovery_gap_ms = 0;
    // SANITISE now() (clock-guarded-retention part 3): unparseable or negative
    // is an ANOMALY, never a quiet fallback. NOT a wedge risk — nothing here
    // is persisted beyond clearing a stale marker; the next pass issues its
    // own fresh SELECT now() and is judged on that fresh reading. CLEARing the
    // marker (the round-3 fix) ensures a distinct anomaly cannot leave a stale
    // recovery identity a later same-direction skew would free-ride on.
    const std::optional<std::int64_t> parsed_now = parse_reap_i64(now_raw);
    if (!parsed_now || *parsed_now < 0) {
        return ReapDecision{.marker = MarkerAction::clear(),
                            .new_anchor = std::nullopt,
                            .run_sweeps = false,
                            .clock_anomaly = true,
                            .recovered = false};
    }
    const std::int64_t now_ms = *parsed_now;

    if (anchor_raw.has_value()) {
        const std::optional<std::int64_t> parsed_anchor = parse_reap_i64(*anchor_raw);
        if (!parsed_anchor || *parsed_anchor < 0) {
            // SELF-HEAL a corrupt/tampered PERSISTED anchor: re-anchor to this
            // pass's own sanitised now_ms and clear any stale skew marker
            // (recorded against the now-discarded anchor), declining only this
            // one pass. Do NOT drain-on-repeat — a garbage anchor is not
            // evidence of genuine elapsed downtime the way a persisting skew
            // is, and auto-draining on tampering risks a mass-reap.
            return ReapDecision{.marker = MarkerAction::clear(),
                                .new_anchor = now_ms,
                                .run_sweeps = false,
                                .clock_anomaly = true,
                                .recovered = false};
        }
        const std::int64_t anchor = *parsed_anchor;

        // Overflow-safe forward-skew comparison (subtracting two already-
        // sanitised non-negative int64_t values cannot overflow). forward and
        // backward are mutually exclusive, so "direction" is a lossless raw
        // fact, not a classified enum.
        const bool forward_skew = now_ms >= anchor && now_ms - anchor > max_plausible_skew_ms;
        const bool backward_skew = now_ms < anchor;

        if (forward_skew || backward_skew) {
            const std::string_view current_direction = forward_skew ? "forward" : "backward";
            std::optional<DeclinedMarker> declined;
            if (marker_raw.has_value())
                declined = parse_declined_marker(*marker_raw);
            // RECOVER only on the FULL (anchor, direction) match — a value-only
            // match let a DIFFERENT-direction anomaly at the same frozen anchor
            // recover and run the sweeps against a corrupted now_ms (round-2
            // external review defect).
            if (declined.has_value() && declined->anchor == anchor &&
                declined->direction == current_direction) {
                // Reading-continuity window (PR #4299 round 4): the SAME
                // (anchor, direction) matching is necessary but no longer
                // sufficient — the anomaly must also have PERSISTED a
                // real-time-plausible interval measured from the reading it
                // was first observed at. This compares the full fact set,
                // including the magnitude/continuity of the reading, so a
                // second UNRELATED same-direction jump at the same frozen
                // anchor cannot free-ride the first anomaly's decline.
                const std::int64_t delta = now_ms - declined->first_now_ms;
                if (delta < 0 || delta > max_recovery_gap_ms) {
                    // A NEW, distinct anomaly: a discontinuous forward jump past
                    // the ceiling, or a further-backward step (negative delta).
                    // It earns its OWN decline-once against this reading.
                    return ReapDecision{
                        .marker = MarkerAction::arm(anchor, current_direction, now_ms),
                        .new_anchor = std::nullopt,
                        .run_sweeps = false,
                        .clock_anomaly = true,
                        .recovered = false};
                }
                if (delta < min_recovery_gap_ms) {
                    // Not yet persisted long enough. PRESERVE the ORIGINAL
                    // first_now_ms (do NOT reset it, or offset replicas ticking
                    // every few seconds would reset it forever = a wedge).
                    return ReapDecision{
                        .marker =
                            MarkerAction::arm(anchor, current_direction, declined->first_now_ms),
                        .new_anchor = std::nullopt,
                        .run_sweeps = false,
                        .clock_anomaly = true,
                        .recovered = false};
                }
                // min <= delta <= max: the SAME anomaly genuinely persisted a
                // real-time-plausible interval — recover and drain.
                return ReapDecision{.marker = MarkerAction::clear(),
                                    .new_anchor = now_ms, // UNCONDITIONAL — move off the stale anchor
                                    .run_sweeps = true,
                                    .clock_anomaly = false,
                                    .recovered = true};
            }
            // ARM / re-arm against this pass's (anchor, direction) at THIS
            // reading; overwrites any stale marker. A fresh anomaly declines
            // once. Anchor unchanged (a decline never advances it, so the
            // identical repeat presents the same frozen pair).
            return ReapDecision{.marker = MarkerAction::arm(anchor, current_direction, now_ms),
                                .new_anchor = std::nullopt,
                                .run_sweeps = false,
                                .clock_anomaly = true,
                                .recovered = false};
        }

        // Clean accepted pass with a valid anchor: advance to max(anchor,
        // now_ms) (parenthesised to dodge the <windows.h> `max` macro, MSVC).
        return ReapDecision{.marker = MarkerAction::clear(),
                            .new_anchor = (std::max)(anchor, now_ms),
                            .run_sweeps = true,
                            .clock_anomaly = false,
                            .recovered = false};
    }

    // First/no-anchor pass (part 6 PROCEED): anchor to now_ms and sweep.
    return ReapDecision{.marker = MarkerAction::clear(),
                        .new_anchor = now_ms,
                        .run_sweeps = true,
                        .clock_anomaly = false,
                        .recovered = false};
}

} // namespace yuzu::server
