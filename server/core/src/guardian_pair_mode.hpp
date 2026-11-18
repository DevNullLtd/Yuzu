#pragma once

/// @file guardian_pair_mode.hpp
/// The census pair MODE (UP-14 server PR B): how the agent's emit-order pair relates to the
/// agent's pair clock, decided once per census-bearing event by the per-agent order step (or, for
/// a Repair, read from the clock without writing it) and handed to the census write. Pure: no
/// store, no I/O. The mode is a CLOSED set. The step's SQL returns one of the labels below as text,
/// and anything else (an unknown label, a NULL) is a failure of the step, never a default: a mode
/// the code does not know must not read as `current`, which is the permissive one.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

namespace detail {
/// The limits on a wire pair, in ONE place. They live here, in the pure header, because both the
/// ingest boundary (`pair_from_wire`, `guardian_ingest.cpp`) and the store (`census_pair`,
/// `guaranteed_state_store.cpp`) read them and the store must not pull in the ingest header
/// (protobuf, spdlog) for three constants. Each half of a pair is in [1, `kPairValueLimit`): below
/// 2^62 the BIGINT sign bit is unreachable. On top of that (UP-9) a pair must be PLAUSIBLE:
/// `emit_seq` below `kEmitSeqCeiling` (2^40, about 1.1e12 events in one boot) and `boot_epoch`
/// (Unix seconds) at most `kEpochSkewSeconds` (ten years of 365.25 days) past the server's receipt
/// time. A pair that passes the range check and fails this one is `Implausible`: one such pair
/// accepted would pin an agent's pair clock above every honest event for the life of the row,
/// because only a higher pair advances the clock. The bound is absolute and stateless; a pair
/// inside it is still judged by the pair clock (an agent whose clock was pinned by a value just
/// inside it heals when the hold expires, one hour after the last accepted event).
inline constexpr std::uint64_t kPairValueLimit = std::uint64_t{1} << 62;
inline constexpr std::uint64_t kEmitSeqCeiling = std::uint64_t{1} << 40;
inline constexpr std::int64_t kEpochSkewSeconds = 315'576'000;

/// The census pair-decision counter's name (`census_decision_label` is its `decision` label). Here
/// beside the label set for the same reason as the limits above: the store counts it, the ingest
/// boundary and server.cpp pre-seed it.
inline constexpr char kGuardianCensusPairDecisionsMetric[] =
    "yuzu_server_guardian_census_pair_decisions_total";

/// The Repair-shed counter's name: one per Repair of a pending event the store refused at its
/// process-wide cap (`GuaranteedStateStore::kRepairMaxConcurrent`). A plain counter with no
/// labels, counted by the store and pre-seeded to 0 at boot
/// (`preseed_guardian_repairs_shed_metric`).
inline constexpr char kGuardianRepairsShedMetric[] = "yuzu_server_guardian_repairs_shed_total";
} // namespace detail

enum class PairMode {
    Unpaired,          // no usable pair, and the pair clock is not fresh (or never set)
    UnpairedHeld,      // no usable pair while a fresh pair clock exists
    RefusedRetired,    // the event carries the epoch the latest recovery retired
    Current,           // a higher epoch, or a higher sequence in the live epoch (or no clock yet)
    CurrentStraggler,  // the live epoch, a sequence not above the mark, clock fresh
    CurrentRebase,     // a stale clock re-based by this event (first delivery only)
    RefusedRegression, // a lower epoch while the clock is fresh
};

/// The label the order step's SQL returns for a mode, and the label a log line uses.
[[nodiscard]] constexpr const char* pair_mode_label(PairMode m) noexcept {
    switch (m) {
    case PairMode::Unpaired:
        return "unpaired";
    case PairMode::UnpairedHeld:
        return "unpaired_held";
    case PairMode::RefusedRetired:
        return "refused_retired";
    case PairMode::Current:
        return "current";
    case PairMode::CurrentStraggler:
        return "current_straggler";
    case PairMode::CurrentRebase:
        return "current_rebase";
    case PairMode::RefusedRegression:
        return "refused_regression";
    }
    return "";
}

/// Every mode, in enumerator order. `parse_pair_mode` walks THIS list, so a mode missing from it
/// could never be parsed from the step's answer (and would fail the step, silently). The asserts
/// below tie it to the enum: it is contiguous from 0, every enumerator has a label, and the value
/// one past the list has none (the switch above returns "" outside the enumerators, so an
/// enumerator added after the last one fails here until this list is extended).
inline constexpr std::array<PairMode, 7> kPairModes = {
    PairMode::Unpaired,         PairMode::UnpairedHeld,     PairMode::RefusedRetired,
    PairMode::Current,          PairMode::CurrentStraggler, PairMode::CurrentRebase,
    PairMode::RefusedRegression};

[[nodiscard]] constexpr bool pair_mode_table_is_complete() noexcept {
    for (std::size_t i = 0; i < kPairModes.size(); ++i) {
        if (static_cast<std::size_t>(kPairModes[i]) != i ||
            std::string_view(pair_mode_label(kPairModes[i])).empty())
            return false;
    }
    return std::string_view(pair_mode_label(static_cast<PairMode>(kPairModes.size()))).empty();
}
static_assert(pair_mode_table_is_complete(),
              "kPairModes must list every PairMode in enumerator order, each with a label");

/// Parse the text the step's SQL returned. `nullopt` for anything outside the SQL's closed set (an
/// empty string, a differently cased label, a label from a later version): the caller fails the
/// step, it never substitutes a mode.
[[nodiscard]] constexpr std::optional<PairMode> parse_pair_mode(std::string_view s) noexcept {
    for (const PairMode m : kPairModes) {
        if (s == pair_mode_label(m))
            return m;
    }
    return std::nullopt;
}

/// What the order step decided for one event: the mode and the epoch the agent's most recent
/// lower-epoch recovery retired (NULL when none).
struct PairDecision {
    PairMode mode{PairMode::Unpaired};
    std::optional<std::int64_t> retired_epoch;
};

/// The decision used where no step ran (the step seam is off, a test switch): the v4 behaviour,
/// where an unpaired event is `unpaired` and a paired one is `current`, and nothing is retired.
[[nodiscard]] constexpr PairDecision default_pair_decision(bool paired) noexcept {
    return {paired ? PairMode::Current : PairMode::Unpaired, std::nullopt};
}

/// What the census statement decided for one event, the label set of
/// `yuzu_server_guardian_census_pair_decisions_total{decision}`. A metric and a log, never a row
/// decision: the statement alone decides the row, and it RETURNs the label from the same expression
/// text so C++ never re-derives it. The set is CLOSED; the statement answers NULL only for an
/// unpaired-mode event the key rule refused (v4 never labelled one), and the caller treats a NULL
/// for any other mode, or a label outside this set, as a failure of the census write.
enum class CensusDecision {
    AppliedPair,       // a pair-mode event became the verdict in the live epoch order
    AppliedKey,        // an unpaired event became the verdict by the key rule, over an unpaired row
                       // or no row (an `unpaired_held` event over such a row included)
    TransitionToPair,  // a pair-mode event replaced an unpaired verdict
    TransitionToKey,   // an unpaired event replaced a paired verdict after the hold expired
    Rebase,            // a stale clock re-based the row: applied by arrival, flagged
    HeldUnpaired,      // an unpaired event refused over a paired row: while the pair clock is
                       // fresh, or, once the hold has expired, when the event is older by arrival
                       // than the paired verdict (a Repair, a late-committing pending event)
    RefusedRegression, // a lower epoch refused while the pair clock is fresh; over an ABSENT row
                       // it is an applied, flagged insert (projection outcome `applied`)
    RefusedRetired,    // an event of the retired epoch refused; an absent row: as above
    RefusedDuplicate,  // an equal pair refused (two processes, one epoch)
    RefusedStraggler,  // a same-epoch lower sequence refused while the pair clock is fresh
};

inline constexpr std::array<CensusDecision, 10> kCensusDecisions = {
    CensusDecision::AppliedPair,
    CensusDecision::AppliedKey,
    CensusDecision::TransitionToPair,
    CensusDecision::TransitionToKey,
    CensusDecision::Rebase,
    CensusDecision::HeldUnpaired,
    CensusDecision::RefusedRegression,
    CensusDecision::RefusedRetired,
    CensusDecision::RefusedDuplicate,
    CensusDecision::RefusedStraggler};

/// The label the census statement returns for a decision, and the metric label.
[[nodiscard]] constexpr const char* census_decision_label(CensusDecision d) noexcept {
    switch (d) {
    case CensusDecision::AppliedPair:
        return "applied_pair";
    case CensusDecision::AppliedKey:
        return "applied_key";
    case CensusDecision::TransitionToPair:
        return "transition_to_pair";
    case CensusDecision::TransitionToKey:
        return "transition_to_key";
    case CensusDecision::Rebase:
        return "rebase";
    case CensusDecision::HeldUnpaired:
        return "held_unpaired";
    case CensusDecision::RefusedRegression:
        return "refused_regression";
    case CensusDecision::RefusedRetired:
        return "refused_retired";
    case CensusDecision::RefusedDuplicate:
        return "refused_duplicate";
    case CensusDecision::RefusedStraggler:
        return "refused_straggler";
    }
    return "";
}

[[nodiscard]] constexpr bool census_decision_table_is_complete() noexcept {
    for (std::size_t i = 0; i < kCensusDecisions.size(); ++i) {
        if (static_cast<std::size_t>(kCensusDecisions[i]) != i ||
            std::string_view(census_decision_label(kCensusDecisions[i])).empty())
            return false;
    }
    return std::string_view(
               census_decision_label(static_cast<CensusDecision>(kCensusDecisions.size())))
        .empty();
}
static_assert(census_decision_table_is_complete(),
              "kCensusDecisions must list every CensusDecision in enumerator order, each with a "
              "label (it is the metric's pre-seed list and the parser's list)");

/// Parse the label the census statement returned. `nullopt` for anything outside the closed set
/// (an empty string, a differently cased label, a label from a later version).
[[nodiscard]] constexpr std::optional<CensusDecision>
parse_census_decision(std::string_view s) noexcept {
    for (const CensusDecision d : kCensusDecisions) {
        if (s == census_decision_label(d))
            return d;
    }
    return std::nullopt;
}

/// Whether the census statement may legitimately answer NULL for an event of this mode: only the
/// unpaired modes, where the key rule can refuse an event without a label. Every other mode has a
/// label on every returned row.
[[nodiscard]] constexpr bool census_decision_may_be_null(PairMode m) noexcept {
    return m == PairMode::Unpaired || m == PairMode::UnpairedHeld;
}

/// Interpret the decision column of the census upsert's one row (`text` is nullopt for SQL NULL).
/// Returns true with `out` set to the decision, or empty for the one legitimate NULL; false with
/// `why` set for a NULL on a mode that always has a label and for a label outside the closed set.
/// The caller turns a false into a failed census write: a decision the code cannot read means the
/// statement and the code disagree about the labels, so the row decision it describes is not
/// trusted.
[[nodiscard]] inline bool interpret_census_decision(std::optional<std::string_view> text,
                                                    PairMode mode,
                                                    std::optional<CensusDecision>& out,
                                                    std::string& why) {
    out.reset();
    if (!text) {
        if (census_decision_may_be_null(mode))
            return true;
        why = std::string("the census decision is NULL for mode ") + pair_mode_label(mode);
        return false;
    }
    out = parse_census_decision(*text);
    if (!out) {
        why = "unknown census decision '" + std::string(text->substr(0, 40)) + "'";
        return false;
    }
    return true;
}

} // namespace yuzu::server
