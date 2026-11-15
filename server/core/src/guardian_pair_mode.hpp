#pragma once

/// @file guardian_pair_mode.hpp
/// The census pair MODE (UP-14 server PR B): how the agent's emit-order pair relates to the
/// agent's pair clock, decided once per census-bearing event by the per-agent order step (or, for
/// a Repair, read from the clock without writing it) and handed to the census write. Pure: no
/// store, no I/O. The mode is a CLOSED set. The step's SQL returns one of the labels below as text,
/// and anything else (an unknown label, a NULL) is a failure of the step, never a default: a mode
/// the code does not know must not read as `current`, which is the permissive one.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

enum class PairMode {
    Unpaired,          // no usable pair, and the pair clock is not fresh (or never set)
    UnpairedHeld,      // no usable pair while a fresh pair clock exists
    RefusedRetired,    // the event carries the epoch the latest recovery retired
    Current,           // a higher epoch, or a higher sequence in the live epoch (or no clock yet)
    CurrentStraggler,  // the live epoch, a sequence not above the mark, clock fresh
    CurrentRebase,     // a stale clock re-based by this event (first delivery only)
    RefusedRegression, // a lower epoch while the clock is fresh
    ImplausibleHeld,   // UP-9: a pair the ingest boundary withheld as implausible; ALWAYS held
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
    case PairMode::ImplausibleHeld:
        return "implausible_held";
    }
    return "";
}

/// Parse the text the step's SQL returned. `nullopt` for anything outside the SQL's closed set (an
/// empty string, a differently cased label, a label from a later version, and `implausible_held`
/// itself: that mode is set by the store from the ingest boundary's flag and the SQL never returns
/// it): the caller fails the step, it never substitutes a mode.
[[nodiscard]] constexpr std::optional<PairMode> parse_pair_mode(std::string_view s) noexcept {
    for (const PairMode m :
         {PairMode::Unpaired, PairMode::UnpairedHeld, PairMode::RefusedRetired, PairMode::Current,
          PairMode::CurrentStraggler, PairMode::CurrentRebase, PairMode::RefusedRegression}) {
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
    AppliedKey,        // a key-mode event became the verdict (v4 rule)
    TransitionToPair,  // a pair-mode event replaced an unpaired verdict
    TransitionToKey,   // an unpaired event replaced a paired verdict after the hold expired
    Rebase,            // a stale clock re-based the row: applied by arrival, flagged
    HeldUnpaired,      // an unpaired event refused while the pair clock is fresh
    RefusedRegression, // a lower epoch refused while the pair clock is fresh
    RefusedRetired,    // an event of the retired epoch refused
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
