#pragma once

/// @file guardian_pair_mode.hpp
/// The census pair MODE (UP-14 server PR B): how the agent's emit-order pair relates to the
/// agent's pair clock, decided once per census-bearing event by the per-agent order step (or, for
/// a Repair, read from the clock without writing it) and handed to the census write. Pure: no
/// store, no I/O. The mode is a CLOSED set. The step's SQL returns one of the labels below as text,
/// and anything else (an unknown label, a NULL) is a failure of the step, never a default: a mode
/// the code does not know must not read as `current`, which is the permissive one.

#include <cstdint>
#include <optional>
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

} // namespace yuzu::server
