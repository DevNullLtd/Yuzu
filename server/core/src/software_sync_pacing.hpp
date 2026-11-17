#pragma once

/// @file software_sync_pacing.hpp
/// Pure admission and pacing rule for an on-demand "Sync now" run (software_sync::Runner). No
/// clock, no state and no I/O: the Runner owns the ledger of runs still spreading and asks
/// `admit` whether one more may start and how far apart its devices must be asked to report.
///
/// WHAT THE BUDGET BOUNDS. `kFleetPacingBudgetPerSec` is the report rate this server PROCESS asks
/// the fleet for across every run that is still spreading. A run of N devices is admitted at a
/// rate r (reports per second) and every device is told to fire inside a window of
/// `delay_max_s = ceil(N / r)` seconds (`delay_max_s` is the agent's stable per-device offset
/// range), so the run costs at most r reports per second on average.
///
/// What it does NOT bound: the rate at which reports ARRIVE. It limits what the server ASKS for.
/// An agent keeps a fire it already armed when it is sooner than the offset it was given
/// (agents/core/src/sync_scheduler.cpp), so a device whose own scheduled sync is due sooner
/// reports then, as a full send, whatever the run said. The spread and the
/// `estimated_completion_at` derived from it are therefore ESTIMATES, not guarantees, and the
/// agent is not changed by this rule.
///
/// Both numbers are per server process: replicas multiply them (the ledger is in memory, so a
/// restart also forgets it while agents keep the delays they already armed).
///
/// Invariant: the sum of the rates of the runs `admit` has admitted and the caller still holds
/// never exceeds `kFleetPacingBudgetPerSec`, because a run may take at most `kMaxRunShare` of
/// what is free.

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>

namespace yuzu::server::software_sync {

/// ponytail: interim ruling (50 reports/s per server process), not a measurement. The S-1
/// follow-up measures the real ingest ceiling and only retunes this constant.
inline constexpr double kFleetPacingBudgetPerSec = 50.0;
/// The widest spread a run may ask for, in seconds. Equals the agent's `kSyncNowMaxDelaySeconds`
/// (agents/core/src/sync_now_decision.hpp:48): a larger `delay_max_s` is a FAILURE on the agent.
inline constexpr std::int64_t kMaxSpreadSecs = 86'400;
/// The largest fraction of the free budget one run may take, so a later run always finds room.
inline constexpr double kMaxRunShare = 0.5;
/// Below this free-budget share a run is not started (it would take longer than it saves).
inline constexpr double kMinRunRate = 1.0;

/// One run still spreading: the rate it was admitted at and the second its spread ends. `id` is the
/// caller's handle on its own entry; `admit` ignores it.
struct ActiveRun {
    double rate{0.0};
    std::int64_t ends_at{0};
    std::uint64_t id{0};
};

struct Admission {
    enum class Kind {
        Admit,    ///< start now at `rate`, spread over `delay_max_s`, reserve until `ends_at`
        Busy,     ///< no budget free right now; retry after `retry_after_s`
        TooLarge, ///< cannot be spread inside kMaxSpreadSecs even at the share it could have
    } kind{Kind::Busy};
    std::int64_t delay_max_s{0}; ///< Admit: the `delay_max_s` command parameter (0 = immediate)
    double rate{0.0};            ///< Admit: reports per second this run reserves
    std::int64_t ends_at{0};     ///< Admit: the second the reservation can be released
    std::int64_t retry_after_s{0}; ///< Busy: seconds until the earliest running run ends (>= 1)
};

/// Decide one run of `targets` devices against `active` at time `now` (epoch seconds). Runs with
/// `ends_at <= now` are over and free their rate, whatever the caller still holds; a `now` that
/// stepped backwards simply keeps more of them active (no negative delay or retry arises).
/// Preconditions: `targets >= 1` (the Runner answers an empty run before it asks), and `active` is
/// every run the caller still holds.
[[nodiscard]] inline Admission admit(std::span<const ActiveRun> active, std::size_t targets,
                                     std::int64_t now) {
    Admission out;
    double in_use = 0.0;
    std::int64_t earliest_end = 0;
    bool any_active = false;
    for (const ActiveRun& r : active) {
        if (r.ends_at <= now)
            continue;
        in_use += r.rate;
        if (!any_active || r.ends_at < earliest_end)
            earliest_end = r.ends_at;
        any_active = true;
    }
    const double free_rate = std::max(0.0, kFleetPacingBudgetPerSec - in_use);
    const double share = free_rate * kMaxRunShare;
    if (share < kMinRunRate) {
        out.kind = Admission::Kind::Busy;
        // With nothing active the budget cannot be short, but keep the answer total and bounded.
        out.retry_after_s =
            any_active ? std::clamp<std::int64_t>(earliest_end - now, 1, kMaxSpreadSecs) : 1;
        return out;
    }
    const double rate = std::min(static_cast<double>(targets), share);
    const double spread = static_cast<double>(targets) <= rate
                              ? 0.0
                              : std::ceil(static_cast<double>(targets) / rate);
    if (spread > static_cast<double>(kMaxSpreadSecs)) {
        out.kind = Admission::Kind::TooLarge;
        return out;
    }
    out.kind = Admission::Kind::Admit;
    out.rate = rate;
    out.delay_max_s = static_cast<std::int64_t>(spread);
    out.ends_at = now + std::max<std::int64_t>(out.delay_max_s, 1);
    return out;
}

} // namespace yuzu::server::software_sync
