#pragma once

/// @file command_start_gate.hpp
/// The pure start decision for a command task the dispatch pool has dequeued (ADR-2005). While the pool
/// is closing (a reconnect teardown or a stop) an ordinary task that has not started its plugin is
/// rejected, because the pool destructor waits for every task. A PROTECTIVE action (the closed set in
/// `yuzu/protective_actions.hpp`: the four firewall containment actions and `__guard__.push_rules`)
/// is never rejected there and never sleeps a stagger or delay: a containment queued ahead
/// of a teardown still runs (`__guard__.push_rules` is answered inline in the command loop and is
/// never queued in the pool). It uses the one `is_protective_action` predicate that also chooses the
/// reserved lane at submit; never keep a second list.
///
/// A protective action is also never rejected as EXPIRED (`command_may_expire`): a containment that
/// waited in the queue past its `expires_at` still runs. The stored-state reconciler stays the
/// authority and re-applies drift, so a late containment is applied rather than dropped.
///
/// A protective task that runs while the pool is closing is counted on
/// `yuzu_agent_protective_commands_run_closing_total` and logged at WARN (throttled), because the
/// pool destructor waits, unbounded, for it (during a systemd stop, inside `TimeoutStopSec=60`).

#include <yuzu/protective_actions.hpp>

#include <yuzu/metrics.hpp>

#include <atomic>
#include <cstdint>
#include <string_view>

namespace yuzu::agent {

/// True when a dequeued command may start its plugin.
[[nodiscard]] inline bool command_may_start(std::string_view plugin, std::string_view action,
                                            bool pool_closing) {
    return !pool_closing || yuzu::protective::is_protective_action(plugin, action);
}

/// True when a command's stagger/delay sleep applies (never for a protective action).
[[nodiscard]] inline bool command_may_stagger(std::string_view plugin, std::string_view action) {
    return !yuzu::protective::is_protective_action(plugin, action);
}

/// True when an `expires_at` that has passed rejects the command (never for a protective action).
[[nodiscard]] inline bool command_may_expire(std::string_view plugin, std::string_view action) {
    return !yuzu::protective::is_protective_action(plugin, action);
}

/// True when this run is a protective action starting while the pool is closing.
[[nodiscard]] inline bool protective_runs_while_closing(std::string_view plugin,
                                                        std::string_view action, bool pool_closing) {
    return pool_closing && yuzu::protective::is_protective_action(plugin, action);
}

/// True for the 1st to 5th and every 100th occurrence: bounds the per-task WARN.
[[nodiscard]] inline bool closing_run_warn_due(std::uint64_t occurrence) {
    return occurrence >= 1 && (occurrence <= 5 || occurrence % 100 == 0);
}

/// Count a protective run at a pool close; returns true when the caller should log the WARN.
/// `seq` is the process-wide occurrence counter owned by the caller.
[[nodiscard]] inline bool note_protective_run_closing(yuzu::MetricsRegistry& metrics,
                                                      std::atomic<std::uint64_t>& seq) {
    metrics.counter("yuzu_agent_protective_commands_run_closing_total").increment();
    return closing_run_warn_due(seq.fetch_add(1, std::memory_order_relaxed) + 1);
}

} // namespace yuzu::agent
