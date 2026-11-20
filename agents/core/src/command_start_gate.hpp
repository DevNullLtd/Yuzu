#pragma once

/// @file command_start_gate.hpp
/// The pure start decision for a command task the dispatch pool has dequeued (ADR-2005). While the pool
/// is closing (a reconnect teardown or a stop) an ordinary task that has not started its plugin is
/// rejected, because the pool destructor waits for every task. A PROTECTIVE action (the closed set in
/// `yuzu/protective_actions.hpp`: the four firewall containment actions and `__guard__.push_rules`)
/// is never rejected there and never sleeps a stagger or delay: a containment or rule push queued ahead
/// of a teardown still runs. It uses the one `is_protective_action` predicate that also chooses the
/// reserved lane at submit; never keep a second list.

#include <yuzu/protective_actions.hpp>

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

} // namespace yuzu::agent
