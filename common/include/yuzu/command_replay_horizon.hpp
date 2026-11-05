#pragma once

/// @file command_replay_horizon.hpp
/// #3678 (HA WS-0 / WS-3): the single-sourced relationship between the agent's durable
/// command-dedup ring and the server's command-redelivery horizon.
///
/// The agent (`CommandDedupStore`, `agents/core/include/yuzu/agent/command_dedup_store.hpp`)
/// remembers the most recent `kAgentDedupRingRows` TERMINAL commands per agent and evicts
/// the oldest by rowid. An evicted id is freshly claimable, so a server that re-sends the
/// same `command_id` after that many newer commands have reached the agent makes the agent
/// RE-EXECUTE it. The command outbox (`server/core/src/command_outbox_delivery.cpp`) is the
/// server-side redelivery source: it re-drives a `pending` row with its STABLE `command_id`.
///
/// `kMaxOutboxRedeliveryHorizonCommands` is the most dispatch CALLS the outbox lets elapse
/// between a row's first send and a redrive. Every ring-consuming send passes the one
/// dispatch chokepoint (`ServerImpl::build_classified_command`) and mints one command_id,
/// so one dispatch call is at most one ring slot on any agent; a fleet-wide count of
/// dispatch calls therefore upper-bounds the number of newer commands any single agent has
/// received. That is deliberately conservative (it also counts commands sent to other
/// agents and `__guard__`).
///
/// The 2x margin is the headroom the count does not otherwise account for: a failed or
/// skipped dispatch-record write undercounts by one, and a redrive can race the agent's
/// claim. Do not tighten it to `<`/`<=` without re-deriving those.
///
/// Pure decision code only (#2549 firewall): constants, no I/O, no store/wire types, no
/// server-trust-boundary authority.

#include <cstdint>

namespace yuzu {

/// Terminal rows the agent dedup ring retains. `CommandDedupStore::kMaxDedupRows` is
/// defined as this value; do not restate the number anywhere else.
inline constexpr std::int64_t kAgentDedupRingRows = 20000;

/// Maximum fleet-wide dispatch calls that may elapse between an outbox row's first send
/// and a redrive of it. A redrive past this is dead-lettered, never sent.
inline constexpr std::int64_t kMaxOutboxRedeliveryHorizonCommands = 10000;

static_assert(kMaxOutboxRedeliveryHorizonCommands > 0,
              "a non-positive horizon would dead-letter every redrive");
static_assert(2 * kMaxOutboxRedeliveryHorizonCommands <= kAgentDedupRingRows,
              "the outbox redelivery horizon must stay at most half the agent dedup ring: "
              "a redelivery older than the ring re-executes (#3678)");

} // namespace yuzu
