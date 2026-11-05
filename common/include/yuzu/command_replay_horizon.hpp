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
/// between a row's first send attempt and a redrive. Every ring-consuming send passes the one
/// dispatch chokepoint (`ServerImpl::build_classified_command`) and mints one command_id, so one
/// dispatch call is at most one ring slot on any agent. The sequence the outbox reads
/// (`ExecutionTracker::current_dispatch_seq`) is the shared `dispatch_seq`, advanced when a
/// dispatch record is written, PLUS the reading process's count of dispatches whose record was
/// not written (a failed, refused or latch-skipped write): those still consume ring slots.
///
/// WHAT THIS BOUND IS, AND IS NOT. It is a conservative estimate, not a proof, and it errs in two
/// directions that must not be confused:
///  * OVER-count (safe: a row is dead-lettered EARLY, a scheduled fire is lost, audited and
///    counted). The sequence is fleet-wide, so every principal's dispatches advance it; a fan-out
///    loop (the Guardian, asset-tag and sync pushes) records one call PER TARGET although each
///    agent receives one command from it; `__guard__` consumes no dedup-ring slot yet counts; a
///    re-record of the same id counts again. One push to `kMaxOutboxRedeliveryHorizonCommands`
///    targets therefore dead-letters every stamped pending row at that moment.
///  * UNDER-count (UNSAFE: a row could be redriven after the agent evicted it). The unrecorded
///    count is per PROCESS. A record-write failure on a replica other than the one reading the
///    sequence is not counted, so while the shared database is write-failing on another replica
///    the horizon can trip late. A leader change resets the local term, which usually reads as a
///    sequence that went BACKWARDS and dead-letters the row (safe), but is not guaranteed to. The
///    2x margin is what absorbs what remains (the race between the horizon check and the agent's
///    claim, and tick-length staleness); it is NOT sized to tolerate a sustained, uncounted
///    write outage. A sound close of the under-count needs the agent to refuse an id older than
///    its own ring (a wire change), tracked separately.
///
/// The margin is the headroom the count does not otherwise account for. Do not tighten it to
/// `<`/`<=` without re-deriving all of the above.
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
