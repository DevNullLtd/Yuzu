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
/// `kMaxOutboxRedeliveryHorizonCommands` is the most dispatches the outbox lets elapse between a
/// row's first attempt and a redrive of it. Every ring-consuming send passes the one dispatch
/// chokepoint (`ServerImpl::build_classified_command`) and mints one command_id, so one dispatch
/// is at most one ring slot on any agent. The outbox measures elapsed dispatches from two counters
/// (`ExecutionTracker::current_dispatch_position`, `dispatch_position.hpp`) that are deliberately
/// kept SEPARATE, because they are on different scales:
///  * `shared`     -- `dispatch_seq`, advanced when a dispatch RECORD is written; lives in the
///                    database, so every replica reads the same number.
///  * `unrecorded` -- the reading PROCESS's count of dispatches whose record was not written
///                    (failed, refused, latch-skipped). They were still sent and may have taken a
///                    ring slot. It restarts at zero in every process.
/// A row is stamped with both and with the leader epoch of the stamping term. A redrive's
/// estimate is `(shared_now - shared_stamp) + local`, where `local` is the exact difference of the
/// two unrecorded counts when the same leadership term (hence the same process) reads it, and the
/// reader's whole unrecorded count when any other term does. The two are never summed into one
/// stored number: an earlier version did, and a value stamped by one process was then read on
/// another process's scale, which could make a stale row look young.
///
/// WHAT THIS BOUND IS, AND IS NOT. It is a conservative estimate, not a proof, and it errs in two
/// directions that must not be confused:
///  * OVER-count (safe: a row is dead-lettered EARLY, a scheduled fire is lost, audited and
///    counted). The shared sequence is fleet-wide, so every principal's dispatches advance it; a
///    fan-out loop (the Guardian, asset-tag and sync pushes) records one call PER TARGET although
///    each agent receives one command from it; `__guard__` consumes no dedup-ring slot yet counts;
///    and every redrive that re-records its own id advances it again, so rows stuck in a long
///    outage age each other (100 such rows add about 3 a second). One push to
///    `kMaxOutboxRedeliveryHorizonCommands` targets dead-letters every stamped pending row at that
///    moment. A different-term reader also charges its whole unrecorded history, which includes
///    failures that predate the stamp. That count never decays inside a process: once a process has
///    accumulated about `kMaxOutboxRedeliveryHorizonCommands` unrecorded dispatches (one large
///    push during a tripped record latch is enough), EVERY later change of leadership on it
///    dead-letters every stamped pending row until it restarts.
///  * UNDER-count (UNSAFE: a row could be redriven after the agent evicted it).
///      - A record-write failure on a replica OTHER than the one reading the position is not
///        counted: its unrecorded count lives in its own process. A sustained write outage on a
///        non-leader replica therefore lets the horizon trip late.
///      - The same hole exists for an EARLIER PROCESS LIFETIME of the SAME replica. A restart or a
///        change of leadership gives the reader a new epoch and, after a restart, a count of
///        zero, so the unrecorded dispatches the previous process made AFTER the stamp are
///        forgotten and the row reads younger than it is. A restart is therefore not a safe
///        refusal; it is an under-count. (A restart cannot make the SHARED sequence go
///        backwards, so it never produces `redelivery_sequence_regressed`.)
///      - The shared sequence restored to a value still ABOVE a row's stamp reads as small
///        progress, which under-counts the dispatches the restore rewound.
///      - A replica that acts on a stale snapshot of a row can still send it after a peer
///        dead-lettered it, because the send precedes the fenced bookkeeping write (the ADR-2002
///        section 6 gap); the agent's dedup absorbs that unless the id has been evicted.
///      - A command dispatched before the stamp but queued (a gateway backlog, a slow agent
///        stream) and claimed by the agent after the stamp takes a ring slot the count never saw.
///      The 2x margin absorbs the race between the horizon check and the agent's claim and the
///      staleness of one tick; it is NOT sized to tolerate a sustained, uncounted outage. A sound
///      close of the under-count needs the agent to refuse an id older than its own ring (a wire
///      change) and is not part of this change.
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
