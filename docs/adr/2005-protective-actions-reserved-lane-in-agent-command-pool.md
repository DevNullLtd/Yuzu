---
status: accepted
owner: Fraser Jarvis (@fjarvis)
---

# ADR-2005 - Protective actions have a reserved lane in the agent command pool

**Authors:** Fraser Jarvis (@fjarvis)
**Date:** 2026-11-18
**Relates to:** ADR-0047 (quarantine store, the containment gate), `common/include/yuzu/protective_actions.hpp`
(the closed protective set), `agents/core/src/thread_pool.hpp`, #4816, #8204, `docs/user-manual/upgrading.md`
("Bounds, and what they do not promise")

## Context

The agent runs every command on one bounded worker pool (4 to 32 workers, sized from
`hardware_concurrency`). `firewall.quarantine` and its release shared that pool with every other plugin.
A command that blocks in the kernel (a stalled network mount, an unanswered resolver) holds one worker
until the call returns, so enough of them left no worker for a containment action: the security
decision to contain a device could be starved by unrelated commands.

## Decision

The owner ruled on 2026-11-18, in-session, accepting the recommendation ("All recs") that containment
must not be starvable by ordinary commands. The agent command pool therefore has a **reserved lane**:

1. **One admission rule, in one place.** `ThreadPool` starts an ordinary task only while fewer than
   `workers - reserved` ordinary tasks are running. Protective tasks have their own queue, are taken
   first, and may use any worker. No caller decides this; a caller only labels the task.
2. **The label is `yuzu::protective::is_protective_action(plugin, action)`**, the ONE predicate (the
   closed four-action `firewall` containment set plus `__guard__.push_rules`). Widening that set is a
   security decision and is not made here; the lane inherits it. The label is computed at the single
   submit site in `agent.cpp`.
3. **The reserve is one worker** (`kReservedProtectiveWorkers = 1`), clamped so at least one worker
   always remains for ordinary commands. With the pool minimum of 4 workers, 3 stuck ordinary commands
   leave the fourth free for containment.
4. **Separate bounds.** A full ordinary queue never rejects a protective task (own queue, same bound).
5. **Observability.** The heartbeat carries `yuzu.command_pool_busy` (`running/workers`) and
   `yuzu.command_pool_queued`, read from a lock-free gauge that outlives every pool (a reconnect
   destroys and re-creates the pool). The agent has no `/metrics` endpoint, so the tag is the signal.

## What this does NOT establish

- **Pool teardown is not covered.** The reserved lane governs worker admission while a pool is running. It does not cover pool teardown: when the stream drops the agent destroys the pool and drains every queued task (a task sleeping on a stagger or delay of up to 600 s included) before it reconnects, so a quarantine or `__guard__.push_rules` dispatched in that window is delivered only after the drain ends (tracked in #8247).
- **Independence is asserted, not verified.** The reserve guarantees a WORKER is available to a
  protective command. It does not prove the protective action's own blocking calls (a firewall
  backend, a resolver, the filesystem it touches) are independent of whatever stalled the ordinary
  commands. A protective command that itself blocks holds its worker; the reserve is one worker.
- **No protective-versus-protective reserve.** The lane has one worker (more on a larger pool); several
  stuck protective commands can occupy all of it.
- **A stagger or delay sleep runs on the worker.** A command carrying `stagger_seconds` or
  `delay_seconds` (up to 600 s) sleeps on its worker, protective commands included; the protective lane
  does not skip it.
- **Result writes share `stream_write_mu_`.** A protective result waits on the same stream write mutex as
  every ordinary result.
- **The `firewall` plugin has no plugin-level mutex**, so two protective commands can enter it together.
- It does not bound a stall inside an ordinary command (that is the helper-thread work in the plugins)
  and does not free a worker that is already stuck.
- A wedge is still visible only as commands that never finish; the tag above makes the pool state
  readable from the server, nothing more.

## Invariants (catastrophic-if-violated)

- The admission rule exists only in `ThreadPool::ordinary_may_start_locked`; a second copy at a call
  site is how the reserve silently erodes.
- The lane's membership is `is_protective_action`, never a second list.
- `reserved` is clamped below `workers`; the pool never reserves its last ordinary worker.
- Tests assert exact numbers (pool of 4, reserve 1: 3 stuck ordinary tasks start, a 4th does not, a
  protective task runs promptly); removing the reserve must turn them red.
