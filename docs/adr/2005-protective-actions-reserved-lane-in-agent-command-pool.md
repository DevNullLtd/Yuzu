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

Owner decision, Fraser Jarvis, 2026-11-18: the pool-teardown join (#8247), the bounded-helper unload
residual (#8204), the ~60 s `patch_connectivity` ordinary-worker hold and the ordinary-lane filesystem
stall are documented residuals the owner accepted for this change. Protective-lane starvation (#8288) is
not owner-accepted: it is tracked in #8288.

- **Pool teardown is not bounded.** The reserved lane governs worker admission while a pool is running. It does not bound pool teardown. When the stream drops the agent destroys the pool. A queued ordinary task that has not started is answered REJECTED ("agent reconnecting") without running and an ordinary command's stagger sleep ends within about a second. A queued protective action is never rejected: it runs, with no stagger sleep, before the pool is destroyed. The agent then waits, with no bound, for every task already RUNNING its plugin to return before it reconnects; a command blocked in the kernel holds that wait, the reserved lane does not help, and a quarantine or `__guard__.push_rules` sent after the drop is not received until it returns (#8247). The 20 s shutdown watchdog does not cover this wait.
- **Independence is asserted, not verified.** The reserve guarantees a WORKER is available to a
  protective command. It does not prove the protective action's own blocking calls (a firewall
  backend, a resolver, the filesystem it touches) are independent of whatever stalled the ordinary
  commands. A protective command that itself blocks holds its worker; the reserve is one worker.
- **No protective-versus-protective reserve.** A protective task has its own queue, is taken first and
  may use ANY worker, so `workers` stuck protective tasks leave no worker for a further protective task
  or for an ordinary one (four stuck protective tasks on `ThreadPool(4, .., 1)` were verified to block
  both). Capping protective running at `workers - 1`, or one in-flight protective task per
  `(plugin, action)`, is a follow-up tracked in #8288, not part of this change.
- **A protective action never sleeps a stagger or delay.** An ordinary command carrying `stagger_seconds` or
  `delay_seconds` (up to 600 s) sleeps on its worker in slices of at most one second, and the sleep ends when
  the pool is closing for a reconnect or the agent is stopping: the command is then not started, is answered
  REJECTED ("agent reconnecting" or "agent stopping") and its claim is released so a redelivery can run it.
  A protective action skips the sleep and, while the pool is closing, is not rejected: it starts at once
  (`command_start_gate.hpp`, the same `is_protective_action` predicate that picks the lane).
- **Result writes share `stream_write_mu_`.** A protective result waits on the same stream write mutex as
  every ordinary result.
- **The `firewall` plugin has no plugin-level mutex**, so two protective commands can enter it together.
- It does not bound a stall inside an ordinary command (that is the helper-thread work in the plugins)
  and does not free a worker that is already stuck: the lane guarantees a worker, not a bounded pool,
  so a Linux/macOS `filesystem` stall can still hold ordinary workers. A bounded helper can itself stay
  blocked in the kernel until the plugin is unloaded; the host drain barrier is tracked in #8204. A
  `windows_updates.patch_connectivity` dispatch holds an ordinary worker for up to about 60 s. These
  are accepted residuals.
- A wedge is still visible only as commands that never finish; the tag above makes the pool state
  readable from the server, nothing more.

## Invariants (catastrophic-if-violated)

- The admission rule exists only in `ThreadPool::ordinary_may_start_locked`; a second copy at a call
  site is how the reserve silently erodes.
- The lane's membership is `is_protective_action`, never a second list.
- `reserved` is clamped below `workers`; the pool never reserves its last ordinary worker.
- Tests assert exact numbers (pool of 4, reserve 1: 3 stuck ordinary tasks start, a 4th does not, a
  protective task runs promptly); removing the reserve must turn them red.
