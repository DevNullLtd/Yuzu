- **Fixed — a new clock-guarded sweep recovers an execution row permanently wedged at
  `status='running'`** (#4982 Part B). When `ExecutionTracker::set_agents_targeted` /
  `::mark_cancelled` itself fails on the synchronous REST/MCP dispatch path (now counted by
  `yuzu_exec_tracker_bookkeeping_failed_total`, #4982 part 1), the execution row it leaves
  behind previously stayed `running` forever with no repair path. `reap_stuck_running_executions`
  (~15-minute cadence) now cancels a `running`/`agents_targeted=0` row once it is at least 30
  minutes old — but explicitly **excludes** any execution with a still-`pending`
  `command_outbox_store.outbox` entry, since a `schedule_runner`/`command_outbox_delivery`-
  originated execution can legitimately sit at `running`/`agents_targeted=0` for the full
  duration of a `containment_unreadable`/`route_unreadable` degrade (retried indefinitely, no
  cap) — that population is not a bookkeeping failure and must never be mass-cancelled. The
  sweep also adopts a would-wipe guard (unlike its two DELETE-based siblings in this file,
  which deliberately don't): if the candidates are an implausibly large fraction of all
  currently-running executions (above a 20-row floor), it declines to act rather than risk
  mass-cancelling live work on the strength of what is more likely a systemic bug. New metric
  `yuzu_exec_tracker_stuck_reap_total{outcome}` (cancelled\|not_cancelled\|would_wipe\|
  clock_anomaly\|degraded), and a new `execution_tracker.reap_stuck_running_executions` row in
  the WS-10 background-job classification table (`ReplicaSafe`). Full seven-part
  clock-guarded-retention record: `docs/clock-guarded-retention.md`'s own entry for this sweep.
  **Fix round 2** (post-adversarial-review, still pre-release): the sweep no longer wedges
  permanently after a >24h clock gap — a repeated same-direction anomaly now recovers and
  drains gradually instead of declining forever (see the doc entry above); the candidate select
  and the cancel are now ONE atomic `UPDATE ... RETURNING id` inside the same lock-held
  transaction (closing a TOCTOU window against a genuinely-dispatched row and making the
  500-row cap an honest per-pass bound under a second replica); the advisory lock is now
  try-and-skip rather than blocking; and a bounded per-pass log now names the cancelled
  `execution_id`s.

  **Fix round 3** (post-adversarial-review, still pre-release): the sweep's exclusion of
  still-`pending` outbox rows above was only as trustworthy as the write side it depends on —
  `command_outbox_delivery.cpp` committed the outbox `pending → sent` transition and
  `ExecutionTracker::set_agents_targeted`'s real target count as two SEPARATE autocommit
  statements, so a genuinely in-flight, successfully-dispatched command could read `state='sent'`
  (excluded by this sweep's own clause) with `agents_targeted` still `0` between the two commits —
  a false candidate, force-cancelled with no kill RPC ever sent. Fixed by
  `CommandDeliveryFinalizationOwner::mark_sent_with_target` (`command_delivery_finalization_owner.{hpp,cpp}`,
  a new ADR-0012 query owner): the sent-transition and the target-count write now commit in ONE
  transaction, so this sweep's own atomic recheck (round 2, above) can no longer observe them
  half-applied. See `docs/clock-guarded-retention.md`'s own entry for the full race and
  `docs/adr/0012-server-postgres-store-contract.md`'s Update for the new owner and its shared-fragment
  exception.

  **Fix round 7** (post-adversarial-review, still pre-release): an unparseable or negative
  *persisted* `stuck_exec_reap_anchor` — storage corruption, a bad migration, or a manual repair
  gone wrong — previously declined every future pass without repair, wedging the sweep
  permanently with no recovery path short of an operator hand-editing `reap_meta` (the
  round-2 skew-recovery marker above cannot reach this case, since control returns before it is
  read). The sweep now self-heals a corrupt persisted anchor the same way `GatewayRouteStore`'s
  sibling already does: re-anchor to the current pass's own sanitised clock reading and clear any
  stale skew marker, declining only that one pass.

  **Governance Gate 2 fix, still pre-release (BLOCKING, security-guardian, empirically
  reproduced):** the candidate predicate excluded a still-`pending` outbox row but never
  consulted `agent_exec_status` — a synchronous REST/MCP dispatch that genuinely reached one or
  more agents, with real responses recorded there, but whose OWN `set_agents_targeted`
  bookkeeping write failed, sat at `agents_targeted=0` forever (the terminal transition requires
  `agents_targeted > 0`) and was force-cancelled by this sweep at the 30-minute mark regardless
  of how many agents actually succeeded. The candidate predicate now also excludes any row with
  at least one `agent_exec_status` row — Part B's original orphan population (a dispatch refused
  BEFORE any agent was ever reached) has zero such rows, so this does not narrow that population;
  only a row with a genuine per-agent response is now additionally excluded. Every cancellation
  this sweep performs also now writes an `execution.cancel` audit row (`principal="system"`) —
  see `docs/user-manual/audit-log.md` — closing a gap where a background actor silently
  transitioning a command's terminal state left no audit trail at all (governance Gate 2,
  security-guardian, SHOULD).

  **Governance Gate 3 fixes, still pre-release (sre, SHOULD):** the pass's true, uncapped backlog
  size (`candidate_count`) was computed for the would-wipe ratio check and then discarded — a
  sustained failure storm producing more than 500 new stuck rows per ~15-minute cadence, but still
  under the 50%-of-running-population would-wipe ratio, looked identical to a healthy,
  fully-draining reaper. A new `capped` outcome on `yuzu_exec_tracker_stuck_reap_total` now fires
  once per ACCEPTED pass whose true backlog exceeded the cap, same meaning as the
  `GatewayRouteStore` sibling's `ok_capped`. A new `skipped` outcome fires when another replica
  already held the advisory lock this tick — previously this pass touched no outcome field at
  all, asymmetric with that same sibling's own `skipped`. See `docs/user-manual/metrics.md`'s new
  "Execution bookkeeping + stuck-execution reap metrics" section.
