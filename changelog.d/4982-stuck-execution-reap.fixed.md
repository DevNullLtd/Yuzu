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
