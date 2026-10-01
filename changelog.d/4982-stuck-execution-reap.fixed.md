- **Fixed — a new clock-guarded sweep recovers an execution row permanently wedged at
  `status='running'`** (#4982 Part B). When `ExecutionTracker::set_agents_targeted` /
  `::mark_cancelled` itself fails on the synchronous REST/MCP dispatch path (now counted by
  `yuzu_exec_tracker_bookkeeping_failed_total`, #4982 part 1), the execution row it leaves
  behind previously stayed `running` forever with no repair path.
  `reap_stuck_running_executions` (~15-minute cadence) now cancels a `running`/
  `agents_targeted=0` row once it is at least 30 minutes old, subject to two exclusions:
  any execution with a still-`pending` `command_outbox_store.outbox` entry (a
  `schedule_runner`/`command_outbox_delivery`-originated execution can legitimately sit at
  `running`/`agents_targeted=0` for the full duration of a `containment_unreadable`/
  `route_unreadable` degrade, retried indefinitely — that population is not a bookkeeping
  failure and must never be mass-cancelled), and any execution with at least one real
  `agent_exec_status` response already recorded (a dispatch that genuinely reached one or
  more agents is never force-cancelled on the strength of its own bookkeeping write having
  failed — that row is left `running` instead, since there is no repair path today that
  re-derives `agents_targeted` from the agents' own reported responses).

  The sweep also adopts a would-wipe guard (unlike its two DELETE-based siblings in this file,
  which deliberately don't): if the candidates are an implausibly large fraction of all
  currently-running executions (above a 20-row floor), it declines to act rather than risk
  mass-cancelling live work on the strength of what is more likely a systemic bug. A corrupt or
  unparseable persisted clock anchor self-heals rather than wedging the sweep permanently. The
  candidate selection and the cancel are one atomic, re-checked statement inside the same
  advisory-lock-held transaction, so a row that stops matching between selection and mutation
  (a genuine dispatch landing, its outbox entry going pending, a real agent response arriving)
  is correctly excluded at commit time, never force-cancelled on stale information.

  New metric `yuzu_exec_tracker_stuck_reap_total{outcome}` (`cancelled`\|`not_cancelled`\|
  `would_wipe`\|`clock_anomaly`\|`degraded`\|`capped`\|`skipped`) and a new
  `execution_tracker.reap_stuck_running_executions` row in the WS-10 background-job
  classification table (`ReplicaSafe`). Every cancellation this sweep performs also writes an
  `execution.cancel` audit row (`principal="system"`). Full seven-part clock-guarded-retention
  record: `docs/clock-guarded-retention.md`'s own entry for this sweep.

  A related fix closes a race in the delivery path this sweep's exclusion depends on:
  `command_outbox_delivery.cpp`'s delivery loop now commits the outbox `pending → sent`
  transition and the execution's real `agents_targeted` count in ONE transaction
  (`CommandDeliveryFinalizationOwner::mark_sent_with_target`), so a genuinely in-flight,
  successfully-dispatched command can never be observed as a false stuck-execution candidate
  between the two writes.

  A second related fix closes the same false-cancel risk inside `command_outbox_delivery.cpp`'s
  own automatic terminal paths (a redelivery attempt whose authority was revoked, or whose
  payload fails validation, after an earlier attempt for the same execution already reached
  real agents): every automatic cancel in that file now checks for an existing agent response
  first, through one shared chokepoint, and declines to cancel — leaving the row `running` for
  the stuck-execution sweep above to correctly never touch — rather than force-cancelling a
  dispatch that genuinely ran.
