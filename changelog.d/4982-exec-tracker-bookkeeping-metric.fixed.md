- **Fixed — `ExecutionTracker::set_agents_targeted` / `::mark_cancelled` failures are now
  observable, not log-only** (#4982). Every REST (`rest_api_v1.cpp`'s async result-set
  producers) and MCP (the result-set producer tools and `execute_instruction`'s post-dispatch
  bookkeeping) call site that previously did only `spdlog::error(...)` on a pool-exhausted or
  failed-statement bookkeeping write now also increments a new counter,
  `yuzu_exec_tracker_bookkeeping_failed_total{op,surface}` (`op` ∈ `set_agents_targeted`\|
  `mark_cancelled`). No inline retry is added — retrying inside an already-degraded-store
  request handler would risk doubling request latency for no reliability gain. A sustained
  `mark_cancelled` failure can still leave an execution row stranded at `status='running'`
  forever when the dispatch it was meant to cancel never actually reached an agent; recovering
  that population is the stuck-execution sweep (#4982 Part B — see that fragment). **Fix round
  2** (post-adversarial-review, still pre-release): the identical swallowed-failure pattern was
  found, uninstrumented, at the equivalent call sites in `workflow_routes.cpp`,
  `schedule_runner.cpp` and `command_outbox_delivery.cpp` — `surface` widens to `rest`\|`mcp`\|
  `workflow`\|`schedule`\|`outbox` (10-series closed set, still pre-seeded to 0 at boot). The
  `command_outbox_delivery.cpp` site where a fallback `mark_cancelled` was attempted after
  `set_agents_targeted` itself failed had neither a log line nor a metric at all before this
  fix; it now gets both.
