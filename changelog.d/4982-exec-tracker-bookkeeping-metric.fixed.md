- **Fixed — `ExecutionTracker::set_agents_targeted` / `::mark_cancelled` failures are now
  observable, not log-only** (#4982). Every REST, MCP, workflow, schedule, and command-outbox
  call site that previously did only `spdlog::error(...)` on a pool-exhausted or failed-statement
  bookkeeping write now also increments a new counter,
  `yuzu_exec_tracker_bookkeeping_failed_total{op,surface}` (`op` ∈ `set_agents_targeted`\|
  `mark_cancelled`, `surface` ∈ `rest`\|`mcp`\|`workflow`\|`schedule`\|`outbox`, a 10-series
  closed set pre-seeded to 0 at boot). No inline retry is added — retrying inside an
  already-degraded-store request handler would risk doubling request latency for no reliability
  gain. A sustained `mark_cancelled` failure can still leave an execution row stranded at
  `status='running'` forever when the dispatch it was meant to cancel never actually reached an
  agent; recovering that population is the stuck-execution sweep (#4982 Part B — see that
  fragment).
