- **Fixed — `ExecutionTracker::set_agents_targeted` / `::mark_cancelled` failures are now
  observable, not log-only** (#4982). Every REST (`rest_api_v1.cpp`'s async result-set
  producers) and MCP (the result-set producer tools and `execute_instruction`'s post-dispatch
  bookkeeping) call site that previously did only `spdlog::error(...)` on a pool-exhausted or
  failed-statement bookkeeping write now also increments a new counter,
  `yuzu_exec_tracker_bookkeeping_failed_total{op,surface}` (`op` ∈ `set_agents_targeted`\|
  `mark_cancelled`, `surface` ∈ `rest`\|`mcp`), pre-seeded to 0 at boot across the closed
  4-series label set. No inline retry is added — retrying inside an already-degraded-store
  request handler would risk doubling request latency for no reliability gain. A sustained
  `mark_cancelled` failure can still leave an execution row stranded at `status='running'`
  forever when the dispatch it was meant to cancel never actually reached an agent; recovering
  that population is tracked separately as a follow-up (#4982 part 2).
