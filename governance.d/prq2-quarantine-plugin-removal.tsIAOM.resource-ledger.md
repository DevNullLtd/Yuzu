# Resource Ledger — PRQ.2 removal of the legacy containment plugin; firewall-only containment (server cut-over)

Range: `origin/dev..HEAD` (branch `feat/quarantine-plugin-removal`)

Rows are written at build time from the code; the `/governance` run that owns the findings
ledger re-verifies each row at gate 3 and appends any finding it raises there.

## Summary

This change deletes C++ (the legacy agent plugin and its tests) and rewrites the server's
containment path (`quarantine_reapply`, `quarantine_containment_reconciler`, the REST `DELETE`
handler, `QuarantineStore` schema v4). It introduces **no new manual-lifetime resource**: no
`new`/`delete`, no raw `malloc`, no new thread, no new file descriptor, no detached work. What it
adds is value types, one `std::function` adapter, pooled-connection leases that already carry an
RAII owner, and one RAII in-flight guard. Each is listed below.

## Table 1 — resources acquired

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| Pooled Postgres connection | the existing `PgPool` lease (`pool.try_acquire_for(kWriteTimeout)` / `kReadTimeout`) | `QuarantineStore::guarded_record_update`, `request_release`, `mark_released`, `list_release_owed`, `clear_release_owed`, `mark_endpoint_confirmed` | one statement or one transaction | Every new store method takes the lease inside the function and releases it on return; no lease crosses a call or is held while a command is dispatched or awaited. A closed store, an acquire timeout and a query error return a typed error (never an empty success). |
| Live-poll slot | `LiveInflightGuard` (RAII) | the `DELETE /api/v1/quarantine/{agent_id}` handler's bounded confirmation poll | the handler body | One slot for the whole poll (`detail::release_confirm_max_polls()` x `live_poll_interval_ms()`), released by the destructor on every exit path including an exception; a refused slot (the whole-server in-flight cap) skips the wait and the handler answers `202 releasing`, so backpressure never changes what was recorded. |
| Mutation gate (agent) | `yuzu::shared::MutationGate::Guard` (moved from `agents/plugins/quarantine/src/quarantine_serialization.hpp` to `agents/shared/mutation_gate.hpp`, namespace `yuzu::shared`) | the firewall plugin's `gated()` (the one acquisition site) | action body | Behaviour unchanged: FIFO ticket gate, 2 s budget, `quarantine_status` never takes it. Only the namespace, the header's home and its banner changed; the unit test moved with it (`tests/unit/test_mutation_gate.cpp`). |
| Dispatch adapter | `ReapplyDispatchFn` (`std::function`) | `redispatch_stored_containment` callers (the reconciler and MCP `quarantine_device`) | one call | Captures by reference only objects that outlive the call; a throw is caught inside `redispatch_stored_containment` and reported as `dispatch_threw`. |
| Reconciler thread | existing `QuarantineContainmentReconciler` background thread | `server.cpp` (unchanged owner) | server lifetime | No new thread. The tick body was rewritten (per-agent state machine, owed-release leg); it is stopped and joined by the existing shutdown path. Per-tick dispatch work is bounded by `kMaxDispatchesPerTick` (50), and each agent holds at most one pending command (`Pending::{none,status,apply,release}`). |

## Table 2 — value-type state (no manual lifetime management)

| Resource | Type | Owner | Notes |
|---|---|---|---|
| `QuarantineRecord` (+ `release_requested_at`, `device_release_owed_at`) | struct of `std::string`/`int64_t` | caller stack frames | Read through one column list (`kRecordCols`) so the `releasing` status is derived in one place. |
| `ContainmentReply`, `ContainmentReapplyResult`, `ContainmentReapplyError` | structs / `std::expected` | `redispatch_stored_containment` and the reconciler | Parsed once per reply; `probe_configured` and `allow_set_unchanged` are plain fields. |
| Reconciler `AgentState` map (`agent_id` -> state: kind, pending, session, record id, owed-release flags, the allow-set report flag, timestamps) | `std::unordered_map` | the reconciler; read and written by the tick thread and by heartbeat callbacks, every access under `mu_` | Entries are erased when an agent has no record and nothing owed; the heartbeat fast path reads only `unconfirmed_cache_`, under the existing `mu_`. `reconcile_one` works on a plain copy of its entry taken under `mu_` when it claims the entry, so a reply is honoured only for the record and session it was sent under and a re-quarantined or reconnected device is never confirmed from an older reply. |
| Gauges `yuzu_server_quarantine_release_pending{reachability}`, `yuzu_server_quarantine_forced_release_owed{reachability}` | `yuzu::Gauge` entries in the existing metrics registry | `server.cpp` (seeded at boot), the reconciler (set each tick) | Two fixed label values each, pre-seeded to 0. |

## Table 3 — threads and callbacks

No thread is created or destroyed. The `std::function` callbacks the reconciler is handed (`Deps`:
dispatch, record reads and writes, audit, metrics, the millisecond overrides used by tests) are
stack- or server-lifetime-scoped and are invoked from the reconciler's tick thread and from heartbeat callbacks (`notify_agent_heartbeat`); the REST
`DELETE` handler runs on the httplib pool and calls the same dispatch function synchronously inside
its bounded poll. Nothing is stored beyond the call that received it.
