# Resource Ledger: result sets that are not ready or incomplete

New or modified owned resources in `server/core/src/` (`result_set_store.cpp`,
`agent_registry.cpp`, `server.cpp`, `execution_tracker.cpp`, `agent_service_impl.{hpp,cpp}`) and
their unit tests. No thread, socket, descriptor, callback, `FILE*` or SQLite handle is added.

## Resources

### Persisted column `result_sets.agents_unanswered`
- **Site:** migration v5 in `result_set_store.cpp`, written by `ResultSetStore::materialize` in the
  same transaction that writes the membership, `device_count` and `agents_failed`.
- **Owner type:** the existing `result_set_store` schema; the column lives and dies with its row.
- **Release point:** the row's own deletion.
- **Transfer:** never. Read back into `ResultSet::agents_unanswered` by value.
- **Failure cleanup:** a failed update rolls back with the membership insert; the migration is
  idempotent (`IF NOT EXISTS`).

### `OwnedMembers` and the completeness list
- **Site:** `member_set_owned` returns an `OwnedMembers` value (a member set plus a `bool`);
  `AgentRegistry::evaluate_scope_impl` holds a local `std::vector<std::string>` of the set ids whose
  use depends on completeness.
- **Release point:** scope exit.
- **Failure cleanup:** RAII only.

### Persisted column `agent_exec_status.response_dropped`
- **Site:** migration v10 in `execution_tracker.cpp`, written by `upsert_agent_status_once` in the
  same transaction and the same statement as the agent's status, before the outbox append (the
  outbox contract is unchanged: the event payload does not carry it).
- **Owner type:** the existing `execution_tracker` schema; the column lives and dies with its row.
- **Release point:** the row's own deletion; a later terminal write for the same agent replaces it.
- **Transfer:** never. Counted by `ExecutionTracker::count_response_dropped` (a read-only count
  under its own bounded read lease; `nullopt` on any failure), called only by the result-set fill
  pass once an execution is terminal or its set has timed out.
- **Failure cleanup:** a failed upsert rolls back with the status; the migration is a
  constant-default `ADD COLUMN`.

### Completeness inherited from a parent set
- **Site:** `CreateRequest::agents_failed` / `agents_unanswered`, set by `inherit_completeness` at
  every producer whose members come from the parent's (the inventory producers and the three
  asynchronous ones, REST `run_async` and MCP `rs_run_async`) and persisted by `insert_row_impl` in
  the same insert as the row; `materialize` adds the fill's own counts to them in its
  status-guarded update. The fill pass never reads the parent.
- **Owner type:** plain integers on a request or local value; no handle.
- **Release point:** scope exit.
- **Failure cleanup:** none needed: the counters ride the existing insert and update statements.

### `AgentServiceImpl::unverified_frames_` (bounded in-memory registry)
- **Site:** member of `AgentServiceImpl`, type `UnverifiedFrameRegistry`
  (`unverified_frame_registry.hpp`). Written by `note_unverified_frame` at the two RUNNING ingest
  sites (Subscribe and gateway) when the frame's provenance is unverified; read and erased by
  `take_unverified_frame` at the two terminal ingest sites.
- **Owner type:** owned by value by the service; `std::map` entries plus a `std::mutex`, no thread,
  no callback, no handle.
- **Bound:** 4,096 entries (oldest evicted, counted as
  `yuzu_server_response_ingest_dropped_total{reason="unverified_registry_overflow"}`) and one hour
  per entry (expired on every `note` and `consume`, against `steady_clock` seconds).
- **Lock:** its own `mu_`, held only for the map operations; no other lock is taken under it and it
  is never held across I/O.
- **Release point:** each entry on consume, expiry or eviction; the whole registry with the service.
  It has the same lifetime as the service's other members (for example `cmd_times_mu_`), so the
  detached gateway-forward threads that reach `process_gateway_response` are bounded by the same
  service-lifetime ordering as those members.
- **Failure cleanup:** RAII only; nothing persists.
