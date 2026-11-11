# Resource Ledger: result sets that are not ready or incomplete

New or modified owned resources in `server/core/src/` (`result_set_store.cpp`,
`agent_registry.cpp`, `server.cpp`) and their unit tests. No thread, socket, descriptor, callback,
`FILE*` or SQLite handle is added.

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
- **Transfer:** never. Counted by `ExecutionTracker::get_summary` into
  `ExecutionSummary::agents_response_dropped` (a read-only count under the existing lease).
- **Failure cleanup:** a failed upsert rolls back with the status; the migration is a
  constant-default `ADD COLUMN`.

### Completeness inherited from a parent set
- **Site:** `CreateRequest::agents_failed` / `agents_unanswered`, set by `inherit_completeness` at
  the inventory producers and persisted by `insert_row_impl` in the same insert as the row; the
  asynchronous fill pass in `server.cpp` adds the parent's counters (read through `get`) to its own
  before `materialize`.
- **Owner type:** plain integers on a request or local value; no handle.
- **Release point:** scope exit.
- **Failure cleanup:** a degraded parent read skips the set for that tick; it retries on the next.
