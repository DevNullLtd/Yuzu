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
