# Resource Ledger: Echo roll-up-only server reads

New or modified owned resources introduced in `server/core/src/` (`result_set_store.cpp`,
`result_set_members.hpp`, `result_set_matcher.cpp`, `settings_model.cpp`, `server.cpp`) and
their unit tests. No thread, socket, descriptor, callback, `FILE*` or SQLite handle is added.

## Resources

### Persisted column `result_sets.agents_failed`
- **Site:** migration v4 in `result_set_store.cpp` (`ALTER TABLE result_sets ADD COLUMN IF NOT
  EXISTS agents_failed BIGINT NOT NULL DEFAULT 0`), written by `ResultSetStore::materialize` in
  the same transaction that writes the membership and `device_count`.
- **Owner type:** the existing `result_set_store` schema; the column lives and dies with its row
  (deleted by the existing GC sweep and `delete_set`). No new table, index or schema.
- **Release point:** the row's own deletion. Nothing separate to release.
- **Transfer:** never. The value is read back into `ResultSet::agents_failed` by value.
- **Failure cleanup:** the update runs inside `materialize`'s transaction (`with_txn_for`); a
  failure rolls the membership insert and the count back together. The migration runs in its own
  transaction under the migration runner and is idempotent (`IF NOT EXISTS`).

### Failed-agent set in `result_set_members`
- **Site:** `result_set_members` (`result_set_members.hpp`), called by the result-set maintenance
  tick in `server.cpp`.
- **Owner type:** two function-local `std::unordered_set<std::string>` (`seen`, `failed`) and the
  returned `ResultSetMembers` value (a `std::vector<std::string>` plus an `int64_t`).
- **Release point:** scope exit. The sets are bounded by the number of distinct responders of one
  execution (the response store's per-execution read), the same bound the existing `seen` set had.
- **Transfer:** the result moves out by value; the caller moves the vector into `materialize`.
- **Failure cleanup:** RAII only; a `std::bad_alloc` unwinds both sets.

### Scratch copy in `references_raw_capture_table`
- **Site:** `result_set_matcher.cpp`.
- **Owner type:** a local `std::string` copy of the SQL (at most 100,000 bytes, the cap both
  transports already enforce before the call) and a lowercased word copy per identifier.
- **Release point:** scope exit.
- **Transfer:** never; the function returns a `bool`.
- **Failure cleanup:** RAII only.

### Source-tree read in a unit test
- **Site:** `read_definition` in `tests/unit/server/test_echo_retention_tiers.cpp`.
- **Owner type:** a local `std::ifstream`, closed by its destructor on every path.
- **Release point:** scope exit. It reads two committed YAML files and writes nothing.
