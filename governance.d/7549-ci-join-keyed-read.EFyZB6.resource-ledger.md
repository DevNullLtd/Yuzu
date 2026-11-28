# Resource Ledger — #7549 roster-keyed device-CI read

Range: `2c3d0ac148..86d1a9df7f` plus the fix round committed with this file (branch `feat/hw-roster-ci-presence-7549-7566`)

## Summary

This diff adds **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle, mapped
library, temp path or file descriptor of its own**. The only owned resource on the new path is one pooled
Postgres connection leased through `PgPool::Lease` (move-only RAII), held across all chunks of one read. The
tests hold two further leases in a scope. No manual cleanup was added.

## Table 1: owned state in `DeviceInventoryStore::list_device_ci_for`

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Pooled connection | `PgPool::Lease` (`auto lease = pool_.try_acquire_for(kQueryAcquireTimeout)`; copy deleted) | after the closed-store check and the empty-ids early return, so those two paths take no lease | scope exit, on every return (budget spent, statement failure, normal) and on a `bad_alloc` unwind | none; the lease is never moved out | `PgPool::release` rolls back or discards a connection that is not idle. Every statement is a bare autocommit `PQexecParams` (no `BEGIN`), so a failed middle chunk leaves an idle, healthy connection. The middle-chunk test proves a read straight after succeeds. |
| R2 | Per-chunk result | `pg::PgResult res` (RAII, `PQclear` in the destructor) | each loop iteration | end of that iteration, before the next chunk | none; rows are copied into `DeviceCiRecord` values by `fill_record` | destroyed on every early return; `PQerrorMessage(lease.get())` is read while the lease and the result are both live |
| R3 | Id batch | `std::vector<std::string_view> views` borrowing from the `const&` `agent_ids` parameter | reserved once (`min(chunk, ids)`), refilled by `assign` each iteration | function exit | none | the views never outlive the call: `pg::to_text_array(views)` copies into an owned `std::string` before the next `assign`, and `exec_params` copies that literal for `PQexecParams` |
| R4 | Result vector | `std::vector<DeviceCiRecord> out` (local) | grows by `push_back` (no per-chunk `reserve`, removed in the fix round) | returned by value on success; destroyed on every `nullopt` return | moved to the caller | RAII; never returned partially |
| R5 | Function-local `static DegradeSampler s` | static storage (magic statics) | first use of each degrade branch | process exit | none | two relaxed atomics; same pattern as every other site in the file |
| R6 | Budget deadline | `steady_clock::time_point` value | computed once from `std::clamp(budget, 0, 24h)` | n/a | n/a | value type; the clamp removes signed overflow for any injected budget |

## Table 2: `apply_ci_read` and the `server.cpp` call

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R7 | Id copy | `std::vector<std::string> ids` (local to `apply_ci_read`) | built from `result.rows` | function exit | passed to the reader by const reference | RAII |
| R8 | Join map | `std::unordered_map<std::string, DeviceCiRecord> ci_by_agent` | built from the returned records (`key` copied before the record is moved) | function exit | records moved in | RAII; a duplicate id keeps the first (`emplace`) |
| R9 | Reader callback | `CiKeyedReadFn` (`std::function`), a temporary built in `build_hw_roster`; the real one captures `this` only | constructed inside the call expression | end of the full expression | none; never stored | invoked synchronously on the HTTP/MCP worker that is running `build_hw_roster`. `stop()` joins the web server before `device_inventory_store_.reset()`, so the capture cannot outlive the store (unchanged from the old inline dereference) |

## Tests

The new tests hold two `PgPool::Lease` values (move-only, scoped to one `SECTION`) so a lease taken before the
empty-ids check would time out, and use a throwaway database cloned per test by `YUZU_REQUIRE_PG_DB_TPL`. The
`ALTER TABLE ... RENAME COLUMN` in the failed-statement section runs against that private clone.

## Residuals (disclosed, not changed here)

- The 20 s budget is checked only before chunks 2 and later, so one read can hold a connection for about 50 s
  (20 s plus one 30 s statement). Documented in `docs/user-manual/inventory.md`; the structural fix is deferred
  (see the ledger row `arch-F1`).
- Each chunk is its own autocommit snapshot (ledger row `UP-6`).
