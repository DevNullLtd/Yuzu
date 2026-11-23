# Resource Ledger — echo rollback_wedged offline reason

Range: `origin/dev..HEAD` (branch `fix/echo-storage-offline-rollback-wedged`, reviewed range `47697d783..ae408bc517`)

## Summary

Round 2 (fix diff `bcb3a87d60..ae408bc517`) adds no resource either: see R5 to R7. This diff adds **no thread, subprocess, socket, fd, `FILE*`, `sqlite3*`, `sqlite3_stmt*`, OpenSSL object, BCrypt handle, mapped library, allocated C string or temp path** to production code. The one new member is a value-type `std::function<int(sqlite3*)>` on `EchoDatabase` that is empty in production. The new slow-tick code uses only value types (`std::string`, an enum) and the plugin KV calls the tick already made.

## Table 1 — new owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `EchoDatabase::rollback_`, a `std::function<int(sqlite3*)>` | `EchoDatabase` (value member, declared after `fold_` and before `mu_`) | copied from `OpenSeams::rollback` by `open()` before the schema steps, on the local object, before it is returned or published; empty in production | `EchoDatabase` destructor | moved in the move constructor and move assignment, the moved-from copy left empty; self-move guarded | none needed: no resource behind it. It is called only by `rollback_locked()` with `mu_` held and a non-null `db_`, and never receives ownership of the handle |
| R2 | `rollback_locked(char** errmsg)` | member function, no state | n/a | n/a | n/a | seam path passes no `errmsg`, so the caller's `err` guard frees nothing; seam-less path is the original `sqlite3_exec(db_, "ROLLBACK", ...)` |
| R3 | `OpenSeams::rollback` | caller-owned `std::function` inside the caller's `OpenSeams`, taken by const reference | built by a test only | caller scope | copied into the database, never aliased | none |
| R4 | tag value read in `do_collect_slow` | prvalue `std::string` from `PluginContext::storage_get`, a temporary in the switch condition | only when `storage_exists` is true | end of the full expression | passed to `online_offline_tag_action` as a `std::string_view`, which does not outlive the call | value type |

| R5 | `EchoPlugin::refuse_on_closed_store(ctx, action)` | member function, no state | n/a | n/a | n/a | reads `db_` (null-checked) and the lock-free probes `is_open()` and `query_engine_available()`; takes no lock, so no new lock-order edge; writes one line to the caller's `ctx` |
| R6 | `refused_on_closed_store` / `format_closed_store_refusal` | pure free functions in `echo_status_format.hpp` | n/a | n/a | returns `std::optional<std::string>` by value (copy of line 0 of `format_storage_offline_lines`, a fixed two-element vector) | value types, nothing to release |
| R7 | null guard in `do_collect_slow` | early return, no state | n/a | n/a | n/a | writes `error|Echo database not initialized`, rc 1, before the reconcile |

## Table 2 — existing resources the diff reaches (ownership unchanged)

| Resource | Owner | Interaction |
|---|---|---|
| `db_` (`std::atomic<sqlite3*>`) | `EchoDatabase` | still closed (`sqlite3_close_v2`) and nulled only under `mu_` on a failed rollback with the connection still in a transaction; the seam receives the live pointer and cannot null it. `is_open()` is a lock-free atomic read, now also taken by the slow tick |
| plugin `db_` (`std::unique_ptr<EchoDatabase>`) | `EchoPlugin` | `do_collect_slow` now returns early on a null `db_` (g3-1 fixed); `refuse_on_closed_store` null-checks it too, while the other actions still deref it as before; both teardown paths call `trigger_engine_.stop()` before the plugin `shutdown()` (agent.cpp:1432, 4241), see finding g3-1 |
| plugin KV key `heartbeat.storage_offline` | host KV, per plugin | set or deleted from the slow tick through `PluginContext`, outside `collect_mu_`, taking no `EchoDatabase` lock, so no new lock-order edge |

## Deadlines and bounds

No new blocking wait, loop or unbounded buffer. The tick adds one `storage_exists`, a `storage_get` only when the key is present, and a rare `storage_set` or `storage_delete`.
