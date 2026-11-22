# Resource Ledger - #7290 / #7291 (Echo v10 migration failure loads offline and retries; update-verified marker at registration)

Run: `7290-echo-v10-failure-handling.hR4j48`. Range `04e15e3be99fb876a041e4ab127b31818d541c80..25a124d9e90e3ec36fdcb4a5bc360bbb518bba9e`. This is the Gate 1 Resource Ledger for the C++ diff. Each resource below was independently proved by the security-guardian and cpp-safety governance reviewers (one owner, one release path, explicit transfer, checked failure cleanup).

## Production code

| # | Resource | Kind and owner | Acquired | Released | Transferred or aliased | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | retry thread | `std::thread` inside `yuzu::echo::OpenRetryLoop`, owned by the plugin member `open_retry_` (declared last, so destroyed first) | `OpenRetryLoop::start`, from `init` when the open failed with a retried reason; `start` calls `stop` first, so a second start cannot orphan a thread | `OpenRetryLoop::stop` (notify, then join): called by `shutdown` before the gate closes and before `db_.reset()`, and by the destructor; idempotent | none: never detached, never joined by itself | an attempt that throws is logged and counts as a failed attempt; `retry_open` returns true early once `db_` is set so a second attempt can never reassign it |
| R2 | stop flag, mutex, condition variable | members of `OpenRetryLoop`; `stop_` is `std::atomic<bool>` written under `mu_` | with the loop | with the loop | the cancel predicate handed to the attempt reads `stop_` lock-free (it is polled from a SQLite progress callback) | none needed |
| R3 | retry-attempt database handle | `std::expected<EchoDatabase>` local in `retry_open`, moved into the plugin's `std::unique_ptr<EchoDatabase> db_` only on success | `EchoDatabase::open` | destructor: dropped (and closed) when the loop was cancelled, or when the open failed; `db_` is released by `shutdown` after the retry thread is joined | moved once, into `db_`; `db_` is written only by init or by the retry thread while the loop runs | closed by the destructor on every early return |
| R4 | migration deadline and cancel guard | `ScopedProgressHandler` local inside the v10 transaction lambda in `migrate_to_v10`, wrapping the `sqlite3*` the transaction already owns | at the start of the lambda | destructor, before COMMIT or ROLLBACK and before the handle it guards; copy deleted | captures `&expired` and the caller's `OpenSeams`, both of which outlive it | a throw in the callback is treated as expired (interrupt, rollback); a poisoned handle cannot commit |
| R5 | `online_` dispatch gate and `offline_` state | `std::atomic<bool>` and a struct under `offline_mu_` in the plugin | with the plugin | with the plugin | `online_` is stored true exactly once, as the last statement of `start_collection`; `shutdown` closes it after joining the loop | init resets both for a same-process re-init |
| R6 | heartbeat key `heartbeat.storage_offline` | a row in the host KV store, written with the SDK `storage_set` | `go_offline` | `storage_delete` at recovery in `start_collection` (result checked, warned on failure) and replayed from `do_collect_slow` until it succeeds; the server also drops the tag when the agent disconnects | none | a failed set or delete is logged, never thrown |
| R7 | update-verified marker | a regular file `<exe_dir>/.yuzu-update-verified`, path from the single `update_verified_marker()`; written by `Updater::mark_update_verified`, read by `rollback_if_needed` | `remove()` of whatever sits at the name, then `yuzu::shared::write_file_atomic` | consumed by `rollback_if_needed`; removed by packaging scripts | the shared writer creates an exclusive-create, no-follow sibling temp and renames it over the name, so nothing planted is written through | the writer's guard removes its temp on a failure path; a write failure is one logged warning and never a throw; process death can leave one `.tmp.<16hex>` sibling (orphan sweeping is declined in the shared writer, #4723) |
| R8 | file-size and free-space probes | `std::filesystem::file_size` and `space` with `error_code` overloads, plain values | per retry attempt | n/a | none | an error reads as unknown and the open is attempted |

## Server code (static only here: braga cannot build the server, ADR-0035)

| Resource | Owner | Notes |
|---|---|---|
| per-reason counters | a 4-slot `std::array` local to the fleet sweep in `agent_registry.cpp` | published into a closed label set every sweep (zeros included); the tag value is never stored or logged |

## Test code

| Resource | Owner | Notes |
|---|---|---|
| `OpenRetryLoop` fixtures | locals in `test_echo_open_retry.cpp`, declared after the state their lambdas capture | destroyed (and joined) before that state |
| temp databases, link fixtures | `TempDbFile`, `TempUpdaterDir` and the salted `yuzu_test_` temp dirs | removed by their destructors |
| `sqlite3_trace_v2` probe in the in-flight cancel case | installed through `v10_before_begin` on a connection the open owns | the connection is closed on failure |

## Not present in this diff

No new fd, HANDLE, SOCKET, `FILE*`, OpenSSL object, subprocess, detached work, cast resting on aliasing or manual cleanup outside RAII is added. No policy floor applies to the resources above.
