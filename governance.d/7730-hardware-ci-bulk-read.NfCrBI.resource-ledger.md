# Resource Ledger: the bulk device-CI read (PR 1 of 3)

Range reviewed: `origin/dev..f025c558a0` (merge-base `6a5e29add2`; the branch is 23 commits). Companion to the
`7730-hardware-ci-bulk-read.*.jsonl` fragment. Gate 1 summary as corrected by `cpp-safety` in Gate 3 and
Gate 8 rounds 1 to 3.

## Production code

| Resource | Owner type | Acquired | Released | Failure cleanup |
|---|---|---|---|---|
| Pooled PostgreSQL connection for `DeviceInventoryStore::list_device_ci_after` | `pg::PgPool` lease inside `pool_.with_txn_for(...)` (`PgTxn` declared after the lease) | start of the call | lambda exit through the destructors (ROLLBACK first, then release) | every early return, exception and a COMMIT failure unwind through both guards; a failed COMMIT leaves `ok` false so rows from an unconfirmed transaction are never served |
| `PGresult` objects (`t`, `res`) | `pg::PgResult` RAII inside the lambda | after each statement | lambda exit, before COMMIT | every field is copied to `std::string` before release (no `PQgetvalue` pointer survives) |
| `DeviceCiKeysetStatement` (`sql`, `params`) built by `device_ci_keyset_statement(q)` | by-value return (NRVO); the `std::string_view` ids vector over `q.agent_ids` is consumed inside the builder and `to_text_array` copies | call start | call exit | none needed; no view onto a temporary |
| Function-local `static DegradeSampler` (two relaxed atomics) in the degrade branches | function-local statics | first use | process exit | constant-initialised atomics; a race only perturbs log sampling, never a counter |
| Runtime index check `warn_if_agent_id_c_index_unusable` (store open path, after the projection probe) | reuses the constructor's single pooled `lease` (RAII, non-owning `PGconn*`); one `PgResult` (RAII) | inside the store constructor | function exit | rows are copied into `std::string` before the result is released; a failed or throwing check only logs; `open_ = true` is set last so the store is never half-open |
| Migration constants `kAgentIdCIndexKey` (`constexpr string_view`), `kAgentIdCIndexName` (`constexpr const char*`), `kMigrationV4Sql` and `kAgentIdCIndexCreateSql` (`const std::string`, built from constants only) | internal-linkage statics | static initialisation | process exit | no initialisation-order hazard (inputs are `constexpr`); `PgMigration::sql` copies the text |
| `device_inventory_migrations()` accessor | const reference to a function-local static vector | first call | process exit | owns nothing |
| `hw_ci_page_reader` closure in `HardwareRoutes::Deps` and `ToolDeps` (captures `this` = `ServerImpl`) | `std::function` copies | route and MCP registration | with the routes | `ServerImpl::stop()` stops the web server, waits up to 15 s, then joins `web_thread_` or calls `std::_Exit(1)`, all before `device_inventory_store_.reset()`; no thread and no detach added; the closure reads `device_inventory_store_` at call time and answers nullopt (a degrade, never an empty page) when it is null |
| `ReadFailure` string_view members (`describe_read_error`) | borrowed views onto string literals and `inline constexpr` strings (static storage); `audit_detail` is an owning `std::string` | per call | per call | documented in the header; no view onto a temporary |

No new fd, HANDLE, SOCKET, `FILE*`, SQLite object, OpenSSL object, BCrypt handle, allocated C string, mapped library,
temp path, subprocess, thread, detached work, raw cast or manual cleanup in production code. The v4 index is a
database object, not a C++ resource.

## Test code

| Resource | Owner type | Failure cleanup |
|---|---|---|
| Holder thread in "a v3 database upgrades to v4 behind a lock held longer than the pool's lock timeout" | `std::jthread` declared after the state it uses; no `REQUIRE` or `CHECK` inside the thread | joined on every path including a failed `REQUIRE` or an exception on the main thread; failure recorded in an `std::atomic<bool>` and an error string read only after the join |
| `std::latch` for the holder | local | counted down on every path (acquire failure, BEGIN or LOCK failure, success, exception) so the waiter never hangs |
| Second `PgPool` (`short_lock_pool`, size 2) and the holder lease with an open transaction and a table lock | `PgPool` and lease RAII | released by COMMIT, ROLLBACK or `PgPool::release` (which rolls back a non-idle connection or discards it); destroyed after the join |
| `LogCapture` | existing RAII helper | `stop()` before `text()` |
| Throwaway databases | `YUZU_REQUIRE_PG_DB_TPL` (fresh generated name per test and per `SECTION`) | index drops and creates leak nothing into other tests |
| `FakeCiKeysetStore` (`reader()` captures `this`; `erase()` is `std::erase_if` on a vector) | test-local object owned by the harness | `read()` returns copies; no iterator is held across calls |

## Sanitizer evidence

- ASan and UBSan on the cursor decoder, `read_page` limit edges (0, -1, `INT_MAX`, `INT_MIN`, 1001) and
  `describe_read_error` over 43 values on both surfaces: zero reports (cpp-safety, rounds 1 and 2; 600,036 fuzzed
  tokens). Round 3 changed the page model in comments only.
- TSan on the holder-thread test was not run (cpp-safety recommends one run). No MSVC, Clang or macOS build and no
  live stack was run. No sanitizer run of the store against PostgreSQL.

## Not covered by this ledger

The COMMIT-failure and BEGIN-failure branches in `list_device_ci_after` are not driven by a test. `statement_timeout = 0`
in the migration has no behavioural test (a text test pins it). The double-parenthesis form of an index definition
accepted by the index check was never printed by PG 16, 17 or 18.4, so that branch is unexercised.
