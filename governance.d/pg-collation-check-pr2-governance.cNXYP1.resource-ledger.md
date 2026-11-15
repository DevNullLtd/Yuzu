# Resource Ledger: PostgreSQL collation version check (PR 2 of 3)

Range `origin/dev..HEAD` (tip after fix round 2). Verified by the Gate 3 and Gate 8 cpp-safety reviewers from a read of
the range; the Gate 1 table is amended by the rows marked CHANGED.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| `std::thread PgCollationRecheck::thread_` | `PgCollationRecheck` (held in `std::unique_ptr<PgCollationRecheck> pg_collation_recheck_` in `ServerImpl`) | `start()` under `mu_`, only when not stopped; CHANGED: `thread_` is assigned BEFORE `started_ = true`, so a throwing `std::thread` constructor leaves `started_` false | `stop()` (join outside `mu_`, self-join guarded); the destructor calls `stop()` | none (non-copyable) | `request_stop()` sets the flag under `mu_` and notifies; a check cut short by stop drops its report |
| join point in `ServerImpl::stop()` | `ServerImpl::stop()` | CHANGED: `request_stop()` early (start of the drain, inside the lifecycle lock); the join is the LAST step before `gw_mgmt_pool_.reset(); pg_pool_.reset();`, after the leader resign, audit cleanup and offload flush | the join | none | the three `std::_Exit(1)` escalations in `stop()` precede the join and end the process; a second termination signal hard-exits before taking `lifecycle_mu_`. A join against a backend that is frozen while its connection keeps acknowledging data is unbounded and ends only when the orchestrator kills the process, after every step above has run (documented) |
| pooled PostgreSQL connection | `PgPool` lease inside `pool.with_txn_for(5 s, ...)` | per check | RAII at the end of the transaction | none | the callback gets a borrowed `PGconn*` and never keeps it; each result is a `PgResult` RAII object; `SET LOCAL statement_timeout` is transaction-scoped |
| `[this]` check lambda borrowing `ServerImpl::pg_pool_` and `metrics_` | the `std::function` inside `PgCollationRecheck` | construction in `run()` under `lifecycle_mu_` with `if (!teardown_complete_ && !stop_requested_.load(std::memory_order_acquire))` | destroyed with the recheck | none | lifetime rests on three facts: `metrics_` is declared before `pg_pool_`, `pg_pool_` before `pg_collation_recheck_`, and the join precedes `pg_pool_.reset()`; the wiring gate pins the guard polarity, the join position and the member order |
| `MetricsRegistry` series | the registry | by-name lookup per write | `clear_gauge_family` on the mismatch family only | none | CHANGED: one new gauge `yuzu_pg_collation_check_last_completed_timestamp_seconds` (a registry entry, not a resource) is written by every applied report and never cleared; no `Gauge&` is cached anywhere |
| `state_mu_`, `mu_` | `PgCollationRecheck` | per call | RAII lock guards | none | `state_mu_` is a leaf and is never held across the check; `mu_` is released inside `wait_for`; the thread never takes `lifecycle_mu_` |
| test-only: cluster-wide role in the `[nonsuper]` case | the test's `RoleGuard` | `CREATE ROLE ... VALID UNTIL now()+1h` | `DROP OWNED BY`, `DROP ROLE` each in its own try | none | expires by itself after an hour if a kill skips the guard |

No fd, `FILE*`, HANDLE, SOCKET, `sqlite3*`, OpenSSL or BCrypt object, `dlopen`, subprocess, temp path or manual `new`/`delete`
is introduced. Not run: TSan, MSVC, Clang or macOS builds.
