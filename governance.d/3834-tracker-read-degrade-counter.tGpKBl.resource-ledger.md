# Resource Ledger - #3834 (ExecutionTracker read-degrade counter)

Run: `3834-tracker-read-degrade-counter.tGpKBl`. Base `origin/dev` 5662c5f07 plus the working-tree change. This is the Gate 1 Resource Ledger for the C++ diff, as verified independently by `cpp-safety` (Gates 3 and 8) and `security-guardian` (Gates 2 and 8).

## Production code (`server/core/src/execution_tracker.{cpp,hpp}`, `server.cpp`)

| Resource | Owner | Acquired | Released / transferred | Failure cleanup |
|---|---|---|---|---|
| `PgPool::Lease` in `get_children_checked` | local `auto lease` (move-only RAII) | `pool_.try_acquire_for(kReadTimeout)` | consumed by value into `pool_.with_txn_on(std::move(lease), fn)`; never read after the move; only the `!lease` null check sits between acquire and call | `!lease` returns before any use (counter + warn); otherwise RAII. Behaviour matches the old `with_txn_for` (`pg_pool.cpp:393-400`: `run_in_txn(try_acquire_for(t), fn)` vs `run_in_txn(std::move(lease), fn)`) |
| Transaction in `get_children_checked` | `run_in_txn` (`PgTxn` RAII) | `BEGIN` inside `with_txn_on` | `COMMIT` or rollback in `run_in_txn` | unchanged vs `with_txn_for`; the lambda body (incl. `scrub_executions`) is byte-identical |
| `yuzu::MetricsRegistry* metrics_` | NOT owned; borrowed from `ServerImpl::metrics_` | `set_metrics(&metrics_)` in the `ServerImpl` constructor, before any thread that reads the tracker | n/a | null-safe (`note_read_degrade` checks). Lifetime: `ServerImpl::metrics_` is declared (`server.cpp` ~23061) before `execution_tracker_` (~23229), so it is destroyed after it; `~ExecutionTracker` is defaulted and never touches `metrics_`; `stop()` joins reader threads before `execution_tracker_.reset()` |
| Counter series (15) in the registry | `MetricsRegistry` | `seed_read_degrade_metrics` at boot (store-open branch only) / first increment | registry lifetime | n/a |
| `kReadDegradeMethods`, `kReadDegradeReasons` (`constexpr std::array` via CTAD) and the `kMethod*`/`kReason*` constants indexed out of them | none (static storage, string-literal pointers) | compile time | n/a | no dangling possible |

## Test code (`tests/unit/server/test_execution_tracker.cpp`)

| Resource | Owner | Notes |
|---|---|---|
| `yuzu::MetricsRegistry m` wired into a longer-lived tracker | RAII local + `MetricsWire` (non-copyable; unwires in its destructor) | declared AFTER the registry in every scope, so it unwires first, including when a `REQUIRE` throws; no use of `set_metrics(nullptr)` outside the one 'no metrics wired' SECTION |
| `pg::PgPool tiny` (size 1), `ExecutionTracker`, `auto held = tiny.acquire()` | RAII locals | the tracker is constructed BEFORE the lease is held (its constructor acquires unboundedly); destruction order is lease, tracker, pool |
| `pg::PgConn locker` (ACCESS EXCLUSIVE lock) | RAII local | declared after the fixture bundle, so it closes first and releases the lock even if a `REQUIRE` fails |
| DDL lease for the dropped-table test | block-scoped `Lease` | released before the readers run; the database is an ephemeral per-test clone |
| `source_scan.hpp` cache (`comment_free_source`) | process-static `std::map`, read-only | file stream is RAII; a read failure throws a Catch exception, never returns an empty string |

## Not present in this diff

No new thread, detached work, callback that outlives its call, fd, `FILE*`, subprocess, cast, temp path, OpenSSL/BCrypt object, SQLite handle, or manual cleanup. No policy floor applies.

Sanitizers: the existing nightly ASan/UBSan tier is sufficient; TSan has nothing to observe (single-threaded tests; the registry mutex is a leaf lock with no re-entry into the pool).
