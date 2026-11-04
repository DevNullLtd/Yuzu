# Resource Ledger — agent sync scheduler: delay_max_s, maintenance window, catch-up

Range: `origin/dev..HEAD` (branch `feat/sam-19-sync-scheduler`)

## Summary

This diff introduces **no fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` / OpenSSL object / BCrypt
handle / allocated C string / mapped library / temp path / subprocess / thread**. The scheduler's
state stays in the existing `__sync__` KV keys; the window and catch-up add no persisted key. The
only new C-library calls are `localtime_r` / `localtime_s` and `mktime`, which write into
caller-owned `std::tm` values on the stack and hand back nothing to release.

## Table 1 — new owned state (all RAII value types)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `SyncSource::window` | `std::optional<SyncWindow>` (two ints) | `SyncSource` | per source, fixed at registration | Set only by `make_installed_software_source`. |
| `SyncScheduler::clock_` | `LocalClock` (two `std::function`) | `SyncScheduler` | scheduler lifetime | Defaults to `system_local_clock()`, whose lambdas capture nothing; tests inject a fake zone. |
| `pending_` entries | `std::pair<size_t, int64_t>` (was `size_t`) | `SyncScheduler` | guarded by the existing `pending_mu_` | Same single cross-thread container; drained under the same lock by `drain_pending`. |
| `tm` / `LocalTm` | stack structs | `system_local_clock` lambdas, `next_window_fire` | function-local | Value types; `mktime` normalises in place. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `pending_mu_` | `SyncScheduler` | `request_now` still takes it once, after resolving the source list without it (`sources_` is append-only and complete before publication, as before); no new lock, no change in lock order. |
| `__sync__` KV writes | `SyncScheduler::save_state` | `catch_up_if_overdue` and the delayed arm call the existing `save_state`; same keys, same write order. |
| `sync_wake_` | `Agent` | Untouched; the `__sync__` branch still sets it on SUCCESS only. |

## Tests

Test code adds only Catch2 locals (`std::map`, `std::vector`, `std::unique_ptr<SyncScheduler>`) and
lambdas capturing a test-local rig by `this`/reference. No file, process or network is opened.
