# Resource Ledger — DEX Apps tab Usage view

Range: `origin/dev..HEAD` (branch `feat/dex-usage-ui`)

## Summary

This diff adds **no thread, lock, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, handle,
cache or store read of its own**. It adds one dashboard fragment (`GET /fragments/dex/apps/usage`)
and two pure renderers. Everything the route reads goes through code that already exists and owns its
own resources: the `DexApi::apps_usage` seam (with its 30-second answer cache and read budget), the
`FleetReadFn` gate, and the `DexAuditFn` audit hook. Nothing here retains a closure beyond the request.

## Table 1 — new owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `DexAppsUsageControls` (window, platform, slice, group list) | value type (`std::string`, `std::vector<DexGroupOption>`), a local of the route handler | filled per request from the validated query and `group_list_fn_()` | handler return | passed by const reference to the two renderers | value type; a throw while filling is caught by the handler's `try`/`catch` and answers an `internal_error` panel |
| R2 | The rendered page (`std::string`) and its intermediate fragments | `std::string` locals in the pure renderers | per render | function exit | returned by value to `res.set_content` | RAII; the worst page (100 applications x 52 cells) is bounded by a 3 MiB test ceiling |
| R3 | A throwaway `httplib::Response probe` | stack local of the route handler | before the Forensics gate | handler return | lent to `fleet_read_fn_` by reference | stack unwinding; its body and status are never forwarded |
| R4 | `apps_page` (a lambda shared by the Stability route and the usage route) | `const auto` local of `DexRoutes::register_routes`, copied into each handler closure | at registration | when the sink drops the handler | none | captures `this` only; `DexRoutes` owns `dex_api_` and `apps_error_log_`, which outlive the registered handlers, exactly as the existing Apps handler's own `this` capture did |

## Borrowed state (owned elsewhere, unchanged)

| Borrowed | Owner | This diff's interaction |
|---|---|---|
| `perm_fn_`, `fleet_read_fn_`, `audit_fn_`, `group_list_fn_` | `DexRoutes` (set once at registration) | called per request, in the REST route's order; never stored |
| `dex_api_` (`std::shared_ptr<const DexApi>`) | `DexRoutes::set_dex_api` | `apps()` and `apps_usage()` are called through it; the seam's cache, budget and visible-device filter are unchanged |
| `apps_error_log_` (`RefusalLogThrottle`) | `DexRoutes` | `should_warn` with two new keys (`usage_not_wired`, `usage_internal_error`); the table is bounded by its own `max_keys` |

## Harness-only notes

The new test file uses `TestRouteSink` and in-process closures. It opens no file, store, socket or
process, and starts no thread.
