# Resource Ledger - #2540 (dashboard Echo purge and re-enable authorize through the per-device scoped gate)

Run: `2540-dashboard-echo-scoped-perm.UsCDtW`. Range `b7a9905e68152a5c3e9ebef5230fe6a70e08e46d..798257f195dd74481aa50feb6adf1a79a300b3bc` plus the governance round 1 fix that carries this file. This is the Gate 1 Resource Ledger for the C++ diff (`server/core/src/dashboard_routes.{cpp,hpp}`, `server.cpp`).

## Production code

| # | Resource | Kind and owner | Acquired | Released | Transferred or aliased | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `scoped_perm_fn_` | `DashboardRoutes::ScopedPermFn` member (`std::function`), owned by `DashboardRoutes` | `set_scoped_perm_fn` in `server.cpp`, before `register_routes` | `DashboardRoutes` destructor | none: a copy of the shared `scoped_perm_fn` lambda, which captures the `ServerImpl` `this` that owns `dashboard_routes_` and so outlives it | unset: both POSTs answer 503 and dispatch nothing |
| R2 | throwaway `httplib::Response probe` | stack local in `probe_echo_scoped_perm` | per probe | scope exit | none: the gate writes its refusal into it and it is discarded | RAII |
| R3 | `EchoScopedProbe` | stack POD (two bools) returned by value | per request | scope exit | by value | none needed |

The governance round 1 fix adds no resource: the service-scoped-token refusal on both POSTs reads `session->token_scope_service` (a member of the `std::optional<auth::Session>` local the handler already holds), writes the response and one audit row through the existing `audit_or_flag`, and returns. The recheck change only selects between two string literals for the audit detail.

## Test code (`tests/unit/server/test_dashboard_echo_fragments.cpp`, `test_dashboard_echo_retention.cpp`)

| Resource | Owner | Notes |
|---|---|---|
| `FragmentHarness` / `FrameHarness` | RAII locals, one per test case or section | the route sink is declared last, so it is destroyed first while the `DashboardRoutes` its handlers captured is still alive |
| harness lambdas capturing `this` or `&h` | the harness that registers them | every capture is of an object that outlives the route sink; `audit_persists` captures `&h` and a `std::string` by value and is destroyed with `h` |
| `RestApiV1 api` and `rest_sink` in the parity case | RAII locals | `rest_sink` is declared after `api`, so it is destroyed first; the lambdas capture locals declared before both |
| Postgres test databases | `ManagementGroupStorePg`, `YUZU_REQUIRE_PG_DB_TPL` | per-test template clones, dropped by their owners |

## Not present in this diff

No fd, HANDLE, SOCKET, `FILE*`, SQLite or OpenSSL object, thread, mutex, subprocess, detached work, callback that outlives its call, cast, temp path or manual cleanup is added. No policy floor applies to the resources above.
