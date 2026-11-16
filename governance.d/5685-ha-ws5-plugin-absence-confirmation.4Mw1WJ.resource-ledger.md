# Resource Ledger — HA WS-5 follow-up: plugin-absence confirmation

Range: `5710c9998f..HEAD` (branch `feat/ha-ws5-plugin-list-freshness`, stacked on PR #7718)

## Summary

This diff adds **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle, mapped
library or temp path**, and no raw `new`/`delete`, `release()`, `reinterpret_cast` or `const_cast` in production
code. New owned or borrowed state: two atomics, one RAII admission guard, one pool lease inside a transaction, one
borrowed `GatewayRouteStore&`, and call-scoped views. Independently re-verified by `cpp-safety` in Gate 3 and in
Gate 8 rounds 2 and 3 (no policy-floor item in any round). TSan and ASan were NOT run (finding
`fu-tsan-and-chaos-not-run-confirmation`).

## Table 1 — owned and borrowed state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `RouteSessionConfirmFn route_session_reader_` | `std::function` member of `AgentRegistry`, guarded by `missing_plugin_mu_` | `configure_route_session_reader` | rewired or cleared by the same call; `server.cpp` stop() calls `configure_route_session_reader({})` | none | `ids_missing_plugin` COPIES it out under the lock and invokes the copy with no lock held, so a rewire during a call cannot dangle the `std::function` |
| R2 | Borrowed `GatewayRouteStore&` captured by the lambda from `make_route_session_confirmer` (`plugin_absence_confirmation.hpp`) | `ServerImpl::gateway_route_store_` | at wiring in `server.cpp` | unwired in stop() immediately after the presence unwire and before `gateway_route_store_.reset()` | none | NOT a barrier for an in-flight call: safety rests on every dispatch, REST, MCP, gRPC and scheduler thread being joined before the unwire (server.cpp stop(): servers shut down, the loop threads and `web_thread_` joined first), the same discipline as the `OfflineEndpointStore*` borrow. `gateway_route_store_` is destroyed before `registry_`; the unwire is what keeps the reference from dangling. Pinned textually by `tests/test_presence_departure_wiring_lexical.py` |
| R3 | `std::atomic<int> confirms_in_flight_` | member of `AgentRegistry` | compare-exchange admission in `ids_missing_plugin` | the `InFlight` guard's destructor | none | RAII: the guard is constructed with `admitted = false` and set true only after a successful compare-exchange; every later exit (early return, exception from `subset.reserve`, the reader, `count`) releases it; a shed caller never touches the count; relaxed ordering is adequate for a pure counter |
| R4 | `InFlight` admission guard | stack RAII owner of one slot | `ids_missing_plugin` | destructor | none | exception-safe |
| R5 | `std::atomic<std::int64_t> confirm_warn_at_ms_` | member of `AgentRegistry` | initialised to -60000 | none | none | relaxed CAS rate limit, one warn a minute; a failed CAS means another thread just warned |
| R6 | Pool lease and `PgTxn` in `GatewayRouteStore::confirm_sessions` | RAII, via `pool_.with_txn_for(kReadTimeout, lambda)` | on entry | COMMIT, or ROLLBACK by the `PgTxn` destructor on a `false` return or an exception; the lease returns after | none | the lambda runs at most once, synchronously; `SET LOCAL statement_timeout = '2s'` is transaction-scoped so it cannot leak onto the pooled connection; a failed `SET` or SELECT returns an error and the registry fails open (`degraded`) |
| R7 | Two `std::vector<std::string_view>` in `confirm_sessions` | function-local | built from the caller's `std::span<const PluginAbsence>` | function exit | none | valid for the whole call; `pg::to_text_array` copies them into owned strings before `exec_params` |
| R8 | `std::span<const PluginAbsence> claims` | borrowed view in `ids_missing_plugin` | the cached `shared_ptr<const vector<PluginAbsence>>` when nothing was dropped as local, else a local `subset` vector | function exit | none | the local `remote` shared_ptr keeps the cached vector alive for the whole function; `subset` is declared before the span; the confirmer does not retain the span |
| R9 | `remote_only`, `to_withhold`, `still_remote` (`vector<const T*>`) | function-local raw pointers into `*remote` | built under `mu_` or after the read | function exit | none | `remote` outlives them; `reserve` happens before `mu_`, so no allocation or throw under the lock; `missing.insert` copies |
| R10 | `count` and `warn_limited` lambdas | local, capture `this` (a `const AgentRegistry*`) | in `ids_missing_plugin` | function exit | none | never stored; use the `MetricsRegistry&` member, whose `counter()` and `describe()` take the registry mutex (verified by a TSan harness over the metrics registry alone) |
| R11 | `PluginAbsence` (`offline_endpoint_types.hpp`), `RouteSessionConfirmFn` alias | value types | n/a | n/a | n/a | n/a |

## Test-side contexts (not production)

Reader lambdas in `tests/unit/server/test_agent_registry_presence.cpp` capture test locals (`routes`,
`confirm_stub_ids`, `directory`, `directory_reads`, `throw_on_read`, the shed test's `entered` and `release`) by
reference. They are stored in a registry that was declared first, so those locals are destroyed before it, but the
destructor never invokes the callback. The reader threads in the rewire, shed and concurrency tests are owned by a
`Joiner` struct declared after the vectors, which sets the stop flag and joins on every exit including a failed
`REQUIRE`.

## Table 2 — what is NOT introduced

No new background loop, sampler or thread (WS-10 classification unchanged). The confirmation runs inline on the
dispatching thread, takes no registry lock across its single bounded database statement, and is limited to two
in flight at a time.

## Known limits recorded elsewhere

No TSan or ASan run (`fu-tsan-and-chaos-not-run-confirmation`). Pool behaviour under concurrent dispatch plus
`register_fresh` load is not measured end to end (`r4-confirmation-cost-not-measured-end-to-end`).
