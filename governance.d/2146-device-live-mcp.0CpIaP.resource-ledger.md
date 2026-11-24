# Resource Ledger: per-device live read, the get_device_live MCP twin and the REST route rework (#2146)

Range: `5283238fc56b2e68062920bfad5dec8bde412d39..9ad2654d3b57d19f1e8c60fd0f9f84229f519d6d` (branch `feat/device-live-twin-mcp`)

Recorded by: Claude Sonnet 5.5 (orchestrator), reviewed by cpp-safety at Gate 3 and Gate 8 (two rounds)

## Summary

This diff introduces **no subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle,
mapped library or temp path, and no `new`/`delete`, `malloc` or cast** in production code (the
added lines were grepped at Gate 1 and again at both Gate 8 rounds). It adds no thread to the
server. Its owned state is: one admission lease per live read, one RAII gauge publisher, a handful of
stack locals, three `std::function` members that capture the server `this`, and one pure poll loop
that sleeps on the httplib worker thread that is already serving the request. The only threads in
the diff are in test code and are joined by a scope guard.

## Table 1: new owned state

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `kLiveRead` admission lease | `StreamBudget::Lease` (move-only, idempotent `release()`) inside `LiveAdmission` (`live_admission.hpp`) | the REST route, the MCP handler and the quarantine release confirm wait, one each per call | one request | The only `kLiveRead` acquire site is `admit_live_read`. It checks the drain flag before the lease and again after it, and gives the lease back on a refusal. Released on every return and every throw by scope exit. Caps: 2 per principal, 4 across callers, plus the global held-open cap. |
| `LiveGaugeMirror` | RAII publisher of `active_for_surface(kLiveRead)` (`live_gauge_mirror.hpp`) | handler stack frame (REST, MCP, quarantine confirm) | one request | Declared before the lease at every site, so the lease is returned first and the gauge then publishes the lower count. Copy and move deleted; `publish()` is `noexcept`; tolerates a null budget or gauge. The maintenance tick also refreshes the gauge and boot sets it to 0. |
| `should_stop` predicate | `std::function<bool()>` capturing the `StreamBudget*` | the poll call | one `poll_live_output` call | Reads `closing()` only (never the drain flag). The budget outlives the handlers: `stop()` joins the web thread before any member is destroyed. |
| `RestApiV1` draining function | `std::function` set by `set_draining_fn`, capturing `ServerImpl` `this` | `RestApiV1` | server lifetime | Wired in `server.cpp` before `register_routes()`. Same lifetime rule as the existing `draining_fn_` and `scoped_perm_fn`; pinned by a lexical test. |
| `McpServer` typed scoped-gate function | `std::function` set by `set_scoped_gate_fn`, capturing `this` | `McpServer` | server lifetime | The same lambda the REST route uses. Unset fails closed to `gate_unreadable`. Pinned by a lexical test. |
| Poll limits, injectable clock and sleep | `LivePollLimits` aggregate (`max_polls`, `interval`, 25 s steady-clock `deadline`, `max_output_bytes`, `over_cap`) and `LiveClockFn` | the poll call | one call | Values only. `kLiveReadIncompleteRetryMs` (25000) is `static_assert`-pinned to the deadline. The poll holds no lock across its sleep. |
| Poll and render locals | `std::vector<StoredResponse>` rows, joined `std::string` (cap 4 MiB REST, 1 MiB MCP), `ordered_json` tree (at most 20000 rows on REST, 1000 on MCP) | handler stack frame | one request | Bounded by the caps. `query_bounded` stops reading at the byte cap. Borrowed views (`reason`, `detail`) come from static literals or locals that outlive the full expression; `utf8_clamp_prefix` returns a view that is copied into a `std::string` before its source dies. |
| Pre-seeded counters and gauge | 186 `yuzu_server_live_requests_total` series plus one gauge | the metrics registry | server lifetime | Created at boot from the closed `kAllLiveSurfaces`, `kAllKindLabels` and `kAllLiveOutcomes` sets (2 x 3 x 31). Bounded cardinality. |

## Table 2: pre-existing resources touched without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `StreamBudget` and its mutex | `ServerImpl` (`stream_budget_`) | One new surface (`kLiveRead`) and a surface-wide cap evaluated under the same mutex as the global and per-principal caps. `try_acquire` allocates before it counts, so a throw cannot leak a slot. |
| Shutdown drain | `ServerImpl::stop()` | `keep_draining_for_work` gains a required `live_reads` argument (no default). The drain waits for `kLiveRead` leases within the existing 30 s cap; `begin_closing()` then makes any remaining poll answer `shutting_down` within about one interval plus one store read. Verified by cpp-safety and sre: a live poll cannot reach the 15 s `_Exit`, and a leaked lease costs at most the cap. |
| `ResponseStore` reads | the response store | `query_bounded` scoped by `agent_id` in SQL with `ResponseTierFilter::for_fixed_plugin_poll`; there are still exactly four `unrestricted_internal_consumer()` sites. Rows persist for `response_retention_days`. |
| Audit writers | `AuthRoutes` / `ToolDeps` | Rows are written as the original session (`audit_as_session`). The `requested` row stays fail-closed (REST 503 plus `Sec-Audit-Failed`, MCP internal error). A throwing sink is caught and counted as a lost row. |
| `/api/v1/quarantine` release confirm wait | `RestApiV1` | Now leases `kLiveRead` through `admit_live_read`; a refused or draining admission skips the wait and the reconciler finishes the release. Containment semantics unchanged. |
| Dispatch | `command_dispatch_fn` / `DispatchCaller` | Dispatches as the caller with `approval_provenance = None`; no new `DispatchCaller` reconstruction site. The REST route now refuses a second resolution that is a different principal than the first. |

## Tests

Test code adds Catch2 locals and fakes only. The N-thread admission tests in `test_mcp_stream.cpp`
create `std::thread` workers coordinated by `std::atomic<bool>` flags, with no sleeps and no Catch2
macro on a worker; a stack `Joiner` guard sets the release flags and joins on every path including a
throwing `emplace_back`. The `[pg]` tests use the standard `YUZU_REQUIRE_PG_DB_TPL` fixtures (one
hand-expanded copy of that skip pattern is noted in the quality-engineer report). No real file,
process or socket is opened. Suggested sanitizer coverage: ASan/UBSan over the live, MCP and REST
suites, and a targeted TSan run of the two concurrent-admission tests and the shutdown REST tests.

## Fix rounds after the adversarial review

Range: `eac55cbedb..3893161b04` (commits `ac3aa7f364`, `b3c70749c2`, `4c8eb0c1ce`, `f726c8e194`, `3893161b04`). Recorded by:
Claude Sonnet 5.5 (orchestrator); cpp-safety reviewed round 1 at Gate 3 and rounds 2, 3 and 4 at Gate 8. This section supersedes the
header range above and the two statements below that the fix rounds made stale; nothing else in this ledger changed.

**No new owned resource in any of the five commits**: no fd, HANDLE, SOCKET, `FILE*`, `sqlite3*`, OpenSSL or BCrypt object,
allocated C string, mapped library, temp path, subprocess, callback context or thread; no manual cleanup, no cast, no
manual-cleanup exception (so no `adjudicated_by`). The added code is:

| Item | Type | Owner and lifetime |
|---|---|---|
| `ResponseQuery::order_by_id` | `bool`, default false, honoured only by `query_bounded` | a field of the caller's stack `ResponseQuery`; the live poll sets it on its own local |
| `rank` / `out_rank` in `query_bounded` | two `const char* const` pointing at string literals | static storage, used inside the `resp_read` lambda while the SQL `std::string` is built (the `+` chain copies); never stored |
| `live_read_timeout_retry_ms`, `live_read_incomplete_retry_ms` | `[[nodiscard]] inline constexpr ... noexcept` over `std::string_view`, returning `std::int64_t` | the view is only compared, never stored; both call sites pass a handler-local `std::string kind` that outlives the call |
| REST null-Forensics-set refusal | one added `|| forensics_plugins == nullptr` term | a pointer the route lambda already captured by value at registration; takes no lease and writes no audit row (it sits before admission) |
| Tests | Catch2 locals, `PostgresTestDb` then `PgPool` then `ResponseStore` (reverse-order RAII), `AtomicSave` (non-copyable, restores the poll atomics on every exit path), one `RestGsHarness` constructor flag, one pure-Python lexical gate with no subprocess or network | scope-exit |

Statements in the sections above that this change set made stale (kept for the record, not edited):
the header range ends at `9ad2654d3b`; Table 2's `ResponseStore` reads row omits that `query_bounded` now ranks by `id DESC` when the
live poll sets `order_by_id` (the scope clause, the `ResponseTierFilter::for_fixed_plugin_poll` tier clause and the four
`unrestricted_internal_consumer()` sites are unchanged); and "cpp-safety at Gate 3 and Gate 8 (two rounds)" and "grepped at Gate 1
and both Gate 8 rounds" now read as five rounds (the mechanical trigger grep was repeated on every fix commit).

Suggested sanitizer coverage: unchanged (no lifetime or threading surface was added). The Postgres-backed tests ran in the
scoped suite with `YUZU_TEST_POSTGRES_DSN` set (4934 cases, 438572 assertions, exit 0, on the tip tree).
