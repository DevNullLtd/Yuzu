# Resource Ledger — `5686-ha-ws5-session-read-heartbeat-obs.kAKFQC`

Every owning boundary the C++ in `origin/dev..HEAD` (branch `feat/ha-ws5-session-read-and-heartbeat-obs`; nine commits
`0a04dc173` #5684, `ad9168d0f` #5686, `f7a8f6b82` probe, `156824bc4` reconciler tests, `d36c3371d` + `b6ac026b2` docs/HELP,
`529a67dc3` ledger, `79ea64780` F1 (probe starts right after the first failure), `683ed5dee` F1 polish (governed HEAD of this update);
merge-base `6608fcea7`) acquires. Required by the Gate 1 contract on any C++ diff. The author's Gate 1 ledger was
independently re-proved by `security-guardian`, `cpp-safety` (Gate 2/3) and again at Gate 8 on the fix commits.

The diff acquires no raw fd, HANDLE, SOCKET, `FILE*`, `sqlite3*`/statement, OpenSSL or BCrypt object, allocated C string,
mapped library, subprocess or temp path, adds no production thread, no mutex or other lock, no detached work, no cast, no
manual (non-RAII) cleanup and no shell-out. What it does own or borrow:

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| `AgentRegistry::mu_` taken inside `session_is()` / `session_id_of()` / `get_session()` at the three reconciler sites (churn check, confirm-time capture, pre-dispatch capture) | `std::lock_guard` inside the accessor | accessor entry | accessor return | none; `session_id_of` returns a COPY of the id (`std::string` by value), `session_is` a bool | RAII; no early-return leak. Lock order reconciler `mu_` -> registry `mu_` pre-exists at the churn site; the two capture calls run outside the reconciler `mu_` |
| `dispatch_session_id` / `confirmed_session_id` (`std::string` locals) | the `reconcile_one` frame | `session_id_of(agent_id)` immediately BEFORE `dispatch_fn` / at confirm | frame exit; copied into `st.pending_session_id` under the reconciler `mu_` | by value | none needed |
| temporary `std::shared_ptr<AgentSession>` from `get_session(...)` in the churn condition | full-expression temporary | `get_session` | end of the full expression (boolean test only) | none | RAII |
| `HeartbeatIngestion::PresenceBatch presence_batch` (`bool store_failed; size_t skipped, failed, skips_since_fail, next_probe; static constexpr kMaxProbeSpacing`) | stack local in `GatewayUpstreamServiceImpl::BatchHeartbeat`, one per RPC invocation | start of the entry loop | handler return | lent by RAW POINTER to each synchronous `ingest()` call; never stored, never shared across threads or RPCs | stack unwinding; an `ingest()` exception is caught per entry and the state stays consistent |
| `std::chrono::steady_clock::time_point started` | `BatchHeartbeat` frame | after `onbehalf::enforce` | handler return | value | none |
| `metrics_->histogram(...)` / `counter(...)` references | `MetricsRegistry` (node-based families; references stable) | used inside one full-expression | not retained | none | none |
| `warn_slot_due`'s function-static `std::array<std::atomic<std::int64_t>, kWarnSlotKeys.size()+1>` (10 -> 11 slots; new key `presence_upsert_skipped` takes old shared slot 9, unlisted keys share slot 10) | static storage duration, relaxed CAS | first call | process exit | none | n/a |
| `onbehalf::sanitize_for_log(request->gateway_node(), 64)` temporary `std::string` in the new WARN | full-expression temporary | WARN call | end of statement | by value | RAII |
| Reconciler test: `std::thread writer` + `std::atomic<bool> stop_writer` + local `JoinGuard` (replaces `std::jthread`; Apple libc++ has none) | `JoinGuard` (reference-holding, non-copyable); it raises the flag with release ordering then joins if joinable | thread construction | guard destructor on any exit incl. REQUIRE unwind, or the explicit stop+join on the normal path (the guard then sees a non-joinable thread) | none | captures `registry` and the `std::latch` by reference, both declared before the thread; the writer holds no Catch2 assertion and only calls `AgentRegistry::map_session`; `std::this_thread::yield()` in the loop |
| Reconciler test: injected `Deps::now_fn` clock (`[&clock]` lambda, strictly increasing) | the test body | test start | test exit | none | feeds only the confirmed/applied stamps, not backoff or claim timing (those use `steady_clock`); invoked only from the single-threaded `tick()` |
| Reconciler test: `MockDispatch::on_dispatch` wrappers (`[&, respond = dispatch.on_dispatch]`) and the swap-test `map_session("session-B")` call | the test body | before the tick loop | test exit | init-capture COPIES the previous `std::function` before assignment (no self-recursion) | captured references (`dispatch`, `swapped`, `registry`, `rstore`) outlive the lambda; declaration order reconciler last -> destroyed first |
| `PgPool::Lease held` (size-1 pool) in the heartbeat-ingestion and wiring tests (batch skip, probe schedule, mid-batch recovery, last-entry failure, N=40 saturation bound) | the test body / SECTION | `pool.acquire()` | scope end, or an explicit release between `ingest()` calls in the recovery test | RAII move-only | declared after the pool and store so it is destroyed first; each SECTION re-run re-acquires |
| Postgres test databases from `YUZU_REQUIRE_PG_DB_TPL` (`qdb`, `rdb`, `db`, `offline_tpl`, `gwroutewiring_tpl`, `quarantine_recon_tpl`, `responsestore_recon_tpl`): per-test cloned `PostgresTestDb` | the macro-declared fixture | test start | test end (RAII drop of the clone) | none | same fixtures as sibling tests; names use the `yuzu_test_` prefix, salted per test |
| `metrics.serialize()` string in the pre-seed/HELP test | local `std::string` | call | scope end | by value | RAII |
| Lifetime coupling in the wiring test: `presence_pool` -> `offline` -> `ingestion` -> `f.svc` (holds a raw `HeartbeatIngestion*`) | the test body, declared in that order so destroyed in reverse | construction | scope end | raw pointer lent to `svc`, not dereferenced after `ingestion` is gone (`GatewayUpstreamServiceImpl` has no destructor that calls it) | same pattern as the existing WS-5 wiring tests |
| `metrics` / `store.set_metrics(&metrics)` in `test_heartbeat_ingestion.cpp` | the test body; `metrics` now declared BEFORE `store` | construction | scope end | raw pointer lent to the store | store no longer outlives the registry it borrows (cs-3) |

**No manual cleanup in new C++.** **Portability.** After the fix commits the tree has no `std::jthread`, `std::stop_token` or
`<stop_token>` in added lines (policy floor `g3-cx-F1-jthread-test-macos`); a green macOS CI leg on the pushed commit is
still to be observed.

**Evidence (author fix agents, Linux, own build dir `/tmp/prA-govfix-build`, Postgres `:5433`):** `[reconciler]` 32 cases /
452 assertions, `[quarantine]` 116 cases, `[heartbeat_ingestion]` 14 / 95, `[gateway_route_wiring]` 70 / 1708, `*#5686*`
3 / 117, `*#5684*` 3 / 172 — re-run by the orchestrator at `b6ac026b2` (docs-only after `d36c3371d`). Mutation (fix agent,
not committed): moving the `dispatch_session_id` capture after `dispatch_fn` makes the new session-swap test fail; file
restored. Independent TSan evidence (author, before the fix commits): old reconciler `:600` race reported, fixed code
clean in 3 runs; per-site TSan sensitivity for `:215`/`:434` is NOT evidenced.

**F1 update (commits `79ea64780`, `683ed5dee`).** No new resource class. Changes: `PresenceBatch::next_probe` is now set to `1` on the
first failure of a streak (`was_tripped ? std::min(next_probe*2, kMaxProbeSpacing) : 1`, both arms `size_t`; the cap keeps the
multiply <= 2^17, no wrap), so attempts land on entries 1,2,4,8,16,... (`floor(log2 N)+1` per saturated batch); the batch is
still a per-RPC stack aggregate lent by raw pointer. New test locals are values only: a `std::vector<int>` of 1-based entry
indices at which `batch.failed` increments (sequence test) and `PgPool::Lease` holds scoped to inner blocks in the isolated-failure
and recovery tests (released before the probe; declared after pool and store as before). The 3-entry test gained a
`next_probe == 2` check. Mutation evidence (scratch copy of the tree at `/tmp/prA-f1-mut-src`, old failure arm, new tests kept):
5 tests fail, so the new tests discriminate F1. Real-tree results at `683ed5dee`: `[heartbeat_ingestion]` 16 cases / 121
assertions, `[gateway_route_wiring]` 70 / 1708, `*#5686*` 3 / 117, `*#5684*` 3 / 146, `[reconciler]` 32 / 452.
