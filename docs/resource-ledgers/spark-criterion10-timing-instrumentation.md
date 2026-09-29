# Resource Ledger - #4606 latency instrumentation (`Guardian T_detect` / `T_wire` / `T_server`)

This ledger lists every lock, buffer, callback context and borrowed view the #4606 benchmark
instrumentation introduces or moves, with its owner and release path, for the C++ diff of that change
(from `a9984d565` to the branch tip). A Resource Ledger is a policy-floor artifact
(CLAUDE.md standing rule 2), so it is a standalone file rather than a line in a PR description or a
governance transcript. The Gate 1 summary of the governance run carried the first two rows; the
remaining rows were added as later fix rounds moved locks or added the shared neutraliser, and the
Gate 8 reviewers (`cpp-safety`, `security-guardian`) re-derived them independently. The
`format_arm_committed_line` row was added by the later rule-id neutralisation round of PR #4657; that
round's review findings are recorded in `governance.d/4606-criterion10-instrumentation.uvwyxL.jsonl`
(`pass_ordinal` 18).

Nothing in this change adds a file descriptor, HANDLE, SOCKET, `FILE*`, `sqlite3*`/`sqlite3_stmt*`,
OpenSSL or BCrypt object, allocated C string, mapped library, temp path, subprocess or production
thread. No callback is registered; the one existing callback context it touches keeps its capture
list. The only thread it adds is a test reader thread (last row of the agent table).

## Agent: `agents/core/src/guardian_spark_runtime.{hpp,cpp}`, `guardian_spark_timing.{hpp,cpp}`, `agent.cpp`

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `last_eval_timings_mu_` (`std::mutex`) and `last_eval_timings_` (`std::vector<EvalTimingRecord>`) | `GuardianSparkRuntime` members, non-copyable, RAII | class construction | class destruction | Leaf lock: held only across the move-assign at the tail of `evaluate_key` and the copy in `last_eval_timings_for_test()`, always through `std::lock_guard`; never nested under `registry_mu_`, `eval_mu` or any other lock; no I/O under it. The move-assign is `noexcept`, so there is no failure path. |
| `staged` (`std::vector<EvalTimingRecord>`) | Local to `evaluate_key` | `reserve(planned * 2)` before the reads (outside `registry_mu_`), populated in the `registry_mu_` commit section | Function exit, or moved into `last_eval_timings_` after the log lines are written | Owns its strings; no borrowed views. Every early return before staging leaves it empty. It is not read after the move. Allocation is the failure path: `reserve()` and the per-entry `event_id` copy run before the real `enqueue_all`, so each is inside a `try`/`catch(...)`. A `reserve()` failure is swallowed (the loop's own allocations then decide). A failure in the per-entry copy erases the failing rule's tail of `staged` (any of its entries already staged, keeping earlier rules' records; `erase` of a tail range does not allocate) and lets the enqueue and the drain-worker wake proceed: the timing lines are lost, never the event. Pinned by fault-injection tests (a `reserve()` failure, the first record, part-way through a batch, and a middle rule failing between an earlier and a later rule in the same pass). |
| `eval_lk` (`std::unique_lock` on the key's `eval_mu`; was `std::lock_guard`) | Function-scope RAII | `evaluate_key` entry | One explicit `unlock()` after the outbox waker and before any log I/O; scope exit on every earlier return | Same mutex as before, only the wrapper type and one unlock point changed. It is never re-locked, every return before the unlock releases by RAII, and nothing after the unlock touches per-key state. |
| `stream_write_mu_` scope in `send_guardian_outbox_entry` | `std::lock_guard` in an inner block | Before the stream null check | End of the inner block, before the `T_wire` log call | `return Retain` from inside the block is RAII-safe. The log runs strictly after `ok` is captured and inside `try`/`catch(...)`, so a log failure can never turn a real `Sent` into `Retain`. |
| `set_event_sink` lambda (callback context capturing `this`; existing) | `AgentImpl` | Existing | Existing | The capture list is unchanged. The body only adds a `try`/`catch(...)`-wrapped `T_wire` log after `emit_guardian_event` returns (that function now returns its `bool`). |
| `id_token` (`guardian_spark_timing.cpp`) | Pure function returning an owning `std::string` | Per call | Temporary, dies at the end of the enclosing `std::format` full-expression | Takes a `const std::string&` of a live record member; no view is stored. |
| `format_arm_committed_line` (`guardian_spark_timing.cpp`) and its call in `commit_new_generation_locked`, plus the five `::yuzu::log_id_token(...)` arguments in `guardian_spark_runtime.cpp` (late-arm, #4508 wedge-withdrawal, sweep residue, two lifecycle-capacity warnings) | Pure function returning an owning `std::string`; each `log_id_token` call returns an owning `std::string` temporary | Per call, at the arm commit (under `registry_mu_`) and at the five log sites | Temporary, dies at the end of the enclosing full-expression (the `spdlog::info("{}", ...)` call or the log call's argument list); no view is stored | Every site sits inside an existing `try { ... } catch (...) {}` (the arm-committed line inside the commit firewall, the #4508 line inside its `noexcept` function's try/catch), so an allocation failure drops the log line and never escapes. The formatter prints `unknown` for a null `type` or `via` rather than passing a null pointer to `std::format`. It takes no lock and adds a few small heap allocations per arm commit under `registry_mu_` (no cost figure is recorded). |
| Test reader thread in the `[tsan]` case of `tests/unit/test_guardian_spark_runtime.cpp` (test-only) | The test case (`std::thread`, holds `rt` and two atomics by reference) | Created before the barrier is released | Joined by the test after the writer threads are joined and `writers_done` is set | Loops on the accessor until `writers_done`; the accessor copies under `last_eval_timings_mu_`. No production code path creates it. |

## Shared header and server: `common/include/yuzu/log_token.hpp`, `server/core/src/guardian_ingest.cpp`, `guaranteed_state_store.{hpp,cpp}`, `web_utils.hpp`

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `log_token(std::string_view)` / `log_id_token(std::string_view)` | Pure header-only functions returning owning `std::string`; the `string_view` parameter is borrowed for the call only | Per call | Returned string is a temporary or a local of the caller | Allocation failure throws `bad_alloc`. The `T_server` call sits inside the existing best-effort `try`/`catch(...)` block. The replay (debug), conflict, error, oversized-detail and parse-failure lines call it outside a `try`. On the replay, conflict, error and oversized-detail lines that is the same allocation class `sanitize_label` already had (it also copied the string); the parse-failure warn previously printed the raw agent id with no copy, so it is the one line that now allocates where it did not, on an ingest thread that has no catch-all around it, alongside the unguarded `ev_row` string copies that already allocate there (OOM-only, and accepted). |
| `T_server` block (`ingest_guardian_response`) | Locals only (`std::string` temporaries, `int64_t` values) | Per Inserted, non-observation event | Block scope | No lock is held and no I/O other than the `spdlog::info` call; wrapped in `try`/`catch(...)` so it cannot escape onto the gRPC ingest thread. Runs after the outcome switch and before the observers, changes no outcome and returns nothing. |
| `EventInsertResult::committed_wall_ns` | Plain `int64_t` value member of a returned struct, in memory only | Set right after `txn.commit()` succeeds | Struct lifetime | Never persisted; `0` for every non-Inserted outcome. |
| `audit_token` forwarding to `log_token` | Inline function, no state | n/a | n/a | Behaviour is byte-identical to the body it replaced (pinned by `test_log_token.cpp` and `test_web_utils.cpp`). |

## Trigger rows and invariants this change was checked against

- Spark detection layer row: no `mtx_` is taken on a worker or callback; no mechanism `watch()`/`unwatch()` calls `emit()` or `fault()`; `spark_engine.*`, `spark_mechanism.*`, `hard_exit.hpp` and `reconcile_rule_locked()` are untouched.
- Durable command idempotency row: not triggered. The `agent.cpp` hunks are inside `send_guardian_outbox_entry` and the drift-sink lambda, not the Subscribe command loop's claim/record/release sites.
- `common/include/` firewall: `log_token.hpp` is pure decision code (no I/O, no store or wire types, no trust-boundary authority), so it needs no annotation in CLAUDE.md.
- Known and recorded, not resolved here: the log lines are written synchronously on the Spark consumer, convergence and send-worker threads, so a blocked log sink stalls whichever thread is writing. That is a flip precondition in `docs/spark-flip-gate.md` section 7, adjudicated ACCEPT-WITH-PRECONDITION by the architect Gate 8 reviewer.
