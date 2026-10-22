# Resource Ledger - `6062-bound-approval-primitive.2rfT8G`

Every owning boundary the C++ in `16934bebe..HEAD` (`feat/6062-bound-approval-primitive`,
issue #6062, epic #6060, four-eyes MVP PR2) acquires or hands off. Required by the Gate 1
contract on any C++ diff; recorded here rather than only in a run narrative so a later reader
can check it against the code. Written at HEAD `3db8d88b5` (31 C++/JS files, 4865 insertions,
209 deletions by `git diff 16934bebe..HEAD --stat -- '*.cpp' '*.hpp' '*.js'`) after Gate 4 of
the round-4 re-verify reported that no Resource Ledger covered the fix-round diff
(`g8r4-cs-2`, a candidate policy floor).

**Provenance, stated plainly.** Authored by the fix agent from the diff and the code at the
HEAD above. It is NOT independent of the author of the change, and it records what was READ and
what was RUN; anything not run is marked UNVERIFIED in the last column and in the closing
section. Attestation is for the maintainer to record in the run ledger.

**Scope.** Production C++: `approval_manager.{hpp,cpp}`, `approval_model.{hpp,cpp}`,
`approval_routes.cpp`, `approvals_fragment_routes.cpp`, `approvals_page_render.{hpp,cpp}`,
`approvals_ui.cpp`, `approval_denial_audit.hpp`, `reserved_definition_id.hpp`, `server.cpp`
(wiring and HELP text), `mcp_server.cpp` and `rest_api_v1.cpp` (schema and description text
only), `instruction_{store,yaml}.cpp` (comments only). Front end: `yuzu-operate.js`. Tests: the
files under `tests/unit/server/` listed in the test rows.

**Summary.** The diff acquires NO new raw fd, HANDLE, SOCKET or `FILE*`; no `sqlite3*`; no
OpenSSL or BCrypt object that outlives a call (the one OpenSSL use is the existing one-shot
`EVP_Digest` over a stack buffer, `sha256_hex.hpp`); no allocated C string; no mapped library;
no subprocess; no production thread; no new production mutex; no advisory lock (none appears in
`approval_manager.cpp`). Its resource-class content is: Postgres pool leases and a borrowed
`PGconn*`, a Postgres row lock held by the caller's transaction, `pg::PgResult` RAII, three
callback-bearing `std::function` members, three function-local static throttles, and, in tests
only, one `std::thread`, temp directories, file streams and a swapped spdlog default logger.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup | Verification |
|---|---|---|---|---|---|---|
| Pooled-consume read lease (`get_checked`: `pool_.try_acquire_for(kReadTimeout)`, 1500 ms) | local `pg::PgPool::Lease` inside `get_checked`, one per read (the first read, and the precondition's fresher read) | top of `get_checked` (`approval_manager.cpp`, the `try_acquire_for(kReadTimeout)` in the checked-read function) | RAII at the end of `get_checked`, BEFORE it returns to `consume_core` - so no lease is held while the precondition callback or the consume test hook runs on the pooled path | none (the row is copied out as an `Approval` value) | early returns and exceptions unwind the lease; an exhausted pool is a `kStoreError` with `binding_check_unevaluated=true` on the first read | READ; pooled-read-fault test exists (`test_approval_manager.cpp`); no sanitizer run by me |
| Pooled-consume write lease (CAS and diagnostic read: `pool_.try_acquire_for(kWriteTimeout)`, 2000 ms) | local `pg::PgPool::Lease lease` in `consume_core` | after every check has passed and after the `kBeforeCas` hook, so the hook (a second lease in tests) never runs under it | RAII at function exit; held across the CAS and the one diagnostic read | none | lease failure returns `kStoreError` "temporarily unavailable"; every later return path destroys it; the ticket is untouched if the CAS did not match | READ and RUN (pool-exhaustion text paths in unit tests); lost-acknowledgement behaviour (CAS committed, response lost) is NOT claimed handled: ADR-1009 `up-9` |
| Borrowed `PGconn*` (held overload `consume_ticket(PGconn*, ...)`) | the CALLER owns the connection and its transaction; `ApprovalManager` only borrows it for the call | passed in by the caller | never released or stored by this code; no member holds it; the null pointer is refused (`kStoreError`) so it cannot degrade into the pooled overload | none | on any `kStoreError` the caller's transaction is aborted by Postgres and the caller must roll back (documented on the declaration) | READ and RUN (held-overload tests incl. an aborted-transaction read fault); no production caller exists (tripwire) |
| Postgres row lock (`SELECT ... FOR UPDATE` in `read_row`, held overload) | the CALLER's transaction | taken by the first read and again by the precondition's read | released by the caller's COMMIT or ROLLBACK, NOT by this code; lives across the precondition callback and across the denial observer | none | rollback releases it; on an AUTOCOMMIT connection the lock drops after each statement, so the explicit-column and row-version pins are what hold (ADR-1009 `cs-3`: `PQTRANS_INTRANS` refusal deferred to PR3) | RUN (lock probes via a second connection, SQLSTATE 55P03; autocommit race cells) |
| `pg::PgResult` locals (every query in the new and changed paths, incl. `PQresultErrorField` for SQLSTATE) | stack-local RAII wrapper | `pg::exec_params` | destructor on every path | `result_sqlstate`/column values are copied into `std::string` before the result dies; no pointer into a result escapes | n/a | READ; not run under a sanitizer by me |
| Denial observer (`PreconditionDenialObserver`, a `std::function` member, `approval_manager.hpp`) | `ApprovalManager` member | set once at startup, `server.cpp:6519`, as `make_precondition_denial_audit_observer([this]{ return audit_store_.get(); })`, capturing `ServerImpl*` by value | destroyed with the manager | none | exceptions from the observer are caught and logged in `consume_core`; the observer calls `AuditStore::log`, which takes its OWN pool lease (`kWriteTimeout` 4000 ms) - on the HELD overload that is a second lease taken while the caller holds a connection and a row lock (ADR-1009 `sg-4`, deferred, not fixed) | READ; observer-throws test RUN; `this` outlives the manager by teardown order: `approval_manager_.reset()` (`server.cpp:10594`) precedes `audit_store_.reset()` (`:11214`) and `audit_store_` is declared before `approval_manager_` (`:22208` vs `:22239`); a consume still in flight from another thread during `stop()` is UNVERIFIED |
| Consume test hook (`std::function<void(ConsumeTestStage)> consume_test_hook_`, test seam) | `ApprovalManager` member | `set_consume_test_hook_for_test`, public, tests only | destroyed with the manager | none | set ONCE before any consume and read without a lock (the `denial_observer_` / `ApiTokenStore::test_hook_*` convention); setting it while a consume runs is a data race and is documented as forbidden; the hook is not exception-guarded; the test hooks capture `&bundle` and run SQL on a second pool lease | READ; the tripwire test fails if the setter is used in production code; on the held overload the hook runs under the row lock, so tests only interleave over an autocommit connection (a second-lease UPDATE would wait on the lock); NOT run under TSan |
| `RefusalLogThrottle` statics (3): `approvals_fragment_routes.cpp` (`state_unapprovable`), `approval_manager.cpp` diagnostic pin-mismatch warning, `approval_manager.cpp` integrity error line (in the `integrity_refusal` lambda) | function-local `static`, program lifetime | first call (thread-safe magic static) | static destruction at process exit | none | internally locked (`std::mutex`); at most 1024 keys of 8- to 11-character id prefixes (`id[0:8]`, with `...` appended by `redact_id` in the two consume-side ones); a full table demotes a NEW key to debug for the window (a documented loss of a first-sighting warning); a log call during static destruction would touch a destroyed throttle - UNVERIFIED (request threads are expected to be joined before exit) | READ; page-side throttle has a test (`one warning for three renders`); the two consume-side ones are untested |
| Request-id prefixes in logs | n/a (string handling) | `redact_id` | n/a | n/a | the full id is a bearer capability; every new log line carries the 8-character prefix only | READ; one test asserts the full id is absent from the page warning |
| One-shot digest (`sha256_hex`, `EVP_Digest`) | stack buffers in the helper | per call | n/a | n/a | returns `nullopt` on failure, treated as unevaluated/refused, never as a pass | READ; helper pre-dates the diff |
| JSON parse and dump of the stored request (`nlohmann::json`) | local values | per call | RAII | none | bounded first: `bound_request_is_readable` checks size and a lexical depth scan BEFORE any parse, and the summary and `approval_row_json` only dump a request that passed it (recursion in `nests_deeper_than` is capped at depth 17); the stack property for an 8192-deep input is NOT observable by any unit test | READ; ASan/UBSan fuzz of the lexical scanner and renderer was run by Gate 3/4 reviewers on scratch harnesses, not by me |
| `JoinGuard` + `std::thread consumer` (test: lock-race leg) | the test body (`test_approval_manager_bound.cpp`) | `std::thread consumer([&]{ ... consume_ticket(...) })` while a writer holds an uncommitted UPDATE | `JoinGuard` destructor: first `ROLLBACK` on the writer's lease (the consumer is parked on its lock), then `join()`; the explicit `join()` on the happy path leaves it unjoinable | none | a failing `REQUIRE` unwinds through the guard (declared after the thread, destroyed first); a throwing release callback is swallowed and the thread is still joined; no `std::jthread` (Apple Clang 15) | RUN: Gate 3 forced a failing REQUIRE after the consumer parked (ordinary Catch2 failure, no terminate) and reported a TSan-clean copy; real-PG TSan run NOT done |
| `yuzu::test::TempDir` (tripwire test, temp copy of `server.cpp` and synthetic files) | the test body | `TempDir("yuzu_test_tripwire_")` | RAII `remove_all` | none | salted with the repo's `unique_temp_path`, `yuzu_test_` prefix; the real tree is never written | RUN |
| `std::ifstream` file reads (tripwire test; the two server.cpp wiring pins) | locals | per file, binary | RAII | none | an unopenable file fails the test (`REQUIRE(in.is_open())`) instead of being skipped | RUN |
| spdlog default logger swap (`yuzu::test::LogCapture`, page-warning throttle test) | test-local RAII | constructor | `stop()` / destructor restore the previous logger and level | none | works because the store and routes are compiled into the test binary; read after `stop()` | RUN |
| Second-lease helpers in tests (`probe_row_lock`, `interleave` hook SQL, `rewrite_column`, `run_sql`, `in_txn`) | test-local `Lease` | per call | RAII; `in_txn` rolls back if its body throws | none | pool size 4 in the fixture; no test holds more than three leases | RUN |

**Adjudications recorded:** none required - no manual (non-RAII) cleanup was added anywhere in
this diff.

**Not acquired, stated so the absence is checkable.** No new thread, mutex, condition
variable, atomic, socket, fd, `FILE*`, subprocess, `dlopen`, temp path in production code, and
no advisory lock. `ApprovalManager::mtx_` (pre-existing) is still held across the mint
transaction in `submit_impl`, including the expiry sweep: a row-locked sweep stalls other mints
(ADR-1009 `up-3`, deferred); this diff only moved argument validation ahead of it.

**Sanitizer, toolchain and platform coverage - UNVERIFIED by me.** No ASan/UBSan/TSan run of
the Postgres-backed tests was done by the author of this ledger; reviewers ran scratch
harnesses over the renderer, the lexical scanner and the join guard (reported in the Gate 3 and
Gate 4 reviewer notes), not the full suite. MSVC and
Apple Clang were not run: the code uses no POSIX-only calls, designated initialisers or
`std::jthread`, which is an argument, not evidence. The three SAML ACS test cases that skip
unconditionally are unrelated to this diff.
