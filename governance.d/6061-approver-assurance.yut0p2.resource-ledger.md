# Resource Ledger — `6061-approver-assurance.yut0p2`

Every owning boundary the C++ in `f661391fc..HEAD` (`feat/6061-approver-assurance`,
issue #6061, epic #6060, four-eyes MVP PR1) acquires or touches. Required by the
Gate 1 contract on any C++ diff; recorded here rather than only in the run narrative
so a later reader can check it against the code.

**Provenance, stated plainly.** This ledger was written retroactively, after the
round-8 ledger pass left one open policy-floor candidate (`R8-CS-1`, a Resource
Ledger omission on a C++ diff): cpp-safety found no Resource Ledger file for the PR
in the repo. The first-run Gate 1 ledger was session-held (in the orchestrating
session's narrative) and is NOT in the repo. This file is authored by the
orchestrating session from the actual diff (`git diff f661391fc HEAD -- '*.cpp'
'*.hpp'`: 16 files, 1981 insertions, 314 deletions). It is NOT independent of the
author of the change. Attestation is by the maintainer (see the `R8-CS-1` row in
`governance.d/6061-approver-assurance.yut0p2.jsonl`).

**Scope of the C++ delta.** Production C++ (10 files): `approval_manager.{cpp,hpp}`,
`approver_assurance.hpp` (new), `approval_routes.{cpp,hpp}`,
`approvals_fragment_routes.cpp`, `mcp_orientation.cpp`, `mcp_server.cpp`,
`schedule_runner.cpp`, `server.cpp`. Test C++ (6 files): `test_approval_manager.cpp`,
`test_approval_routes.cpp`, `test_approvals_fragment_routes.cpp`,
`test_instruction_extras_ui.cpp`, `test_mcp_server.cpp`, `test_schedule_runner.cpp`.
The only C++ delta after the first governance run's `fb1075ab8` is
`tests/unit/server/test_instruction_extras_ui.cpp` (36 inserted lines, verified with
`git diff fb1075ab8 HEAD --stat -- '*.cpp' '*.hpp'`).

**Summary.** The diff acquires NO new raw fd / HANDLE / SOCKET / `FILE*`, no
`sqlite3*` / `sqlite3_stmt*`, no OpenSSL or BCrypt object, no allocated C string, no
mapped library, no subprocess, no new thread, and no new mutex. Every Postgres
interaction in production code goes through the existing `PgPool` lease /
`with_txn_for` and `pg::exec_params` / `pg::PgResult` APIs; production code in the
diff calls no `PQconnectdb`, `PQexec`, `PQclear` or `PQfinish` (checked with `git
diff f661391fc HEAD -- server/core/src/approval_manager.cpp` for those tokens; the
only `PGconn*` mention is the pre-existing `with_txn_for` lambda parameter in
`submit()`). Test code acquires one raw connection (`PQconnectdb` in
`test_schedule_runner.cpp`) wrapped immediately in `pg::PgConn`.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| Postgres write transaction in `ApprovalManager::submit()` (`PGconn*` passed to the lambda) | `PgPool::with_txn_for` (pre-existing); the lambda borrows `PGconn* conn` for the call only | `pool_.with_txn_for(kWriteTimeout, ...)` (`approval_manager.cpp` ~432); the diff changes only the SQL text inside the lambda (sweeps now compare against `EXTRACT(EPOCH FROM now())` in-SQL; the insert takes `submitted_at` as a parameter) | `with_txn_for` commits or rolls back and returns the connection to the pool when the lambda returns | none; the lambda stores no `conn` | each early `return false` inside the lambda (a non-`TUPLES_OK` sweep, the cap check, the insert) rolls the transaction back via `with_txn_for`. New code adds no manual `ROLLBACK` / `PQexec` |
| Postgres `Lease` in `consume_ticket()` (the CAS plus the new diagnostic read) | `PgPool::Lease` (RAII, `pg_pool.hpp`), local | `pool_.try_acquire_for(...)` (pre-existing acquisition); the diff adds a second `pg::exec_params` (the `why_sql` read) on the SAME lease | `Lease::~Lease` / `reset()` at function exit | none | the diagnostic read is read-only; a failed or odd result degrades to the generic `kNotConsumable` and returns, with the lease still released by RAII. The `PgResult res` of the CAS stays alive while `why` is created, which is fine because each `PgResult` owns its own `PGresult*` |
| Postgres `Lease` in the new `ApprovalManager::ticket_is_live()` | `PgPool::Lease`, local | `pool_.try_acquire_for(kReadTimeout)`; a failed acquire returns `std::unexpected` | scope exit (RAII) | none | a non-`TUPLES_OK` result logs and returns `std::unexpected`; lease released by RAII. `ScheduleRunner` treats that as "hold the occurrence", never as "dead ticket" |
| Postgres `Lease` in `set_review_status()` | `PgPool::Lease`, local (pre-existing acquisition) | unchanged; the diff moves `reviewed_at` into the SQL (`kDbNowEpochSql`) and drops one bind parameter | scope exit (RAII) | none | unchanged |
| `pg::PgResult` values (`exp`, `expa`, `ins`, `res`, `why`, and the `ticket_is_live` result) | each is a local `pg::PgResult` (RAII, `PQclear` in the destructor, `pg_raii.hpp`) | each `pg::exec_params(...)` call | end of enclosing scope | none | RAII on every path, including the early returns. The SQL text is held in local `std::string`s (`sweep_pending_sql`, `sweep_approved_sql`, `insert_sql`, `consume_sql`, `why_sql`, `review_sql`, `sql`) that outlive the `exec_params` call that takes `.c_str()`; `exec_params` is synchronous, so the pointer is not retained |
| SQL text assembled from constants (`ticket_live_sql()`, `kDbNowEpochSql`, `kApprovalTicketTtlSeconds`, `kApprovalReviewedAtSlackSeconds`) | by-value `std::string` return / `constexpr` | `ticket_live_sql()` is called per statement | n/a (value type) | n/a | n/a. Only integer constants are interpolated; every caller-supplied value (`id`, `consumed_by`, `comment`, `status`, `reviewer`) remains a bound `$n` parameter |
| `WriteGate write_gate` and its lambda in `handle_review()` (`approval_routes.cpp`) | local `const WriteGate` in the handler's stack frame. Members: `std::function resolve_session` (holding the lambda) and `std::vector<std::string> trusted_origins` (a COPY of `deps.csrf_trusted_origins`) | constructed after the `perm_fn` gate and the `resolve_session_fn` call | destroyed on handler return | none; `refuse_cross_site` is `const`, synchronous and not stored | **Lifetime reasoning for the by-reference capture.** The lambda `[&session](const httplib::Request&) { return session; }` captures the local `std::optional<auth::Session> session` by reference. `session` is declared before `write_gate`, so it is destroyed AFTER it (reverse declaration order). `write_gate` is used only for the synchronous `refuse_cross_site(...)` call on the same stack frame; it is never copied into `Deps`, never moved out and never handed to a thread or deferred task. The lambda returns `session` by value (a copy), so `refuse_cross_site` never holds a reference into it. Nothing outlives the handler frame |
| `Deps` copy captured by the route lambdas (`[deps]`, `register_approval_routes`) and the new `Deps::step_up_fn` (`StepUpFn`, a `std::function`) / `Deps::csrf_trusted_origins` (`std::vector<std::string>`) members | the registered handler lambda owns its by-value copy of `Deps` (pre-existing pattern); `handle_review(const Deps&, ...)` borrows a reference to that copy for the call | registration time | when the sink drops the handler | `std::function` and `vector` members are copied with the `Deps` | the handler only reads through the reference. `deps.approval_manager` stays a raw non-owning pointer (pre-existing), so the pointee must outlive the web server; see the `step_up_fn` row |
| `step_up_fn` closure in `server.cpp` (`[this]`, captures `ServerImpl*`; the inner audit lambda also captures `this`) | `ServerImpl` local, then copied into the `Deps` for the approval routes, `SettingsRoutes` and `RestApiV1` | the closure body is MOVED verbatim from further down the same function to above the Approval routes' registration (no new capture, no new logic) | copies die with the handlers | `std::function` copy per consumer | lifetime of `this` relative to handler threads: the diff does not change it, and the closure's capture set is identical to the pre-existing one. Teardown orders `web_server_->stop()` (`server.cpp` ~10179) before the stores. Whether that stop fully joins in-flight handler threads before `auth_mgr_` / `audit_log` are destroyed was NOT re-verified by this ledger: `unverified` |
| `std::string_view` parameters: `write_a4(res, code, std::string_view message, std::string_view remediation, ...)` in `approval_routes.cpp`; `approver_refusal_reason()` (returns a view of string literals), `kApproverAssuranceMessage` (`constexpr string_view` of a literal) in `approver_assurance.hpp` | non-owning views | call sites pass literals or the temporary `std::string` from `approver_refusal_message(refusal)` | n/a | none | **Validity.** `detail::error_json_a4(..., string_view, ...)` copies the bytes into the returned `std::string` before returning (stated in `rest_a4_envelope.hpp` ~48-51), and `write_a4` consumes it within the same full-expression, so the temporary `std::string` argument outlives every use. `approver_refusal_reason()` returns views of static literals, so it cannot dangle, and `approver_refusal_message()` returns an owning `std::string` |
| `approver_assurance.hpp` (`check_approver_class`) | pure functions over `const auth::Session&`; `noexcept`; no I/O, no allocation in the class check itself (`approver_refusal_message` allocates a `std::string`) | n/a | n/a | n/a | no resource. Comparisons are `std::string` against literals |
| MCP `approve_request` / `reject_request` handler body (`mcp_server.cpp`) | replaces the old store-calling body with an unconditional typed refusal; no new locals beyond `refusal` and `audit_ok` | n/a | n/a | n/a | the refusal path no longer touches `approval_manager`; the `kExpired` branch added to the recall path only builds a response string. No resource |
| `schedule_runner.cpp` liveness check | calls `d_.approval_manager->ticket_is_live(a.id)` (a raw non-owning pointer, pre-existing and null-checked by the surrounding code) | per candidate ticket inside the existing loop | n/a | n/a | a `std::expected` error returns `false` (hold the occurrence). No new thread, callback or capture |
| `approvals_fragment_routes.cpp`, `mcp_orientation.cpp`, `approval_manager.hpp` additions | `std::any_of` over a borrowed `listed->approvals` and a lambda `[&]` used synchronously; text and `constexpr` constants only | n/a | n/a | n/a | no resource. The `[&]` lambda is a synchronous predicate argument and is not stored |
| Test code, `test_approval_manager.cpp` | `std::ifstream` (RAII) over `YUZU_SERVER_SRC_DIR/approval_manager.cpp`; a leased connection via `pool.acquire()` in `db_now_epoch` (RAII `Lease`); `ApprovalManagerPg` fixture (existing helper) | per test | scope exit | none | RAII. `count_occurrences` / `statement_from` take `std::string_view needle/anchor` (literals) and a `const std::string&` haystack that outlives the call. No temp path: the test reads a checked-in source file and creates none |
| Test code, `test_schedule_runner.cpp` `Harness::age_review` | `pg::PgConn conn{PQconnectdb(instr_db.dsn().c_str())}` (RAII, closes with `PQfinish`) and a `pg::PgResult` | per call | scope exit | none | RAII. Interpolates a test-generated approval id into an `UPDATE` (test-only, never caller text). Connects to the per-test ephemeral database `instr_db` (the `PostgresTestDb` fixture), not a shared one |
| Test code, `test_approval_routes.cpp` | fixture `Harness` members `step_up_labels`, `audits_at_step_up`, `csrf_trusted_origins`; `deps.step_up_fn = [this](...)` | `Harness` construction | `Harness` destruction | n/a | the `[this]` capture is safe only while the fixture outlives the sink and deps it configures, which holds because the route sink is a member of the same `Harness`. Not separately re-checked against the fixture's member order: `unverified` |
| Test code, `test_instruction_extras_ui.cpp` (the only post-`fb1075ab8` C++ delta) | `count_of(std::string_view hay, std::string_view needle)` and `has(std::string_view, std::string_view)`; `const auto& whole = kYuzuOperateExtrasJs` (a reference to a namespace-scope `const std::string`, declared `extern` in `page_routes.cpp`); `const std::string js = whole.substr(guard, second - guard)` | per test | scope exit | none | **Validity.** `js` is an owning `std::string` that lives for the whole test body, and the views passed to `count_of` / `has` are created from it (or from `whole`) for the duration of each call only; nothing stores a view. The helper loops advance by `needle.size()` and call `find` on the same view they iterate. No temp path, no I/O |
| Test code, `test_mcp_server.cpp` | `YUZU_REQUIRE_PG_DB_TPL` fixture, `pg::PgPool pool`, `ApiTokenStore`, `ApprovalManagerPg`, `McpTestServer` (all existing helpers) | per test | scope exit (reverse declaration order) | none | RAII throughout. Declaration order puts `pool` before `store` and the server last, so teardown runs the server first. Not exercised under a sanitizer for this ledger: `unverified` |
| Casts | the production diff adds none (checked: no added line in `server/core/src/*.{cpp,hpp}` contains `static_cast`, `reinterpret_cast` or `const_cast`; the `static_cast`s visible in the touched files are pre-existing context lines). Test code adds `static_cast<unsigned char>` before `std::isalnum` in `test_approval_manager.cpp` | n/a | n/a | n/a | the test cast is the standard character-classification idiom (avoids a negative `char`). Nothing else |
| Temp paths | none created by this diff | n/a | n/a | n/a | the diff adds no `unique_temp_path` / `TempDir` / `TempDbFile` user and no file write; the one file read is a checked-in source via `YUZU_SERVER_SRC_DIR` |

**Not covered / not verified (stated rather than implied).**

- Sanitizer coverage: ASan / UBSan / TSan results for the new tests were `unverified` by this
  ledger's author; only the code was read.
- `ServerImpl` teardown ordering of `step_up_fn`'s `this` capture against in-flight handler
  threads: `unverified` (see the row above). The capture set is unchanged from the pre-existing
  closure, which is the basis for treating it as not newly introduced.
- The first-run Gate 1 Resource Ledger is not in the repo and could not be compared against.

**Adjudications recorded:** none required. No manual (non-RAII) resource cleanup exists in
the C++ this diff adds; the one raw acquisition in test code (`PQconnectdb`) is wrapped in
`pg::PgConn` in the same statement.
