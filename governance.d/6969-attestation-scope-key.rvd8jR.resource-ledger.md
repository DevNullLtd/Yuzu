# Resource Ledger, attestation scope key (#6969 PR-A, schema v4), range origin/dev...2e60fde803 (merge-base f16ae48118)

Committed beside `governance.d/6969-attestation-scope-key.rvd8jR.jsonl` (the run ledger; its policy-floor finding `g8-cs-1-resource-ledger-two-test-threads` is closed by the commit that adds both files).

Authorship and independence. Every row and this file were written by the authoring Claude Code session from the reports of its own governance subagents (security-guardian, docs-writer, architect, cpp-expert, cpp-safety, quality-engineer, happy-path, unhappy-path, consistency-auditor, chaos-injector, compliance-officer, sre, enterprise-readiness). Those agents are the same model family and session, so none of this is independent of the author, and no external reviewer (Kimi or Codex) read the branch. Recording limits: for the Gate 2 to Gate 6 rows the `severity_native` field is null because the reporters' own words were not kept verbatim; the facts (trigger, impact, exposure, line numbers) were re-derived by the recorder from the run reports and may be coarser than the reporters' own. Gate 8 rows carry the reporters' native bands as they wrote them. Findings left `open` are follow-ups whose GitHub issues are NOT filed (issue filing waits for the push go); each is superseded with its issue number when filed.

## Gate 1 baseline (d4d2b0e749)

No new fd, HANDLE, SOCKET, FILE*, sqlite3*, OpenSSL or BCrypt handle, thread, callback, subprocess or temp path. The added lines of `server/core/src` read only through existing RAII `PgResult` holders and `std::string_view` over them (`access_review_store.cpp`). No new raw cleanup.

## Addendum (fix round 2e60fde803)

- Tests only: two local `std::thread` objects (`fleet_thread`, `group_thread`) in the concurrent two-scope attest test (`tests/unit/server/test_access_review_store.cpp`, about lines 3025-3046). Owner is the test scope; both are joined on every normal path before any Catch2 assertion; none is detached. They use no `REQUIRE` or `CHECK`; shared state is `std::atomic<bool> go` and `std::atomic<int> failures`; the store and pool outlive the join. If the second thread's constructor threw, the first would be joinable at unwind and `std::terminate` would run (finding `g8-cs-2`, optional `std::jthread`, not applied).
- Tests only: the DO-block rollback test's `DYNAMIC_SECTION`s each build a fresh database through `YUZU_REQUIRE_PG_MIGRATION_DB`, dropped by `~PostgresTestDb` (`DROP DATABASE ... WITH (FORCE)`) on every path; the planting `PgConn` closes before the pool opens; `LogCapture` is RAII.
- Production: the hex escape in `append_json_escaped` writes `\u00` plus two digits from a static `std::string_view` table into a `std::string` (index is `b >> 4` and `b & 0x0F` for `b < 0x20`, in bounds); `<cstdio>` was dropped. `kHistoryScopeCol` is a `constexpr` count over a `const char*` string literal. No new resource.

## Sanitizer coverage needed

- TSan: the two-thread attest test is a real concurrent writer on a shared store and pool. NOT run (TSan is `--full` only).
- ASan/UBSan: none beyond the default run; the hex write is in bounds by construction.
