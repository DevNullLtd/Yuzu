# Adversarial review synthesis — #2396 login/Postgres availability (384031a7d)

Panel: **Codex** (empirical — compiled the change, GCC 15.2, ran `[auth_routes]` 16/49; repo-wide caller audit) + **Kimi-K3** (static, over an injected bundle). Opus adjudicator verified every finding against the committed code.

## Verdict: PASS — no CRITICAL/HIGH. Three MEDIUMs confirmed and FIXED; four Kimi findings refuted at cross-exam.

Both seats reached PASS. Fail-closed authentication is preserved at every site; the retry is correctly scoped off the login stripe; no enumeration oracle; lease RAII clean.

### Confirmed & fixed (both reviewers, or one + independent adjudication)

| # | Finding | Provenance | Fix |
|---|---|---|---|
| CDX-P2-03 / K1 | `mfa_init_enrollment` reuse guard flattened every store-unavailable error to `WriteFailed` → a `StoreBusy` acquire-timeout was mislabelled `reason=query_error` at the enroll-init 503. Both seats independently traced it. | static (both), fail-closed intact | guard now `return existing.error()` (preserves StoreBusy/QueryFailed); `break_load_mfa_row_only` test updated to assert `QueryFailed` |
| CDX-P1-01 / K4 | `record_failed_login` 503 incremented only `yuzu_auth_read_degrade_total`, not the coarse `yuzu_auth_secret_unavailable_total` my doc says fires "alongside" it → an alert on the coarse series undercounts a login outage. Kimi conceded LOW→MEDIUM against the anchor. | static (both), compiled (Codex) | added the `secret_unavailable_total{route=login}` increment at that site — all three login-path 503 sites now move both counters (doc now true) |
| CDX-P1-02 / K7 | retry *recovery-within-a-request* untested — the saturated-pool test proves exhaustion + later-request recovery, not that a transient empty acquire rides out to success in the same call. Also flagged by governance's quality-engineer. | empirical (Codex compiled the range), Kimi adopted | extracted `detail::acquire_with_bounded_retry` (header-only, pool-free seam); added a deterministic unit test proving empty→empty→success within one call, bounded exhaustion, no-retry-on-success, retries==0 |

### Refuted at cross-examination
- **K2** (contract blast-radius: an exact-match `==QueryFailed`/`WriteFailed` caller missing StoreBusy) — Codex ran a repo-wide caller audit: no vulnerable caller exists; the error-sensitive MFA callers all use `is_store_unavailable`. (Also confirmed by governance authdb.) Refuted.
- **K3** (no tests) — withdrawn by Kimi; artifact of the code-only bundle I gave it. Codex proved the test files exist/compile/partially ran.
- **K5** (fixed Retry-After 2s vs 5s breaker) — Codex: a minimum-delay hint is not a promise the dependency is healthy; sre earlier confirmed non-amplifying. Refuted (tuning only).
- **K6** (compounded ~4.2s latency) — Codex: the first exhausted read short-circuits; requires a second availability transition. Refuted.

### What each reviewer ran
- Codex: offline meson reconfigure PASS; `meson compile tests/yuzu_server_tests` PASS (GCC 15.2); `[auth_routes]~[pg]` 16/49 PASS; PG-tagged degrade tests SKIPPED (DSN unset in its sandbox — the adjudicator ran them separately, all green); repo-wide `rg` caller audit.
- Kimi: static over the injected diff + surrounding handler source + anchor.

Note: the two metric-correctness fixes (CDX-P2-03, CDX-P1-01) directly harden the reason-label feature this change exists to add; the third closes the highest-value test for it.
