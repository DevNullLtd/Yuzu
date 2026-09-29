# Adversarial review synthesis — #2399 MFA monotonic counter guard

**Target:** `445adb520..HEAD` (feat/auth-mfa-counter-guard). **Panel:** Codex (empirical, `compiled`/`test-run`) + Kimi-K3 (static). **Orchestrator/adjudicator:** Opus.

## VERDICT: PASS

Both independent reviewers returned PASS. No CRITICAL/HIGH. The production guard is correct, fail-closed, and satisfies the AuthDB MFA invariant and the `docs/auth-mfa-design.md` anchor. Adjudicated below against real code.

## Consolidated findings

| ID | Sev | Found by | Provenance | Disposition |
|---|---|---|---|---|
| K1 / CDX-P1-01 | MEDIUM | **both, independently** | compiled (Codex) + static (Kimi) | accept as known non-blocking limitation |
| K2 | — | Kimi | static | **withdrawn** (falsified) |
| K3 | LOW | Kimi only (Codex missed) | static | **fix applied** |

### K1 — guard lacks regression-sensitive in-situ coverage (MEDIUM, converged, non-blocking)
Both reviewers independently reached this: deleting/inverting/de-RETURNING the production guard fails **no** test. The concurrency test's exactly-once is delivered by the pre-existing `SELECT … FOR UPDATE` + `verify_window` (the loser is rejected before the UPDATE), and the white-box test runs its own username-keyed SQL *copy*, not the production id-keyed statement.

**Adjudication:** valid and correct — and it is the *same* point governance's `quality-engineer` raised (Gate 3 SHOULD) and accepted as proportionate. The regression-insensitivity is **inherent to a defensively-unreachable branch**: the 0-row path cannot be induced through the public API while `FOR UPDATE` holds, so true regression-sensitivity would require extracting a production seam — over-engineering for a defense-in-depth layer. **Correction to Codex's empirical sub-point:** its "`[pg][auth_db][secrets]` → 11/11 skipped" is a *sandbox-DSN artifact*, NOT Yuzu CI behavior — `scripts/ci/ensure-postgres.sh` guarantees a reachable DSN on every CI server-test leg, so these tests **do** run in CI. The "PG-less CI runs nothing" framing does not hold for Yuzu.
**Disposition:** accepted, non-blocking, already tracked (governance ledger `qe-guard-branch-coverage`, fixed via the white-box test as the proportionate defense-in-depth coverage). No production-seam refactor.

### K2 — NULL `mfa_last_counter` → permanent false (WITHDRAWN)
Kimi hypothesized a NULL counter row could make every login false. **Falsified by me directly:** `auth_db.cpp:247` = `mfa_last_counter BIGINT NOT NULL DEFAULT 0`. Codex reached the same falsifier; Kimi withdrew. Correct.

### K3 — concurrency test busy-spins without yield (LOW, Kimi only)
`while (!go.load(acquire)) {}` is a bare empty-body spin; correct synchronization (acquire/release, joined), but wasteful and — on Yuzu's shared 4-runner-per-box CI (Wee Tam / Big Tam) — a minor oversubscription risk that could delay the releasing thread. **Fix applied:** `std::this_thread::yield()` in the spin body. The count-based assertion is deterministic regardless, so the slight loosening of near-simultaneity Codex flagged does not affect correctness, and CI politeness on the shared boxes is the better tradeoff.

## Coverage gaps neither hit
None material. Both went deep on security/fail-closed, RETURNING/TUPLES_OK semantics, param binding, verify_window contract, concurrency/rollback, and doc consistency. Cross-platform: nothing platform-specific in the diff (both skimmed, correctly). Agentic-first: N/A (no REST/MCP/error-envelope surface changed) — verified by both.

## What each reviewer ran
- **Codex:** `meson compile -C build-linux tests/yuzu_server_tests` PASS; `[auth_db]~[pg]` PASS (19 assertions); `git diff --check` PASS. PG cases skipped (no DSN in sandbox).
- **Kimi:** static over the injected CONTEXT bundle (diff + full `mfa_verify_login_code` + `verify_window` + caller error-mapping + anchor).
- **Opus:** verified K2's schema claim and K1's CI-PG premise directly against the tree.
