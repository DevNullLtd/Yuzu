# Adversarial review synthesis — #3762 MFA enrollment TOCTOU

**Target:** `f91d08f18..HEAD` (feat/auth-mfa-enrollment-toctou). **Panel:** Codex (empirical) + Kimi-K3 (static). **Adjudicator:** Opus orchestrator.

## VERDICT: PASS (after folding the converged BLOCK finding)

Codex returned BLOCK; Kimi returned PASS-flipping-to-BLOCK-iff-anchor-confirmed. The single deciding fact both reviewers deferred to the orchestrator — Codex's cited hard invariant — was **confirmed verbatim** (`docs/auth-mfa-design.md:640`, "`mfa_disable` is atomic against in-flight verifies … any concurrent verify either sees the old state (and matches) or the new state (and fails)"). The converged finding was **fixed in-place** (commit `b8ae6467e`), which resolves the BLOCK.

## Findings

### CDX-01 / K4 — enrol over a concurrently-disabled secret (converged; was BLOCK) → FIXED
Both reviewers independently reached the same mechanism: `mfa_verify_enrollment` verifies the provisional secret **before** its transaction; `mfa_disable` NULLs **both** `mfa_totp_secret` and `mfa_enrolled_at`; so a verify racing a disable re-evaluates its `mfa_enrolled_at IS NULL` guard against the post-disable row, still matches, and enrolls the account with a **NULL TOTP secret** (unusable second factor; TOTP login fails closed, recovery codes live). This violates the confirmed hard invariant (item 3).

**Adjudication:** the race is **pre-existing** (verified: `git show origin/dev` — the old unguarded UPDATE matched the same post-disable row; the diff neither introduced nor worsened it), so on provenance alone it would not *gate* #3762. But (a) the anchor is a confirmed hard invariant, (b) the fix is **one clause on a line this diff already edits**, and (c) both external reviewers converged and the panel returned BLOCK. Filing-and-shipping a cheap, in-line, invariant-closing fix would have been the wrong call. **Folded** `AND mfa_totp_secret IS NOT NULL` into the guarded UPDATE (`b8ae6467e`) — exactly Kimi's preferred fix and the non-NULL half of Codex's. Post-disable → 0 rows → classify keeps WriteFailed/503 (fail-closed, no half-state). Closes #3778 in-place. White-box test extended to pin the disabled-secret rejection.

### K1 / CDX-02 — 0-row classify branch has no *deterministic* test (MEDIUM/LOW) → accepted
The classify branch (concurrent-enroll → MfaAlreadyEnrolled) is reachable through the public API only under the actual race, so it is deterministically testable only via the concurrency test's `already==1`/`other_err==0` assertions (not the pre-check short-circuit). This is the same defensively-race-only situation as #2399's guard branch. quality-engineer's governance mutation test showed the concurrency test IS regression-sensitive (20/20). Codex's "14/14 SKIPPED" is a **sandbox-DSN artifact** — the suite runs in Yuzu CI (`ensure-postgres.sh`) and ran locally here (592 assertions). Accepted, non-blocking; matches the #2399 disposition.

### K2 / CDX-03 — white-box test duplicates production SQL (LOW) → accepted (precedented)
Same as #2399: deterministic predicate documentation, backstopped by the empirically-verified concurrency test. Non-blocking.

### K3 — loser blocks on winner's in-txn 10×PBKDF2 regen; timeout unverified (LOW) → REFUTED
Codex verified `with_txn_for`'s duration is a **connection-acquisition deadline only** (`pg_pool.hpp:232-239`), not a statement/lock timeout — so there is no lock-timeout that could re-surface a false 503 under load. Refuted by the empirical read.

### K5 — the two added comments contradict on whether `mfa_disable` is the *sole* un-enroll path (LOW) → FIXED
Reconciled in `b8ae6467e`: the code comment now says "every un-enroll path (`mfa_disable`, soft-delete) NULLs `mfa_enrolled_at`", consistent with the test comment.

## What each reviewer ran
- **Codex:** `meson compile` PASS; `[pg][auth_db][secrets]` 14/14 SKIPPED (no sandbox DSN); `git diff --check` PASS. Static-verified `pg_pool` timeout semantics.
- **Kimi:** static over the injected bundle; deferred the anchor + timeout falsifiers to the orchestrator/Codex.
- **Opus:** confirmed the anchor verbatim; confirmed the race is pre-existing (`git show origin/dev`); folded and tested the fix (592 assertions green).
