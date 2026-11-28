# Security review — Hardened auth mode + break-glass (SOC 2 CC6.3/CC6.6)

**Date:** 2026-06-29
**Change:** `--auth-mode=sso-only` (disable local-password fallback) + a
constrained, MFA-mandatory, audited, auto-expiring break-glass account armed via
the host CLI `yuzu-server --break-glass-arm`.
**Branch:** `feat/auth-hardened-mode`
**Controls:** SOC 2 **CC6.3** (logical access — disable local-password
fallback), **CC6.6** (privileged access — tightly constrained break-glass).
Closes `/auth-and-authz` gap-matrix **P0 #3** (both halves of Workstream B line
70).

## What shipped

- **`--auth-mode <standard|sso-only>`** (`YUZU_AUTH_MODE`, default `standard`).
  Under `sso-only`, `POST /login` rejects every local-password login between the
  lockout pre-check and `verify_password` with the **same generic 401** as a bad
  password (no enumeration/mode oracle; PBKDF2 skipped). Only OIDC SSO
  (`/auth/callback`, untouched) mints a session.
- **Break-glass account** — `--break-glass-user` is the single exempt principal,
  exempt **only while armed**. "Armed" is `users.break_glass_armed_until`
  (AuthDB migration **v4**, one nullable column), a future timestamp evaluated in
  SQL against `CURRENT_TIMESTAMP` like `locked_until`, so it **auto-expires**
  (`--break-glass-window-secs`, default 24 h) and is never a standing bypass.
- **Arming is out-of-band** — `yuzu-server --break-glass-arm` validates the
  account, verifies the audit store is writable **before** mutating, arms via a
  single `UPDATE … RETURNING` (no `sqlite3_changes()`, #1033), and writes
  `auth.breakglass.armed` attributed to the kernel OS identity. Mirrors the
  `--mfa-reset` contract (#1226). It does **not** require a session, so it works
  during the IdP outage it exists for.
- **AuthDB:** `break_glass_status` / `arm_break_glass` accessors +
  `break_glass_account_problem` validator (shared by the boot guard and the arm
  one-shot).

## Control / authz decisions

- **CC6.3 — local-password fallback disabled, fail-closed.** `sso-only` refuses
  to start (`EXIT_FAILURE`) when `--oidc-issuer` is empty — it cannot boot an
  unreachable server that locks every operator out. The activation evidence is
  the boot-posture log banner.
- **CC6.6 — break-glass mandatory MFA, two layers.** (1) The server refuses to
  start under `sso-only` if the named break-glass user doesn't exist or has no
  MFA enrolled (`break_glass_account_problem`; because `mfa_status` filters
  `is_active=1`, a soft-deleted user reads as un-enrolled and is rejected). (2)
  At login, an un-enrolled break-glass account is **hard-denied 403**
  (`auth.breakglass.denied`) — enrollment is deliberately **not** offered,
  because the enrollment flow only requires the password and would let a
  password-only adversary self-enrol and break the glass with no real second
  factor (governance UP-1).

## Threats considered (governance pipeline, 9 reviewers)

- **Enumeration / mode / arm-state oracle.** Response body/status/headers are
  identical to a bad-password 401. Residual: response **timing** (an armed
  break-glass username runs PBKDF2; everything else short-circuits) can reveal
  that the break-glass account is currently armed — accepted, identical in kind
  to the lockout pre-check's documented timing residue; discloses at most
  "armed", never a credential.
- **Audit-flood amplification (UP-2).** The sso-only denial is **metric-only**
  (`yuzu_auth_local_disabled_total{target}`), not a per-attempt audit row — a
  credential spray under sso-only would otherwise grow `audit.db` without bound
  (the account never locks on this path). Same anti-flood posture as the
  lockout-blocked path.
- **Bare-password break-glass session (UP-1).** Impossible: the hard-deny above
  + the forced TOTP challenge mean a break-glass session always carries a second
  factor. The `auth.breakglass.login` row fires **after** `verify_password`
  succeeds, so a wrong password is a normal `auth.login_failed`, never a
  spurious "ok" break-glass row.
- **Silent disarm via window overflow (UP-4).** A `--break-glass-window-secs`
  large enough to overflow `datetime()` to NULL is detected (the arm returns
  `armed=false`) and the one-shot fails loudly rather than reporting a dormant
  account as armed.
- **Confused arm one-shot vs server start.** The arm + `--mfa-reset` one-shots
  run before the sso-only boot guard, so they are never blocked by a missing
  OIDC issuer (governance happy-path finding).

## Residual risks (accepted / tracked)

- **Break-glass lockout DoS — FIXED.** Flagged by Hermes (MEDIUM, finding F),
  security-guardian (LOW), and unhappy-path (UP-13): an attacker who learns the
  break-glass username could spray wrong passwords to keep the account locked and
  the escape hatch unreachable during an IdP outage. **Closed in the second
  hardening round:** the break-glass account is now exempt from failed-login
  lockout while `--auth-mode=sso-only` (the second factor remains mandatory, the
  un-armed password is never evaluated, wrong attempts are still audited +
  per-IP rate-limited). Regression test:
  `test_auth_routes_hardened.cpp` "the break-glass account is exempt from
  failed-login lockout".
- **Login timing residue (MEDIUM, accepted).** An armed break-glass username
  runs PBKDF2 while other sso-only rejects short-circuit, so response timing
  leaks "armed"/"sso-only mode" (never a credential). A constant-time floor was
  **deliberately rejected** — it would re-introduce the PBKDF2-cost amplification
  DoS the skip exists to avoid. Same accepted trade-off as the shipped lockout
  pre-check.
- **Arm + audit non-atomic across two DBs — handled (review #1735 HIGH-2).** The
  `auth.db` arm and the `audit.db` row cannot share a transaction. A **handled**
  `audit.log() == false` now triggers a **compensating un-arm**
  (`AuthDB::disarm_break_glass`) before the non-zero exit, so the exemption is
  never left standing without a record — the "never granted without a record"
  guarantee holds in code, not just in the doc. The only residual is a SIGKILL /
  power loss in the microsecond window between the `UPDATE` and the `INSERT`
  (genuinely unavoidable without cross-DB atomicity); the `is_open()` pre-check
  catches the common audit-unwritable case before mutating, and the next
  break-glass login still emits `auth.breakglass.login` as a backstop. A double
  fault (audit write AND the un-arm both fail) is logged loudly for manual
  intervention.
- **No `--break-glass-disarm` / arm-expiry audit event (compliance SHOULD).**
  The window auto-expires silently; an explicit early-disarm command + an
  expiry/disarm audit row are tracked follow-ups.
- **OIDC reachability not probed at boot (UP-8).** `sso-only` checks only that
  `--oidc-issuer` is non-empty, not that the IdP resolves; a typo'd issuer with
  no break-glass user is a silent lockout. Documented prerequisite; an IdP
  discovery probe is a tracked follow-up.
  *(Superseded in part by #4160: a runtime-wiring check now refuses to start when no
  provider came up, but OIDC reachability is deliberately still NOT probed at start-up
  so an IdP outage at restart cannot block boot. See `docs/auth-architecture.md`,
  "Boot guard". This dated record is otherwise unchanged.)*

## Validation

- Unit: `tests/unit/server/test_auth_break_glass.cpp` (DB accessors + validator)
  and `tests/unit/server/test_auth_routes_hardened.cpp` (wire path: generic-401
  no-oracle, no per-attempt audit, exempt-only-while-armed, hard-deny of an
  un-enrolled break-glass login, wrong-password-is-normal-failure). Full auth
  suite green (1635 assertions); server build + link clean.
- Governance pipeline: security-guardian PASS (no CRITICAL/HIGH); cpp-safety /
  cpp-expert / consistency-auditor PASS; unhappy-path UP-1/UP-2 (BLOCKING) fixed
  in the hardening round; docs-writer + compliance-officer SHOULD findings
  addressed (this record, CHANGELOG, upgrading, audit-log, observability,
  runbook).

## Reviewer

Governance pipeline (9 agents) + Hermes pre-submission security passes on
`feat/auth-hardened-mode`.
