# Security review — Account lockout (SOC 2 CC6.3)

| Field | Value |
|---|---|
| Date | 2026-06-12 |
| Scope | Account-lockout control on the local-password login path (`feat/auth-account-lockout`) |
| Control | SOC 2 CC6.3 (authentication) — brute-force / credential-stuffing protection |
| Driver | `/auth-and-authz` gap matrix P0 #2 |
| Reviewer | governance pipeline (Gate 2 security-guardian + authdb; Gate 3 cpp-safety/cpp-expert/architect/quality-engineer; Gate 4 happy/unhappy/consistency; Gate 6 compliance/sre/enterprise-readiness); Codex + Claude two-phase adversarial; Hermes cyber-security (Anthropic-Cybersecurity skills) — **all PASS, no CRITICAL/HIGH**, hardening folded in. |
| Status | Implemented; governance + adversarial + Hermes cyber-security all PASS |

## Purpose

Records the evidence chain for adding account lockout to Yuzu Server's
local-password login. After `--auth-lockout-threshold` consecutive failed
`POST /login` attempts an account is locked for `--auth-lockout-window-secs`;
the counter resets on a successful login or an admin unlock. Scope is
local-password only — OIDC delegates to the IdP and the MFA code path has its
own rate-limit.

## Control surface

| Element | Location |
|---|---|
| State (3 columns on `users`, migration v3) | `server/core/src/auth_db.cpp` (`kMigrations` `{3,...}`) |
| Accessors (`lockout_status`/`record_failed_login`/`clear_failed_logins`) | `auth_db.{cpp,hpp}` |
| Login gate (pre-check / record / clear) | `server/core/src/auth_routes.cpp` `POST /login` |
| Admin unlock `POST /api/v1/users/<name>/unlock` | `server/core/src/rest_api_v1.cpp` (`UserManagement:Write` + step-up) |
| Config + boot posture log | `server/core/include/yuzu/server/server.hpp`, `main.cpp` |
| Tests | `tests/unit/server/test_auth_lockout.cpp` (8 cases, 76 assertions) |

## Design decisions with security rationale

- **Generic 401 on a locked account** — identical body to a bad password, no
  `Retry-After`, no "locked" wording. Preserves the existing anti-enumeration
  posture; the lock is observable only server-side (audit + metric). The
  pre-check skips PBKDF2 on a locked account, removing a CPU-amplification
  vector.
- **Temporary, auto-expiring window** — `locked_until` is a future timestamp,
  never a permanent flag, so an attacker cannot weaponise lockout to
  permanently DoS a legitimate principal. An expired window starts a fresh
  attempt budget.
- **No row for a non-existent user** — `record_failed_login` is scoped
  `WHERE username = ? AND is_active = 1`, so spraying random usernames neither
  locks nor creates an account and cannot grow storage.
- **Audit without flood-amplification** — `auth.lockout.applied` fires once on
  the threshold crossing; subsequent blocked attempts increment a metric, not
  an audit row.
- **`RETURNING`, never `sqlite3_changes()`** (#1033) on the shared FULLMUTEX
  connection; all SQL parameterised.
- **Admin unlock self-target permitted** (recoverable) — matches the
  session-revoke precedent, not the `#397/#403` hard-403 self-target guard.

## Adversarial review checklist (to confirm in the pre-submission gate)

- Lockout-as-DoS against a legitimate admin (temporary window + admin unlock).
- Counter/`locked_until` race under concurrent failures (single atomic
  `UPDATE ... RETURNING`).
- Pre-check → verify → record TOCTOU window.
- Username case/whitespace bypass (validated by `is_valid_username`).
- Audit-flood amplification on the blocked path (metric-only).

## Hard-invariant regression check

HTTPS/bind defaults, six security headers, parameterised SQL, `auth.db`
0600 / dir 0700, `MigrationRunner::run` for the schema, `require_admin`
denied-audit on the unlock 403, and the structured JSON error envelope are all
unchanged. No `AuthDB::mu_` held across a sibling-bus publish (audit/event/
metric emission happens in the route after AuthDB calls return).

## Governance findings — resolution

No CRITICAL/HIGH. One BLOCKING and several SHOULD/NICE; the merge-blocking and
high-value items were folded into the commit (hardening round):

- **BLOCKING (enterprise-readiness)** — lockout ON by default is a behavior
  change for existing deployments → added a CHANGELOG `### Breaking Changes`
  entry + `docs/user-manual/upgrading.md` § "Account lockout is ON by default".
- **SHOULD (architect S1 / security-guardian)** — unlock handler now mirrors the
  sessions route's audit-failure surface (try/catch → `Sec-Audit-Failed` header
  + `audit_emitted` body), tested in `test_rest_sessions.cpp`.
- **SHOULD (consistency)** — `auth.lockout.applied`/`.cleared` results normalized
  to the canonical `ok|denied|error` envelope (`warn`/`success` removed); doc
  tables corrected.
- **SHOULD (unhappy UP-15 / consistency)** — dropped the per-attempt
  `auth.lockout.blocked` analytics event; blocked attempts are now strictly
  metric + rate-limited log (matches the stated "no amplification" design).
- **SHOULD (compliance/unhappy UP-14)** — login-path `applied`/`cleared` audit
  emissions are now return-checked (lost CC6.3 evidence is logged at `error`).
- **SHOULD (unhappy UP-12)** — `clear_failed_logins` gained the `is_active = 1`
  filter for parity with the sibling lockout accessors.
- **SHOULD (sre/enterprise)** — added `docs/ops-runbooks/auth-db-recovery.md`
  § "Account lockout recovery" + the `threshold=0` hardened-baseline deviation
  note and NIST 800-63B guidance in `server-admin.md`.
- **Verified non-issues** — migration v3 partial-apply (UP-9/10): MigrationRunner
  wraps each version in `BEGIN IMMEDIATE … COMMIT`/`ROLLBACK`. `window_secs`
  overflow (UP-3): `int` caps at ~68 years, within SQLite's datetime range.
  `/readyz` (sre): `auth.db` already covered by `is_auth_db_ok()`.

## Adversarial review (Codex + Claude, two-phase) — resolution

A two-reviewer adversarial pass split on one finding; the orchestrator
adjudicated and folded the proportionate fixes into the commit:

- **C1 — concurrent check-then-act race (Codex HIGH/BLOCK, Claude MEDIUM).**
  Initially adjudicated MEDIUM/non-blocking, then **CLOSED in code** at the
  operator's direction before merge. A synchronized burst could verify more than
  `threshold` passwords before the lock armed (the per-IP rate-limit does not
  bound a 1-request-per-IP botnet). Fix: the whole `lockout_status` →
  `verify_password` → `record/clear` sequence is held under a **striped
  per-username login lock** (`AuthRoutes::login_lock_for` / `login_locks_`), so
  concurrent attempts for one account serialize and at most `threshold` reach
  verification — Codex's own falsifier ("a route-level synchronization … that
  prevents more than threshold concurrent requests … from reaching successful
  password verification"). Covered by a 16-thread barrier-style concurrent route
  test (`failed_count` ends exactly at `threshold`). Single-process scope
  (adequate for single-node SQLite `auth.db`); the HA/multi-replica form is a
  DB-atomic reservation at the Postgres migration (follow-up).
- **C2 — unlock route absent from OpenAPI discovery (A2).** Fixed: added
  `POST /api/v1/users/{username}/unlock` to `openapi_spec()` + a discovery test.
- **C4 — lockout inert in config-file-only mode but boot log claimed "active".**
  Fixed: the boot posture log now warns "CONFIGURED but INACTIVE" when
  `--data-dir` is unset (no auth.db ⇒ no lockout). The shipped systemd unit
  passing no `--data-dir` is the real-world trigger — see follow-up.
- **C5 — locked path skips PBKDF2 ⇒ timing lock-state oracle.** Accepted +
  documented; a constant-time floor would re-introduce the PBKDF2 DoS the skip
  avoids.
- Withdrawn under cross-exam: a claimed seed-vs-live divergence between the
  in-memory `users_` map and the `auth.db` users table — falsified because
  `verify_password` cross-checks `auth_db_->get_user` and denies login on an
  absent/inactive row.

## Hermes cyber-security pass (Anthropic-Cybersecurity skills) — resolution

**PASS, no CRITICAL/HIGH.** Explicitly cleared the admin-unlock endpoint of
BFLA/BOLA (perm → auth → step-up → action ordering correct) and confirmed the
anti-enumeration design. Findings:

- **F1 timing oracle / F2 concurrency** — duplicates of C5 / C1; already
  documented. Hermes concurs MEDIUM + follow-up.
- **F3 (MEDIUM) — no per-attempt audit row for blocked-while-locked attempts.**
  This is the *deliberate* flood-avoidance decision (governance UP-15 had the
  per-attempt analytics event removed). The `yuzu_auth_lockout_blocked_total`
  metric is the documented continuation signal — `docs/observability-conventions.md`
  directs SIEM rules to watch it (a `_blocked_total` spike after one
  `_applied_total` is the brute-force-against-a-locked-account shape). Recorded
  as an explicit accepted trade-off, not an oversight; SIEM rules must not key
  solely on `auth.login_failed`.
- **F4 (LOW) — FIXED.** A failed pre-check `lockout_status` read left
  `prior_failed_count = 0`, so a later successful login skipped the counter
  clear. The pre-check now records `lockout_read_failed` (and logs the fail-open
  degradation, no longer silent), and the success path clears defensively when
  the count is unknown.
- **F5 (LOW) — FIXED.** Negative `--auth-lockout-threshold` / `-window-secs`
  were accepted then silently clamped; now rejected at parse time
  (`CLI::NonNegativeNumber` / `CLI::PositiveNumber`).

## Deferred follow-ups (filed, non-blocking)

- **DB-atomic attempt-reservation** to replace the single-process striped login
  lock with an HA/multi-replica-correct primitive, landing with the auth store's
  Postgres migration (C1 is closed for single-node; this is the multi-node form).
- **systemd unit ships no `--data-dir`** (`deploy/systemd/yuzu-server.service`),
  so AuthDB — and therefore lockout, MFA persistence, and cross-restart
  sessions — is unwired in a bare systemd deployment. Pre-existing, broader than
  lockout; wire `--data-dir /var/lib/yuzu` (matches `StateDirectory=yuzu`) under
  the breaking-change treatment (adversarial C4 root cause).
- **A4 error-envelope migration** for the `/api/v1/users` + `/sessions` route
  cluster (all use legacy `error_json`; A4 is confined to events/dex/executions)
  — do the cluster as a unit, not a lone-route exception (adversarial C3).
- **`just_locked` transition detection** — derive it from an actual
  unlocked→locked transition rather than `failed_count == threshold`, so a
  threshold lowered across restart (counter already above the new threshold)
  still emits the once-per-lock `auth.lockout.applied` evidence (adversarial C6).
- **Route-harness metric assertions** for `yuzu_auth_lockout_applied_total` /
  `_blocked_total` (adversarial C7).
- `--unlock-account <username>` break-glass CLI mirroring `--mfa-reset` (sre/ER).
- `yuzu_auth_lockout_read_errors_total` counter to make the fail-open pre-check
  read-error path observable (sre / UP-7).
- `yuzu_auth_accounts_locked_current` gauge + Prometheus alert rules in
  `docs/prometheus/yuzu-alerts.yml` (sre).
- `docs/user-manual/server-admin.md` `--data-dir` row says it "defaults to the
  config dir" — the code does not default it; correct the doc (found during
  adversarial C4 trace).
- Monotonic-clock consideration for the `locked_until` window vs backward wall-
  clock jumps (UP-2) — revisit in the QUIC-era auth work.
  *(Update 2026-10-08: the QUIC work was withdrawn, ADR-0066 — this item needs its own owner
  and no longer waits on a transport change.)*
