# MFA (TOTP) — Yuzu design reference

Status: **PR 1 + PR 2 + PR 3 of 3 shipped (v0.13+), plus the at-rest
encryption follow-up SHIPPED (2026-07-16)** — self-service
enrollment, login challenge, recovery codes (PR 1); step-up on 11
high-risk REST + Settings surfaces (PR 2); OIDC `amr` short-circuit plus
enforcement modes (`admin-only` / `required`) with login-time enrollment
bootstrap (PR 3). The MFA ladder is complete. `mfa_totp_secret` at-rest
encryption landed as part of the `AuthDB`/`ScimStore` ADR-0006 Postgres
cutover (`SecretCodec`'s first production consumer, ADR-0010) — see
"At-rest protection" below, which previously described this as a planned
follow-up and now describes the shipped mechanism. Bundled with the same
cutover: MFA state reads now fail **closed** (a distinct
`AuthDBError::SecretUnavailable` outcome) on a store/decrypt failure,
closing a latent bypass class where a read error could previously collapse
to "not enrolled" — see `docs/auth-architecture.md` "MFA fails closed on
secret-read failure".

This doc is the single design reference for Yuzu's MFA implementation.
For why MFA matters at all and where it sits in the broader A&A roadmap,
see `.claude/skills/auth-and-authz/SKILL.md` gap matrix entry P0 #1 and
`docs/enterprise-readiness-soc2-first-customer.md` workstream B (SOC 2
CC6.6 — privileged access).

---

## TL;DR

- **TOTP only.** RFC 6238, HMAC-SHA1, 30 s step, 6 digits. Works with
  every shipping authenticator app out of the box. WebAuthn / FIDO2 is
  deliberately deferred.
- **Per-user enrollment via the Settings page.** Operator scans an inline
  SVG QR code (server-rendered from the `otpauth://` URI by the vendored
  Nayuki `qrcodegen`; see `server/core/src/mfa_qr.{hpp,cpp}` and issue
  #1232), or enters the base32 secret manually — a one-time reveal in the
  existing `<div class="token-reveal">` pattern. They then enter the next
  code from their authenticator to confirm, and receive 10 single-use
  base32 recovery codes. The same QR is rendered in the login-time
  enrollment-bootstrap form (delivered to the browser via the `qr_svg`
  field of the `/login` 202 response).
- **Login challenge.** `POST /login` accepts the password and, if the
  user has TOTP enrolled, returns HTTP 202 + an opaque short-lived
  `mfa_pending_token` instead of minting a session. The browser swaps to
  a TOTP form and posts the token + 6-digit code to `POST /login/mfa`.
  Recovery codes share the same endpoint (heuristic: `-` separator or
  non-6-digit length).
- **Step-up window** (PR 2). On a successful TOTP proof the session's
  `mfa_verified_at` is bumped to `system_clock::now()` (wall-clock since
  HA WS-1/1a — see the corrected hard invariant #5). High-risk
  endpoints reject the session as "stale" if the gap exceeds
  `cfg.mfa_step_up_window_secs` (default 300 s) and prompt for a fresh
  code via `POST /login/mfa/stepup`.
- **Audit chain.** Every state transition emits an audit row through
  `AuthRoutes::audit_log`. The verbs are: `mfa.enroll.initiated`,
  `mfa.enroll.verified`, `mfa.enroll.failed`, `mfa.enroll.race`,
  `mfa.disabled`, `mfa.login.required`, `mfa.login.verified`,
  `mfa.login.failed`, `mfa.recovery_codes.generated`,
  `mfa.recovery_code.used` (PR 2 adds `mfa.step_up.*`).

---

## What ships in PR 1

The slice of the design that is live as of v0.12 — **table is historical
(SQLite `auth.db` era); see the callouts for what the 2026-07-16 Postgres
cutover changed.**

| Surface | File(s) | Notes |
|---|---|---|
| RFC 6238 TOTP + RFC 4648 base32 + otpauth URI | `server/core/src/totp.{hpp,cpp}` | Tested against RFC 6238 Appendix B SHA-1 vectors; unaffected by the Postgres cutover |
| Schema migration v2 (SQLite era) | `server/core/src/auth_db.cpp` (`kMigrations`) | `users.mfa_*`, `sessions.mfa_verified_at`, `mfa_recovery_codes`, `auth_kv` — `sessions`/`auth_kv` were **dropped** (not carried) into the single Postgres `auth` migration; see "Schema" below |
| MFA accessors on `AuthDB` | `server/core/{src,include}/yuzu/server/auth_db.{cpp,hpp}` | `mfa_init_enrollment` / `mfa_verify_enrollment` / `mfa_verify_login_code` / `mfa_consume_recovery_code` / `mfa_regenerate_recovery_codes` / `mfa_disable` / `mfa_status` still exist on the Postgres-backed `AuthDB`; **`mfa_mark_session_stepup` was removed** in the Postgres cutover along with `AuthDB`'s session surface (step-up state is `Session::mfa_verified_at`, now a durable `mfa_verified_ms` column on the `SessionStore` row for Postgres deployments — HA WS-1/1a) |
| AuthManager glue | `server/core/{src,include}/yuzu/server/auth.{cpp,hpp}` | `verify_password`, `create_local_session(user, role, mfa_verified)`, `mark_session_mfa_verified`, `auth_db_ptr()` |
| `Session::mfa_verified_at` | `server/core/include/yuzu/server/auth.hpp` | `system_clock::time_point` (wall-clock since HA WS-1/1a, ADR-2002 §4 — see invariant #5); default-constructed = not verified |
| Login flow | `server/core/src/auth_routes.{cpp,hpp}` | `POST /login` returns 202 + pending token on MFA-enrolled users; new `POST /login/mfa` route; `MfaPending` map with TTL reaper |
| Login page | `server/core/src/login_ui.cpp` | Hidden MFA form revealed on 202 response |
| Settings panel | `server/core/src/settings_routes.{cpp,hpp}`, `settings_ui.cpp` | `render_mfa_fragment` + four `/api/settings/mfa/*` POST routes; new "Multi-Factor Authentication" section |
| Config | `server/core/include/yuzu/server/server.hpp` + `main.cpp` | `mfa_enforcement`, `mfa_step_up_window_secs`, `mfa_login_pending_secs` + matching CLI flags |
| Tests | `tests/unit/server/test_totp.cpp`, `tests/unit/server/test_mfa_store.cpp` | RFC vectors + AuthDB end-to-end |

---

## Schema

**Historical (SQLite `auth.db`, pre-2026-07-16 Postgres cutover).** v2
migration in `auth_db.cpp:kMigrations`. The columns were all nullable so
existing rows survived the migration unchanged; `mfa_last_counter` had
`DEFAULT 0` to keep its `NOT NULL` honest.

```
users:
  mfa_totp_secret BLOB          -- raw 20-byte HMAC-SHA1 key, PLAINTEXT
  mfa_enrolled_at DATETIME      -- NULL = provisional or never enrolled
  mfa_disabled_at DATETIME      -- NULL = active or never enrolled
  mfa_last_counter INTEGER      -- replay floor; updated on every verify

sessions:
  mfa_verified_at DATETIME      -- NULL = never stepped up

mfa_recovery_codes:
  id INTEGER PK
  username TEXT
  code_hash TEXT                -- PBKDF2-SHA256 (matches password_hash)
  code_salt TEXT                -- 16 hex bytes
  consumed_at DATETIME          -- NULL = unused
  created_at DATETIME

auth_kv:
  key TEXT PK
  value BLOB
  created_at / updated_at DATETIME
```

`auth_kv` was provisioned empty for the at-rest encryption work below, but
was **never used** — see "At-rest protection".

**Current (Postgres, schema `auth`, ADR-0006).** The single-migration
`auth.users` table carries the same MFA columns, minus `sessions` (dropped
from `AuthDB` — operator sessions are now durable in the separate `SessionStore`
(HA WS-1/1a, ADR-2002 §4), not on `AuthDB`; see `docs/auth-architecture.md`
"Durable operator sessions")
and `auth_kv` (dropped, unused scaffolding, superseded outright by
`SecretCodec` — never reused for anything else):

```
auth.users:
  mfa_totp_secret BYTEA         -- SecretCodec envelope-encrypted (see below), NOT plaintext
  mfa_enrolled_at TIMESTAMPTZ   -- NULL = provisional or never enrolled
  mfa_disabled_at TIMESTAMPTZ   -- NULL = active or never enrolled
  mfa_last_counter BIGINT       -- replay floor; updated on every verify

auth.mfa_recovery_codes:
  id BIGINT PK
  username TEXT
  code_hash TEXT                -- PBKDF2-SHA256 (matches password_hash), unaffected by SecretCodec
  code_salt TEXT
  consumed_at TIMESTAMPTZ       -- NULL = unused
  created_at TIMESTAMPTZ
```

---

## At-rest protection — SHIPPED (2026-07-16, ADR-0010)

**The TOTP secret is now envelope-encrypted, not plaintext.**
`auth.users.mfa_totp_secret` is AES-256-GCM ciphertext via `pg::SecretCodec`
— `AuthDB` is `SecretCodec`'s first production consumer. The DEK is wrapped
by the install-level KEK (`FileKeyProvider`, the same 0600-PEM-in-0700-dir
custody the CA root private key already uses), and the AAD binds the
`{schema, table, column, row id}` tuple (`{"auth", "users",
"mfa_totp_secret", <users.id>}`) so a ciphertext blob cannot be swapped
between rows even by someone with raw SQL access. A read/decrypt failure
(tamper, an unresolvable/rotated KEK, a corrupt blob, or a transient
Postgres outage mid-read) surfaces as `AuthDBError::SecretUnavailable` and
every caller fails **closed** — see `docs/auth-architecture.md` "MFA fails
closed on secret-read failure" for the full call-site list and rationale.

**Everything below this line describes the retired SQLite-era posture, kept
for history.** The TOTP secret used to be plaintext in `users.mfa_totp_secret`,
with these compensating controls:

- `auth.db` was created and re-chmod'd to **0600** on every open. Same
  posture as password hashes.
- The parent directory was **0700** on Unix.
- The agent process runs as a dedicated non-root account (`docs/agent-
  privilege-model.md`) — this control is unrelated to storage substrate and
  still applies today.

Threat model at the time: an attacker with read access to `auth.db` already
had the password-hash store, the session cookie store, the enrollment-token
hashes, and every API-token row, so plaintext TOTP secrets did not
materially worsen that posture on their own — but a `pg_dump`/backup/
snapshot exposure of the **Postgres** substrate is a materially different
threat surface than a single 0600 SQLite file (ADR-0010's motivating
rationale for the whole `SecretCodec` mechanism), which is why the
encryption landed as a hard requirement of the Postgres cutover rather than
staying an indefinitely-deferred follow-up. The originally-sketched
mechanism — a per-server AES-256-GCM master key stored in `auth_kv` under
`key='mfa_master_key'`, `mfa_totp_secret_enc + nonce + tag` columns, a v3
SQLite migration — was **superseded outright**, not implemented: `auth_kv`
carries no rows in the shipped schema at all (it does not exist in Postgres;
see "Schema" above), and the actual mechanism is `SecretCodec`'s generic
envelope-encryption seam, shared with every other secret-bearing store on
the Postgres substrate rather than an auth-specific one-off.

---

## TOTP details

| Parameter | Value | Source |
|---|---|---|
| Algorithm | HMAC-SHA1 | RFC 6238 default |
| Time step | 30 seconds | RFC 6238 default |
| Code length | 6 digits | RFC 6238 default |
| Secret length | 20 bytes (160 bits) | RFC 4226 §4 R6 |
| Skew tolerance | ±1 step (90 s effective window) | RFC 6238 §5.2 small-skew recommendation |

`Totp::verify_window` walks `current ± 1` and rejects any candidate
`<= mfa_last_counter`. On a successful match, `mfa_last_counter` is
updated to the matched counter, so the same code cannot be reused within
its 90 s window even via clock-skew accommodation.

The login verify (`AuthDB::mfa_verify_login_code`) advances the counter
under a **two-layer** replay guard: the SELECT-verify-UPDATE runs as one
`SELECT … FOR UPDATE` row-locked transaction (so two concurrent submissions
of one still-valid code cannot both pass), and the counter-advancing UPDATE
additionally carries the same `RETURNING`-gated atomic-UPDATE idiom the
recovery-code path uses below (recovery has no preceding lock stage, since it
needs an app-side PBKDF2 compare first) —
`… WHERE mfa_last_counter < $matched RETURNING id`. A zero-row `RETURNING`
result means the stored counter already reached the matched value and the
submission is graded an already-consumed code — never a burned success and
never a store error. The `WHERE` guard is defense-in-depth behind the row
lock: it keeps the advance monotonic even if that isolation were ever
weakened (a read replica, a future lock-free refactor).

The constant-time string compare inside `verify_window` is moot for
6-digit codes (length leak is bounded) but defends against timing
oracles in case a future change widens the truncation.

---

## Recovery codes

10 codes per enrollment, format `XXXXX-XXXXX` (10 base32 characters with
a `-` separator inserted for readability). Stored as PBKDF2-SHA256
hashes against per-row 16-byte salts (same PBKDF2 parameters as the
password store: 100 000 iterations).

Single-use enforcement: `mfa_consume_recovery_code` finds every unconsumed
row for the user, constant-time-compares the salted hash against each
candidate (bounded wall time regardless of which row matches — no early
break, avoids leaking match position via timing), then on a Postgres schema
`UPDATE auth.mfa_recovery_codes SET consumed_at = now() WHERE id = $1 AND
consumed_at IS NULL RETURNING id` (originally, on SQLite, a
`sqlite3_changes()` check served the same role — see the root `CLAUDE.md`
`sqlite3_changes()` race note, #1033; Postgres's `RETURNING` was adopted
directly rather than porting that idiom). The `WHERE consumed_at IS NULL`
guard plus a zero-row `RETURNING` result means a concurrent consume that
wins the race is treated as no-match by the loser — race-safe without an
explicit transaction.

`mfa_regenerate_recovery_codes` deletes every row for the user (consumed
or otherwise) and issues 10 fresh ones. The UI surfaces this when
recovery_codes_remaining drops below 5 or when the operator presses
"Regenerate recovery codes". Unlike the consume path, DELETE-all + INSERT-10
is **not** self-serializing, so it takes a `SELECT … FOR UPDATE` on the
`auth.users` row first (#3779): without it two concurrent regenerates each
delete the committed rows and insert 10 (20 persist under READ COMMITTED), and
each caller is handed a set that no longer matches storage. The row lock — the
same one `mfa_verify_enrollment`, `mfa_verify_login_code`, `mfa_disable` and
`remove_user` already take for the user — orders them into clean sequential
last-writer-wins (returned == persisted for each caller in turn). The
`is_active = TRUE` predicate additionally **refuses** a regenerate once
`remove_user` has deactivated the account: the loser re-reads `is_active =
FALSE`, matches zero rows, and returns `UserNotFound` — so a regenerate racing an
account **deactivation** can never leave live recovery codes on a disabled
account. (An `mfa_disable` leaves `is_active = TRUE`, so a regenerate racing it is
serialized by the row lock but still issues codes; those are inert — a recovery
code is only consumable through an MFA challenge, which a disabled account cannot
present — and the next enroll/disable clears them. The `is_active` refusal is
specific to `remove_user`, not `mfa_disable`.)

`mfa_disable` deletes the user's recovery codes alongside clearing the
secret — leaving them around would let a disabled user authenticate via
a stale code after re-enrolling.

---

## Login flow (PR 1)

```
Browser                    Server (POST /login)             AuthDB
  │  username + password   │                                  │
  ├───────────────────────►│  verify_password(user, pw)       │
  │                        ├──────────────────────────────────►
  │                        │      Role / nullopt              │
  │                        ◄──────────────────────────────────┤
  │                        │                                  │
  │                        │  mfa_status(user)                │
  │                        ├──────────────────────────────────►
  │                        │      MfaStatus{ enrolled }       │
  │                        ◄──────────────────────────────────┤
  │                        │                                  │
  │                        │  ┌─ enrolled = false:            │
  │  Set-Cookie + 200 OK   │  │  create_local_session(…, false) →
  ◄────────────────────────│──┘                               │
  │                        │                                  │
  │                        │  ┌─ enrolled = true:             │
  │  202 + pending_token   │  │  store MfaPending{user, role, exp}
  ◄────────────────────────│──┘  return pending_token         │
  │                        │                                  │
  │  POST /login/mfa       │                                  │
  │  pending_token + code  │                                  │
  ├───────────────────────►│                                  │
  │                        │  lookup MfaPending               │
  │                        │  mfa_verify_login_code           │
  │                        ├──────────────────────────────────►
  │                        │      bool                        │
  │                        ◄──────────────────────────────────┤
  │                        │                                  │
  │  Set-Cookie + 200 OK   │  create_local_session(…, true)   │
  ◄────────────────────────│                                  │
```

The `mfa_pending_token` is opaque (32 random bytes hex-encoded), stored
in-process in `AuthRoutes::mfa_pending_`, TTL'd by
`cfg.mfa_login_pending_secs` (default 120 s), reaped lazily on every
access. Lost on server restart — the user just goes back to `/login`,
which is exactly the right UX.

Recovery codes ride the same endpoint: the handler distinguishes by
shape (`-` separator or non-6-digit length → recovery; otherwise TOTP).

---

## Step-up flow (PR 2 — design)

```
Browser                    Server (POST /api/v1/sessions)    AuthDB
  │  DELETE /sessions      │                                  │
  ├───────────────────────►│  require_permission(...)         │
  │                        │  mfa_step_up(session, "sessions.revoke")
  │                        │     │                            │
  │                        │     ├─ (now - mfa_verified_at) ≤ window
  │                        │     │      → pass, run handler   │
  │                        │     │                            │
  │  401 mfa_step_up_required ◄──┤      → return A4 envelope  │
  ◄────────────────────────│                                  │
  │                        │                                  │
  │  POST /login/mfa/stepup│                                  │
  │  code                  │                                  │
  ├───────────────────────►│                                  │
  │                        │  mfa_verify_login_code           │
  │                        ├──────────────────────────────────►
  │                        │      bool                        │
  │                        ◄──────────────────────────────────┤
  │                        │  mark_session_mfa_verified(token)│
  │                        │  mfa_mark_session_stepup(token)  │
  │                        ├──────────────────────────────────►
  │  200 OK                │                                  │
  ◄────────────────────────│                                  │
  │                        │                                  │
  │  DELETE /sessions retry│  mfa_step_up(...) → pass         │
  ├───────────────────────►│                                  │
  │  200 OK                │                                  │
  ◄────────────────────────│                                  │
```

Step-up sites (from the discovery pass): user delete + role change in
Settings; token create/revoke, session revoke, Guardian rule create /
update / delete / push, software-package create + deployment execute in
REST API v1. Eleven sites total.

`POST /api/v1/file-retrieval` was in the original discovery list but is
**not** a step-up site. It is agent-originated push-back — the only
caller is the agent's `content_dist` plugin uploading a file it
retrieved on the operator's behalf, not a browser operator acting on a
session cookie. Step-up evaluates a session's `mfa_verified_at` against
a local `users`-row enrollment; an agent upload has neither, so the gate
has nothing to evaluate. Guardian rule **delete** took its place in the
high-risk set during PR 2 governance (removing a remediation rule is as
destructive as updating one), keeping the count at eleven.

---

## Enforcement modes (PR 3 — shipped)

`Config::mfa_enforcement` (CLI `--mfa-enforcement`, env
`YUZU_MFA_ENFORCEMENT`):

- `optional` (default) — users may enrol themselves, but login does not
  require it. Operators get a self-service security posture.
- `admin-only` — an admin without MFA must enrol before login completes.
  Non-admins are unaffected.
- `required` — same enforcement for every role.

**Login-time enrollment bootstrap.** A hard `POST /login` rejection would
deadlock — the Settings enrollment panel needs a session, which the
rejected user does not have. Instead the enforced un-enrolled login
reuses PR 1's pending-token machinery:

1. `POST /login` verifies the password, sees the user is un-enrolled and
   that enforcement applies, calls `mfa_init_enrollment`, and returns
   **HTTP 202** `{"status":"mfa_enrollment_required","mfa_pending_token",
   "otpauth_uri","secret_base32","expires_in"}` — no session cookie.
   Audit: `mfa.enroll.required`.
2. The login page swaps to an enrollment form (QR/secret + code field).
3. `POST /login/mfa/enroll` confirms the first TOTP code against the
   provisional secret (`mfa_verify_enrollment`), promotes it to enrolled,
   mints the **MFA-verified** session, and returns the one-time recovery
   codes. Audit: `mfa.enroll.verified` + `mfa.recovery_codes.generated` +
   `auth.login`.

The enrollment token (`MfaPending::enrollment == true`) and the login
challenge token are mutually exclusive: each endpoint rejects the other's
token type so neither can be replayed across paths. `/login/mfa/enroll`
joins the `is_login` per-IP rate-limit bucket and the per-pending
5-attempt cap, so the provisional secret can't be brute-forced. If
enforcement is configured but `auth_db` is unavailable, `/login` fails
**closed** (503) rather than minting an unprotected session.

Self-target guard: `POST /api/settings/mfa/disable` refuses to disable an
operator's own MFA while enforcement protects their role (`required` →
all roles; `admin-only` → admins). The block is audited
(`mfa.disabled`/`error`, detail `blocked: mfa_enforcement=<mode>`) and
surfaced inline in the Settings fragment. Without it an admin in a
hardened deployment could strip their own MFA and be forced back through
enrollment at the next login (or, mid-session, lose access to every
step-up-gated surface).

### Threat model — residual risks (reviewed, accepted/mitigated)

- **Enrollment-bootstrap TOFU takeover (Hermes H-1).** Under enforcement,
  an attacker who holds a victim's *password* but no second factor can,
  on a still-un-enrolled account, complete the login-time enrollment
  (bind their own authenticator, receive the recovery codes) before the
  victim ever logs in — locking the victim out. This is **not a new
  capability** vs `optional` mode (there, a password-holder can already
  enrol MFA via Settings and lock the victim out); enforcement only makes
  it more automatic by revealing the provisional secret at login. It is a
  trust-on-first-use property of any self-service enrollment. **Mitigations
  in place / tracked:** (a) the documented rollout — enrol all users under
  `optional` *before* switching to `required` (upgrading.md) leaves no
  un-enrolled account to hijack; (b) every bootstrap emits
  `mfa.enroll.required` + `mfa.enroll.verified` audit rows for SOC/SIEM
  alerting; (c) break-glass admin reset (#1226) and an out-of-band /
  admin-provisioned enrollment channel are the durable fixes (roadmap).
  The fundamental control remains "don't let the password be compromised."
- **Stale-`iat` SSO re-prompt churn / livelock (Hermes M-1 + governance
  UP-D6).** An IdP that re-issues id_tokens with a *stale* `iat` (does not
  refresh it on re-auth) can leave an MFA'd SSO session perpetually past the
  step-up window, re-prompting on every high-risk action. Under `required`
  (where a no-`amr` session is also gated, A4/B1) this becomes a hard re-SSO
  loop for high-risk endpoints rather than mere churn. Conformant IdPs
  refresh `iat` on re-authentication, which resolves it; the iat-anchoring
  is deliberate (a genuinely old MFA assertion *should* re-prompt).
  Recovery for a misconfigured IdP is the out-of-band restart in `optional`
  (a server restart, NOT an in-app login, so it survives the loop). Treated
  as an IdP-configuration limitation, documented, not worked around
  (clamping would defeat the staleness check). The future-`iat`/`nbf`
  rejection uses a generous 300 s skew (not the 60 s `exp` skew) so honest
  NTP drift does not cause a total SSO outage (UP-D4).
- **Pending-token load-shed (Hermes H-2).** The in-memory pending map is
  capped (`mfa_pending_cap_`, default 50k); at capacity `/login` 202
  issuance is load-shed with a 503 and a `yuzu_auth_mfa_pending_load_shed_total`
  counter (+ a `warn` log) for alerting. The cap bounds the O(n)-reap CPU/
  lock DoS to O(n)·rps; a time-ordered map for O(log n) reap is a tracked
  follow-up. A distributed flood of *valid-credential* logins can still fill
  the cap and 503 legitimate logins fleet-wide until reap (≤ TTL) — the
  per-IP `login_rate_limiter_` blunts single-source; distributed-with-valid-
  creds is the residual, monitored via the new counter.
- **Pending-token timing side-channel (Hermes M-2).** The "token not found"
  path returns faster than "token found, code verified"; a precise attacker
  could distinguish a valid pending token by timing. Low value (tokens are
  32-byte random, 120 s TTL, 5-attempt cap, rate-limited) and pre-existing;
  noted, not fixed.
- **Account-posture oracle (UP-15).** Under enforcement, a caller who
  already knows a valid password can distinguish "enrolled" (`200`) from
  "enforced but un-enrolled" (`202 mfa_enrollment_required`). Inherent to a
  login-time enrollment flow and only exposed post-password; accepted.
  Aggressive per-username throttling belongs to the account-lockout work
  (auth-and-authz roadmap), not here.

---

## OIDC interop (PR 3 — shipped)

Before PR 3, OIDC/SSO sessions were blanket-exempt from local step-up:
an OIDC identity lives in the IdP — `create_oidc_session` never writes a
`users` row, so there is no local TOTP secret to step up against and a
`mfa_status()` lookup for such a session returns `UserNotFound`. The PR 2
gate therefore treated `auth_source == "oidc"` like a bearer credential
and passed it unconditionally; without that exemption every OIDC session
would have failed the gate **closed** and been locked out of every gated
endpoint (PR #1199 review HIGH).

PR 3 replaces the blanket exemption with `amr`-driven gating. Microsoft
Entra and most OIDC IdPs assert the methods used to authenticate via the
`amr` claim (RFC 8176, plus the Entra-specific `mfa` value):

1. `std::vector<std::string> amr` is parsed into `IdTokenClaims`
   (`oidc_provider.cpp`, tolerating both the spec's array form and a lone
   string from non-conformant IdPs). All claim extraction is now type-
   guarded (`is_string`/`is_number`), so a malformed `sub`/`iat` on a
   signature-valid token cannot throw an uncaught `type_error` out of
   `parse_id_token` (`iat` is load-bearing in PR 3 — governance sec-M1).
2. `amr_asserts_mfa()` (in `mfa_step_up.{hpp,cpp}`) is the policy
   allowlist: `mfa`, `otp`, `hwk`, `face`, `fpt`, `iris`, `sms`, `swk`,
   `tel`. `pwd` (password-only) and the **single-factor** `pin` / `user`
   ("user presence") are deliberately excluded — admitting them would let
   a non-MFA login satisfy the gate (governance UP-7). Matching is
   case-sensitive per RFC 8176 (fail-safe: a mixed-case value is rejected,
   never wrongly admitted).
3. `/auth/callback` seeds the new session's `mfa_verified_at` only when
   `amr_asserts_mfa(claims.amr)` is true **and `iat > 0`**. **Clock-domain
   note:** since HA WS-1/1a (ADR-2002 §4) `Session::mfa_verified_at` is a
   `system_clock` (wall-clock) instant, so the handler seeds it **directly
   from the IdP `iat`** (`mfa_verified_at = system_clock::time_point{iat}`) —
   the earlier steady-clock age-projection algorithm (`steady_now − age`) has
   been removed. A stale IdP assertion still re-prompts because its seeded
   wall-clock instant is already old relative to the step-up window. A future
   `iat` is **clamped to now** (`iat > system_now` → `mfa_verified_at =
   system_now`) so an IdP-clock-ahead skew cannot mint a proof that stays
   fresh past the window; the downstream step-up gate additionally fails
   closed on any `mfa_verified_at > now` residue (see hard invariant #5). A
   missing/zero `iat` is **not** seeded (fabricating a fresh window from a
   timestampless assertion would let a replayed `amr`-without-`iat` token look
   fresh — governance UP-9); such a session simply falls into the "no proof"
   branch below, which passes.
4. `require_mfa_step_up` no longer early-exempts `oidc`. It skips the local
   `mfa_status` lookup for OIDC sessions (there is no `users` row) and:
   - **No seeded proof** (`mfa_verified_at` default — the IdP did not
     attest MFA, or omitted `iat`): the outcome is **enforcement-symmetric**
     with how a local user is treated, keyed on
     `mfa_enforcement_protects(mode, session.role)`:
     - mode does **not** protect this role (`optional`, or `admin-only` for
       a non-admin) → **PASS**. There is no second factor to step up;
       gating would 401 → `/auth/oidc/start` → silent re-SSO → same
       `amr`-less token → 401 … an infinite lockout loop for every non-MFA
       IdP (governance UP-5/UP-6). This keeps the default deployment safe
       and is never weaker than the PR 2 blanket exemption.
     - mode **does** protect this role (`required`, or `admin-only` for an
       admin) → **step up** (re-SSO). The operator required MFA for this
       principal, so an SSO login the IdP did not MFA must re-authenticate
       — symmetric with a local `required` user being forced to enrol. If
       the IdP never asserts `amr`, this is a deployment misconfiguration,
       recoverable by restarting in `optional`
       (docs/ops-runbooks/auth-db-recovery.md). (Hermes adversarial + cyber
       A4/B1 — closes the CC6.6 "enforcement that doesn't enforce on SSO"
       gap; supersedes the originally-deferred `--mfa-oidc-amr-required`
       flag by tying the behaviour to the enforcement mode itself.)
   - **Fresh `amr`-seeded proof** (within `mfa_step_up_window_secs`):
     PASS regardless of mode — the SSO login's MFA clears the gate without
     a redundant prompt.
   - **Stale `amr`-seeded proof** (older than the window): FAIL regardless
     of mode, remediation = re-SSO (`challenge_url = /auth/oidc/start`); an
     external identity has no local secret for `/login/mfa/stepup`, which
     itself rejects an OIDC caller with a precise 400 (governance cons-B1).

   (`api_token` / `mcp_token` remain unconditionally exempt.) The
   enforcement mode is threaded into `require_mfa_step_up` from the shared
   `StepUpFn` closure (server.cpp) — see hard invariant #8.

---

## Audit chain

Every transition writes to `AuditStore` via `AuthRoutes::audit_log`
(or `SettingsRoutes::audit_fn_`). The verbs are:

| Verb | When |
|---|---|
| `mfa.enroll.initiated` | `POST /api/settings/mfa/init` — secret generated |
| `mfa.enroll.required` | `POST /login` blocked an un-enrolled login under enforcement and issued an enrollment-pending token (PR 3) |
| `mfa.enroll.verified` | `POST /api/settings/mfa/verify` or `POST /login/mfa/enroll` — first code accepted |
| `mfa.enroll.failed` | First code rejected (Settings or login bootstrap) |
| `mfa.enroll.race` | Result `ok` — a concurrent verify already resolved enrollment; the benign loser, kept out of the `mfa.enroll.failed` bad-code population (#3777, CC7.2) |
| `mfa.disabled` | `POST /api/settings/mfa/disable` (`error` + `blocked: mfa_enforcement=<mode>` when the self-target guard fires) |
| `mfa.login.required` | `POST /login` returned a pending token |
| `mfa.login.verified` | `POST /login/mfa` TOTP code accepted |
| `mfa.login.failed` | `POST /login/mfa` rejected (TOTP or recovery) |
| `mfa.recovery_codes.generated` | Enrollment, regenerate, or login bootstrap |
| `mfa.recovery_code.used` | `POST /login/mfa` accepted a recovery code |

PR 2 adds `mfa.step_up.required`, `mfa.step_up.passed`,
`mfa.step_up.failed`. PR 3 adds `mfa.enroll.required` and routes
`mfa.enroll.verified` / `mfa.enroll.failed` through the new
`POST /login/mfa/enroll` bootstrap endpoint as well as Settings.

For SOC 2 evidence, the relevant compliance control is CC6.6
(privileged access). The `mfa.enroll.verified` row plus the every-login
`mfa.login.verified` row together form the "every privileged login was
MFA-verified" assertion auditors look for.

---

## Test coverage

- `tests/unit/server/test_totp.cpp` — base32 RFC 4648 vectors, RFC 6238
  Appendix B SHA-1 vectors (truncated to 6 digits), ±1 skew acceptance,
  replay rejection, `otpauth://` URI shape, CSPRNG output.
- `tests/unit/server/test_mfa_store.cpp` — temp `AuthDB`, end-to-end
  enroll → verify → login → recovery → disable → re-enroll lifecycle.
  Verifies replay protection on login codes, single-use recovery codes,
  case-and-separator-insensitive recovery code matching.
- End-to-end / UAT coverage: enroll via Settings, log out, log back in
  with TOTP code, perform an admin action. `bash scripts/start-UAT.sh`.
- `tests/unit/server/test_mfa_step_up.cpp` — gate decision tree, including
  PR 3 OIDC gating (fresh `amr` proof passes, no/stale proof → 401 with
  `challenge_url=/auth/oidc/start`) and the `amr_asserts_mfa` allowlist.
- `tests/unit/server/test_auth_routes_mfa.cpp` — route-level coverage for
  `/login/mfa` (PR 2) and the PR 3 enforcement bootstrap: enforced
  un-enrolled login → 202 enrollment challenge, `/login/mfa/enroll`
  completion, `admin-only` role-scoping, already-enrolled login still
  gets the challenge, and cross-endpoint token-replay rejection.
- `tests/unit/server/test_settings_routes_mfa.cpp` — the self-target
  disable guard under `required` / `admin-only`.
- `tests/unit/server/test_oidc_provider.cpp` — `amr` claim parsing (array,
  lone-string, and absent forms).

---

## Hard invariants (do not regress)

When extending the MFA surface (now that at-rest encryption has shipped —
see "At-rest protection" — or any later auth work) make sure none of these
regress:

1. **TOTP secrets never leave the auth store after enrollment confirms.**
   Once a user is **enrolled**, no read path returns the secret bytes —
   even `mfa_status` only reports `enrolled / disabled / count`, and
   `mfa_init_enrollment` refuses (`MfaAlreadyEnrolled`). A **provisional**
   (un-confirmed) secret is re-revealable to the already-authenticated
   caller for the duration of the enrollment window: `mfa_init_enrollment`
   on a provisional row **reuses** the existing secret rather than
   rotating it (#1227), so a second tab / retried `/login` bootstrap does
   not invalidate the QR already scanned. The provisional secret is reaped
   by `cleanup_provisional_mfa` if abandoned, bounding the re-reveal
   window. Break-glass (`--mfa-reset`, #1226) clears the secret entirely
   (it never reveals it).

   **TOCTOU guard (do not remove).** `mfa_init_enrollment` reads
   `mfa_enrolled_at IS NOT NULL` and `mfa_totp_secret` in the **same**
   `SELECT` (`auth_db.cpp`) — historically (SQLite era) this was two
   sequential statements on a `SQLITE_OPEN_FULLMUTEX` connection
   (`mfa_status()` then `load_mfa_row()`), so the "enrolled" flag and the
   secret bytes could in principle observe different points in time if a
   concurrent `mfa_verify_enrollment` stamped `mfa_enrolled_at` between
   them; the single-SELECT form now used on Postgres removes that window
   structurally rather than relying on read-ordering discipline alone. The
   reuse branch still re-checks `!existing->enrolled` before re-revealing —
   a row observed enrolled returns `MfaAlreadyEnrolled` rather than
   re-revealing a now-**confirmed** secret. Reuse is gated on a
   genuinely-provisional snapshot only; this is what keeps the "enrolled
   secrets never re-revealed" half of the invariant true under
   concurrency. A decrypt failure on the fetched blob (`SecretCodec`) is
   its own `SecretUnavailable` outcome — see the file header note in
   `auth_db.cpp` and `docs/auth-architecture.md` "MFA fails closed on
   secret-read failure" — never folded into either "not enrolled" or a
   successful reveal.

   **Re-reveal grants no new capability.** Reaching `mfa_init_enrollment`
   requires already being authenticated *as that user* (settings session,
   or a `/login` bootstrap that has already passed the password). An actor
   who can reach init can therefore already complete enrollment by binding
   their own authenticator regardless of whether the secret rotates per
   call — so reuse-vs-rotate does not expand what a password-holder can do
   to a not-yet-enrolled account. It only extends the *window* over which
   the same provisional secret is observable, bounded by
   `cleanup_provisional_mfa` (default 1h, 60s floor). Optional anomaly
   hardening (per-user init rate-limit, distinct `mfa.enroll.reused` audit
   verb, tighter window) is tracked as a follow-up, not a correctness
   requirement.
2. **Replay protection persists.** `mfa_last_counter` is the floor on
   every accepted code. Step-up verifies must update it too.
3. **`mfa_disable` is atomic against in-flight verifies.** The
   destructive UPDATE clears both the secret and all recovery codes;
   any concurrent verify either sees the old state (and matches) or the
   new state (and fails). No half-disabled "secret cleared but
   recovery codes still active" state.
4. **`mfa_pending_` token TTL is enforced on every access** via
   `reap_mfa_pending_locked`. A 5-minute window between password
   success and TOTP submission is a credential-stuffing surface — keep
   the default tight.
5. **`Session::mfa_verified_at` is `system_clock` (wall-clock), and the
   step-up window is defended two other ways.** Since HA WS-1/1a (ADR-2002
   §4) the session lifetime fields moved off `steady_clock` to wall-clock so
   they survive the durable `SessionStore` round-trip (see
   `docs/auth-architecture.md` → "Durable operator sessions (HA WS-1/1a,
   ADR-2002 §4)"). The former monotonic NTP-step resistance is replaced by:
   (a) `mfa_step_up.cpp` **fails closed on a future-dated proof** — a
   `mfa_verified_at > now` value is treated as **no proof** (re-prompt),
   never as an extended-into-the-future window; and (b) the step-up window
   is deliberately short (`mfa_step_up_window_secs`, default 300 s), so the
   blast radius of any residual clock movement is bounded to a few minutes.
   DB-primary wall-clock integrity is a monitored dependency (HA WS-11).
6. **Audit on every gate.** `audit_log` is called on success AND
   failure for `mfa.enroll`, `mfa.login`, and `mfa.step_up`. The
   CC6.6 evidence chain is the success row + the failure row together
   — losing either side breaks it.
7. **Self-target guard extends to MFA disable** (wired in PR 3). An
   operator cannot disable their own MFA while enforcement protects their
   role — `required` protects every role, `admin-only` protects admins.
8. **OIDC step-up gating is enforcement-symmetric and must not livelock the
   DEFAULT deployment** (PR 3, governance UP-5/UP-6 + Hermes A4/B1).
   `require_mfa_step_up` skips the local `mfa_status` lookup for
   `auth_source == "oidc"` (no `users` row). An OIDC session with **no**
   `amr`-seeded proof passes **iff** `mfa_enforcement_protects(mode, role)`
   is false (i.e. `optional`, or `admin-only` for a non-admin) — gating the
   default/unprotected case loops it through `/auth/oidc/start` forever
   (UP-5). Under a mode that protects the role it is gated (re-SSO), so
   enforcement actually enforces on SSO. Regressions to guard against: (a)
   failing closed on the missing `users` row — locks out every SSO operator
   (original PR #1199 HIGH); (b) gating the no-proof case **under
   `optional`** — the UP-5 livelock for the default deployment; (c)
   *passing* the no-proof case **under `required`** — the CC6.6 enforcement
   gap (Hermes A4/B1). The enforcement mode must stay threaded into the
   gate. The seeded timestamp is a wall-clock (`system_clock`) instant and must
   keep its future-dated-proof fail-closed handling (#5), and `/login/mfa/stepup`
   must keep rejecting OIDC callers.
