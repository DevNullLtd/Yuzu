# Authentication

Yuzu supports multiple authentication methods: local password auth with session cookies, OIDC single sign-on, and API tokens for automation. All methods funnel into the same RBAC system once a principal is identified.

## Local Password Authentication

### First-Run Setup

On first launch, the server prompts interactively for admin credentials. These are stored in `yuzu-server.cfg` with PBKDF2-hashed passwords.

> **The config file is a seed, not the password store.** On the first boot against an empty PostgreSQL `auth` schema the server provisions the config file's admin into the AuthDB (`auth.users`). From then on the AuthDB row is the only credential that is checked at login: editing a hash in `yuzu-server.cfg` (or regenerating the file) no longer changes an existing account's password (#5274). Change or reset passwords in the product instead — see [Changing and resetting a local password](#changing-and-resetting-a-local-password).

```
$ ./yuzu-server
No admin account found. Let's create one.
Username: admin
Password: ********
Confirm:  ********
Admin account created.
```

### Login

Authenticate by posting credentials to `/login`. The server returns a `yuzu_session` cookie.

```bash
curl -s -c cookies.txt -X POST http://localhost:8080/login \
  -d "username=admin&password=s3cret"
```

On success the response is a `200 OK` with a JSON body `{"status":"ok"}` and a `Set-Cookie` header containing the `yuzu_session` token. **For users enrolled in TOTP MFA the response is HTTP 202** with body `{"status":"mfa_required","mfa_pending_token":"<opaque>","expires_in":120}` and no cookie — the operator must complete the challenge by posting the pending token + a 6-digit TOTP code (or a `XXXX-XXXX-XXXX-XXXX` recovery code) to `/login/mfa`, which then mints the session cookie. Under MFA enforcement (`--mfa-enforcement=admin-only|required`) an **un-enrolled** user instead receives a 202 with `{"status":"mfa_enrollment_required", ...}` and must enroll via `/login/mfa/enroll` first — distinguish the two 202 cases by the `status` field. See the [Multi-Factor Authentication (TOTP)](#multi-factor-authentication-totp) section below for the full flow. The `cookies.txt` file now contains the session cookie. Use it on subsequent requests:

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/me
```

```json
{
  "data": {
    "username": "admin",
    "role": "admin"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

All REST API v1 responses are wrapped in this envelope. The `data` key holds the payload, and `meta` contains the API version. List endpoints also include a `pagination` key.

### Changing and resetting a local password

Local accounts (created in Settings → User Management, by `POST /api/settings/users`, or the first administrator provisioned from the config file on first boot) have a password that can be changed in the product (#5342). SSO accounts (OIDC/SAML principals) and SCIM-provisioned accounts have no local password; their credentials are managed at the identity provider, and both routes below refuse them with `409` "not a local account". (First-run setup creates the administrator only, and the Windows installer no longer accepts `/OPERATOR_USER`/`/OPERATOR_PASS` (#5343): a second account written to the config file alone is never provisioned into the auth store and cannot sign in. A leftover config entry with no stored account is named in a warning at boot.)

**`yuzu-server.cfg` does not change a password (#5274).** Login reads the PostgreSQL auth store only. The config file seeds the first administrator into an **empty** database and is otherwise ignored for credentials, so editing it, regenerating it, or re-running the Windows installer does not change an existing account's password (the installer refuses `/ADMIN_PASS` on an upgrade). Because it re-seeds an empty database, a rebuild onto a fresh database brings back the password the file holds — change it in the product afterwards.

**Password policy.** A new password must be **12 to 1024 bytes** (UTF-8 bytes, not characters). The same bounds apply to account creation, and `/login` answers a password over 1024 bytes exactly like a wrong one, without hashing it.

**Change your own password.** In the dashboard: Settings → User Management → **Change password** on your own row (current password, new password, confirmation). Over REST: `POST /api/v1/users/me/password` with `{"current_password": "...", "new_password": "..."}`. Only a signed-in **local** dashboard session can do this — an OIDC/SAML session gets `409`, and an API, MCP, engine or service-scoped token gets `403`. If your account has MFA enrolled, a fresh step-up proof is required (see below).

- A wrong current password counts as a failed login attempt for [account lockout](server-admin.md#server-cli-flags), exactly like a wrong password at `/login`. Wrong password and locked account both answer `403` "current password is incorrect" — there is no lock-state oracle; the audit row records which it was. If the password could not be checked at all (the auth store could not be read, or the password changed at that moment), the answer is a retryable `503` and nothing counts toward lockout.
- **The new password and the sign-out of every session of the account — including the one you are using, and on every server in an HA cluster — happen in one step**, together with the audit record: all of it is saved, or none of it. No replacement session is issued: the response clears your cookie and you sign in again with the new password (the dashboard sends you to the sign-in page). If the change is refused or fails, nothing changed and your session still works. An unfinished MFA enrolment (a TOTP secret issued but never confirmed) is discarded (except the narrow revoked-session window described as R14 in [docs/auth-architecture.md](../auth-architecture.md)); an enrolled second factor is kept. API tokens are not affected.
- Under `--auth-mode=sso-only` only the configured break-glass account, and only while it is armed, can change its own password; any other local account — or the break-glass account once disarmed — gets `403` without its password being checked.

**Reset another user's password (admin).** In the dashboard: Settings → User Management → **Reset password** on any other local account's row (new password and confirmation). Over REST: `POST /api/v1/users/{username}/password` with `{"new_password": "..."}`. It requires a **durable Administrator**, checked the same way as RBAC role assignment — not an ordinary permission:

- With RBAC off, your own account (re-read from the auth store) must hold the `admin` role. An OIDC session whose admin role comes only from IdP group mapping does not qualify.
- With RBAC on, you must hold an `Administrator` grant as a user principal. A group-held grant, a JIT elevation, or a custom role holding `UserManagement:Write` does not qualify.

A caller who does not qualify gets `403` (`durable_admin_required`); if the stores cannot confirm your authority, `503`. The same rule applies whatever the target's role. The request must come from an interactive dashboard session — tokens of every kind are refused — and passes the shared MFA step-up gate (a fresh proof when you are MFA-enrolled; a SAML session is refused `403` there, as SAML has no MFA attestation yet).

- You cannot reset your **own** password this way (`403`); use the change route above, which requires your current password.
- You cannot reset the configured break-glass account (`403`): it is re-keyed out of band, or by signing in as it while armed and changing its own password.
- In one step, all-or-nothing together with the audit record: the new password is written, every dashboard session of the target is signed out, an unfinished MFA enrolment is discarded (except the narrow revoked-session window described as R14 in [docs/auth-architecture.md](../auth-architecture.md)), and any lockout on the account is cleared (`lockout_cleared` is `true` only when there was a lockout to clear). A refused or failed reset changes nothing. **The target's API tokens are NOT revoked**; the response reports how many are still active (`api_tokens_active`, or `null` with `api_tokens_unknown` when it could not tell), and the dashboard toast says so.
- **If the account may be compromised**, a reset alone is not enough: an attacker may hold an **enrolled** second factor (a reset deliberately keeps an enrolled TOTP secret and its recovery codes) and API tokens. Also clear MFA on the server host with `yuzu-server --mfa-reset <username>` (see [Emergency MFA disable](../ops-runbooks/auth-db-recovery.md#emergency-mfa-disable-break-glass)) and revoke the account's tokens with `DELETE /api/v1/tokens/{id}`. `--mfa-reset` removes the enrolled second factor and its recovery codes and leaves the account **password-only**: the user is walked through a fresh enrolment at their next sign-in only when `--mfa-enforcement` covers them (`required`, or `admin-only` for an admin account). Under the default `optional` nobody is prompted — an admin re-enrols in Settings → Security and sign-in → Two-factor sign-in, and a non-admin account has no self-service enrolment page (#5353), so it stays password-only until enforcement is turned on.

**Both routes:** the request must come from the dashboard's own origin (`Origin`/`Referer` checked; `403` otherwise) with `Content-Type: application/json` (`415` otherwise); the password is never logged, audited or echoed back. Setting the **same** password as the current one is accepted: it is stored with a fresh salt and, like any change or reset, signs out every session of the account. The change is recorded as `user.password_change` (self) or `user.password_reset` (admin) in the same database transaction as the change: if that audit row cannot be written, nothing is changed and the request fails with `503` (`audit_unavailable`, `Sec-Audit-Failed: true`) — there is no "changed but unrecorded" state. A `503` from either route means nothing was changed unless the server lost contact with the database at the very moment of saving; a successful sign-in with the new password confirms the change, which is then audited too. There is deliberately **no MCP tool** for either action — see `rest-api.md` for the full contract and the parity exception (#5357 tracks a temporary-password reset tool).

Non-admin users cannot open Settings, so for them the self-service change is REST-only today (`POST /api/v1/users/me/password` from a signed-in browser session; #5353 tracks a self-service account page).

### Multi-Factor Authentication (TOTP)

Yuzu supports RFC 6238 TOTP (Time-based One-Time Passwords) as a second factor for operator login. Works with every standard authenticator app (Google Authenticator, 1Password, Authy, Microsoft Authenticator). SOC 2 CC6.6 — see `docs/auth-mfa-design.md` for the full design.

#### Enrollment

1. Sign in as an admin. Navigate to **Settings → Security and sign-in** and find the **Two-factor sign-in** panel.
2. Click **Set up two-factor**. The server generates a fresh 20-byte secret and renders it as an **inline QR code** in the page, plus the base32 secret and `otpauth://` URI as text for manual entry — a one-time reveal (`Cache-Control: no-store` is set so the response will not be cached by browsers or proxies).
3. Scan the QR code with your authenticator app, or type the base32 secret in manually if you can't scan.
4. Enter the next 6-digit code shown by your authenticator app and click **Confirm**.
5. The server confirms enrollment and reveals 10 single-use recovery codes in the format `XXXX-XXXX-XXXX-XXXX` (80 bits of entropy). **Save the codes somewhere safe** — they are shown exactly once.
6. From now on, every login by this account will prompt for a TOTP code after the password.

#### Login with MFA enrolled

Browser flow: the login page automatically detects the 202 response and swaps to a TOTP code prompt. Programmatic / `curl` flow:

```bash
# Step 1 — post credentials. Response is 202 + mfa_pending_token if MFA enrolled.
curl -s -X POST http://localhost:8080/login \
  -d "username=admin&password=s3cret"
# {"status":"mfa_required","mfa_pending_token":"abc…64hex","expires_in":120}

# Step 2 — post the pending token + TOTP code (or a recovery code) to /login/mfa.
curl -s -c cookies.txt -X POST http://localhost:8080/login/mfa \
  -d "mfa_pending_token=abc…64hex&code=123456"
# {"status":"ok"}  — cookies.txt now has the session cookie.
```

Recovery codes work on the same endpoint — paste the `XXXX-XXXX-XXXX-XXXX` form. The server distinguishes by shape: exactly 6 ASCII digits is interpreted as TOTP, anything else routes through recovery-code validation. Each pending token allows at most 5 attempts before being invalidated.

#### Regenerating recovery codes

Settings → Security and sign-in → Two-factor sign-in → **Regenerate recovery codes**. The 10 prior codes (consumed or not) are deleted atomically and 10 fresh codes are revealed.

#### Disabling MFA

Settings → Security and sign-in → Two-factor sign-in → **Disable two-factor**. Clears the secret + all recovery codes. After disable, the user falls back to password-only login.

#### Recovery when locked out

If a user loses both their authenticator and all 10 recovery codes (or is locked out by MFA enforcement), an operator clears their MFA on the server host with the audited break-glass command `yuzu-server --mfa-reset <username>`. See `docs/ops-runbooks/auth-db-recovery.md` "Emergency MFA disable" for the full procedure (it writes an `mfa.reset.breakglass` audit row; a direct-SQL fallback is documented for hosts without the binary).

#### Configuration flags

| Flag | Default | Description |
|---|---|---|
| `--mfa-enforcement` | `optional` | `optional`: login never requires it; an administrator can enrol its own account in Settings, but the Settings enrolment routes are administrator-only, so a non-admin cannot enrol itself (see [Enrolling a non-admin approver](../ops-runbooks/auth-db-recovery.md#enrolling-a-non-admin-approver)). `admin-only`: an admin without MFA must enroll before login completes. `required`: every role must enroll. Under `admin-only`/`required` an un-enrolled login is redirected through TOTP enrollment (`POST /login/mfa/enroll`) before a session is minted; the startup log emits an `INFO` line naming the active mode. **Breaking:** in releases before this one these values were accepted but a no-op — see `docs/user-manual/upgrading.md` before enabling. For SSO users see "MFA on SSO sessions" below — your IdP must assert an `amr` MFA method. |
| `--mfa-step-up-window-secs` | `300` | Seconds after a TOTP proof during which high-risk endpoints accept the session as "stepped up" without re-prompting. Set to `0` to disable the step-up gate on every endpoint except JIT elevation (`POST /api/v1/elevate` and the elevation-eligibility routes), which keeps a 300s window (escape hatch — emits a startup `WARN`). It does **not** switch off the MFA requirement on approval approve/reject: those routes always require an enrolled factor and a proof made within the last `min(this value, 300)` seconds (300 when this is `0` or negative), see "Approver MFA requirement" below. |
| `--mfa-login-pending-secs` | `120` | Lifetime of the intermediate `mfa_pending_token` between password success and TOTP submission. The pending state lives in process memory and is lost on server restart. |

Each flag also accepts the matching `YUZU_MFA_*` environment variable.

#### Audit verbs

Every MFA state transition emits an audit row (`docs/user-manual/audit-log.md` lists the full vocabulary). The verbs are:

- `mfa.enroll.initiated` — secret generated, awaiting verify
- `mfa.enroll.required` — `POST /login` blocked an un-enrolled login under enforcement and issued an enrollment-pending token (PR 3)
- `mfa.enroll.verified` — first code accepted; enrollment is live (Settings or the `POST /login/mfa/enroll` bootstrap)
- `mfa.enroll.failed` — first code rejected (Settings or login bootstrap)
- `mfa.enroll.race` — an already-enrolled account (a concurrent verify won the race); audited distinctly from a rejected code, kept out of the bad-code population (#3777, CC7.2)
- `mfa.disabled` — operator or admin cleared the secret (`error` + detail `blocked: mfa_enforcement=<mode>` when the self-target guard refuses a disable under enforcement)
- `mfa.login.required` — `POST /login` returned a 202 pending challenge
- `mfa.login.verified` — `POST /login/mfa` TOTP accepted, session minted
- `mfa.login.failed` — `POST /login/mfa` rejected the code or the pending token
- `mfa.recovery_codes.generated` — 10 codes issued (enrollment or rotation)
- `mfa.recovery_code.used` — one code consumed on login
- `mfa.step_up.required` — high-risk endpoint returned a 401 because the session's MFA proof was stale (PR 2)
- `mfa.step_up.passed` — `POST /login/mfa/stepup` accepted, session's MFA proof refreshed (PR 2)
- `mfa.step_up.failed` — `POST /login/mfa/stepup` rejected the code (PR 2)
- `mfa.reset.breakglass` — MFA enrollment cleared via `yuzu-server --mfa-reset <username>`; principal is the OS account that ran the CLI (not an authenticated session). Written to `audit.db` even when the server is not running in serving mode (#1226)

`auth.login` is also emitted on every successful MFA login alongside `mfa.login.verified` / `mfa.recovery_code.used`, so SIEM rules keying on `auth.login` for session-creation parity stay correct across password, OIDC, and MFA flows.

#### Step-up on high-risk surfaces (PR 2)

These REST + Settings endpoints (token mint/revoke/rotate/confirm, admin session revoke, software package create / deployment start, Guardian rule create/update/delete/push, the full engine-principal lifecycle — create/delete, credential mint/rotate/confirm, role grant/revoke, transfer-owner — account unlock, local password change and admin password reset, user delete, user role change, approval approve and reject (`POST /api/approvals/{id}/approve|reject`, see [Who can approve](instructions.md#who-can-approve); these two apply the stricter [approver rule](#approver-mfa-requirement-6079) instead of this gate), and the two JIT admin-elevation endpoints, which use the same gate with the step-up window floored to 300s so elevation always requires a fresh proof) require a fresh MFA proof on the calling session before the mutation lands. If the proof is older than `--mfa-step-up-window-secs`, the endpoint returns HTTP `401` with an A4 envelope:

```json
{
  "error": {
    "code": 401,
    "message": "MFA step-up required",
    "correlation_id": "req-...",
    "remediation": "POST /login/mfa/stepup with current TOTP code or a recovery code, then retry"
  },
  "meta": {
    "api_version": "v1",
    "mfa_step_up_required": true,
    "challenge_url": "/login/mfa/stepup"
  }
}
```

Dashboard HTMX flows auto-intercept this envelope and prompt the operator inline (no context-switch). Programmatic clients should:

1. Detect the 401 + `meta.mfa_step_up_required == true`.
2. POST `code=<6-digit TOTP or recovery code>` (form-encoded) to `meta.challenge_url` (`/login/mfa/stepup` by default) on the same session cookie.
3. On `200 OK`, retry the original request — the session is now "stepped up" for `--mfa-step-up-window-secs` seconds.

API token / MCP token principals **bypass step-up entirely** on the endpoints above — the token itself was issued as a long-lived bearer credential through an authenticated session and does not re-prompt. Step-up applies to session-cookie principals only. **Exception: approval approve and reject do not accept a bearer credential at all.** An API-token or MCP-token session is refused with `403` rather than passed through, and the MCP tools `approve_request` / `reject_request` always return a typed refusal (the MCP transport runs no step-up); human review requires an interactive cookie session plus step-up. Approve and reject do not use the generic gate described above; see "Approver MFA requirement" below.

#### Approver MFA requirement (#6079)

The generic gate can only ask for a factor the account has, so it passes an account with no enrolled factor. Approve and reject therefore enforce a stricter rule of their own. The session must be interactive (local or OIDC) and its own identity must show a recent second-factor proof; nothing is looked up by username for an SSO identity, so a local account that happens to share a name with an SSO user is never consulted.

| Session | Requirement | Refusal |
|---|---|---|
| Local | Account has an enrolled TOTP factor, and a proof within the approver window that was not made before the current enrolment (disable then enrol again invalidates older proofs). | `403` `approver_assurance_required:mfa_not_enrolled`; `403` `approver_assurance_required:account_unavailable` when the session's account is deleted, deactivated or has an invalid username (sign in again or contact an administrator); a stale proof is the `401` step-up envelope (`mfa.step_up.required` audit row, detail `reason=proof_predates_enrolment` for a pre-enrolment proof) |
| OIDC | The identity provider asserted an MFA-method `amr` on an ID token issued (`iat`) within the approver window. This is **not** a second factor presented again at approval time. | `403` `approver_assurance_required:mfa_proof_missing` when no MFA `amr` seeded a proof; a stale proof is the `401` envelope with `challenge_url=/auth/oidc/start`. If the provider re-authenticates silently without an MFA `amr`, the retry is the same `403`; complete provider-side MFA (for example by signing out of the provider first) before retrying. Real re-authentication at approval time is a tracked follow-up. |
| SAML | Never admitted (#4935). | `403` `approver_assurance_required:saml_mfa_unsupported` |

The approver window is `min(--mfa-step-up-window-secs, 300)` seconds, and 300 when that setting is `0` or negative. The proof age is compared in milliseconds, so a proof 300.5 seconds old is stale for an approval (the generic step-up gate compares whole seconds). The ceiling is measured on the database clock against the proof timestamp stored with the session and read afresh for each decision, so a paused virtual machine or a resumed host cannot extend it. The generic step-up gate keeps its own five-minute tolerance for clock skew and suspend; the approver gate has none. It does not depend on `--mfa-enforcement` or on `--jit-oidc-amr-elevation`, and `--mfa-step-up-window-secs=0` does not switch it off (before #6079 it did, and admitted a SAML approver). Any single MFA-method `amr` value counts, as for other SSO step-up; real re-authentication at approval time (`auth_time` with `max_age`) is a planned follow-up. An unreadable MFA store, or a stored session proof that cannot be read, answers `503` with `retry_after_ms` and increments `yuzu_auth_secret_unavailable_total{route="approval"}`.

Under `optional` and `admin-only` a non-admin local account cannot enrol itself: login enrolment fires only for accounts the mode protects, and the Settings enrolment routes are administrator-only. Such an approver is refused `mfa_not_enrolled` until an administrator enrols them; the procedure is in [Enrolling a non-admin approver](../ops-runbooks/auth-db-recovery.md#enrolling-a-non-admin-approver). Disabling MFA on an account or running `--mfa-reset` does not end that account's existing sessions (session invalidation is a planned follow-up); the proof-versus-enrolment comparison is what stops an older proof being reused after re-enrolment.

#### MFA on SSO sessions (PR 3)

OIDC/SSO sessions carry no local TOTP secret, so they cannot use `/login/mfa/stepup` (it returns `400` for an OIDC caller, pointing back to SSO). Instead, the step-up gate honours the IdP's RFC 8176 `amr` claim:

- If the IdP attested a multi-factor login (`amr` contains `mfa`, `otp`, `hwk`, `fpt`, `face`, `iris`, `sms`, `swk`, or `tel`), the session is treated as stepped-up. Once that proof ages past `--mfa-step-up-window-secs`, high-risk endpoints return `401` with `challenge_url=/auth/oidc/start` — the operator re-authenticates through SSO to refresh it.
- If the IdP did **not** attest MFA, the outcome depends on the enforcement mode, symmetric with how a local user is treated:
  - Under `optional` (or `admin-only` for a non-admin SSO user): the session **passes** the gate. Yuzu cannot mint a second factor for an externally-owned identity, so for the default posture MFA on SSO is the IdP's responsibility.
  - Under `required` (or `admin-only` for an admin SSO user): the session is **gated** — high-risk endpoints return `401` pointing to re-SSO. The operator required MFA for this principal, so an SSO login the IdP did not MFA must re-authenticate (just as a local `required` user is forced to enrol).

Approving or rejecting an approval request is the exception: it needs an MFA-method `amr` on a recent ID token in every `--mfa-enforcement` mode (see [Approver MFA requirement](#approver-mfa-requirement-6079)), so `optional` does not remove the need for the identity provider to assert `amr` for approvers.

**Therefore, before turning on `--mfa-enforcement=required` (or `admin-only` for admin SSO users), configure your IdP to assert `amr` and verify it pre-flight** — otherwise those SSO users will be unable to reach high-risk endpoints (recoverable by restarting in `optional` temporarily (it weakens MFA fleet-wide, so restore your intended enforcement afterwards); see the runbook). Under `optional`, no IdP `amr` configuration is required.

#### Login-time enrollment (PR 3)

Under `--mfa-enforcement=admin-only|required`, an un-enrolled login does not 200. `POST /login` (after a valid password) returns a second 202 variant distinguished by `status`:

```json
{"status":"mfa_enrollment_required","mfa_pending_token":"<opaque>","otpauth_uri":"otpauth://...","secret_base32":"...","expires_in":120}
```

The browser shows the QR / secret, the operator scans it, and posts the pending token + the first 6-digit code to **`POST /login/mfa/enroll`**, which confirms enrollment, mints an MFA-verified session cookie, and returns the one-time recovery codes:

```bash
curl -s -c cookies.txt -X POST http://localhost:8080/login/mfa/enroll \
  -d 'mfa_pending_token=<from-202>&code=123456'
# {"status":"ok","recovery_codes":["XXXX-XXXX-XXXX-XXXX", ...]}
```

The recovery codes are revealed **once** here, exactly as in Settings enrollment — save them before continuing. The endpoint shares the `/login` rate-limit bucket and the 5-attempt-per-pending cap. If `auth_db` is unavailable the enforced login fails closed (`503`) rather than minting an unprotected session.

### Logout

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/logout
```

Returns `200 OK` with `{"status":"ok"}`. The session is invalidated server-side and the `yuzu_session` cookie is cleared via `Set-Cookie` with `Max-Age=0`.

### Session lifetime

Dashboard cookie sessions have an **absolute lifetime of 8 hours** from login. When this expires the operator is redirected to the sign-in page at `/home`, which remembers the screen that was requested (see `GET /home` in [server-admin.md](server-admin.md)). Sessions are also invalidated server-side by an **explicit action** — logout, session revocation (Settings → User Management → Revoke sessions, or "Sign out everywhere"), a role change, or removing elevation eligibility. For Postgres-backed deployments a session is a durable row (`SessionStore`, HA WS-1/1a, ADR-2002 §4) and therefore **survives a server restart** — a restart no longer drops it. Only config-file-only (non-Postgres) deployments keep the old behavior where a restart clears all sessions. See `docs/auth-architecture.md` "Durable operator sessions (HA WS-1/1a, ADR-2002 §4)".

An optional **idle (inactivity) timeout** can shorten this. When `--session-inactivity-secs` (`YUZU_SESSION_INACTIVITY_SECS`) is set to a positive value, a session idle longer than that window is invalidated server-side and the operator is prompted to log in again — regardless of the 8-hour absolute limit. The default `0` disables it (only the absolute lifetime applies). The window is **sliding**: any authenticated request resets it. Scope is **cookie sessions only** — API tokens and MCP tokens are never idle-timed-out, and OIDC users simply re-authenticate via SSO. A recommended hardened value is `900` (15 minutes).

See [Server Administration — CLI flags](server-admin.md) for configuration and `docs/auth-architecture.md` "Inactivity session timeout" for design detail.

### Auth Middleware Behavior

| Client type | Unauthenticated behavior |
|---|---|
| Page request (path does not start with `/api/` or `/events`) | 302 redirect to `/home` (the sign-in landing page), with `?next=<screen key>` when the path is one of its screens |
| API request (path starts with `/api/` or is `/events`) | `401 Unauthorized` with JSON error body `{"error":"unauthorized"}` |

The middleware distinguishes browser from API by request path, not by the `Accept` header.

## HTTPS

Enable TLS for the dashboard and REST API with CLI flags:

| Flag | Default | Description |
|---|---|---|
| `--https` | off | Enable HTTPS listener |
| `--https-port` | `8443` | HTTPS listen port |
| `--https-cert` | (required) | Path to PEM certificate file |
| `--https-key` | (required) | Path to PEM private key file |
| `--no-https-redirect` | off | Disable automatic HTTP-to-HTTPS redirect |

Example:

```bash
./yuzu-server \
  --https \
  --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key
```

When HTTPS is enabled (the default), plain HTTP requests are redirected to HTTPS by default, except `GET`/`HEAD` on the four health-probe paths (`/livez`, `/readyz`, `/health`, `/api/health`), which are served directly. Pass `--no-https-redirect` to not start the HTTP listener at all (HTTPS only; see server-admin.md).

```bash
# Verify HTTPS is working
curl -s --cacert /etc/yuzu/ca.crt https://localhost:8443/api/v1/me \
  -b cookies.txt
```

## OIDC Single Sign-On

Yuzu supports OpenID Connect with PKCE for browser-based SSO against a provider that serves OpenID Connect Discovery (`{issuer}/.well-known/openid-configuration`). Verified end to end against Keycloak 26.4.0 (Linux test host, plain `http` and `https` via a TLS-terminating proxy). Microsoft Entra ID is supported by the standard (endpoints and keys come from its discovery document) but has not been verified end to end by the project; use the manual procedure below.

Yuzu reads the authorization endpoint, token endpoint and `jwks_uri` from the discovery document the first time a sign-in needs them; it never derives them from the issuer URL.

- **The issuer must match byte for byte.** The configured issuer must match the discovery document's `issuer` and the tokens' `iss` byte for byte, including any trailing slash. Copy it from the IdP's discovery document. (Yuzu removes one trailing slash only to build the discovery URL.) An issuer holding a query (`?`) or a fragment (`#`) is refused (`the issuer must not contain a query or fragment`), because OpenID Connect Discovery defines an issuer with neither.
- **Endpoint rules.** Every endpoint in the document must be an absolute URL with the same scheme as the issuer, at most 2048 bytes, with no fragment (`#`, for every discovered endpoint including `jwks_uri`; a query is allowed and is kept: the sign-in redirect appends its parameters with `&`, and the authorization endpoint's query must not use the names of the OAuth request parameters Yuzu adds: `client_id`, `response_type`, `scope`, `redirect_uri`, `state`, `nonce`, `code_challenge` and `code_challenge_method`, compared ASCII case-insensitively after percent-decoding; a query on the token endpoint is kept too, and a test pins the request target the IdP receives on Linux, macOS and Windows), and a plain `host[:port]` authority (a host of at most 253 bytes, a port from 1 to 65535, no user info). An IPv4-mapped IPv6 literal such as `[::ffff:1.2.3.4]` is rejected on purpose: the HTTP client library cannot represent it. Use the IPv4 address or a host name. The document must list all three of `authorization_endpoint`, `token_endpoint` and `jwks_uri`.
- **Entra issuer.** Use the tenant-ID form, `https://login.microsoftonline.com/<tenant-guid>/v2.0`. A tenant domain name, `common` and `organizations` do not give an issuer that equals the document's, so they fail the exact issuer check.

**Test Connection.** In Settings, "Test Connection" fetches and validates the discovery document with the validation a sign-in applies, for the issuer typed in the form (the saved issuer when the field is blank), then fetches the `jwks_uri` and reports how many signing keys it found. The two requests run one after the other, each with its own total bound (see Timing below), so one click can take up to about 20 s in the worst case (a slow discovery document followed by a stalled JWKS fetch); a dead IdP fails at the discovery step. The typed issuer and the `jwks_uri` it leads to are subject to the same egress policy as a sign-in (see "Network and trust"): an internal address is refused with `address not permitted by the OIDC egress policy` unless the server runs with `--oidc-allow-private-networks`, and link-local and cloud-metadata addresses are always refused. It checks discovery and signing keys only: it does not exercise the token endpoint, the client secret, the redirect-URI registration, the audience or the group claims. Step 4 of the procedure below is the real sign-in test.

**Test Connection is a connectivity check, not a guarantee of what a sign-in will hit.**

- It makes its own requests and never reads or clears the running provider's state: the 30 s no-retry window after a failed discovery and the mark that another sign-in is fetching discovery. It can be green while sign-ins are being refused by either.
- It uses the issuer typed in the form, which may differ from the issuer the running provider was built with.
- It skips TLS verification when the form's `skip_tls_verify` checkbox is ticked OR the server's current `skip_tls_verify` value is true (the value the form shows ticked), so unticking the box cannot turn verification on while that value is true. That value is the `--oidc-skip-tls-verify` flag at start, replaced by the stored Settings value once boot has applied it, and by the form's value after a save. The running provider keeps the value it was built with (the flag at start; the form's value after a save), so after a restart with a stored Settings value that differs from the flag the two disagree.

### Manual verification against a real IdP

The unit tests run against a loopback IdP, not a real one. To check a real provider, use this procedure (Keycloak is the quickest to stand up locally). The sign-in itself was verified against Keycloak 26.4.0, over plain `http` and over `https` on a Linux test host; the admin-console paths below follow that version's console, so correct them if your console differs:

1. Run Keycloak and create a realm. Create the client (Clients > Create client): in the wizard's Capability config step switch **Client authentication** On (that is what makes it a confidential client; the default is Off) and leave the standard flow enabled, and in the Login settings step enter `https://<yuzu-host>/auth/callback` (or your `--oidc-redirect-uri`) as a Valid redirect URI. After creating the client, open its Settings tab and check the stored Valid redirect URIs: the value must be exactly the callback URL you entered, with no `/*` appended. The client secret is on the client's Credentials tab. For the admin mapping, open Clients > your client > Client scopes > the `-dedicated` scope. While it has no mappers, click **Configure a new mapper**; once one exists the button is Add mapper > By configuration. Choose Group Membership and set Token Claim Name to `groups` (the form opens with it empty), switch **Full group path OFF** (it defaults to ON) and leave Add to ID token on (the default). Create a group (Groups > Create group, for example `yuzu-admins`) and add your test user to it (Users > the user > Groups > Join group: tick the group, then click Join).
2. Start the server with `--oidc-issuer https://<keycloak>/realms/<realm>`, the client id and secret, `--oidc-redirect-uri` (set it explicitly: when omitted it defaults to `http(s)://localhost:<port>/auth/callback`) and `--oidc-admin-group yuzu-admins` (the value of the entry in the token's `groups` claim; with Full group path off that is the group's name). The issuer must equal the `issuer` in `https://<keycloak>/realms/<realm>/.well-known/openid-configuration`. The sign-in page (`/home`) shows a "Sign in with single sign-on" link whichever OIDC provider is configured; it starts the same flow. Keycloak's stock endpoints (`/protocol/openid-connect/auth`, `/token`, `/certs`) need no proxy or rewriting: they come from the discovery document.
3. In Settings, click "Test Connection": it should report that it discovered the authorization, token and JWKS endpoints and how many signing keys it found.
4. Open `/auth/oidc/start`, sign in at the IdP and confirm you land in the dashboard as an administrator. Then remove the user from the group and confirm the next sign-in is not an admin session.

This procedure does not include a wrong-audience check. The refusal of a token minted for another client is covered by the unit tests (`test_oidc_provider.cpp`), and it was reproduced once against a real Keycloak through a fault proxy that swapped the client id; it is not a step of the procedure.

### Network and trust

- **Direct egress.** The Yuzu server itself must reach the issuer host, and also the hosts in the document's `jwks_uri` and `token_endpoint`, which may differ from the issuer host (some providers serve `jwks_uri` from another host). Only the authorization endpoint is visited by the browser alone.
- **ASCII host names only.** A host name that contains a byte outside ASCII is refused wherever it appears (the issuer, a discovered or a configured endpoint) with the same errors as any other malformed host (for example `the issuer has no well-formed host`), because the egress check and the Windows token request would otherwise ask the resolver for different names. Give an internationalized name in its punycode (`xn--`) form.
- **No proxy.** No HTTP(S) proxy is used on the discovery and JWKS path (no proxy setting is applied and the proxy environment variables are not read), so the server needs a direct route to those hosts. This is unchanged by the egress policy below. The one exception is the Windows token request: WinHTTP uses the system default proxy (`WINHTTP_ACCESS_TYPE_DEFAULT_PROXY`), so on a proxy-only Windows server the token step can work while discovery and the JWKS fetch fail.
- **Egress policy (which addresses the server will connect to).** Every OIDC request the server makes (discovery, the JWKS, Test Connection, and the token POST) first resolves the target host name itself and classifies EVERY address it gets, by the address bytes and not by the text (an IP-literal host is classified directly, without DNS, and an IPv4-mapped IPv6 address such as `::ffff:169.254.169.254` is classified by the IPv4 address inside it). If no address is permitted the request is not made, and the error is the fixed text `request failed: address not permitted by the OIDC egress policy` (`token endpoint request failed: ...` for the token POST), which names no address; the server log names the host and the address class. Two tiers, plus one rule on the scheme:
  - **Always refused, no switch:** unspecified addresses (`0.0.0.0/8`, `::`), link-local (`169.254.0.0/16`, `fe80::/10`, which holds the cloud metadata address `169.254.169.254`), the other cloud metadata addresses (`100.100.100.200`, `168.63.129.16`, `fd00:ec2::254`), multicast, and the reserved block `240.0.0.0/4` including `255.255.255.255`. Oracle Cloud's metadata address `192.0.0.192` is not on this list: it lies in the `192.0.0.0/24` special-purpose block, which `--oidc-allow-private-networks` admits.
  - **Refused unless the server operator sets `--oidc-allow-private-networks`:** loopback (`127.0.0.0/8`, `::1`), RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), carrier-grade NAT (`100.64.0.0/10`), IPv6 unique-local (`fc00::/7`), and other non-global blocks (documentation, benchmarking and IETF protocol-assignment ranges, and any IPv6 address outside `2000::/3`; inside it the IETF protocol-assignment block `2001::/23`, which holds Teredo `2001::/32`, IPv6 benchmarking `2001:2::/48` and ORCHID `2001:10::/28`, is non-global except the sub-ranges the IANA IPv6 special-purpose registry marks globally reachable: `2001:1::1`, `2001:1::2`, `2001:1::3`, `2001:3::/32`, `2001:4:112::/48`, `2001:20::/28` and `2001:30::/28`; a range the registry does not positively mark globally reachable is refused).
  - **Plain http to a public address is refused, with no switch.** A request over `http://` whose target address is public (an IP-literal host or a name that resolves to one) is not made, and the error is the distinct fixed text `request failed: plain http is not permitted to a public address` (`token endpoint request failed: ...` for the token POST); a public address in a mixed answer list is skipped, never connected to. `https://` to a public address is unchanged. `http://` to a loopback, private, carrier-grade NAT or unique-local address is still governed by `--oidc-allow-private-networks` alone, and stays exposed to anyone on that network path: the keys, the token response and the client secret travel unencrypted there. This is the realistic internet man-in-the-middle case closed; it does not make a private-network `http` issuer safe.
  - **NAT64.** An IPv6 address inside a NAT64 prefix is classified by the IPv4 address embedded in it, so `Pref64 + 169.254.169.254` is link-local and `Pref64 + 10.0.0.5` is private, whatever the prefix looks like on its own. Every RFC 6052 section 2.2 layout is decoded (`/32`, `/40`, `/48`, `/56`, `/64`, `/96`, including the skipped reserved octet). The server learns prefixes two ways: from the operator (`--oidc-nat64-prefix`, below) and from RFC 7050, by resolving `ipv4only.arpa` and decoding the IPv6 answers that embed `192.0.0.170` or `192.0.0.171`. The `ipv4only.arpa` lookup is made only when a request is about to be pinned to an IPv6 address that would otherwise be permitted (never for an IPv4-only request), within the request's DNS timeout, and repeated after 10 minutes when it learned a prefix and after 1 minute when it learned none; a lookup that fails or times out counts as "none discovered" and does not fail the request, because most networks have no DNS64. A learned prefix is never forgotten: later answers (empty, A-only or different) only add to the set, which is kept until the server restarts, so a resolver cannot make the server unlearn a translator it already saw. The set holds at most 64 prefixes; an answer that would exceed that is never installed partially, and requests that need the learned prefixes are refused with the fixed text `the NAT64 prefix discovery answer exceeds the supported number of prefixes` until a later answer fits. A prefix, configured or learned, is trusted to describe a translator: the embedded IPv4 address decides, so a configured prefix may permit a destination its own address class (a unique-local prefix for a private-network NAT64, say) would otherwise gate; only the always-refused tier is never relaxed. A learned prefix is only consulted for an address the built-in rules would permit, so it cannot relax a refused one. The well-known prefix `64:ff9b::/96`, IPv4-mapped IPv6 and 6to4 are decoded without any lookup. **Operator warning:** a configured prefix asserts that a NAT64 translator lives there and can permit HTTPS connections to ULA addresses even when `--oidc-allow-private-networks` is off; declare only actual translation prefixes (native IPv6 services inside a declared prefix get the same embedded-IPv4 classification; always-refused addresses remain blocked).
  - **Residual: translators the server cannot see.** A translator whose prefix is neither discoverable (no DNS64 answer for `ipv4only.arpa` on the server's resolver) nor configured, a proxy, a VPN, or CLAT/464XLAT outside the host, is invisible: an address such a path maps to a private or link-local destination is classified from its own bytes, so it can read as public. TLS verification still uses the host name, so over `https` such a path is limited to a blind TCP connect, and plain `http` to a public-looking (translated) address is refused by the rule above.

  The switch is a process-level flag (`--oidc-allow-private-networks`, env `YUZU_OIDC_ALLOW_PRIVATE_NETWORKS`, default off). It cannot be set from the dashboard, from `POST /api/settings/oidc` or from any REST body: a Settings save rebuilds the provider with the value from the server's own configuration and ignores any field of that name. An IdP on a private network (a typical self-hosted Keycloak or ADFS) needs the switch; a public IdP does not. The check applies to each request's own host, so a `jwks_uri` or `token_endpoint` on another host is vetted when it is used, not when the issuer was. On Linux and macOS the connection is then PINNED to a vetted address (TLS server-name indication and certificate verification still use the host name), so a DNS answer that changes between the check and the connect cannot redirect the request. A host with several permitted addresses is tried address by address while the connect fails. **Windows token POST:** WinHTTP resolves the name on its own and cannot be pinned, so the token request is only pre-checked (the name is resolved and classified, then WinHTTP resolves it again). Because WinHTTP may connect to any address of its own answer, the pre-check is strict: if ANY address the name resolves to is refused, the request is refused outright, even when another is permitted (elsewhere a mixed answer is pinned to its permitted address). A DNS answer that changes between those two lookups (DNS rebinding) is NOT covered on that one request. The Windows token request does not follow redirects (the WinHTTP redirect policy is set to never) and accepts only HTTP status 200, as the other platforms do: a token endpoint that answers 3xx cannot send the request on to a host that was never checked, and the sign-in fails. A Windows name lookup that does not finish even after it is canceled is kept by the server until it completes and then freed; 16 stuck lookups at once make further name lookups fail closed ("the host name did not resolve") until one completes. Discovery and the JWKS use the portable HTTP client on every platform and are pinned there too.
- **Use an https issuer.** The JWKS fetched from the issuer is the trust root for every ID token, and the client secret is sent to the token endpoint, both over the issuer's own scheme. With an `http://` issuer anyone on the network path can substitute the keys and mint a sign-in for any user, or read the client secret. The server logs a warning at start-up and at every Settings save for an `http://` issuer on a non-loopback host. An `http://` issuer (or endpoint) whose address is PUBLIC is refused outright; one on a loopback or private address is allowed only with `--oidc-allow-private-networks`, and remains exposed to anyone on that network path: use `http://` for a loopback lab only. See [Security hardening -> OIDC](security-hardening.md#oidc-hardening).
- **TLS verification.** `--oidc-skip-tls-verify` now also governs the discovery and JWKS requests, as well as the token request on Linux and macOS. The Windows token request uses WinHTTP, which ignores it. A private CA is trusted through the server's operating-system trust store; there is no OIDC-specific CA setting. On Linux the OpenSSL environment variable `SSL_CERT_FILE` also supplies trust for discovery, the JWKS request and the token POST (verified with a private CA and a failing run without it: `request failed: SSL server verification failed`); the operating-system store itself was not tested here.
- **When the IdP is contacted.** Nothing contacts the IdP at server start or when you save the OIDC settings: the first sign-in after a restart (or after a save, which rebuilds the provider) pays one discovery round trip. "Test Connection" checks reachability and trust before then, within the limits listed above.

### Server Configuration

OIDC can be configured in two ways:

**Option 1: Dashboard Settings** (convenient, but NOT durable on its own - see below; set Option 2 as well)

Navigate to **Settings → Security and sign-in** in the dashboard and use the **Single sign-on** panel (the older Settings page carries the same form under **Directory Integration / OIDC SSO**). Enter the issuer URL, client ID, client secret, and admin group ID. Fill in **Redirect URI**: it is required and must be exactly the callback URL registered at the IdP; a blank value is refused with a red message naming the field, because a provider without one never fetches discovery and `GET /auth/oidc/start` would answer `500` (only the startup flag path fills in the localhost default). Click **Test SSO** to check the issuer's discovery document and signing keys (it does not test the client ID or secret), then **Save SSO settings**; the confirmation names the admin group, because changing or clearing it signs SSO administrators in as ordinary users. The panel's status reads **Running** when the live provider is active, **Saved, not running** when the values are stored but no provider is running, and **Not configured**. Changes take effect immediately on the running server - but **only on the running server**. The provider is rebuilt at the next startup from the command-line or environment values, before the stored settings are read, and nothing rebuilds it afterwards. **If you configure OIDC only here, SSO stops working after the next restart** (the dashboard and `GET /api/config` will still show it as configured). Set the same values as CLI flags or environment variables per Option 2 as well, and see [Security hardening -> OIDC](security-hardening.md#oidc-hardening) before rotating a secret.

**Option 2: CLI flags**

| Flag | Description |
|---|---|
| `--oidc-issuer` | Issuer URL, exactly as the IdP's discovery document states it in `issuer` (e.g., Entra: `https://login.microsoftonline.com/<tenant-guid>/v2.0`; Keycloak: `https://<keycloak>/realms/<realm>`) |
| `--oidc-client-id` | Application (client) ID from the IdP |
| `--oidc-client-secret` | Client secret (required for Entra/Azure AD web apps) |
| `--oidc-redirect-uri` | Callback URL. If omitted it defaults to a localhost URL derived from the listen port (`http(s)://localhost:<port>/auth/callback`); set it explicitly for any real IdP. It must match the IdP's registration. The request `Host` header is never used |
| `--oidc-admin-group` | The value of the entry in the token's `groups` claim that maps to the admin role (the group object ID for Entra; the group name for Keycloak with Full group path off). The value is trimmed automatically, same as `--saml-admin-group` — #1830 |
| `--oidc-skip-tls-verify` | Disable TLS cert verification for OIDC discovery, JWKS and (Linux/macOS) token requests (insecure, dev only). The Windows token request ignores it |
| `--oidc-allow-private-networks` | Let the OIDC discovery, JWKS and token requests connect to loopback, RFC 1918, carrier-grade NAT and IPv6 unique-local addresses (an IdP on the internal network). Off by default. Link-local and cloud-metadata addresses stay refused either way. Env: `YUZU_OIDC_ALLOW_PRIVATE_NETWORKS`. Not settable from the dashboard (see "Egress policy") |
| `--oidc-nat64-prefix` | Comma-separated NAT64 prefixes (RFC 6052: `/32`, `/40`, `/48`, `/56`, `/64` or `/96`, for example `2001:db8:122:344::/64`) in use on this network. An IPv6 address inside one is classified by the IPv4 address it embeds (the prefix is trusted to describe a translator, so it may permit a destination its own address class would gate). Prefixes the network's DNS64 announces for `ipv4only.arpa` (RFC 7050) are learned without this flag; set it when the network does not announce them. Default: none. At most 16 entries; an unparsable entry, a length outside that set or non-zero bits after the prefix is a startup error. Env: `YUZU_OIDC_NAT64_PREFIXES`. Not settable from the dashboard (see "Egress policy") **Operator warning:** a configured prefix asserts that a NAT64 translator lives there and can permit HTTPS connections to ULA addresses even when `--oidc-allow-private-networks` is off; declare only actual translation prefixes (native IPv6 services inside a declared prefix get the same embedded-IPv4 classification; always-refused addresses remain blocked). |

Saving the OIDC settings in the dashboard, or writing an `oidc_*` key through `PUT /api/config/{key}`, needs the administrator role on your own account: a session that is administrator only through a temporary elevation is refused with `403`. A stored `oidc_admin_group` still applies after a restart.

Example startup:

```bash
./yuzu-server \
  --https --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --oidc-issuer "https://login.microsoftonline.com/abcd1234-.../v2.0" \
  --oidc-client-id "11111111-2222-3333-4444-555555555555" \
  --oidc-client-secret "your-client-secret" \
  --oidc-redirect-uri "https://yuzu.example.com:8443/auth/callback" \
  --oidc-admin-group "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

### OIDC Login Flow

1. User clicks "Sign in with single sign-on" on the sign-in page (`/home`; the link appears only when a provider is configured).
2. Browser is redirected to `GET /auth/oidc/start`, which generates a PKCE challenge, sets the browser-binding cookie, and redirects to the IdP's authorization endpoint.
3. User authenticates at the IdP.
4. IdP redirects back to `GET /auth/callback` with an authorization code. The browser presents the binding cookie.
5. Server checks the binding cookie, exchanges the code for tokens, validates the ID token, extracts claims, and creates a local session.

```
Browser           Yuzu Server               IdP
  |                    |                          |
  |-- GET /auth/oidc/start -->                    |
  |<-- 302 + Set-Cookie (binding) --|             |
  |                    |-- 302 authorize?... ---->|
  |                    |                          |
  |                    |          (user authenticates)
  |                    |                          |
  |                    |<--- 302 /auth/callback --|
  |<-- Set-Cookie -----|                          |
```

### OIDC sign-in fails

Run "Test Connection" in Settings first: it shows whether the server can fetch and validate the discovery document and the signing keys for the issuer typed in the form, which often points at the same cause as a failed sign-in but does not reproduce one (see "Test Connection" above for what it does not read). Then read the server log (a `--log-file` can trail the console output by several seconds, so give it time before concluding a line is missing).

| What you see | Log line (server log) | Meaning |
|---|---|---|
| `GET /auth/oidc/start` answers JSON `500` "could not start the SSO sign-in flow" | `OIDC auth flow could not start: OIDC discovery unavailable` | Discovery failed or is inside its 30 s no-retry window. The cause is on the earlier `OidcProvider: discovery failed for issuer <issuer>: <reason>` line. Explicit endpoint values exist only as a test seam in the provider: no flag, environment variable or Settings field sets one, so a deployment always takes its endpoints from the discovery document. Or another sign-in is fetching discovery right now: that caller gets the same `500` and the same log line with NO cause line of its own (normal at the first sign-ins after a restart or a Settings save, even when the IdP is healthy; retry in a moment). That state ends when the fetch in progress returns, which is within the total bound (10 s by default: the 5 s per-operation timeout times 2) on every platform. If sign-ins keep getting this answer with no cause line well past that, restart the server: the in-flight mark is held in memory and a restart clears it. |
| The browser lands on `/home?error=sso_failed` (via `/login?error=sso_failed`) | `OIDC callback failed: OIDC discovery unavailable` | The token request needed discovery and it failed (same cause line as above, or another sign-in is fetching discovery right now and this one got no cause line). |
| The browser lands on `/home?error=sso_failed` (via `/login?error=sso_failed`) | `OIDC callback failed: JWKS signing keys unavailable` | The signing keys could not be fetched; look for `OidcProvider: JWKS fetch failed: <reason>` (the reason is the same `HTTP <status>` or `request failed: <detail>` text as for discovery), `OidcProvider: JWKS response missing 'keys' array`, `OidcProvider: JWKS parse error: <detail>`, or `OidcProvider: discovery is unavailable, cannot fetch signing keys` (discovery failed, is inside its 30 s window, or another sign-in is fetching it; see the discovery rows above). |
| The browser lands on `/home?error=sso_failed` (via `/login?error=sso_failed`) | `OIDC callback failed: JWT signature verification failed: JWT signature verification failed ... token may be forged` (the second part carries a dash character between `failed` and `token`) | The token's signature does not verify against the key it is checked with. Every sign-in fetches the JWKS afresh and checks the token against that answer only, so a key rotation is not a failure. If a named `kid` is not in the key set just fetched, the token is refused with `...no matching JWKS key found for kid=<kid>` (a token from a different realm or tenant, or a key the IdP no longer publishes): it is never checked against another key. The first key of the fetched set is used only for a token with NO `kid` member at all; there, a mismatch produces the `token may be forged` failure above. A `kid` that is present but empty or not a string is refused (`JWT kid is not a non-empty string`). If the fetch itself fails (or the answer is not a JWKS), the result is `JWKS signing keys unavailable` instead (the row above); an answer with no usable keys gives the `no matching JWKS key found` refusal. |

The `<reason>` of a discovery failure is one of: `issuer mismatch: the discovery document names "<value>"` (the document's `issuer` is not the configured issuer); `discovery document has no <field>`; `<field> is not an absolute https URL on the issuer's scheme` (also shown for an endpoint that is over 2048 bytes, has user info, has a fragment, has a malformed `host[:port]`, or (the authorization endpoint) has a query using a reserved parameter name); `HTTP <status>` (for example `HTTP 404` when the issuer URL is wrong); `request failed: address not permitted by the OIDC egress policy`, `request failed: plain http is not permitted to a public address` or `request failed: the host name did not resolve` (see the egress policy under Network and trust); `request failed: <detail>` (a refused or timed-out connection, a TLS failure, a connection cut at the total time bound, or a body over 256 KiB; a redirect is not followed and shows as `HTTP 302`); `request exception: <detail>` or `discovery exception: <detail>` (the HTTP client or the discovery code threw; the detail is the exception text); `discovery response is not valid JSON: ...` or `discovery response is not a JSON object`; `the issuer must be an http or https URL`, `the issuer must not contain a query or fragment`, `the issuer is longer than 2048 bytes`, `the issuer contains a space or control character`, or `the issuer has no well-formed host`. Because the reason can carry IdP-controlled text, it is passed through `log_key_token` before it is logged: control bytes, DEL and the Unicode line breaks NEL, U+2028 and U+2029 become `_`, and a reason longer than 256 bytes is shortened to its head and tail joined by `~`. The issuer inside `issuer mismatch: ...` is folded more strictly by `log_token` (it also turns spaces, `=` and `,` into `_`) and is cut at 200 bytes.

- **Timing.** Each discovery or JWKS request has per-operation timeouts of 5 s (connect, read and write) and a total bound of 2 x the per-operation timeout (10 s by default) from the start of the request. The bound covers name resolution (on Linux and macOS the resolver is capped at the per-operation timeout, rounded up to whole seconds, where the HTTP client library is built with its non-blocking resolver: true of the Linux build, not checked for macOS. On Windows the server runs its own overlapped lookup and cancels it at that same timeout, then waits up to 5 s more for the canceled lookup to finish, so a name lookup there can add up to 5 s beyond the per-operation timeout), the connect, the TLS handshake and the response. A host with several permitted addresses is tried one address at a time (at most four) while the connect fails, and each connect is bounded by the 5 s connect timeout. A dead or very slow IdP can therefore hold a sign-in for about 10 s per request.
- **How the bound is enforced.** A watchdog shuts the socket down at the deadline and again every 50 ms, because a shutdown issued before the connection completes does not persist on macOS (measured). The token-exchange POST is not covered: it has per-operation timeouts only (Linux and macOS: 10 s connect, 15 s read, 15 s write; Windows: the WinHTTP defaults) and no total bound; its response is capped at 256 KiB on every platform (a larger reply fails the sign-in with `token endpoint request failed: <detail>`, or `token endpoint request failed (WinHTTP)` on Windows). The watchdog on Windows works differently: it takes a private duplicate of the socket and, from the deadline, cancels the pending I/O on it and shuts the connection down every 50 ms; if that has not released the request after 10 re-issues (500 ms) it closes the duplicate abortively (`SO_LINGER` with a zero timeout), which resets the connection. httplib on Windows waits with `WSAPoll`; the evidence that this cut ends a stalled handshake is the end-to-end drip test, not a unit test of the mechanism. Which tests ran on which OS is in `docs/test-coverage.md`.
- **Retry windows.** A failed discovery (including one that failed because the server could not start a thread or, on Linux and macOS, had no descriptor to spare) is not retried for 30 s: calls inside that window fail at once with `OIDC discovery unavailable` and the cause line is not repeated. The window applies to discovery only; the JWKS is fetched afresh on every sign-in (nothing is cached or remembered), so a failed fetch is simply tried again at the next one. While one request is fetching discovery, any other sign-in that needs it fails at once rather than waiting (so the first sign-in after a restart pays one round trip, and sign-ins that arrive during it get the JSON `500` above).
- **Audit and metrics.** A failed callback is audited as `auth.oidc_login_failed` (no detail) and counted in `yuzu_auth_oidc_login_total{result="error"}`. That covers a callback that could not get discovery or the signing keys (it shares this generic row and counter with token-exchange and claim failures) and one where the provider hit an unexpected error handling the IdP's response (the failure text is the fixed `OIDC callback processing failed`). A sign-in whose session could not be stored writes the same action with `reason=session_create_failed`, in the same counter series. A sign-in refused because a Settings save replaced the provider while it was in flight writes it with `reason=provider_replaced` (`reason=provider_replaced;post_mint=true` when the refusal came after the session was minted and deleted again), also counted under `result="error"`.
- **A flow that fails to start leaves only a log line.** `GET /auth/oidc/start` failing (discovery unavailable, inside the 30 s window, or another sign-in fetching discovery) writes no audit row and increments no counter (tracked in #5704), so an outage that stops every sign-in at the start step shows in neither the audit trail nor `yuzu_auth_oidc_login_total`.
- **Log lines to watch.** These are the main OIDC lines and their exact prefixes in the server log (not every OIDC line): `OIDC auth flow could not start: ` (error; the suffix `OIDC discovery unavailable` is the discovery case), `OidcProvider: discovery failed for issuer ` (error; the cause), `OIDC callback failed: ` (warn; the suffix is the reason, for example `OIDC discovery unavailable`, `JWKS signing keys unavailable` or `OIDC callback processing failed`), `OidcProvider: JWKS fetch failed: ` (error), `OidcProvider: skipping JWK #` (warn; one malformed key in a served set was skipped and its siblings kept; at most 8 per document, then one `JWKs were skipped in total` summary line), `OidcProvider: the token names kid=` followed by `which the fetched key set does not hold` (warn; the sign-in was refused; a token with no kid and an empty key set logs `OidcProvider: the token has no kid and the fetched key set has no usable key`), `OIDC callback refused: a Settings save replaced the provider while this sign-in was in flight` and `OIDC callback refused after the session was minted: a Settings save replaced the provider` (warn; audit reason `provider_replaced`), `OidcProvider: ` followed by `replaced providers still have a request in flight` (warn; the reply to a Settings save is waiting for the oldest, the settings are already stored), `OidcProvider: discovery is unavailable, cannot fetch signing keys` (warn), `OIDC egress: refused host '` (warn; the request was not made), `OIDC egress: the issuer host of ` (warn at start-up and at every Settings save; the configured issuer is an IP address in a refused class), `OIDC issuer ` followed by `uses http:// on a non-loopback host` (warn at the same times), `OIDC egress: --oidc-allow-private-networks is set; ` (info at start-up), `OIDC handle_callback: unexpected ` (error; an unexpected failure while processing the IdP's response) and `OIDC callback: session could not be created for '` (error).
- **Log hygiene.** IdP-controlled values (subject, issuer, audience, display name, e-mail, key id, the token endpoint's status, response body, `error` and `error_description`, and JWT payload parse errors) are neutralized in the OIDC sign-in log lines written by the provider (the token-exchange lines included, and the first eight bytes of the callback `state` parameter, which any request can supply), in the `OIDC session created for ...` line, in the `provision_sso_identity failed` and session-persistence error lines (not in the group-provisioning lines, see below) and in the callback handler's line for the `error` and `error_description` query parameters of `/auth/callback` (a request needs no session and no IdP to send them). A control character or a Unicode line break (NEL, U+2028, U+2029) in one becomes `_` and cannot forge a second log line, and a value over 256 bytes is shortened in the log.
- **Audit values.** The audit detail of that callback row (`idp error: ...`) is sanitized the same way for control characters, `;` and `=`. The stored display name, the session and the audit principal keep the original value.
- **Not yet neutralized (tracked in #5704).** In the callback handler, the `OIDC login denied for ...` line and the group-provisioning skipped, exceeded and failed lines print the principal as received, the failed line also prints the raw store error text (`auth_routes.cpp`), and the failure path puts the database error text into the `reason=` field of its audit detail. The audit detail sanitizer (`display=`, `email=` and the rows above) neutralizes control characters, `;` and `=` but not NEL, U+2028 or U+2029. The equivalent SAML sign-in log lines are in the same state.
- **Keycloak hostname.** Keycloak builds the `issuer` in its document from its configured hostname (frontend URL). If the Yuzu server reaches Keycloak by an internal name but Keycloak's frontend URL is different, the configured issuer cannot be both reachable and equal to the document's issuer, and the log shows `issuer mismatch`. Configure the issuer as the URL Keycloak states in `issuer`, and make that URL reachable from the Yuzu server. Keycloak in `start-dev` mode derives the issuer from the request's Host header, so this mismatch only appears once a frontend URL is configured (for example `KC_HOSTNAME`).
- **A failed sign-in that "worked in Test Connection".** Test Connection does not exercise the token endpoint, client secret, redirect-URI registration, audience or group claims (see above); a failure there shows as `OIDC callback failed: ...` with the provider's own message. It also does not read the provider's discovery state, so a sign-in refused with `OIDC discovery unavailable` can follow a green Test Connection. A third cause is TLS verification: Test Connection skips it when the form's checkbox is ticked or the server's current `skip_tls_verify` value is true, while the running provider keeps the value it was built with, so after a restart with a stored Settings value that differs from `--oidc-skip-tls-verify` Test Connection can say Connected while the sign-in fails with `request failed: SSL server verification failed`.

### Known limits

- A sign-in can stall for about 10 s per request (the total bound above) while the IdP is dead or trickling, and a failed discovery is not retried for 30 s. The token-exchange POST has per-operation timeouts only (10 s, 15 s, 15 s on Linux and macOS; the WinHTTP defaults on Windows) and no total bound, so a token endpoint that trickles bytes can hold that sign-in for as long as it likes.
- A SIGTERM that arrives while a sign-in is stalled in such a token POST does not stop the server cleanly: the shutdown waits up to 15 s for the web listener thread (log line `Shutting down server: waiting up to 15s for the web listener thread to finish...`), then writes `ServerImpl::stop: web thread did not finish within the 15s shutdown grace bound (#2703 Gate 7 item 2) - force-exiting.` to stderr and exits with status 1, skipping the rest of the teardown.
- A Settings save does not wait for sign-ins, and a sign-in cannot be completed under configuration a save has replaced. `GET /auth/oidc/start` and `GET /auth/callback` take the OIDC lock shared only long enough to pick up the current provider and copy the settings they read (redirect URI, admin group, SCIM link claim), then run their network requests without it. When the callback's token exchange and JWKS fetch finish, it compares the provider it started with to the published one (under the shared lock, before any group, role or session work); if a save has replaced it in the meantime the sign-in is refused like any other callback failure (the user is sent to `/login?error=sso_failed`, the audit row is `auth.oidc_login_failed` with `reason=provider_replaced`, and the log line is `OIDC callback refused: a Settings save replaced the provider while this sign-in was in flight`), so no session is minted under the old admin group or issuer after the save returns. The callback checks twice: once before any group, role or session work, and again right after the session is minted (the group sync, the SCIM read and the session write between the two take as long as the database takes). A save that replaced the provider during that span makes the callback delete the session it just minted and set no cookie (audit `reason=provider_replaced;post_mint=true`, with `;db_persisted=false` if the durable delete failed). A save that lands after the second check is ordered after the sign-in, which is the same outcome as a sign-in that finished a moment before the save. The group sync that already ran is not undone; the next sign-in reconciles again. A session that is already live is not revoked by a save: after demoting an admin group, end the affected operators' sessions yourself with `DELETE /api/v1/sessions?username=oidc:<iss>#<sub>` or Settings > User Management > Revoke sessions (a restart does not end sessions). Every save rebuilds the provider, including one that changes nothing, so every sign-in in flight at that moment is refused, and every flow started before the save (including one waiting at the IdP's login page) cannot complete after it, because the new provider does not know the old one's pending state: those users start again, so save outside peak sign-in hours. The new provider and the saved settings take effect in the server process that handled the save; another replica picks up the stored settings at its next restart, as it did before this change. While a save waits for the OIDC lock, new sign-in and landing-page requests wait at a gate until it owns the lock (the lock itself prefers readers on glibc, so a steady stream of overlapping requests could otherwise keep a save out); the wait is the length of the requests already inside. The replaced provider is destroyed when the next Settings save runs or the server stops, once its last in-flight request has ended (until then a provider that still had a request keeps the old client secret in memory). The one wait left is rare: if more than 16 replaced providers are each still in a request (16 saves while sign-ins are stalled in token POSTs, which have no total bound, or in the database work after the exchange, which is bounded by the statement and pool timeouts; tracked in #5983), the save's reply waits for the oldest of them and the log says `OidcProvider: N replaced providers still have a request in flight`; the settings are already stored by then.
- **A Settings save whose reply does not come.** Saves run one at a time. Three causes, in the order to check: another save is ahead of it (each waiting save holds one HTTP worker); the database is slow, because the save writes six settings and an audit row before it answers (check the Postgres pool and statement timeouts); or more than 16 replaced providers are each still in a request (a token POST, or the database work after it), in which case the log says `OidcProvider: N replaced providers still have a request in flight` and the settings are already stored. Only the reply is delayed; sign-ins are never held by a save.
- JWKS fetches are not single-flight and not cached: each sign-in makes its own request, so a burst of N sign-ins makes N parallel JWKS requests (#1900, #5983).
- A successful discovery is cached for the life of the provider. If the IdP moves its endpoints or `jwks_uri`, save the OIDC settings again (which rebuilds the provider) or restart the server.
- Signing keys are fetched afresh for every sign-in and are not cached: a key the IdP has retired or revoked stops verifying at the next sign-in (#1901 UP-19). The price is one JWKS request per sign-in, and an IdP whose JWKS endpoint is down or answers something that is not a JWKS refuses every sign-in with `JWKS signing keys unavailable` until it answers again (there is no grace period for a previously fetched key; log line `OidcProvider: JWKS fetch failed: ...`). Confirm the server can reach `jwks_uri` and that your IdP's published rate limit for it covers your peak sign-in rate: every sign-in makes one request, and a 429 or 5xx logs `OidcProvider: JWKS fetch failed: HTTP <status>` and fails that sign-in with `sso_failed`, with no retry (the user starts the sign-in again; the authorization code is already used). Under `--auth-mode=sso-only` an outage locks out every operator who has no armed break-glass account (the local-password path does not use `/auth/callback`; see Hardened auth mode), so name one before relying on it. A sign-in also holds one HTTP worker of the pool shared with the dashboard and REST for up to about 10 s while its JWKS request runs (see "Hardened auth mode" in [upgrading](upgrading.md)). A token that names a `kid` the fetched key set does not contain, or carries a `kid` that is not a non-empty string, is refused; only a token with no `kid` member is checked against the first key. Keys are parsed one by one: a served key that is not an object, has a `use`, `kid` or `alg` that is not a string, or has key material that does not parse is skipped (log line `OidcProvider: skipping JWK #<n>: ...`) and its siblings are kept, while a document that is not a JWKS at all (`keys` is not an array) fails as a whole. A served set with no usable key at all refuses the sign-in (no matching key). A fetch, once made, cannot be recalled: a key withdrawn at the IdP in the moments between the fetch and the signature check still verifies that one token.
- A discovered `jwks_uri` and `token_endpoint` may be on any host: the rules above restrict their scheme, length and authority, and the egress policy restricts the ADDRESS the server will connect to, not the host name (there is no allow-list of names, and no per-host setting). There is no operator override for the endpoints: they come from the discovery document or not at all, so an air-gapped IdP that does not serve its discovery document cannot sign in. When the policy refuses a request the server has not connected to anything; a hostname that resolves to both permitted and refused addresses is connected to a permitted one only.
- The Windows token request cannot pin the address WinHTTP connects to, so a DNS rebinding between the egress pre-check and WinHTTP's own lookup is not covered on that request, and a name whose answer mixes permitted and refused addresses is refused outright there (see "Egress policy"). It does not follow redirects and accepts only HTTP status 200, and its reply is capped at 256 KiB like every other IdP response. It also refuses a token endpoint whose host or port WinHTTP parses differently from the host and port the egress policy vetted (log line `WinHTTP: the URL's host or port is not the host and port the egress policy vetted`), which fails that sign-in; Test Connection does not use WinHTTP and cannot show this.
- No proxy support on the discovery and JWKS path (the Windows token request uses the system default proxy); the Windows token request ignores `--oidc-skip-tls-verify` (`winhttp_post`).
- Windows: discovery and the JWKS fetch use the portable HTTP client from handler threads, which was once found failing there for `https` issuers. The tree has an `https` test from a handler thread (`[https_handler_thread]`), but the project has not verified a real `https` sign-in on a Windows server: test one before relying on it; a failure shows as the log lines above.
- On Linux and macOS a request needs one spare file descriptor beyond its socket, reserved before the socket is opened. If none is available the request fails closed with `request failed: no file descriptor available` (and starts the 30 s discovery window), rather than running without its time bound.
- Deferred, tracked: #1900 (JWKS fetch resilience), #5983 (the token POST total bound, JWKS single-flight, discovery expiry) and #1901 (kid binding, the RSA key-size floor), #5704 and #1902 (audit reason tokens, the audit row and counter for a failed start, and the log and audit lines listed under Log hygiene).

### Browser binding

The sign-in is bound to the browser that started it. `GET /auth/oidc/start` sets a short-lived (10 minute) `HttpOnly` cookie holding a random secret, and the server keeps only a SHA-256 digest of that secret beside the pending flow. `GET /auth/callback` refuses a request that does not present the matching cookie, so a callback URL only completes in the browser that began the flow. A refused callback does not consume the pending flow, so the original browser can still finish within the 10 minute window; the cookie is cleared once the flow it proved has been used.

- **Cookie name.** `__Host-yuzu_oidc_bind` (`Secure`, `Path=/`) when the server's own listener runs with HTTPS, and `yuzu_oidc_bind` on plain HTTP, the same rule the session cookie follows. A server behind a TLS-terminating proxy that itself listens on plain HTTP therefore uses the unprefixed, non-`Secure` name, the same posture as its session cookie and weaker than SAML's HTTPS-only stance.
- **Same host name.** The cookie is bound to the host name it was set on, so the sign-in must be started on the same host name as the configured `--oidc-redirect-uri`. A sign-in started on a different host name (an IP address, a short name) is refused with `sso_failed` until it is restarted on the configured host.
- **`SameSite=Lax`.** The identity provider returns by a top-level GET, which a `Lax` cookie accompanies (SAML needs `None` because its assertion arrives as a POST). This relies on the default `query` response mode, which is what Yuzu requests; it does not request `form_post`.
- **Multiple replicas.** The pending flow and its digest are held in server memory, so the callback must reach the replica that handled `GET /auth/oidc/start`. Configure session affinity on `GET /auth/oidc/start` and `GET /auth/callback`, as for SAML (see [SAML HA](../auth-architecture.md#ha--multi-replica)).
- **Restarts and upgrades.** A sign-in started before a server upgrade or restart cannot be completed afterwards; the user restarts it from the login page. Starting a second SSO sign-in in the same browser replaces the cookie, so the earlier unfinished sign-in in that browser must be restarted.
- **Audit.** Refusals are audited as `auth.oidc_login_failed` with `reason=browser_binding_missing` (no cookie), `reason=browser_binding_mismatch` (a cookie that does not match the flow) or `reason=browser_binding_unavailable` (the server could not compute the digest; the flow stays pending). A callback refused because a Settings save replaced the provider mid-exchange carries `reason=provider_replaced`. The browser sees the usual generic `sso_failed` error in every case.

### Group-to-Role Mapping

When the IdP includes group claims (e.g., Entra ID `groups` claim), Yuzu checks whether the user belongs to the admin group specified by `--oidc-admin-group`. If the user's group list contains that group ID, they receive the `admin` role. Otherwise they receive the default `user` role.

Admin via OIDC is granted **only** through explicit membership in the configured admin group. Email and display name are **never** used to elevate privileges — they are attacker-controllable values, so a match against a local admin account's name does **not** grant admin (enforced in `create_oidc_session`).

> **Note:** Only a single admin group mapping is currently supported via the `--oidc-admin-group` CLI flag. Multi-role group mapping (e.g., mapping different groups to ITServiceOwner or Operator) is planned for a future release and will use the RBAC store's group-scoped role assignments.

### RBAC Group Provisioning (#1832)

Independently of the `--oidc-admin-group` admin mapping above, every OIDC login reconciles the IdP's `groups` claim into the RBAC store so that group-scoped role assignments take effect for SSO users. There is no dedicated group-membership UI — a group-scoped role grant is made via the management-group role-delegation API, `POST /api/v1/management-groups/{id}/roles`, whose `principal_id` field is free text: set `"principal_type": "group"` and `"principal_id": "entra:<group-id>"` to delegate `Operator` or `Viewer` to everyone the IdP asserts is in that group. Each asserted group is written as `entra:<group-id>` — **namespaced** by identity source, never the raw IdP group id — so a locally-created RBAC group can never collide with (or be impersonated by) a same-named IdP group.
>
> **Do not confuse the two forms.** `--oidc-admin-group` (the admin mapping above) matches against the **raw** IdP group object id as it appears in the token's `groups` claim — configure it with the raw id (e.g. `a1b2c3d4-…`), *not* the namespaced `entra:<id>` form, or admin elevation silently fails. Only group-scoped RBAC role delegation (`principal_id`) uses the namespaced `entra:<id>` form.

The reconcile also removes any of the user's `entra:`-owned memberships that the IdP no longer asserts, so a group removal on the IdP side takes effect on the user's **next SSO login** — memberships are **not** revoked mid-session; a live cookie session or already-issued API token retains its prior roles until re-authentication (residual, tracked in #1836 — the operator's manual mitigation in the interim is `DELETE /api/v1/sessions?username=<name>`, "Session lifetime" above). A malformed or oversized (`>200` groups) assertion, or a reconcile-store failure, denies the login outright rather than granting a session with stale roles.

**Entra group overage.** Once a user belongs to more groups than fit in the ID token (Entra's documented threshold is 200 groups), Entra omits the `groups` claim entirely and sends a `_claim_names`/`_claim_sources` indirection pointer instead. Reconciliation is **skipped** for that login — existing memberships are left exactly as they were, and the login still succeeds — rather than reading the resulting empty claim as "this user is in zero groups" and deleting every one of their existing memberships. A heavily-grouped legitimate user simply doesn't get their SSO-driven roles updated on an overaged login until Entra can report the full set (out-of-band group lookup, e.g. via Microsoft Graph, is not implemented in this release).

See the `auth.sso_group_provision` audit action (`docs/user-manual/audit-log.md`) for the full `result=ok|skipped|error` contract and detail-field shape.

> **Upgrade note:** Before this fix, OIDC groups were synced under their raw (un-namespaced) id, so an operator may have assigned an RBAC role directly to a group named e.g. `8f3c...` (the raw Entra group id). Those role assignments do **not** automatically move to the new namespaced group. **Re-assign any such role to `entra:<group-id>`** via the same `POST /api/v1/management-groups/{id}/roles` API — the old raw-id group row is left in place (harmless, but no longer reachable by future logins) and can be deleted once you've confirmed the namespaced group has the role.

> **Operational note (fail-closed):** a transient `rbac.db` failure during an OIDC login denies the login outright (no session minted) rather than granting one under unreconciled roles (`docs/auth-architecture.md` "RBAC group provisioning (#1832)"). This does not affect the break-glass/local-password path (`/login`, hardened-mode escape hatch): break-glass logins never call `/auth/callback` and so never touch RBAC group reconciliation.

### Entra ID Setup Checklist

> Microsoft Entra ID is supported by the standard but has not been verified end to end by the project. Verify with the manual procedure above before relying on it.

1. Register an application in Entra ID (Azure Portal > App registrations).
2. Set the redirect URI to `https://yuzu.example.com:8443/auth/callback` (type: Web).
3. Create a client secret under Certificates & secrets.
4. Under Token configuration, add the `groups` optional claim to the ID token.
5. Grant `openid`, `profile`, and `email` API permissions.
6. Pass the tenant-ID issuer URL (`https://login.microsoftonline.com/<tenant-guid>/v2.0`), client ID, secret, and admin group ID to the Yuzu server flags (`--oidc-issuer`, `--oidc-client-id`, `--oidc-client-secret`, `--oidc-admin-group`).

## SAML 2.0 SSO

Yuzu supports SAML 2.0 SP-initiated single sign-on against a single, statically-configured IdP. This is an alternative to OIDC for enterprises whose identity infrastructure requires SAML rather than OpenID Connect.

> **Platform note:** SAML is supported on Linux and macOS only. A Windows server logs an error at startup and does not enable SAML regardless of flag values. If you need SSO on Windows, use OIDC.

> **Role note:** SAML sessions default to `role=user`. Configure `--saml-group-attribute` + `--saml-admin-group` to promote users in a specific IdP-attested group to `role=admin` — see [SAML Group-to-Role Mapping](#saml-group-to-role-mapping) below. Leave both flags unset (the default) and every SAML session lands as `role=user`, same as prior releases. JIT elevation is still non-functional for SAML users regardless of role (the elevation check requires a local `auth.users` row, which SAML users do not have) — a SAML admin gets `role=admin` directly at login via group mapping, not via the elevation endpoint.

> **HTTPS required:** SAML uses a `Secure` browser-binding cookie (`__Host-yuzu_saml_bind`). Browsers silently drop `Secure` cookies over plain HTTP. SAML fails closed at startup when `--https-cert`/`--https-key` are not configured. Do not run SAML over HTTP.

> **MFA step-up:** MFA step-up is not supported for SAML sessions in this release. A SAML session hitting any step-up-gated endpoint (token lifecycle, session revoke, Guardian rule write, software deploy, engine-principal lifecycle, user management, JIT admin elevation) receives a `403` regardless of `--mfa-enforcement` mode (while step-up is on; `--mfa-step-up-window-secs=0` disables the gate before the SAML check). Approval approve/reject is not on that list: it no longer uses the generic gate and refuses a SAML session in every configuration, including `--mfa-step-up-window-secs=0`, with `approver_assurance_required:saml_mfa_unsupported` (#6079). This includes the Settings-page API-token Create and Revoke buttons. Use `--mfa-enforcement=optional` and rely on your IdP to enforce MFA at login time. Do not use `--mfa-enforcement=required` for SAML deployments — it denies SAML users at all step-up gates.

> **SCIM linkage and force-logout:** if SCIM provisioning is also enabled, a SAML login whose NameID resolves to a SCIM resource forms a durable link, and SCIM deprovisioning that resource revokes the linked SAML session automatically. A SAML session is also individually force-loggable by an admin via `DELETE /api/v1/sessions?username=saml:<entity_id>#<NameID>`. See [SCIM ↔ SAML identity linkage](scim-provisioning.md#scim--saml-identity-linkage-federated-session-revocation) for the NameID-Format contract this depends on.

### Registering the SP with Your IdP

Before configuring the server, register Yuzu as a Service Provider with your identity provider:

1. **SP Entity ID** — a URI that identifies this Yuzu installation to the IdP (e.g. `https://yuzu.example.com`). You choose this value; it must be unique within the IdP's SP registry.
2. **ACS URL** — the Assertion Consumer Service URL where the IdP will POST the SAML response. This is `https://yuzu.example.com/saml/acs` (or the equivalent for your host and port). Set this as the ACS / reply URL in your IdP.
3. **Bindings** — configure the IdP to use **HTTP-Redirect** for the AuthnRequest and **HTTP-POST** for the response to the ACS.
4. **IdP signing certificate** — download or copy the IdP's assertion-signing certificate in PEM format and store it on the Yuzu server host (e.g. `/etc/yuzu/idp-signing.pem`, readable by the `yuzu` service account).

### Server Configuration

SAML is enabled via CLI flags (or the matching environment variables). All five flags (`--saml-idp-entity-id`, `--saml-idp-sso-url`, `--saml-idp-cert`, `--saml-sp-entity-id`, `--saml-sp-acs-url`) are validated at startup as one unit — supplying any subset produces a startup warning that names the missing flag, and SAML is disabled (fail-closed). A partial configuration never logs "SAML SP initialized".

| Flag | Env var | Description |
|---|---|---|
| `--saml-idp-entity-id` | `YUZU_SAML_IDP_ENTITY_ID` | Entity ID URI of the IdP (must match what the IdP uses in its assertions) |
| `--saml-idp-sso-url` | `YUZU_SAML_IDP_SSO_URL` | IdP's HTTP-Redirect SSO endpoint URL |
| `--saml-idp-cert` | `YUZU_SAML_IDP_CERT` | Path to the IdP signing certificate PEM file on the server host |
| `--saml-sp-entity-id` | `YUZU_SAML_SP_ENTITY_ID` | Entity ID URI this SP advertises to the IdP |
| `--saml-sp-acs-url` | `YUZU_SAML_SP_ACS_URL` | Full public URL of the ACS endpoint (`https://<host>/saml/acs`) |
| `--saml-sp-key` | `YUZU_SAML_SP_KEY` | Optional. Path to an SP AuthnRequest signing private key PEM (**RSA only**). When set, AuthnRequests are signed — see [AuthnRequest Signing](#authnrequest-signing) below. Left unset (the default), AuthnRequests remain unsigned |
| `--saml-name-attribute` | `YUZU_SAML_NAME_ATTRIBUTE` | Optional. `<Attribute Name="...">` whose first value is the user's display name (e.g. Entra's `displayname` claim URI). The session display is then derived name → email → raw NameID. Empty (default) leaves it as the raw NameID. Display/audit only — never identity or authz |
| `--saml-email-attribute` | `YUZU_SAML_EMAIL_ATTRIBUTE` | Optional. `<Attribute Name="...">` whose first value is the user's email (e.g. Entra's `emailaddress` claim URI). Used as a display fallback and logged only — never stored durably or used for identity |

Example startup:

```bash
./yuzu-server \
  --https --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
  --https-key  /etc/yuzu/server.key \
  --saml-idp-entity-id "https://idp.example.com/saml" \
  --saml-idp-sso-url   "https://idp.example.com/saml/sso" \
  --saml-idp-cert      /etc/yuzu/idp-signing.pem \
  --saml-sp-entity-id  "https://yuzu.example.com" \
  --saml-sp-acs-url    "https://yuzu.example.com/saml/acs"
```

### SAML Group-to-Role Mapping

Two additional flags, both optional and independent of the five required
SAML flags above, let you grant admin access via IdP-attested group
membership:

| Flag | Env var | Description |
|---|---|---|
| `--saml-group-attribute` | `YUZU_SAML_GROUP_ATTRIBUTE` | Name of the `<Attribute Name="...">` in the assertion's `<AttributeStatement>` whose `<AttributeValue>`s are group identifiers (e.g. Entra's `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`) |
| `--saml-admin-group` | `YUZU_SAML_ADMIN_GROUP` | The single group value (from `--saml-group-attribute`) that grants `role=admin` |

When both flags are configured and the assertion's group list contains the
value in `--saml-admin-group`, the resulting session is `role=admin`.
Otherwise (including when either flag is left empty) the session is
`role=user` — the same default as prior releases.

Matching is **exact string equality only** — no wildcard, prefix, or regex
matching, and only a single admin group is supported (no multi-group /
multi-role mapping, same limitation as OIDC's `--oidc-admin-group`).

Admin via SAML is granted **only** through explicit membership in the
configured group. `NameID`, email, and display name are **never** used to
elevate privileges — mirrors the OIDC guard described above
(`create_oidc_session`) — and group values are read from the same
signature-verified assertion as `NameID`, so a forged or wrapped assertion
element cannot inject group membership that the IdP didn't attest to.

> **Configuring `--saml-admin-group` against a real IdP:**
>
> - The value must be the **exact identifier your IdP puts in the assertion**
>   — not a human-friendly display name. Entra ID, for example, sends group
>   **object ID GUIDs** (e.g. `4fb5b234-...`) in the group claim, not the
>   group's display name; configure the GUID, not "Admins".
> - Matching is **case-sensitive** — a value that differs only in case (or
>   has stray leading/trailing whitespace copy-pasted from a portal — the
>   admin-group value is trimmed automatically, but the group values inside
>   the assertion itself are compared as the IdP sent them) will not match.
> - **Entra ID "groups overage"**: a user who is a member of more than ~150
>   groups gets **no `groups` claim at all** in the assertion — Entra
>   substitutes a Graph API link instead. Such a user's assertion carries zero
>   group values, so `--saml-admin-group` can never resolve them to admin
>   regardless of actual group membership. Either keep the target admin's
>   group count under the overage threshold or use a dedicated,
>   low-membership group for the admin mapping.
> - At most **200 group values** from the configured attribute are considered
>   (a DoS guard, aligned with the RBAC reconcile cap below); an assertion
>   carrying more than 200 values is **rejected outright** when
>   `--saml-group-attribute` is configured and RBAC is enabled — see
>   [SAML Fine-Grained RBAC](#saml-fine-grained-rbac) below. The coarse
>   `--saml-admin-group` mapping on its own (RBAC disabled, or no RBAC store)
>   still just silently ignores a value beyond the 200th, same as before.

Changing either flag requires a server restart to take effect (no hot-reload,
same as the other SAML flags).

### SAML Fine-Grained RBAC

Beyond the coarse admin/user mapping above, SAML now reaches parity with
OIDC's group-to-role reconciliation: when RBAC is enabled and
`--saml-group-attribute` is configured, every value in the configured group
attribute is reconciled into the RBAC store as `saml:<value>` group
principals (source `"saml"`) on every login — the same
`RbacStore::reconcile_idp_memberships` mechanism OIDC's fixed `groups` ID
token claim uses for source `"entra"`. There is no dedicated group-membership
UI — a group-scoped role grant is made via the management-group
role-delegation API, `POST /api/v1/management-groups/{id}/roles`, whose
`principal_id` field is free text: set `"principal_type": "group"` and
`"principal_id": "saml:<value>"` to delegate `Operator` or `Viewer` (the only
two roles this route delegates) to everyone the IdP asserts is in that group;
no new configuration flag is needed —
reconciliation is driven entirely by `--saml-group-attribute`, which you
likely already have configured for the coarse admin mapping above.

Both mechanisms coexist: `--saml-admin-group` still grants the coarse
`role=admin`/`role=user` session role exactly as documented above,
independently of any RBAC-assigned fine-grained permissions.

Reconciliation happens **before** the session is minted, so a provisioning
failure denies the login outright (fail-closed) rather than granting a
session under stale or partially-reconciled roles. Three cases worth
knowing:

- **More than 200 asserted group values DENIES the login.** The verifier
  already truncates its parsed `groups` list to 200 entries (the DoS guard
  above) — reconciling that truncated, incomplete view would silently
  deprovision every membership beyond the 200th on the next login, so the
  login is refused instead (redirects to the login page with an error,
  same as any other SAML failure). This matches OIDC's
  `group_count_exceeded` behaviour exactly.
- **An empty or absent group attribute does NOT deprovision.** SAML cannot
  distinguish "the attribute was never asserted" from "the attribute was
  asserted with zero values" — both produce an empty group list. Unlike
  OIDC (which has an explicit `groups` claim presence signal from the
  token), reconciling an empty SAML group list would delete every one of
  the user's `saml:`-sourced memberships. Reconciliation is skipped
  entirely in this case — existing memberships are left untouched, and the
  login still proceeds normally. **SCIM deprovisioning remains the only
  full deprovisioning path** for a SAML-linked identity — see
  [SCIM ↔ SAML identity linkage](scim-provisioning.md#scim--saml-identity-linkage-federated-session-revocation).
- **A store error also denies the login** (fail-closed) — a reconcile call
  that cannot be answered (e.g. the RBAC store is unavailable) refuses the
  login rather than proceeding under an unknown authorization state.

> **Practical reach of the >200-group deny path.** `/saml/acs` receives the
> IdP's response as an `application/x-www-form-urlencoded` POST, and
> httplib's own form-parsing layer caps that body at 8 KiB
> (`CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH`) — enforced **before**
> the `/saml/acs` handler (and therefore this reconciliation logic) ever
> runs. A base64-encoded SAML response carrying more than roughly 180 group
> values typically exceeds that 8 KiB cap on its own, so in practice a real
> assertion this large is rejected with a bare `413` at the HTTP layer, not
> the SAML-specific deny-and-redirect-to-`/login?error=saml` path described
> above. Deployments whose IdP can assert that many groups see a generic
> `413`, not this section's denial. A follow-up tracks raising the cap for
> `/saml/acs` so the documented >200-group deny path is reachable at its
> full documented range.

Reconciliation only runs when a live RBAC store is wired in **and**
`--saml-group-attribute` is non-empty; with either condition unmet (RBAC
disabled, or the attribute unconfigured), this section is a no-op and only
the coarse `--saml-admin-group` mapping applies — group-scoped RBAC role
assignments do not reach SAML principals in that configuration.

### AuthnRequest Signing

One additional flag, optional and independent of the five required SAML
flags above, signs SP-initiated AuthnRequests over the HTTP-Redirect
binding:

| Flag | Env var | Description |
|---|---|---|
| `--saml-sp-key` | `YUZU_SAML_SP_KEY` | Path to the SP AuthnRequest signing private key PEM (**RSA only, 2048–16384 bits** — EC, RSA-PSS, and out-of-range keys are rejected) |

When configured, AuthnRequests are signed with RSA PKCS#1 v1.5 + SHA-256
(`SigAlg` `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), carried as
the `SigAlg`/`Signature` query parameters on the redirect. The key file must
satisfy the same private-key permission check as the HTTPS/gateway TLS keys
(not group/other-readable). Left unset (the default), AuthnRequests remain
**unsigned** — a compliant IdP that accepts unsigned requests keeps working
unchanged.

**Fail-closed:** a configured key that is unreadable, over-permissioned,
exceeds 64 KiB, is malformed, encrypted/passphrase-protected, is not RSA, or
is outside the 2048–16384-bit range disables SAML **entirely** at startup (loudly — an `ERROR` log line, never a
silent fall-back to unsigned requests). A per-request signing failure fails
`/auth/saml/start` rather than emitting an unsigned redirect. Changing
`--saml-sp-key` requires a server restart (no hot-reload, same as the other
SAML flags).

**Registering the signing certificate with your IdP.** Yuzu does not yet
publish an SP metadata endpoint, so the IdP must be told about the signing
key's public half manually — otherwise the IdP receives a signed request it
cannot verify and rejects (or silently ignores) the signature even though
Yuzu booted cleanly. Generate an **unencrypted** RSA private key and a
self-signed public certificate, then register the certificate in your IdP's
SP/relying-party application as the **request-signing (AuthnRequest)
verification certificate**:

```bash
# Unencrypted RSA-2048 key (--saml-sp-key) + a self-signed public cert to hand the IdP
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /etc/yuzu/saml-sp-key.pem -out /etc/yuzu/saml-sp-cert.pem \
  -days 730 -subj "/CN=<your-sp-entity-id>"
chmod 600 /etc/yuzu/saml-sp-key.pem   # must not be group/other-readable
```

Point `--saml-sp-key` at `saml-sp-key.pem` and upload `saml-sp-cert.pem` to
the IdP (Okta, Entra ID, and PingFederate each expose a "request signature"
or "signing certificate" field in the SP app config). The key **must be
unencrypted** — a passphrase-protected key is rejected at boot rather than
prompting for the passphrase.

SAML is Linux/macOS only; AuthnRequest signing follows that same platform
scope — there is no signing support on Windows (SAML is disabled there
regardless of flag values).

### SAML Login Flow

1. The operator clicks "Sign in with single sign-on" on the sign-in page (`/home`), which links to `GET /auth/saml/start` when SAML is enabled and no OIDC provider is (when both are enabled the button starts OIDC), or navigates directly to `GET /auth/saml/start`.
2. The server generates a `<samlp:AuthnRequest>` and redirects the browser to the IdP via **HTTP-Redirect binding** (the request is deflate-compressed and URL-encoded in the `SAMLRequest` query parameter).
3. The operator authenticates at the IdP.
4. The IdP POSTs a `<samlp:Response>` containing a signed assertion to the ACS endpoint (`POST /saml/acs`) via **HTTP-POST binding**.
5. The server validates the assertion (signature, audience, recipient, expiry, and replay protection) and mints a session cookie on success.

```
Browser           Yuzu Server               IdP
  |                    |                          |
  |-- GET /auth/saml/start -->                    |
  |                    |-- 302 SAMLRequest? ---->|
  |                    |                          |
  |                    |      (user authenticates)|
  |                    |                          |
  |                    |<--- POST /saml/acs ------|
  |<-- Set-Cookie -----|                          |
```

The resulting session behaves identically to an OIDC session — it is subject to the same 8-hour absolute lifetime and the optional `--session-inactivity-secs` idle timeout. See [Session lifetime](#session-lifetime) for details.

### What Is and Is Not Supported

| Capability | Status |
|---|---|
| SP-initiated login (HTTP-Redirect AuthnRequest) | Supported |
| Signed assertion validation (pinned IdP cert) | Supported |
| Audience / recipient / expiry validation | Supported |
| Replay protection (`InResponseTo` single-use) | Supported |
| Group-to-role mapping | Supported — `--saml-group-attribute` + `--saml-admin-group`, exact-match only; both unset ⇒ all SAML users are `role=user` (see [SAML Group-to-Role Mapping](#saml-group-to-role-mapping)) |
| Fine-grained RBAC group provisioning | Supported — parity with OIDC; requires RBAC enabled + `--saml-group-attribute`, reconciles asserted groups into `saml:<value>` RBAC group principals (see [SAML Fine-Grained RBAC](#saml-fine-grained-rbac)) |
| Admin access for SAML users | Supported via group mapping above; JIT elevation itself is still non-functional for SAML users (no local `users` row) — an admin session is granted directly at login, not via the elevation endpoint |
| Login-page SSO button | Not in this release — navigate directly to `GET /auth/saml/start` |
| MFA step-up at high-risk endpoints | Not supported — SAML sessions receive 403 at all step-up-gated endpoints regardless of `--mfa-enforcement` while step-up is on; rely on IdP MFA. This includes approving or rejecting approval requests: a SAML user cannot approve in any configuration (`saml_mfa_unsupported`), and a SAML-only deployment has no working approver path until #4935 is decided (known limitation, tracked in #6098) |
| `--auth-mode=sso-only` with SAML-only | Supported (Linux/macOS) — a complete SAML SP config with HTTPS enabled satisfies the hardened-mode boot guard, so a SAML-only deployment can disable local-password login. Windows *server* still requires OIDC (SAML is a stub there; the server is out of scope on Windows regardless). SAML operators cannot use JIT elevation (see "Admin access" above) |
| Multi-replica / HA without sticky sessions | Not supported — pending AuthnRequest state is in-process; configure load-balancer session affinity on `/auth/saml/start` and `/saml/acs` |
| AuthnRequest signing | Supported — set `--saml-sp-key` to an RSA private key PEM; AuthnRequests are then signed over the HTTP-Redirect binding with RSA PKCS#1 v1.5 + SHA-256 (see [AuthnRequest Signing](#authnrequest-signing) above). Left unset (the default), AuthnRequests remain unsigned |
| AttributeStatement parsing | Only the configured `--saml-group-attribute` is read (for group-to-role mapping); no other assertion attributes are stored or surfaced beyond `NameID` |
| IdP-metadata auto-fetch | Not in this release — cert and SSO URL are configured statically |
| IdP cert hot-reload | Not supported — update `--saml-idp-cert` and restart the server |
| Runtime reconfigure via dashboard | Not in this release — a server restart is required to change SAML flags |
| SP metadata endpoint | Not in this release — register the SP manually using the flag values |
| Windows | Not supported — SAML is Linux/macOS only |

## API Tokens

API tokens provide non-interactive authentication for scripts, CI/CD pipelines, and integrations. Tokens are passed as Bearer tokens and bypass the session/cookie mechanism.

### Creating a Token

Requires `ApiToken:Write` RBAC permission.

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-pipeline",
    "expires_at": 1893456000
  }'
```

The `expires_at` field is a Unix epoch timestamp in seconds and must be in the future (the example value is 1 January 2030; use your own). Pass `0` or omit it for a non-expiring token. A negative, past or non-integer value is `400`.

```json
{
  "data": {
    "token": "yuzu_Ab3xK9m2...",
    "name": "ci-pipeline"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

The `token` field (prefixed `yuzu_`) is returned only at creation time. Store it securely.

### Using a Token

Pass the token in the `Authorization` header:

```bash
curl -s -H "Authorization: Bearer yuzu_Ab3xK9m2..." \
  http://localhost:8080/api/v1/me
```

Alternatively, use the `X-Yuzu-Token` header:

```bash
curl -s -H "X-Yuzu-Token: yuzu_Ab3xK9m2..." \
  http://localhost:8080/api/v1/me
```

A plain, untiered, unscoped API token carries the creating user's own RBAC role and grants — it is
not automatically admin unless its creator is. Two mechanisms narrow a token below that: an
`mcp_tier` bounds what it can do through the MCP endpoint (see [MCP Token
Restrictions](#mcp-token-restrictions) below), and a `scope_service` floors its session role to
`user` regardless of the creator's role, so an `ITServiceOwner` RBAC grant becomes its sole
authority ceiling (see [Service-Scoped Tokens](#service-scoped-tokens) below).

### Listing Tokens

Requires `ApiToken:Read` RBAC permission. Returns tokens owned by the authenticated user.

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/tokens
```

```json
{
  "data": [
    {
      "token_id": "a1b2c3d4e5f6",
      "name": "ci-pipeline",
      "principal_id": "admin",
      "created_at": 1742383800,
      "expires_at": 1750185000,
      "last_used_at": 1742397720,
      "revoked": false
    }
  ],
  "pagination": {
    "total": 1,
    "start": 0,
    "page_size": 1
  },
  "meta": {
    "api_version": "v1"
  }
}
```

Timestamps are Unix epoch seconds. The plaintext token value is never returned after creation.


### Token Length Limits

For DoS protection, Yuzu enforces maximum token lengths:

| Token type | Max length | Behavior on exceed |
|---|---|---|
| Session tokens (`yuzu_session` cookie) | 64 hex chars | 401 Unauthorized |
| API tokens (Bearer or X-Yuzu-Token) | 256 chars | 401 Unauthorized |

Tokens exceeding these limits are rejected before any cryptographic operations, preventing resource exhaustion attacks.

### Service-Scoped Tokens

Service-scoped tokens are API tokens with an additional `scope_service` field that restricts the token holder to operations within a specific service boundary. These tokens cannot access admin routes and require RBAC to be enabled.

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "name": "finance-svc-token",
    "scope_service": "finance",
    "expires_at": 1893456000
  }'
```

Service-scoped tokens:
- Cannot access any `/api/v1/admin/*` routes (403 Forbidden)
- Require RBAC to be enabled; rejected if RBAC is disabled (403 Forbidden)
- Carry a session role floored to the base `user` level regardless of the
  minting principal's own role — an `ITServiceOwner` RBAC grant is the
  authority ceiling for a service-scoped token, never the minter's role, and
  it is applied by the permission gates and by the fleet-read gate alike

**Default-deny (guardian-confinement-2298 PR 3 — "the flip").** Holding
`ITServiceOwner` for a given `securable:operation` is necessary but no
longer sufficient. A service-scoped token is denied fleet-wide access by
default — the operation must also appear on a server-side allow-list that
ships **empty**, so today a fresh install denies every fleet-wide
operation to every service-scoped token, full stop. This is the deliberate
opposite of the token's `service` tag acting as an automatic per-service
filter: there is no such filter today. A small, explicitly-reviewed set of
routes have their own real per-request confinement instead (checked
against a matching `service` tag on the target device) — the response
body's `error.permission` field, when present, names the missing grant;
its absence on a `403` means the route has no grant that would help at
all, and reaching it as a service-scoped token is not currently possible
by design. Widening what a service-scoped token can reach is a
security-reviewed change to the server, not a per-token configuration
option.

**A service-scoped token may never write or delete the `service` tag
itself (#3289)**, on any target device — in or out of its own scope. The
`service` tag is the confinement boundary the token is checked against, so
without this restriction a token could rewrite or delete its own cohort's
`service` tag and move a device out of (or a different device into) its
own confinement. Writing or deleting any OTHER tag key on an in-scope
device is unaffected — only the `service` key is restricted, and the
restriction applies regardless of the value being written (even
re-asserting the token's own current value is denied). This does not
affect a plain, non-service-scoped session's `Tag:Write`/`Tag:Delete`
grant, which remains sufficient to set or move any device's `service` tag.

**Bootstrap note.** A brand-new service token, on a brand-new install, has
no other credential to fall back on — it cannot use itself to discover or
claim a `service` tag for its own agents, or to widen its own reach. As of
#3289, an agent cannot self-claim a `service` tag on its own behalf either
(its gRPC `Register` sync silently drops any `service` value it reports).
Stand up a new service's automation using an interactive session (or a
plain, unscoped API token) for the one-time setup, and mint the
service-scoped token only once the agents it should reach already carry
the matching, operator-or-API-assigned `service` tag.

### Revoking a Token

Requires `ApiToken:Delete` RBAC permission. This performs a soft revoke (the token record remains but is marked revoked).

```bash
curl -s -b cookies.txt -X DELETE \
  http://localhost:8080/api/v1/tokens/a1b2c3d4e5f6
```

Returns `200 OK` with:

```json
{
  "data": {
    "revoked": true
  },
  "meta": {
    "api_version": "v1"
  }
}
```

Returns `404` if the token ID is not found. Returns `503 service unavailable` if the server's token store database failed to open at startup — a storage outage is never reported as `404` (see the API Tokens section of the [REST API reference](rest-api.md)).

### Rotating a Token

Rotation replaces a token's secret without a hard cutover, using the same
**overlap-pair** model as engine-principal credential rotation (see
[Engine Principals](engine-principals.md) "Rotate the credential"): a
**successor** token is minted while the existing (**predecessor**) token
stays valid for an overlap window, so whatever consumes the old secret has
time to pick up the new one.

Requires `ApiToken:Rotate` RBAC permission — a dedicated operation, distinct
from `ApiToken:Write` (which gates creating/listing/revoking a token; see
[Creating a Token](#creating-a-token) and [Revoking a Token](#revoking-a-token)
above). `{token_id}` is the **predecessor's** id:

```bash
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/tokens/a1b2c3d4e5f6/rotate \
  -H "Content-Type: application/json" \
  -d '{ "overlap_secs": 604800 }'
```

```json
{
  "data": {
    "token": "yuzu_Nm7pQ2z...",
    "token_id": "f6e5d4c3b2a1",
    "expires_at": 1750185000,
    "overlap_expires_at": 1742990600
  },
  "meta": { "api_version": "v1" }
}
```

The raw successor secret is returned exactly once, the same as at creation.
`overlap_secs` defaults to 7 days if omitted (24-hour floor, 10-year
ceiling). Once the new secret is installed wherever it's consumed, close
the loop explicitly instead of waiting on the auto-revoke sweep — `{token_id}`
here is the **successor's** id, from the `rotate` response above, and the
request body must now also carry the raw successor secret itself (`secret`,
below) as proof you actually received it:

```bash
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/tokens/f6e5d4c3b2a1/confirm \
  -H "Content-Type: application/json" \
  -d '{ "secret": "yuzu_Nm7pQ2z..." }'
```

`confirm` revokes the predecessor immediately and promotes the successor to
the token's sole active credential. If you skip it, a 60-second background
sweep does it for you, with this SLA: **a predecessor is revoked within one
60-second tick of its overlap window elapsing; on the first occurrence of a
given clock-guard anomaly the tick declines instead and revocation defers to
the next tick (roughly 120 seconds total), after which an identical anomaly
drains normally on the following tick; every decline is counted and
logged — a fresh deployment's first-ever bootstrap decline (no durable
clock reading yet) increments `yuzu_rotation_sweep_bootstrap_declines_total`,
any other decline (an implausible reading, or a big step since the last
accepted tick) increments `yuzu_rotation_sweep_declined_total`; the two are
deliberately separate series (see
[metrics.md](metrics.md#rotation-sweep-clock-guard-metrics-2964)).** A
big-step decline is **not necessarily a clock fault** — the sweep's 3600s
big-step threshold is crossed just as readily by a multi-tick gap with a
perfectly correct clock (a maintenance window, a database failover, an
instance left off overnight) as by an actual clock jump; see
[metrics.md](metrics.md#rotation-sweep-clock-guard-metrics-2964) for the
full caveat. One case
is not "eventually" but **never**, by design, until an operator acts: **the
successor was never presented at all** — the sweep leaves BOTH credentials
active indefinitely rather than revoke your only working token out from
under you (a dropped rotate response, or simply never picking up the new
secret, must not end in zero usable credentials). A **sustained clock
anomaly is NOT this case**, even though it sounds like it should be: the
guard suppresses only a *repeat of the identical* anomaly (the fact-set
dedup rule) and drains on the very next tick once it does, so a clock fault
that settles on one anomaly shape — even indefinitely — costs at most the
one extra declined tick already described above, and revocation then
proceeds on schedule against the (still bad) clock reading; do not read this
SLA as "credentials are held safe for the duration of a clock incident". The
genuinely open-ended **never**-until-an-operator-acts case on this axis is a
clock fault that keeps changing shape tick to tick (each distinct fact set
declines fresh, so dedup never gets a repeat to suppress) — indistinguishable
from a sustained fault using the counters above alone, which is exactly why
`docs/ops-runbooks/rotation-sweep-clock-guard.md` exists. The other
genuinely open-ended case is a **store-wide-lock fault** — every replica
losing the sweep's advisory lock to a wedged holder — which the same runbook
and the `YuzuRotationSweepNotRunning` alert exist to surface.

**That safeguard covers the automatic sweep only — it does not cover an
explicit `confirm`.** `confirm` is your attestation that you received and
retained the successor secret, and it revokes the predecessor straight away.
Since #3015, `confirm` proves that attestation instead of merely asserting
it: the request must carry the raw successor secret itself, verified
server-side against the stored hash before the predecessor is touched. A
lost rotate response can no longer be turned into a confirm by recovering
the successor's `token_id` out-of-band — without the secret, `confirm`
returns `403` and nothing is revoked. If the rotate response was lost, you
have no way to satisfy that check, so the recovery path is the same as
before: revoke the unknown successor (that keeps the predecessor working)
and start a new rotation. Proof of possession gates this immediate,
explicit `confirm` call only; it leaves the automatic sweep described above
untouched. If the successor secret did actually reach wherever it's
consumed (so it has been presented at least once, per the carve-out above),
the sweep still auto-revokes the predecessor on its own schedule with no
secret required, so waiting for it is also a valid recovery when you're
unsure whether `confirm` would succeed.

`confirm`'s check that you're the same operator who called `rotate` is
stored durably, not just in memory, so a server restart no longer blocks
confirming an in-flight rotation. The one exception is a rotation already
in flight *before* this durability guarantee was deployed to your server —
that pair has no durable record of who initiated it, and a restart still
leaves it permanently unconfirmable (it fails closed rather than accepting
just anyone). If you're mid-rotation during an upgrade, confirm before
restarting if you can. If you can't, the 60-second background sweep still
resolves the pair on its own timer — **provided the successor was
presented at least once** (the same carve-out described above): if so, no
action is required. If the successor was never presented at all, the sweep
never resolves this pair — both credentials stay active until you act. To
resolve it by hand — either because the successor was never presented, or
because you'd rather not wait — revoke whichever side (predecessor or
successor) you no longer trust with `DELETE /api/v1/tokens/{token_id}`
(see above), rather than retrying `confirm`.

**MFA step-up is required on every call, if you have MFA enrolled — and
that includes a repeat call.** Unlike most session activity, `rotate` and
`confirm` re-validate a *fresh* step-up proof **every time**, including a
same-caller retry that just re-serves the same successor secret within the
grace window — a repeat `rotate` is not treated as "already proved" just
because the first call succeeded. If your last MFA proof is stale (or you
haven't stepped up this session yet), you get a `401`:

```json
{
  "error": {
    "code": 401,
    "message": "MFA step-up required",
    "correlation_id": "req-..."
  },
  "meta": {
    "api_version": "v1",
    "mfa_step_up_required": true,
    "challenge_url": "/login/mfa/stepup"
  }
}
```

Follow `challenge_url` to present a fresh TOTP code (or recovery code) —
`/login/mfa/stepup` for a local session, `/auth/oidc/start` for an OIDC
session — then retry the `rotate`/`confirm` call. This only applies to the
interactive (cookie) session these examples use; a caller authenticated
with a bearer API/MCP token is exempt, since minting that token already
required MFA. See [Multi-Factor Authentication (TOTP)](#multi-factor-authentication-totp)
for enrollment and the step-up window.

**Self-service only — no admin override, and no delegate.** You can rotate
or confirm only a token **you own**; there is no admin bypass (a human
token's raw successor secret authenticates *as its owner*, so an admin
completing someone else's rotation would be identity takeover, not an
administrative convenience — an admin who needs to act on someone else's
token has [revoke](#revoking-a-token) instead). Rotating/confirming a token
you don't own returns the same `404 token not found` as a token that
doesn't exist. **Under RBAC-on, this composes to effectively admin-only**:
`ApiToken:Rotate` is granted only to the `Administrator` and
`ApiTokenManager` roles, so an `Operator`- or `Viewer`-role user who owns a
token has no path to rotate it themselves under RBAC-on, and no admin can
do it for them either — the same pre-existing property already applies to
creating a token ([`ApiToken:Write`](#creating-a-token)) and to
[deleting one](#revoking-a-token) (the sibling `ApiToken:Delete`
operation) — all three operations are held by the same two roles and no
others; rotation does not change it.

**Under the default RBAC-off configuration, self-rotate now works for any
owner.** RBAC ships off, and independently of the RBAC-on grant above, any
authenticated non-admin owner of a token — a plain cookie session or an
untiered personal access token — can rotate/confirm their own token in the
shipped default configuration. This was not always true: before a fix, the
same admin-only rule that gates create/delete also blocked self-rotate for
everyone but an admin under RBAC-off, which left the feature reachable by
nobody but an admin out of the box. Ownership is still the actual security
boundary either way — this only changes who may *attempt* the call, never
who it can succeed for.

**Lifetime-neutral by design.** The successor token always inherits the
predecessor's expiry exactly — a non-expiring token stays non-expiring, a
30-day token stays a 30-day token from its *original* grant. There is no
request field to extend it; rotating a credential is a lateral swap, never
a way to renew a grant. If you need a longer-lived replacement, create a
new token instead.

**Rotate is not approval-gated the way Delete is.** The caller's own
`mcp_tier`/`scope_service` must equal the predecessor's own values (the
authority-inheritance guard above), so rotation can never mint a token with
*more* authority than the caller already holds. That equality closes the
privilege-escalation direction, but it does not make `rotate`/`confirm`
approval-equivalent to `revoke`/`delete` — MCP's approval policy has no
`ApiToken` rule for `Rotate`, so at the `supervised` tier a `Delete` call
requires the approval workflow and a `Rotate`/`confirm` pair does not. A
same-principal, equal-tier sibling token — for example two MCP agents both
minted at `operator` for one human — can therefore be rotated and confirmed
(destroying the sibling's predecessor and revealing a fresh successor
secret to the caller) with neither an `ApiToken:Delete` grant nor a
supervised-tier approval. There is no privilege gain here — the caller
never exceeds their own authority — but the residual is availability (the
sibling's predecessor is destroyed) plus cross-consumer credential capture
(the caller sees the sibling's new raw secret) within one principal's own
tokens.

**You can now rotate your own MCP-tiered or service-scoped token from a
plain dashboard/cookie session.** The guard was originally bare EQUALITY,
not "no broader than": a cookie or JIT-elevated interactive session
carries an empty `mcp_tier`/`scope_service`, which matched an untiered
token but not one that itself carried a tier or scope — so you could not
rotate or confirm your own MCP-tiered or service-scoped token from the
dashboard at all, only a caller presenting that token's own credential (or
an equally-tiered one) could. That was backwards precisely when you
suspect the token's secret, which is the main reason anyone rotates a
credential. This is now fixed: a session holding **no** standing
`mcp_tier`/`scope_service` at all — a plain cookie or JIT-elevated
interactive session — may rotate or confirm ANY token it owns regardless
of that token's own tier/scope. This is a single special case, not a
general "no broader than" rule: such a session already holds a strict
superset of what any tiered/scoped token can do, and the successor still
inherits the *token's own* narrower tier/scope, never your session's — you
cannot use this to mint yourself a broader credential. A session holding
SOME tier/scope of its own still must match the target token's exactly.

**The `400` rejection text stays folded for a genuine mismatch.** A
non-owner and a genuine tier/scope mismatch (one non-empty tier/scope
against a different one) both still return the identical
`"no such token to rotate"` / `"no such token to confirm"` wording (by
design — see "Self-service only" above for why this is not an enumeration
oracle). This wording is deliberate and is not being changed to
disambiguate the two cases, since doing so would reopen the oracle it
exists to close.

**A token within 24 hours of its own expiry cannot be rotated.** This is
by design, not a gap: rotation is lifetime-neutral (see above) and the
overlap window has a 24-hour floor, so there is no way to fit a
lifetime-neutral overlap inside a shorter remaining window without either
extending the token's life or shrinking the floor below the point where
both secrets are reliably live for a cutover — neither is acceptable. The
store's `400` names this directly
(`"overlap window would exceed the predecessor credential's expiry"`).
Rotation is not a renewal mechanism; if a token is nearing expiry, create
a fresh one instead of trying to rotate the old one.

See the [REST API reference](rest-api.md) `POST /api/v1/tokens/{token_id}/rotate`
and `.../confirm` for the full error matrix.

## JIT Admin Elevation

To reduce **standing** privilege (SOC 2 CC6.3/CC6.6), an operator can hold a non-admin role day-to-day and **activate** admin **just-in-time** for a short, justified window — so a compromised everyday session is not a standing admin session. Two steps:

**1. An admin grants eligibility** (one-time, per operator). The granting administrator must hold the administrator role on their own account; a session that is administrator only through an elevation can revoke eligibility but not grant it:

```bash
curl -s -X POST -H "Cookie: yuzu_session=$ADMIN_COOKIE" \
  -H "Content-Type: application/json" -d '{"eligible":true}' \
  https://yuzu.example.com/api/v1/users/alice/elevation-eligibility
```

Eligibility is the per-user `users.elevation_eligible` flag — distinct from holding standing admin, and enumerable for access reviews. An admin **cannot** grant their own eligibility (another admin must). Revoking it (`{"eligible":false}`) immediately ends any elevation the user currently holds.

**2. The eligible operator elevates** when they need admin. A second factor is **mandatory** to elevate, regardless of `--mfa-enforcement` — but which second factor depends on how the operator signed in:

- **Local (password) sessions** must have **MFA enrolled** and are challenged for a fresh **TOTP code** via the shared step-up gate.
- **OIDC/SSO sessions** are NOT challenged for a TOTP code (a durable SSO identity has no local TOTP secret to check against — see "SSO operators" below) — the second factor is the **IdP-attested `amr` claim** captured at login.

```bash
curl -s -X POST -H "Cookie: yuzu_session=$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"justification":"prod incident #42","duration_secs":600}' \
  https://yuzu.example.com/api/v1/elevate
# -> {"status":"ok","expires_in":598,"expires_at":"2026-07-02T13:10:00Z"}
```

`expires_in` is the TRUE remaining seconds computed after the grant (always `<=` the requested `duration_secs` — it is clamped to `--jit-max-elevation-secs` **and** to the session's own absolute lifetime, so it is never an exact echo of the request), and `expires_at` is the same window as a wall-clock RFC3339 UTC timestamp. The session is now admin for the window (capped by `--jit-max-elevation-secs`, default 1h, and by the session's own absolute expiry). For Postgres-backed deployments the elevation is **durably persisted** (`SessionStore`, HA WS-1/1a, ADR-2002 §4), so it **survives a server restart**, bounded by a hard 24h wall-clock ceiling and the session's absolute expiry. It **auto-reverts** when the window lapses, on logout, and on explicit revoke — but no longer on a restart. Step down early with `POST /api/v1/elevate/revoke`. Every step (`role.elevation.granted`/`denied`/`revoked`/`expired`, `user.elevation_eligibility.set`) is audited — the `granted` row's detail records which factor was used (`mfa=local_totp` or `mfa=oidc_amr`). Technical invariants: `docs/auth-architecture.md` "JIT admin elevation".

### SSO operators

An OIDC/SSO operator elevates through the same two steps above, with the following differences:

- **Eligibility is granted on the durable, stable principal** — `oidc:<iss>#<sub>` (the IdP-issuer-scoped subject claim, never the display name) — via the **query form** of the eligibility endpoint, `POST /api/v1/users/elevation-eligibility?username=<principal>`, e.g.:

  ```bash
  curl -s -X POST -H "Cookie: yuzu_session=$ADMIN_COOKIE" \
    -H "Content-Type: application/json" -d '{"eligible":true}' \
    'https://yuzu.example.com/api/v1/users/elevation-eligibility?username=oidc:https://idp.example.com/%23sub-4821'
  ```

  The path form (`POST /api/v1/users/{username}/elevation-eligibility`) remains for local usernames only — an SSO principal contains `/` and `#`, which a path segment cannot carry (the server percent-decodes and strips the URL fragment before route matching), so it must use the query form instead.

  The operator must have **logged in at least once** before an admin can grant eligibility — first login auto-provisions a durable row for the principal (`AuthDB::upsert_sso_identity`); granting eligibility against a principal with no row yet **404s** ("user not found"), since the grant is an `UPDATE` against an existing row, not an `INSERT`.
- **The second factor is the IdP-attested `amr` claim**, captured on the OIDC session at login — never a local TOTP challenge. A session created from a login where the IdP did not assert `amr` is denied elevation unconditionally (`403`, "elevation requires an IdP-attested MFA proof"), independent of the `--mfa-enforcement` setting. Disabling `--jit-oidc-amr-elevation` (default enabled) turns OIDC JIT elevation off entirely — an OIDC session cannot fall back to a local TOTP step-up (its step-up challenge is re-authenticating via SSO), so operators must elevate from a local-authenticated session with local TOTP instead.
- **Finding the principal string**: Settings → Users lists every durable SSO identity with an **SSO** badge next to its row; the row's displayed name IS the `oidc:<iss>#<sub>` principal to use in the eligibility-grant URL above.
- **SAML operators cannot elevate today** — SAML carries no `amr`-equivalent claim, so a SAML session fails closed at the same MFA gate a non-MFA'd OIDC session would hit. SAML JIT elevation is a deferred workstream (see `docs/auth-architecture.md` "JIT admin elevation").
- **Cross-protocol identity-source scoping**: an elevation grant is scoped to the identity *source* that earned it, not just the principal string — the check is a **direct equality** between the session's own `auth_source` and the eligible row's `identity_source` (`local`↔`local`, `oidc`↔`oidc`, `saml`↔`saml`), not an "oidc-or-else-local" fallback. A local session can only spend a grant recorded against an `identity_source='local'` row; a SAML session (SAML JIT elevation is not yet provisioned — see below) would need an `identity_source='saml'` row, which no row carries today, so SAML fails closed at this gate too. This closes a theoretical collision where a crafted SAML NameID (or a legacy local row) shares a principal string with a real OIDC identity.

## MCP Tokens

MCP (Model Context Protocol) tokens are API tokens with an additional `mcp_tier` field that controls what the token holder can do through the MCP endpoint (`POST /mcp/v1/`). MCP tokens enable AI models and automation tools to interact with Yuzu's fleet management capabilities via JSON-RPC 2.0.

### Authorization Tiers

| Tier | Access |
|---|---|
| `readonly` | Read-only tools only (list agents, query audit log, check compliance, etc.) |
| `operator` | Read-only tools + tag writes + auto-approved instruction executions |
| `supervised` | All operations, but destructive actions require admin approval via the approval workflow |

Tier enforcement happens *before* RBAC checks. A tier can block an operation even when RBAC would permit it; conversely, if the tier permits but RBAC denies, the request is still blocked. Both layers must allow.

The `supervised` tier marks destructive operations as approval-gated, and the behaviour now depends on the transport. On the MCP `/mcp/v1/` transport these run through the **ticket-then-recall** approval flow: the first call mints a pending approval, and after an admin approves it, a recall carrying the `approval_id` executes the operation. On a non-MCP transport (the REST API) an approval-gated operation is denied with an `auth.approval_required` audit; only Reads and trivially-allowed operations succeed there.

### Creating an MCP Token

MCP tokens are created via the same `POST /api/v1/tokens` endpoint as regular API tokens, with the addition of the `mcp_tier` field. MCP tokens **require** an expiration date, with a maximum lifetime of 90 days.

```bash
# expires_at: unix epoch seconds, in the future and at most 90 days out (here, 30 days).
# macOS: EXPIRES_AT=$(date -v+30d +%s)
EXPIRES_AT=$(date -d '+30 days' +%s)
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "name": "claude-desktop-readonly",
  "mcp_tier": "readonly",
  "expires_at": $EXPIRES_AT
}
EOF
```

```json
{

### MCP Token Restrictions

MCP tokens have the following restrictions:

- Cannot access admin-only routes (user management, settings) — 403 Forbidden regardless of creator's role
- The tier restricts which operations are permitted (`readonly` → read only; `operator` → read + tag writes + execute; `supervised` → all ops with approval workflow)
- If RBAC is enabled, the creator's actual RBAC role applies after the tier check
- If RBAC is disabled, the creator's legacy role (user/admin) applies after the tier check

  "data": {
    "token": "yuzu_Ab3xK9m2...",
    "name": "claude-desktop-readonly"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

The `mcp_tier` field accepts `"readonly"`, `"operator"`, or `"supervised"`. If `expires_at` is omitted or set to `0` for an MCP token, the server rejects the request, and so does a past or negative value. Maximum expiration is 90 days from creation.

MCP tokens can also be created via the Settings UI under the API Tokens section, which provides an MCP tier dropdown when creating a new token.

### Using an MCP Token

Pass the token in the `Authorization` header when making JSON-RPC 2.0 requests to the MCP endpoint:

```bash
curl -s -X POST http://localhost:8080/mcp/v1/ \
  -H "Authorization: Bearer yuzu_Ab3xK9m2..." \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": { "name": "list_agents", "arguments": {} },
    "id": 1
  }'
```

### Server-Side Kill Switches

| Flag | Description |
|---|---|
| `--mcp-disable` | Reject all requests to `/mcp/v1/` with an error response |
| `--mcp-read-only` | Allow only read-only MCP tools regardless of the token's tier |

### Audit

Every MCP tool invocation is logged as an audit event with `action: "mcp.<tool_name>"` and includes the `mcp_tool` field on the `AuditEvent` record.


### Audit Log Actions

The following audit actions are emitted for authentication and authorization events:

| Action | Result | Description |
|---|---|---|
| `auth.admin_required` | `denied` | Token blocked from admin route (service-scoped, MCP, or non-admin). Not written for an interactive cookie session refused on an auto-loading dashboard panel (Access Users; the Enrollment Tokens, Pending Agent Approvals and Auto-Approve Policies fragments, whether shown on Settings or on Groups and enrolment). A refused token or engine caller, and every refused write, always writes a row |
| `auth.permission_required` | `denied` | Token blocked from permission-gated operation. Not written for an interactive cookie session refused on an auto-loading dashboard panel (the probe-gated Dashboard and Access panels), though `yuzu_auth_topology_floor_denied_total` still counts a floored refusal; token and engine callers always are |
| `auth.scoped_permission_required` | `denied` | Token blocked from agent-scoped operation |
| `auth.approval_required` | `denied` | Supervised-tier MCP token blocked from an approval-gated operation **on a non-MCP (REST) transport**. On the MCP `/mcp/v1/` transport there is no such denial — the operation runs through the ticket-then-recall approval flow (the first call mints JSON-RPC `-32006` `ApprovalRequired`; a recall with the approved `approval_id` executes). See `mcp.md`. |
| `auth.login` | `success` | Successful local password login |
| `auth.login_failed` | `failure` | Failed login attempt |
| `auth.logout` | `success` | User-initiated logout |
| `auth.oidc_login` | `success` | Successful OIDC SSO login |
| `auth.oidc_login_failed` | `failure` | Failed OIDC login attempt; a refused browser-binding check carries `reason=browser_binding_missing`, `browser_binding_mismatch` or `browser_binding_unavailable`; a session that could not be stored carries `reason=session_create_failed`; a sign-in refused because a Settings save replaced the provider carries `reason=provider_replaced` (`;post_mint=true` when refused after the session was minted) |
| `auth.saml_login` | `ok` | Successful SAML 2.0 SSO login |
| `auth.saml_login_failed` | `error` | Failed SAML login attempt (missing binding cookie, oversize body, missing SAMLResponse, or signature/audience/expiry/replay validation failure) |

All `denied` results include a `detail` field explaining the reason. Examples per action:
- `auth.admin_required` → `"MCP token blocked from admin route"`, `"service-scoped token blocked from admin route"`, `"non-admin user blocked from admin route"`
- `auth.permission_required` → `"MCP token tier 'readonly' does not allow Execution:Execute"`, `"RBAC denied Execution:Execute"`
- `auth.scoped_permission_required` → `"agent service 'X' does not match token scope 'Y'"`, `"MCP token tier 'readonly' does not allow Tag:Write"`
- `auth.approval_required` → audit detail `"MCP token tier 'supervised' requires approval for Execution:Execute on a non-MCP transport"`, client-facing message `"operation requires approval for this MCP tier on this transport"` — this is the **non-MCP (REST) path** (`auth_routes.cpp`). On the MCP `/mcp/v1/` transport there is no `auth.approval_required` denial: the ticket-then-recall approval flow handles the operation (`mcp_server.cpp`), so the MCP tool call mints `-32006` `ApprovalRequired` and a recall with the approved `approval_id` executes.

### JSON Error Envelope

All authentication and authorization errors use the standard JSON envelope:

```json
{
  "error": {
    "code": 403,
    "message": "service-scoped token does not grant Agent:Execute (requires ITServiceOwner AND an explicit service-scope allow-list entry)"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

HTTP status codes:
- `401 Unauthorized` — No valid authentication provided (missing/invalid token). Also returned when the token store itself is unavailable: authentication fails closed rather than revealing storage state. If valid tokens suddenly return `401`, check `/readyz` for `api_token_store` before rotating credentials.
- `403 Forbidden` — Authentication valid but operation not permitted (scope/tier/role restriction)
- `503 Service Unavailable` — Required backend unavailable: TagStore for scope verification, or the API token store database failed to open at startup (token CRUD routes)

## API Reference Summary

| Method | Endpoint | Auth required | Description |
|---|---|---|---|
| `POST` | `/login` | No | Authenticate with username/password; returns JSON `{"status":"ok"}` + session cookie |
| `POST` | `/logout` | Session | Invalidate current session; returns JSON `{"status":"ok"}` |
| `GET` | `/auth/oidc/start` | No | Begin OIDC PKCE login flow (302 redirect to IdP); sets the browser-binding cookie that `/auth/callback` requires (refusals: `browser_binding_missing` / `_mismatch` / `_unavailable`) |
| `GET` | `/auth/callback` | No | OIDC callback (IdP redirects here; creates session, 302 to `/`) |
| `GET` | `/auth/saml/start` | No | Begin SAML 2.0 SP-initiated login flow (302 redirect to IdP via HTTP-Redirect binding); Linux/macOS only |
| `POST` | `/saml/acs` | No | SAML Assertion Consumer Service — IdP POSTs the response here; validates and creates session; Linux/macOS only |
| `GET` | `/api/v1/me` | Any (session, Bearer, or X-Yuzu-Token) | Current user info and role |
| `POST` | `/api/v1/tokens` | RBAC `ApiToken:Write` | Create a new API token |
| `GET` | `/api/v1/tokens` | RBAC `ApiToken:Read` | List tokens owned by the authenticated user |
| `DELETE` | `/api/v1/tokens/{id}` | RBAC `ApiToken:Delete` | Revoke (soft-delete) an API token |
| `POST` | `/api/v1/tokens/{id}/rotate` | RBAC `ApiToken:Rotate`, self-service | Mint an overlap-pair successor for a token you own (see [Rotating a Token](#rotating-a-token)) |
| `POST` | `/api/v1/tokens/{id}/confirm` | RBAC `ApiToken:Rotate`, self-service | Maker-checker confirmation closing an in-flight rotation |
| `POST` | `/mcp/v1/` | Bearer token with MCP tier | MCP JSON-RPC 2.0 endpoint (22 read-only tools, 3 resources, 4 prompts) |

## Planned Features

| Feature | Phase | Status |
|---|---|---|
| AD/Entra directory sync (LDAP user/group import) | 7.5 | Stub |
