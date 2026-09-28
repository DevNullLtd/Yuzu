# Authentication & Authorization — Yuzu Server

Reference for the authentication and authorization features implemented in the Yuzu server. CLAUDE.md keeps only the hard invariants; this document is the implementation history and feature inventory.

## Transport and identity

- **mTLS** for agent ↔ server gRPC connections. Note that a migration from gRPC->QUIC is intended.
- **Windows certificate store integration** — agent can read mTLS client cert + private key from the Windows cert store instead of PEM files. Uses CryptoAPI/CNG (`CertOpenStore`, `CertFindCertificateInStore`, `NCryptExportKey`). Searches Local Machine first, falls back to Current User. Exports full certificate chain (leaf + intermediates) as PEM. CLI flags: `--cert-store MY --cert-subject "yuzu-agent"` or `--cert-thumbprint "AB12..."`.
- **Certificate hot-reload** — HTTPS cert/key PEM files are polled for changes (default 60s interval) and hot-swapped without server restart. Validates PEM parse, cert/key match, and key file permissions before applying. gRPC TLS reload not supported. CLI: `--no-cert-reload`, `--cert-reload-interval`. Audit action: `cert.reload`. Metrics: `yuzu_server_cert_reloads_total`, `yuzu_server_cert_reload_failures_total`.

Certificate setup instructions: `scripts/Certificate Instructions.txt`.

## Login and session management

- **RBAC login** — session-cookie auth with PBKDF2-hashed passwords in `yuzu-server.cfg`. Legacy roles: `admin` (full access) and `user` (read-only). First-run interactive setup prompts for credentials.
- **Login page** — dark-themed, with greyed-out OIDC SSO stub where appropriate. Yuzu does not support Light Mode.
- **Settings page** (admin-only) — TLS toggle, PEM cert upload, user management, enrollment tokens, pending agent approvals, AD/Entra section.
- **Hamburger menu** — upper-right dropdown with Settings, About (popup), and Logout.
- **Auth middleware** — `set_pre_routing_handler` redirects unauthenticated requests to `/login`, returns 401 for API calls.
- **HTMX paradigm** — Settings page uses HTMX for all server interactions; server renders HTML fragments. Vanilla JS reserved only for clipboard copy. Dominant UI pattern going forward.
- **Session revocation REST surface (CC6.3 revocation, CC6.7 disposition, CC6.8 termination).**
  - `DELETE /api/v1/sessions?username=<name>` — admin-only via `UserManagement:Write`. Cookie sessions only; API tokens deliberately not revoked.
  - `DELETE /api/v1/sessions/me` — any interactive authenticated principal. Wipes cookie sessions AND revokes the caller's API tokens (lost-laptop UX). MCP-tier and service-scoped tokens rejected with 403. Response sets `Set-Cookie: yuzu_session=; Max-Age=0` so the client side completes the disposition.
  - Both wrap `AuthManager::invalidate_user_sessions`, which returns `RevokeResult { count, db_persisted }`. Since HA WS-1/1a (ADR-2002 §4) sessions ARE durable (`SessionStore`, see "Durable operator sessions" below): with a store wired it deletes every durable row for the user FIRST (bumping the write-generation so all replicas drop their cached copies), then wipes this replica's cache — `count` is the fleet-wide total killed and `db_persisted` reflects the durable-delete outcome (false on a store error, with the local wipe still done so the operator's "kill NOW" intent is honored — the REST handler's `result="partial"`/`db_error=true` audit path). On a legacy config-file-only deployment (no store) it stays an in-memory wipe with `db_persisted=true`.
  - Audit actions split for SIEM correlation: `session.revoke_all` (cross-user) vs `session.revoke_all.self` (self via either route, including admin self-target through the admin path). Both use `target_type=User` (project PascalCase convention). `result` ∈ {`success`, `partial`, `denied`}.
  - Prometheus counter `yuzu_auth_sessions_revoked_total{caller, result, scope}` for CC7.2 anomaly detection.
  - Self-target guard distinction (DO NOT CONFLATE WITH `#397/#403`): the existing `#397/#403` self-target guard on `DELETE /api/settings/users/<self>` and role demotion is a hard 403 to prevent admin-role self-lockout (an unrecoverable state). Session revocation self-target is recoverable (re-auth) and is permitted but audited as `.self`. Future refactors must not "fix" the session-revocation self-target into a hard 403.

### Durable operator sessions (HA WS-1/1a, ADR-2002 §4)

Operator sessions are durable Postgres rows so a session survives a core-replica
restart/failover and — with DB-clock authority (#3715, below) — validates
identically on any replica under arbitrary cross-host clock skew, a prerequisite
of the HA "safe-to-scale" gate. The design:

> **DB-clock authority (ADR-2002 §4, completed — WS-1/1a, #3715).**
> Durable timestamps are **authored from PostgreSQL `now()`** (in the store, in
> SQL — `SessionStore::create`/`set_elevation`/`mark_mfa`/`touch_activity`), NOT
> the calling replica's `system_clock`, so every replica dates a session in the
> ONE DB clock domain — the fix for cross-host skew. Reads (`find`) return
> `db_now_ms` in the **same atomic SELECT**; `AuthManager` adjudicates absolute
> expiry / idle / elevation / MFA against `db_now_ms` and then derives a **local
> monotonic (`steady_clock`) remaining-duration deadline** at cache-populate
> (`derive_session_deadlines`), so the per-request hot path touches neither the DB
> nor the local wall clock and is immune to local skew/steps.
>
> A backward `now()` on the DB primary is the residual the reversal admits
> (ADR-2002 §4). Four layered defences bound it: **(1)** every derived remaining
> is CLAMPED so a lowered `now` cannot inflate the LIVED duration past its
> authored maximum — elevation against `elevation_issued + kMaxElevationWindow`,
> the base session against `created_at`, MFA against its window ceiling; **(2)**
> the authored-width ceilings still REJECT an over-`kMaxElevationWindow` (24 h)
> elevation and a future-dated MFA proof outright; **(3)** a generous
> `kWallSanitySkew` (5 min) wall-clock ceiling backstops `steady_clock`'s
> suspend-blindness (a suspended replica's monotonic clock pauses); **(4)**
> DB-primary clock integrity is monitored — `reap_expired()` reads `now()` itself
> and declines + raises `yuzu_auth_session_reap_clock_anomaly_total` (distinct
> from the local host-clock `yuzu_auth_local_clock_backward_total`) on a backward
> step, alerted by `YuzuSessionReapClockAnomaly`. So "validates identically on any
> replica" now holds under arbitrary cross-host skew (the steady deadline is
> derived from the shared DB clock), with the wall ceiling assuming replicas stay
> roughly NTP-synced for the suspend backstop only.

- **Store.** `SessionStore` (`server/core/src/session_store.{hpp,cpp}`, schema
  `session_store`) is a born-on-PG, fail-closed store (ADR-0012). The row key is
  the **SHA-256 of the bearer token**, never the raw token (secret-at-rest); the
  raw token is hashed at every store boundary. Rows carry the authz-relevant
  `Session` fields in wall-clock epoch-millis.
- **Write-through + validate cache.** `AuthManager` write-throughs every session
  op to the store and validates against it, with the in-memory `sessions_` map
  as a **generation-gated process-local cache**: a durable `write_generation`
  counter is bumped in the same txn as every authz-affecting mutation (create,
  invalidate, elevate, revoke-elevation, mfa-verify — but **not**
  `touch_activity`, a sliding idle update). `validate_session` polls the
  generation on a ~1s interval (single-flight); when it advances (a mutation
  landed, possibly on another replica) the whole cache is cleared and the next
  lookup re-reads authoritative state. Operator sessions number in the tens, so a
  global generation whose bump clears the whole cache is cheap. **Two distinct
  staleness bounds:** in NORMAL operation a mutation propagates within the ~1s
  refresh interval. During a refresh OUTAGE (PG brownout, failed
  `read_generation`) the cache is served UNCHANGED only within a bounded
  stale-serve budget — `kSessionGenStaleServeBoundMs` (30s) from the last
  SUCCESSFUL refresh (the `rbac_store` pattern the ADR names). Past that budget
  the generation view is "stale" and NO cache hit is trusted: every validate —
  including a locally-minted session — falls through to the authoritative store
  and **fails closed (401)** while the store stays degraded. So a
  revoked/demoted/elevated session cannot ride the cache past ~30s of outage,
  not to its 8h absolute expiry.
- **Authoritative reads.** A `SessionStore::find` returns
  `expected<optional<Row>>`: `nullopt` = definitively absent, `unexpected` = DB
  degraded. `validate_session` never treats a degraded read as "no valid
  session" in a way that grants — a degraded lookup **fails the request (401)**.
  A locally-minted session is served from the cache during a brief blip (within
  the stale-serve budget above); once the budget is exceeded even it falls to the
  authoritative read and fails closed until PG recovers.
- **Wall-clock (the reversal) + ceilings.** The `Session` lifetime fields
  (`expires_at`, `mfa_verified_at`, `elevated_until`, `last_activity_at`) moved
  from `steady_clock` (monotonic) to `system_clock` (wall-clock), because a
  durable row is compared against absolute wall time on any replica. The
  NTP-step resistance the monotonic clock gave is replaced by two
  defense-in-depth wall-clock controls: (1) `is_elevated()` enforces a hard
  `kMaxElevationWindow` (24 h) ceiling anchored by `Session::elevation_issued_at`
  (stamped with `elevated_until` at every grant, cleared with it on revoke), so
  a forward clock corruption or an anchor-less `elevated_until` cannot extend
  admin past the ceiling; (2) the MFA step-up gate treats a **future-dated**
  proof (`mfa_verified_at > now`, i.e. a backward step) as no proof — fail
  closed. DB-primary clock integrity is a monitored security dependency (HA
  WS-11).
- **Retention.** `SessionStore::reap_expired` is a wall-clock bulk delete, so it
  joins the clock-guarded-retention set (routed concern #2360/#2361): an
  advisory lock taken as its own statement, a persisted `reap_anchor_ms`
  sanitised against implausible forward *and* backward skew (declined, not acted
  on), an unconditional per-pass cap, and a recorded missing-anchor decision
  (proceed — sessions are re-mintable). It **deliberately carves out** two of the
  seven parts, the `api_token_store` precedent (recorded here per the rule's
  "record which way you went"): part (1) the would-wipe probe — sessions reach
  100% expiry as routine drain, so it cannot separate a true from a false
  positive; and part (4) fact-set anomaly dedup — a declined pass is logged and
  surfaced as `yuzu_auth_session_reap_clock_anomaly_total` (the DB-clock-integrity
  monitor) rather than deduped by fact identity. Single-writer today (one
  server); it becomes PG-shared state under the ADR-0012 advisory lock when a
  second replica lands.
- **Legacy path.** Config-file-only deployments (no `--postgres-dsn`, so no
  pool) leave `AuthManager::session_store_` null and keep the pre-HA in-memory
  sessions unchanged. The store is wired at boot only when the PG substrate is
  up; a wired store that fails to migrate/open is a **fail-closed boot error**
  (ADR-0007) and is surfaced at `/readyz` + `/healthz` via
  `AuthManager::is_session_store_ok()`.

## Account lockout (SOC 2 CC6.3)

Brute-force / credential-stuffing protection on the **local-password** login
path (`POST /login`). OIDC delegates throttling to the IdP; the MFA
code-verification path has its own per-token failure rate-limit — neither is in
scope here.

- **State** lives in three columns on `auth.users` (Postgres schema `auth` —
  originally SQLite `auth.db` migration v3, carried unchanged into the
  single-migration Postgres schema, ADR-0006): `failed_login_count`,
  `last_failed_login_at`, `locked_until` (`NULL` = not locked). A non-existent
  username has no row, so spraying random usernames neither locks a
  non-existent account nor grows storage (anti-enumeration). All three
  accessors (`AuthDB::lockout_status` / `record_failed_login` /
  `clear_failed_logins`) are parameterised via `pg::exec_params` and use
  `RETURNING` (the SQLite-era `sqlite3_changes()` race, #1033, does not apply
  on Postgres — `RETURNING` was already the idiom here).
- **Policy** is config, not schema, so operators retune without a migration:
  - `--auth-lockout-threshold` (`YUZU_AUTH_LOCKOUT_THRESHOLD`, default `5`,
    `0` disables) — consecutive failures before lock.
  - `--auth-lockout-window-secs` (`YUZU_AUTH_LOCKOUT_WINDOW_SECS`, default
    `900`) — lock duration. The lock **auto-expires** after the window; it is
    never permanent, so it cannot be weaponised to permanently DoS a
    legitimate principal. The posture is logged once at boot for CC6.3
    evidence.
- **Flow** in `auth_routes.cpp` `POST /login`:
  - *Pre-check* (before PBKDF2): if the account is currently locked, reject
    with the **same generic 401** as a bad password — no `Retry-After`, no
    "locked" wording, so the response body is not a username-enumeration /
    lock-state **content** oracle. `verify_password` is skipped entirely, so the
    ~100 ms PBKDF2 is never burned on a locked account. Fail-open on a read error
    (lockout protects against *wrong* passwords; `verify_password` is still the
    real gate). *Accepted residue:* skipping PBKDF2 makes the locked path
    measurably faster than a known-user wrong-password 401, so response **timing**
    is a weak lock-*state* oracle (it reveals that an account is locked, never a
    credential). This is an accepted trade-off — adding a constant-time floor to
    the locked path would re-introduce the PBKDF2-cost DoS the skip exists to
    avoid.
- **Concurrency — per-username serialized (single-node).** The flow is
  *check-then-act* (`lockout_status` → `verify_password` → `record_failed_login`).
  Without serialization a **synchronized burst** for one username could all
  observe `locked=false` and each verify a password before any sibling recorded
  its failure, so the effective single-burst guess budget would be the in-flight
  concurrency rather than `auth_lockout_threshold` (the per-IP `login_rate_limit`
  does **not** bound a distributed botnet firing one request per IP). The whole
  sequence is therefore held under a **striped per-username login lock**
  (`AuthRoutes::login_lock_for` / `login_locks_`): concurrent attempts for one
  account serialize, so at most `threshold` reach password verification before
  the lock arms (covered by a barrier-style concurrent route test). Different
  usernames hash to different stripes and log in fully in parallel — only a burst
  against one account is throttled, which is the intended effect. This is
  **still single-process (in-memory) scope** — the auth store's ADR-0006
  Postgres migration (Wave 3, shipped) moved the underlying `users` table
  substrate but did **not** change this algorithm: the striped lock lives in
  `AuthRoutes`, not the database, so it still only serializes attempts within
  one server process. A DB-atomic attempt-reservation (now straightforward on
  Postgres — e.g. `UPDATE ... WHERE failed_login_count < threshold RETURNING`)
  is the multi-replica-correct form and remains a tracked follow-up, not
  something this migration delivered incidentally. `login_rate_limit` remains
  the companion control for the distributed vector.
  - *On failure*: `record_failed_login` increments the counter and arms
    `locked_until` on the threshold-th failure. A window that has **fully
    expired** starts a fresh attempt budget (the waited-out user gets their
    attempts back).
  - *On success*: `clear_failed_logins` resets the counter (covers all three
    success exits — no-MFA mint, MFA challenge, enforced enrollment).
- **Admin unlock** — `POST /api/v1/users/<name>/unlock`, gated by
  `UserManagement:Write` and the MFA step-up gate. Self-target is permitted
  (recoverable, same reasoning as session self-revoke). The operability path
  for an operator who can't wait out the window.
- **Audit** — `auth.lockout.applied` (once, on the threshold crossing),
  `auth.lockout.cleared` (success reset or admin unlock, actor recorded). A
  blocked attempt while already locked is counted via the metric, **not**
  audited per-attempt (flood-amplification, same rationale as the MFA pending
  load-shed).
- **Metrics** — `yuzu_auth_lockout_applied_total`,
  `yuzu_auth_lockout_blocked_total`.

## Inactivity (idle) session timeout (SOC 2 CC6.3)

`/auth-and-authz` skill gap matrix P1 #8. A **sliding** idle window that
invalidates an operator dashboard cookie session after a period of inactivity,
*under* the absolute 8-hour session lifetime (`kSessionDuration`). Wires the
previously-reserved `sessions.last_activity_at` column end-to-end.

- **Config** — `--session-inactivity-secs` (`YUZU_SESSION_INACTIVITY_SECS`),
  `Config::session_inactivity_secs`. **Default 0 = disabled** (opt-in): the
  absolute lifetime already exists and an idle-logout that drops a legitimate
  user mid-coffee-break is a behaviour change, so it is off unless an operator
  turns it on (recommended `900` = 15 min). Boot posture is logged for CC6.3
  evidence. Enabling it satisfies the CC6.3 inactivity-timeout control.
- **Durable since HA WS-1/1a (ADR-2002 §4).** Operator sessions are durable
  Postgres rows in `SessionStore` (schema `session_store`); `AuthManager`
  write-throughs every session and validates against it, with the in-memory
  `AuthManager::sessions_` map serving as a generation-gated process-local
  cache (see "Durable operator sessions" below). The idle state
  (`last_activity_ms`) is a durable row column **authored from Postgres `now()`**
  (GREATEST-clamped, monotonic) via `SessionStore::touch_activity`, which
  deliberately does NOT bump the write-generation (a slide is not an authz change,
  so it never invalidates any replica's cache). The idle window is adjudicated
  against a **local monotonic (`steady_clock`) anchor** derived from the DB clock
  at cache-populate (`derive_session_deadlines`), so it survives a replica
  restart/failover and ages identically on any replica under arbitrary cross-host
  skew (DB-clock authority, #3715). (Before HA WS-1/1a the idle state lived only
  in-memory on a monotonic `steady_clock`; it is now a durable DB-clock-authored
  column adjudicated on a derived steady deadline, with the JIT-elevation/MFA
  windows carrying the same treatment plus hard authored-width ceilings — see
  below.) `AuthManager::session_inactivity_` holds the configured window (set once
  at startup via `set_session_inactivity`).
- **Enforcement is in `validate_session`** (the same place the absolute
  `expires_at` is checked, and which already conditionally upgrades its shared
  lock for the opportunistic reap). When the feature is on: a session idle
  longer than the window is **rejected and evicted** (the reap re-reads
  `last_activity_at` under the write lock so a concurrent touch at the boundary
  doesn't kill a now-active session); an active one has `last_activity_at`
  **slid forward** (the window slides). **The touch is throttled** — the window
  is advanced (which needs the exclusive lock) at most once per
  `touch_granularity` (a quarter of the idle window, capped at 30 s), so a burst
  of requests for an active session stays on the **shared** lock rather than
  serialising on `mu_`; `last_activity_at` therefore lags real activity by at
  most the granularity (far inside any minutes-scale window, so an active session
  is never wrongly evicted — idle-out fires within `[window − granularity,
  window]`). The idle-*disabled* small-map read stays a pure shared-lock path (no
  behaviour change for deployments that leave it off).
- **Scope: cookie sessions only.** API tokens and MCP tokens resolve through
  `synthesize_token_session` (their own store), never `validate_session`, so a
  long-lived automation token is **never** idle-timed-out. OIDC sessions are
  subject to the same idle window but the user simply re-authenticates via SSO.
- **Durable mirror (HA WS-1/1a).** A throttled touch advances the durable
  `last_activity_ms` column via `SessionStore::touch_activity`, at most once per
  session per `kActivityPersistGranularity` (60 s), so the sliding update is not
  a per-request SQL write and — because it does NOT bump the write-generation —
  never invalidates any replica's validate cache. `last_activity_at` therefore
  survives a restart (unlike the pre-HA in-memory state, which reset on
  restart). The session surface lives on the dedicated `SessionStore`, never on
  `AuthDB` (which has no session table — see "AuthDB — persistent authentication
  store" below). Idle expiry is not separately audited (neither was absolute
  expiry) and emits **no Prometheus counter** — the observable signal is the
  `auth.login` audit row on re-authentication.

## MFA / TOTP (v0.12+, SOC 2 CC6.6)

Full design: `docs/auth-mfa-design.md`. Summary:

- **RFC 6238 TOTP** (HMAC-SHA1, 30 s step, 6 digits, ±1 step skew with
  replay protection). 10 single-use base32 recovery codes per
  enrollment, PBKDF2-SHA256 hashed.
- **Self-service enrollment** via Settings → Multi-Factor Authentication.
  One-time `otpauth://` reveal in the same `<div class="token-reveal">`
  pattern as API-token issuance.
- **Login challenge** — `POST /login` returns HTTP 202 +
  `mfa_pending_token` (opaque, in-process, `cfg.mfa_login_pending_secs`
  TTL) when the user has TOTP enrolled; browser swaps to a TOTP form
  and posts to `POST /login/mfa`. Recovery codes share the same
  endpoint.
- **Storage — encryption-at-rest SHIPPED (ADR-0010).** `auth.users.mfa_totp_secret`
  (BYTEA) is envelope-encrypted via `pg::SecretCodec` — AES-256-GCM, DEK
  wrapped by the `FileKeyProvider`-custodied install KEK, AAD-bound to
  `{"auth", "users", "mfa_totp_secret", <row id>}` so a ciphertext blob
  cannot be swapped between rows. This landed with the `auth`/`scim_store`
  Postgres cutover (ADR-0006 Wave 3) and is `SecretCodec`'s **first real
  consumer** (ADR-0010 was accepted with no production caller until this).
  The SQLite-era `auth_kv` scaffolding table this doc previously described as
  the planned mechanism was **not** carried into the Postgres schema — it was
  unused scaffolding, superseded outright by `SecretCodec`. A store/decrypt
  failure on this column (tamper, wrong/rotated KEK, corrupt blob) surfaces
  as the distinct `AuthDBError::SecretUnavailable` and every MFA reader fails
  **closed** on it — see "MFA fails closed on secret-read failure" below;
  this is a hard invariant, not an implementation detail.
- **Everything else stays a verify-only hash** — password hashes, recovery
  codes, enrollment tokens, and SCIM bearer tokens are unaffected by
  `SecretCodec`; there is nothing to decrypt for a one-way hash.
- **CLI flags / Config** — `--mfa-enforcement <optional|admin-only|required>`
  (PR 1 honours `optional` only), `--mfa-step-up-window-secs` (default
  300), `--mfa-login-pending-secs` (default 120).
- **Step-up on high-risk surfaces** — `cfg.mfa_step_up_window_secs` (300 s
  default) controls how long after a TOTP proof high-risk endpoints
  accept the session as "stepped up." PR 2 wires the 11 step-up sites
  (user delete, role change, token create/revoke, session revoke,
  Guardian rule write / push, software-package write, software-deploy
  execute, file-retrieval upload) and the `/login/mfa/stepup` route.
- **OIDC `amr` short-circuit** (PR 3) — `IdTokenClaims.amr` parsing so
  IdP-asserted MFA skips the local TOTP step.
- **MFA fails CLOSED on a secret-read/decrypt failure (ADR-0006/0010
  hardening, shipped with the Postgres cutover).** `AuthDBError::SecretUnavailable`
  is a distinct outcome from both "not enrolled" and "code rejected" — it
  means `mfa_totp_secret`'s envelope could not be read/decrypted (Postgres
  outage mid-read, tamper, an unresolvable/rotated KEK, a corrupt blob) while
  `mfa_enrolled_at` says the account IS enrolled. Every reader that touches
  the secret (`mfa_status`, `mfa_verify_login_code`, `mfa_verify_enrollment`,
  `mfa_init_enrollment`'s provisional-reuse arm) returns this distinctly, and
  every caller (`auth_routes.cpp`'s `/login/mfa` + `/login`'s MFA-pending
  branch, `mfa_step_up.cpp`'s `require_mfa_step_up`, `settings_routes.cpp`'s
  MFA fragment + enrollment routes) maps it to a **503** (retry/alert) —
  **never** to "not enrolled" (which would silently drop an enrolled
  privileged account's second factor and let a password-only login mint a
  session) and **never** to "code rejected" (which would burn one of the
  user's limited verification attempts against a transient outage). This
  closes a pre-existing latent MFA-bypass class: before this hardening, ANY
  read failure on the enrollment state collapsed to "not enrolled" by
  omission, and a Postgres substrate makes read failures during a network
  partition or failover materially more likely than a local SQLite file ever
  did — the fail-closed handling was bundled into this migration precisely
  because the substrate change made the gap exploitable, not merely
  theoretical.

Hard invariants live in §"Hard invariants" of `docs/auth-mfa-design.md` —
do not regress them when shipping PR 2 / PR 3.

## JIT admin elevation (SOC 2 CC6.3/CC6.6)

`/auth-and-authz` skill gap matrix P1 #9. Reduce **standing** privilege: a
pre-authorized operator holds a non-admin base role day-to-day and **activates**
admin **just-in-time** for a bounded, justified, MFA-gated window, then
auto-reverts — so a compromised everyday session is not a standing admin session.

- **Eligibility is a per-user flag** — `users.elevation_eligible`
  (originally SQLite `auth.db` migration v5; now a column on the single-migration
  Postgres `auth.users` schema, ADR-0006), distinct from holding standing admin and trivially enumerable
  for access reviews. Admin-managed (and MFA-step-up-gated) via
  `POST /api/v1/users/<name>/elevation-eligibility` `{"eligible": bool}`
  (`AuthDB::set_elevation_eligible`/`is_elevation_eligible`, parameterised,
  `RETURNING` — no `sqlite3_changes()`, #1033). Default 0 (not eligible) — nobody
  gains elevation rights silently. **Self-grant is blocked** (an operator — even
  one acting under an active elevation — cannot set their own eligibility, so a
  temporary admin window can't manufacture a durable self-elevation right).
  **Revoking eligibility immediately terminates any in-flight elevation** for
  that user (`AuthManager::revoke_user_elevations`, symmetric with the session
  wipe on demote/delete) — an incident-response "revoke now" drops admin access
  rather than leaving it standing for the window.
- **Activation** — `POST /api/v1/elevate`
  `{"justification": <required>, "duration_secs": <int>}`. Requires the caller to
  be eligible **and** present a mandatory second factor **and** pass a fresh MFA
  step-up. The mandatory second factor is **local TOTP enrollment** for a local
  session, or a **fresh IdP-attested MFA `amr` proof** for an OIDC session when
  `--jit-oidc-amr-elevation` is enabled (OIDC elevation is **restored** by #1852's
  durable SSO identity provisioning — an OIDC session's stable principal now has a
  `users` row to key eligibility on; see "OIDC-amr elevation" below). This
  requirement is mandatory **unconditionally** here, NOT gated on
  `--mfa-enforcement`: elevation is the privilege-crossing boundary (non-admin →
  full admin), so — unlike the other step-up sites where the actor is already
  admin — an eligible operator who presents no second factor (a local session
  with no enrolled TOTP, or an OIDC session with no `amr` proof / the toggle
  off) is refused (403, `role.elevation.denied`). Sets
  `Session::elevated_until = min(now + min(duration, --jit-max-elevation-secs), session.expires_at)`
  (default cap 1h, max 24h; an absent/0 `duration_secs` defaults to the cap, a
  negative one is a 400, a present-but-wrong-typed field is a 400). **The window
  is also clamped to the session's own absolute `expires_at`** (follow-up B,
  shipped) — an elevation can never outlive the cookie session that carries it,
  even when the requested/capped duration would otherwise extend past it.
  **A session already AT or PAST its own `expires_at` — e.g. one that crosses
  its absolute lifetime in the window between `validate_session` and
  `elevate_session` — is REJECTED (401), not granted a zero-or-negative-length
  window** (governance hardening round, UP-1/UP-4 dead-window guard): a `200
  ok` response with `expires_in:0` would mislead a scripted caller into
  believing it holds admin, and the lapsed window would later mint a spurious
  `role.elevation.expired` for privilege that was never actually conferred.
  `AuthManager::elevate_session` computes this and leaves the session
  unmutated when it applies; the handler's existing nullopt→401 path (already
  used for "session vanished between validate and elevate") covers it, no
  separate branch needed. The response reports the TRUE remaining time as
  `expires_in` (seconds, computed after any clamp — always `<=` the
  requested/capped duration) alongside an absolute `expires_at` (RFC3339 UTC —
  read directly off the `system_clock` `elevated_until`, which since HA WS-1/1a
  (ADR-2002 §4) is a durably-persisted wall-clock instant, so it carries the
  same meaning across a restart and off-process). The justification is
  sanitised (control bytes incl. DEL →
  space) and capped (1 KiB) into the audit detail. The `role.elevation.granted`
  audit is **fail-closed**: if it can't persist, the elevation is rolled back
  (compensating `revoke_elevation`) and the call 500s with `Sec-Audit-Failed`
  — a privileged activation never stands without a record. Audits
  `role.elevation.granted` (justification + the true post-clamp duration +
  `expires_at` — kept in sync across the audit row, the JSON response, and the
  analytics event); `role.elevation.denied` for an ineligible /
  failed-eligibility / not-MFA-enrolled caller.
- **Effective role** — `auth::effective_role(session)` returns `admin` while
  `is_elevated(session)` holds, else the base `role`. THE authorization functions
  gate on it: `require_admin` checks `effective_role`, and
  `require_permission`/`require_scoped_permission` **short-circuit to allow** an
  elevated session (full admin for the window). Since HA WS-1/1a (ADR-2002 §4)
  `elevated_until`/`elevation_issued_ms` are **durably persisted** to
  `SessionStore` and authored from Postgres `now()` (#3715), so the elevation
  **survives a server restart** and adjudicates identically on any replica.
  `is_elevated` decides against a **local monotonic (`steady_clock`) deadline**
  derived from the DB clock at cache-populate (`derive_session_deadlines`) — with
  a generous `kWallSanitySkew` wall backstop for `steady_clock`'s suspend-
  blindness — and REJECTS a grant whose authored width exceeds the hard
  `kMaxElevationWindow` (24 h) ceiling or whose issued-at is in the future
  (a backward clock step below the grant). It is also bounded by the session's own
  absolute expiry, and auto-reverts when the window lapses or on explicit
  revoke/logout, but **not** on restart. See `docs/auth-architecture.md` →
  "Durable operator sessions (HA WS-1/1a, ADR-2002 §4)".
- **Scope: interactive cookie sessions only.** `/api/v1/elevate` reads the
  session cookie and `elevate_session` keys on the cookie token; API and MCP
  tokens resolve through `synthesize_token_session` (no cookie, no
  `elevated_until`), so a long-lived automation credential can **never** be
  elevated.
- **OIDC-amr elevation — RESTORED by durable SSO identity (#1852).** As of the
  `oidc:<iss>#<sub>` principal re-key (#1837/#1857), an OIDC session's principal
  is not a local-charset `users` username (it contains `:`/`#`), and before #1852
  the OIDC login path wrote **no `users` row at all** — so `is_elevation_eligible`
  fail-closed and OIDC operators could not JIT-elevate. #1852 auto-provisions a
  durable `users` row for the stable principal (`AuthDB::upsert_sso_identity`,
  migration v6 — see "Durable SSO identity" below), and the elevate route's
  target-lookup chokepoints now validate through `is_valid_principal` (a strict
  superset of `is_valid_username` that additionally accepts a reserved-prefixed
  `oidc:`/`saml:`/`ad:` principal), so an admin can grant `elevation_eligible`
  against the SSO principal and the eligibility gate passes. This does **not**
  resurrect the pre-#1837 accident where an SSO display name that coincidentally
  equalled a *local* username borrowed that local user's eligibility + TOTP — the
  principal is now the immutable `oidc:<iss>#<sub>`, bound to its own provisioned
  row.
- **OIDC-amr elevation (design).** An OIDC operator whose SSO
  session was authenticated with IdP MFA — asserted via the OIDC `amr` claim
  at `/auth/callback`, which seeds `Session::mfa_verified_at` when
  `amr_asserts_mfa(claims.amr)` is true (see `docs/auth-mfa-design.md` "OIDC
  interop") — CAN elevate without local TOTP enrollment. **Prerequisite:**
  eligibility is keyed on the `users` table row, which the OIDC login path now
  **auto-provisions** for the stable principal (`upsert_sso_identity`, #1852 —
  see "Durable SSO identity" below); an admin grants `elevation_eligible` against
  that SSO principal directly, no manual `POST /api/v1/users` step. MFA status is
  **not** consulted for an OIDC session — its second factor is the IdP `amr`
  proof, checked below, never a local TOTP secret. The mandatory-second-factor
  check at
  `POST /api/v1/elevate` (`auth_routes.cpp`) branches EXPLICITLY on identity
  source, not a single "skip the local check" flag:
  ```cpp
  const bool oidc_amr_proof = session->auth_source == "oidc" &&
                              session->mfa_verified_at.time_since_epoch().count() != 0;
  const bool oidc_amr_elevation = cfg_.jit_oidc_amr_elevation && oidc_amr_proof;
  if (session->auth_source == "oidc") {
      if (!oidc_amr_elevation) { /* 403 — distinct reason for no-amr vs toggle-off */ }
      // else fall through to elevation_step_up (freshness on the amr seed)
  } else {
      if (auto st = db->mfa_status(session->username); !st || !st->enrolled) { /* 403 */ }
  }
  ```
  **LOAD-BEARING (security-F1, hardening-round consistency S-2):** an OIDC
  session must **never** fall through to the local `mfa_status` lookup. A
  local *namesake* account (same username, unrelated identity) might be
  TOTP-enrolled, and an earlier draft that used a single `if (!oidc_amr_elevation)
  { <local enrollment check> }` guard let an OIDC caller with no amr proof
  inherit that namesake's enrollment — passing the enrollment gate on a factor
  the OIDC caller never actually presented, then possibly clearing
  `elevation_step_up` too (its no-proof-OIDC branch PASSes under
  `--mfa-enforcement=optional`), granting elevation with a **mislabeled**
  `mfa=local_totp` audit row. The disjoint `auth_source` branch above closes
  that: OIDC sessions have exactly one path to "second factor satisfied" (a
  seeded amr proof with the toggle on) and never consult the `users` MFA
  column at all. This seam remains the ONLY place that unconditionally blocks
  a single-factor (no-amr) OIDC session from elevating — `require_mfa_step_up`
  alone cannot, per the note above. **SAML** sessions carry no `amr` equivalent
  yet: they are provisioned but cannot elevate (no local TOTP to check either;
  SAML-MFA is a future workstream).
  A seeded-but-stale proof still falls through to the **same**
  `elevation_step_up` freshness gate every other session goes through — never
  a silent grant. The granted audit row records which factor source was used:
  `role.elevation.granted` detail is `duration_secs=<n> mfa=<oidc_amr|local_totp>
  expires_at=<rfc3339> justification=<text>` — `duration_secs` is the TRUE
  post-clamp window (follow-up B), and BOTH machine-parsed tokens (`mfa=` and
  `expires_at=`) are placed **before** the free-text `justification=` field
  (hardening-round consistency S-3) so a crafted justification containing a
  forged `mfa=...`/`expires_at=...` token can never be mistaken for the
  genuine, code-emitted values by a first-match grep.
  Toggle: **`--jit-oidc-amr-elevation`** (`YUZU_JIT_OIDC_AMR_ELEVATION`,
  default **true**; `--no-jit-oidc-amr-elevation` to disable). Disabling it
  means **OIDC sessions cannot use JIT elevation at all** — an operator must
  elevate from a local-authenticated session with local TOTP instead. This is
  NOT "OIDC sessions fall back to requiring local TOTP": an OIDC session has
  no way to present a local TOTP step-up (its step-up challenge is re-SSO, not
  a TOTP code), so the toggle-off denial is unconditional for that identity
  source, with its own distinct audited reason from the no-amr-assertion case.
  A one-time INFO log line is emitted at boot when OIDC is configured and the
  toggle is on, so an incident responder can discover the posture without
  reading source or an individual audit row.
- **`--mfa-step-up-window-secs` governs the OIDC-elevation proof-freshness
  bound too.** The elevate route's shared `elevation_step_up` gate (which
  every session — local and OIDC — must additionally clear after the
  unconditional enrolled/amr checks above) uses
  `cfg.mfa_step_up_window_secs` as its window when it is positive (default
  300 s), and 300 s when the operator has globally disabled step-up via
  `<= 0`, so the privilege boundary always requires a fresh proof. A positive
  value below 300 is used as-is; this is a substitution, not a floor. For an OIDC session this is the
  same `Session::mfa_verified_at` freshness check the local branch uses —
  there is no separate OIDC-specific timer; an operator narrows the window
  operator-wide with the one flag.
- **Incident response for a compromised SSO operator (no reaper/SCIM yet —
  #1859, tracked).** Until a deprovisioning sweep ships, stopping a
  compromised SSO operator's privileged access is two manual levers, both
  immediate: (1) `POST /api/v1/users/{principal}/elevation-eligibility
  {"eligible":false}` — stops future JIT elevation and drops any
  currently-active elevation window (`AuthManager::revoke_user_elevations`);
  (2) `DELETE /api/v1/sessions?username=<principal>` — force-logs-out the
  operator's current cookie session(s). Neither lever deactivates the
  `auth.users` row itself or stops the IdP from minting the operator a fresh
  session on next login (that requires IdP-side deprovisioning today); (1)+
  (2) together are the full standing-access kill switch available in this
  slice. #1859 will add a durable-side deactivation/reaper so a stale IdP
  removal ages the row out even without an admin doing this manually.
- **Step-down** — `POST /api/v1/elevate/revoke` clears the window
  (`role.elevation.revoked`). **Passive expiry on lapse is now audited too
  (follow-up A, shipped)** — `role.elevation.expired` — but LAZILY, not via a
  background reaper thread: there is no standing timer, so the row is emitted
  by `AuthManager::reap_expired_elevation` at the `AuthRoutes::resolve_session`
  cookie chokepoint, on the FIRST authenticated request the operator makes
  *after* the window has lapsed. `elevated_until` is cleared to the sentinel on
  that first observing call, so emission is exactly-once — a request that finds
  the sentinel already cleared (a prior reap, or a manual
  `revoke_elevation`/`revoke_user_elevations`, which clear to the same
  sentinel) emits nothing, so a manual step-down never ALSO produces a spurious
  `expired` row. **The `role.elevation.expired` emission is itself best-effort
  / at-most-once** (governance hardening round, UP-3): `elevated_until` is
  cleared to the sentinel BEFORE the audit call, so a store failure loses only
  the confirmatory `expired` row, never the reap itself (the session still
  correctly reverts to base role) — and the window's end remains
  reconstructible from the earlier, fail-closed `role.elevation.granted` row's
  `duration_secs`/`expires_at`. **Boundary: an operator who elevates and never
  issues another authenticated request before abandoning the session (closing
  the browser, letting the tab idle) never triggers the lazy reap** — there is
  no event for that lapse, only the deterministic `granted` row + its
  `duration_secs`/`expires_at`, from which the window's end is still
  computable for audit reconstruction. **The same boundary applies to idle
  (inactivity) eviction** — see "Inactivity session timeout" below: if the
  idle reaper evicts the session (erases it from `sessions_`) before the
  operator's next request, that request never reaches `resolve_session`'s
  cookie-found branch at all, so the lazy reap likewise never fires; the
  window's end is, again, reconstructible from the `granted` row rather than
  from a live `expired` event. Implementation: `Session::elevated_until` +
  `AuthManager::elevate_session`/`revoke_elevation`/`reap_expired_elevation`
  (auth.cpp); the three
  endpoints in `auth_routes.cpp`; `Config::jit_max_elevation_secs`.

## Hardened mode (sso-only) + break-glass (SOC 2 CC6.3/CC6.6)

`/auth-and-authz` skill gap matrix P0 #3. Closes Workstream B *"Disable
local-password fallback in hardened mode (or tightly constrain break-glass
account policy)"* — this ships **both** halves.

- **`--auth-mode <standard|sso-only>`** (`YUZU_AUTH_MODE`, default `standard`).
  Under `sso-only` the local-password login path is disabled fleet-wide — only
  an SSO provider mints a session: OIDC (`/auth/callback`) or SAML (`/saml/acs`),
  both untouched by the gate (the `POST /login` gate keys on `auth_mode` alone,
  never on which provider is wired). The rejection at
  `POST /login` returns the **same generic 401** as a bad password (no
  "disabled"/"sso-only" wording, no `Retry-After`) so the response BODY carries
  no enumeration/mode/arm-state oracle, and `verify_password` (PBKDF2) is
  skipped — same posture and accepted *timing* residue as the lockout pre-check.
  The denial is recorded as a **metric, not a per-attempt audit row**
  (`yuzu_auth_local_disabled_total{target=break_glass|other}`) — a credential
  spray would otherwise grow `audit.db` without bound, the exact amplification
  the lockout *blocked* path avoids; the CC6.3 evidence is the boot-posture
  banner + this counter (the `{target}` label, cardinality 2, flags probing of
  the break-glass account itself for SIEM alerting).
- **Boot guard (fail-closed).** `sso-only` **refuses to start** unless at least
  one SSO provider is configured well enough to actually mint a session —
  otherwise every operator is locked out (the break-glass account is for an IdP
  **outage**, not for never wiring SSO). The testable core is
  `sso_only_boot_guard_ok` (`sso_boot_guard.{hpp,cpp}`), mirroring the SCIM boot
  guard; it accepts **either**:
  - **OIDC** — both `--oidc-issuer` **and** `--oidc-client-id` (the same
    predicate the OIDC provider's `is_enabled()` uses; issuer-without-client-id
    leaves SSO silently non-functional, review #1735 HIGH-1); **or**
  - **SAML** (non-Windows) — all five SP fields (`--saml-idp-sso-url`,
    `--saml-idp-cert`, `--saml-sp-entity-id`, `--saml-sp-acs-url`,
    `--saml-idp-entity-id`) **and HTTPS enabled**. HTTPS is part of the gate, not
    deferred to runtime: `server.cpp` leaves the SAML provider disabled under
    `--no-https` (its Secure browser-binding cookie is dropped over plain HTTP,
    so `/auth/saml/start` would 404), so a SAML-only `--no-https` deployment would
    otherwise pass a presence-only gate and boot straight into a fleet-wide
    lockout. SAML is excluded on Windows because the provider is a compile-time
    stub there (it can never mint a session; running the *server* on Windows is
    out of scope regardless).

  The gate checks config **presence**, not runtime validity: a SAML config whose
  IdP cert / SP key is unreadable, oversized, or non-RSA still passes the boot
  guard and is then disabled **loudly** by `server.cpp` — exactly as OIDC
  issuer/JWKS runtime validity is not gate-checked either. The active SSO
  path(s) are named in the boot banner for CC6.3 evidence.
- **Break-glass account.** `--break-glass-user <name>` (`YUZU_BREAK_GLASS_USER`)
  designates the single local account exempt from `sso-only`, exempt **only
  while armed**. "Armed" is `users.break_glass_armed_until` (migration v4) — a
  future timestamp evaluated in SQL against `CURRENT_TIMESTAMP` exactly like
  `locked_until`, so the exemption **auto-expires** (default 24h,
  `--break-glass-window-secs` / `YUZU_BREAK_GLASS_WINDOW_SECS`, `86400`) and can
  never be a permanent standing bypass. A non-exempt or un-armed attempt gets
  the same generic 401 + `auth.local_disabled`.
- **Mandatory MFA, enforced two ways.** (1) Boot **fails closed** if the
  break-glass user doesn't exist or has no MFA enrolled
  (`break_glass_account_problem` in `auth_db`, shared by the boot guard and the
  arm one-shot; because `mfa_status` filters `is_active=1`, a soft-deleted user
  also reads as un-enrolled and is rejected). (2) If MFA is cleared out-of-band
  between boot and login, the login handler **hard-denies** the break-glass login
  (`403` + `auth.breakglass.denied`, `Severity::kCritical`) — it does **not**
  fall through to TOTP *enrollment*, because enrollment would hand a fresh secret
  to whoever proved the password and let a password-only adversary self-enrol and
  break the glass with no real second factor (governance UP-1). An enrolled
  break-glass login that proceeds emits `auth.breakglass.login` (`result=ok`,
  `kCritical` — `result=ok` means the *password* was accepted; the row's `detail`
  is explicit that the mandatory TOTP challenge still runs before a session is
  minted) + the metric `yuzu_auth_break_glass_login_total` + a `warn` log.
- **Lockout-exempt under sso-only (availability).** The break-glass account is
  exempt from failed-login lockout while `--auth-mode=sso-only`, so an attacker
  who learns its username cannot spray wrong passwords to keep it locked and
  render the escape hatch unreachable during an IdP outage (governance Hermes-F /
  UP-13). Safe because the second factor is still mandatory and, while un-armed,
  the password is never evaluated; wrong attempts are still audited
  (`auth.login_failed`) + per-IP rate-limited. Normal lockout still applies in
  standard mode.
- **Arming is an out-of-band host operation, never a session route.** The IdP
  being down is *why* you break the glass, so arming cannot depend on a login.
  `yuzu-server --break-glass-arm` (with `--break-glass-user` + `--postgres-dsn`
  for the auth store, and `--data-dir` for the audit-store write below — the
  auth store itself moved to Postgres/ADR-0006 and no longer needs
  `--data-dir`, but the one-shot still verifies the SQLite `audit.db` under
  `--data-dir` before mutating) arms the account for the window and exits —
  mirroring the `--mfa-reset` break-glass contract (#1226): it validates the
  account (exists + MFA), verifies the audit store is **writable before**
  mutating, and writes
  `auth.breakglass.armed` attributed to the **kernel-authoritative OS identity**
  (`resolve_os_principal`, not the forgeable `USER` env var), `principal_role =
  break-glass`. Refuses to arm — and exits non-zero — if any check fails or the
  audit row can't persist.

Implementation: gate at `auth_routes.cpp` `POST /login` (between the lockout
pre-check and `verify_password`); accessors `AuthDB::break_glass_status` /
`arm_break_glass` (single `UPDATE ... RETURNING`, no `sqlite3_changes()` —
#1033); the boot guard's testable core is `sso_only_boot_guard_ok`
(`sso_boot_guard.{hpp,cpp}`, shared with `server.cpp` via `saml_config_complete`),
called from a thin wrapper in `main.cpp` alongside the flags + arm one-shot;
`Config::auth_mode` / `break_glass_user` / `break_glass_window_secs` in
`server.hpp`. Tests: `tests/unit/server/test_auth_break_glass.cpp` (DB
accessors) + `test_auth_routes_hardened.cpp` (login-gate wire path) +
`test_sso_boot_guard.cpp` (boot-guard predicate — OIDC/SAML/HTTPS/platform).

## RBAC group provisioning (#1832)

Every OIDC `/auth/callback` login reconciles the IdP's `groups` claim into the
RBAC store (`RbacStore::reconcile_idp_memberships`), so group-scoped role
assignments made against an IdP-sourced group stay in sync with the IdP's
current membership. Mirrors the break-glass metric/audit treatment above.

- **Namespacing (confused-deputy fix).** Every IdP-asserted group is written
  as `<source>:<group-id>` (`entra:8f3c...`, via `namespaced_group_name`) —
  never the raw IdP id. A locally-created RBAC group can therefore never
  collide with (or be impersonated by) a same-named IdP group; `create_group`
  additionally rejects a `source='local'` create whose name starts with a
  reserved IdP prefix (`local:`/`entra:`/`saml:`/`ad:`, derived from the same
  list of recognized IdP sources `reconcile_idp_memberships` accepts — adding
  a future IdP there automatically reserves its prefix too).
- **Reconcile, not append-only (deprovisioning fix).** The transaction upserts
  every asserted `{external_id, display}` AND deletes any of the user's
  memberships in a `source`-owned group that was NOT re-asserted this login —
  scoped to `groups.source = ?`, so it is structurally incapable of touching a
  `source='local'` membership. An empty asserted set (the IdP now reports zero
  groups) removes ALL of the user's `source`-owned memberships — full
  deprovisioning takes effect on the user's next SSO login (residual: a live
  session/token retains its prior roles until re-authentication, tracked in
  #1836 — see the session-revocation REST surface above for the manual
  interim mitigation).
- **Source-verify guard.** Before joining a membership to a namespaced group
  row, the reconcile checks that row's `source` column matches the call's
  `source`. A pre-existing row of a DIFFERENT source occupying the same
  namespaced name (e.g. a local group literally named `entra:<gid>`, created
  before the `create_group` reserved-prefix guard existed) is never joined —
  closes a residual confused-deputy path the namespacing alone doesn't cover
  on an upgraded deployment carrying pre-guard data.
- **Group-overage skip (UP-1).** Entra omits the `groups` claim entirely
  (replacing it with a `_claim_names`/`_claim_sources` indirection pointer)
  once a user belongs to more groups than fit in the token. Treating the
  resulting empty claim as "zero groups" would delete every one of the user's
  existing memberships on that login — a silent mass-deprovision of a
  legitimate, heavily-grouped user. `OidcProvider::parse_id_token` sets
  `groups_claim_present`/`groups_overage` on `IdTokenClaims`; the free
  function `groups_claim_reconcilable(claims)` (mirrors `amr_asserts_mfa`,
  unit-testable without a live route) gates whether `/auth/callback` calls
  the reconcile at all. When it doesn't, existing memberships are left
  untouched and the login still proceeds — fail-OPEN on membership, never on
  authentication.
- **Cap + input validation (fail-closed on abuse, fail-soft on garbage).** An
  assertion of more than `RbacStore::kMaxIdpGroupsPerLogin` (200) groups
  denies the login outright (no session minted) before any mutation — defends
  against a compromised/misconfigured IdP turning one login into an unbounded
  write storm. Within the cap, an individual asserted entry with a blank or
  implausibly long (`>512` byte) `external_id` is silently dropped rather than
  seeding a garbage group.
- **Source contract.** `reconcile_idp_memberships` rejects `source == "local"`
  or an empty source outright (`unexpected`, no mutation) — the
  stale-membership DELETE's `source`-scoping is safe only for a real IdP
  source; a miswired call passing `"local"` would mass-delete every local
  group membership fleet-wide.
- **Fail-closed on the login.** An over-cap assertion or a reconcile-store
  failure (e.g. an unreachable/degraded PostgreSQL `rbac_store` — pool-acquire
  timeout or query error, ADR-0041) denies the login outright before a
  session is minted — a heavily-loaded or unhealthy `rbac_store` degrades
  availability (SSO logins fail) rather than integrity (a session with
  stale/unreconciled roles). The break-glass/local-password escape hatch
  (`/login`, hardened-mode) is unaffected — it never calls `/auth/callback`
  and so never touches group reconciliation.
- **Audit + metrics.** `auth.sso_group_provision` (`result=ok|skipped|error`)
  — `ok` only when the reconcile actually changed something
  (`detail=source=entra;added=N;removed=M`, `added+removed>0`; a no-op login
  writes no row), `skipped` for the group-overage/absent-claim case
  (`detail=reason=groups_overage|groups_absent;source=entra`), `error` for a
  denied login (`detail=reason=<cause>;source=entra`). An `error` result also
  emits the shared `auth.oidc_login_failed` audit row + analytics event (the
  same ones the token-exchange-failure branch emits) so a SIEM query counting
  failed OIDC logins by that action doesn't miss a provisioning-denied one.
  Metric: `yuzu_auth_sso_group_provision_total{source, result}` (same
  `result` vocabulary). See `docs/user-manual/audit-log.md`.

Implementation: `RbacStore::reconcile_idp_memberships` /
`namespaced_group_name` (`rbac_store.{hpp,cpp}`); the callback gate in
`auth_routes.cpp` `/auth/callback`; the claim parsing + gating decision in
`oidc_provider.{hpp,cpp}` (`IdTokenClaims::groups_claim_present` /
`groups_overage`, `groups_claim_reconcilable`). Tests:
`tests/unit/server/test_rbac_store.cpp`, `test_oidc_provider.cpp`.

**SAML now rides this same reconcile path (source `"saml"`).** The
`/saml/acs` handler reconciles `--saml-group-attribute`'s asserted values
the same way, before minting the session — see
`docs/user-manual/authentication.md` "SAML Fine-Grained RBAC" for the
operator-facing detail. Two SAML-specific differences from the OIDC shape
above: (1) SAML has no `groups_claim_present`/`groups_overage` equivalent —
it cannot distinguish "attribute absent" from "attribute present, zero
values" — so an EMPTY asserted set skips reconciliation unconditionally
(never reconciles zero groups), rather than gating on a presence signal;
(2) the cap is enforced by the SAML verifier itself
(`saml::kMaxGroupValues`, 200 — aligned with, and independent of,
`RbacStore::kMaxIdpGroupsPerLogin`) via a `group_cap_truncated` flag on the
parsed assertion, and a truncated assertion denies the login before
`reconcile_idp_memberships` is ever called (never a partial/truncated
reconcile).

## Stable principal vs. display name (#1837)

`Session` carries two separate identity fields with different jobs:

- **`username`** — the STABLE authorization principal. `check_permission`,
  `reconcile_idp_memberships`, elevation eligibility, and every audit
  `principal` field key on this value. It must be immutable for the
  lifetime of the identity it represents.
- **`display_name`** — a human-readable label for UI/audit-DETAIL
  rendering ONLY. Never consulted for authorization; safe to change on
  every login.

**Why this split exists.** Before #1837, `create_oidc_session` keyed
`username` on `claims.name` (falling back to `claims.email`) — an
IdP-editable, non-unique display label. Two different SSO users who
happened to share a display name (a common collision in orgs with
duplicate names, or after a legal name change re-used an old name)
collided onto ONE authorization principal. Once #1832 shipped
`reconcile_idp_memberships` — which deletes a principal's un-reasserted
IdP-sourced group memberships on every login — that collision became
destructive: user B's login could silently delete user A's group
memberships (and, in the group-membership window between the two
logins, inherit A's roles).

**The fix.** OIDC sessions now key `username` on:

```
"oidc:" + iss + "#" + sub
```

`sub` (the OIDC subject claim) is only guaranteed unique **per issuer**
(RFC 7519) — a bare `sub` from two different IdPs (or two tenants of the
same IdP product) could theoretically collide, so `iss` (the token
issuer) scopes it. This is an OPAQUE id — never render it as a human
name. `display_name` is set to `claims.name` (falling back to
`claims.email`), exactly as `username` used to be computed, and is
free to change on every login without touching the stable principal or
the RBAC memberships/roles bound to it.

`sub` is now authorization-load-bearing (it is half of the RBAC
principal), so `OidcProvider::validate_claims` — the same chokepoint that
already rejects `iss`/`aud`/`exp`/`nonce` mismatches — also rejects a
token whose `sub` is empty, contains a control character (byte `< 0x20`
or `== 0x7F`, including CR/LF/tab), or exceeds 255 bytes, and rejects an
empty `iss` defensively. Without this, an IdP token that omits `sub`
would collapse every such login onto the single principal `oidc:<iss>#`
(destructive under the #1832 reconcile), and a control/newline byte in
`sub` would corrupt the audit `principal` column. Rejection is
fail-closed — the login is denied (`auth.oidc_login_failed`), no session
minted.

**Recovering a human name without a live session.** There is no
persistent principal→display-name directory. The audit `principal`
column is the authoritative stable id (`oidc:<iss>#<sub>`) for every SSO
audit row; the human name for that same login is carried alongside it in
that row's `detail` field (`display=<sanitized name>;email=<sanitized
email>` — see `/auth/callback`'s `audit_log_for_principal` calls, which
attach this to every SSO audit action: `auth.oidc_login`,
`auth.oidc_login_failed`, `auth.sso_group_provision`). A live session's
`Session::display_name` is the other source, for the currently-signed-in
user only. Rendering a principal for which no session is live and no
audit row is being inspected (e.g. an admin-facing user list keyed on raw
`username` strings) has no name to show today — a durable
principal→display-name directory (persistent, survives restart, joinable
outside an audit row) is tracked as a fast-follow in **issue #1852**. An
earlier revision of this section documented an in-memory
`AuthManager::sso_identities_` resolution map upserted on every
`create_oidc_session` call; it had zero production callers (every render
site used a live session or an audit-row detail instead) and was removed
as dead code in the #1837 governance hardening round.

**Render sites.** `GET /api/me` (the legacy dashboard nav-bar
"who am I", consumed by every page's `nav-user`/`context-user` JS) and
`GET /api/v1/me` both now return `display_name` alongside the stable
`username`; the dashboard JS shows `display_name`, falling back to
`username` for a legacy/local session predating this field.

**SAML was unaffected this slice; since resolved (ADR-2001 PR4a).** At the
time of the #1837 hardening round documented above, `create_saml_session`
still keyed `username` on the raw NameID (`display_name` set to the same
value, purely for render-site parity) — SAML did not sync to `rbac_store`
yet (dropped in #1827; it now does, under source `"saml"`, see #1832
above), so the collision risk this fix closes was dormant there. ADR-2001
PR4a has since closed the SAML side of the same gap:
`create_saml_session` now keys `username` on the stable
`saml_principal_id(entity_id, name_id)` (`"saml:" + entity_id + "#" +
name_id`, `saml_principal.hpp`), mirroring the OIDC split above
byte-for-byte; `display_name` still carries the raw NameID for render-site
parity. This unlocks force-logout (`DELETE /api/v1/sessions?username=
saml:<entity_id>#<NameID>`, `is_valid_principal` accepts the `saml:`
reserved prefix on the same wider SSO charset as `oidc:`) and SCIM
deprovision-time session revocation for linked SAML identities (see
`docs/user-manual/scim-provisioning.md` "SCIM ↔ SAML identity linkage").
JIT elevation is **not** part of this fix — no `auth.db` `users` row is
provisioned for a SAML principal, so `provision_sso_identity` is still not
wired to SAML (`AuthManager::provision_sso_identity`'s docstring) and a
SAML session still cannot elevate.

**Audit-detail-field injection defense (`sanitize_detail_value`).** Every
IdP-supplied value that reaches an audit `detail` string or an
`emit_event` JSON attribute — `name`/`email`/`sub` (and the derived
`display`) — is untrusted: a hostile or misconfigured IdP, or a
user-editable IdP profile field, controls it. `detail` is a flat
`"k=v;k=v"` string parsed by SIEM tooling, so an unsanitised value could
inject `;`/`=` to forge additional fields or `\r`/`\n`/other control
bytes to inject fake log lines. `detail::sanitize_detail_value`
(`auth_routes.hpp`/`.cpp`) is the single chokepoint that neutralises
this: it replaces `;`, `=`, `\r`, `\n`, and any control byte (incl. DEL)
with `_`, then truncates to 128 bytes on a UTF-8 code-point boundary.
Every `display=`/`email=`/`oidc_sub`/`name` value attached in
`/auth/callback` is run through it before concatenation. **It is
audit-detail-field-injection defense only — it does NOT strip HTML
markup and is not a stored-XSS defense by itself.** A value with no
control bytes (e.g. a display name containing `<script>`) passes through
unchanged; if that value is later rendered into HTML, the render layer's
own escaping (`html_escape`) is what neutralises it. See the docstring on
`detail::sanitize_detail_value` in `auth_routes.hpp` for the full contract.

**Migration.** `RbacStore` **legacy SQLite** schema v3 (distinct from the PG
schema's own v3, ADR-0041 — different migration sequences, same file)
deletes every `group_members` row
belonging to an IdP-sourced group (`groups.source != 'local'`) on
upgrade — those rows were keyed on the OLD display-name principal and
would otherwise be BOTH orphaned (never re-referenced by the new
stable-keyed principal) AND a resurrected confused-deputy hazard: a
LOCAL user who later takes the old display name as their username would
silently inherit whatever roles the stale row's group grants. The purge
is additive/safe — only `group_members` rows for non-local groups are
removed; `groups`/`roles`/`role_permissions`/local memberships are
untouched, and IdP membership re-populates under the new stable key on
each affected user's next SSO login via `reconcile_idp_memberships`.

**Resolved — durable SSO identity restores OIDC JIT admin elevation
(#1852).** `AuthDB::set_elevation_eligible`/`is_elevation_eligible` key on
`users.username` and were gated through `is_valid_username`, which allows
only alphanumerics plus `. _ -` and explicitly rejects `:` (comment:
"prevent config file format injection"). The stable OIDC principal shape
(`oidc:<iss>#<sub>`) contains both `:` and `#`, so it failed that check
unconditionally — `POST /api/v1/users/{name}/elevation-eligibility` 400'd
before reaching the store, and `is_elevation_eligible(session->username)`
for a live OIDC session returned `InvalidUsername`, treated as
fail-closed/denied by the caller. Widening `is_valid_username`'s charset
alone would not have been sufficient: an OIDC login provisioned **no
`users` row at all** — `elevation_eligible` is a column on `users`, and
there was no row for an SSO principal to set it on. Both halves are now
fixed:

- **Durable identity row.** `/auth/callback` calls
  `AuthManager::provision_sso_identity` immediately after
  `create_oidc_session` mints the session — a new, independent call, not
  folded into `create_oidc_session` itself (that method holds `mu_` for the
  in-memory session map; provisioning does unrelated auth-store I/O that must
  not serialize behind it). It forwards to `AuthDB::upsert_sso_identity`
  (originally SQLite `auth.db` migration v6, now columns on the Postgres
  `auth.users` schema: `identity_source`, `external_iss`,
  `external_sub`, `display_name`, `last_seen_at`), which `INSERT ... ON
  CONFLICT(username) DO UPDATE`s a row for the stable principal —
  `password_hash`/`salt_hex` are `''` (never resolvable on the local login
  path — see the constant-time-compare note at the top of this document),
  `role` defaults `'user'` on first insert only. The `ON CONFLICT` refresh
  arm updates **only** `display_name`/`last_seen_at`/`is_active` — it
  deliberately never touches `role` or `elevation_eligible`, so a standing
  admin grant and elevation eligibility survive every re-login. **Fail-soft
  by design:** a provisioning error is logged and the login still succeeds
  (a login must never fail because a secondary bookkeeping write failed);
  the principal simply cannot elevate until a later successful login
  provisions it. IdP-side deprovisioning has no push signal into Yuzu today
  — a removed IdP account's row goes stale, aged by `last_seen_at`; a
  reaper/SCIM-driven sweep of long-unseen SSO rows is a tracked follow-up,
  not built in this slice.
- **`is_valid_principal` at the elevation-cluster target-lookup
  chokepoints.** A strict SUPERSET of `is_valid_username` (any string the
  strict validator accepts is accepted unchanged) that additionally accepts
  a reserved-prefixed (`oidc:`/`saml:`/`ad:`) principal after a narrow
  control-byte/SQL-metacharacter blocklist (rejects `< 0x20`, `0x7F`, `;`,
  `=`, `\`, `'`, `"`, `` ` ``, space; caps at 255 bytes; permits `: # / . _
  - @ ~ % |` — the alphabet a real issuer URL + opaque sub actually need).
  Replaces `is_valid_username` at exactly four call sites, all
  target-lookups on an EXISTING row, never a create path:
  `AuthDB::set_elevation_eligible`, `AuthDB::is_elevation_eligible`, the
  `POST /api/v1/users/{name}/elevation-eligibility` target parameter, and
  `DELETE /api/v1/sessions?username=`'s target parameter. Every other
  `is_valid_username` call site — local user create (`upsert_user`),
  delete, role-change, `mfa_status`, account-unlock (a lockout-domain
  action; SSO logins never accumulate lockout state, so there is nothing to
  unlock), and all password/lockout sites — is deliberately left untouched.
- **The elevate route's mandatory-MFA gate branches on `auth_source`.**
  See "JIT admin elevation" above for the local-vs-OIDC split and the
  dedicated unconditional amr-proof gate that prevents the restoration from
  accidentally granting elevation to a never-MFA'd SSO login under the
  default `--mfa-enforcement=optional`.
- **Settings → Users surfaces SSO rows.** `AuthDB::list_users` now selects
  `identity_source`; the fragment renders an `SSO` badge and suppresses the
  Remove button for a non-local row (`DELETE
  /api/settings/users/:username` stays on the strict validator, so it would
  always 400 against a `oidc:<iss>#<sub>` target — there is no local-delete
  equivalent for a durable SSO identity; its lifecycle is IdP-driven).
  Revoke-sessions stays available (principal-keyed, per the previous
  bullet).
- **A side effect, not the goal: `users.display_name` is now a durable
  record for a provisioned principal.** The "Recovering a human name
  without a live session" gap described above is *narrowed* by this — a
  future render site could join `users.display_name` by principal instead
  of relying only on a live session or an audit-row `detail` field — but no
  such render site is wired in this slice; that remains a fast-follow.

**Governance hardening round (2026-07-03) — see
`docs/security-reviews/sso-durable-identity-2026-07-03.md` for the full
record.** Four fixes on top of the base restoration above:

- **Source-scope guard on the eligibility grant.** `is_elevation_eligible`
  keys on the raw principal string alone, which is a landmine: a crafted SAML
  NameID equal to a provisioned OIDC principal, or a legacy
  `identity_source='local'` row that happens to be named `oidc:<iss>#<sub>`
  with `elevation_eligible=1`, would otherwise let a session borrow a grant
  never made against its own identity source. The elevate handler now fetches
  the target row's `identity_source` (`AuthDB::get_user`, which selects it)
  immediately after the eligibility check and requires it EQUAL the session's
  `auth_source` — a direct mapping (`local`↔`local`, `oidc`↔`oidc`,
  `saml`↔`saml`), not "oidc-or-else-local" — denying with
  `role.elevation.denied` / `detail=identity-source mismatch` otherwise.
- **`upsert_sso_identity` no longer resurrects a deactivated row.** The
  `ON CONFLICT` refresh arm dropped `is_active = 1` from its `SET` clause — a
  re-login against a row a future deprovisioning sweep (#1859) had
  soft-deleted no longer silently reactivates it.
- **`AuthDB::invalidate_all_sessions` moved to `is_valid_principal`.** Force-
  logging-out an SSO principal via `DELETE /api/v1/sessions?username=`
  previously hit `InvalidUsername` at this inner call even though the REST
  layer had already accepted the principal — corrupting the audit trail with
  `result="partial"`/`db_error=true` for an action that fully succeeded (OIDC
  sessions are never persisted to any AuthDB `sessions` table — durable sessions
  live in the separate `SessionStore`, HA WS-1/1a — so 0 matched rows at this
  AuthDB call IS success).
- **Settings → Users "Revoke sessions" URL-encodes the principal.** The
  button previously built its `hx-delete` URL with `html_escape` alone, which
  does not touch `#` — a durable SSO principal's `#` was silently truncated
  by the browser's URL-fragment parsing before the request left the client.

SAML still cannot elevate, though the reason has narrowed since ADR-2001
PR4a (see "SAML was unaffected this slice; since resolved" above):
`create_saml_session` now keys `username` on the reserved-prefix stable
principal `saml:<entity_id>#<NameID>`, so `is_valid_principal` DOES
recognise it as an SSO principal (unlocking force-logout, per that section)
— but `provision_sso_identity` is still never called from the SAML ACS
handler, so no `auth.db` `users` row is provisioned for a SAML principal.
A SAML session therefore still cannot elevate — not because of a missing
MFA proof specifically, and no longer because `is_valid_principal` rejects
the identity shape, but because there is no durable identity row to hold
`elevation_eligible` on in the first place. Wiring `provision_sso_identity`
into the SAML ACS handler is a tracked follow-up, separate from PR4a.

**This is not a regression of a previously-supported flow.** Before #1837,
`Session::username` for an OIDC session was the mutable display name
(`claims.name`, falling back to `claims.email`), and `is_elevation_eligible`
looked that string up directly in `users.username`. Elevation for an SSO
operator therefore only ever "worked" by accident, and only when **both**
of two coincidences held: the IdP-asserted display name had to consist
solely of `is_valid_username`'s narrow charset (no space, no `@` — so most
real display names/emails already failed this silently), **and** it had to
exactly match an existing *local* `users.username`. When both held, the SSO
login's principal silently **borrowed that local principal's
`elevation_eligible` flag and `mfa_totp_secret` enrollment** — a latent
cross-principal grant with zero cryptographic binding between the SSO
identity and the local account it happened to name-collide with: anyone
the IdP would authenticate under that same display name inherited that
local account's admin-elevation path. #1837 severs this borrowing as a
direct, correct consequence of closing the display-name collision it rode
on (see above) — it is closing an unsafe accident, not breaking a supported
capability. #1852 is the deliberate, durable restoration.

**Session-revocation-by-username is a narrower, structurally different
gap.** The operationally-critical kill step
(`AuthManager::invalidate_user_sessions`'s in-memory sweep, keyed by plain
string equality over `sessions_`) carries no `is_valid_username` gate and
revokes any principal string, `oidc:<iss>#<sub>` included — there is no
missing-row problem here, unlike elevation. `DELETE
/api/v1/sessions?username=`'s own query-parameter check does still run
`is_valid_username` at the REST layer, so an admin typing the literal
`oidc:<iss>#<sub>` string still gets a 400 today from that endpoint — but
that charset-only validator predates #1837 and would already have rejected
most OIDC display-name-keyed usernames (spaces, `@`) before this change
too, so this is a narrow, pre-existing, easily-widened validator gap, not a
new #1837 regression and not gated on #1852. Separately, the historical
`auth.db`-persisted half of revocation
(`AuthDB::invalidate_all_sessions`'s `DELETE FROM sessions`, surfaced as
`db_persisted=false` for an SSO target) was **already** a no-op for OIDC
before #1837 too: `AuthDB::create_session` was never called for an OIDC
login — SSO sessions have always been in-memory-only and were never
written to `auth.db`'s `sessions` table in the first place. **This whole
distinction is now moot for every login path, not just OIDC:** the ADR-0006
Postgres cutover dropped `AuthDB::invalidate_all_sessions`/`create_session`
and the `sessions` table entirely (see "AuthDB — persistent authentication
store" below) — `invalidate_user_sessions` today is purely the in-memory
sweep described at the top of this bullet, for every `auth_source`.

Implementation: `Session::username`/`display_name`
(`auth.hpp`), `AuthManager::create_oidc_session` (`auth.cpp`), the
stable-id construction and per-audit-row `display=`/`email=` detail
attachment in `auth_routes.cpp` `/auth/callback`, `RbacStore` legacy SQLite
migration v3 (`rbac_store.cpp`; distinct from the PG schema's own v3,
ADR-0041). Tests: `tests/unit/server/test_oidc_principal_key.cpp`.

## SAML 2.0 SP

`/auth-and-authz` skill gap matrix P1 #6. Thin first slice: SP-initiated login
against a single, statically-pinned IdP. Mirrors the OIDC SSO session seam
(same cookie / `auth_source` / RBAC funnel) but uses the SAML 2.0 protocol.
**Linux and macOS only — SAML is unsupported on Windows *server* builds and
fails closed there** (a Windows server logs an error at startup and does not
enable SAML regardless of flag values). This is a deliberate non-gap, not
unfinished work: running the Yuzu **server** on Windows is out of scope, so a
Windows-server SAML port is not planned. (The Yuzu **agent** on managed
Windows endpoints is a separate binary and is unaffected.)

### Configuration

SAML is enabled only when **all five** required flags below are set; supplying
any subset produces a startup warning (naming the missing flag) and SAML is
disabled (fail-closed). All five are validated at startup as one unit — a
partial configuration never yields a "SAML SP initialized" log. The two
group→role flags are optional and independent of the enable gate (see Group→role
mapping below).

| Flag | Env var | Description |
|---|---|---|
| `--saml-idp-entity-id` | `YUZU_SAML_IDP_ENTITY_ID` | Entity ID URI of the IdP (e.g. `https://idp.example.com/saml`) |
| `--saml-idp-sso-url` | `YUZU_SAML_IDP_SSO_URL` | IdP's HTTP-Redirect SSO endpoint URL |
| `--saml-idp-cert` | `YUZU_SAML_IDP_CERT` | Filesystem path to the IdP's signing certificate (PEM) |
| `--saml-sp-entity-id` | `YUZU_SAML_SP_ENTITY_ID` | Entity ID URI the SP advertises to the IdP |
| `--saml-sp-acs-url` | `YUZU_SAML_SP_ACS_URL` | Full URL of this server's Assertion Consumer Service (`POST /saml/acs`) |
| `--saml-group-attribute` *(optional)* | `YUZU_SAML_GROUP_ATTRIBUTE` | `<Attribute Name="...">` in the assertion's `<AttributeStatement>` whose `<AttributeValue>`s are group identifiers (e.g. Entra's `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`) |
| `--saml-admin-group` *(optional)* | `YUZU_SAML_ADMIN_GROUP` | Group value (from `--saml-group-attribute`) that grants `role=admin` |
| `--saml-name-attribute` *(optional)* | `YUZU_SAML_NAME_ATTRIBUTE` | `<Attribute Name="...">` whose first `<AttributeValue>` is the user's human display name (e.g. Entra's `http://schemas.microsoft.com/identity/claims/displayname`). Empty leaves the display as the raw NameID. See "Attribute-based display" below |
| `--saml-email-attribute` *(optional)* | `YUZU_SAML_EMAIL_ATTRIBUTE` | `<Attribute Name="...">` whose first `<AttributeValue>` is the user's email (e.g. Entra's `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`). Used only as a display fallback and logged |
| `--saml-sp-key` *(optional)* | `YUZU_SAML_SP_KEY` | Filesystem path to an SP AuthnRequest signing private key (PEM, **RSA only**); when set, AuthnRequests are signed (see AuthnRequest signing below) |

Example startup:

```bash
./yuzu-server \
  --https-cert         /etc/yuzu/server.crt \
  --https-key          /etc/yuzu/server.key \
  --saml-idp-entity-id "https://idp.example.com/saml" \
  --saml-idp-sso-url   "https://idp.example.com/saml/sso" \
  --saml-idp-cert      /etc/yuzu/idp-signing.pem \
  --saml-sp-entity-id  "https://yuzu.example.com" \
  --saml-sp-acs-url    "https://yuzu.example.com/saml/acs"
```

> **HTTPS is required.** The `__Host-yuzu_saml_bind` browser-binding cookie is
> `Secure`-only; browsers silently drop `Secure` cookies over plain HTTP. If
> `--https-cert`/`--https-key` are not configured, the server logs an error at
> startup and leaves SAML disabled (fail-closed). Do not run SAML over HTTP.

### Login flow

SP-initiated via HTTP-Redirect binding; assertion consumed via HTTP-POST
binding.

1. The operator navigates to `GET /auth/saml/start`. There is no "Sign in with
   SAML" button on the login page in this release — the login-page SSO button
   for SAML is a deferred item (see Deferred items below).
2. The server builds a `<samlp:AuthnRequest>` (SP entity ID, ACS URL,
   `ID`=random, `IssueInstant`, `ForceAuthn=false`) and redirects the browser
   to the IdP's SSO URL via HTTP-Redirect binding (deflate-compressed,
   URL-encoded `SAMLRequest` query parameter). When `--saml-sp-key` is
   configured, the request is signed (see AuthnRequest signing below);
   otherwise it is unsigned — the IdP must be configured to accept unsigned
   requests in that case.
3. The user authenticates at the IdP.
4. The IdP POSTs a `<samlp:Response>` containing a signed `<saml:Assertion>`
   to the ACS endpoint (`POST /saml/acs`).
5. The server validates the response (see Security posture below) and, on
   success, mints an ephemeral session cookie.

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

### Session

The minted session is **durable** — since HA WS-1/1a (ADR-2002 §4)
`AuthManager::create_saml_session` write-throughs to `SessionStore` exactly as
OIDC does, so it **survives a server restart** (for Postgres-backed
deployments; config-file-only deployments keep the old in-memory-only
behavior). It has the identical lifetime to OIDC sessions — 8-hour absolute,
subject to `--session-inactivity-secs`. See `docs/auth-architecture.md` →
"Durable operator sessions (HA WS-1/1a, ADR-2002 §4)". Session fields:

- `auth_source = "saml"`
- `role = admin` when `--saml-admin-group` is configured and the assertion's
  IdP-attested groups (see Group→role mapping below) contain it, `role = user`
  otherwise — including every login when the two group→role flags are unset
  (the unconfigured default). JIT elevation is non-functional for SAML users
  regardless of role: the elevation endpoint checks `is_elevation_eligible` and
  `mfa_status` against the Postgres auth store, and SAML users have no row in
  `auth.users` — both lookups fail-closed and the elevation is denied. A SAML admin
  therefore gets `role=admin` permissions immediately at login, not via
  elevation.

### Group→role mapping

SAML admin access is available via IdP-attested group membership, mirroring
the OIDC `--oidc-admin-group` mechanism:

- `--saml-group-attribute` names the `<Attribute Name="...">` element inside
  the assertion's `<AttributeStatement>` whose `<AttributeValue>` children are
  read as group identifiers.
- `--saml-admin-group` is the single group value that grants `role=admin`.
  Matching is **exact string equality only** — no wildcard, prefix, or regex
  matching.
- If either flag is empty (the default), no group is ever eligible for admin
  and every SAML login is `role=user` — identical to the original thin slice.

**Security:** admin is granted **only** from the configured group attribute's
values — **never** from `NameID`, email, or display name, all of which are
attacker-controlled fields that ride in the same assertion (mirrors the C3 fix
in `create_oidc_session`). Group values are parsed from the **same
XSW-verified assertion node** that `NameID` is read from — never a second,
unverified document-wide search — so a signature-wrapping attack cannot inject
groups the IdP didn't attest to. Parsing is capped at 64 `<AttributeValue>`
entries (across however many `<Attribute>` elements carry the configured
Name) as a DoS guard; values beyond the cap are silently ignored rather than
rejecting the assertion.

### Attribute-based display (name / email)

By default a SAML session's `display_name` is the raw `NameID` — often an
opaque `persistent` identifier. `--saml-name-attribute` and
`--saml-email-attribute` let the operator name the `<Attribute>` elements that
carry the user's display name and email, so the dashboard and audit rows show
a human name instead. The session display is derived exactly like OIDC's
(`create_oidc_session`): **name attribute → email attribute → raw NameID**.

- Both values are read from the **same XSW-verified assertion node** as the
  `NameID` and groups (never a second document-wide search), via the same
  namespace-checked walk — a signature-wrapping attack cannot inject a display
  name or email the IdP didn't attest to. The first non-empty `<AttributeValue>`
  wins; empty values are skipped.
- They are **session-enrichment only**. Email is used as a display fallback and
  logged; it is **not** stored as a durable session field (mirroring OIDC,
  which has no session email field either). Neither value is ever an identity,
  authz, or SCIM-linkage input — the SAML identity key stays `NameID`-only
  (`saml_principal_id`), and admin is still granted **only** from the group
  attribute, never from the name/email attributes (the security note above
  continues to hold — these attributes are attacker-controlled labels).
- Both flags empty (the default) reproduces the raw-`NameID` display exactly —
  a fully backward-compatible addition.

> **PII in operational logs (data-handling note, CC6.7).** When configured, the
> parsed display name and email appear in the **operational** log (`spdlog`) at
> `info` on session creation — the same posture OIDC already has (its
> `create_oidc_session` logs the resolved display + email identically). These
> are IdP-attested values, are **not** written to the audit store (the SAML
> audit row keys on the stable NameID-derived principal only), and are not
> otherwise persisted. Operational logs inherit the deployment's general
> log-access and retention controls; a first-customer questionnaire asking
> "where does user PII appear in logs" is answered here for both SSO paths.
> Tightening this to a hashed/omitted form across OIDC and SAML consistently is
> tracked as a follow-up.

Because role is computed fresh at every session mint (no persisted mapping),
there is no schema or migration involved, and changing `--saml-admin-group`
takes effect on the next login after a server restart (see Rotating the IdP
signing certificate below for the general "no hot-reload" caveat that also
applies to these two flags).

### Audit actions

| Action | Result | When |
|---|---|---|
| `auth.saml_login` | `ok` | ACS validation passed; session minted |
| `auth.saml_login_failed` | `error` | ACS validation failed (signature, audience, expiry, replay, etc.) |

### Security posture

- **Assertion signature verified against the pinned IdP cert only.** The cert
  at `--saml-idp-cert` is the sole trusted signing authority. In-document
  `<KeyInfo>` values are ignored — the IdP cannot nominate its own trust
  anchor.
- **XML signature-wrapping (XSW) defended.** The server locates the signed
  element by `ID` attribute and verifies that the element under the
  `<Signature>` is the one that was actually consumed, preventing a wrapped
  unsigned sibling from being treated as validated.
- **Audience validated.** The `<saml:AudienceRestriction>` must include
  `--saml-sp-entity-id`.
- **Recipient validated.** The `<saml:SubjectConfirmationData Recipient>` must
  equal `--saml-sp-acs-url`.
- **Expiry validated.** `NotOnOrAfter` on `<saml:Conditions>` and
  `<saml:SubjectConfirmationData>` are enforced.
- **Solicited-only + single-use `InResponseTo` (replay-protected).** The
  server generates a random `ID` for each `AuthnRequest`, stores it in memory,
  and requires the `<samlp:Response>` `InResponseTo` to match exactly. The ID
  is consumed on first use; a replayed response is rejected.

### MFA enforcement with SAML

**MFA step-up is not supported for SAML sessions in this release.** A SAML
session hitting any of the 24 step-up-gated endpoints (token mint/revoke,
session revoke, Guardian rule write, software deploy, user delete/role change)
receives a `403` with `"MFA step-up is not available for SAML sessions in this
release"` — regardless of `--mfa-enforcement` mode. The gate (`require_mfa_step_up`
in `mfa_step_up.cpp`) exits with an honest denial before reaching the local
`mfa_status` lookup, which would fail anyway (SAML users have no local `users`
row). This means:

- `--mfa-enforcement=required` — SAML users are denied at every step-up gate.
- `--mfa-enforcement=admin-only` — the SAML-specific early exit fires on
  `auth_source == "saml"` before role is even consulted, so this applies
  equally to a `role=user` SAML session and a `role=admin` SAML session minted
  via group→role mapping (see Group→role mapping above) — both are denied.
- `--mfa-enforcement=optional` — same: the SAML-specific exit fires before
  enforcement mode is consulted.

**Recommendation:** Use `--mfa-enforcement=optional` or `--mfa-enforcement=admin-only`
when SAML is in use, and configure your IdP to enforce MFA at login time. Avoid
`required` unless you are prepared for SAML users to be denied at all step-up
gates. The recommended pattern for a SAML deployment is `optional` with IdP-side
MFA enforcement.

### `--auth-mode=sso-only` covers SAML (SOC 2 CC6.3)

A SAML-only deployment **can** run under `--auth-mode=sso-only`: the boot guard
accepts a complete SAML SP config (all five `--saml-*` fields) **with HTTPS
enabled** as an SSO path, exactly as it accepts a complete OIDC config — see the
Hardened-mode boot-guard bullet above for the full predicate. A dual OIDC+SAML
deployment satisfies it via either provider. On Windows the SAML provider is a
stub, so a Windows *server* still needs OIDC for `sso-only` (running the server
on Windows is out of scope regardless).

Two limitations a SAML-only `sso-only` operator should know (neither is new to
this change; both are pre-existing SAML properties that simply become more
visible without a local-password fallback):

- **No privilege elevation for SAML operators.** A SAML session cannot perform a
  local TOTP step-up and has no OIDC `amr` proof, so JIT admin elevation
  (`POST /api/v1/elevate`) is unavailable to it. A SAML-only deployment that
  needs elevation should grant standing admin via the group→role mapping
  (`--saml-admin-group`) rather than rely on JIT.
- **No SAML button on the login page.** `/login` still renders a password form
  (which always returns the generic 401 under `sso-only`) and, if OIDC is also
  configured, its SSO button; SAML operators navigate to `GET /auth/saml/start`
  directly.

### HA / multi-replica

Pending `AuthnRequest` state (the random `ID` stored for replay protection) is
kept in process memory. In a multi-replica deployment, load-balancer **sticky
sessions (session affinity)** must be configured on `GET /auth/saml/start` and
`POST /saml/acs` so the ACS POST for a given request is always routed to the
replica that generated it. Without affinity, approximately `(N−1)/N` of logins
fail as "unsolicited" (no matching pending ID). OIDC shares this limitation via
its in-process PKCE state.

### Rotating the IdP signing certificate

Update `--saml-idp-cert` and **restart the server** — there is no hot-reload
for the IdP cert in this release.

### AuthnRequest signing

Optional and independent of the five-flag enable gate: `--saml-sp-key`
points at a filesystem PEM containing the SP's AuthnRequest signing private
key. Design:

- **Binding and algorithm.** Signs over the **HTTP-Redirect binding** only
  (the only binding the SP uses for AuthnRequest) with **RSA PKCS#1 v1.5 +
  SHA-256** (`SigAlg` `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`),
  carried as the `SigAlg`/`Signature` query parameters alongside
  `SAMLRequest` — per the standard query-string signing scheme for this
  binding.
- **RSA only.** EC and RSA-PSS keys are rejected; only a plain RSA key
  parses.
- **Pinned single signing key, parsed once at boot.** `server.cpp` reads the
  key file, and `SamlProvider`'s constructor parses it once into an owned
  `EVP_PKEY`, retained for the process lifetime — mirrors the IdP cert's
  pinned-at-boot posture (N1 above), applied here to the SP's own key
  instead of the IdP's — the key is not re-read per request.
- **Fail-closed, never a silent downgrade.** The key file passes the same
  private-key permission check used for the HTTPS/gateway TLS keys (not
  group/other-readable), then the same 64 KiB read-and-cap the IdP cert PEM
  uses. A permission failure, unreadable file, oversize file, malformed PEM,
  or non-RSA key disables SAML **entirely** at startup (the provider is not
  constructed / is reset) rather than silently falling back to unsigned
  AuthnRequests. A per-request signing failure fails `/auth/saml/start`
  rather than emitting an unsigned redirect.
- **Backward-compatible default.** Left unset, AuthnRequests remain
  unsigned, same as prior releases.

### Deferred items (not in this slice)

- **Login-page SSO button.** There is no "Sign in with SAML" button on the
  login page; users must navigate directly to `GET /auth/saml/start`.
- **AttributeStatement parsing beyond group/name/email.** Group→role mapping
  (`--saml-group-attribute`) plus the display-name/email session-enrichment
  attributes (`--saml-name-attribute`/`--saml-email-attribute`, see
  "Attribute-based display" above) are read; no *other* assertion attributes
  (department, title, custom claims, …) are stored or surfaced.
- **SP metadata endpoint.** No `GET /saml/metadata` endpoint is provided; IdP
  registration uses the manual flag values.
- **Windows server support — out of scope, not deferred.** Running the Yuzu
  server on Windows is not a targeted deployment, so SAML on a Windows server
  is intentionally not built: the server detects Windows at startup, logs an
  error, and does not enable the SAML routes. (Correction: this was previously
  documented as blocked on an XML processing library missing from the vcpkg
  manifest — that is inaccurate; libxml2/xmlsec are already in the manifest.
  The exclusion is a product-scope decision, not a dependency gap.)
- **IdP-metadata auto-fetch.** The IdP cert and SSO URL are supplied statically
  via flags; SAML metadata XML auto-discovery is not implemented.
- **Settings-UI runtime reconfigure.** SAML can only be configured via CLI
  flags or environment variables; there is no dashboard panel for it in this
  slice. A server restart is required to change the configuration.

## SCIM v2 provisioning (SOC 2 CC6.2/CC6.7/CC6.8)

`/auth-and-authz` skill gap matrix P1 #7. RFC 7643 (Core Schema) / RFC 7644
(Protocol) — lets an enterprise IdP (Okta/Entra/OneLogin) auto-provision and
auto-deprovision Yuzu operators via its SCIM connector, rather than an admin
managing accounts by hand. Slice 1 (Users) shipped every SCIM-provisioned
account at the fixed, floor-privilege `user` role; slice 2 (this section's
"Groups → role mapping" below, issue #2021, SOC 2 **CC6.7**) lets an IdP grant
`role=admin` to members of a configured admin group.

### Configuration (fail-closed)

| Flag | Env var | Description |
|---|---|---|
| `--scim-enable` | `YUZU_SCIM_ENABLE` | Enable the `/scim/v2/*` route surface. Default `false` — SCIM is entirely inert when disabled (no routes registered, no boot-log line). |
| `--scim-token` | `YUZU_SCIM_TOKEN` | The bearer credential the IdP's SCIM connector authenticates with. Secret — treat like a password. |
| `--scim-admin-group` | `YUZU_SCIM_ADMIN_GROUP` | `displayName` of the SCIM group whose members are granted `role=admin`. Default empty — no SCIM group grants admin; every SCIM-provisioned user stays `role=user`. The value is whitespace-trimmed at load. Mirrors `--saml-admin-group`. **Requires a server restart to take effect** — there is no Settings-UI/live-reload path; renaming the group's `displayName` in the IdP likewise requires updating this flag and restarting. |

**Prefer `YUZU_SCIM_TOKEN` over `--scim-token`.** A value passed on argv is
visible to any local user via `ps`/`/proc/<pid>/cmdline`; the environment
variable does not appear there. `YUZU_SCIM_TOKEN` is the recommended
delivery method — the flag remains supported for parity with the other
`--scim-*` options and local/manual testing.

Two fail-closed startup guards, both refusing to start (`EXIT_FAILURE`):

- **`--scim-enable` without `--scim-token`.** There is no way to gate the
  surface without a credential, so the server does not boot rather than
  expose an unauthenticated provisioning API.
- **`--scim-enable` together with `--no-https`.** The bearer token is a
  long-lived, high-privilege credential (it can create/delete operator
  accounts); it must never cross the wire in plaintext. This mirrors the
  `--auth-mode=sso-only` boot posture — a security-relevant flag combination
  is rejected at boot, not silently degraded.

The active SCIM posture (enabled/disabled, and — if enabled — that a token is
configured) is logged **once at boot** as CC6.2 evidence, the same pattern as
the `sso-only` boot-posture banner.

### Auth

Every `/scim/v2/*` route — **including the discovery endpoints** — requires
`Authorization: Bearer <token>`, validated **constant-time** (`CRYPTO_memcmp`)
against the SHA-256 hash stored at `--scim-enable` time (mirrors
`ApiTokenStore`'s token-hashing pattern). A missing, malformed, or invalid
token is a `401` + `WWW-Authenticate: Bearer` — the same envelope regardless
of *why* it failed (no oracle distinguishing "wrong token" from "no token
configured"). SCIM tokens are their **own credential type**, entirely
distinct from operator API tokens and session cookies — there is no cookie,
no session, no shared token store. Every authenticated SCIM request maps to
a fixed `scim-service` audit principal (there is no notion of "which
operator" made a SCIM call; it is the IdP connector, always).

### Endpoints

All responses (and the accepted PATCH/PUT bodies) use
`Content-Type: application/scim+json`.

`ServiceProviderConfig` advertises **`etag.supported: false`** — there is no
conditional-write enforcement (`If-Match`/`If-None-Match` are not honored);
the `ETag`/`meta.version` a client sees back is informational only, not a
concurrency-control token.

| Endpoint | Purpose |
|---|---|
| `GET /scim/v2/ServiceProviderConfig` | Discovery — capability document |
| `GET /scim/v2/ResourceTypes` | Discovery — describes the User and Group resource types |
| `GET /scim/v2/Schemas` | Discovery — the core User and Group schemas |
| `POST /scim/v2/Users` | Provision a new user |
| `GET /scim/v2/Users/{id}` | Read a single user (`404` if unknown) |
| `GET /scim/v2/Users?filter=userName eq "x"&startIndex=&count=` | Existence check + pagination (SCIM `ListResponse`) |
| `PUT /scim/v2/Users/{id}` | Replace (`externalId`, `active`) |
| `PATCH /scim/v2/Users/{id}` | Primary lifecycle path — deactivate / reactivate |
| `DELETE /scim/v2/Users/{id}` | Deprovision |
| `POST /scim/v2/Groups` | Create a group (`displayName`, optional `members[]`) |
| `GET /scim/v2/Groups/{id}` | Read a single group |
| `GET /scim/v2/Groups?filter=displayName eq "x"&startIndex=&count=` | List groups (SCIM `ListResponse`, pagination) |
| `PUT /scim/v2/Groups/{id}` | Replace a group |
| `PATCH /scim/v2/Groups/{id}` | Add/remove members (RFC 7644 §3.5.2 PatchOp on `members`) |
| `DELETE /scim/v2/Groups/{id}` | Delete a group |

`Group` is now advertised alongside `User` in `/scim/v2/ResourceTypes` and
`/scim/v2/Schemas` (schema urn `urn:ietf:params:scim:schemas:core:2.0:Group`).

### Provisioning model

`POST /scim/v2/Users` creates the account with a discarded
CSPRNG-generated password — a SCIM-provisioned user never authenticates
with a local password; they sign in via the IdP/SSO. Role defaults to
`user` and is recomputed immediately against the current
`--scim-admin-group` membership (see Groups → role mapping below) — so a
user who already appears in the admin group's `members[]` at the moment
they are provisioned is created `role=admin`, not `user`-then-promoted. A
duplicate `userName` is rejected `409` (`scim_type=uniqueness`) rather than
silently upserting. Success is `201` + `Location` (the resource's canonical
URL) + `ETag` (the resource's `etag_version`, bumped on every mutation).

**Reprovisioning a returning employee works.** If the `userName` collision is
against an existing SCIM-provisioned account that is currently **deactivated**,
`POST` revives that account rather than rejecting `409` — this is the
"left, then rejoined" case an IdP connector replays automatically when a
person is re-added and re-assigned the app. The `409 uniqueness` rejection is
reserved for a `userName` collision against a **currently-active** account.

### `userName` charset — must be a slug, not an email address

Yuzu account usernames are slug-shaped: alphanumeric plus `.`, `_`, `-`
only — **no `@`**. Stock Okta/Entra provisioning defaults `userName` to the
user's email address, which contains `@` and is rejected `400` at
`POST /scim/v2/Users` (and at any subsequent identity-touching `PUT`/`PATCH`).
**Operators must remap `userName` to a non-email slug attribute** in the
IdP's provisioning/attribute-mapping configuration before assigning any
users — the `400` response carries an error-message hint calling out the
rejected character(s) to speed up this diagnosis. Native support for an
email-shaped `userName` (deriving a slug server-side) is a planned follow-up
— see Deferred below.

`GET .../Users?filter=userName eq "x"` is the connector's standard
existence-check-before-create call. **Only the `userName eq "..."` filter is
supported** (attribute + operator case-insensitive, value double-quoted);
any other attribute or operator is rejected `400` (`scim_type=invalidFilter`)
rather than silently ignored or partially matched.

`PUT /scim/v2/Users/{id}` replaces the mutable identity fields (`externalId`,
`active`). A `userName` change is rejected `400`
(`scim_type=mutability`) — **rename is out of scope this slice**; deleting
and re-provisioning is the only supported path for a IdP-side username
change today.

### Deprovision and reactivation

`PATCH /scim/v2/Users/{id}` is the primary lifecycle path (both the pathless
`{"value":{"active":false}}` and explicit `{"path":"active","value":false}`
PatchOp forms are accepted). **`PUT /scim/v2/Users/{id}` triggers the
identical deactivate/reactivate semantics** whenever its body's `active`
value differs from the account's current state — some IdP connectors issue a
full `PUT` rather than a `PATCH` for lifecycle changes, and that path gets
the same audit behavior described below, not a silent no-op:

- **`active:false` deprovisions** — soft-deletes the underlying auth account
  and **cascades session revocation** (an in-flight session for a
  just-terminated employee does not outlive the IdP's deprovisioning call).
- **`active:true` reactivates** — restores the account and **clears any
  stale lockout** (`failed_login_count`/`locked_until`), so a re-hire isn't
  stuck behind a lockout window from before their termination. **MFA is
  NOT restored** — a reactivated user re-enrolls TOTP from scratch on next
  login, the same posture as any other de-enrolled account; SCIM never
  resurrects a stale second factor.

`DELETE /scim/v2/Users/{id}` is the equivalent one-shot deprovision (`204`),
for IdPs that issue a hard delete rather than a PATCH/PUT-to-inactive.

**All lifecycle audit writes are set-and-proceed; evidence integrity is
enforced by an alert on the failure metric.** Every action (provision,
update, deactivate, reactivate, delete) completes even if its audit write
fails, and each failure unconditionally bumps
`yuzu_scim_audit_write_failures_total`. A fail-closed `500` on a
*termination* audit-write failure was considered and **rejected**: because
the account is already mutated, the IdP's retry re-reads the terminated
post-state, takes the non-termination (no-op / `404`) branch, and never
re-attempts the missing audit — the `500` fails the request without ever
re-landing the evidence row it was meant to guarantee. The correct CC6.8
control is therefore an **alert on `yuzu_scim_audit_write_failures_total`**
(same-day follow-up on a missed termination record); deploy that rule when
you enable SCIM.

### 🔴 Provenance guard (the load-bearing security invariant)

**SCIM may only ever mutate accounts that SCIM itself provisioned, and only
while they are still floor-privilege.** Every deactivate / reactivate /
delete / update re-verifies **both**
`provisioning_source == "scim"` (a `users` column,
`AuthDB::set_provisioning_source`/`get_provisioning_source`; originally
SQLite `auth.db` migration v7, now a column on the Postgres `auth.users`
schema) **and** `role == "user"` **immediately before** touching
the auth account — not at lookup time, at the mutation site. Either mismatch
(the target `scim_id` maps to a username whose `provisioning_source` is
`local` or anything else, **or** whose `role` has since been elevated, e.g.
by a dashboard admin promoting a former SCIM user) refuses with **`404`,
never `403`** — a `403` would be an existence oracle (it confirms the
resource exists but is protected); a `404` is indistinguishable from "no
such SCIM resource" — plus a `scim.user.provenance_denied` audit row so the
attempt is still recorded even though the caller sees a plain not-found.

This is the invariant that makes it safe to point a third-party IdP
connector at this endpoint at all: **a locally-created admin account, or the
`--break-glass-user` break-glass account, can never be deactivated by an IdP
push** — even if an attacker who compromises the IdP (or a misconfigured
connector) knows or guesses that account's SCIM-facing `id`. The `role`
half of the check adds a second belt: **an operator-elevated SCIM account is
not SCIM's to tear down** — once a SCIM-provisioned account has been
promoted (e.g. to `admin`) by a human through the dashboard, it drops out of
SCIM's write authority entirely, the same as if it had never been
SCIM-provisioned. **The one code path from a SCIM request to `role=admin`
is Groups → role mapping (below), and it is bounded by design:** admin is
granted only while the user is a current member of the single group named
by `--scim-admin-group` — there is no other field or code path by which a
SCIM request can set `role=admin`, so a compromised IdP can elevate a SCIM
account only as far as that one configured group, never past it, and (via
this guard) can still never touch a local or already-elevated-and-thus-
out-of-scope account, whether that account was always local or was
originally SCIM-provisioned and later promoted.

### Groups → role mapping (SOC 2 CC6.7, issue #2021)

`/scim/v2/Groups` lets an IdP push SCIM Group resources
(`POST`/`GET`/`PUT`/`PATCH`/`DELETE`, list with `startIndex`/`count`
pagination and an optional `filter=displayName eq "..."`; `PATCH` follows
RFC 7644 §3.5.2 PatchOp semantics on the `members` path). `Group` is
advertised alongside `User` in `/scim/v2/ResourceTypes` and
`/scim/v2/Schemas` (schema urn
`urn:ietf:params:scim:schemas:core:2.0:Group`).

**Role resolution reuses the existing machinery, not a parallel
implementation.** Because the auth store's role model (`auth.users.role`) is
binary (`admin` | `user`), granting admin via group membership is a parity check, not a
richer mapping: a SCIM-provisioned user is `role=admin` **iff** they are
currently a member of the group whose `displayName` equals
`--scim-admin-group` (`YUZU_SCIM_ADMIN_GROUP`, default empty — no SCIM
group grants admin). This calls the same `resolve_role_from_groups`
(`server/core/include/yuzu/server/auth.hpp`) helper SAML (#1826) and OIDC
already use for their own `--saml-admin-group`/`--oidc-admin-group`
mapping — one role-resolution function, three callers, not three
divergent implementations. Role is recomputed (never left stale) at every
point membership could have changed: on user creation, and on any Group
`POST`/`PUT`/`PATCH`/`DELETE` that could add or remove a user from the
admin group. Removing a user from the admin group demotes them back to
`user` on the next recomputation — there is no separate "apply pending
role change" step.

**The provenance guard is preserved, not bypassed, for group-driven role
changes.** A role recomputation triggered by a Group mutation only ever
writes to accounts with `provisioning_source == "scim"` — exactly the same
guard that already protects deactivate/reactivate/delete (see Provenance
guard above). If a Group's `members[]` includes the SCIM `id` of a
non-SCIM account (a locally-created admin, or the `--break-glass-user`
account), that member is silently skipped for role purposes — never
role-changed. A compromised or misconfigured IdP therefore cannot use
Group push to elevate, demote, or otherwise touch a local principal, even
by naming its SCIM-facing id in a group's membership list.

**`deprovision_role_ok` is a demote-before-delete ordering gate, not a
"manual elevation is protected" guarantee.** `deprovision_role_ok`
(`server/core/src/scim_routes.cpp`) refuses to delete/deactivate any
account whose DB-authoritative role is not `user`, returning `404` (never a
`403` existence oracle) — regardless of *how* that account came to be
non-`user` (a dashboard promotion or Groups → role mapping). Its job is
purely sequencing: SCIM must never be able to deprovision an elevated
account without an explicit, auditable demotion happening first. It is not
a promise that a manually-elevated account stays elevated — see Model A
below for what actually governs durability of a manual role change on a
SCIM account. Because Groups → role mapping can now put a SCIM-provisioned
user at `role=admin` through ordinary group membership (not just a manual
dashboard promotion), **a user who is admin via group membership cannot be
SCIM-deprovisioned until the IdP first removes them from the admin
group** — that removal demotes them back to `user` via the next
`recompute_scim_user_role` call, at which point the next deactivate/delete
call proceeds normally. This was evaluated and accepted rather than
special-cased: standard Okta/Entra offboarding already removes a departing
employee from all group assignments (including any admin group) as part of
unassigning the app, ahead of or alongside deactivating the user, so the
required ordering matches the normal IdP-side offboarding flow rather than
imposing an unusual one. Operator-facing guidance is
`docs/user-manual/scim-provisioning.md` "Deprovisioning order matters for
group-granted admins".

**Model A — IdP group membership is authoritative for a SCIM account's
role.** For any SCIM-provisioned account, `--scim-admin-group` membership,
not a manual dashboard edit, is the durable source of truth for role. A
manual (out-of-band, e.g. dashboard) role change to a SCIM-provisioned
account is **reverted to the group-derived role on the next event that
recomputes that user's membership** — i.e. a Group `POST`/`PUT`/`PATCH`/
`DELETE` that resolves to this user via `recompute_scim_user_role`, or a
`User` reprovision (`POST` reviving a deactivated account) — **not** on a
plain deactivate/delete (`deprovision_role_ok` blocks those against a
non-`user` account outright, so they never reach a recompute), and **not**
on server restart or on changing `--scim-admin-group` itself (both require
a subsequent Group mutation to actually re-evaluate membership — see
Recovery/alerting in `docs/user-manual/scim-provisioning.md`). **Residual
(carried from the Users slice, not new here):** a manually-promoted SCIM
account that is a member of **no** SCIM group is neither reverted by this
mechanism nor SCIM-deprovisionable (`deprovision_role_ok` still blocks it)
until an operator demotes it by hand — there is no membership-recompute
event that would ever touch it, because `recompute_scim_user_role` only
acts on users a Group mutation or reprovision actually resolves to.

**Architectural constraints, by design (not gaps):**

- **`displayName`-keyed, not stable-ID-keyed.** `--scim-admin-group` matches
  against a SCIM Group's mutable, non-unique-at-create `displayName` —
  unlike OIDC's `sub`+`iss` stable-identity keying (#1837), there is no
  IdP-durable group identifier in play here. A `displayName` rename in the
  IdP requires the operator to update `--scim-admin-group` to match and
  restart (see Configuration above) — the mapping does **not** follow a
  renamed group automatically. Group `POST`/`PUT` now reject `409` (create
  on an existing `displayName`, or a `PUT` rename onto one) rather than
  silently permitting a second same-named group, but this only prevents
  *duplicate* names — it does not make `displayName` a stable key.
- **Binary `admin`|`user` only.** The auth store's role model (`auth.users.role`) has exactly two
  values; Groups → role mapping cannot express anything finer even if a
  future RBAC expansion introduces more roles — the same constraint SAML
  and OIDC group→role mapping already operate under.
- **Deliberately does not reuse `directory_group_role_mappings`
  (`directory_sync.cpp`).** That table is stable-`group_id`-keyed storage
  built for the AD/Entra directory-sync path and does not apply here: SCIM
  Groups → role mapping resolves live, per-request against
  `--scim-admin-group` via `resolve_role_from_groups`, with no persisted
  mapping row of its own. This was evaluated and rejected rather than
  overlooked — reusing a stable-ID-keyed table for a `displayName`-keyed
  mapping would either force a fabricated stable id onto SCIM Groups or
  quietly change the matching semantics; a dedicated (if narrower)
  resolution path was judged clearer than overloading a table built for a
  different keying model.
- **Bounded Group membership.** Each Group operation enforces a bounded
  maximum on `members[]` size, refusing an unbounded membership push rather
  than accepting an arbitrarily large list in one call.

**Threat model addition: a compromised IdP cannot elevate a local
account.** The provenance guard bounds Groups → role mapping to SCIM's own
accounts (see above); the group-parity design bounds it to exactly one
configured group (see Role resolution above). Combined, a compromised or
malicious IdP connector can grant admin only to accounts it itself
provisioned, only via the single group an operator explicitly configured
as `--scim-admin-group`, and never to a local admin or the break-glass
account regardless of what it puts in a group's membership list. Full
change record: `docs/security-reviews/scim-groups-role-2026-07-13.md`.

### Audit actions

Audit `result` is one of **`success` | `failure` | `denied`** — not
`ok`/`error`. `success` is a completed mutation; `denied` is a guard
refusing an otherwise-well-formed request (409 uniqueness, provenance/role
mismatch, bad bearer token); `failure` is an internal error after the
request was otherwise accepted (e.g. an audit-write or transaction failure
that triggers a `500`).

| Action | Result | When |
|---|---|---|
| `scim.user.provisioned` | `success` | `POST /scim/v2/Users` succeeds (new account, or a revived reprovision) |
| `scim.user.provisioned` | `denied` | `POST` rejected `409` — `userName` collision against a currently-active account |
| `scim.user.provisioned` | `failure` | `POST` rolls back after a `500` (e.g. the account-creation transaction fails) |
| `scim.user.updated` | `success` / `failure` | `PUT /scim/v2/Users/{id}` succeeds / fails `500` |
| `scim.user.deactivated` | `success` / `failure` | `PATCH`/`PUT`/`DELETE` sets the account inactive; `failure` (set-and-proceed) if the audit write could not persist |
| `scim.user.reactivated` | `success` / `failure` | `PATCH` or `PUT` sets `active:true`; `failure` (set-and-proceed) on an audit-write error |
| `scim.user.deleted` | `success` / `failure` | `DELETE /scim/v2/Users/{id}` succeeds / audit-write failure (set-and-proceed) |
| `scim.user.provenance_denied` | `denied` | A deactivate/reactivate/delete/update targets an account whose `provisioning_source != "scim"`, **or** whose current `role != "user"` |
| `scim.auth.denied` | `denied` | Bearer-auth validation fails (missing/malformed/wrong token) on any `/scim/v2/*` route, including discovery |
| `scim.group.created` | `success` / `denied` / `failure` | `POST /scim/v2/Groups` succeeds / rejected `409` — `displayName` collision against an existing group / rolls back `500` |
| `scim.group.updated` | `success` / `denied` / `failure` | `PUT`/`PATCH /scim/v2/Groups/{id}` succeeds / rejected `409` — rename onto an existing `displayName` / fails `500` |
| `scim.group.deleted` | `success` / `failure` | `DELETE /scim/v2/Groups/{id}` succeeds / audit-write failure (set-and-proceed) |
| `scim.user.role_changed` | `success` / `failure` | A user's role is recomputed to a new value (user create, or a Group create/replace/patch/delete affecting admin-group membership); records `old_role`→`new_role`, `reason=group` |

All rows carry `principal = "scim-service"`, `principal_role = "scim-service"`.
`target_type` is `"User"` for the user-lifecycle and `role_changed` rows,
`"Group"` for the group-lifecycle rows.

### Metrics

Prometheus counters (all in the `yuzu_scim_*` namespace):

| Metric | Labels | Meaning |
|---|---|---|
| `yuzu_scim_requests_total` | `op`, `status` | Every `/scim/v2/Users` **and now `/scim/v2/Groups`** request, by operation (`op` = `create`\|`get`\|`list`\|`replace`\|`patch`\|`delete` — the literal wire values `scim_routes.cpp` passes to `record_request`) and outcome bucket (`status` = `2xx`\|`4xx`\|`5xx`). The three discovery documents (`ServiceProviderConfig`/`ResourceTypes`/`Schemas`) are NOT counted here (they carry no lifecycle op) — a rejected bearer against them still surfaces via `yuzu_scim_auth_failures_total`. |
| `yuzu_scim_auth_failures_total` | — | Bearer-auth failures on any `/scim/v2/*` route; pairs with `scim.auth.denied` audit rows. |
| `yuzu_scim_audit_write_failures_total` | — | An audit-log write itself failed. All lifecycle actions (provision, update, deactivate, reactivate, delete, group create/update/delete, role change) are set-and-proceed on this failure mode — the SCIM call still succeeded and the bump is the only record that the evidence row is missing; alert on this counter rather than expecting a `500` (see "All lifecycle audit writes are set-and-proceed" above). |
| `yuzu_scim_provenance_denied_total` | — | Provenance- or role-guard refusals; pairs with `scim.user.provenance_denied` audit rows. |
| `yuzu_scim_role_changes_total` | — | A user's role was recomputed to a new value via Groups → role mapping; pairs with `scim.user.role_changed` audit rows (`success`). |
| `yuzu_scim_role_change_failures_total` | — | `recompute_scim_user_role`'s `AuthManager::update_role` call reported a genuine AuthDB write failure — a role change that was decided but did **not** durably apply; pairs with `scim.user.role_changed` audit rows (`failure`). A sustained non-zero rate means role changes are silently not taking effect — alert on it distinctly from `yuzu_scim_audit_write_failures_total` (that counter covers a lost *evidence row* for an otherwise-successful mutation; this one covers the mutation itself failing). |

### Storage

**SHIPPED (ADR-0006 Wave 3): `ScimStore` is now its own born-on-Postgres
store, schema `scim_store`, alongside `AuthDB`'s `auth` schema — not a table
riding inside `auth.db` any more.** `ScimStore`'s resource-mapping table
(`scim_resources` — the IdP-facing `id`/`externalId` ↔ Yuzu `username`
mapping), its bearer-token table (`scim_tokens` — sha256 hashes only), and
its Group tables (`scim_groups`/`scim_group_members`) all live under the
`scim_store` Postgres schema, migrated by `ScimStore`'s own
`PgMigrationRunner` instance, independent of (but constructed alongside)
`AuthDB`'s `auth`-schema migration. `ScimStore(pg::PgPool&)` takes the same
shared server `PgPool` `AuthDB` does — a distinct schema, not a distinct
database or connection identity. This closed out the former SQLite-era
`auth.db`-cohabitation design (see history below) as part of the same
migration that moved `AuthDB` itself.

**History (pre-migration; kept for context).** Before ADR-0006 Wave 3,
`scim_resources`/`scim_tokens` were a deliberate, dated, eyes-open exception
to ADR-0006's "no new server-side SQLite store" rule — they rode the
existing SQLite `auth.db` file (their own `"scim"` `MigrationRunner`
component) rather than standing up a new Postgres store, pending `auth.db`'s
own eventual Postgres cutover. That cutover has now happened for both stores
in lockstep — the exception is retired, not carried forward. See
`docs/postgres-migration-ladder.md`'s auth/SCIM row for the shipped record.

### SCIM ↔ OIDC identity linkage for deprovision (ADR-2001, CC6.8)

`docs/adr/2001-scim-oidc-identity-linkage.md` (Accepted). Closes a gap in the
CC6.8 termination control above: a SCIM-provisioned user and their OIDC login
identity are **two disjoint `auth.users` rows** (SCIM provisions
`username=<slug>`; OIDC login always mints `username="oidc:" + iss + "#" +
sub` and never adopts the slug), and every API/MCP token a federated user
holds is minted on the **`oidc:` principal**, never the slug. Deprovisioning
the slug alone (the pre-ADR-2001 behavior) therefore revoked **zero** of a
federated user's tokens while reporting a clean success — the exact
silent-under-revocation gap this ADR closes. **PR1+PR2+PR3 of the ADR's
delivery plan are all shipped** (link formation, the revoke seam, D1, D2,
and the deny-at-login backstop, ADR §4) — a deprovisioned linked identity
can no longer re-authenticate via OIDC and mint a fresh session; see
"Deny-at-login backstop" below for the exact deny sites, the fail-closed
store-unavailable posture, and the honest (narrowed-not-eliminated) scope
of the in-flight-deprovision race it self-heals.

**Join key: `--oidc-scim-link-claim`.** Configures which validated ID-token
claim is compared against a SCIM resource's `externalId` to form the link at
login. Default `sub`; boot rejects any value outside the allow-list `{sub,
oid}` fail-closed (`main.cpp`, `CLI::IsMember`) — never a silent fallback to
an unvalidated claim. This is an **operator decision per IdP**, not a
universal default:

| IdP | Typical `externalId` source | Correct `--oidc-scim-link-claim` |
|---|---|---|
| Okta | The OIDC `sub` claim | `sub` (default — no flag needed) |
| Microsoft Entra ID | The AAD object id, which rides the ID token as the `oid` claim, **not** `sub` | `oid` (`--oidc-scim-link-claim=oid`) |

Getting this wrong is not silent: it is exactly the condition the D2
detector (below) exists to surface. An IdP whose SCIM `externalId` shares no
value with any OIDC claim Yuzu validates **cannot** have its federated
tokens revoked by SCIM at all — there is no join key available for any
`--oidc-scim-link-claim` setting to select; this is a fundamental limitation
of the design (single trusted-issuer join on IdP-asserted claims only, ADR
constraint 3), not a configuration mistake, and it too is surfaced via D2
rather than failing silently.

**Link formation (login-time, fail-open).** On a successful OIDC login,
Yuzu compares the configured claim's value against `scim_resources
.external_id`. A link is recorded (in `ScimStore`'s dedicated
`identity_links` table, keyed `(iss, sub)` unique, secondary-indexed on
`scim_id`) **only when exactly one active SCIM resource matches** —
zero matches is normal (no link, nothing to do); more than one match is
treated as **no link**, not an arbitrary pick (`ScimStore::
find_unique_active_by_external_id`; the mis-link-prevention guard, ADR §2).
The link write itself is fail-open — a write failure never fails the login,
because a missing link is caught by the D2 detector below. Independently of
whether a link formed, **every OIDC login also records a durable
observation** of the claim value it presented (`ScimStore::
record_login_observation`) — this is what makes D2 possible at all.

**Deprovision-time revoke.** SCIM `active:false` (PATCH/PUT), SCIM `DELETE`,
and the dashboard's `DELETE /api/settings/users/{username}` all resolve the
full principal set — the slug **plus every `oidc:<iss>#<sub>` identity
currently linked to it** — and revoke API tokens (`ApiTokenStore::
revoke_for_principal`) and sessions for **each** principal in that set,
**before** the account is marked inactive/deleted. On any revoke that fails
to persist, the caller does **not** report a clean success: SCIM returns
`500` (so the IdP retries) and the audit result is `partial`; the dashboard
delete likewise refuses to proceed to `remove_user`. This mirrors `/me`'s
own `api_tokens_revoked=N`/`sessions_revoked=N` detail-string pattern.
Implementation: `deprovision_revoke.{hpp,cpp}` (the shared
resolver/orchestrator, deliberately **not** a reuse of `session_revoke_fn`,
which carries unrelated `caller=self|admin` metric semantics) and
`oidc_principal.hpp` (the single `oidc_principal_id(iss, sub)` builder every
call site uses — a hand-built format would silently miss every token for a
principal built the "wrong" way).

**The ~60s residual, stated honestly.** A previously-issued API/MCP token
may keep *validating* for up to `ApiTokenStore`'s validate-cache
TTL (~60s) after the underlying `revoke_for_principal` call has already
persisted. The revoke is durable, but that cache is **process-local**
(`token_cache_` / `revoke_generation_`), and `revoke_token` /
`revoke_for_principal` invalidate only on the replica that served the call —
so on that replica this is a narrow race against the eviction, while on every
*other* replica holding a cached entry it is a deterministic window lasting
out that replica's own TTL. Add the (irreducible) IdP→SCIM propagation lag on
top. **Cookie sessions are not instant either, since HA WS-1a**:
`validate_session` routes to `validate_session_durable`, a generation-gated
cache bounded by the 1 s generation refresh (`kSessionGenRefreshMs`) and
widening to the 30 s stale-serve ceiling (`kSessionGenStaleServeBoundMs`) for
as long as a Postgres brownout blocks refreshes. The honest guarantee is
**"revoked within ~60s of the deprovision reaching Yuzu,"** not instant —
do not describe this as instantaneous revocation.

**D1 — a SCIM slug elevated to admin outside SCIM (the #2021 guard
interaction).** `deprovision_role_ok` still refuses (404, per the
provenance/role guard above) to deprovision a slug whose current role is not
`user` — including when that elevation happened via Groups→role mapping or
a manual dashboard promotion. Post-linkage, that refusal now has a new
consequence: the linked federated identity's tokens are **not**
auto-revoked either (auto-revoking on the IdP's unilateral say-so would
reopen exactly what #2021 defends against — a compromised or racing IdP
tearing down an admin). ADR-2001 D1 keeps the refusal, but makes it loud
whenever a linked identity actually exists to be missed: a human must
terminate the federated identity manually (revoke its tokens from the
dashboard, or demote-then-redeprovision). **What actually fires, precisely
(this is a real divergence from the ADR's `kCritical` shorthand worth
naming explicitly — see below):**

1. An `AuditStore` row, action `scim.user.deprovision_role_refused_with_link`,
   **`result="failure"`** — always, and no different in kind from any other
   audit row on this surface. `AuditEvent` has **no severity column**; a
   D1 audit row cannot itself be "critical" any more than a break-glass-login
   audit row can (same pattern there).
2. The Prometheus counter `yuzu_scim_deprovision_role_refused_with_active_link_total`
   — always, unconditionally, alongside the audit row.
3. A `Severity::kCritical` `AnalyticsEvent` (`emit_scim_critical_event`,
   `scim_routes.cpp`) — **only when `AnalyticsEventStore` is wired**, i.e.
   only when analytics event collection is enabled (`--no-analytics` is
   opt-*out*, so this is on by default unless explicitly disabled, but it is
   a product-analytics pipeline, not a dedicated security-alert channel, and
   a deployment that disables analytics loses this signal entirely).

**Operator guidance: alert on (1)+(2), the metric and the `result="failure"`
audit row — that is the primary, always-on D1 signal regardless of the
analytics-collection setting.** The `kCritical` analytics event is
enrichment on top for a deployment that has analytics wired, not the
detection mechanism itself. Do not build a detection rule that assumes an
audit row can itself carry a severity level — filter on `action=
"scim.user.deprovision_role_refused_with_link"` (or the metric), not on any
notion of a "critical audit."

**D2 — the fail-loud detector for a mismatched/misconfigured link claim.**
Every OIDC login records **both** the `sub` and `oid` candidate claim
values it observed, not only the value of the claim `--oidc-scim-link-claim`
is currently configured to use. When a deprovision resolves a principal set
of size 1 (slug only — no linked identity) but a recorded login observation
shows the slug's `externalId` matches **either** candidate value at some
prior OIDC login, that is a real signal: the user **did** authenticate via
OIDC, but the link never formed — almost always a misconfigured
`--oidc-scim-link-claim` (or, per the worked-examples table above, an IdP
whose `externalId` has no matching OIDC claim at all). Recording both
candidates (rather than only the configured one) is what makes D2 able to
catch the specific, common failure mode where the *wrong* claim is
configured — e.g. an Entra deployment left on the default `sub` whose
`externalId` actually matches `oid` — instead of a case where the
configured-but-wrong claim's value happens never to have been observed at
all. This bumps `yuzu_scim_deprovision_unlinked_total`
(`ScimRoutes::maybe_flag_d2_unlinked`). **A non-zero rate here means some
federated population's tokens are NOT being revoked by SCIM deprovision
today** — investigate the flag value before trusting the CC6.8 claim for
that population. D2 is a detection signal conditioned on a login-then-
deprovision pair actually occurring in the observed window, not a
standing guarantee — a zero rate means "nothing detected yet," not
"every federated user is provably linked."

**Deny-at-login backstop (ADR-2001 §4, PR3 — shipped).** An OIDC login whose
linked SCIM resource is deprovisioned is refused. `ScimStore::
linked_resource_active(iss, sub)` resolves the identity in one query — a
LEFT JOIN from `identity_links` to `scim_resources` — and returns a
`LinkedResourceState{scim_id, active}` tri-state: store-unavailable (the
query itself could not be answered) is treated identically to a resolved
inactive/orphaned link — **fail-closed, deny**; no `identity_links` row at
all is a genuine non-match — **proceed**; a linked row whose `scim_resources`
counterpart is gone (hard-DELETEd by a SCIM `DELETE` — `identity_links` is
**not** FK-cascaded) or explicitly `active=false` — **deny**, naming the
`scim_id` that drove it; a linked row with `active=true` — **proceed**. The
LEFT JOIN is load-bearing: an INNER join would collapse the orphaned-link
case into "no rows," which reads as "no link" and would let a
fully-deprovisioned identity re-authenticate — exactly the bypass this join
shape exists to close.

`oidc_login_denied_deprovisioned(scim_store, iss, sub)`
(`oidc_scim_link.{hpp,cpp}`) is the single pure decision function both call
sites in `/auth/callback` share:

1. **Primary check**, immediately after the OIDC principal is built and
   strictly **before** any mutation below it (group reconcile, session mint,
   `provision_sso_identity`, the ADR-2001 §2 link/observation writes, MFA
   `amr` seeding) — a denied login leaves no side effect behind.
2. **Post-mint re-check**, run again immediately after `create_oidc_session`
   and strictly **before** the `Set-Cookie` header is written. If a
   concurrent SCIM deactivate/DELETE landed in the window between the
   primary check and the mint, this re-check catches it: it calls
   `AuthManager::invalidate_user_sessions` on the session just minted and
   denies — self-healing the check-then-mint race **without** holding a
   cross-store lock over the mint (which would violate the "never hold one
   store's pool lease while calling another" discipline in §3 above).

Both deny sites emit the **byte-identical** `/login?error=sso_failed`
redirect the existing token-exchange-failure branch uses (no
"deprovisioned" wording reaches the browser — no oracle), a server-side
audit row `auth.oidc.deprovisioned_denied` (`result=failure`, principal =
the OIDC username), and increment the pre-seeded counter
`yuzu_auth_oidc_deprovisioned_denied_total`. `detail` distinguishes the two
denial causes rather than folding them into one reason: `reason=
linked_scim_resource_inactive` plus `;scim_id=<id>` when an actually
resolved (deactivated or orphaned) SCIM resource drove the denial, versus
`reason=scim_store_unavailable` (no `scim_id` — there is no resource to
name; the store itself could not be asked) on the fail-closed
store-unavailable path — this path denies **every** OIDC login while it
persists, not only deprovisioned ones (`docs/user-manual/scim-provisioning.md`
"Availability: a ScimStore/Postgres outage denies ALL OIDC logins"). On the
post-mint re-check path only, `detail` additionally carries
`;post_mint_recheck=true;sessions_invalidated=<N>`, and
`;db_persisted=false` if the session-revoke write itself did not persist.

**The honest guarantee — read this before describing CC6.8 as fully
closed.** Deny-at-login **fully closes** the dominant case: a re-login
against an **already-completed** deprovision is refused, unconditionally —
there is no window left to race once the deprovision itself has landed. It
**narrows, but does not eliminate by construction**, the rarer
**in-flight-deprovision** race: a login that authenticates and
mints/refreshes its link strictly *inside* the gap between the primary
check and the mint, concurrently with a deprovision landing in that same
gap, is caught by the post-mint re-check in the overwhelming majority of
timings — but a microsecond check-then-mint window remains theoretically
possible and is **deliberately not closed by lock-serialization** (the
cross-store-lock deadlock hazard above). **That residual's bound differs by
credential kind — the two must not be collapsed into one figure.** An
API/MCP token caught in the race is bounded by the existing ~60s
`ApiTokenStore` validate-cache window. A session that slips through is
**not** on the same clock: `AuthManager::validate_session` re-checks only
the session's own expiry/idle timeout on every request, never SCIM-linked
deprovision state, so a slipped session remains valid for up to the
**session's own TTL** (the absolute `kSessionDuration`, 8h by default, or a
shorter configured `--session-inactivity-secs` idle timeout) — it is cut
short early only if a *subsequent* deprovision call happens to land against
the same identity, which an IdP is not guaranteed to send again once it
believes the resource is already deactivated. Do not describe a slipped
session as bounded by ~60s, and do not describe this residual overall as
"the race has nothing left to win" — that overclaims what a lock-free,
cross-store design can guarantee; see
`docs/adr/2001-scim-oidc-identity-linkage.md` "Known residuals" for the
full statement, including the forward caveat on single-primary Postgres
reads (this guarantee assumes no read-replica routing).

### New audit actions (ADR-2001)

| Action | Result | When |
|---|---|---|
| `scim.user.deprovision_role_refused_with_link` | `failure` | D1: a role-refused deprovision (`deprovision_role_ok` 404) for a slug with ≥1 active linked OIDC identity that was NOT auto-revoked |
| `auth.oidc.deprovisioned_denied` | `failure` | §4/PR3: an OIDC login was refused because its linked SCIM resource resolved deprovisioned (deactivated, orphaned) or because `ScimStore` could not answer at all (fail-closed). Emitted from `/auth/callback`, not a `/scim/v2/*` route. `detail` carries `reason=linked_scim_resource_inactive;scim_id=<id>` when an actually resolved resource drove the denial, or `reason=scim_store_unavailable` (no `scim_id`) when the store itself could not be asked, and on the post-mint re-check path only, `post_mint_recheck=true;sessions_invalidated=<N>` (+`db_persisted=false` if that revoke itself failed to persist) |

The existing `scim.user.deactivated`/`.deleted` rows (see Audit actions
above) now also carry `api_tokens_revoked=N sessions_revoked=N
principals=N` in `detail` on success, and `partial` is now a possible
`result` for those two actions specifically (a non-persisted credential
revoke — see "Deprovision-time revoke" above), in addition to the existing
`success`/`failure`.

### New metrics (ADR-2001)

| Metric | Meaning | Operator action on non-zero |
|---|---|---|
| `yuzu_scim_deprovision_role_refused_with_active_link_total` | D1: a deprovision was refused (role != `user`) for a slug with an active linked federated identity — that identity's tokens were NOT auto-revoked | A human must terminate the linked federated identity's credentials manually (revoke its tokens, or demote the account then let the next deprovision proceed normally). Alert on this alongside the existing `yuzu_scim_provenance_denied_total`. |
| `yuzu_scim_deprovision_unlinked_total` | D2: a deprovision found a login observation matching the slug's `externalId` but resolved no formed link — almost certainly a misconfigured `--oidc-scim-link-claim`, or an IdP whose `externalId` has no corresponding OIDC claim (see the worked-examples table) | Re-check `--oidc-scim-link-claim` against your IdP (Okta: `sub`; Entra: `oid`). If neither matches, this population's federated tokens are not reachable by SCIM revoke by design — treat their manual revocation as a required step of the offboarding runbook until a shared claim exists. |
| `yuzu_auth_oidc_deprovisioned_denied_total` | §4/PR3: an OIDC login was denied at `/auth/callback` because its linked SCIM resource resolved deprovisioned (deactivated, orphaned, or the store degraded) — the deny-at-login backstop actually firing | A deprovisioned federated identity attempted to re-authenticate; confirm the deprovision was intentional. A sustained non-zero rate against one identity may indicate a termination the user (or their IdP session) has not yet noticed, or a store-degrade making the check fail closed — correlate with ScimStore/Postgres availability. |

### Residual risks / deferred (next slice)

- **Crash-window non-atomicity in the two-store deactivate/reactivate
  path — still applies on Postgres.** `ScimStore` and `AuthDB` are separate
  stores (separate schemas, separate per-call leases/transactions off the
  shared `PgPool`) even though both are now Postgres; a deactivate that
  soft-deletes the auth account and touches SCIM state is not one atomic
  cross-schema transaction. A crash between the two steps remains an
  **irreducible** window given the two-store design — it is reconciled by
  the IdP's own periodic re-sync (a deactivated user whose session survived
  the crash gets a follow-up deactivate call on the next sync cycle), not by
  a code-level fix. The Postgres migration changed the storage engine under
  each store, not this cross-store boundary.
- **No per-route SCIM rate limit.** SCIM calls share the server's global
  rate-limit only — there is no SCIM-specific throttle tuned to expected IdP
  connector call patterns.
- **`userName` is email-incompatible.** Yuzu usernames are slug-shaped
  (alnum, `.`, `_`, `-` — no `@`); a stock Okta/Entra `userName=email`
  mapping 400s. Operators must remap `userName` to a slug attribute (see
  above). Native email-shaped `userName` support is a planned follow-up.
- **Deprovision-ordering constraint on group-granted admins.** A
  SCIM-provisioned user who is `role=admin` via Groups → role mapping cannot
  be SCIM-deprovisioned until the IdP first removes them from the admin
  group (see Groups → role mapping above) — accepted as matching normal IdP
  offboarding order, not tracked as a defect.
- **`userName` rename via `PUT`.** Rejected `400 mutability` this slice;
  delete + re-provision is the only path for a username change.
- **The SCIM token stays a verify-only sha256 hash, unaffected by the
  `SecretCodec` rollout.** Like `ApiTokenStore`, there is nothing to decrypt
  — a reversible encrypted form was never planned and is not needed; the
  `mfa_totp_secret` envelope-encryption (shipped, see MFA/TOTP above) is a
  genuinely different case because TOTP verification needs the *plaintext*
  secret back, not just a compare.
- **ADR-2001 deny-at-login backstop (§4/PR3) has SHIPPED — the
  login-vs-deprovision TOCTOU is now closed for OIDC, honestly scoped.** A
  federated identity whose linked SCIM slug is **already** deprovisioned is
  refused at OIDC login, unconditionally — the simpler "re-login after
  deprovision" case is fully closed, no exceptions. The rarer **in-flight**
  race — a login that authenticates and forms/refreshes the identity link
  concurrently with a deprovision landing in the same narrow window — is
  **narrowed, not eliminated by construction**: a post-mint re-check
  self-heals the overwhelming majority of timings by invalidating a session
  minted during the race, but a microsecond check-then-mint gap remains
  theoretically possible and is deliberately not closed via cross-store
  lock-serialization (a deadlock hazard against this codebase's store
  discipline). That residual is bounded by the eager revoke PR1/PR2 already
  provide plus the ~60s `ApiTokenStore` validate-cache window. See "Deny-at-
  login backstop" above and "Known residuals" in
  `docs/adr/2001-scim-oidc-identity-linkage.md` for the precise guarantee —
  do not describe it as "the race has nothing left to win." **The remaining
  named residuals for the federated population are: (1) the ~60s
  validate-cache window (unaffected by PR3 — it bounds API/MCP token
  validation staleness after a *successful* revoke, a different mechanism
  from the login-path deny); and (2) a SAML identity whose IdP asserts an
  **unstable NameID Format** (`transient`/`unspecified`, or a missing
  Format) is deliberately not SCIM-linked** — SAML link formation (PR4a)
  and the SAML deny-at-login backstop (PR4b, issue #3066) now cover SAML on
  par with OIDC (see "SAML ↔ SCIM identity linkage" below), but linkage
  forms ONLY for a **stable** NameID (`persistent` or SAML 1.1
  `emailAddress`); an unstable-NameID SAML login still succeeds and is
  simply unrevocable via SCIM, and Yuzu never normalizes it into a linkable
  identity — a deliberate, documented residual, not an oversight in this
  ADR's scope. **ADR-2001 is also fundamentally unable to revoke a federated
  population whose IdP SCIM `externalId` shares no value with any OIDC claim
  Yuzu validates** — no `--oidc-scim-link-claim` setting helps in that case;
  see the "SCIM ↔ OIDC identity linkage" subsection above for the D2 metric
  that surfaces this.

Implementation: `server/core/include/yuzu/server/scim_store.hpp` +
`server/core/src/scim_store.cpp` (storage layer), `server/core/include/yuzu/
server/scim_json.hpp` + `server/core/src/scim_json.cpp` (JSON codec +
discovery documents), `server/core/src/scim_routes.{hpp,cpp}` (HTTP routes).
Tests: `tests/unit/server/test_scim_store.cpp`,
`test_scim_json.cpp`, `test_scim_routes.cpp`.

### SAML ↔ SCIM identity linkage (ADR-2001 PR4a+PR4b, CC6.8)

`docs/adr/2001-scim-oidc-identity-linkage.md` (Accepted, SAML addendum). The
SAML analogue of "SCIM ↔ OIDC identity linkage for deprovision" above, shipped
as **PR4a** (link formation + deprovision-time revoke — the SAML counterpart
of that section's PR1+PR2) **and PR4b** (deny-at-login — the SAML counterpart
of that section's §4/PR3). Before PR4a, a SAML login's session was keyed on
the raw NameID alone, and no link to any SCIM resource was ever recorded, so
a SCIM deprovision could not reach a SAML-authenticated identity's session at
all.

**Stable principal: `saml:<entity_id>#<NameID>`.** `AuthManager::
create_saml_session` now keys the session's `username` (the authorization/
audit/revoke principal) on `saml::saml_principal_id(entity_id, name_id)`
(`server/core/src/saml_principal.hpp`) — `"saml:" + entity_id + "#" +
name_id`, mirroring `oidc_principal_id(iss, sub)`'s shape byte-for-byte and
built through the same kind of single shared builder (both the session-mint
site and the deprovision resolver route through it, so a hand-built copy at
either site cannot drift from the other and silently miss a session on
revoke). `display_name` stays the raw NameID — human-readable rendering
only (dashboard, audit detail), never the authorization key. Both the NameID
and the `entity_id` are sanitised at the ACS handler (non-empty, ≤255 bytes,
no control bytes — the same rule `OidcProvider::validate_claims` applies to
`sub`/`oid`) **before** either value enters the principal string or the link
store; a malformed value fails the SAML login outright (redirect
`/login?error=saml`, no session minted) — fail-closed, the same posture OIDC
takes for the same class of durable-join-key input.

**Single-IdP precondition — stronger than the OIDC side.** SAML's join key
is the assertion's NameID; unlike OIDC's `--oidc-scim-link-claim` (which
selects among candidate claims), there is exactly one candidate value and no
per-issuer partitioning question, because Yuzu accepts assertions from
exactly one pinned IdP (`--saml-idp-cert` + `--saml-idp-entity-id`, both
already required — `SamlProvider::is_enabled()`). `--saml-idp-entity-id` is
now additionally load-bearing for the principal build itself: it is the
`entity_id` half of every `saml:<entity_id>#<NameID>` string, verified by
`SamlProvider::validate_response` to equal the assertion's signed
`<saml:Issuer>` before the ACS handler ever reads it. This single-pinned-IdP
shape is what makes a bare NameID→`externalId` match safe by construction —
the multi-IdP partitioning caveat the OIDC section's constraint 5 states does
not apply here as written, because there is only ever one IdP to partition
against.

**The NameID Format contract — a NameID is a safe join key ONLY when it is
STABLE and equals the SCIM `externalId`.** SAML's `<NameID>` element carries
an optional `Format` attribute; `SamlProvider::validate_response` now reads
it into `SamlAssertion::name_id_format` from the same XSW-verified assertion
node as the NameID itself. A link to a SCIM resource forms **only** when the
Format is one of the two STABLE URIs Yuzu treats as safe —
`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` or the SAML 1.1
`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
(`saml::is_linkable_name_id_format`, `saml_scim_link.hpp`). A `transient`
Format — re-minted per login by design — or an `unspecified`/missing Format
is conservatively treated as **not linkable**; Yuzu never coerces or
normalizes an unstable NameID into a linkable one. **This is an operator
configuration obligation, not something Yuzu can enforce on the IdP's
behalf: the operator must configure their IdP to emit a NameID that is both
a stable Format and equal to the SCIM `externalId` it provisions that same
user with.** A NameID that is stable-Format but numerically different from
the SCIM `externalId` (or an IdP left on `transient`) simply never forms a
link — the SAML login still succeeds, but that identity is **unlinkable, and
therefore unrevocable via SCIM deprovision**. This is the direct SAML
analogue of the OIDC section's D2 case (a mismatched/misconfigured join
claim), and — as of **#3072 (2026-08-14), SHIPPED** — SAML now has its own
D2-style observability, described in "SAML D2 observability (#3072)" below.
Unlike OIDC there is still no `--saml-scim-link-claim` knob to misconfigure
among several candidates (SAML has exactly one candidate join key, the
NameID itself), so #3072's detector shape necessarily differs from OIDC's
D2 — see that section for the honest scope of what it can and cannot
attribute.

**Link formation (login-time, fail-open).** On a successful SAML login with a
linkable NameID Format, Yuzu compares the NameID against
`scim_resources.external_id` using the same `find_unique_active_by_external_id`
exactly-one-active-match rule the OIDC side uses (`ScimStore`) — zero matches
is normal (no link), more than one match forms no link (never an arbitrary
pick). A formed link is recorded in a **dedicated `saml_identity_links`
table** (`ScimStore` migration v4 — a separate table from OIDC's
`identity_links`, deliberately not a generalization of it, keeping this PR
off the OIDC linkage schema surface), keyed `(entity_id, name_id)` unique
with a secondary index on `scim_id`. The link write itself is fail-open — a
write failure never fails the login, mirroring the OIDC side's posture
exactly (`saml::link_saml_login_to_scim`, `saml_scim_link.{hpp,cpp}`).

**Residual — rotating the pinned trust anchor orphans existing links.**
Because a link row is keyed on the pinned IdP identifier (`entity_id` for
SAML, `iss` for OIDC — part of the principal identity itself), rotating
`--saml-idp-entity-id` (or, symmetrically, the OIDC `--oidc-issuer`) leaves
every existing `saml_identity_links`/`identity_links` row keyed on the *old*
value. `saml_linked_resource_active(new_entity_id, name_id)` then matches
zero rows and reads as "no link → proceed", so the deny-at-login backstop
does **not** fire for an already-deprovisioned identity logging in under the
new identifier. Crucially the backstop **cannot re-arm itself via SCIM** for
such an identity: `link_saml_login_to_scim` re-forms a link only against an
*active* SCIM resource (`find_unique_active_by_external_id`), and a
deprovisioned resource is inactive — so the login keeps proceeding, and
re-running SCIM deprovision does nothing (there is no active resource to
re-link to). This is a deliberate, documented residual of the
single-pinned-IdP linkage model, in the same family as the unstable-NameID
residual below: within the designed envelope — one stable pinned identifier
— the control holds; rotating that identifier is re-establishing the trust
anchor. Across such a rotation the operator relies on the **primary**
termination control — the IdP no longer issuing assertions for a terminated
user — since the deny-at-login backstop (which exists precisely for the case
where SCIM deprovision and IdP de-authorization are decoupled or lagging) is
blind to a pre-rotation-deprovisioned identity until it is re-provisioned
and re-links on a subsequent login. It is not a code gap the deny logic can
close without abandoning the `entity_id`/`iss`-scoped link key (which is
what keeps a SAML `saml:` principal and an OIDC `oidc:` principal from ever
colliding on a shared NameID/subject).

**Deprovision-time revoke: SAML has no API tokens, so revoke = session
invalidation.** `resolve_deprovision_principals`
(`deprovision_revoke.cpp`) now runs a second pass alongside the existing
OIDC one: for every row `ScimStore::saml_links_for_scim_id(scim_id)` returns,
it adds `saml::saml_principal_id(entity_id, name_id)` to the principal set a
deprovision revokes — fail-**closed** on that lookup's own `nullopt`, exactly
like the OIDC pass (a store blip must never be read as "no linked SAML
identity"). Because SAML never mints API/MCP tokens (there is no
`revoke_for_principal` call site keyed on a `saml:` principal — only
`create_saml_session` mints anything for one), the practical effect of
resolving a `saml:` principal into the revoke set is **session
invalidation only**: the linked SAML session (if still live) is torn down;
there are no SAML-keyed tokens to revoke.

**Deny-at-login backstop — PR4b (#3066), SHIPPED.** PR4a alone closed only the
*deprovision-time* gap: an existing SAML session for a deprovisioned, linked
identity is revoked. PR4b closes the login-time gap the same way §4/PR3
closes it for OIDC above — a deprovisioned SAML identity is now refused *at*
`/saml/acs`, not merely torn down on the next deprovision pass.
`ScimStore::saml_linked_resource_active(entity_id, name_id)` is the SAML
analogue of `linked_resource_active(iss, sub)`: a LEFT JOIN from
`saml_identity_links` to `scim_resources` in one query, reusing the OIDC
side's `LinkedResourceState` tri-state shape — store-unavailable is
fail-**closed** (deny), no linked row is a genuine non-match (proceed), an
orphaned link (the `scim_resources` row hard-deleted) denies unless an active
reprovision sibling exists for the same NameID
(`find_unique_active_by_external_id`, the same reprovision rule §4 uses), and
an explicitly-deactivated link denies unconditionally. `saml::
saml_login_denied_deprovisioned(scim_store, entity_id, name_id)`
(`saml_scim_link.{hpp,cpp}`) is the single pure decision function both call
sites in `/saml/acs` share — a **primary check** immediately after
`saml_principal` is built and strictly before any mutation (link formation,
session mint), and a **post-mint re-check** immediately after
`create_saml_session` and strictly before `Set-Cookie`, which invalidates the
just-minted session via `AuthManager::invalidate_user_sessions` and denies if
a concurrent deprovision landed in the check-then-mint window — the identical
self-healing shape §4 uses for OIDC. Unlike the OIDC side there is no
separate link-claim parameter: SAML's join key is always the NameID itself
(see the NameID Format contract above), so the orphaned-branch reprovision
check resolves against `name_id` directly.

Both deny sites emit the **byte-identical** `/login?error=saml` redirect
every other SAML failure branch uses (no oracle), a server-side audit row
`auth.saml.deprovisioned_denied` (`result=failure`, principal = the
`saml:<entity_id>#<NameID>` string), and increment the pre-seeded counter
`yuzu_auth_saml_deprovisioned_denied_total`. `detail` distinguishes the two
denial causes exactly like the OIDC row: `reason=
linked_scim_resource_inactive;scim_id=<id>` when a resolved (deactivated or
orphaned-not-reprovisioned) SCIM resource drove the denial, versus `reason=
scim_store_unavailable` (no `scim_id`) on the fail-closed store-unavailable
path; the post-mint re-check path additionally carries `;post_mint_recheck=
true;sessions_invalidated=<N>` (+`;db_persisted=false` if that session
invalidation itself failed to persist). PR4b inherits the `--scim-enable`
gate for free — `/saml/acs` reads the same `AuthRoutes::scim_store_` member
the SCIM routes already null-check, so with SCIM off the decision function
receives a null store and unconditionally proceeds; there is no new
feature-off SAML login outage, only the same store-availability coupling §4
already documents for OIDC while `--scim-enable` is on.

**The honest guarantee — read this before describing SAML CC6.8 as fully
closed, exactly as the OIDC section above asks.** Deny-at-login fully closes
the dominant case for SAML too: a re-login against an already-completed
deprovision is refused, unconditionally. It narrows, but does not eliminate
by construction, the same in-flight-deprovision race described for OIDC
above, for the identical reason (the cross-store-lock deadlock hazard) — the
post-mint re-check self-heals the overwhelming majority of timings, and a
microsecond check-then-mint gap remains theoretically possible. SAML mints no
API/MCP tokens, so there is no ~60s validate-cache bound to lean on for a
slipped session on this side; a SAML session that does slip through the race
is bounded only by the session's own TTL (the absolute `kSessionDuration` or
a configured `--session-inactivity-secs`), the identical residual the OIDC
section states for a slipped session. **Test coverage caveat, shared by both
providers, stated once:** this codebase has no mock-IdP integration harness
exercising a live `/saml/acs` or `/auth/callback` round trip end to end —
`saml_login_denied_deprovisioned` and `oidc_login_denied_deprovisioned` are
each covered by direct unit tests against the decision function
(`test_saml_scim_link.cpp`, `test_oidc_scim_link.cpp`), and each call site's
wiring into its route handler (ordering relative to link formation, mint, and
`Set-Cookie`; the audit-detail construction; the redirect) is verified by
code inspection rather than an end-to-end test — an existing limitation of
both backstops, not something PR4b newly introduced. See
`docs/adr/2001-scim-oidc-identity-linkage.md`'s SAML addendum item 8 for the
full statement.

Implementation: `server/core/src/saml_principal.hpp` (the single
`saml_principal_id(entity_id, name_id)` builder), `server/core/src/
saml_scim_link.{hpp,cpp}` (login-site link orchestration + the NameID Format
gate), `server/core/include/yuzu/server/scim_store.hpp` + `scim_store.cpp`
(the `saml_identity_links` table, migration v4), `server/core/src/
deprovision_revoke.cpp` (the SAML second pass), `server/core/src/
saml_provider.{hpp,cpp}` (`SamlAssertion::name_id_format` extraction).
Tests: `tests/unit/server/test_saml_principal.cpp`,
`test_saml_scim_link.cpp`, `test_saml_provider.cpp`, `test_saml_routes.cpp`,
`test_scim_store_pg.cpp`, `test_scim_routes.cpp`,
`test_auth_sso_identity.cpp`.

### SAML D2 observability (#3072, SHIPPED 2026-08-14)

Before #3072, SAML's version of D2 was a genuine, stated gap: unlike OIDC —
which has a `--oidc-scim-link-claim` knob an operator can misconfigure among
several candidate claims, and therefore a candidate to detect a mismatch
against — SAML has exactly one join key (the NameID), so there was nothing
to record a "should-have-matched" observation about. #3072 closes that gap
with a SAML-shaped detector, not a copy of OIDC's: it splits the signal
across **login time** (three new, always-on, observe-and-proceed signals)
and **deprovision time** (one D2-style tripwire), because the two catch
genuinely different failure shapes on SAML — see "Honest scope" below.

**New table: `saml_login_observations` (`ScimStore` migration v5).** The
SAML analogue of `oidc_login_observations` (§"D2" above) — keyed
`(entity_id, name_id, name_id_format)` **unique**, secondary-indexed on
`name_id` (`saml_observation_matches` looks up by `name_id` alone, which the
3-column unique key does not serve). `name_id_format` is deliberately part
of the uniqueness key rather than folded into `(entity_id, name_id)` alone:
a later login presenting the same NameID value under a **stable** Format
must not silently overwrite — and so erase — an earlier observation
recorded under an **unstable** Format; each `(entity_id, name_id, format)`
triple is its own row. Bounded upsert (`seen_at` refreshed on every login,
one row per distinct NameID+Format pair) — no GC/retention obligation,
matching `oidc_login_observations`' no-GC posture.

`ScimStore::record_saml_login_observation(entity_id, name_id,
name_id_format)` records **every** SAML login's NameID observation,
including an unstable-Format one — it is called **before** the
linkable-Format gate in `link_saml_login_to_scim`, unconditionally.
Observe-only: the NameID is never normalized here, and this call never
influences whether a link forms. `ScimStore::saml_observation_matches(name_id)`
returns a tri-state `std::optional<bool>` mirroring `observation_matches`'
OIDC contract: `nullopt` means the store could not answer (closed, lease
timeout, failed statement) and the caller **must** skip rather than
false-positive a "never seen"; engaged `true`/`false` are a genuine
seen/not-seen answer.

**`find_unique_active_by_external_id_checked` — the store-error-aware
lookup #3072 needed to build the login-time signals.**
`ScimStore::find_unique_active_by_external_id` (used by both OIDC and SAML
link formation) always collapsed "zero matches", "ambiguous (>1) matches",
and "the store could not answer" into the same `nullopt` — sufficient for
link formation's fail-open posture, but not enough to drive a distinct
audit verb per cause. The new `find_unique_active_by_external_id_checked`
returns a 4-state `ActiveExternalIdLookupResult{status, resource}` —
`matched` / `no_match` / `ambiguous` / `store_error` — with the identical
underlying query and the identical ADR-2001 §2 mis-link guard (no `LIMIT 1`;
more than one row is `ambiguous`, never an arbitrary pick). The plain
`find_unique_active_by_external_id` is now a thin, byte-unchanged
compatibility wrapper over it (`matched` → the resource, every other status
→ `nullopt`) — every pre-existing caller (OIDC link formation, both
providers' orphan/reprovision checks, SAML link formation, deny-at-login)
keeps its exact prior behaviour.

**`link_saml_login_to_scim` now returns a typed `SamlScimLinkOutcome`**
(`saml_scim_link.hpp`) instead of `void` — `not_linkable` / `linked` /
`no_active_match` / `ambiguous_match` / `lookup_store_error` /
`link_write_error` — so `POST /saml/acs` can drive per-outcome audit/metric
signals without re-deriving the cause. Every value is still a **proceed**
outcome for the login itself: login-time linking stays fail-open by
contract, unchanged from before #3072 (the PR4b deny-at-login backstop
above is the only SAML-side path that can refuse the login).

**Two new login-time audit verbs at `POST /saml/acs`, observe-and-proceed —
these are NOT denies.** The SAML login still succeeds on every branch below;
only the audit trail and a counter change:

- `auth.saml.link_unmatched` (`result=failure`) — fires on
  `SamlScimLinkOutcome::no_active_match` (`reason=
  no_active_external_id_match;name_id_format=<format>`) **or**
  `::ambiguous_match` (`reason=
  ambiguous_active_external_id_match;name_id_format=<format>`). The two
  causes share one audit action but bump **separate** counters
  (`yuzu_scim_saml_link_unmatched_total` vs
  `yuzu_scim_saml_link_ambiguous_total`) — an ambiguous `externalId` is a
  distinct, more actionable misconfiguration (duplicate/stale SCIM data)
  than ordinary IdP/SCIM drift, and stays separately countable in metrics
  even though the audit `detail` already distinguishes the two by `reason=`.
- `auth.saml.link_lookup_failed` (`result=failure`,
  `reason=scim_store_unavailable`) — fires on `::lookup_store_error`: the
  `ScimStore` lookup itself could not answer. Distinct from
  `link_unmatched` so a store outage is never misread as "the identity has
  no matching SCIM user."

`::linked`, `::not_linkable`, and `::link_write_error` keep the pre-#3072
behaviour — no new login-time audit row (`link_write_error` still bumps the
pre-existing `yuzu_scim_saml_link_write_failures_total` inside
`link_saml_login_to_scim` itself, unchanged).

**Deprovision-time D2: `maybe_flag_saml_d2_unlinked`.** The SAML analogue of
`maybe_flag_d2_unlinked` (§"D2" above) — fires when a deprovisioned
resource's `externalId` has **zero** linked SAML identities
(`ScimStore::saml_links_for_scim_id`) but a recorded SAML login observation
shows a NameID matching that `externalId`. It queries
`saml_links_for_scim_id` **specifically** — never OIDC's `links_for_scim_id`
or a `principals.size()` proxy — mirroring the PR4a C2 lesson
`maybe_flag_d2_unlinked` already learned: an OIDC link coexisting on the
same `scim_id` must never mask a missing SAML link, and vice versa. Bumps
the new `yuzu_scim_deprovision_saml_unlinked_total` counter; a store-error
`saml_links_for_scim_id`/`saml_observation_matches` read is skipped rather
than risking a false positive off an unconfirmed read (the identical
fail-safe posture `maybe_flag_d2_unlinked` takes).

**Honest scope — read this before treating #3072 as SAML's D2 in full.**
The login-time signals and the deprovision-time D2 tripwire are
**complementary, not overlapping**, because SAML's single-candidate-NameID
model forces a split OIDC's multi-candidate-claim model does not need:

- The **login-time signals** catch a **stable-Format** NameID that failed
  to link — no active match, an ambiguous match, or a store error — at the
  moment it happens, because at that moment the store lookup that would
  answer "does this NameID match any active `externalId`" has already run
  as part of ordinary link formation.
- The **deprovision-time D2 tripwire** catches the complementary case: an
  **unstable-Format** NameID (`transient`/`unspecified`/missing) whose
  *value* nonetheless matches the deprovisioned resource's `externalId` —
  a login that was never even attempted as a link (the Format gate skipped
  the lookup entirely), but whose observation record still lets deprovision
  time notice the value would have matched.
- **What neither one attributes: a stable-Format NameID that never matches
  any `externalId`, discovered only at deprovision time.** SAML has no
  second candidate the way OIDC's `sub`/`oid` pair does, so there is no
  second value to re-check against the deprovisioned resource's
  `externalId` after the fact — attributing that case at deprovision time
  would mean guessing, and a guessed CC6.8 attribution is worse than an
  honestly-absent one. This case is caught at **login time instead** (via
  `link_unmatched`/`link_lookup_failed` above, which fire at the moment the
  mismatch is observable) — true **deprovision-time** attribution for a
  pure stable-Format drift case is deferred to **issue #3098** (a second
  SAML join attribute, or an operator-configured mapping, would be needed
  to give deprovision time a second candidate to check the way OIDC's `oid`
  gives D2 one).

**Two further residuals (governance hardening round, UP-2/UP-3).**
**UP-2 — the observation write is fail-open, like every other write on this
path.** If `record_saml_login_observation` itself fails (a `ScimStore`
blip during the login window), the login still proceeds and that login is
simply never recorded, so a later deprovision's D2 tripwire cannot fire
for it — the same shape as a missed link write. Not a security regression
versus pre-#3072 (D2 is a detective control; deprovision-time revocation
itself is unaffected), and it is itself surfaced: the observation write
and the link write share `yuzu_scim_saml_link_write_failures_total`, so a
sustained non-zero rate there is the honest signal that D2 coverage — not
only linkage — is degraded for that window. **UP-3 — no GC, and the
deprovision-time match is entity/format-agnostic.** `saml_login_observations`
rows are never pruned, a deliberate choice mirroring `oidc_login_observations`:
the table is a bounded upsert keyed on distinct identities, not one row
per login event, and it is durable CC6.8 evidence rather than regenerable
scratch data — the `ResultSetStore` pruning model does not apply here.
Separately, `saml_observation_matches` matches on `name_id` **value
alone** (`WHERE name_id = $1`, no `entity_id`/`name_id_format`
predicate) — safe under the single-pinned-IdP precondition already stated
for this addendum, but worth naming explicitly: `maybe_flag_saml_d2_unlinked`
therefore fires on *any* recorded NameID-value match regardless of the
Format it was observed under, which makes the tripwire slightly
**broader** than "catches the unstable-Format-but-value-matches case"
alone — an under-statement in the framing above, not a false guarantee,
since the detector is strictly more protective than described (it would
also, for example, catch a stable-Format value-match whose link write
itself failed). A future multi-`entity_id` SAML deployment would need an
`entity_id` predicate added to `saml_observation_matches` before this
match stays safe, the same way constraint 5's forward caveat already
requires for OIDC's issuer partitioning.
`yuzu_scim_deprovision_saml_unlinked_total` remains a **review** signal,
not a hard alarm with one root cause.

New metrics: `yuzu_scim_saml_link_unmatched_total`,
`yuzu_scim_saml_link_ambiguous_total`,
`yuzu_scim_saml_link_lookup_failures_total`,
`yuzu_scim_deprovision_saml_unlinked_total` — see
`docs/user-manual/metrics.md` "SCIM deprovision-linkage metrics" for the
operator-facing description of each, and
`docs/user-manual/rest-api.md`'s SCIM audit-actions table for the two new
audit verbs.

Implementation: `server/core/include/yuzu/server/scim_store.hpp` +
`scim_store.cpp` (`saml_login_observations` table migration v5,
`record_saml_login_observation`, `saml_observation_matches`,
`find_unique_active_by_external_id_checked`), `server/core/src/
saml_scim_link.{hpp,cpp}` (`SamlScimLinkOutcome`, the unconditional
observation write), `server/core/src/auth_routes.cpp` (the two login-time
audit/metric branches at `/saml/acs`), `server/core/src/scim_routes.cpp`
(`maybe_flag_saml_d2_unlinked`), `server/core/src/server.cpp` (the four
counter registrations). Tests: `tests/unit/server/test_saml_scim_link.cpp`,
`test_scim_routes.cpp`, `test_scim_store_pg.cpp`.

## Granular RBAC (Phase 3)

- 7 roles, 38 securable types, per-operation permissions, deny-override logic.
- **OIDC SSO** — Full PKCE flow, Entra ID discovery, JWT validation, group-to-role mapping.
- **AD/Entra integration** — Microsoft Graph API for user/group import.

### `ProductPack` securable seeding fix (#4029)

`ProductPack` was used as an RBAC securable-type string by the shipped
`/api/product-packs*` routes (`workflow_routes.cpp`, `perm_fn(req, res,
"ProductPack", "Read"/"Write"/"Delete")`) but was never seeded into
`RbacStore::seed_defaults()`'s `types[]` array or `mcp_server.cpp`'s
mirrored `kRbacSecurables[]`. `role_permissions.securable_type` carries a
hard FK to `securable_types(name)`, so no role — not even Administrator —
could ever be granted `ProductPack:*` while RBAC was enabled; the routes
were reachable only via the RBAC-off legacy fallback or an elevated-session
bypass. Fixed as part of #4029 (the same class of gap #2376's
`EnginePrincipal` cut fixed for a different securable, see above): `types[]`
now includes `ProductPack` (Administrator gets full CRUD for free via the
existing cross-type loop), and `Read` is additionally granted to
Operator/PlatformEngineer/Viewer — the same population that already holds
`InstructionDefinition:Read`, for consistency across the content/catalog
domain. Write/Delete stay Administrator-only (the issue's ask was scoped to
the read twins; a follow-up could widen this if an operator role needs to
author/uninstall packs directly). `#4032` tracks the identical gap for
`Workflow` and `Directory`, fixed by sibling issues in their own PRs — this
fix touches `ProductPack` only.

## The authorization topology floor (#2376)

**The defect.** `RbacStore::rbac_enabled_` defaults `false`, so a fresh
install runs with RBAC off — the default posture, not an edge case. With
RBAC off, `AuthRoutes::require_permission`/`require_scoped_permission` fall
through to a legacy branch (`server/core/src/auth_routes.cpp`, both
functions, ~:713/~:919) that allows every `Read` to any authenticated
non-engine session (see the `rbac_enforcement_in_effect` gate at ~:699,
which is the branch above the legacy fallback — a live RBAC grant is always
consulted first and returns before the legacy branch is ever reached; the
legacy branch is reachable only when RBAC is disabled or the store is
unwired). On a default install that gave a plain `user` session read access
to the authorization TOPOLOGY itself: the fleet-wide access-review export
(the surface that exists to **be** SOC 2 CC6.2 evidence — see "Periodic
access reviews" below), `GET /api/v1/rbac/roles` (the RBAC role graph), and
the engine-principal grant graph (`GET /api/v1/engine-principals*` and its
MCP twins).

**The fix has three parts**, all keyed off the single
`server/core/src/authz_topology_floor.hpp` chokepoint:

1. **A new `EnginePrincipal` securable** (`Read` only, so far), cut away
   from the over-broad `Security:Read`. The engine-principal inventory and
   grant-graph reads moved onto it: REST `GET /api/v1/engine-principals`,
   `GET /api/v1/engine-principals/{id}`, `GET
   /api/v1/engine-principals/{id}/roles`, and the MCP twins
   `list_engine_principals`, `get_engine_principal`, `list_engine_roles`.
   This is the same move #2324 made cutting `AccessReview` away from
   `AuditLog:*` (see "Periodic access reviews" → "#2225 round 2" below) —
   the same shape of over-broad-securable defect, closed the same way.
   Seeded (`RbacStore::seed_defaults()`) to `Administrator` (full CRUD via
   the existing cross-type loop) and `Viewer` (`Read`) — exactly the two
   built-in roles that reached these routes via `Security:Read` before the
   cut, so no built-in role's authority widens or narrows under
   RBAC-enabled enforcement; only the RBAC-off legacy posture changes (see
   below).
2. **The topology floor itself**: `{AccessReview:Read, UserManagement:Read,
   EnginePrincipal:Read}` — plus, as of #4028, `{TlsConfig:Read,
   PluginSigning:Read, ServerConfig:Read, AnalyticsConfig:Read}` (see
   "Settings read-twins" below), and as of #4031, `{Enrollment:Read,
   OidcConfig:Read}` — require the `admin` session role regardless of the
   RBAC on/off toggle, via `authz_topology_floor.hpp`'s
   `topology_floor_applies()`. The three groups are different categories
   that happen to share this one mechanism: the original three are
   authorization-topology reads (the RBAC role graph, the engine-principal
   grant graph, the access-review export) that intentionally stay reachable
   by an admin-owned session on ANY transport, MCP tokens included, per the
   legacy-role-fallback note below; the #4028 four and #4031 two are
   server-administration reads that #520 additionally excludes from every
   MCP tier outright (`mcp_policy.hpp`'s `tier_allows()`), so an admin-owned
   MCP token cannot reach them even though it would otherwise satisfy this
   same floor check. (`Directory` deliberately has no floor entry, since it
   was never `admin_fn_`-gated to begin with — `list_directory_users` and
   most of `get_directory_status`'s payload stay reachable at Viewer role
   and readonly MCP tier. **One field is the exception:**
   `groups[].mapped_role` on `get_directory_status` — the AD-group ->
   Yuzu-role authorization map, the same data class as the floored
   `OidcConfig` `admin_group` field (colleague review on #4176 caught this
   inconsistency: `mapped_role` was newly MCP-reachable at readonly tier and
   newly Viewer-reachable under RBAC-on with no floor treatment at all,
   despite the sibling `OidcConfig` field being floored in this same PR).
   Flooring all of `Directory:Read` was rejected — it would also demote
   `list_directory_users` (lower-sensitivity PII, not authorization
   topology) to admin-only under RBAC-off. Instead
   `directory_status_json`'s `reveal_mapped_role` parameter redacts just
   that field to the empty string for a non-admin caller, checked via the
   same `auth::effective_role(session) == auth::Role::admin` test the
   topology floor itself uses — REST v1, the legacy route, and the MCP tool
   all compute it independently at their own call site, since the floor
   mechanism only gates whole-route `(securable, operation)` pairs, not
   individual response fields.) It is consulted **only**
   inside the legacy (RBAC-off) fallback of
   `require_permission`/`require_scoped_permission`
   — never ahead of, or instead of, the live-RBAC branch. That ordering is
   load-bearing, not incidental: #2324 cut the dedicated `AccessReview`
   securable specifically so a non-admin `Reviewer` role could be seeded
   `AccessReview:Read` and reach the export without being `admin`. If the
   floor ran ahead of the live-RBAC branch (or replaced it), it would deny
   that seeded `Reviewer` grant and destroy the entire reason the
   `AccessReview` securable exists. Because the live-RBAC branch in both
   functions always `return`s (true or false) before the legacy branch's
   code is reached, "floor only in the legacy branch" is structural, not a
   convention that could silently drift — there is only one path into the
   floor check.
3. **Observability.** A floored denial gets a distinct audit reason —
   `"topology floor: non-admin role denied <securable>:<operation>"` on the
   `auth.permission_required`/`auth.scoped_permission_required` audit
   actions, `result=denied` — instead of the generic `"non-admin role
   denied ..."` an ordinary legacy write/delete/execute/approve denial
   gets. It is also counted separately in
   `yuzu_auth_topology_floor_denied_total{permission}`, so an operator can
   alert on floored denials specifically rather than parsing audit-log
   text.

**Deliberately NOT floored, on purpose:**

- **`Security:Read`** — considered and excluded because it is too coarse
  for this purpose. It also gates quarantine visibility, CA issued-certs
  (`GET /api/v1/ca/issued` and its `list_issued_certs` MCP twin),
  `/ca/root-csr`, and KEK status — all operational reads, not authorization
  topology. Flooring `Security:Read` wholesale would have swept those four
  in too, denying them to non-admins on RBAC-off installs where they
  currently work. This is exactly why the engine-principal reads were cut
  to their own `EnginePrincipal` securable rather than floored on
  `Security:Read` directly — a floor can only be as narrow as the
  securable it keys on.
- **`ApiToken:Read`** and **`ManagementGroup:Read`** — considered and
  excluded for the same reason: they are operational data, not
  authorization topology.

The floor is **not configurable** — there is no toggle that widens it back
open; a footgun that can re-open a security floor is not a feature. See
`docs/security-reviews/authz-topology-floor-2026-08-05.md` for the full
recorded decision, including why the floor is keyed on `(securable,
operation)` rather than route path (an MCP tool call and an unrelated MCP
tool call share the same `/mcp/v1/` wire path, so a route-keyed floor
cannot distinguish `list_engine_roles` from `list_issued_certs`), and why
`Viewer` keeps `EnginePrincipal:Read` under RBAC-enabled enforcement (a
narrower RBAC-on role model is a separate decision from closing the
RBAC-off gap, not taken here).

**No schema migration.** `seed_defaults()` runs unconditionally on every
`RbacStore` construction and its seed loops are `INSERT OR IGNORE`, so an
existing deployment picks up the `EnginePrincipal` securable and its grants
on the next boot with no migration required — the same mechanism that
introduced `AccessReview` and `SoftwareLicensing`. A migration is needed
only when a change cannot be expressed as an idempotent additive re-seed
(`rbac_store.cpp`'s legacy SQLite v4 migration *deletes* rows, which is why
it needed one — distinct from the PG schema's own migration sequence,
ADR-0041, currently at v3).

## Settings read-twins (#4028, api-parity programme #2146)

Eight `/fragments/settings/*` dashboard sub-areas (TLS, HTTPS, gateway, server-config, MCP,
data-retention, analytics, plugin-signing) were gated **only** by `AuthRoutes::require_admin` — a
whole-route role check, not an RBAC securable/operation pair, with no REST v1 twin and no RBAC-off
fallback at all. #4028 migrated all eight onto four new securables, split along sensitivity lines
rather than one blanket `Settings:Read` (the same reasoning `EnginePrincipal` above was cut for):

- **`TlsConfig`** — the `tls` and `https` fragments (mTLS/HTTPS listener posture, cert/key/CA file
  paths).
- **`PluginSigning`** — the `plugin-signing` fragment and its REST twin, the hardened
  `GET /api/v2/agent/plugin-policy` (deliberately distinct from the unrelated `PluginConfig`
  securable, which gates per-plugin runtime kill-switch config — a different domain). Its
  deprecated `/api/v1/` predecessor is frozen on `require_admin`, not this securable — see
  `docs/api-versioning-policy.md` and #4144.
- **`ServerConfig`** — the `gateway`, `server-config`, `mcp`, and `data-retention` fragments
  (operational/infra config, "nothing secret" per #4028's own evidence).
- **`AnalyticsConfig`** — the `analytics` fragment (ClickHouse integration; embedded-credential
  risk, see below).

Each is `Read`-only today, seeded to `Administrator` only (via the existing cross-type CRUD loop in
`seed_defaults()` — matching every other admin-only securable's precedent, e.g. `PluginConfig`,
`PluginSecret`, `UploadGrant`, `PowerManagement` above), deliberately absent from `Viewer`'s blanket
read-list and every other role's explicit grant list — this is a mechanical RBAC-ification of an
already-admin-only gate, not a broadening. All four `(securable, "Read")` pairs are also added to
`authz_topology_floor.hpp`'s `kTopologyFloor[]` (see that file's own doc comment for why: migrating
an admin-only gate onto a Read securable without flooring it would silently widen every one of these
eight routes from admin-only to any-authenticated-user on an RBAC-off install, the out-of-the-box
default) — extending that file's floor beyond its original "authorization topology" framing to a
second, related case: preserving an *existing* admin-only posture across the RBAC-off toggle.

**The MCP question (#520).** `require_admin`'s own comment states the deliberate design this issue
had to resolve explicitly, not silently override: "MCP tokens are for fleet management (queries,
instruction execution) and must not be used to administer the server itself (settings, users, TLS,
OIDC)." #4028 ships all eight sub-areas **REST-only** — no MCP tool touches any of them — treating
read-only settings visibility as a meaningfully different exposure than the fleet-query surface #520
was written to keep MCP confined to, but one that still requires its own reviewed amendment to #520
rather than a side effect of a routine twin PR. See [MCP Server](mcp-server.md) for the policy
itself.

Shipping no MCP *tool* is not, by itself, sufficient to preserve #520's intent, because these eight
routes are also reachable over REST, and an MCP *token* can call any REST route its tier and role
admit — an MCP tool registration and an MCP token's REST reach are two independent things. The
topology floor above requires `admin` role in the RBAC-off legacy fallback, but `require_permission`
does not otherwise distinguish an admin-owned MCP token from an ordinary admin session: an MCP token
carries its **creator's** real legacy role there by design (see "The authorization topology floor"
above), so an admin-owned MCP token — at any tier, including `readonly` — would satisfy the floor
exactly like an interactive admin session would, unless something stops it earlier. Hardening
this route off `require_admin` (which rejected every `mcp_tier` token
outright, regardless of role) onto `require_permission` — now `GET /api/v2/agent/plugin-policy`,
split from the still-`require_admin`-gated, deprecated `/api/v1/` shape by #4144 — would have
silently reopened it to admin-owned MCP tokens without an explicit second control. #4028's actual enforcement point is
`mcp_policy.hpp`'s `tier_allows()`: `TlsConfig`, `PluginSigning`, `ServerConfig`, and
`AnalyticsConfig` are denied at **every** tier there (readonly/operator/supervised) for **every**
operation, so `require_permission`'s tier check 403s an MCP token before it ever reaches the
topology-floor/legacy-role fallback that would otherwise admit it. This deliberately puts these four
securables in a different category from the pre-existing three topology-floor pairs
(`AccessReview`/`UserManagement`/`EnginePrincipal`), which keep the admin-owned-MCP-token
reachability described above by design (see the topology floor section) — those are
authorization-topology reads, not server-administration reads, and #520's language is specific to
the latter. Coverage: `test_mcp_server.cpp` ("no tier admits the #4028 server-administration
securables") pins `tier_allows()` directly; `test_auth_routes.cpp` ("no MCP tier ... reaches the
#4028 settings-administration securables") exercises the same guarantee through the real
`require_permission()` end-to-end path, with an admin-owned readonly-tier token and RBAC disabled —
the exact combination that would otherwise have passed.

**Analytics also fixed a leak, not just added RBAC.** `render_analytics_fragment` (and the new
`GET /api/v1/settings/analytics` twin) previously rendered the ClickHouse URL verbatim, masking only
the separate `clickhouse_password` field — a URL with embedded userinfo credentials
(`clickhouse://user:pass@host:9000/db`) leaked the credential regardless. The shared builder now
strips URL userinfo unconditionally (`settings_model::sanitize_url_userinfo`) before either surface
ever sees it, and never reads the raw password into a response at all — only a
`clickhouse_password_set` bool. Fix-round hardening (governance Gate 2-8, three rounds, plus two
external adversarial-review passes, `/home/dgr/advrev-4028`) found the initial strip itself
incomplete: an unescaped `@`, `/`, or `?` inside the userinfo let part or all of a credential
through, and a query-string credential form (`?password=...`, no `@` at all) was not modeled. A
first attempt tried to locate the authority boundary (the path-starting `/`) and search for `@`
only within it, widening past an embedded `/` via a "does this look like a `host[:port]`"
heuristic — governance re-review found that unfixable (a digit-only password segment before the
`/` is lexically identical to a real port, so the heuristic cannot tell them apart) and it shipped
a regression on top of the bypass it was meant to close. A second design deleted that heuristic
entirely — the userinfo delimiter became simply the LAST `@` anywhere in the URL, with the query
string or fragment dropped afterward — which deliberately over-strips when the path itself
contains a later, harmless `@` (`.../db@table` becomes `.../table`), an accepted trade-off since
the alternative is a heuristic that can be fooled into leaving a real credential in place. That
second design itself shipped with two further bypasses an adversarial-review round found: a
schemeless URL whose query string contains a nested `://` could fool scheme-boundary detection
into skipping the strip entirely, and a query string that itself contains an `@` could make the
query-strip (which ran against the already-userinfo-stripped string) miss its own delimiter and
leave a password fragment exposed.

**Current (third) design closes both, plus one further gap the fix itself introduced.**
`sanitize_url_userinfo` bounds the scheme scan to a genuine RFC 3986 §3.1 grammar match
(`ALPHA *(ALPHA/DIGIT/"+"/"-"/".")` immediately followed by `"://"`, evaluated from position 0
only — never an unbounded search), and computes both the userinfo-ending `@` and the
query/fragment-start cut points against the ORIGINAL string, unioning the two removal ranges
rather than mutating sequentially; when the two ranges overlap (an inherently ambiguous shape —
a real `?`-corrupted password vs. no userinfo at all with the query containing its own `@`), it
over-strips to the scheme prefix, the same conservative resolution the design already applies
elsewhere. A subsequent adversarial-review round of this exact fix (finding CDX-01) found the
scheme scan itself accepted a DIGIT (or `+`/`-`/`.`) as the *first* scheme byte, contrary to RFC
3986's ALPHA-first requirement — a schemeless credential URL whose "username" happened to be
scheme-shaped and digit-led (e.g. `9name://pass@host:9000/db`) had that digit-led prefix wrongly
preserved as if it were a real scheme. Requiring the first scheme byte be a letter closed this.
All three findings (`g8b-sanitizer-scheme-boundary`, `g8b-sanitizer-query-at-ordering`, and
CDX-01) are closed and verified — compiled, linked against the real object, and exercised against
every adversarial shape either external reviewer or this fix round constructed, including a
2,000,000-case fuzz run under ASan/UBSan. Regression tests for all three shapes live in
`tests/unit/server/test_settings_model.cpp`. Treat this sanitizer as a hand-rolled, adversarially
verified deny-list transform, not an RFC-3986-conformant parser — it has been through four design
iterations and three rounds of independent review specifically because ad hoc string surgery on
URLs is a narrow, easy-to-misjudge problem; a future editor changing this function should read its
full round-by-round history in `settings_model.cpp`'s header comment before touching it again.

## On-behalf-of assertions rejected (ADR-1005 Interim rules)

Until server-verifiable delegation ships (ADR-1005 auth follow-up), the server
accepts **no** on-behalf-of assertion on **any** ingress surface — any such
header or metadata key is **rejected, not ignored**. Five names are reserved
(case-insensitive; source of truth `server/core/src/on_behalf_guard.hpp`, and
the list only ever grows): `On-Behalf-Of`, `X-On-Behalf-Of`,
`X-Yuzu-On-Behalf-Of`, `X-Yuzu-Delegated-Operator`,
`X-Yuzu-Delegation-Artifact`.

Enforcement: **HTTP** — checked in the pre-routing chokepoint (`server.cpp`)
before auth, the allowlist, and the rate limiter, so REST, MCP, dashboard
fragments, and static files all reject with `403` + the A4 error envelope.
**Recorded exception (the only one):** the four liveness/readiness probe
paths (`/livez`, `/readyz`, `/health`, `/api/health`) are exempt — a
mesh/SSO proxy that stamps a reserved header on every request must not be
able to fail the probes and crash-loop the server (governance CH-3/UP-5); a
probe performs no identity-bearing action and nothing consumes the header on
that path. This exception is recorded in ADR-1005's exception ledger on
acceptance. **gRPC** — a single server interceptor on the
one `ServerBuilder` (`grpc_on_behalf_interceptor.hpp`) covers the agent,
management, and gateway-upstream services and every future RPC method by
construction; a call carrying a reserved metadata key is cancelled via
`ServerContext::TryCancel()` (client observes `CANCELLED`). `TryCancel()`
alone does not stop a handler from running, so it is paired with an
enforcement seam (`grpc_on_behalf_enforce.hpp`): the first statement of every
RPC handler on `AgentServiceImpl` and `GatewayUpstreamServiceImpl`
independently re-derives the same reserved-key check from
`context->client_metadata()` (not `ServerContext::IsCancelled()` — its
propagation from `TryCancel()` is not synchronous with handler dispatch,
confirmed by an end-to-end test) — the call is a true no-op on that surface,
not merely a wrong status code on an already-committed side effect. **Gateway
note:** the Erlang gateway's
own agent-facing listener reads only its known metadata keys and mints fresh
upstream calls, so a reserved key sent to the gateway is dropped rather than
rejected — tracked as a follow-up (Erlang-side reject, #1974) rather than an
exception. **Consequence for `GatewayUpstreamServiceImpl`'s own enforcement:**
today's gateway never forwards the agent's original gRPC metadata onward, so
an agent cannot smuggle a reserved key through it — the `ProxyRegister`/etc.
handlers' `onbehalf::enforce()` guard is currently defense-in-depth against
the gateway's own client, not a proven end-to-end control against relayed
agent metadata. If a future change adds metadata passthrough (e.g. for
tracing), it must re-derive the reserved-key check against the forwarded
metadata explicitly — the guard does not do this automatically. Rejections
are counted in
`yuzu_onbehalf_rejected_total{surface,event="security"}`; there is
deliberately **no audit row** (the rejection fires pre-auth, so there is no
resolved principal to attribute — the metric is the signal). **Accepted
evidence limit:** the warn log is sampled (1 per 100 rejections per surface,
a deliberate pre-rate-limiter flood defence), so the counter proves *how
many* attempts occurred while only ~1% carry a forensic log line with
timestamp/source — state this plainly if asked "can you show every attempt". When delegation
ships it will use a **server-issued artifact**, never a client-asserted
header, so these names stay rejected on client ingress permanently.

## API tokens and automation

- **API tokens** — Bearer token and `X-Yuzu-Token` header auth for automation. MCP tokens (see `docs/mcp-server.md`) use the same table with mandatory expiration (max 90 days).
- **Ownership-scoped revocation** — `DELETE /api/v1/tokens/{id}` and `DELETE /api/settings/api-tokens/{id}` both require the caller to own the token; the global `admin` role is the sole bypass. Cross-user revoke returns `404 token not found` (identical to unknown-id, to prevent enumeration). Denied attempts are recorded with `result=denied`, `detail=owner=<principal>`. See #222 and `docs/user-manual/server-admin.md` "Upgrade Notes".

### Device tokens (`DeviceTokenStore`, ADR-0052, capability 18.8) — currently dormant, docs/user-manual/rest-api.md "Device Tokens"

Standing invariant: **token presenter MUST equal token subject** — a device token's `device_id`
(the agent it is bound to) is the only identity `validate_token` checks a presenter against;
`principal_id` (the operator who issued it) is never part of that check. #823's re-registration
defence — every token bound to an agent's `device_id` is revoked when that agent re-registers,
closing the window an mTLS-disabled impersonation (#779) could otherwise exploit to replay a
stolen token — is keyed on this same `device_id` column (`revoke_by_device`, #3401). Fails closed
on a genuine revoke failure (ADR-0012 §1): the registration is refused, not merely logged.

### Service-scoped token fleet-wide confinement — durable default-deny (guardian-confinement-2298 PR 3, "the flip")

A **service-scoped API token** is bound to one IT service's agents (`session->token_scope_service` non-empty on the resolved session) — created so an integration's credential reaches only the devices tagged to its own service, not the whole fleet. A recurring gap closed across several earlier branches: a confinement check keyed on username, role, or resource ownership never actually consulted the token's *own* service-tag scope, so a service-scoped token could reach fleet-wide data or, on a few mutating surfaces, fleet-wide actions. Those earlier fixes (PR 1 role cap, PR 2 Phase 0 primitives, PR 2 gate renames) capped the blast radius and built the primitives; **this PR flips the underlying security posture from admit-by-default to deny-by-default**, closing the pattern structurally rather than instance-by-instance.

**Two authority axes compose, never supersede.** Management-group visibility (`RbacStore::authorize_list_read`, ADR-0017) and service-scope visibility are independent — a session's effective reach is the **intersection**, via `authz::meet`, never one axis overriding the other. Service scope is never left unfiltered because "some other axis already checked."

**The default-deny flip, `AuthRoutes::require_permission`'s service-scoped branch:** ITServiceOwner remains the **authority ceiling** — a service token can never exceed what that role grants — but is no longer the sole gate. A `(securable_type, operation)` pair must *also* clear the seeded-**empty** `kServiceScopeGlobalSafe` allow-list (`service_scope_policy.hpp`) to be exercised fleet-wide/unconfined; everything else `403`s by default now. Branch order is fixed and load-bearing — `elevated → engine → mcp_tier → service → RBAC-enforced-legacy → legacy` — and **must not be reordered**: the elevated branch is guarded (`is_elevated && token_scope_service.empty()`) so an elevated service-scoped session can't bypass the flip; the engine branch gets its own belt-and-braces default-deny consult (mint already rejects a non-empty `scope_service` on an engine token — this guards a corrupted row only); and the `mcp_tier` branch never `return true`s on its own — it only denies or falls through into the service branch below it, so a token carrying *both* `mcp_tier` and `scope_service` still hits the same default-deny check (verified during PR 3 review — see the commit history on this file for the specific trace). A small testonly override seam (`AuthRoutes::set_service_scope_global_safe_override_for_test`) exists because the allow-list ships empty, which would otherwise leave the admit branch of both this check and MCP's mirror (below) untestable dead code.

`AuthRoutes::require_scoped_permission`'s service branch and `AuthRoutes::require_fleet_read` both apply the same standardized `rbac_enforcement_in_effect` predicate (not raw `is_rbac_enabled()`) and the same RBAC-off hard-`403` posture for a service-scoped session — **`require_fleet_read` deliberately does NOT narrow to a tag-scoped view when RBAC is off; it denies outright**, matching `require_permission`'s posture rather than diverging from it.

**Two deliberately separate route classes (closes #3218 — do not merge these gates):** `require_list_read` is the sole gate on fleet-wide rollup routes and refuses a service-scoped session outright (no per-service slice to narrow a rollup to). `require_fleet_read` **REPLACES** `require_permission` (never pairs with it — see its own doc comment's BLOCKING falsifier) on routes migrating toward real per-request confinement (Phase 2 — see below); its own doc comment and `require_list_read`'s cross-reference each other's route class so a future reader doesn't reach for the wrong one. `require_fleet_read` never consults `kServiceScopeGlobalSafe` — a migrated route serves confined service-scoped tokens directly through the gate's own `meet(management-group, service-scope)` composition, instead of the flip's allow-list route.

**MCP's mirror: the C8 `ServiceScopeClass` chokepoint (§3c).** Every `tools/call` dispatch consults a third field on the tool's `kToolSecurity` row — `denied` (the default), `confined` (a real downstream confinement mechanism exists — `deny_fleet_wide_service_scoped`, a `scoped_perm_fn` check, a fail-closed `exec_visible` derivation, or (as of #3290) `fleet_read_fn_`/`require_fleet_read`'s `meet(management-group, service-scope)` composition), or `global_safe` (boot-validated against the same `kServiceScopeGlobalSafe` table `require_permission` reads). `confined` is **not** a claim that the tool is actually usable by a service-scoped caller — most `confined` tools still deny downstream via their own `perm_fn`/`scoped_perm_fn` under the seeded-empty allow-list; it only means the C8 layer itself doesn't short-circuit before the tool's own (pre-existing) confinement runs. `query_installed_software` and, as of #1700, `get_agent_details` are the tools so far where `confined` means real usability, not just a non-short-circuiting label — see the Phase 2 progress note below. `resources/read` bypasses C8 structurally but calls `perm_fn` directly, so it is covered by the flip the same way any REST route is.

**Explicit denies for gate-less routes (§3e).** A route that never calls `require_permission`/`require_scoped_permission`/C8 at all is untouched by the flip regardless of how the flip itself is tuned — these needed their own deny. `AuthRoutes::deny_service_scoped_session` is `server.cpp`'s shared gate for this shape (health-summary fragment, the legacy `/events` SSE stream, the instructions-list fragment, and the six result-set HTMX fragments); `ComplianceRoutes` and `WorkflowRoutes` carry their own file-local equivalents for the same reason every other route-owner class in this list does (below). A residual grep sweep of every `auth_fn`/`perm_fn` call site in `rest_api_v1.cpp` (74 sites) and `mcp_server.cpp` (3 sites) found four more real instances — three sharing one shape (`management-groups/{id}/roles` GET/POST/DELETE, plus the `POST /api/v1/tokens` service-scope minting check, all bypassing `require_permission` via a **direct** `rbac_store->check_permission` call) and the eight-route `/api/v1/result-sets*` REST family (the twin of the HTMX fragments above) — plus one **distinct, more severe, not service-scope-specific** bug in the same pass: `POST /api/v1/result-sets/from-inventory-query` had no authorization check of any kind (CWE-862), missed by an earlier fix that gated its three dispatch siblings. Full inventory, including document-only dispositions and the sweep's own accounting: `docs/security-reviews/service-scope-flip-route-inventory-2026-08.md`.

**The per-file `deny_service_scoped_*`/`deny_fleet_wide_service_scoped` helpers are now a SECOND, largely-redundant layer, not the primary defense.** For any route that also calls `require_permission`/`require_scoped_permission` (the vast majority), the flip above already denies a service-scoped token structurally — five of the seven original in-handler deny sites (`list_schedules`, `get_dex_signal_detail`, `list_dex_perf_devices`, `compare_app_perf_versions`, `list_network_devices`) are still double-denies, kept for now and scheduled for Phase 2 retirement. Two are retired: `query_installed_software`'s in the first Phase 2 migration (below), and `get_dex_group_app_perf`'s in #3290 Phase 2 bucket 1a — both were provably dead (fired after their route's own `perm_fn`), unlike the five that remain, which are live-but-redundant (their deny fires BEFORE `perm_fn`, so retiring them changes the observable response, not just deletes unreachable code — a different, more cautious backlog item). Same bucket-1a pass also retired `deny_service_scoped_schedule` (`schedule_routes.{hpp,cpp}`) entirely — its four call sites (`schedule.create`/`.list`/`.delete`/`.enable`) all fired after their route's own `require_permission`. The remaining per-file helpers (below) stay in place; they remain load-bearing **only** for routes with no other RBAC gate call at all (the §3e class above) — `EXTEND the pattern, do not fork a new copy` still applies to *that* subset. Current call sites, including this PR's additions: `deny_service_scoped_`/`deny_service_scoped_mutation_` (`guardian_routes.{hpp,cpp}`), `deny_service_scoped_` (`dex_routes.{hpp,cpp}`, `deployment_routes.{hpp,cpp}`, `preflight_routes.{hpp,cpp}`, and the new `compliance_routes.{hpp,cpp}`), `deny_service_scoped_schedule_list` + the new `deny_service_scoped_scope_estimate` (both local lambdas in `workflow_routes.cpp`), the shared `deny_fleet_wide_service_scoped` lambda in `rest_api_v1.cpp` (now covering the result-set REST family too) and `mcp_server.cpp`, the new `AuthRoutes::deny_service_scoped_session` (`server.cpp`'s shared gate for its own gate-less routes), plus inline checks in `device_routes.cpp` / `network_routes.cpp` / `inventory_routes.cpp` / `tar_tree_routes.cpp`.

**Phase 2 progress (#3290).** The first migration landed: `GET /api/v1/inventory/software` + its MCP twin `query_installed_software` are now on `require_fleet_read` — both surfaces' `deny_fleet_wide_service_scoped`/blanket-deny call sites are retired for this tool pair (the REST call was already provably dead, firing after `perm_fn`; the MCP call was live and is now gone). `require_fleet_read` itself gained the elevated/engine/mcp_tier caller-class branches it was missing at Phase 0 (mirroring `require_list_read`'s ladder — see its own doc comment). Prioritization for this and future migrations is **documented reasoning, not the metric** — no production fleet exists yet, so `yuzu_auth_service_scope_default_denied_total` has no real traffic to rank by; the criterion-1 substitute and the ranked backlog live in `docs/security-reviews/service-scope-phase2-migrations-2026-08.md`. The §3d `authorize_list_read` supersede→intersect migration (below) is a separate, not-yet-started stream.

**Second migration (#1712/#1700, this ADR-0017 continuation).** Closes the "World A" gap this ADR flagged (`Fail-closed list-read gate (HIGH)` finding) for three readers that previously had NO per-agent filter at all: dashboard `/fragments/results`, the workflow executions-drawer detail route (its responses section AND its per-agent status grid/table — both read per-agent data, from `ResponseStore` and `ExecutionTracker` respectively, and the route's gate migration admits the same newly-in-scope caller to both), and MCP `get_agent_details` — all three routes migrated onto `require_fleet_read` as their sole gate, replacing `perm_fn`/`perm_fn_`/`tier_allows`+`perm_fn` outright. `get_agent_details` is reclassified from `ServiceScopeClass::denied` to `confined` (`kToolSecurityRows`, `mcp_server.cpp`) since it now has this same real confinement mechanism; a correctly-confined service-scoped token gets a real filtered/404-collapsed answer instead of a blanket 403.

Out of scope for this migration, flagged not fixed (none newly reachable by this migration's admission change — unlike the status grid above, these were already reachable by their current caller class before #1712, so leaving them unmigrated does not widen anything): MCP `list_agents` (same unscoped-fleet-read shape `get_agent_details` had), the dashboard results workflow's sidecar routes — `/fragments/results/filter-bar`, `/fragments/create-group-form`, and `POST /api/dashboard/group-from-results` (all still on flat `perm_fn_`, reading unscoped `ResponseStore` facet queries — tracked as #3489, #3525 tracked the same finding and was closed as its duplicate; see ADR-0017's "In scope" Responses bullet for the detailed reachability analysis distinguishing `filter-bar`'s latent-only exposure from `group-from-results`' real, pre-existing `ManagementGroup:Write`-vs-`Response:Read` privilege-crossing risk — this same risk is why the dashboard's "Create Group from N Agents" button is now withheld from a confined caller entirely, #1712 hardening round), REST `GET /api/v1/execution-statistics/agents` (same flat `perm_fn(Execution,Read)` gate, returns per-agent execution stats with no confinement — found by Gate 4 consistency-auditor's re-derivation of the sibling-handler check on this PR's exact `(securable, operation)` pairs, tracked as #3526; the workflow executions LIST fragment `/fragments/executions` carries the same data class at lower severity, noted in the same issue). `/sse/executions/{id}` and REST `/api/v1/events` (formerly tracked here as #3699) are now migrated — see the Third migration paragraph below.

**Third migration (#1634, this ADR-0017 continuation).** Closes the systemic gap #1634 tracked since 2026-06-23: the legacy REST `/api/responses/{id}/aggregate`/`/export`/catch-all-list routes (`server.cpp`), MCP `query_responses`/`aggregate_responses`, and REST `GET /api/v1/executions/{id}/visualization` all carried a per-row post-filter (`response_agent_in_scope`/`response_scope_fn`) that sat BEHIND a still-flat global gate — the exact "inert filter" shape #1711/#1550 shipped and this ADR names as the systemic defect. All five migrated onto `require_fleet_read`/`fleet_read_fn_` as their sole gate; the response list/export routes and `query_responses` additionally push the resolved visible-agent set into `ResponseStore::query`/`query_by_execution` as SQL `agent_id = ANY(...)` **before** `LIMIT`/`OFFSET` (a new optional scope parameter, ADR-0017 INV-3) rather than post-filtering a capped/paginated read — the INV-3-compliant fix an adversarial review (Kimi + Codex) found the first migration pass had missed. `GET /api/v1/executions/{id}` (REST final-state lookup), `GET /api/v1/events` (REST SSE), `GET /sse/executions/{id}` (dashboard SSE — closing the #3699 gap above), and MCP `get_execution_status`/`list_executions` also migrated: all four collapse an invisible execution to the same 404/not-found shape a genuinely nonexistent one gets (no existence oracle), and a confined non-dispatcher's view is a redacted projection (recomputed per-agent counts from only the visible agent-status rows, `scope_expression`/`parameter_values` replaced with a fixed placeholder) — dispatcher ownership admits VISIBILITY only (avoids a false 404 on a just-dispatched execution with zero responses yet) and never bypasses this projection, a distinction the same adversarial-review round caught the first attempt getting wrong. `list_executions` has a weaker mechanism than the others — execution rows carry no single `agent_id` to filter by, so a confined caller is restricted to `dispatched_by = session->username` (`ExecutionQuery::dispatched_by`) rather than a real visible-agent intersection. As of the PR #3793 review round, `agents_targeted`/`agents_responded` on this route ARE now projected (a batched, non-N+1 `get_agent_statuses_for_executions` call) the same way `get_execution_status` projects them, closing that specific gap; the confinement AXIS itself remains own-dispatches-only, not a real visible-agent intersection. **Disclosure gap (found in the same review round, not fixed):** `dispatched_by = session->username` is scoped to the minting principal, not intersected against a service-scoped token's own service-tag scope — an admitted service token sees its minting user's full dispatch-history metadata (status/timing/lineage, no agent identities), not narrowed to its own service. Recorded here as disclosed, not fixed. The two SSE routes share one event projector (`execution_event_scope.hpp`): `agent-transition` events are filtered by `agent_id`, `execution-progress` is dropped for confined subscribers (execution-wide counts, no `agent_id`), and `execution-completed` is sanitized (real `status` field preserved, counts stripped) rather than dropped, so the client still closes its stream. `query_responses`/`aggregate_responses`/`get_execution_status`/`list_executions` are reclassified `ServiceScopeClass::confined` (`kToolSecurityRows`), matching the real `fleet_read_fn_` mechanism they now have.

**Fourth migration (#3789, this ADR-0017 continuation).** Closes the gap #1634's own Gate 2 review found and deliberately deferred: the legacy pre-v1 `/api/executions` (list), `/{id}` (detail), `/{id}/summary`, `/{id}/agents`, `/{id}/children`, `POST /{id}/rerun`, and `POST /{id}/cancel` routes (`execution_routes.cpp` as of #2542 PR-7, extracted from `server.cpp`) carried NO management-group confinement at all — a bare `require_permission(Execution, Read/Execute)`, unlike every other execution-reading surface migrated above. All five GET routes now gate on `require_fleet_read(..., "Read")`, mirroring the `GET /api/v1/executions/{id}` shape: an invisible or nonexistent execution collapses to one 404 (no oracle) for EVERY caller — but the audit row is written only when the caller's scope was actually engaged (`gate.scope`). A confined caller failing this check writes `execution.read`/`denied`; an unconfined caller's genuinely-nonexistent id is ordinary "not found", not a confinement decision, and writes no row at all — auditing it as `denied` would have inflated the CC7.2 denial-rate metric with routine 404 traffic (compliance-officer, #3789 Gate 6 finding F2, corrected before merge). The caller-visible 404 response is identical either way; only the server-side audit trail distinguishes the two. A confined view redacts `scope_expression`/`parameter_values` and recomputes the four agent counts from only the in-scope, terminal-status rows. `/agents` — the worst pre-migration leak, returning raw agent identities and `error_detail` fleet-wide — filters its row list to `authz::in_scope`. `/children` does NOT inherit the detail route's "keep lineage truthful" precedent: a visible parent does not authorize enumerating separate child execution records, so each child is checked against the same visibility predicate independently. (#2146 A2-R1 gave `/children` a REST v1 twin, `GET /api/v1/executions/{id}/children`, and an MCP twin, `get_execution_children` - both reuse this exact confinement logic via `execution_scope_rules.hpp`, never re-derived, and share a new `execution_child_row_json` builder with the legacy route.) The LIST route goes further than every sibling migrated above (including `list_executions`, next paragraph): rather than a post-fetch drop or an own-dispatches-only filter, the confinement predicate is pushed into the `WHERE` clause itself, before `LIMIT` (ADR-0017 INV-3) — `dispatched_by = $owner OR EXISTS (SELECT 1 FROM agent_exec_status WHERE agent_id = ANY($visible))`, one statement, no N+1 (`ExecutionTracker::query_executions_checked`'s new `ExecutionScope` parameter). The owner disjunct is load-bearing, not cosmetic: `agent_exec_status` rows are written only on response arrival, so an agent-membership-only predicate would make a caller's own just-dispatched execution invisible to them until the first agent replies.

The two mutating routes (`rerun`/`cancel`) keep `require_permission(Execution, Execute)` ahead of the fleet gate — `require_fleet_read` structurally rejects any operation but `Read` (its legacy-open `AdmitAll` branch has no MCP approval-ticket check, so a mutation must never reach it) — then additionally take `require_fleet_read(..., "Read")` purely for scope. Mutation admission is stricter than read visibility: an adversarial review (external model, Sol/gpt-5.6-sol) found that "every EXISTING agent-status row is in scope" is a false-admission path, because those rows are response-arrival-seeded — an execution targeting agents A and B can have only A's row while B, still pending, might be out of scope. The rule implemented instead: zero status rows (the just-dispatched window) admits ONLY the dispatcher; one or more rows requires the row count to equal `agents_targeted` (a complete ledger) AND every row's agent to be in scope — dispatcher ownership is not a bypass once rows exist. Nonexistent, zero-visible, partial-visibility, and incomplete-ledger all collapse to the identical 404 + non-distinguishing audit detail (a distinct status for "partial visibility" would itself be a hidden-cohort disclosure). `mark_cancelled`'s pre-existing false-success-on-nonexistent-id behavior (an `UPDATE` matching zero rows still reports `PGRES_COMMAND_OK`) is fixed as a side effect: an explicit existence check now runs before every cancel attempt, for confined and unconfined callers alike.

New degrade-distinguishable tracker accessors (`get_execution_checked`, `get_children_checked`, `get_agent_statuses_for_executions_checked`, `query_executions_checked`) fail closed (503, `retry_after_ms`) on a transient read failure rather than collapsing it into "absent"/"empty" the way their pre-#3789 plain twins do — required because these five routes now write `denied` audit rows and 404 responses off these results, which the old degrade-collapsing methods cannot safely feed. `execution_scope_rules.hpp`'s `execution_visible` and `admit_confined_mutation` deliberately scan every status row with no early exit, even after a match is found — an early return makes wall-clock time a function of WHERE in the row list the first in-scope agent falls, a residual timing side-channel on the admit path (cpp-expert, #3789 Gate 3). **Behavior changes accepted, not oversights:** `/summary`'s nonsense zero-filled-200 response for an unknown id is now a 404 for every caller, confined or not; `/agents` and `/children` similarly now 404 on an unknown id instead of an empty-array 200; a caller holding `Execution:Execute` but not `Execution:Read` can no longer rerun/cancel (the mutation routes need both); gate-failure responses on a degraded RBAC/management-group store are now 503 (`retry_after_ms`) where the old flat gate failed closed 403. Coverage: `tests/unit/server/test_legacy_executions_scope_authz.cpp` (pure-function unit tests for the shared `execution_scope_rules.hpp` predicates, a real-rig PG confinement test, and per-route source tripwires) plus new `[pg][execution_tracker]` cases in `test_execution_tracker.cpp` for the SQL pushdown and the new checked accessors.

Deferred, not fixed here (flagged for a follow-up, not swept into #3789): MCP `list_executions` still uses the weaker own-dispatches-only axis this migration's LIST route improves on — worth backporting the same SQL-pushdown shape; `workflow_routes.cpp` still calls the degrade-collapsing plain `get_agent_statuses` at one site.

Still open after this migration (unrelated files, tracked separately, not swept into #1634): REST `GET /api/v1/execution-statistics/agents` + the workflow executions LIST fragment (#3526); three reliability gaps on the workflow detail route — legacy-fallback starvation, untested store-degrade banner, `get_execution` error-vs-absent ambiguity (#3527); `/fragments/results` has no audit trail at all (#3528); no `[pg]` end-to-end test proves the real `require_fleet_read`/`RbacStore`/`ManagementGroupStore` composition for the #1712 call sites (#3529). **Staleness of an already-open SSE stream (compliance/sre finding, this round):** `require_fleet_read`/`fleet_read_fn` is evaluated once, at subscribe time — neither `/sse/executions/{id}` nor `/api/v1/events` re-checks the caller's management-group scope for the life of the connection, so a scope narrowed (or a session revoked) mid-stream via `invalidate_session` does not disconnect an already-open subscriber; `invalidate_session` (`auth.cpp`) only erases the session record, it never reaches an open httplib connection, and no lever exists today to force-disconnect one live stream short of a full server restart. This is the same one-time-admission shape `require_fleet_read`'s non-streaming callers already have (a scope change doesn't retroactively alter an in-flight response either), but a held-open stream widens the exposure window from one request to as long as the tab/worker stays connected. Accepted for this migration (real-time revocation is a separate, larger change to the SSE subsystem, not a #1634 scope-pushdown fix); worth a security runbook line if this becomes an operational concern before it is addressed.

`GET`/`PUT`/`DELETE /api/agents/:id/properties[/:key]` — found in this same governance re-review, bare `require_permission(Infrastructure,Read/Write)` with no per-agent scope filter at all (including a WRITE path) — is now **fixed** (#3700): all three routes migrated to `require_scoped_permission("Infrastructure", "Read"/"Write", agent_id)`, the same per-target gate the Tag routes (`/api/tags/set`, `/api/tags/delete`) use. RBAC-off behavior is unchanged, since `Infrastructure` is not in `kTopologyFloor`. Coverage: `tests/unit/server/test_agent_properties_scope_authz.cpp`.

**Fifth migration (#4031 hardening round, adversarial review of the branch before push).** `GET /api/v1/enrollment/pending-agents` — a new REST v1 route, not a legacy one — was gated on bare `require_permission(Enrollment, Read)` (`perm_fn`) in an earlier revision of this branch, the exact anti-pattern this ADR's Consequences section names as forbidden for a new list/fan-out read of per-agent data: `pending_agent_row_json` rows carry a genuine `agent_id` plus hostname/os/arch/agent_version (`auth::PendingAgent`). Migrated onto `require_fleet_read("Enrollment", "Read")` as the route's sole gate, filtering with `authz::in_scope(gate.scope, agent.agent_id)` — the same idiom `GET /api/v1/inventory/software` uses. The defect this closed was **under-admission, not disclosure**: `require_permission`'s ordinary RBAC branch resolves authority via `RbacStore::collect_roles` (direct/group-role grants only) and never consults `ManagementGroupStore`, so a caller holding *only* a management-group-scoped `Enrollment:Read` grant — a combination the product's own docs (`docs/user-manual/rbac.md`) instruct operators to configure — was denied outright (403) rather than admitted with a real, correctly confined result. That result is typically empty under the intended enrollment workflow (a pending/not-yet-approved agent normally has no management-group membership yet — group assignment follows approval), but this is **not enforced by the data model**: `management_group_members.agent_id` carries no enrollment/agent-registry foreign key, and `POST /api/v1/management-groups/{id}/members` accepts any non-empty caller-supplied id with no existence check, so a pre-assigned membership row yields a non-empty, correctly-confined result via the same filter — never a widening. No live exploit path existed under the default seed (`Enrollment:Read` grants to Administrator only, resolved via `check_permission`'s global-grant branch regardless of which primitive gates the route), which is why this passed the branch's 7-pass, multi-agent governance run before an adversarial review of the branch caught it.

This migration also closed a **second, load-bearing gap it exposed**: `Enrollment:Read` is the first `kTopologyFloor`-floored securable ever routed through `require_fleet_read`. Unlike `require_permission`'s legacy (RBAC-off) branch, `require_fleet_read`'s subordinate primitive, `RbacStore::authorize_list_read`, has no floor concept of its own by design (a data-layer primitive must not depend on `Session`) — its own legacy-open branch returns `AdmitAll` unconditionally once RBAC enforcement is off, with no way to distinguish an admin session from any other authenticated one. Every prior `require_fleet_read` caller (`Inventory`/`Execution`/`Response`/`Schedule:Read`) is unfloored, so this gap was latent, not exercised, until now — and `require_list_read`'s own doc comment (`auth_routes.hpp`) had already named the identical risk as something "a FUTURE floored securable... must re-apply explicitly." Fixed inside `require_fleet_read` itself (`authz_gates.cpp`), not as a route-level bolt-on: a pre-check mirroring `require_permission`'s own legacy-branch floor logic (same audit-reason prefix `"topology floor: "`, same `yuzu_auth_topology_floor_denied_total` counter) now runs before the management-group axis whenever RBAC enforcement is off, denying a non-admin session on any floored pair. Coverage: `tests/unit/server/test_authz_gates.cpp` (RBAC-off + floored securable, non-admin-denied and admin-admitted); `tests/unit/server/test_enrollment_directory_routes.cpp` (route-level scope-filtering, including the admitted-empty-not-403 case that is the whole point of the fix).

**Consequences accepted for v1 (recorded, not oversights):** fleet-wide aggregates with no per-agent identity (e.g. `get_dex_perf_fleet`, `get_network_fleet`) stay `denied` at C8 — a `confined` label with no real downstream mechanism would be an unenforced claim; re-admission is a Phase 2 `kServiceScopeGlobalSafe` entry with security-guardian sign-off, not an inferred-safe classification during a routine change. Service-tag writes (whoever sets an agent's `service` tag moves scope) are hardened as of #3289 — a service-scoped session is denied, value-blind, before writing/deleting the `service` key at every REST/legacy-dashboard/MCP tag-mutation site, and the agent's own gRPC `Register` sync path no longer accepts an agent-claimed `service` value at all; plain `Tag:Write`/`Tag:Delete` remains sufficient for non-service-scoped (already fleet-scoped) holders. A related but distinct gap — a live agent's in-memory self-reported tags shadowing the store during scope-DSL evaluation — was tracked separately as #3295 and is now closed: `evaluate_scope`'s `tag:<key>` resolver is store-first (a TagStore row of any source wins over a connected agent's live claim; the session value answers only when the store has no row at all), and `register_agent` drops an agent-claimed `service` key from the session at ingest. No cached derived confinement sets. Dispatch's supersede→intersect migration (§3d, four `authorize_list_read` callers) is deferred, not part of this PR. **Bootstrap note:** an empty-cohort service token cannot bootstrap its own scope via any route — and since #3289, neither can an agent via its own Register sync; onboarding a brand-new service still needs an interactive/unscoped path; see `docs/user-manual/authentication.md`.

**Known-but-unfixed instances predating this PR** were tracked as GitHub issues #3123 (device discovery), #3124 (response/execution data), #3125 (inventory data) — this PR proposes closing them as fixed-by-flip (every instance they list reaches `require_permission`/`require_scoped_permission`, which now denies by default), pending review; per the issue-standard, automation does not close a `security`-labelled issue unilaterally. Check each issue's current body before citing an instance count from it historically — issues were edited down as fixes landed elsewhere.

**ADR:** `docs/adr/1006-service-scope-default-deny.md` records the design-of-record — the two-axis composition, the branch-order rule and the two rejected hoists, the two enforcement shapes behind one composer, why `RbacStore` stays single-axis, and the four decisions above (RBAC-off hard-`403`, the two-gate split, explicit-deny for §3e, ADR-in-same-PR).

## Engine principals & delegation (ADR-1005 — design)

**Stream liveness is cached; authorization is not** (#2367). The per-tick
re-check that keeps a held-open MCP/SSE stream alive reads the engine principal
through `EnginePrincipalStore::get_for_auth_revalidate` — a 15 s, Active-only
liveness cache with exactly one caller, the private
`AuthRoutes::engine_credential_state`. Every *fresh* authorization decision —
session synthesis, and the REST/MCP on-behalf-of target checks — still calls the
authoritative `get_for_auth` and reads through to Postgres on every call, so a
revoked principal cannot obtain a new session or a new delegation at any point.
A cached answer is reported as `auth::CredentialCheck::kValidStale` rather than
`kValid`, which is what stops a stream from riding the cache and then collecting
a full fresh outage-grace window on top of it. See ADR-0031 Consequences for the
invalidation and bounding rules, and `docs/mcp-server.md` "Revocation." for the
resulting latency bounds.

- **Design doc:** `docs/auth-engine-principals-design.md` (execution-plan item
  2b, feeds Phases 4–5). **Shipped (PR 4.1–4.3):** the identity store + RBAC
  resolution (PR 4.1–4.2) and the operator-facing REST + MCP + admin-console
  lifecycle surface (PR 4.3) below are live. Delegation (Phase 5, RFC 8693
  token exchange) remains design-only — not yet implemented.
- Third principal class (`engine`) for use-case-engine hosts: dedicated
  born-on-Postgres `EnginePrincipalStore` (named human owner, justification,
  required `internal`/`external` classification, soft-retained after revoke),
  reserved `engine:` id namespace, per-module granularity.
- Token sessions branch on a persisted `ApiToken.principal_kind`
  (`human`|`engine`) — an engine token attributes to the engine principal
  itself (`auth_source="engine_token"`), never to its creating human. Engine
  tokens are referentially checked against `EnginePrincipalStore` at mint
  time, always `mcp_tier=readonly`, and always carry a ≤90-day expiry.
- **Session-authorization semantics — RBAC-only, no fallback (PR 4.2 fix
  round).** `AuthRoutes::require_permission`/`require_scoped_permission`/
  `require_list_read` (the last is the ADR-0017 admit-then-filter list-read
  gate, #3038 — see the Authentication/RBAC row in
  `.claude/routed-concerns-access-control.md`) all
  branch on `session->principal_kind == "engine"` **before** falling through
  to the legacy pre-RBAC path or the MCP-tier/service-scoped resolution used
  for human and agent sessions. An engine session's authority is resolved
  **exclusively** against `RbacStore`:
  - `rbac_store_` unavailable — null/unopened, or a runtime degrade of the
    PostgreSQL `rbac_store` substrate (pool-acquire timeout / query error,
    ADR-0041) — → **`503`** (cannot evaluate authority; retryable, never a
    silent allow — the deny-on-degrade contract).
  - RBAC disabled, or no matching `(principal="engine:<slug>", role, scope)`
    grant → **`403`**.
  - A matching grant → allowed.

  This closes the gap where an engine credential — before this fix — inherited
  fleet-wide `Read` the moment RBAC was off (the historical default), via the
  same legacy fallback human sessions still use. Engine principals now get
  **no** legacy fallback and **no** service-scoped fallback under any
  circumstance; the only path to authority is an explicit assignment. This is
  the concrete mechanism behind design §4.2's promise: *"An engine principal
  with no assignments can do nothing."*
- **Audit attribution.** `AuthRoutes::make_audit_event` re-stamps
  `principal_class="engine"` from the resolved session's `principal_kind`
  after the generic (credential-presentation-based) classification runs —
  an engine principal's bearer-token requests previously mislabelled as
  `"agent"` in the audit trail (design §6 / `adr-1005-execution-plan.md`
  Decision 9) now attribute truthfully.
- **Reserved-namespace fail-closed guards.** `find_local_groups_with_prefix`
  returns `std::nullopt` (not an engaged-empty optional) when the RBAC store
  can't be read, and the `server.cpp` boot-time `engine:`-collision preflight
  requires `rbac_store_->is_open()` before trusting a clean scan — a degraded
  or unreachable `rbac_store` (PostgreSQL substrate, ADR-0041) now fails the
  boot closed rather than booting "clean" past a reserved-namespace collision
  it could not actually see. `upsert_sso_identity`
  separately rejects any `engine:`-prefixed write at the SSO identity-sync
  surface (design §3.3), sharing the `kEngineReservedPrefix` constant with the
  store's own create-path guard.
- **Fleet-wide role-assignment authoring (PR 4.2 deliverable, design §4.1).**
  `GET`/`POST`/`DELETE /api/v1/engine-principals/{id}/roles` (+ MCP twins
  `list_engine_roles`/`assign_engine_role`/`unassign_engine_role`) are the
  authoring surface that makes `RbacStore::assign_role(principal_type="engine")`
  reachable in production — see `docs/user-manual/rest-api.md` "Engine
  Principals" for the full contract. Mutations require admin + MFA step-up;
  admin/built-in/wildcard role targets are rejected as `4xx`, never silently
  narrowed or a `500` (design §4.2 "no admin, ever").
- Authorization model: scoped role assignments `(principal, role, scope)`
  for **all** principal classes, evaluated permissions ∩ scope through
  ADR-0017's `authorize_list_read` chokepoint for list/fan-out reads and
  the per-device scoped-permission path for single-target operations
  (ADR-0017 PR-A is a named prerequisite, its charter to be amended or
  extended for the `engine` principal type). Engine principals are
  default-deny, structurally barred from `admin`. **Today (PR 4.2) grants are
  fleet-wide only** — scoped (management-group) engine assignment is rejected
  pending that Phase-5 chokepoint.
- Delegation (Phase 5): RFC 8693 token-exchange shape — server-issued
  opaque, audience-bound, short-TTL artifact; effective authority = engine
  principal's assignments ∩ operator's assignments ∩ operator's scope
  (decision-level intersection — a delegation only ever narrows);
  self-asserted delegation stays rejected permanently.
- Engine credentials: 90-day ceiling, overlap-pair rotation (≤2 active),
  minted **credentials** are MCP tier hard-locked `readonly` for v1. This is
  distinct from the tier a *human/automation caller* needs to invoke the
  lifecycle surface itself — see "Lifecycle surface (PR 4.3)" below.


#### Catastrophic invariants (routed-concern detail)

These are the clauses `.claude/routed-concerns-access-control.md` routes here. A service-scoped API
token (`session->token_scope_service` non-empty) **must never reach fleet-wide data or actions
unfiltered.**

1. **`AuthRoutes::require_permission`'s service-scoped branch is the PRIMARY closure mechanism.**
   ITServiceOwner is the authority ceiling only; a `(securable_type, operation)` pair must ALSO clear
   the seeded-EMPTY `kServiceScopeGlobalSafe` allow-list (`service_scope_policy.hpp`) or it 403s.
   **Widening that allow-list is a security decision** — security-guardian sign-off plus a
   policy-table entry, never inferred from one route being changed.

2. **Branch order in `require_permission`/`require_scoped_permission` is fixed — `elevated → engine →
   mcp_tier → service → RBAC-enforced → legacy` — never reorder it.** The elevated branch is guarded
   (`is_elevated && token_scope_service.empty()`); the `mcp_tier` branch must never `return true` on
   its own (deny, or fall through into the service branch only). A tier-admit that bypasses the
   service check reopens the flip on every route at once.

3. **MCP's mirror is C8's `ServiceScopeClass`** — `denied` by default; `confined` requires a REAL
   downstream confinement mechanism (a label with none is the same lie this concern exists to
   prevent); `global_safe` boot-validates against the same allow-list.

4. **A route reaching agent/fleet data via NO `require_permission`/`require_scoped_permission`/C8 call
   at all is untouched by the flip and needs its OWN explicit deny — EXTEND an existing per-file
   helper, never fork a new one.** The helpers: `AuthRoutes::deny_service_scoped_session`
   (`server.cpp`), `ComplianceRoutes::deny_service_scoped_`, `WorkflowRoutes`' local
   `deny_service_scoped_schedule_list`/`deny_service_scoped_scope_estimate`,
   `deny_service_scoped_`/`deny_service_scoped_mutation_` (`guardian_routes.*`), `deny_service_scoped_`
   (`dex_routes.*`, `deployment_routes.*`, `preflight_routes.*`), the shared
   `deny_fleet_wide_service_scoped` lambda (`rest_api_v1.cpp`, `mcp_server.cpp`), plus inline checks in
   `device_routes.cpp`/`network_routes.cpp`/`inventory_routes.cpp`/`tar_tree_routes.cpp`.

   These per-file helpers are now a SECOND, largely-redundant layer for routes the flip already
   covers — scheduled for Phase 2 retirement, not removed here. `schedule_routes.*`'s
   `deny_service_scoped_schedule` was the first FULLY retired (#3290 Phase 2 bucket 1a, 2026-08-21):
   all four of its call sites were provably dead (they fired *after* `require_permission`), unlike the
   still-live-but-redundant helpers above, which fire *before* their route's gate and so are a
   different, more cautious retirement class.

5. **A blanket deny's A4 error body MUST NOT name a `.permission` the caller does not currently hold**
   if holding it would not, by itself, admit the caller — omit the field rather than claim a false
   self-remediation grant. (Found live in PR 3's own `require_permission`/`require_scoped_permission`
   service branches, and fixed in the same round that wrote the clause.)

   This MUST binds: every branch inside the service-scoped path of
   `require_permission`/`require_scoped_permission`; every NEW gate-less-route deny added after this
   clause was written; and every site in (4) already migrated to the no-`.permission` `a4_denial`
   shape — as of that round: `AuthRoutes::deny_service_scoped_session`,
   `ComplianceRoutes::deny_service_scoped_`, `WorkflowRoutes`'
   `deny_service_scoped_schedule_list`/`deny_service_scoped_scope_estimate`,
   `GuardianRoutes::deny_service_scoped_`/`deny_service_scoped_mutation_`,
   `DexRoutes::deny_service_scoped_`, `DeploymentRoutes::deny_service_scoped_`. #3167 closed the
   remainder — `PreflightRoutes::deny_service_scoped_`'s 3 call sites plus its separate inline deny on
   the MUTATING `POST /fragments/auto/run`, `schedule_routes.*`'s `deny_service_scoped_schedule` and
   its 4 call sites (each already passed a correctly-typed permission per operation — the defect was
   unactionability, not a wrong permission TYPE, a claim the routed row previously made in error), and
   the inline checks in `device_routes.cpp`/`network_routes.cpp`/`inventory_routes.cpp` (×2)/
   `tar_tree_routes.cpp` (×2).

   **One known, tracked exception, not retroactively bound:** pre-existing
   `deny_fleet_wide_service_scoped` call sites that fire AFTER the route's own `perm_fn` already
   confirmed the caller holds that exact grant, where `.permission` names a grant the caller
   demonstrably already has — a different, informational claim. `GET /api/v1/inventory/software` no
   longer illustrates this (#3290 retired its after-gate deny entirely, migrating the route onto
   `require_fleet_read`). **NO LIVE EXAMPLE CURRENTLY EXISTS:** an exhaustive check of every remaining
   `deny_fleet_wide_service_scoped` call site — all 20 in `rest_api_v1.cpp` and, as of #3290 Phase 2
   bucket 1a, all 5 remaining in `mcp_server.cpp` — found every REST site fires BEFORE its route's
   `perm_fn`, not after (see `docs/security-reviews/service-scope-phase2-migrations-2026-08.md`'s
   migration checklist). `deny_service_scoped_schedule` (previously 4 sites, `permission` param
   defaulting empty) and the one MCP site whose surrounding `perm_fn` fired first
   (`get_dex_group_app_perf`) are no longer part of this count at all — both were retired outright in
   bucket 1a as provably dead, not merely candidates that failed to match the exception shape.

   Do not read "no current instance" as "no longer needed": the next route to add an after-gate
   `deny_fleet_wide_service_scoped` call with a non-empty `.permission` becomes the example, and this
   clause still governs it. **A gate-less-route deny not yet audited against this clause is NOT
   assumed compliant.**

6. **The tag being read to decide admission must never be mutable by that same admission (#3289).**
   `require_scoped_permission`'s service branch reads the target agent's `service` tag to decide
   whether to admit a `Tag:Write`/`Tag:Delete` — so without a separate guard it would authorize the
   very write that changes that tag, letting a service-scoped token move an agent out of (or a
   different agent into) its own confinement.

   **EXTEND `authz::service_scope_may_mutate_tag_key`** (`service_scope_policy.hpp`) at every
   tag-mutation site — REST v1 PUT/DELETE `/api/v1/tags`, the legacy dashboard
   `/api/tags/set`/`/api/tags/delete` (via `AuthRoutes::deny_service_scoped_service_tag_mutation`), and
   MCP `set_tag`/`delete_tag` — checked BEFORE the scoped gate, **value-blind** (no read-compare
   TOCTOU: even a no-op rewrite of the token's own current value is denied).

   The agent's own gRPC `Register`→`TagStore::sync_agent_tags` path is the same class of gap on a
   DIFFERENT axis (no gate at all, not a TOCTOU) — `authz::is_service_tag_key` is filtered there too,
   silently dropping an agent-claimed `service` value rather than refusing the whole sync (a
   pre-existing agent-authored row self-heals on the next sync).

   A live agent's in-memory self-reported tags shadowing the store during scope-DSL evaluation
   (`agent_registry.cpp`) was a THIRD, distinct mechanism this clause did not cover, tracked separately
   as #3295 — now CLOSED: the `tag:<key>` resolver is store-first (a TagStore row of any source wins
   over a connected agent's live claim; the session value answers only when the store has no row at
   all), and `register_agent` drops an agent-claimed `service` key from the session at ingest,
   mirroring this clause's own store-side purge.

Full design, decisions, and the closed route inventory: `docs/adr/1006-service-scope-default-deny.md`
and `docs/security-reviews/service-scope-flip-route-inventory-2026-08.md`.
### Lifecycle surface (PR 4.3)

Operator-facing CRUD for engine-principal identities and their credentials —
full reference: `docs/user-manual/rest-api.md` "Engine Principals" section,
`docs/user-manual/mcp.md` tools 55–63 (52–54 are the role-assignment tools), `docs/user-manual/engine-principals.md`
walkthrough.

- **Surfaces:** 9 REST routes under `/api/v1/engine-principals` (create, list,
  get, delete, credential mint/rotate/confirm, transfer-owner, and the
  `GET /audit/no-admin` auditor), 9 MCP twin tools, and an "Engine Principals"
  section in the Settings admin console (create form, list, mint/rotate buttons
  behind a one-time secret-reveal panel, revoked rows showing `superseded_by` +
  revoke detail).
- **REST gating:** every *mutating* route is human-admin + MFA-step-up gated;
  the three read routes are human-admin + RBAC gated but not step-up gated —
  list and get on `EnginePrincipal:Read` (moved off the over-broad
  `Security:Read` by #2376, see "The authorization topology floor" above), and
  `audit/no-admin` on `AuditLog:Read`. Every route —
  reads included — structurally denies a caller whose own session is
  engine-classed (`principal_kind="engine"` / `auth_source="engine_token"`, the
  §9 belt): an engine principal can never read or mutate its own or another
  engine principal's lifecycle surface.
- **MCP gating:** the 6 mutating tools all gate on `Security:Write`
  (`mint_engine_credential`/`rotate_engine_credential` included — aligned with
  their REST twins, not `Security:Execute`), require the `supervised` tier,
  and are maker-checker approval-gated (approver ≠ submitter), same posture
  as every other destructive MCP op. The 3 read tools (`list_engine_principals`,
  `get_engine_principal`, `audit_engine_no_admin`) are plain `Read`-class RBAC
  checks available on every MCP tier including `readonly`, and are not
  approval-gated. **All 9 tools**, mutating and read alike, carry the same §9
  engine-session denial belt as their REST twins — an engine-classed MCP
  caller is denied on every one of them, including the three reads.
- **Overlap-pair credential rotation** (design §7): at most 2 active
  credentials per principal, a 24-hour minimum overlap window (rejected
  outright, never truncated, below the floor), a ~120-second grace window
  that re-serves the same successor secret on a same-caller retry, and a
  60-second background sweep that auto-revokes the predecessor once its
  overlap window elapses — **unless the successor was never presented at
  all** (governance UP-5): a dropped/lost successor secret must never leave
  the principal at zero usable credentials, so that predecessor is left
  active and the operational, non-security `successor_unused` warning is
  raised again past the window's own end. Note the three signals do NOT
  share a cadence (`rotation_warn_dedup.hpp`): the **log line** repeats
  every tick for as long as the pair stays stuck, while the **audit row and
  its metric** fire once per pair per state — once pre-elapse, once more on
  crossing into elapsed. The row records that the decline happened; an
  un-throttled row would be ~1440/day per stuck pair into the audit store,
  which is itself a retention hazard. Do not build a stuck-pair alert on
  `increase(...{reason="successor_unused"})` — it will fire once and never
  again; the alertable signal is tracked in #2969. The sweep's per-tick
  auto-revoke is bounded
  (`kMaxAutoRevokesPerTick`) so a clock jump degrades to a multi-tick drain
  rather than a fleet-wide cutover in one tick.
  **Confirm replay classification (#2404):**
  a `confirm` replayed after its own rotation already resolved returns a
  *terminal* conflict (REST `409` / MCP `kInvalidParams`), never a retryable
  `503`, so an agentic client honouring the tool's `idempotentHint` stops
  instead of retrying a permanently-failing call; the decision is made by a
  positive-read state classifier (`rotation_confirm_state.hpp`) that keeps
  `success` a one-time effect. The confirm is never a silent success no-op:
  the initiator grace binding is evicted post-confirm, so a success answer
  would attest without verifying initiation.
- **Confirm-identity binding survives a server restart (#2961).** The
  maker-checker check that only the operator who called `rotate` may
  `confirm` used to be resolvable **only** from the in-process
  `rotation_grace_cache_` — a restart mid-overlap (default window 7 days)
  silently and permanently forfeited it, so `confirm` 409'd forever for that
  pair and the sweep cut over on the timer with no error surfaced at cutover
  time (filed as #2961; affects both arms). Migration v3 adds a durable
  twin, `api_tokens.rotation_initiator`, stamped on the successor row
  **inside the same advisory-locked mint transaction**. Both
  `confirm_rotation` (engine arm) and `confirm_token_rotation` (human arm,
  below) now resolve the identity check through the single chokepoint
  `ApiTokenStore::resolve_rotation_initiator`: RAM first, the durable column
  as the RAM-absent recovery path, **fail closed** if the two disagree, and
  an empty durable value is **never** treated as a wildcard. That last point
  is deliberate: a rotation already in flight when this migration is
  applied has no durable initiator and stays unconfirmable after a restart
  — an operator upgrading mid-rotation should confirm it first if possible.
  If not, the T12 sweep resolves the pair on its own timer **provided the
  successor was presented at least once** (the same UP-5 carve-out that
  gates every sweep auto-revoke — "never presented" leaves both credentials
  active indefinitely, sweep or no sweep); only in that presented case is no
  action required. If the successor was never presented, or the pair must
  be resolved by hand for any other reason, revoke the specific credential
  no longer trusted via `DELETE /api/v1/tokens/{token_id}` (an engine
  credential is an ordinary API token row), **never** the principal-level
  revoke route, which is terminal and destroys both credentials plus the
  principal. **Unaffected
  — deliberately:** the 120-second raw
  successor secret re-serve (bullet above, F4) stays RAM-only; a one-time
  reveal must never become durable, so a restart still forfeits that
  capability. Design record: `docs/security-reviews/human-token-rotation-2026-08-10.md`
  "Open risks" (#2961, marked resolved).
- **No-admin auditor** — `GET /api/v1/engine-principals/audit/no-admin` /
  MCP `audit_engine_no_admin` — independently resolves every engine
  principal's actual roles + effective permissions against the live RBAC
  reference tables and reports any violation (literal admin/system-role
  grant, or a full securable × operation wildcard grant). Fails closed
  (`503`, "cannot verify") rather than reporting a false `ok:true` if RBAC
  reference data can't be resolved.
- **Audit-persist posture (#2466/#2406 + #3937, ADR-1005 "mutations fail closed
  on audit failure"):** every *mutating* engine-principal REST route fails closed
  — `503` + `Sec-Audit-Failed: true` — if its audit row cannot persist, so a
  privileged mutation never reports success on an unrecorded action (mint/rotate
  additionally withhold the one-time secret). **Since #3937 the MCP mutation twins
  fail closed too** — a JSON-RPC `503` error (with `audit_persisted:false` in
  `error.data`, not on a success result), matching the REST posture and the
  in-MCP plugin-config precedent; mint/rotate withhold the secret there as well.
  (The human-token twins + the ~20 other set-and-proceed MCP write tools are a
  separate, tracked decision.) The *reads* instead set the header
  and proceed: they commit no state and disclose only authorization **topology
  metadata** (principal ids, owners, role grants), not per-person behavioural
  PII — so the fail-closed-on-read posture that governs the device/network PII
  reads (which exists to keep individual-identifying data off an unaudited
  response) does not apply. Full contract: `docs/user-manual/rest-api.md`
  "Engine Principals" → *Audit-persist failure*.
- **Owner-delete interlock (two-mode enforcement):** a user who owns an
  active engine principal must not be silently removed, or the principal's
  audit trail loses its named responsible human. Enforcement mode is chosen
  by whether an operator is in the loop (enterprise-architect ruling, PR 4.3
  governance):
  - **Interactive dashboard delete → prevention.** `DELETE
    /api/settings/users/{username}` (`settings_routes.cpp`) is blocked with
    `409` until ownership is transferred (`count_active_owned_by`,
    fail-closed on a store-unreachable read). An admin is present and can
    transfer first.
  - **Automated SCIM deprovision → detection.** SCIM deactivate/delete
    (`scim_routes.cpp` `deactivate()` + inline `DELETE`) is a CC6.8-mandated
    termination with no operator to transfer-first. Refusing it would leave a
    terminated employee **active** (a worse control failure); cascade
    auto-revoke is rejected because `revoke()` is terminal/irreversible (an
    IdP flap would destroy machine identities). So the deprovision **always
    succeeds** and a shared `flag_owner_deprovisioned` helper emits a
    high-signal audit `engine_principal.owner_deprovisioned` + increments
    `yuzu_engine_principal_owner_deprovisioned_total` when the departing user
    owned active principals (or ownership can't be verified), for out-of-band
    reassignment. It fires ONLY on the two genuine deprovision paths — never
    on SCIM undo/rollback (`remove_user` used to clean up a just-created or
    revived account). The orphaned principal keeps authenticating on its own
    `principal_type='engine'` credential and never derived authority from the
    owner, so the departed user gains nothing. Alert on the metric.

## Human API-token rotation (P2 #11, SOC 2 CC6.3)

Self-service overlap-pair rotation for **human-owned** API tokens —
`ApiTokenStore::rotate_token`/`confirm_token_rotation`
(`server/core/src/api_token_store.hpp`), the human-arm sibling of
`rotate_engine_credential`/`confirm_rotation` documented under "Engine
principals & delegation" → "Overlap-pair credential rotation" above. This
section covers the capability's design rationale; the wire surface, error
matrix, and telemetry are documented once each, cross-referenced below —
this section does not restate them.

- **Token-keyed, not principal-keyed — because a human is not an engine
  principal.** The engine arm arbitrates on a **≤2-active-credentials-PER-
  PRINCIPAL** ceiling, which is sound because an engine principal has
  exactly one credential by design. That invariant is **false** for a human:
  `principal_id` is a username, and one person routinely holds several
  unrelated named tokens at once (a CI token, a personal automation token, an
  MCP token). A principal-wide ceiling would therefore block rotating *any*
  one of those tokens the moment the user held a third, unrelated one — a
  defensive rejection that has nothing to do with the token actually being
  rotated. `rotate_token`/`confirm_token_rotation` instead key on the TOKEN
  being rotated and enforce the ≤2 ceiling **per `rotation_group`** — a
  human's other, unrelated active tokens never count against it
  (`api_token_store.hpp` "Human arm" doc block). The advisory lock is still
  taken on `hashtext(principal_id)`, the same key the engine arm and the
  T12 maintenance sweep use, so all rotation activity for one principal
  — human or engine — still serializes.
- **This distinction was caught at plan review, before any code existed** —
  a copy of the engine arm's principal-keyed ceiling would have shipped a
  control that silently blocked rotation for any user with more than two
  tokens. See `docs/security-reviews/human-token-rotation-2026-08-10.md` for
  the review record.
- **The identical class of defect then recurred one layer up, in the REST
  route, and was caught a second time.** The route's successor lookup
  (needed to return the freshly-minted token's `token_id`/`expires_at`)
  initially copied the engine rotate route's inline "linked-row" loop —
  sound only under that route's own per-principal ≤2 ceiling, unsound here,
  where several independent in-flight rotations can exist per principal.
  Reproduced against live Postgres and fixed by extracting the derivation
  into one shared, DB-free, unit-testable seam — `derive_rotation_successor`
  (`server/core/src/token_rotation_lookup.hpp`) — so the REST route today
  and the MCP twin landing separately both call the same function, rather
  than each risking its own copy of the same defect. Full reproduction
  narrative and reviewer attribution:
  `docs/security-reviews/human-token-rotation-2026-08-10.md`.
- **Self-service only, enforced at the store seam — not merely the route.**
  Both `rotate_token` and `confirm_token_rotation` reject unless
  `requesting_user` equals the resolved token row's own `principal_id`,
  checked inside the store itself (both in a pre-transaction lookup and
  again, authoritatively, on the fresh re-read under the advisory lock — the
  route-level ownership check that runs first is defense-in-depth on top of
  this, not a substitute for it). This is a deliberate asymmetry with the
  engine arm, where the requesting caller is a third-party admin by design:
  a **human** token's raw successor secret authenticates *as that user*, so
  an admin re-serving or confirming another user's rotation would be handed
  (or would complete the cutover of) a credential that impersonates someone
  else — identity takeover, not a permission gap an admin override could
  legitimately cross. An admin who needs to act on another user's token has
  `revoke_token`/`revoke_for_principal` instead; there is no rotate-as-admin
  path, by design.
- **Under RBAC-on, this composes into an effectively admin-only rotation
  path — a pre-existing property of the surface, not a new caveat.** REST
  rotate/confirm gate on `ApiToken:Rotate` — deliberately its own operation,
  distinct from `ApiToken:Write`'s create/list/revoke axis (round-3 security
  finding; see the `mcp_policy.hpp` `tier_allows()` operator-tier comment for
  the full narrative on why a shared op string was rejected) — which the
  RBAC seed data (`rbac_store.cpp:397,480,662`) grants only to
  `Administrator` and `ApiTokenManager` — no other built-in role (`Operator`,
  `PlatformEngineer`, `Viewer`, `ITServiceOwner`) holds it. Composed with the
  self-service-only requirement immediately above (no admin override), an
  `Operator`- or `Viewer`-role user who owns a token has **no** RBAC-on path
  to rotate it themselves, and no admin can do it on their behalf either —
  the token cannot be rotated by anyone until its owner is separately
  granted `ApiToken:Rotate`. This mirrors the posture of the surface's other
  operations — `POST /api/v1/tokens` (create) is gated on `ApiToken:Write`;
  `DELETE /api/v1/tokens/{id}` is gated on the sibling `ApiToken:Delete`
  operation (`rest_api_v1.cpp:2624`) — and the RBAC seed data grants all
  three operations to the same two roles (`Administrator`,
  `ApiTokenManager`) and to no others, so the admin-only conclusion holds
  identically across create, delete, and rotate. It is stated here because
  "self-service" throughout this section means *self-service subject to
  holding the relevant `ApiToken:*` grant*, never *available to any
  authenticated owner*.
- **Under the shipped RBAC-OFF default, self-rotate was admin-only for
  everyone else until #2963 fixed it — composed with the self-service-only
  ownership check, the feature was reachable by nobody but an admin in the
  actual out-of-the-box configuration.** RBAC ships off, so before this fix
  `AuthRoutes::require_permission`/`require_scoped_permission`'s legacy
  fallback denied every non-`Read` operation — `ApiToken:Rotate` included —
  to a non-admin caller, exactly like `ApiToken:Write`/`Delete` above. But
  rotation is inherently self-targeted in a way create/delete are not: the
  store already refuses any `requesting_user` other than the resolved
  token's own `principal_id`, so gating the ATTEMPT on an admin role added
  no safety, only unreachability. The decision (#2963): `ApiToken:Rotate` is
  now on the legacy self-service allowlist
  (`server/core/src/legacy_self_service_allow.hpp`) — the ONLY (securable,
  operation) pair on it today — so a plain non-admin, non-MCP-tier caller
  (a cookie session or an untiered PAT) may attempt rotate/confirm under
  RBAC-off; the store's ownership check is what actually decides whether it
  succeeds. This is the mirror image of `authz_topology_floor.hpp`'s
  `kTopologyFloor` (which narrows the legacy fallback for authorization-
  topology reads regardless of the toggle) — one list widens a single
  self-targeted exception, the other floors a fixed admin-only set; neither
  overrides a live RBAC grant, and both apply strictly inside the legacy
  branch, below it. The exemption does **not** widen to `ApiToken:Write`/
  `Delete` or any other operation — see that header's own criteria for what
  else could ever join it.
- **Not an ownership-enumeration oracle.** The non-owner rejection is folded
  into the exact same wording the genuinely-nonexistent-token case uses
  (`"no such token to rotate"` / `"no such token to confirm"`) — a caller
  cannot distinguish "this token doesn't exist" from "this token exists but
  isn't yours" from the error text alone. Mirrors the posture the human
  `DELETE /api/v1/tokens/{id}` route already takes for a non-owner.
- **Lifetime-neutral by deliberate choice — rotation cannot be used to
  extend a grant.** The successor's absolute `expires_at` always inherits
  the predecessor's verbatim (a perpetual token stays perpetual; a 30-day
  token stays a 30-day token measured from its own original grant) — never
  recomputed as `now + 90d`, which would silently extend authorization
  lifetime through what should be a lateral credential swap. The store-level
  API retains an internal `successor_expires_at` override parameter (reused
  by the engine arm's own successor-TTL logic), but the REST route
  deliberately does not expose it — a senior-architecture ruling, recorded
  in the security review, that rotation must read as lifetime-neutral in
  CC6.3 evidence with no caller-controlled escape hatch. A caller that
  genuinely needs a longer-lived replacement mints a fresh token via `POST
  /api/v1/tokens` instead, which is a distinct, separately-audited action.
- **Confirm error taxonomy is adjudicated, not ad hoc** — the state
  classifier (`rotation_confirm_state.hpp`'s
  `classify_confirm_state_in_group`, the group-scoped sibling of the
  engine arm's `classify_confirm_state`) distinguishes a POSITIVE fact
  (`kGroupEmpty` — the principal-wide active read succeeded and returned
  rows, but none carry the pinned `rotation_group`: the rotation has
  already resolved) from a genuinely AMBIGUOUS one (`kAmbiguousEmpty` — the
  principal-wide read came back empty, indistinguishable from a swallowed
  `SELECT` failure). `kGroupEmpty` classifies `Conflict` (REST `409` / MCP
  `kInvalidParams`, terminal — "rotate again if a new rotation is needed",
  never retry the same confirm); `kAmbiguousEmpty` stays `Transient` (REST
  `503`, retryable). An earlier round had this backwards — `kGroupEmpty` as
  `Transient` — which independent architect adjudication corrected before
  merge: reusing a retryable classification on a permanently-failing state
  would make a conforming agentic client (one that honours the tool's
  `idempotentHint`) retry that exact call forever. See the "Confirm replay
  classification (#2404)" bullet under the engine arm above for the
  precedent this decision follows, and
  `engine_store_error_class.hpp`'s file-level doc comment for the shared
  classifier both transports read through.
- **Store-layer scope only in this branch.** REST:
  `POST /api/v1/tokens/{id}/rotate` / `.../confirm`
  (`docs/user-manual/rest-api.md` "API Tokens" for the REST reference,
  `docs/user-manual/authentication.md` "Rotating a Token" for the operator
  walkthrough) — self-service, gated on
  `ApiToken:Rotate` (the human permission axis, distinct from
  `ApiToken:Write`'s create/list/revoke axis; **not** `Security:Write`,
  which gates the engine admin surface), MFA step-up re-validated on every
  call including an idempotent grace-window re-serve. Telemetry:
  `docs/observability-conventions.md` + `docs/user-manual/metrics.md`
  "Human API-token confirm metric (P2 #11)" (`yuzu_api_token_rotation_*`,
  `yuzu_api_token_confirm_total`, both kind-discriminated from the engine
  family at the one `rotation_sweep_names_for_kind` chokepoint,
  `rotation_sweep_naming.hpp`). Audit:
  `docs/user-manual/audit-log.md` (`api_token.rotate`, `api_token.confirm`,
  `api_token.reveal`, `api_token.rotation.auto_revoke`,
  `api_token.rotation.successor_unused`). **MCP tool twins
  (`rotate_api_token` / `confirm_api_token_rotation`) have shipped as of
  this section** — see `docs/mcp-server.md` "Human API-token rotation
  tools" and `docs/user-manual/mcp.md` rows 70–71 for the MCP-side
  reference; REST and MCP now have full parity on this surface.
- **The authority-inheritance guard closes the escalation direction, but is
  not equivalent to gating `Rotate` the way `Delete` is gated (governance
  Gate 8 follow-up).** Equality between the caller's own current
  `mcp_tier`/`scope_service` and the predecessor's guarantees no privilege
  GAIN — a rotation can never mint more authority than the caller already
  holds. It does not, on its own, make `rotate`/`confirm` net-neutral with
  `revoke`/`delete`: `mcp_policy.hpp`'s `requires_approval()` has no
  `ApiToken` rule at all, so at `supervised` tier a `Delete` call goes
  through the approval workflow and a `Rotate`/`confirm` pair does not. A
  caller can therefore rotate-then-confirm a same-principal sibling token of
  equal tier and scope — destroying its predecessor and revealing a fresh
  successor secret to themselves — with neither `ApiToken:Delete` nor a
  supervised-tier approval. No privilege gain, but a real residual:
  availability (the sibling's predecessor is destroyed) plus cross-consumer
  credential capture, within one principal's own tokens. **#2963 widens this
  residual's reach, not its shape** (governance Gate 4 UP-3): a full-authority
  session (empty tier/scope) can now rotate-then-confirm a same-principal
  SIBLING that carries a tier or scope, not only an untiered/perpetual one —
  previously the bare tier-equality guard blocked that combination
  structurally. Concretely: a caller who compromises only a principal's
  cookie session (e.g. via XSS/CSRF) can now silently rotate/confirm a
  *different*, genuinely MCP-tiered automation token belonging to the same
  principal, breaking whatever consumes it. Still no privilege gain — the
  successor inherits the sibling's own tier/scope, never the attacker's — so
  this stays an availability/credential-capture residual, not an
  authorization one, and the disposition is unchanged: `ApiToken:Rotate`
  remains deliberately not approval-gated (see above), and this is accepted,
  not fixed, by this decision.
- **The guard's blocking of the DE-escalating direction was decided and
  fixed by #2963 — a single full-authority exception, not a tier lattice.**
  The guard was originally bare equality, not "no broader than": a cookie
  or JIT-elevated interactive session carries an empty `mcp_tier`/
  `scope_service`, which matched an untiered predecessor but did **not**
  match a token that itself carried a tier or scope — so the owner of an
  MCP-tiered or service-scoped token could not rotate or confirm it from
  the dashboard or a plain interactive REST session at all, only the
  holder of that token's own secret (or an equally-tiered session) could.
  This was backwards precisely when the token's secret is the thing under
  suspicion, which is the main reason anyone rotates. The decision: a
  caller presenting empty `""`/`""` — no standing tier/scope authority at
  all — may now rotate/confirm ANY of its own tokens regardless of that
  token's tier/scope (`caller_may_act_on_tiered_token`,
  `api_token_store.cpp`). This is deliberately a single special case, never
  a general "no broader than" ordering: such a caller already holds a
  strict superset of what any tiered/scoped token can do, and the
  successor still inherits the TOKEN's own narrower tier/scope verbatim,
  never the caller's, so nothing is escalated. A caller holding SOME
  non-empty tier/scope still refuses on exact equality against a
  DIFFERENT one — no lattice comparison was introduced. See
  `docs/user-manual/authentication.md` "Rotating a Token" for the
  operator-facing statement, and `docs/user-manual/rest-api.md`'s
  rotate/confirm error matrices for the wire-level behavior. The
  `"no such token to rotate"`/`"...to confirm"` wording stays identical
  for absent/not-owned/genuinely-mismatched-tier and is still not an
  authority-probing oracle — it no longer needs to also cover the
  full-authority-caller case, since that case now succeeds instead of
  being folded into the same denial.
- **A token within 24h of its own expiry cannot be rotated — by design, not
  a gap, decided explicitly by #2963.** The overlap window has a 24h floor
  (`kOverlapFloorSecs`, `api_token_store.cpp`) and rotation is deliberately
  lifetime-neutral (the successor inherits the predecessor's `expires_at`
  verbatim, per the bullet above) — so `now + overlap_secs` cannot be made
  to fit inside a window shorter than 24h without either extending the
  token's lifetime or shrinking the overlap floor, and neither is
  acceptable: the floor exists so both the old and new secrets are
  verifiably live long enough for a controlled cutover. The store already
  refuses this case with a specific, non-generic error
  (`"overlap window would exceed the predecessor credential's expiry"`),
  and #2963 confirms that message is the intended terminal answer, not a
  bug to patch — rotation is not a renewal mechanism. The path for a token
  nearing expiry is to mint a fresh one via `POST /api/v1/tokens` before
  the old one lapses, exactly as for a caller wanting a longer-lived
  replacement (the bullet above). No code change; this bullet exists so
  the boundary is stated plainly instead of only discoverable from the
  error text.
- **A non-admin rotation caught mid-flight by an RBAC-off→on toggle can strand
  at `confirm`, and can require MANUAL operator resolution, not merely a
  delay — corrected 2026-09-17 after PR #4470 review, governance Gate 4 UP-6
  originally understated this.** `ApiToken:Rotate` is granted only to
  `Administrator`/`ApiTokenManager` under RBAC-on (`rbac_store.cpp`'s seed
  data) — before #2963 only an admin could start a self-service rotation at
  all, so this toggle race could only ever strand an admin, who already
  holds the RBAC-on grant and is unaffected. Now a non-admin owner can start
  one under the RBAC-off legacy allowlist; if an operator enables RBAC
  before that caller confirms, `confirm` hits the RBAC-enforced branch and
  403s for a non-admin role lacking the grant. **Whether this self-heals
  depends entirely on whether the successor secret is ever actually
  presented for authentication** — the background sweep's eligibility
  predicate (`kRotationEligiblePredicate`, `api_token_store.cpp`) requires
  the successor's `last_used_at <> 0`, which `confirm` never sets and which
  only a real authenticated request using the new secret sets. A caller
  whose automation is still waiting on a successful `confirm` signal before
  switching to the new secret — precisely the shape of this stranded case —
  may never present it, in which case the pair is **PERMANENTLY ineligible**
  for the sweep (the same "dropped/lost secret" case documented above for an
  ordinary rotation, not a special one), and requires an operator to revoke
  one of the two credentials manually; it does not resolve on any documented
  timescale on its own. There is no admin-override confirm path
  (rotate-as-admin/confirm-as-admin is deliberately not offered, per the
  identity-takeover rationale above). Accepted, not fixed, by this decision:
  enabling RBAC mid-flight against in-progress self-service rotations is an
  operator action outside this feature's scope to guard against, but the
  operator-facing guidance must state the manual-resolution possibility
  plainly rather than imply automatic recovery.
- **Known residual gaps, tracked, not fixed by this capability:** three
  pre-existing issues were surfaced while building this feature and filed
  rather than folded in silently — `#2943` (a confirm-path fallthrough
  shared by both arms that the human arm inherits), `#2944` (an
  engine-only defect; this feature's own REST route does not have it), and
  `#2945` (security-labelled, an open credential-**minting** escalation on
  the `ApiToken:Write` chokepoint — distinct from this feature's own
  rotate/confirm routes, which now gate on the separate `ApiToken:Rotate`
  operation seeded to the SAME two roles). None is a defect *in* the shipped
  rotation code itself. Full
  detail, mechanism, and compensating-control status — `#2945` in
  particular is **not** merely "unrelated and tracked separately"; it is
  recorded as an open risk against the sibling `ApiToken:Write` mint
  surface — are in the security review's "Open risks" section:
  `docs/security-reviews/human-token-rotation-2026-08-10.md`.

## Agent enrollment (3 tiers)

- **Tier 1 (manual approval)** — agents without a token enter a pending queue; admin approves/denies via Settings page. Agents retry and are accepted once approved.
- **Tier 2 (pre-shared tokens)** — admin generates time/use-limited enrollment tokens via the dashboard; agents pass `--enrollment-token <token>` at startup for auto-enrollment.
- **Tier 3 (platform trust)** — proto fields reserved (`machine_certificate`, `attestation_signature`, `attestation_provider`) for future Windows cert store / cloud attestation enrollment.
- **Enrollment token persistence** — tokens stored in `enrollment-tokens.cfg`, pending agents in `pending-agents.cfg` (same directory as `yuzu-server.cfg`).
- **Agent `--enrollment-token` CLI flag** — passes token in `RegisterRequest.enrollment_token`.

## Per-session peer binding and NAT-aware relaxation

`Register` and `Subscribe` are separate gRPC connections correlated by a
`session_id`. To stop a sniffed `session_id` from being replayed from another
host, Subscribe is bound to the Register connection by **two layers**:

- **Peer-IP binding (#826, hardened #1058/#1059)** — Subscribe's source IP must
  equal the IP recorded at Register (or, under `--gateway-mode`, a trusted
  gateway IP). A mismatch increments
  `yuzu_grpc_subscribe_peer_mismatch_total{event="security"}` and emits a
  `session.peer_mismatch` audit row (`result="denied"`).
- **Identity binding (authoritative)** — the `agent_id`↔session binding (#827)
  and, under mTLS, the client-identity binding (#1118,
  `yuzu_grpc_subscribe_identity_mismatch_total`). These are *stronger* than
  source IP.

**NAT-aware relaxation (#1128).** Exact-IP binding false-rejects a legitimate
agent whose Register and Subscribe egress *different* public IPs (multi-egress
NAT, proxy pool, CG-NAT, SD-WAN). Strict exact-match is the **default**; two
**opt-in** accommodations downgrade a mismatch to *advisory* (audit + metric, no
reject) instead:

1. **mTLS-advisory — `--nat-trust-mtls-identity`** (`Config::nat_trust_mtls_identity`,
   **default off**) — when enabled, a verified client identity matching the one
   bound at Register treats the IP as defence-in-depth only, so the mismatch is
   tolerated. **Opt-in because it is safe ONLY with per-agent client certs:** a
   shared/fleet-wide cert makes every identity "match", which would let an
   insider agent replay another agent's session from its own IP (gov UP-2). Off
   by default — identity-match never relaxes the IP binding unless the operator
   affirms per-agent certs via this flag.
2. **`--trusted-nat-cidr <cidr>[,…]`** (`Config::trusted_nat_cidrs`) — when the
   Register *and* Subscribe IPs both fall inside one operator-declared range
   (analogous to `--gateway-mode`, but for direct-connect NAT). Declaring a
   range asserts the hosts in it are mutually trusted not to replay each other's
   sessions — keep ranges narrow (never `0.0.0.0/0`). Malformed entries are
   logged and ignored at startup.

A mismatch *outside* both accommodations is still a hard reject — the replay
guard is intact, and an empty/malformed extracted IP is always reject (#826:
empty is a mismatch, never a wildcard). A tolerated mismatch emits
`yuzu_grpc_subscribe_peer_advisory_total{event="security",reason=…}` plus a
`session.peer_mismatch` audit row with `result="ok" outcome=advisory`. The pure
decision lives in `AgentServiceImpl::evaluate_peer_binding` (unit-tested);
CIDR containment in `cidr_match.{hpp,cpp}`.

**Gateway origin-IP attribution (#1064).** On the gateway `ProxyRegister` path
the server's transport peer is the *gateway's* IP, so audit rows would
mis-attribute the source (SOC 2 IR-2). `RegisterRequest.gateway_observed_peer`
(an optional, gateway-authoritative, transport-agnostic field — survives the
planned gRPC→QUIC move) carries the agent's origin IP; the server records
`source_ip`=agent origin and `gateway_ip`=transport peer, falling back to the
gateway IP (`origin_observed=false`) when absent. The *direct* Register path
ignores the field, so a *direct* agent cannot forge a source IP. It is **not** a
defence against a compromised gateway (which is inside the trust boundary and
can set any value) — both `source_ip` and the gateway's `gateway_ip` are
recorded so an auditor can cross-check. **Server-side consumption ships now; the
gateway-side population is a follow-up** — today's grpcbox transport can only
source it from `x-forwarded-for` (proxied deployments), and the durable
direct-mode source arrives with the QUIC transport (#376) that owns its socket.

## HTTPS and bind defaults (hard invariants)

- **HTTPS by default** — `https_enabled` defaults to `true`. Operators must provide `--https-cert` and `--https-key`, or use `--no-https` for development. The `--https` flag was replaced with `--no-https`.
- **Secure bind default** — Web UI binds to `127.0.0.1` by default (not `0.0.0.0`). A startup warning is logged if overridden to all interfaces.
- **Metrics auth** — `/metrics` allows unauthenticated access from localhost only. Remote access requires authentication. `--metrics-no-auth` overrides for monitoring infrastructure.
- **Private key permission validation** — Server refuses to start if TLS private key files are group/others-readable on Unix. Uses `std::filesystem::perms` check. Skipped on Windows.
- **CORS on all API endpoints** — CORS headers applied via `set_post_routing_handler` for all `/api/` paths.
- **JSON error envelope** — All error responses use structured `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}` envelope. Health probes (`/livez`, `/readyz`) use `{"status":"..."}` contract.

## Default certificates (PKI PR2, v0.13.0+)

A fresh install no longer refuses to start without operator certs. On first boot
the server generates a per-install internal CA (ECDSA P-384, 10-year) and P-256
leaves for the HTTPS, agent-gRPC, and management-gRPC listeners under the cert
directory (`auth::default_cert_dir()`; override with `--ca-dir`), recorded in
`ca_store` (Postgres, ADR-0053). Implementation: `default_certs.{hpp,cpp}` on the
`x509_ca`/`key_provider`/`ca_store` engine. Behaviour:

- **Per-surface, partial-override.** Defaults fill only the surfaces the
  operator left empty; an explicit `--https-cert`/`--cert` still wins. A surface
  with a cert but no key (or vice-versa) is a hard error (refuse to start) —
  operator and generated material are never mixed.
- **Agent-listener posture.** While the agent surface is on default certs the
  agent (and the management listener when it reuses agent creds) runs
  `REQUEST + VERIFY but NOT REQUIRE` client certs — encrypted +
  server-authenticated, so a first-boot agent with no client cert can connect
  and bootstrap one (per-agent mTLS, below). An operator-supplied agent surface
  keeps the strict `REQUEST_AND_REQUIRE` posture (the relaxation is gated on
  `using_default_agent_certs`, never the global `using_default_certs`).
- **Loud, impossible-to-miss notification (six surfaces):** ERROR startup banner
  with the CA SHA-256 + expiry; one-shot audit `server.default_certs_generated`;
  a 300 s periodic reminder + audit `server.default_certs_in_use`; Prometheus
  `yuzu_server_default_certs_active`; `/health` `tls.default_certs_active` +
  `ca_fingerprint` + `ca_expires_at` (unauthenticated — the CA is already in the
  TLS handshake); `/readyz` gains `ca_store`/`ca_root` checks (load-bearing only
  while on default certs).
- **Opt out** with `--no-default-certs` (legacy refuse-to-start). The CA root
  key is a 0600 file (HSM seam in `key_provider`); the threat model is local-host
  compromise — replace defaults with operator/HSM-backed certs for production.

## Per-agent mTLS (PKI PR3, v0.13.0+)

When the server runs with its built-in CA, agents are issued their own client
certificate at enrollment, so the agent↔server data plane is full mutual TLS with
a cryptographic identity bound to `agent_id`. This makes the existing
peer-identity binding (`#1118`) cryptographic with no new binding mechanism — the
issued leaf's `CN` *is* the `agent_id` the server already checks.

Issuance happens on **both** the direct `Register` and the gateway-proxied
`ProxyRegister` paths (PKI PR5d — both share one `sign_agent_csr` chokepoint); see
`docs/pki-architecture.md` "Per-agent enrollment through the gateway" for the
gateway specifics (the agent↔gateway hop is one-way TLS in M1, so through-gateway
identity stays the app-layer `gateway_observed_peer` until gateway mTLS lands).

**Bootstrap (chicken-and-egg) — resolved on one port.** The agent has no client
cert on first boot, but the data plane requires one. Resolution:

1. The agent connects server-authenticated TLS (verifies the server leaf against
   the CA cert it was given via `--ca-cert`), presenting **no** client cert.
2. The agent generates an EC P-256 keypair + a PKCS#10 CSR and sends the CSR in
   `Register` (`RegisterRequest.csr_pem`). The agent's private key never leaves
   the host.
3. When enrollment is approved (token / attestation / admin-approve — unchanged)
   **and** the built-in CA is active, the server verifies the CSR's
   proof-of-possession, signs a client leaf — `CN=<agent_id>` + URI SAN
   `yuzu://<ca-fingerprint>/agent/<agent_id>` — sized to ≤ the CA's `notAfter`,
   records it in `ca_store` (`purpose=agent`), and returns it in
   `RegisterResponse.issued_certificate` + `issued_ca_chain`. **The CSR's own
   subject/SAN are ignored** — identity is set by the server from the
   authenticated enrollment, never from attacker-controlled CSR fields (this is
   what stops an enrolling agent requesting another agent's identity).
4. The agent persists the leaf + key (`0600`) + chain under `--cert-dir`
   (default `<data-dir>/certs`), rebuilds its channel, and **re-Registers
   presenting the leaf** — a fresh session whose bound identity is the leaf's
   `CN`. (The first, no-cert session bound an empty identity, so the data plane
   would reject it; re-registering binds `CN=<agent_id>`.)

**App-layer enforcement.** `Register` is the only RPC permitted without a verified
client identity (it is how an agent obtains one). Enforcement is **gradual**, so
per-agent mTLS rolls out without breaking a heterogeneous or mid-upgrade fleet:

- `Register` is bootstrap-exempt but, if a client cert *is* presented (re-auth /
  renewal) and it is one of **ours** (issuer-scoped via `is_yuzu_issued`), it must
  match `agent_id` and must not be revoked. A foreign cert (multi-CA bundle) falls
  through to bootstrap.
- `Subscribe` rejects a presented leaf whose serial is on the CRL before taking
  the agent-plane lock (`yuzu_grpc_revoked_cert_total{rpc=subscribe}`), then
  enforces the `#1118` identity overlap **only when the session bound a client
  identity at Register** (i.e. the agent presented a cert). A provisioned agent
  therefore MUST present its leaf on `Subscribe` (a no-cert `Subscribe` against a
  cert-bound session fails the overlap → reject, so the stolen-session guard
  holds); a not-yet-provisioned or legacy (pre-PR3) agent has no bound identity
  and continues on the prior posture (session + `#826` peer-IP binding) rather
  than being hard-rejected.
- `Heartbeat`, `DownloadUpdate`, and `CheckForUpdate` reject a presented
  **revoked** leaf (`yuzu_grpc_revoked_cert_total{rpc=heartbeat|download_update|check_for_update}`)
  so a revoked agent is denied liveness, OTA download, *and* OTA version
  discovery — not just the command channel. `DownloadUpdate` also emits an audit
  row (`session.cert_revoked`); `Heartbeat`/`CheckForUpdate` are metric-only
  (high-frequency). `is_yuzu_issued` results are cached (immutable per cert) so
  the per-heartbeat check is not an ECDSA chain verify fleet-wide.
- **Open-stream revocation sweep (H-1).** The `Subscribe` gate above only runs at
  stream establishment, so a long-lived command channel would keep dispatching to
  an agent revoked *after* it connected (a hostile agent never voluntarily
  reconnects). The server's reaper thread therefore runs a periodic
  `AgentRegistry::sweep_revoked` (~15 s, well inside any CRL validity window) that
  re-evaluates every live Subscribe stream's stored leaf against the CRL and
  `TryCancel`s the stream of any now-revoked agent
  (`yuzu_grpc_revoked_cert_total{rpc=stream_sweep}`); the cancelled agent must
  reconnect, where the establishment gate refuses it. The presented leaf is
  stashed on the session only when a revocation checker is wired (CA active), so a
  non-PKI deployment stores nothing. PR4's operator-revoke handler calls the same
  sweep immediately so a dashboard/REST revoke tears the stream down promptly
  rather than waiting for the next tick. The revocation predicate runs off the
  per-session lock (it reads `ca_store`), and teardown re-checks the cert is
  unchanged so a reconnection mid-sweep is not cancelled by mistake.
- `require_client_identity_` is recomputed *after* the default-cert bootstrap
  (`tls_enabled && !tls_ca_cert.empty()`), since it is baked at construction
  before the CA exists.

**Rollout / upgrade.** Because enforcement is gradual, upgrading a fleet to PR3 is
non-breaking: agents that have not yet auto-provisioned (or run
`--no-auto-provision-cert`, or a pre-PR3 binary) keep connecting on session +
peer-IP binding, while provisioned agents get strict mTLS. Once a fleet is fully
provisioned, a future `--require-agent-identity` flag (tracked follow-up) can
harden this to require a bound identity for *every* agent and reject the
unprovisioned fallback. Folding revocation + identity into a single gRPC
interceptor so every identity-requiring RPC enforces them uniformly is the related
follow-up (today they are enforced at `Register`, `Subscribe`, `Heartbeat`,
`DownloadUpdate`).

**Custody & renewal.** The CA issuing key is loaded transiently per signature via
`FileKeyProvider` and zeroed (RAII) so the crown jewel is not resident for the
process lifetime. Server issuance is fail-closed: a cert that cannot be recorded
in `ca_store` (so it could never be revoked) is not handed out, and per-agent
issuance is rate-limited (one signature per `agent_id` per 30 s) so a holder of a
valid enrollment credential cannot spam the signer. Agent leaves are ~1-year and
auto-renew once two-thirds of their lifetime has elapsed (evaluated at agent
start; a fresh CSR rides the next `Register`). Issuance is audited
(`ca.cert.issued`). On the agent, the leaf key is written `0600` via an atomic
`O_EXCL` stage-and-rename on POSIX; **on Windows the key falls back to
`std::ofstream` + a best-effort permissions tightening — an explicit owner-only
ACL (`SetNamedSecurityInfoW`) is a tracked follow-up shared with the server's
`FileKeyProvider`, so on Windows run the agent under a dedicated service account
with no inherited group-read on the cert directory until then.**

**Trust scoping.** Presented client certs are accepted as agent identities only
when they signature-verify to *our* issuing CA (`verify_chain`), so in a
multi-CA trust bundle a foreign cert carrying a matching `CN` is not mistaken for
a Yuzu agent (nor conflated with a revoked Yuzu serial). If the server signs but
the agent never receives the cert (an active MITM stripping the field, or a
persistent signer outage), the agent bounds its retries and gives up
auto-provisioning for that run rather than looping.

**Agent CA pinning is fail-closed (#1303).** When the agent has TLS on but no CA
to pin — no `--ca-cert` **and** no install CA auto-discovered at any standard
shared-cert path (`/etc/yuzu/certs/default-ca.pem`, ProgramData on Windows, or
`~/Library/Application Support/Yuzu/certs/default-ca.pem` for a non-root agent
on macOS) — it **refuses to connect** rather than silently falling back to the
system trust store. An empty root set makes gRPC verify against the OS roots, which do **not**
trust a Yuzu self-signed install CA, so with the gateway one-way-TLS edge live any
publicly-trusted impostor cert for the dial host would be accepted — a fail-open
MITM on the command fan-out plane. The deliberate escape hatch is
`--tls-system-roots` / `YUZU_TLS_SYSTEM_ROOTS`, for the legitimate case where the
server certificate chains to a public or corporate CA already in the system store;
it logs a loud warning and is never the default. (`--no-tls` remains the dev/demo
opt-out.)

**Operator surface.** Server: `--ca-dir` (shared with the default-cert
bootstrap). Agent: `--cert-dir` / env `YUZU_CERT_DIR` (where the provisioned
credential lives) and `--no-auto-provision-cert` (disable the CSR-at-enrollment
flow — e.g. when supplying an operator-minted client cert via `--client-cert` /
`--client-key`, or an OS-store cert). The provisioned credential is written under
`--cert-dir` as `agent-client.key` (private key, `0600`), `agent-client.pem`
(the issued leaf), and `agent-ca.pem` (the issuing CA chain the agent pins the
server against). Deleting these files makes the agent **auto-re-provision** on
its next enrollment: it generates a fresh keypair + CSR and the server signs a
NEW leaf with a NEW serial. The previously-issued serial stays in `ca_store`
inventory as a now-orphaned `agent` row that no live agent holds — harmless, but
operators reconciling the issued-cert inventory should expect one orphan row per
key-loss event (revoke the orphan if a strict inventory is required).
**Revocation-bypass guard (#1239 H-2):** auto-re-provision is refused when the
agent's prior cert is *revoked* (not merely orphaned). `sign_agent_csr` scans
`ca_store` for a revoked, non-expired cert with `subject==agent_id` and, if found,
returns `nullopt` (audit `ca.cert.reissue_blocked`, metric
`yuzu_server_ca_reissue_blocked_total{reason=revoked_identity}`) — so a
compromised endpoint cannot drop its key and re-enroll its way back onto the data
plane. Clearing a revocation is a deliberate operator re-approval, never an
automatic consequence of key loss.
Implementation: server signer in `server.cpp`
(`sign_agent_csr` / `is_peer_cert_revoked`) on the
`x509_ca`/`key_provider`/`ca_store` engine; agent provisioning in
`agents/core/src/agent_csr.{hpp,cpp}` (self-contained OpenSSL) wired into the
`agent.cpp` connect/register loop.

**Gateway-proxied agents: revocation scope (known limitation).** Per-agent mTLS
identity and revocation enforcement are **authoritative on direct connect only**.
A gateway-proxied agent terminates its TLS at the *gateway*; on the
gateway→server hop the server's transport peer is the **gateway's** cert, not the
agent's leaf — so the server-side revocation gate and the open-stream sweep above
never see the proxied agent's serial, and a revoked agent behind a gateway stays
functional on the data plane. PR5d closes the *issuance* half of this gap
(gateway-proxied agents now obtain a per-agent leaf via `ProxyRegister`
CSR-signing, so the identity exists and is recorded/revocable in `ca_store`), but
*enforcing* that revocation at the gateway edge is future work: durable
cryptographic through-gateway identity (and therefore through-gateway revocation)
arrives with the QUIC single-connection migration (#376). Until then, to revoke a
gateway-proxied agent promptly, revoke at the gateway/management layer (disconnect
the agent) in addition to `POST /api/v1/ca/revoke`. This is the same
direct-connect-authoritative caveat called out in `docs/pki-architecture.md`
("Gateway path identity").

**Gateway CSR-swap forgery (R-5, accepted M1 residual).** Wiring `ProxyRegister`
to sign forwarded CSRs makes the gateway a bounded **confused deputy**. The
server signs the relayed CSR's public key under the **gateway-supplied**
`agent_id` (the through-gateway identity is the app-layer `gateway_observed_peer`,
not a transport-cryptographic binding in M1), so a compromised or on-path gateway
can relay a *victim's* `agent_id` paired with its *own* CSR and obtain a real
CA-signed leaf for that `agent_id`. Worse than a transient relay: that leaf is a
durable credential the attacker can present for **persistent direct mTLS
reconnect**, bypassing the gateway entirely — it **survives gateway eviction**.
Compensating controls (why this is accepted for M1, not a live break):

- Every forged leaf is recorded in `ca_issued` and is **revocable** — and #1290
  stamps `via=gateway_proxy` on the `ca.cert.issued` audit + issuance metric, so
  an incident responder can **scope and bulk-revoke the gateway-issued population**
  after a gateway compromise (the row the forensic control depends on).
- The gateway authenticates to the server over **upstream mutual TLS** (a rogue
  gateway cannot reach the issuance path without being an enrolled gateway).
- PR5c **one-way TLS** on the agent↔gateway edge mitigates the *on-path* (non-gateway-
  compromise) variant.

The actual cryptographic remediation — gateway agent-identity **attestation** +
per-gateway issuance **scoping** so a gateway can only obtain leaves for the
`agent_id`s it legitimately fronts — is tracked in **#1292** (cryptographic
through-gateway binding lands with the QUIC migration, #376). Full threat model:
`docs/security-reviews/pki-pr5-gateway-tls.md`; also summarised in
`docs/pki-architecture.md`.

## HTTP security response headers (SOC2-C1)

All HTTP responses (dashboard, REST API, MCP, metrics, health probes) carry six headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (deny-all baseline for camera/mic/geo/usb/etc.), and `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS only, per RFC 6797).

The CSP is fully `'self'`-only with no external CDN allowance because the HTMX runtime and SSE extension are embedded in the server binary (`server/core/src/static_js_bundle.cpp`) and served from `/static/htmx.js` and `/static/sse.js` — the dashboard works in air-gapped deployments.

The CSP uses `'unsafe-inline'` for `script-src`/`style-src` because the dashboard has inline `<script>`, `onclick=` handlers, and `<style>` blocks; tightening to nonce-based CSP requires a separate dashboard refactor. `upgrade-insecure-requests` is appended to the CSP only on HTTPS deployments.

Operators can extend the CSP via `--csp-extra-sources "https://cdn.example.com https://beacon.example.com"` (space-separated, validated at CLI parse — control bytes / semicolons / `'unsafe-eval'` are rejected at startup with a clear error). The flag's value is appended to `script-src`/`style-src`/`connect-src`/`img-src` only.

Header construction lives in `server/core/src/security_headers.{hpp,cpp}` (`yuzu::server::security` namespace) — the production server and the unit/integration tests in `tests/unit/server/test_security_headers.cpp` (38 cases) share the same `HeaderBundle::make()`/`apply()` code path. The resolved bundle is logged at INFO at startup so operators can confirm activation: `Security headers active: CSP=N bytes, HSTS=on/off, Referrer-Policy="...", Permissions-Policy=N bytes`.

## Self-target principal-destruction guard (hard invariant, #397/#403/ca-B1)

Any handler that destroys, demotes, or otherwise revokes a principal's privileges MUST reject the case where the URL/form target equals the caller's `session->username` (or differs from `session->role` for upserts that demote). UI suppression alone is insufficient — a hand-crafted HTTP request bypasses the dashboard.

**Load-bearing routes today:**

- `DELETE /api/settings/users/:name` — self-delete
- `POST /api/settings/users` — self-demote via role change

**Pattern requirements:**

1. Compare against `session->username` byte-exact. Fail closed when `session->username.empty()`.
2. Emit `audit_fn_(req, "<noun>.<verb>", "denied", "User", target, "<reason>_blocked")` on the rejection branch — `spdlog::warn` alone breaks the SOC 2 CC7.2 evidence chain.
3. Corresponding fragment renderers must accept the session username and suppress destructive controls on the matching row (see `render_users_fragment(const std::string& current_username)` — no default arg, every caller must pass explicitly so a future caller forgetting it is a compile-time failure rather than a silent UI regression).

**Scaling note:** when the third such handler ships, lift the comparison logic into a helper.

## AuthDB — persistent authentication store (Postgres, ADR-0006 — v0.12.0
SQLite retired)

`AuthDB` is **born-on-Postgres**, schema `auth` (`AuthDB(pg::PgPool&,
pg::SecretCodec&)`, migrated via `PgMigrationRunner`, fail-closed
construction — `is_open()`/`is_ready()` false means the server refuses to
start, ADR-0012 §1). It replaced the v0.12.0 SQLite `auth.db` file (itself
the replacement for the original in-memory + on-config-flush model that lost
users on every restart, #618/#388/#527) in the ADR-0006 Wave 3 substrate
migration. Tables: `users`, `enrollment_tokens`, `pending_agents`,
`mfa_recovery_codes`. **Dropped, not migrated:** the SQLite-era `sessions`
table (at the time of this cutover sessions were in-memory-authoritative in
`AuthManager::sessions_`, and that SQLite `sessions` mirror had been a permanent
v1 dead-write, never read back — since HA WS-1/1a (ADR-2002 §4) `sessions_` is a
validate cache in front of the durable Postgres `SessionStore`; see "Durable
operator sessions (HA WS-1/1a, ADR-2002 §4)") and `auth_kv`
(unused scaffolding, superseded outright by `pg::SecretCodec`, ADR-0010).
`ScimStore` migrated in lockstep to its own `scim_store` Postgres schema —
see "Storage" under SCIM v2 provisioning above.

**This was a fresh-start cutover — NOT a backfill.** On first boot against a
Postgres database whose `auth.users` table is empty, `main.cpp` seeds
exactly the config-file admin via `AuthDB::seed_admin_if_empty` (a single
`INSERT ... SELECT ... WHERE NOT EXISTS`, TOCTOU-free against a second
instance racing first boot) and logs a loud "AUTH DATA RESET ON POSTGRES
CUTOVER" warning. **A legacy SQLite `auth.db` is never read** — any prior
local accounts, roles, and MFA enrollments that existed only in a pre-cutover
`auth.db` are gone on upgrade; SCIM self-heals on the IdP's next sync cycle;
humans re-enroll MFA. This is a breaking upgrade by design, matching the
`ApiTokenStore` fresh-start precedent (4.1) rather than attempting a
cross-substrate data migration.

`mfa_totp_secret` is `SecretCodec`'s first production consumer (ADR-0010) —
see "MFA / TOTP" above for the envelope-encryption shape and the
`AuthDBError::SecretUnavailable` fail-closed contract. Everything else
(password hashes, recovery codes, enrollment/SCIM tokens) stays a
verify-only hash, unaffected by `SecretCodec`.

Operator recovery: `docs/ops-runbooks/auth-db-recovery.md` (rewritten for
the Postgres substrate — detection signals, the KEK backup-pairing rule, and
the break-glass one-shots' `--postgres-dsn`/`--ca-dir` requirements).
Security review record: `docs/security-reviews/authdb-2026-04-30.md`
(SQLite-era baseline).

The hard invariants for AuthDB-touching changes (schema/`PgPool`
construction, fail-closed posture, `SecretCodec` registration,
config-as-seed-only / fresh-start, role-field ignored, gate-level audit,
MFA fail-closed on secret-read failure, cleanup cadence, snapshot-and-release
publishing) live in `.claude/agents/authdb.md` — the AuthDB review agent
loads them on any change to `auth_db.{hpp,cpp}` / `auth_routes.{hpp,cpp}` /
`auth.{hpp,cpp}`.

### Availability coupling and the transient-blip ride-out (#2396)

Every password login makes several PostgreSQL-backed AuthDB calls — the
lockout pre-check, `record_failed_login`/`clear_failed_logins`, and
`mfa_status`. Under ADR-0006 the auth substrate is **fail-closed with no
SQLite fallback**, so a store error on the MFA read (or the lockout write)
returns a `503` and mints no session — deliberately, because collapsing an
unreadable enrolled-MFA state to "not enrolled" would silently strip a
privileged account of its second factor (see "MFA / TOTP" above). The cost is
that a *transient* Postgres outage — most commonly the shared pool's
**connect-backoff breaker** fast-failing every acquire for its 200 ms–5 s
window after one connectivity hiccup — could deny **all** logins until it
cleared.

To keep a momentary blip from becoming a console lockout, the **login-decision
reads** `mfa_status` and `load_mfa_row` retry the acquire within a small bounded
budget (`acquire_with_retry` in `auth_db.cpp`: the first acquire is attempted with
`kReadTimeout` (1500 ms), then up to `kAcquireRetries` short retries; worst-case
≈600 ms extra on top of the first attempt). **Since #2146 A2-R1 Gate 8's
fast-fail-on-saturation clamp landed at the shared `PgPool` chokepoint
(`pg_pool.hpp`'s `Options::saturated_fast_fail`, ADR-0012's 2026-09-20 Update),
the first acquire no longer necessarily gets its full `kReadTimeout` budget: if
the pool is already saturated at that instant, the wait is clamped to `min(1500
ms, 500 ms)` = 500 ms instead. This makes the worst case FASTER under
saturation (≈1100 ms total instead of ≈2100 ms), not slower; the `150 ms`
`kAcquireRetryTimeout` retry leg was already below the 500 ms clamp and stays
unaffected.** `mfa_status` is the exact call #2396 names as denying **all**
logins: it `503`s a legitimate, correct-password login on a blip. This **never
weakens fail-closed**: only the *acquire* is retried (a query that ran and
errored is not retried — it will not self-heal in milliseconds), and on budget
exhaustion the call still returns a store-unavailable error
(`AuthDBError::StoreBusy`, which `is_store_unavailable()` treats as unavailable)
→ `503`, no session.

The retry is **deliberately not applied to the lockout-section acquires**
(`lockout_status`, `record_failed_login`, `clear_failed_logins`), which run
under the `/login` per-username stripe mutex: sleeping under that mutex during
an outage would extend the per-username hold and let a same-username login
pile-up pin one HTTP worker per attempt, starving unrelated routes
(worker-pool starvation, closed in governance review). Those reads lose nothing
by not retrying — `lockout_status`/`clear_failed_logins` fail **open** (a blip
degrades the brute-force throttle for that attempt but never denies a valid
login), and `record_failed_login` only gates a wrong-password attempt. So no
`acquire_with_retry` call ever sleeps under the login stripe.

The remaining `503`s are made honest and observable: they carry a
`Retry-After` header and a `retry_after_ms` body field, and each fail-closed
refusal **in the initial `POST /login` handler** increments
`yuzu_auth_read_degrade_total{route,reason}` alongside the existing
`yuzu_auth_secret_unavailable_total{route}`. The `reason` label distinguishes a
transient acquire outage (`pool_acquire_timeout`) from a query that ran and
errored (`query_error`) and from an undecryptable/absent secret
(`secret_unavailable`), so SRE can tell a retry-storm apart from a uniform
outage. **Use `yuzu_auth_read_degrade_total{reason="secret_unavailable"}`, not
the coarser `yuzu_auth_secret_unavailable_total`, to alert on a KEK/secret
outage** — the latter also moves on a plain pool blip (it counts every
store-unavailable `503` on the secret path, not only secret-decrypt failures).
The other `is_store_unavailable`→`503` auth sites (`/login/mfa`, step-up,
enrollment, elevate) are not yet reason-instrumented (finer cardinality and
wider coverage tracked as #2401).

**Not addressed here, by design:** break-glass arming (`--break-glass-arm`)
and `--mfa-reset` are host-CLI one-shots that also require a reachable
Postgres and have no PostgreSQL-free local escape hatch — that is inherent to
the ADR-0006 fail-closed posture, and the mitigation for a *sustained*
database outage is Postgres high availability (the `/ha` workstream), not a
local bypass that would itself weaken the fail-closed guarantee.
`--postgres-pool-size` is the operator lever for reducing acquire contention
on the live server (the login path runs on the shared server pool).

### Role recheck at login — row-lock plus post-mint recheck (#4107)

Local-auth credential checks (`authenticate()`/`verify_password()`) re-verify
role against AuthDB *after* the password check, rather than trusting the
in-process cache: `AuthManager::recheck_role_after_credential_check` calls
`AuthDB::recheck_role_locked`, which takes a `SELECT ... FOR UPDATE` row lock
on the user's row and holds it across the in-process cache write — the same
technique `mfa_verify_login_code` already uses to close its own replay race.
This closes the same-process AND cross-replica divergence residual an
earlier, now-retired in-memory version counter could only narrow (a version
counter can tell you something changed since you looked; it cannot make your
look happen atomically with the change) — Postgres row locks serialize at the
database-engine level, not per-process, so a racing `update_role()`/
`reactivate_user()` from a different replica sharing the same Postgres
primary is serialized against this read exactly like a same-process writer.

**What the row lock alone does NOT close: the check-then-mint gap.** A role
this call observes under the row lock is provably fresh at the moment of the
read — but `persist_new_session` (the actual session mint) is a separate,
later step, outside the row lock (external adversarial review, fjarvis, PR
#4076 — "an inherent check-then-mint gap no non-serialized recheck can
close"). A demotion committing in the window between this function returning
and the mint completing would otherwise mint a session at the pre-demote
role, surviving that demotion's own session sweep (`update_role`'s
`std::erase_if(sessions_, ...)`, which already ran before the new session
existed).

Closing that gap by holding AuthDB's row lock across the mint was considered
and rejected — `persist_new_session` calls `SessionStore::create` in durable
mode, and holding one store's pool lease while calling another is exactly
the cross-store-lock deadlock hazard §3 above names for the structurally
identical OIDC/SAML deprovision race (`SessionStore`'s shared write-
generation row is the concrete instance: this row lock could end up waiting
on that row while some other path holds the gen row and needs this row
lock). Closed instead via the SAME pattern already used for OIDC/SAML: mint
normally, then a **post-mint re-check** (`AuthManager::post_mint_role_recheck`)
immediately re-verifies the just-minted role against a fresh AuthDB read and,
on divergence, a store error, or the account having no active AuthDB row at
all (never provisioned, or removed - the same `UserNotFound` branch
`recheck_role_after_credential_check` uses), revokes the session
(`invalidate_user_sessions`) and denies. Wired into both `authenticate()` and `create_local_session()` —
the latter also closes the same gap for the MFA login-challenge (TOTP/
recovery verify at `/login/mfa`) and enrollment-confirm routes, whose
caller-supplied role can be stale across an entire TOTP round trip, a
wider window than `authenticate()`'s own — NOT `/login/mfa/stepup`, which
re-proves MFA on an existing session and never calls `create_local_session`.

**The honest guarantee.** For the SAME-PROCESS/single-primary-Postgres case
this is airtight, not merely narrowed: a racing `update_role()` commits its
AuthDB `UPDATE` before taking `mu_` to sweep `sessions_`, and the mint's own
`mu_` write is mutually ordered against that sweep, so either the sweep
(running after the mint) removes the just-minted session, or the post-mint
recheck (running after the demote's already-committed write) catches the
divergence directly — one of the two always fires. Ordinary READ COMMITTED
visibility extends the same guarantee across replicas sharing one primary,
with no per-replica coordination needed. **Not closed:** a demote landing
strictly between the post-mint recheck's own read and the response/
`Set-Cookie` actually reaching the client is invisible to this mechanism —
closing that would mean holding the mint's transaction open all the way to
the HTTP response, a larger change than a role recheck (the same residual
OIDC/SAML's own post-mint recheck discloses, `docs/adr/2001-scim-oidc-identity-linkage.md`
"Known residuals").

A denied mint is audited via `auth.login` `result=failure`,
`detail=reason=session_mint_failed;cause=undifferentiated[;method=...]`
(`auth_routes.cpp`) and counted in `yuzu_auth_login_session_mint_denied_total`
— undifferentiated not just between a genuine role divergence and a
post-mint store error, but also against a plain `SessionStore` persist
failure (an ordinary availability event, unrelated to the role recheck at
all), since `create_local_session`'s caller-facing contract (an empty
string) collapses all three into one sentinel. Unlike the OIDC/SAML
counters' genuine-vs-store-unavailable split, this counter is not a
role-recheck-specific signal and must not be alerted on as one.

## RbacStore — the authorization substrate (Postgres, ADR-0041 — SQLite `rbac.db` retired)

`RbacStore` (`server/core/src/rbac_store.{hpp,cpp}`) is the **authorization
substrate**: role definitions, role→permission grants, principal→role
assignments, RBAC groups + membership, and the global `rbac_enabled` flag.
`require_permission` / `require_scoped_permission` / `authorize_list_read`
(World-A confinement, ADR-0017) / the engine-principal default-deny path
(ADR-0031) all resolve through it. It moved from the SQLite `rbac.db` file to
the server's PostgreSQL substrate in the ADR-0041 (Wave 2.1) migration, schema
**`rbac_store`**, born-on-Postgres on the shared server `PgPool` with
fail-closed construction (`!is_open()` → the server refuses to start,
ADR-0007/0012 §1). It is the **highest-blast-radius store** on the migration
ladder — a defect here is a fleet-wide authorization failure — and reuses the
shared pool, so it adds **no new flag or environment variable**.

**Reads FAIL CLOSED — deny-on-degrade (the load-bearing invariant).** Every
authz read keeps its `bool`/deny-on-error contract: a store-not-open,
pool-acquire timeout, or query error returns **deny** (`false` for the
`check_permission` / `check_scoped_permission` / `holds_permission_via_any_group`
/ `check_role_has_permission` bool checks; the empty/most-restrictive result for
the list/scope reads), NEVER allow. Where a caller needs to distinguish "denied"
from "store degraded" for a 403-vs-503 decision (e.g. `authorize_list_read`),
that is exposed via a **separate** tri-state / `std::expected` accessor — the
plain `bool` path stays deny-on-error so no existing chokepoint can regress to
fail-open. This **closes the prior "fails open on a corrupt `rbac.db`" hole**:
under SQLite a corrupt/unreadable RBAC store could fall through to an engaged
allow at some call sites; the PostgreSQL `rbac_store` now denies on any degrade.

**Cross-replica coherence — durable generation token.** Each replica keeps its
in-process permission cache (`perm_cache_`) but validates it against a **durable
`rbac_meta.write_generation` counter** bumped in the same transaction as every
mutation (`assign_role`, `unassign_role`, `set_permission`, role/group changes,
`set_rbac_enabled`). A read refreshes its cached view of the durable generation
at most once per `kRbacGenerationRefreshMs` (1000 ms — one cheap indexed
single-row `SELECT`, not a permission re-query) and clears `perm_cache_` on a
change; a local mutation bumps the counter and clears its own cache immediately.
This bounds cross-replica staleness to the refresh interval under normal
conditions: a revoke on replica A is typically visible on replica B within
~1 s. **That bound is a target the refresh loop aims for, not a hard
guarantee**: the interval-gating timestamp is claimed BEFORE the query runs
(deliberately, to prevent a refresh stampede), so a concurrent reader that
lands while a refresh is genuinely slow (pool saturation, a Postgres blip)
can observe staleness beyond the interval. That condition is now measured,
not silently assumed: a durable-completion timestamp tracks only actual
refresh successes (separately from the stampede-gating timestamp), and a
reader who misses the gate while already past the bound counts a
`stale_beyond_accepted_bound` degrade (fjarvis #2703 F3) — the read still
proceeds from the existing cache; nothing is denied. **Updated 2026-08-11
(#2703 Gate 7 merge-slice, ADR-0041 "Update" section — supersedes the
original "assume changed" text below it):** a failed generation refresh no
longer clears the cache immediately. Trust is extended for a bounded **~5 s**
window (`kRbacStaleServeBoundMs`) past the last confirmed-good refresh — a
deliberate bounded-staleness-for-continuity tradeoff, layered underneath the
~1 s propagation target above. Only once that 5 s bound is exceeded is the
failure treated as "assume changed" (cache cleared) and counted as a
`generation_refresh_failed` degrade. A separate fail-fast circuit breaker
(2 consecutive pool-acquire/query failures) independently bounds how long an
**uncached** check can block on a doomed pool — it denies such checks
immediately once open, but it does not itself clear the cache or shorten the
5 s bound; a cache hit is served regardless of breaker state. **The bound is
tight only for pool-acquisition failure** (no connection available within
the 250ms acquire budget — well under a second for 2 consecutive attempts).
A query that acquires a connection and then blocks on a PostgreSQL-side lock
inherits `PgPool`'s `lock_timeout` (10s default) instead — measured ~18.5s
for 2 such attempts against a live held `ACCESS EXCLUSIVE` lock on
`rbac_meta` (#3016); both modes still converge on a fail-closed deny, just
not at the same speed. See
`docs/enterprise-readiness-soc2-first-customer.md`'s "Availability posture
under PostgreSQL degradation" note for the full mechanism and its CAIQ
characterization. **The `rbac_enabled` flag propagates on the same durable
path.** The ~1 s bounded stale-allow window is an **accepted, gate-recorded
residual risk** (well inside the fleet's minutes-scale revocation-latency
envelope); `LISTEN/NOTIFY` (window → 0) is the named follow-up. **The 5 s
stale-serve bound above covers this flag's cached view too, not just
`perm_cache_`:** `rbac_enforcement_in_effect()` — the fail-closed accessor
every confinement-critical caller MUST use instead of the raw
`is_rbac_enabled()` — consults `rbac_enabled_view_degraded()`, which is
gated by the same `kRbacStaleServeBoundMs` window as the permission cache.
A refresh failure inside the bound therefore keeps trusting the
last-known-good `rbac_enabled` state exactly as it keeps trusting cached
permission verdicts; only past the bound does the view count as degraded
and `rbac_enforcement_in_effect()` fail closed (treats degraded the same as
enabled) regardless of what the raw flag last read.

**Terminology note:** every "the bound" reference in this paragraph and the
ones above it means `kRbacStaleServeBoundMs` (~5 s, the trust/staleness
bound governing when cached state stops being trusted) — a DIFFERENT
constant from `kRbacGenerationRefreshMs` (~1 s, the propagation-target
interval discussed earlier in this section, which only governs how often a
refresh may even be attempted and carries no trust semantics of its own).

**Addendum (2026-08-11, same day, pre-merge, never shipped, G11-CPPEXPERT-B2):**
"a failed generation refresh" above describes only a refresh attempt that
*ran to completion* and then failed. Gate 8 re-review found the fix missed a
second trigger the same 5 s bound needs to cover just as strictly: a refresh
attempt stuck in flight and never completing at all — e.g. blocked on the
`ACCESS EXCLUSIVE`-class lock contention discussed above, for up to the full
~10 s `lock_timeout`. Every concurrent caller during that stall either takes
the gated fast-return path (no state touched) or is itself blocked inside its
own query, so the completed-failure code path that degrades the cache never
ran — trust could be extended for the whole stuck-in-flight duration, not
just the intended 5 s. Fixed same-day: the staleness check now measures
elapsed time directly rather than depending on a refresh attempt's own
completion, at all three sites that decide whether cached state is still
trustworthy (now one shared chokepoint, `generation_view_stale_locked()`).
Never shipped; no SOC 2 assessment period or deployed fleet carried the gap.

**Fail-closed BOOT on the `rbac_enabled` flag.** The `rbac_enabled` flag is
durable in `rbac_meta`. An unreadable OR non-canonical flag at boot **refuses
to start** — the server never serves RBAC-**off** on a fleet that had enabled
it (which would silently make every confined operator fleet-wide-authorized:
a catastrophic fail-open). "Non-canonical" means any value other than the
exact strings `"true"`/`"false"` (fjarvis #2703 F2) — a query error or a
missing row was always fail-closed, but a *readable* value that wasn't
exactly one of those two strings previously coerced silently to `false`. A
schema-level `CHECK` constraint on `rbac_meta.value` for this key rejects a
non-canonical write outright as defense in depth; the application-level
strict parse is what refuses to boot if a bad value ever lands regardless.

**`migrate_from_sqlite()` retired (2026-09-03, #3623, ADR-0041 Update).** No production Yuzu
fleet has ever run a pre-Postgres build of this store (ADR-0009's 2026-08-25
fresh-start-by-default amendment), so the mandatory, single-shot, fingerprint-verified backfill
this section previously described in full — seed-then-backfill via `ON CONFLICT DO NOTHING`,
the `rbac_enabled`-flag-first read-back-verified transfer, the `revoked_seed_defaults`
suppression table (still live and unaffected by this retirement — `seed_defaults()`'s reseed
still consults it), the CHAOS-1 concurrency fix (`pg_advisory_xact_lock`, still live —
`seed_defaults()` and
`remove_permission()` both still take it, only the backfill's third writer is gone), and the
SHA-256 cross-replica marker fingerprinting — is gone. `RbacStore::migrate_from_sqlite()` and
its backfill-only helpers are removed; the two backfill-only rows in `rbac_meta`
(`backfill_complete`/`backfill_source_fingerprint`) are POISONED, not dropped, via a
version-bumped migration — `backfill_source_fingerprint` is forced to the retired code's own
`kSourcelessFingerprint` sentinel (`"sourceless"`), never deleted; `rbac_meta` itself stays,
still holding `rbac_enabled`/`write_generation`. This is the one store in the retirement batch
whose marker is ROWS rather than a whole table, and a bare `DELETE` (the first version of this
migration, caught by governance unhappy-path before merge) would have let a pre-#3623 binary
rolling back read the resulting absence as "never migrated" and fall straight through its own
fingerprint-verification safety net into an unconditional overwrite of the live `rbac_enabled`
flag from a local legacy file — see ADR-0041's Update for the full trace. `server.cpp`'s boot
path now runs `legacy_sqlite_probe::warn_if_legacy_rows` over `rbac_config` (the legacy table
that held the enabled flag), `securable_types`, `operations`, `roles`, `role_permissions`,
`principal_roles`, `groups`, and `group_members` instead — WARN-only, never refuse-boot, a
posture reopened and explicitly reconfirmed for this store given the enabled-flag stakes rather
than defaulted by uniformity with the rest of this retirement batch (see ADR-0041's Update for
the full reasoning). `docs/ops-runbooks/rbac-store-backfill-recovery.md`, which documented this
mechanism's failure modes, is deleted along with it.

**Metrics.** `yuzu_server_rbac_read_degrade_total{reason}` — three
DENYING reasons (`pool_acquire_timeout` / `query_error` /
`generation_refresh_failed`): a degrade denies authz fleet-wide, so a
non-zero rate on one of these is a fleet-wide authorization-availability
event, and the `YuzuRbacReadDegraded` alert pages on exactly this subset.
Two OBSERVE-ONLY reasons share the same metric but deny nothing — the read
still proceeds — and are deliberately excluded from that alert:
`rbac_enabled_non_canonical` (a periodic refresh saw a non-canonical value;
the cached enabled-state is left unchanged rather than coerced) and
`stale_beyond_accepted_bound` (the bounded-stale-serve paragraph above). See
`docs/user-manual/metrics.md` and the `YuzuRbacReadDegraded` alert in
`docs/prometheus/yuzu-alerts.yml`.

**Read split for reviewers.** The plain `bool` authz checks fail closed
(deny-on-error) so no chokepoint can regress to fail-open; the tri-state
`_checked` / `std::expected` accessors are the ONLY place a caller may learn
"degraded" (503) as distinct from "denied" (403). A new read must land on the
correct side of this split — see ADR-0041 and
`docs/adr/0017-management-group-confinement-list-reads.md`.
