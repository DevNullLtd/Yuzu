# Security review — JIT admin elevation (SOC 2 CC6.3/CC6.6)

> ⚠️ **Superseded in part by HA WS-1/1a (ADR-2002 §4).** This review describes
> the elevation window as `steady_clock` (monotonic) and in-memory, dropped on
> restart. As of HA WS-1/1a the window is wall-clock (`system_clock`) and
> **durably persisted** to the `SessionStore` row (survives a restart, bounded
> by a hard `kMaxElevationWindow` 24h ceiling + the session's absolute expiry);
> the monotonic NTP-step resistance is replaced by that ceiling + a backward-step
> guard. See `docs/auth-architecture.md` "Durable operator sessions".

> ⚠️ **Superseded in part by #1837/#1857 (OIDC principal re-key).** The OIDC-amr
> elevation portions of this review are **temporarily inactive**: an OIDC session
> is now keyed on the immutable `oidc:<iss>#<sub>` principal, which has no local
> `users` row, so it is denied JIT elevation at the eligibility gate (the
> OIDC-amr second-factor branch is retained but unreachable-for-success). The
> OIDC-amr test cases cited below were replaced with severance tests on the
> #1857 branch; local-session JIT elevation is unchanged. Restoration of OIDC
> elevation against the stable principal is tracked in **#1852**.

**Date:** 2026-06-30
**Change:** Just-in-time admin elevation — a pre-authorized operator activates a
time-boxed, justified, MFA-gated admin window via `POST /api/v1/elevate`, then
auto-reverts. Eligibility is the per-user `users.elevation_eligible` flag
(admin-managed via `POST /api/v1/users/<name>/elevation-eligibility`).
**Branch:** `feat/auth-jit-elevation`
**Controls:** SOC 2 **CC6.3** (least privilege — reduce standing admin), **CC6.6**
(privileged access — time-boxed, justified, MFA-gated, audited). Closes
`/auth-and-authz` gap-matrix **P1 #9**.

## What shipped

- **`POST /api/v1/elevate`** `{justification (required), duration_secs}` — sets
  the in-memory `Session::elevated_until = now + min(duration, --jit-max-elevation-secs)`
  (default 1h, max 24h). `auth::effective_role(session)` returns `admin` while
  the window is live; `require_admin` gates on it and
  `require_permission`/`require_scoped_permission` short-circuit to allow an
  elevated session. The same `effective_role` is honoured at the previously
  raw-`role` admin-bypass sites (workflow role-gated approval, cross-user API
  token revoke, the dashboard token-list filter) so "elevated = full admin" is
  uniform for the window.
- **`POST /api/v1/elevate/revoke`** — manual step-down. **`--jit-max-elevation-secs`**
  (`YUZU_JIT_MAX_ELEVATION_SECS`).
- **Eligibility** — `users.elevation_eligible` (auth.db migration v5; renumbered
  from v4 at merge after break-glass #1735 took v4 on dev), set via
  `POST /api/v1/users/<name>/elevation-eligibility` (`AuthDB::set_elevation_eligible`/
  `is_elevation_eligible`, parameterised, `RETURNING`, fail-closed read).

## Control / authz decisions

- **MFA is mandatory to elevate, unconditionally (security-F1).** Elevation is
  the privilege-crossing boundary (non-admin → full admin), so — unlike the other
  11 step-up sites where the actor is already admin — an eligible operator with
  **no enrolled second factor** is hard-denied 403 (not merely passed through
  under `--mfa-enforcement=optional`). Enrollment + a fresh step-up are both
  required. Deliberately mirrors the break-glass "no bare-password privilege"
  posture (#1735 UP-1).
- **Cookie sessions only.** `/api/v1/elevate` reads the session cookie and
  `elevate_session` keys on the cookie token; API/MCP tokens resolve via
  `synthesize_token_session` (no cookie, no `elevated_until`), so an automation
  credential can **never** be elevated, and the permission-gate short-circuits are
  unreachable by them.
- **Grant audit is fail-closed (UP-3).** If `role.elevation.granted` can't
  persist, the elevation is rolled back (compensating `revoke_elevation`) and the
  call 500s with `Sec-Audit-Failed` — a privileged activation never stands
  without a record (mirrors the break-glass arm).
- **Revoking eligibility terminates active elevations (UP-1).**
  `set_elevation_eligible(false)` calls `AuthManager::revoke_user_elevations`, so
  an incident-response "revoke now" drops the operator's admin access immediately
  rather than leaving it standing for the window — symmetric with the session
  wipe on demote/delete.
- **Self-grant blocked (UP-6).** An operator (including one acting under an
  active elevation) cannot set their own eligibility, so a temporary admin window
  can't manufacture a durable self-elevation right. Eligibility is always granted
  by another admin, and the grant records the granting actor.
- **Monotonic, in-memory window.** _[SUPERSEDED by HA WS-1/1a — see the banner at
  the top of this file. As of ADR-2002 §4 `elevated_until` is durable wall-clock
  (`system_clock`), survives a restart, and is bounded by `kMaxElevationWindow` +
  `elevation_issued_at`; the paragraph below describes the pre-HA design.]_
  `elevated_until` is `steady_clock` (an NTP
  step can't extend it) and per-session in-memory — a restart or logout drops the
  elevation (fail-safe; nothing in auth.db resurrects it). It cannot outlive the
  session's absolute expiry (`validate_session` rejects past `expires_at`).

## Hermes pre-submission pass-1 fixes

- **`duration_secs` > INT_MAX → 500.** A JSON integer above `INT_MAX` passed
  `is_number_integer()` but `get<int>()` threw → 500. Now read as `int64_t`,
  range-checked, then narrowed (over-cap clamps to the window).
- **TOCTOU: eligibility revoked during the step-up delay.** Eligibility is
  re-checked immediately before `elevate_session` (the human-time MFA step-up sits
  between the first check and the grant), so an admin who revokes mid-step-up wins
  the race — `role.elevation.denied` / `detail=eligibility revoked during step-up`.
- **Step-up escape hatch on the privilege boundary.** The elevation step-up floors
  the window to 300 s when the operator has globally disabled step-up
  (`--mfa-step-up-window-secs <= 0`), so elevation ALWAYS requires a fresh proof
  even when the gate is disabled elsewhere. (For a local enrolled user
  `require_mfa_step_up` already runs the freshness check regardless of
  `--mfa-enforcement`; the floor closes the one remaining global-disable path.)
- **Audit gap on step-up refusal.** A refused elevation step-up now also emits
  `role.elevation.denied` / `detail=mfa_step_up_refused`, completing the
  elevation-specific trail beside the shared `mfa.step_up` row.

## Tr3kkR adversarial review (Codex vs Kimi) fixes — #1748

- **H1 — audit `principal_role` understated the effective role.** `make_audit_event`
  / `emit_event` (auth_routes) and the four `settings_routes` token-management rows
  stamped `principal_role` from the **base** `session->role` while authorizing via
  `effective_role` — so an action authorized as admin under an active elevation was
  logged as `user`. All six now stamp `auth::role_to_string(auth::effective_role(*session))`
  (a no-op for non-elevated sessions). Test: an elevated admin action records
  `principal_role=admin`.
- **H2 — migration-version collision.** Break-glass #1735 merged to `dev` first and
  took `v4`; the JIT `elevation_eligible` migration is **renumbered to `v5`** and the
  branch rebased on current `dev`, so the migrations are contiguous and the collision
  can never silently skip.
- **H3 — non-A4 admin-denial envelope.** `POST /api/v1/users/<name>/elevation-eligibility`
  no longer borrows `require_admin`'s legacy `{error:{code,message}}` 403; it runs an
  **inline A4 admin gate** (token-type guards + `effective_role`, `auth.admin_required`
  audit) returning the A4 envelope with the route's `X-Correlation-Id`.
- **M1 — discovery (A2).** The three routes (`/elevate`, `/elevate/revoke`,
  `/users/{username}/elevation-eligibility`) are added to `openapi_spec()` with request
  schemas + A4 error responses; a route-presence test guards them.
- **L2 — UTF-8 truncation.** The 1 KiB justification cap now backs up to a code-point
  boundary so the audit detail never ends mid-sequence.

## Threats considered (governance pipeline, 8 reviewers + Hermes ×2)

- **Privilege escalation without eligibility / without MFA.** No path: eligibility
  is admin-granted + read fail-closed; MFA enrollment + step-up are mandatory.
- **Token elevation.** Impossible (cookie-only; verified by security-guardian).
- **Justification log/audit injection.** Control bytes (incl. DEL) → space; 1 KiB
  cap; non-empty required; goes into the audit detail as a trailing field.
- **Malformed body / negative-duration least-privilege miss.** Wrong-typed fields
  and negative durations are `400` (not a 500, not a silent max-window grant).

## Residual risks (accepted / tracked)

- **An elevated operator can create standing admins / grant others' eligibility.**
  Inherent to "elevation = full admin" (a standing admin can too); self-grant is
  blocked and every eligibility change is audited with the actor. Access reviews
  must enumerate `users.elevation_eligible` and cross-check the granting actor.
- **Migration v4 collides with the break-glass PR (#1735, also v4).** A merge-gate
  renumber-to-v5 item, flagged in-code.

## Follow-up shipped (2026-07-02) — OIDC amr-asserted elevation

The v1 limitation above ("OIDC-only operators cannot elevate") is closed,
**with a prerequisite**: eligibility and MFA status are both keyed on the
`users` table row, and OIDC login does not create one — a federated-only
identity needs a Yuzu `users` row provisioned first (e.g.
`POST /api/v1/users`) before an admin can grant it `elevation_eligible`. Given
that row, an OIDC session whose IdP login attested MFA via the `amr` claim (a
seeded `Session::mfa_verified_at`, set at `/auth/callback` via
`amr_asserts_mfa` — the same mechanism OIDC login step-up already used) now
satisfies the mandatory-second-factor requirement at `POST /api/v1/elevate`
**without** local TOTP enrollment.

### Hardening round (2026-07-02, post-13-agent-governance) — linchpin fix

The first cut of this follow-up gated the mandatory-MFA check with a single
`if (!oidc_amr_elevation) { <local enrollment check> } `. Governance (13
agents) found this let an OIDC session **fall through to a local namesake's
TOTP enrollment**: a user with the same username but a *different* identity
(local password login vs. federated SSO) could be locally enrolled, and an
OIDC caller with no seeded amr proof would pass the enrollment check on that
namesake's factor, then possibly clear `elevation_step_up` too (its
no-proof-OIDC branch PASSes under `--mfa-enforcement=optional`) — granting
elevation with **no second factor the OIDC caller actually presented**,
mislabeled `mfa=local_totp` in the audit trail (security-F1 / consistency
S-2). The toggle was also inert for OIDC (it only gated the enrollment-skip,
not the step-up's amr acceptance), so `--no-jit-oidc-amr-elevation` did not
actually block an OIDC elevation via the namesake path either.

**Fix — branch EXPLICITLY on identity source** (replaces the single-flag
guard):

```cpp
const bool oidc_amr_proof = session->auth_source == "oidc" &&
                            session->mfa_verified_at.time_since_epoch().count() != 0;
const bool oidc_amr_elevation = cfg_.jit_oidc_amr_elevation && oidc_amr_proof;

if (session->auth_source == "oidc") {
    // An OIDC session's ONLY acceptable second factor is a seeded amr proof
    // with the toggle on. It never consults the local `users` MFA column.
    if (!oidc_amr_elevation) {
        const char* reason = cfg_.jit_oidc_amr_elevation
            ? "no MFA in SSO login (the IdP did not assert amr MFA) — re-authenticate via your IdP with MFA"
            : "OIDC-amr elevation is disabled (--no-jit-oidc-amr-elevation); elevate from a local session with TOTP";
        /* audit role.elevation.denied with `reason`; 403 */
        return;
    }
    // fall through to elevation_step_up (freshness on the amr seed)
} else {
    if (auto st = db->mfa_status(session->username); !st || !st->enrolled) {
        /* audit role.elevation.denied "no MFA enrolled..."; 403 */
        return;
    }
}
```

- **security-F1 guardrail (re-verified twice now).** The OIDC branch is gated
  on a **seeded** proof (`mfa_verified_at != epoch`), never merely
  `auth_source == "oidc"`, AND the two identity sources are now structurally
  disjoint — an OIDC session can never reach the `db->mfa_status(...)` call at
  all. This closes both the original single-factor-under-`optional` gap and
  the namesake-fallthrough gap the hardening round found. This seam remains
  the ONLY unconditional block for a single-factor (no-amr) OIDC session —
  `require_mfa_step_up`'s no-proof-OIDC branch alone would PASS such a
  request under `optional` enforcement.
- A seeded-but-**stale** proof (older than the elevation step-up window, which
  floors to 300s even when the global gate is globally disabled) still falls
  through to `elevation_step_up` and is challenged, not silently granted.
- **Toggle semantics, corrected.** `--jit-oidc-amr-elevation` /
  `YUZU_JIT_OIDC_AMR_ELEVATION` (default true). Disabling it means **OIDC
  sessions cannot use JIT elevation at all** — not "fall back to requiring
  local TOTP for OIDC too" (an OIDC session structurally cannot present a
  local TOTP step-up; its step-up challenge is re-SSO). An operator on a
  toggle-off deployment must elevate from a local-authenticated session with
  local TOTP.
- **Distinct denied reasons.** The audit `detail` for `role.elevation.denied`
  now distinguishes "no MFA in SSO login" (no amr assertion) from "OIDC-amr
  elevation is disabled" (toggle-off) from "no MFA enrolled" (local session) —
  three different failure modes, three different operator remediations.
- **Audit field order (consistency S-3).** The `role.elevation.granted` detail
  is `duration_secs=<n> mfa=<oidc_amr|local_totp> justification=<text>` — the
  code-emitted `mfa=` field is placed **before** the operator free-text
  `justification=` field. `justification` is only control-byte-sanitised, so
  a crafted value like `"x mfa=local_totp"` could otherwise forge the factor
  token a first-match grep reads; putting the genuine field first means it is
  always found before any forged text embedded later in the justification.
- **SRE posture log (SHOULD).** A one-time INFO line is emitted at boot when
  OIDC is configured (`--oidc-issuer` + `--oidc-client-id` both set, the same
  predicate `oidc::Config::is_enabled()` uses) and
  `--jit-oidc-amr-elevation` is on, so an incident responder can discover the
  posture without reading source or an individual audit row's `mfa=` detail.

## Follow-ups shipped (2026-07-02)

Both `expires_in`/`expired`-event follow-ups flagged above have shipped:

- **Follow-up A — `role.elevation.expired` on passive lapse.** Emitted LAZILY (no
  new background thread) by `AuthManager::reap_expired_elevation`, called from the
  `AuthRoutes::resolve_session` cookie chokepoint on the operator's first
  authenticated request after the window elapses. Clears `elevated_until` to the
  sentinel on the first observing call, so emission is exactly-once; a manual
  `revoke_elevation`/`revoke_user_elevations` clears the same sentinel first, so a
  manual step-down never ALSO produces a spurious `expired` row (verified by test).
  **The audit emission itself is best-effort / at-most-once, not exactly-once
  end-to-end:** the sentinel is cleared BEFORE the audit call, so a store failure
  loses only the confirmatory `expired` row — the reap (session reverting to base
  role) still happens regardless, and the window's end remains reconstructible
  from the earlier, fail-closed `role.elevation.granted` row's
  `duration_secs`/`expires_at` (verified by a broken-`AuditStore` test — no
  crash/throw, elevation still reaped). **Accepted boundary:** an operator who
  elevates and then abandons the session (closes the browser, lets it idle)
  without another authenticated request never triggers the lazy reap — no event
  fires for that lapse, though the window's end remains reconstructible from the
  `granted` row's `duration_secs`/`expires_at`. The same boundary applies to idle
  (inactivity) session eviction: if the idle reaper evicts the session first, the
  next request never reaches the cookie-found branch, so the lazy reap likewise
  never fires.
- **Follow-up B — absolute `expires_at` + session-lifetime clamp.**
  `AuthManager::elevate_session` now clamps
  `elevated_until = min(now + min(duration, --jit-max-elevation-secs), session.expires_at)`
  — an elevation can never outlive the cookie session that carries it.
  `POST /api/v1/elevate`'s response now reports the TRUE remaining time as
  `expires_in` (computed after any clamp, so it is `<=` the requested/capped
  duration) plus a wall-clock `expires_at` (RFC3339 UTC). The
  `role.elevation.granted` audit detail carries `expires_at` too, and the
  analytics `emit_event` now carries the same post-clamp `duration_secs` as the
  audit row and response body (all three channels agree).
- **Governance hardening round (2026-07-02) — dead-window guard (UP-1/UP-4,
  merge-blocker, fixed).** A session that crosses its own absolute `expires_at`
  between `validate_session` and `elevate_session` previously clamped to
  `until <= now` and was still granted: a `200 ok` with `expires_in:0` that
  misled a scripted caller into believing it held admin, followed by a spurious
  `role.elevation.expired` for a window that never actually conferred privilege.
  `AuthManager::elevate_session` now detects `until <= now` BEFORE mutating the
  session and returns `nullopt` — the handler's existing nullopt→401 path
  ("session vanished between validate and elevate") covers it, so a dead window
  is now REJECTED (401), never a zero-privilege `200 ok` grant.
- Tests: `tests/unit/server/test_auth_jit_elevation.cpp` `[jit]`, 26 cases / 434
  assertions (empirically verified via the Catch2 binary's own summary line, not
  a grep of `TEST_CASE`) — cumulative across both hardening rounds: elevate_session
  session-lifetime clamp; reap_expired_elevation exactly-once +
  no-op-after-manual-revoke; REST-level lazy-expiry audit + no-double-emit +
  no-emit-after-revoke; `expires_at` presence/format and
  `expires_in <= requested` on the existing grant/cap-clamp REST cases (updated
  from exact-equality to `<=`/tolerance since `expires_in` is now the true
  post-grant remaining time); the dead-window rejection (`elevate_session`
  returns nullopt for a session already at/past its own expiry, via a new
  TEST-ONLY `expire_session_for_test` seam); concurrent TOCTOU reap
  exactly-once under two racing threads; a lazy reap surviving an unwritable
  `AuditStore` without crashing; a reap firing within a request resolves that
  SAME request to base role; the `role.elevation.granted` audit detail carrying
  `expires_at=`.

## Validation

- Unit: `tests/unit/server/test_auth_jit_elevation.cpp` `[jit]` — reconciled
  count read directly from the test binary
  (`tests-build-server-linux_x64/yuzu_server_tests "[jit]"`): **37
  test cases, 837 assertions**, all green (this is the union of the
  OIDC-amr follow-up and the passive-lapse/`expires_at` tails work, now merged).
  Coverage: `effective_role`/`is_elevated`, `AuthManager` elevate/revoke/
  revoke-user-elevations/reap_expired_elevation, `AuthDB` eligibility, and the
  REST surface end-to-end (granted; elevated-passes-admin-gate;
  **MFA-enrollment-mandatory**; **stale-proof-challenged**; ineligible-denied;
  justification-required; **wrong-typed/negative-duration → 400**;
  duration-clamp; **session-lifetime clamp**; **dead-window rejection**;
  revoke-reverts; **eligibility-revoke-kills-elevation**; **self-grant-blocked**;
  tokenless-rejected; OIDC-amr fresh-proof-elevates; OIDC no-proof-still-denied
  with distinct reason; **the F-1 regression case**; OIDC stale-proof-challenged;
  toggle-off-blocks-OIDC-entirely with distinct reason; toggle-off + namesake +
  fresh-amr; users-row-less identity denied at eligibility;
  local-session-unaffected; audit-field-order anti-forgery; lazy passive-expiry
  reap (exactly-once, no-op-after-revoke, **concurrent-TOCTOU exactly-once**,
  **survives-unwritable-audit-store**, **reap-within-request-resolves-base-role**);
  `expires_at` presence/format + audit-detail substring). The F-1 regression
  case was verified to FAIL against the pre-fix single-flag guard and PASS
  against the disjoint-branch fix. Full `--suite server` green; server build +
  link clean.
- Governance pipeline: initial OIDC-amr follow-up review found no
  CRITICAL/HIGH; a 13-agent hardening round found the security-F1 /
  consistency-S2/S3 / unhappy-UP-1/UP-2/UP-8/UP-10 / compliance-MEDIUM cluster
  fixed in that round (all findings addressed pre-merge, no residual
  CRITICAL/HIGH). The passive-lapse/`expires_at` tails also cleared
  security-guardian / authdb / cpp-safety / consistency-auditor / happy-path
  PASS; quality-engineer BLOCKING (untested step-up gate) + unhappy-path
  UP-1/UP-3 fixed; docs-writer BLOCKING (rest-api) addressed (this record +
  rest-api + authentication + audit-log + server-admin + CHANGELOG + SKILL).

## Reviewer

Governance pipeline (8 agents) + Hermes pre-submission security passes on
`feat/auth-jit-elevation`.
