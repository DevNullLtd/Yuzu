# Security review — Inactivity (idle) session timeout (SOC 2 CC6.3)

> ⚠️ **Superseded in part by HA WS-1/1a (ADR-2002 §4).** This review describes
> `last_activity_at` as a monotonic `steady_clock` stamp held only in memory. As
> of HA WS-1/1a it is wall-clock (`system_clock`) and durably mirrored to the
> `SessionStore` row via `touch_activity` (which deliberately does not bump the
> validate-cache generation), so the idle window survives a restart and ages a
> session consistently on any replica. See `docs/auth-architecture.md` "Durable
> operator sessions".

**Date:** 2026-06-30
**Change:** `--session-inactivity-secs` — a sliding idle-timeout for operator
dashboard cookie sessions, under the absolute 8h session lifetime. Wires the
previously-reserved `sessions.last_activity_at` column end-to-end.
**Branch:** `feat/auth-inactivity-timeout`
**Control:** SOC 2 **CC6.3** (logical access — session inactivity timeout).
Closes `/auth-and-authz` gap-matrix **P1 #8**.

## What shipped

- **`--session-inactivity-secs`** (`YUZU_SESSION_INACTIVITY_SECS`,
  `Config::session_inactivity_secs`), **default 0 = disabled** (opt-in; existing
  deployments unaffected; recommended 900). Boot posture logged for evidence.
- Enforced in `AuthManager::validate_session` against the **in-memory** `Session`
  (the authoritative read path — `auth.db` sessions are v1 dead-writes): a
  monotonic `steady_clock` `last_activity_at` is slid forward on authenticated
  touches and the session is rejected + evicted once idle past the window, under
  the absolute `kSessionDuration` (8h).
- **Scope: cookie sessions only.** API and MCP tokens resolve via
  `synthesize_token_session`, never `validate_session`, so long-lived automation
  credentials are **never** idle-timed-out (structurally enforced, not just
  documented).
- Best-effort, throttled `auth.db` mirror (`AuthDB::touch_session_activity`,
  ≤1 write/session/60 s, off the `mu_` lock). No migration (column pre-exists).

## Threats / design decisions

- **No auth weakening.** The absolute `expires_at` check is unchanged and runs
  first; the idle path only ever *adds* a rejection. Idle-disabled (default) is
  byte-identical to prior behaviour.
- **Monotonic window.** _[SUPERSEDED by HA WS-1/1a — see the top banner: since
  ADR-2002 §4 `last_activity_at` is durable wall-clock (`system_clock`), not
  `steady_clock`. The line below describes the pre-HA design.]_ `steady_clock`
  throughout — an NTP/system-clock step can neither extend nor collapse the window.
- **No session-resurrection / UAF.** The shared→unique lock upgrade copies the
  `Session` before releasing the shared lock and re-`find`s the token under the
  write lock; an evict re-checks idle-ness (a concurrent boundary refresh keeps
  the session alive); a raced erase returns `nullopt`. Verified by cpp-safety +
  security-guardian.
- **Snapshot-and-release.** The `auth.db` mirror write happens outside `mu_`; a
  best-effort failure can never affect an access decision (in-memory map is
  authoritative).
- **Touch throttle (governance UP-1/UP-2).** Sliding the window needs the
  exclusive lock, so an unconditional per-request touch would serialise all
  dashboard auth when the feature is on. The touch is throttled to once per
  `touch_granularity` (window/4, cap 30 s) so active-session requests stay on the
  shared lock; `last_activity_at` lags real activity by at most the granularity,
  far inside any minutes-scale window, so an active session is never wrongly
  evicted (idle-out fires within `[window − granularity, window]`).

## Residual / accepted

- **Boundary spurious-401 (LOW, accepted).** A request that observes the session
  idle is rejected even if a concurrent request refreshes it at the exact
  boundary (the session itself survives). Fails safe → the browser re-auths.
- **Sub-60s windows: durable mirror lag (NICE).** With a window < 60 s the
  `auth.db` `last_activity_at` mirror trails the in-memory stamp by up to 60 s.
  Harmless — the in-memory value is authoritative.
- **Test seams (deferred follow-up).** The 60 s persist-throttle and the
  absolute-vs-idle interaction need injectable seams to unit-test end-to-end; the
  core idle behaviour (disabled-survives / idle-evict / sliding-keep-alive /
  best-effort mirror) is covered in `test_auth.cpp [idle]`.
- **Future v2 session-rehydration** must stamp `last_activity_at` on any Session
  it inserts into `sessions_` (the `{}` epoch default is fail-closed → instant
  idle-evict). Documented as an invariant on the `Session` field.

## Validation

Full auth suite green (1497 assertions); server build + link clean. Governance
pipeline (9 agents): no BLOCKING/CRITICAL/HIGH; the UP-1/UP-2 lock-contention
SHOULD is addressed by the touch throttle above; docs + test-hygiene SHOULDs
addressed.

## Reviewer

Governance pipeline (security-guardian, cpp-safety, cpp-expert, authdb,
consistency-auditor, unhappy-path, happy-path, quality-engineer, docs-writer) on
`feat/auth-inactivity-timeout`.
