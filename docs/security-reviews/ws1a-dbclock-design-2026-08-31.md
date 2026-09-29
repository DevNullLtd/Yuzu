# WS-1/1a DB-clock authority — design review record (#3715)

Pre-implementation architect + security-guardian design review of the plan to make
PostgreSQL `now()` the single clock authority for durable operator sessions
(ADR-2002 §4). Reviewed the outline (option A: author via `now()`, adjudicate against a
local monotonic `steady_clock` remaining-duration deadline derived at cache-populate).
Verdict: option A is the doc-prescribed path and sound in outline, but 5 BLOCKING design
requirements must be baked in. Both reviewers independently found the suspend and
underflow hazards.

## Resolved design (v2) — the requirements the implementation MUST satisfy

1. **Author every timestamp from SQL `now()` (H1).** create, set_elevation, mark_mfa,
   touch_activity — not just create. A missed site leaves the skew hole on exactly the
   security-sensitive short windows. The store takes durations (not absolutes) and
   `RETURNING`s the authored values to seed the cache.
2. **Adjudicate the authoritative (cache-miss) path in the DB domain (B1 + H3).** `find()`
   returns `db_now_ms` as a column in the SAME atomic SELECT; absolute-expiry / idle /
   elevation / MFA are decided against `db_now_ms`, then the steady deadline is derived.
   Fail CLOSED on a degraded read — never default a missing `db_now` to 0 / created_at /
   local clock (that would extend every session).
3. **Ceilings clamp the DERIVED remaining, not merely validate the authored width (H2 —
   the sharpest finding).** A backward `now()` lowers `db_now`, inflating
   `remaining = expires − db_now`, so a stored-width `(elevated_until − issued) ≤ kMax`
   check passes while the elevation is *lived* far past 24h. Clamp:
   `remaining_elev = min(elevated_until, issued + kMaxElevationWindow) − max(db_now, issued)`;
   MFA likewise; `remaining_session = expires − max(db_now, created_at)` — which also gives
   the base lifetime its first backstop.
4. **Signed underflow guard (H4 + N2).** `db_now ≥ expires` (already expired at populate)
   fails closed BEFORE any `steady_now + remaining`, in signed arithmetic; don't cache it.
5. **Wall-clock sanity ceiling for steady_clock's suspend-blindness (S1 + H5, both
   reviewers).** `CLOCK_MONOTONIC` pauses across VM/host suspend, so a cached deadline can
   over-live. Consult the absolute `system_clock` deadline with a GENEROUS slack
   (`kWallSanitySkew`, 5 min) so a merely clock-skewed replica (steady already correct) is
   never wrongly rejected, but a gross wall jump past expiry (long suspend) is caught.

## SHOULD (folded)
- **S2** — reap: cutoff, anchor comparison, and anchor update all read ONE in-SQL `now()`
  (the domain that authored expires_at). Advisory lock already present; single-writer still
  correct — no PG-shared-state needed until a 2nd replica.
- **S3** — `create()` takes a duration-based `SessionWriteParams`, distinct from `SessionRow`,
  so a populated absolute `expires_at_ms` cannot be silently ignored. Keep a test seam for
  authoring absolute timestamps (N3 — `expire_session_for_test`).
- **S4** — elevate's dead-window guard moves into the SQL `WHERE` (`LEAST(...) > now()`),
  atomic against the row's own expiry, no wasted write / generation bump on a no-op.
- **S5** — keep the authoritative idle re-check, adjudicated in the DB domain.
- **M6** — ship a FIRING Prometheus alert on a DB-now-backward series, distinct from the
  reap counter (detection is not prevention; the H2 clamps prevent).

## Migration
None — the six columns stay `BIGINT` epoch-ms; `db_now_ms` is computed-not-stored; no 2nd
replica yet. A store-API *contract* change, not a schema one.

## Convergence signals
- Suspend-blindness of steady_clock: architect S1 + security H5, independently.
- Already-expired-at-populate underflow: architect N2 + security H4, independently.
- (These are the two strongest confidence signals in the review — found without either
  reviewer being shown the other's finding.)

## Implementation status (2026-08-31) — COMPLETE
Fully implemented across `session_store.{hpp,cpp}`, `auth.{hpp,cpp}`, `mfa_step_up.cpp`,
`server.cpp`, tests (`test_session_dbclock.cpp` + reworked `test_session_store`/jit/mfa),
and docs. All 5 BLOCKING design requirements (H1–H5) are in the code and unit-verified.
Green: `[session_store]` 198, `[jit]` 971, `[mfa]` 1680+, `[auth]` 1219, `[session_dbclock]` 31.

`/governance dev..HEAD` ran (13 reviewers + Gate 8): no CRITICAL, one HIGH (doc/comment
currency of the reap clock-anomaly semantics + the new local-clock counter) — fixed in the
Gate-7 round, which also folded the convergent MFA suspend-backstop parity (security LOW +
unhappy-path UP-2), the `kWallSanitySkew` comment accuracy (UP-1), the `find()` column-index
guard (×3 reviewers), and the no-op generation-bump (authdb LOW). Self-adversarial (Codex empirical +
Kimi static, the per-PR model-diversity gate) then ran and **caught one HIGH the 13
governance agents missed** (CDX-P1-001, converged with Kimi K4): the durable idle-touch
*persist throttle* compared the replica's local wall clock against a DB-authored timestamp,
so host skew suppressed every durable touch and would idle-out an actively-used session on
failover — the exact cross-host-skew contract this change closes. Fixed by moving the
throttle onto a monotonic `steady_last_persisted` marker. Also folded from that round: the
base-session authored-width ceiling (`kMaxSessionLifetimeMs`, K1 — converged with
unhappy-path UP-12, promoted from deferral) and the derive fail-closed-sentinel-first
reset (K2). Follow-ups filed (non-blocking): a manager-level cross-replica skew integration
test (needs an injectable clock seam — CDX-P1-002); per-replica NTP-sync monitoring for the
suspend backstop (UP-2, operational). Hermes cyber pass is the remaining high-stakes opt-in
(per the current adversarial-review-kimi convention, deep Hermes moved to release testing).
