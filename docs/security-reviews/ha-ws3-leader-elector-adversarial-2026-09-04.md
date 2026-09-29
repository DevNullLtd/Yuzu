# HA WS-3 slice 3.1 (LeaderElector) — self-adversarial review synthesis

**Date:** 2026-09-04 · **Target:** `feat/ha-ws3-leader-elector` (fenced `LeaderElector`
primitive, ADR-2002 §3/§6/§10) · **Panel:** Codex (empirical, `compiled`) + Kimi-K3 (static)
via `/adversarial-review-kimi`, adjudicated by the Opus orchestrator against the code.

Run after a clean 13-agent `/governance` pass (zero CRITICAL/HIGH). The self-adversarial
pass exists precisely to catch the class of blocking finding a reviewer would hit next
round — and it did, on the two core properties of the whole WS-3 workstream. Both models
independently converged on the SAME two issues (the strongest signal this process
produces), splitting only on severity.

## F1 — a follower never reconnects after its dedicated connection dies

- **Reporters:** Kimi (K1, HIGH) + Codex (CDX-2, MEDIUM), independently.
- **Verified** against the code by the orchestrator, then **empirically** by a new
  backend-termination test.
- **Defect:** `try_acquire()` reconnects only when `!open_` (top) or on the already-leader
  liveness branch (`epoch_.has_value()`). A FOLLOWER (`epoch_ == nullopt`) whose dedicated
  connection dies (failover / NAT idle-timeout / proxy restart — the events HA exists for)
  hits the try-lock-query-failure branch, which merely logged and returned `false` without
  reconnecting: `open_` stayed `true`, so the top reconnect never re-fired and every later
  call retried the same dead `PGconn`. The intended failover replica would be permanently,
  silently unable to take leadership until process restart. The leader path self-heals; the
  follower path was a missed branch. Inert at 3.1 (no caller), a real HIGH once wired (3.2).
- **Fix:** on a try-lock QUERY failure (a transport error, distinct from a `'t'`/`'f'`
  result), `drop_leadership_locked()` + `connect_locked()` best-effort, mirroring the
  leader liveness branch. Pinned by `test_leader_elector.cpp` "recovers leadership after its
  backend is terminated" (kills the elector's backend via `pg_terminate_backend`, then
  asserts a later `try_acquire()` recovers leadership and mints an epoch). Strict
  epoch monotonicity is asserted separately by the "epoch is strictly monotonic
  across handover" case, not by the F1 recovery test.

## F2 — the fence was check-then-act, not atomic with the claim

- **Reporters:** Codex (CDX-1, HIGH) + Kimi (K2, LOW), independently.
- **Defect:** the shipped fence was a standalone boolean read, `epoch_is_current(conn, name,
  epoch)` → `SELECT current_leader_epoch ... == epoch`. A claim site using it as
  `if (epoch_is_current(...)) { claim(); }` is a check-then-act race: a successor can advance
  the epoch in the window between the read returning true and the claim committing, so a
  stale ex-leader commits anyway. ADR-2002 §3 requires the epoch check to be indivisible
  from the claim's WRITE, not a separate read. (A prior Gate-7 doc fix addressed snapshot
  staleness under REPEATABLE READ but NOT the check-then-act shape — necessary but
  insufficient, as Codex noted.) Inert at 3.1, a real HIGH (security-control failure) once
  a 3.3 claim site consumes it — and the boolean API actively invites the wrong usage.
- **Decision (operator, 2026-09-04):** remove the boolean; ship an embeddable predicate.
- **Fix:** `epoch_is_current()` is deleted. `LeaderElector::epoch_fence_sql(lock_name, epoch)`
  returns an SQL boolean expression `((SELECT current_leader_epoch FROM
  leader_elector.leader_state WHERE lock_key='<name>') = <epoch>)` for the claim site (3.3)
  to embed INTO its claim's WRITE statement, so the epoch is verified atomically with the
  side effect and a stale epoch admits zero rows — the atomic same-statement fence is now the
  only possible shape. `lock_name` is inlined only after the `[a-z][a-z0-9_]{0,47}`
  validation (no quote can escape the literal) and `epoch` is an integer; an invalid name
  returns the constant-false `(1=0)` (fail-closed). Pinned by "epoch_fence_sql guards a claim
  WRITE atomically" (a guarded INSERT commits 1 row for the current epoch, 0 for a stale
  one) + the stale/no-row/invalid-name predicate cases.

## Adjudicated / refuted / deferred

- **K3 (test adequacy):** addressed — added heartbeat, follower-reconnect-recovery (pins
  F1), and distinct-lock-name (key-derivation distinctness) cases.
- **K4 (schema not created):** REFUTED — the `[pg]` tests pass, which requires
  `PgMigrationRunner` to create the `leader_elector` schema and the qualified runtime
  queries to resolve; a missing schema would fail every case hard.
- **K5 / CDX connection-timeout / liveness-under-mutex (= governance UP-1):** deferred to
  the 3.2 wire-in (a `connect_timeout`/`statement_timeout` coordination DSN + running the
  liveness probe off `mu_`), where a caller drives the loop; tracked in the governance
  ledger.
- **Fence publish window (K2 residual):** the narrow window between B's advisory-lock grant
  and B's epoch commit is inherent to a two-step fence publish; with the embedded predicate
  the claim reads the latest committed epoch at write time, and §6 effectively-once bounds
  the blast radius. Recorded as a 3.3 claim-protocol consideration.
