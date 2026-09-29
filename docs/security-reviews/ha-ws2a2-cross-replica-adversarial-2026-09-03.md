# Self-adversarial synthesis — HA WS-2a-2 (Codex empirical + Kimi static, Opus adjudicator)

## VERDICT: BLOCK — one confirmed single-replica regression + a confirmed boot-window loss

Both reviewers independently reached BLOCK. Root cause (shared): **the durable-id-on-the-live-bus
was pulled into slice 1 prematurely — it delivers no slice-1 benefit and introduces regressions.**

### K1 (HIGH · CONFIRMED by orchestrator) — durable-id-on-bus is a SINGLE-REPLICA reconnect regression
Found: Kimi. Verified by me against code.
- OLD bus: `ev.id = ch->next_id++` **under the channel mutex at publish** → buffer order == id order,
  always → `Last-Event-ID` reconnect (`ev.id > since_id`) can never skip an undelivered event.
- MY change: id assigned at INSERT (`RETURNING event_id`), published post-commit → two concurrent
  same-execution agent transitions can commit+publish out of id-order → channel buffers `[101, 100]`.
  A subscriber that receives 101 and disconnects in the sub-ms window before 100 → reconnects with
  `Last-Event-ID: 101` → `100 > 101` false → **100 lost. Single replica. Not multi-replica-gated.**
- Verified: (1) old = counter-at-publish (`git show origin/dev`); (2) the PG migration REMOVED the
  old SQLite per-execution `recursive_mutex` (execution_tracker.cpp:1089) — no app-level
  serialization of concurrent same-execution append→publish. Inversion reachable. I2 · E5 → HIGH.

### C1 (HIGH · CONFIRMED) — boot→first-poll window loss (cross-replica)
Found: Codex (independent — NOT in my governance ledger). The horizon inits lazily on the FIRST poll
(~2s after boot) to the then-current xmin and returns 0, so a foreign event committing during a
replica's boot→first-poll window falls below the initialized horizon → never delivered to a
subscriber connected in that window (a LIVE gap, so slice-2 reconnect-replay can't rescue it).
Fix: initialize the horizon at CONSTRUCTION (before SSE admission), not at first poll. I2 · E4/E5 → HIGH.

### C2 / UP-1 (HIGH) — cross-replica reconnect inversion — ALREADY governance-caught + scoped
Found: Codex + Kimi (K1's multi-replica sibling) — convergence confirms the governance disposition.
Resolved by the same root fix as K1 + the deferred slice-2 durable replay (already ledgered as the
2nd-replica precondition).

## Recommended fix — Option A (revert durable-id-on-bus to slice 2)
Keep the live in-process bus on the per-channel counter (old, reconnect-safe); the poll re-publishes
foreign events with the local counter; the durable `event_id` stays in the OUTBOX for the slice-2
durable failover replay (where cross-replica cursor stability belongs, paired with id-ordered
delivery). Plus: init the horizon at CONSTRUCTION (C1). This ALSO removes the enterprise-readiness
id-space breaking change (the SSE id stays a per-channel counter — no consumer breakage, simpler docs).

## Non-blocking (deferred/documented)
- C3 (MED) LISTEN/NOTIFY absent — deferred optimization (architect agreed poll is the substrate).
- K2 (LOW) ambiguous-commit + skip-own: an origin-replica committed-but-unpublished row is skip-own-
  excluded on its own poll → live-tail gap on one replica, healed by reconnect/retry. Document.
- K3 (LOW) migration-backfill rows carry `origin_replica=''` → re-published by every replica's poll
  during a rolling deploy (stale-event flood, dup-tolerated). Fix: sentinel origin on backfill rows.
- K6 (LOW) degrade counter now fires at 2s (poll) vs 60s (reap) cadence under one series → alerts
  tuned for reap mis-fire. Separate `yuzu_exec_outbox_poll_degrade_total` (== consistency/architect
  stage-label). Follow-up.
- K4 REFUTED: per-test ephemeral DBs isolate rows (only server-global xmin is shared); no cross-talk.
- K5 resolved by Option A (no id-domain mixing when the bus is all-counter).
- C4/K7 test gaps: add boot-window + id-inversion + full-batch cases with the fix.

## What each ran
Codex: compiled (`meson compile tests`), ran `[execution_event_bus]` (1613 assert pass); `[pg][outbox]`
SKIPPED in its sandbox (no `YUZU_TEST_POSTGRES_DSN`) — they pass here. Codex opened the committed
governance.d ledger mid-run (self-reported Phase-1 contamination); C1 is NOT in that ledger, so it is
an independent find. Kimi: static-only over the code bundle; one Ollama 500 then clean on retry.
