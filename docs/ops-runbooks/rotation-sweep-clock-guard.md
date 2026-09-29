# Runbook: rotation-sweep clock guard

Covers the `YuzuRotationSweep*` alert family (`docs/prometheus/yuzu-alerts.yml`)
for `ApiTokenStore::sweep_expired_rotations` — the 60-second background sweep
that auto-revokes rotation predecessors for **both** engine-credential and
human API-token overlap pairs (#2964). Background: the routed
clock-guarded-retention concern in CLAUDE.md, `docs/user-manual/authentication.md`
"Rotating a Token", `docs/user-manual/engine-principals.md` "Rotate the
credential".

> **Read this first.** As with the audit-store rules, these are not active
> unless you wired `docs/prometheus/yuzu-alerts.yml` into a running Prometheus
> and pointed it at an Alertmanager — see
> `docs/ops-runbooks/audit-store-clock-guard.md`'s own note, which applies
> identically here.

## Why this matters more than a quiet counter suggests

This sweep is the **sole** enforcement of predecessor auto-revoke — the only
thing that ends a predecessor credential's life once its overlap window
elapses, for a caller who never calls `confirm` explicitly. A wedged
store-wide advisory lock (the same lock every replica's sweep takes before it
will classify a tick) stops it fleet-wide, and every *other* signal on the
fleet — agent heartbeats, command throughput, HTTP request rates — stays
green throughout, because nothing about a stuck rotation sweep touches any of
them. The counters below are what actually observe it.

## The decision rule, briefly, and where it actually lives

Every tick reads PostgreSQL's own clock (never this process's), compares it
against a durable per-database anchor (`api_token_store.rotation_retention_meta`,
key `last_pass_now`), and classifies the tick through the same
`audit_retention_rules.hpp::classify` pair `audit_store` uses — reused, not
forked. This page deliberately does not restate that rule, the same way
`docs/user-manual/audit-log.md` and `docs/user-manual/tar.md` do not for their
own clock guards — the canonical, tested definition is `classify()` itself and
`ApiTokenStore::sweep_expired_rotations` (`api_token_store.cpp`), pinned by
`tests/unit/server/test_api_token_store.cpp`. What differs from `audit_store`
worth knowing before you triage:

- **Single-writer by construction, not just by convention.** Before
  classifying anything, the sweep takes a store-wide **session** advisory
  lock (its own key namespace — never `hashtext(principal_id)`) so only one
  replica classifies and mutates per tick. `audit_store` has no equivalent —
  it is not (yet) a multi-replica-safe pass in the same sense.
- **A missing anchor DECLINES**, same answer as `audit_store`'s bootstrap
  case, for the same reason: a rotation sweep that revokes on an unverified
  clock is worse than a pair staying open one more 60-second tick.
- **The scope is different.** `audit_store` probes over every datable row.
  This sweep probes only the **eligible** set — pairs with a live, used
  successor — because a pair whose successor was never used is *permanently*
  ineligible (see "Unless the successor was never presented at all" in the
  two user-manual pages above) and must never influence what this sweep
  decides to touch.
- **No would-wipe detection**, unlike `audit_store`. This sweep's eligible
  population is a drain queue that reaches 100% expiry as a matter of
  routine course (every deployment's first in-flight rotation does, the
  moment its overlap window elapses on a perfectly correct clock) —
  a would-wipe verdict cannot distinguish that routine case from a genuine
  clock jump at any population size, so `api_token_store.cpp` deliberately
  does not adopt that half of the routed clock-guarded-retention concern
  (see the DELIBERATE NON-ADOPTION comment near `kRotationSweepBigStepSecs`'s
  definition). `yuzu_rotation_sweep_declined_total` can only be a big-step
  or bad-state decline here, never a would-wipe one.

## `yuzu_rotation_sweep_lock_skipped_total` — read your replica count first

**On a single-replica deployment (the default), this counter must stay at
exactly `0`, always.** One thread taking one lock once per 60-second tick can
never legitimately lose an election against itself — there is no second
contender. Any non-zero reading on a single-replica install is a fault, not
routine contention: a leaked session-scoped advisory lock from a previous
crashed process (the RAII release guard is exception-safe, but a
`kill -9`/OOM does not run destructors), a stuck advisory lock held by an
unrelated session against the same database, or — less likely — two sweep
loops somehow running in one process. Check
`SELECT * FROM pg_locks WHERE locktype = 'advisory';` on the DSN the server
uses; a session lock with no corresponding live server backend is the leaked
case, and `pg_terminate_backend()` on that backend (identify it first — this
is a shared production database) clears it.

**On a genuinely multi-replica deployment**, a nonzero, roughly
`(replica_count - 1) / replica_count` steady-state rate is expected and
healthy — it is exactly what "one replica wins the lock per tick" looks like
under N contenders. What is NOT expected there either: EVERY replica reading
nonzero on every tick for an extended period with none of them ever
completing a classification (check `yuzu_rotation_sweep_declined_total` /
`yuzu_engine_principal_rotation_sweep_failures_total` / auto-revoked counters
for signs any replica ever won) — that shape means either a leaked lock (as
above) or a replica count Prometheus does not know, and needs the same
`pg_locks` check.

## `yuzu_rotation_sweep_declined_total` — a tick declined, nothing was revoked

**Nothing was auto-revoked** on a declined tick — both credentials in every
affected pair stay active for at least this tick, which is the entire point
of the guard (a clock-driven revocation on an unverified reading is worse
than a predecessor staying valid slightly longer than promised). Because
fact-set dedup only suppresses a *repeat of the identical* anomaly, an
ordinary transient decline is bounded to roughly **one 60-second tick** — the
next tick either has a comparison point (the bootstrap case) or a
newly-plausible clock reading (the anomaly case) and proceeds.

1. Read the `spdlog::warn` line at the point of decline — it names which case
   fired (`decline_reason` on the typed `SweepOutcome::Declined` result) and
   states the cost in the same sentence. Do not infer the cause from the
   counter alone. For a big-step/bad-state decline, `decline_reason` also
   carries the raw `prev`, `pg_now`, and their delta (`facts=...,
   prev=..., pg_now=..., delta=...`) — read these before reaching for
   `pg_locks`/`rotation_retention_meta`, they are often enough on their own
   to tell a real clock jump (a huge, implausible delta) from an ordinary
   outage (a delta a little over one hour).
2. **A big-step decline is NOT proof the clock moved — check for a
   multi-tick gap FIRST.** At this sweep's 3600s big-step threshold, the
   single most common trigger is a perfectly correct clock that simply
   didn't reach a verdict for over an hour: a maintenance window, a
   database failover, a server restart, or a dev/staging instance left off
   overnight all produce the IDENTICAL log line and fact set
   (`decline_reason`'s `facts=...` payload) as a genuine forward clock
   jump — the guard cannot and does not distinguish the two on its own.
   Check the server's own uptime/restart history and any known maintenance
   window BEFORE concluding the clock moved; the `delta` value from step 1
   only tells you HOW FAR the reading moved, not WHY.
3. Only once a multi-tick outage is ruled out, check PostgreSQL's OWN
   clock — the same first step as `YuzuAuditRetentionClockAnomaly`
   (`docs/ops-runbooks/audit-store-clock-guard.md`) — since this sweep reads
   the identical `SELECT EXTRACT(EPOCH FROM now())` on the same server. A
   fault on the Postgres host affects both guards simultaneously; if only
   this one is declining, look at `api_token_store.rotation_retention_meta`
   specifically (`SELECT * FROM api_token_store.rotation_retention_meta;`),
   not the audit store's own anchor table — they are independent rows. That
   table's `last_anomaly_facts` row is a single-row upsert holding the
   MOST RECENT declined fact set only, never a history of past declines —
   do not expect to find prior anomalies there once a later one has landed.
4. If the reason names the bootstrap case (no durable anchor yet, with
   already-eligible predecessors), expect this **at most once per database**
   — the declining tick also settles `rotation_retention_meta.bootstrap_settled`
   (key `bootstrap_settled`), so the next tick proceeds with a comparison
   point. A repeat is the anchor not surviving between ticks (same triage as
   `YuzuAuditRetentionAnchorNotSurviving`) — check whether
   `rotation_retention_meta` is being restored/rolled back independently of
   the rest of `api_token_store`.
5. **A declined tick is not free even though it is safe.** A pair whose
   successor HAS been used stays valid past its promised overlap window for
   at least one more tick — read that as extended exposure to a possibly
   compromised predecessor credential, not as a no-op.

## `YuzuRotationSweepLockContentionUnexpected` — a second writer, on a deployment that should have one

**Single-replica-scoped, by design of the rule, not by nature of the
metric.** This alert exists because on a single-replica deployment (the
default), `yuzu_rotation_sweep_lock_skipped_total` moving at all is already
diagnostic on its own — see the metric's own section above — and a repeated,
sustained rise there means a genuine second writer, not routine contention.
Work the `pg_locks` procedure above: identify the holding backend, confirm
whether it belongs to a Yuzu server you can stop cleanly (its own shutdown
releases the lock through the same RAII guard an ordinary sweep tick does)
before considering `pg_terminate_backend()` on it.

**If you run a genuinely multi-replica deployment, this alert is not for
you as shipped** — the expression pages on `> 1` skip in 15 minutes, which a
healthy N-replica deployment produces routinely on every replica that does
not win a given tick's election. Disable this specific rule, or replace it
with one gated on your actual replica count once such a signal exists (none
does in this rule set today — see the rule's own comment for why one was not
invented here).

## `YuzuRotationSweepNotRunning` — the liveness gap this family cannot close alone

An accepted, un-capped, un-declined tick — the ordinary healthy case —
increments **none** of the counters above. A sweep thread that has silently
died (an uncaught exception past the loop's own catch, a deadlock acquiring
the connection pool before the try block) is invisible to every counter on
this page, exactly the `audit_store` "silence means healthy" trap. This
alert closes it the same way `YuzuAuditRetentionNotRunning` does for
`audit_store`, but on the gauge (`yuzu_rotation_sweep_last_pass_timestamp_seconds`,
pre-seeded to `0` at boot) rather than a passes-attempted counter (this sweep
has no unconditional "tick happened" counter) — see [metrics.md →
Rotation-sweep clock guard
metrics](../user-manual/metrics.md#rotation-sweep-clock-guard-metrics-2964)
for the full reference.

The gauge proves the classification transaction reached a verdict (`Ok` or
`Declined`) — it does **not** prove any predecessor was actually revoked. An
accepted tick that loses some or all of its per-pair revoke transactions to
pool contention still stamps this gauge fresh on schedule; check
`yuzu_rotation_sweep_lost_revocations_total` for that separate failure mode
before concluding "gauge is fresh, so revocation is working".

If this fires, first rule out the case where there is no server log line to
find at all: a migration whose reported success was actually a silent skip
(e.g. a migration-numbering collision, #3013) leaves `rotation_retention_meta`
missing, `ApiTokenStore`'s own post-migration smoke-read catches that at
construction, and (ADR-0012 §1) **the whole server refuses to start** — not
merely "the sweep thread never starts while the rest of the server serves".
This is a BOOT failure, not a runtime one: there is no `sweep_expired_
rotations:` failure line to grep for, because the process never got far
enough to run a tick, and no gauge goes stale, because the process metrics
endpoint itself is down. The actual signature is the scrape target reporting
`up == 0` (or the process simply not being there to `curl /metrics` at all),
not this alert on its own — check whether the server process is running and
the boot log for "Refusing to start: api-token store migration/open failed"
before treating this as a live-but-stuck sweep.

Only once you have confirmed the server IS up and serving should you look
for the hypothetical RUNTIME variant of the same defect — e.g. an
out-of-band `DROP TABLE api_token_store.rotation_retention_meta` after a
successful boot, which the construction-time smoke-read cannot see. THAT
case looks the way this section used to describe: check the server log for
`sweep_expired_rotations:` failure lines (`fail_reason` on the returned
`SweepResult` carries the actual libpq error text and failing stage — the
`S-SWEEP-EXCEPTION-GUARD` catch in `server.cpp` logs and continues rather
than crashing the process, so a repeatedly-throwing tick reads as this
alert, not a restart), and confirm "ApiTokenStore: opened" and "Rotation
sweep thread started" both appear in the (now-relevant, because the server
did boot) server log.

## Verifying recovery

```
yuzu_rotation_sweep_declined_total       # stops increasing
yuzu_rotation_sweep_lock_skipped_total   # back to 0 (single-replica) or its steady multi-replica rate
```

Also confirm the auto-revoked counters
(`yuzu_engine_principal_rotation_auto_revoked_total` /
`yuzu_api_token_rotation_auto_revoked_total`) are moving again if there is a
known backlog of elapsed pairs — a declined tick leaves them flat, and that
flatness is expected while declined, not a second fault.
