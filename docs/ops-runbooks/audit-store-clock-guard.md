# Runbook: audit store health - retention clock guard and write path

Covers the `YuzuAuditRetention*` alert family and `YuzuAuditPersistFailures`
(`docs/prometheus/yuzu-alerts.yml`) - i.e. `audit_store` health (PostgreSQL,
ADR-0040), both the write path and the retention path. `YuzuAuditReadDegraded`
is the other alert in this family; it has its own `runbook_url`
(`audit-log.md#storage`) and is deliberately not duplicated here.
(`YuzuAuditBackfillFailing` was retired alongside `migrate_from_sqlite()`
itself, #3623, ADR-0009 hard-cutover Update, 2026-09-04.)
Background: `docs/user-manual/audit-log.md`, ADR-0040, issue #2360.

> **Read this first.** These rules are NOT active unless you wired them up.
> `deploy/prometheus/prometheus.yml` reads `/etc/prometheus/rules/*.yml`, but no
> shipped compose file mounts `docs/prometheus/yuzu-alerts.yml` there, and the
> repo ships no Alertmanager configuration. Until you mount the rules and point
> Prometheus at an Alertmanager, the `severity:` labels below route nowhere and
> the guard's only durable signal is a counter nobody is watching. Wiring that up
> is a prerequisite for treating any of this as a SOC 2 detective control.

## The retention guard, in one paragraph

(For the write path, see the `YuzuAuditPersistFailures` section below.)

`audit_events` rows expire on a TTL. Since #2360/1d the DECISION clock is
PostgreSQL's own (`SELECT EXTRACT(EPOCH FROM now())`, read inside the
advisory-lock transaction every sweeping replica already serialises through) —
not any one replica's process clock. A forward jump in PostgreSQL's own clock
makes every row look expired at once, and the delete that follows takes the
whole retained window. The guard bounds that: a pass it will not trust DECLINES
and deletes nothing, and every pass it accepts is capped at 25,000 rows.

**Why a pass declined, and whether it is expected, is answered elsewhere:** the
"Was this expected?" ladder in
[The retention clock guard](../user-manual/audit-log.md#the-retention-clock-guard).
This page deliberately does not restate the rule - restating it is what put a
wrong trigger list here before. For what actually fired on a given alert, read
the log line (step 3 below); it names its own trigger.

**It bounds the blast radius; it does not prevent loss.** A sustained clock or
operational fault, left unaddressed, drains at whichever cadence the guard is
currently paced at — see [Capacity](../user-manual/audit-log.md#capacity) for
both cadences; do not assume the slower one. The alert is the control. The
guard is the seatbelt.

**The bootstrap decline (#2579), and why it is not one of your alerts.** A pass
that begins with NO stored clock reading while rows are already expired declines
once, warns, and anchors the reading - it cannot tell whether the clock was wrong
before the guard ever ran, so it holds back rather than delete. That decline
raises `yuzu_server_audit_retention_bootstrap_declines_total` and NOT the
clock-anomaly series, deliberately: it makes no claim that the clock moved, so it
must not fire an alert that says one did. Expect 0 or 1 per database, typically on
first boot against a fresh `audit_store` schema. A value that keeps climbing means
the anchor is not surviving, and `YuzuAuditRetentionAnchorNotSurviving` (below)
fires on it — triage is stated there rather than here so it has one home. The
full trigger list and the reasoning behind these signals live on the canonical
page: [Limits](../user-manual/audit-log.md#the-retention-clock-guard).

## YuzuAuditPersistFailures - audit WRITES are failing

Not a retention problem, and much louder than one:
`yuzu_server_audit_emit_failed_total` is rising, so events are not reaching
PostgreSQL (schema `audit_store`) at all. Behavioural-PII REST routes
are fail-closed, so they are returning `503` while this persists, and the
evidence for whatever is happening right now is not being recorded.

Check, in order: `/healthz` `stores.audit` (a failed migration or an
unreachable `--postgres-dsn` closes the store — the log says so explicitly);
`pg_stat_activity` / connection-pool saturation on the PostgreSQL server; disk
space on the PostgreSQL data volume (not this process's local disk — there is
no local audit file to run out of space on post-cutover); and Postgres errors
in the server log (`PQerrorMessage` text is included in every `AuditStore`
error line). Retention alerts may be silent throughout - a closed store does
not run passes.

**If behavioural-data routes are returning 503 but this counter is FLAT**, look
for a `bad_alloc`-class throw in the audit pipeline instead. That path fails
closed the same way but is only warn-logged, never counted, so the counter
cannot see it.

## YuzuAuditRetentionClockAnomaly - a pass declined

**Nothing was deleted** (the transactional guarantee — see
[The retention clock guard](../user-manual/audit-log.md#the-retention-clock-guard)'s
metrics table, `yuzu_server_audit_cleanup_failed_total` row, for the one
exception: a post-commit exception at the thread boundary, which is not this
alert's trigger). You have time; do not rush a fix that deletes more.

1. Confirm PostgreSQL's OWN clock — not necessarily this server process's OS
   clock, since #2360/1d the decision reads `now()` on the PostgreSQL server,
   which may be a different host. `SELECT now(), extract(epoch from now());`
   against the same DSN, compared to a trusted time source. Look for a large
   offset or a recent step on the PostgreSQL host specifically.
2. If the PostgreSQL server's clock is fine, another trigger is elapsed time.
   Was PostgreSQL down, failed over, or restored from a snapshot more than 7
   days ago (`kAuditMinBigStepSec`, `audit_store.hpp`)? Elapsed time cannot
   distinguish a clock jump from an outage, which is why the decline message
   below covers both.
3. Read the log line — `spdlog::warn` at the point of decline, one of exactly
   two shapes (grep these, not internal enum names, which are never printed):
   - `"no usable previous retention clock reading and rows are already
     expired"` — the bootstrap decline (#2579). Counted separately
     (`bootstrap_declines_total`, not `clock_anomaly_skips_total`) and cannot
     be what fired THIS alert; see the section above instead.
   - `"retention clock anomaly (facts=XXXXX)"` — every OTHER decline, where
     `XXXXX` is a 5-character fact code from `serialize_facts`
     (`audit_store.cpp`), one letter per position or `-` if false, in this
     fixed order: `e`=has_expired, `w`=would_wipe, `s`=big_step (the elapsed-
     time/#2360 step detector), `u`=prev_unusable (the stored reading itself
     was corrupt/unparseable/ahead-of-clock), `b`=no_anchor. The WINNING
     reason (what `classify()` actually declined on) is the highest-precedence
     true flag: `u` first (BadState), then `s` (Step), then `w` (Wipe), then
     `b` (NoAnchor) — see `audit_retention_rules.hpp`'s own doc comment for
     why that order. Example: `facts=ews--` means expired + would-wipe + a
     step both fired; the step (`s`) is what actually decided it, per
     precedence, even though would-wipe (`w`) is also true.
4. If the code is `u` (prev_unusable), the STORED value in
   `audit_store.audit_retention_meta` (key `last_pass_now`) is corrupt,
   negative, or ahead of PostgreSQL's own clock — inspect it directly:
   `SELECT value FROM audit_store.audit_retention_meta WHERE key =
   'last_pass_now';`. This is durable, shared, fleet-wide state; hand-editing
   it is the escalation path in step 6, not a first response.

**Action:** address whichever cause step 3's code identified - a clock fault
on the PostgreSQL host needs time sync there specifically, not necessarily on
this app server; a recent `audit_retention_days` reduction needs nothing (it
can also produce `w`). The next identical-fact-set pass then drains, paced by
the cap — see [Capacity](../user-manual/audit-log.md#capacity) for how fast.
If the clock was genuinely wrong, decide before it drains whether the
already-expired rows should be preserved - page the window out through
`/api/audit` per
[Protecting evidence right now](../user-manual/audit-log.md#the-retention-clock-guard),
which works on any deployment. A raw PostgreSQL-level snapshot/backup taken
through your normal DR tooling is safe here (unlike the retired SQLite store,
there is no local WAL-tearing hazard for an app-level operator to worry about
— that risk moved to whatever backs up PostgreSQL itself, and is out of this
runbook's scope).

**If declines REPEAT with a DIFFERENT fact code each time, step 1 is not
sufficient on its own.** Work the "Was this expected?" ladder on the canonical
page before concluding the clock is fine:
[The retention clock guard](../user-manual/audit-log.md#the-retention-clock-guard).
**Escalate** once that ladder is exhausted: a corrupt or hand-edited
`audit_retention_meta` reading is durable, fleet-shared state living in the
same database as the evidence — treat editing it with the same care as
editing the evidence itself.

## YuzuAuditRetentionFailing - passes are erroring

Passes are being ATTEMPTED and are erroring. This does NOT mean nothing was
deleted (see the qualification linked at the top of the clock-anomaly section
above — a post-delete probe failure specifically can follow a committed
delete), and it is NOT the reaper stopping - that is
`YuzuAuditRetentionNotRunning`, a separate rule. Check the
server log for the specific `AuditStore: reap ... failed` line (each names
which statement failed and includes `PQerrorMessage`), then PostgreSQL health:
disk space, connection-pool saturation, and whether a failed migration closed
the store (in which case audit WRITES are also failing and behavioural-PII
routes are returning 503 - a much louder problem, see
`YuzuAuditPersistFailures` above).

## YuzuAuditRetentionCapBinding - the backlog is outrunning the drain

**Not a fixed-cadence problem — read [Capacity](../user-manual/audit-log.md#capacity)
before doing anything else.** An earlier revision of this section assumed the
cap paces at a fixed 25,000-rows-per-hour rate with "no runtime lever" and told
an operator to compute a drain-time estimate from that figure. That assumption
was wrong: once a backlog forms, the guard re-arms in 5 seconds instead of an
hour (`kAuditBacklogRearmSec`, `audit_store.hpp`) and keeps doing so every pass
until it clears — a real backlog drains roughly three orders of magnitude
faster than the old estimate implied. This alert firing (sustained for the
full `for:` window, not a single capped pass — see the alert's own comment for
why) means even THAT faster cadence is not keeping up with this fleet's
sustained write rate.

Size the problem first:
```sql
SELECT COUNT(*) FROM audit_store.audit_events
WHERE ttl_expires_at > 0 AND ttl_expires_at < extract(epoch from now())::bigint;
```
then check `yuzu_server_audit_rows_deleted_total`'s rate against that count to
see whether it is closing (backlog-recovery mode draining, working as
designed — the alert can still be firing while this is true, since `for: 30m`
requires sustained capping, not a stalled drain) or flat/growing (the fleet's
sustained write rate genuinely exceeds the backlog-recovery ceiling — open an
engineering ticket; both the per-pass cap and the re-arm floor are
compile-time constants with no runtime lever).

## YuzuServerRestartLoop

The server process has restarted more than 3 times in the last 3 hours
(`resets(yuzu_server_uptime_seconds[3h]) > 3`, `for: 15m`). This is a
process-health signal, not evidence of any specific subsystem fault — it fired
before this alert existed too, but only as a silent grace-exclusion buried
inside `YuzuAuditRetentionNotRunning` below (#2854). It stands alone now,
which is what let that rule's grace collapse to a database-state check
(#2854 rung D) without losing this detection.

**See restart history directly** rather than trusting only the alert:
`journalctl --list-boots`, the orchestrator's restart count, or graph
`yuzu_server_uptime_seconds` — a sawtooth is the signature; each drop back
near zero is a restart.

**Likely causes, roughly in order of frequency:** an unhandled exception or
crash during startup or under load (check the process log / systemd journal /
container log around each restart timestamp for the crash signature); an
OOM-kill (check `dmesg` / the orchestrator's eviction events); a failed boot
precondition that causes the process to exit deliberately rather than serve
with a known-bad state (an `AuditStore` schema-migration/open failure is one
such precondition — any fail-closed startup check can produce this same
restart signature); or a supervisor/orchestrator
misconfiguration causing healthy-but-unwanted restarts (an aggressive
liveness-probe timeout, a config-reload path that restarts instead of
reloading).

**Quiet is not the same as "not restarting."** The threshold is deliberately
placed so an install followed by a couple of config-fix restarts, or a steady
hourly restart cadence, does not page — see the threshold derivation comment
above the rule in `docs/prometheus/yuzu-alerts.yml`. A server restarting once
an hour is not covered by this alert at all; if that cadence itself is a
concern, it needs its own investigation, not a lowered threshold here (a
lower threshold pages the ordinary install-plus-fix case too — see the
promtool cases pinning that trade).

**Unstable target identity silences this alert entirely.** `resets()` needs
one continuous series per server. If a restart changes the `instance` label —
dynamic-port or IP-based service discovery, a rescheduled pod — every restart
starts a fresh series with no resets, and this alert goes silent exactly
where a crash loop is most likely. (The retention liveness rules below are
immune: their stamp-based grace reads a value, not a series history.) That is
a scrape-configuration problem, not a rule problem: target a stable identity.

**Two more silences worth knowing about, neither fixable in PromQL:**

- **After a Prometheus restart, a fresh TSDB, a new HA replica, or applying
  this rules file for the first time,** an *actively ongoing* crash loop can
  stay quiet for up to roughly `4 x cadence + 15m` (~2h15m at the 30-minute
  flagship cadence) before enough fresh resets accumulate in the trailing
  window to fire again. Don't read a quiet alert in the ~3h after any of
  those events as evidence the loop stopped — check restart history directly
  (above) instead.
- **A crash loop faster than the metrics-sweep tick that writes
  `yuzu_server_uptime_seconds`** can leave this alert **permanently** silent,
  not just delayed — the gauge is written at most once per boot, so
  `resets()` never sees more than a handful of transitions no matter how long
  the loop runs. There is no dead-man's-switch (`up == 0`) rule for the
  server process in this file today (tracked: #2956); if the process is
  unreachable outright, rely on `up{job="yuzu"}` / your scrape-health
  dashboard, not this alert.

**This alert and `YuzuAuditRetentionNotRunning` can legitimately disagree.**
They key on different facts: this one on restart frequency (`> 3` in the
window, boundary exclusive), the retention rule on the audit database's own
state (anchored, zero passes), which fires at ANY restart count. So a stalled
reaper on a server with 2 or 3 resets fires the retention rule while this
alert stays quiet. Seeing `YuzuAuditRetentionNotRunning` fire alone is not
evidence that a restart loop isn't the cause; check
`resets(yuzu_server_uptime_seconds[3h])` yourself rather than inferring it
from which alerts are firing.

## YuzuAuditRetentionNotRunning

No retention pass has been ATTEMPTED for three hours. This is the one failure the
other rules in this family cannot report: they all key on a counter rising, and
nothing is running to raise one, so the store looks identical to a quiet healthy
one while `audit_store.audit_events` grows without bound and the configured
window stops being enforced.

**First: was this expected?** Three routine, self-clearing causes account for a
firing that needs no action. All three share one shape — Prometheus, not the
server, lost the history.

- **Prometheus was restarted, or its TSDB is fresh.** `increase()` over a
  PARTIAL range returns 0, and the grace watches the DATABASE's history (the
  stamp gauge, non-zero on any server that has ever completed a pass), not
  Prometheus's, so it does not apply. A healthy long-lived server whose last
  hourly pass predates the first scrape is indistinguishable from a dead
  reaper until a pass lands inside the new window.
- **A new HA replica joined**, which is the same thing from the replica's side.
- **You applied this rules file for the first time.**

In all three the alert clears the moment the next pass lands. **Measured: about
45 minutes**, bounded by the 60-minute cleanup interval rather than by anything
this rule controls. (Do not re-derive that as `for:` plus the interval — `for:`
delays when firing STARTS, it does not extend the end, and adding the two is the
arithmetic that produced an earlier wrong "~75 minutes".) If the
firing began within an hour of a Prometheus restart and clears on its own inside
that window, it was this. **If it does NOT clear, it was never this** — carry on
below.

**A resolution now normally IS recovery — but confirm it.** Before #2854 rung D
this rule could resolve and re-fire on a still-dead reaper (measured: as little
as 2 minutes firing per 162-minute restart cycle). The stamp-based grace closed
that structurally: on an anchored database with a dead reaper the expression
holds continuously, so the alert stays firing until a pass actually lands. The
one remaining way to see a resolution without recovery is Prometheus-side — a
scrape gap going stale, a restart clipping the window — so still confirm by
seeing `yuzu_server_audit_retention_passes_total` actually RISE, not only by
seeing the alert go away.

Check that the store opened at boot (a failed migration closes it, and
`start_cleanup()` then early-returns), and look for `AuditStore: retention pass
threw` in the log. The rule's only grace is a 3-hour window carrying no
evidence of any pass — every stamp sample `0` or the unreadable-anchor
sentinel, with at least one `0` — which is `YuzuAuditRetentionNeverRan`'s
state below (the cleanup thread sleeps a full interval before its first pass,
so a fresh install legitimately has no pass yet). The grace reads the whole window, not the instant sample, and it
is EXACTLY `YuzuAuditRetentionNeverRan`'s firing condition, so at every
instant every window shape is owned by exactly one of the pair (a
phase-locked oscillation between the two owners faster than either `for:`
can still starve both — a measured, filed corner; see the rules-file
comment): any evidence of a pass — a genuine
positive stamp OR a dead-CMOS negative one — anywhere in 3 hours lifts the
grace for a full window (an anchor-loss flap mixing `0` with either kind of
real stamp fires HERE), a window of only sentinels fires here too (nothing
rules a dead reaper out), and only windows of zeros-and-sentinels belong to
`YuzuAuditRetentionNeverRan`. A crash-looping server on an anchored database
fires here at EVERY restart cadence. The retired uptime
grace's blind band (164-195 minute cadences, plus an intermittent-firing gap
from ~90 minutes) is closed; the coverage claim is machine-checked on every PR
against `tests/prometheus/blind_band_manifest.json` (empty = fully covered;
method: `docs/prometheus/blind-band-measurement.md`), so read the manifest, not
this paragraph, as the current truth. If the alert is firing on a young server,
the database is anchored and the reaper genuinely has not run for 3 hours —
check whether the process is crash-looping before its first pass can land:
`resets(yuzu_server_uptime_seconds[3h])`.

**If the stamp series is FLAPPING between `0` and another value** (graph
it), the cause is the anchor row itself appearing and disappearing — a
restore loop, a replica template, or a relabel collision merging two servers
— not the reaper alone: triage the anchor first (`SELECT value FROM
audit_store.audit_retention_meta WHERE key = 'last_pass_now';` per server)
alongside the reaper checks above.

**Before assuming a crash loop, check the stamp series exists.** If
`yuzu_server_audit_retention_last_pass_unixtime` returns nothing for this
instance, the rule fired on its absent-series arm — deliberate, because a
server that stops exporting the stamp must not be able to silence its own
liveness alert. **What that tells you is that the GRACE is gone, not that the
SIGNAL is spurious.** The alert's other arm,
`increase(yuzu_server_audit_retention_passes_total[3h]) == 0`, is what actually
fired, and `cleanup_once` bumps that counter unconditionally before every
return — so a flat counter is the dead-reaper condition itself. With the stamp
series missing, this rule can no longer tell a fresh database from a stopped
reaper, and BOTH need checking:

- Fix the scrape path — confirm the target is up and that a
  `metric_relabel_configs` rule is not dropping
  `yuzu_server_audit_retention_last_pass_unixtime` (both operands ship
  unlabelled from one target; a relabel rule touching ONE of them also breaks
  the grace join — see "WHAT WOULD BREAK THE ASSUMPTION" above the rule).
- **And** establish process age out of band (`journalctl --list-boots`, the
  orchestrator's restart count) and read
  `yuzu_server_audit_retention_passes_total` yourself. A process up for more than
  a couple of cleanup intervals with a flat counter is a stopped reaper, and the
  checks earlier in this section — `AuditStore: retention pass threw`, whether
  the store opened at boot — are the work.

Treating this as scrape-only leaves audit retention unenforced while the audit
store grows. The separate `YuzuAuditRetentionMetricMissing` alert covers the other half
— the retention *counter* not being scraped at all, which leaves this rule unable
to fire for anyone.

To check the retention index directly:
```sql
SELECT indexname FROM pg_indexes
WHERE schemaname = 'audit_store' AND tablename = 'audit_events'
  AND indexname = 'idx_audit_ttl_id';
```
Unlike the retired SQLite store, this index is created INSIDE the schema
migration transaction (ADR-0040), so a missing index means the migration
itself failed or was interrupted mid-build — not a best-effort background
build that silently degraded. Treat a missing index as a migration-integrity
problem, not a performance tuning task.

## YuzuAuditRetentionNeverRan

`yuzu_server_audit_retention_last_pass_unixtime` has read exactly `0` for at
least three hours: NO retention pass has ever run against this database. Not
"not recently" — the gauge is seeded from the durable
`audit_store.audit_retention_meta` anchor at startup (#2854), so `0` is a fact
about the DATABASE, not about a young process, and restarts do not reset the
clock (the rule reads the whole `[3h]` window, so a crash-looping fresh
install still pages — mixed-seed loops carry one filed exception, #2997,
detailed below). A fresh install's one legitimate cleanup interval of
silence is over long before this fires.

This is `YuzuAuditRetentionNotRunning`'s excused state, given its own alert
and a first-boot-sized grace: while the target is being scraped the two are
mutually exclusive per server (after TOTAL scrape loss the anchored state
still double-pages with `YuzuAuditRetentionMetricMissing` — see that section
— while the fresh state keeps paging here, joined by that same fleet-wide
absence alert if the whole fleet's series are gone), and
the remediation differs — this one is almost never "the reaper died later",
it is "the first pass never happened":

- **The store did not open at boot.** A failed migration closes it and
  `start_cleanup()` early-returns — check the boot log for the migration
  failure before anything else. This is the classic cause.
- **The process never lives long enough for the first pass.** `run_cleanup`
  sleeps a full 60-minute interval before its first pass; a fresh install
  stuck in a sub-hourly boot loop never reaches it. Check
  `YuzuServerRestartLoop` / `resets(yuzu_server_uptime_seconds[3h])` and the
  crash signature around each restart.
- **The first pass keeps throwing.** `AuditStore: retention pass threw` in
  the log; see `YuzuAuditRetentionFailing` above.

A NEGATIVE stamp does not fire this rule — a dead-CMOS pass is still a pass,
and disproves "never ran" (one corruption-grade exception: a window mixing a
negative stamp with BOTH zeros and sentinels still fires here, because the
sentinel keeps never-ran unprovable — expect an imprecise story there). The INT64_MIN unreadable-anchor sentinel is
treated as UNKNOWN, not as evidence: a window of only sentinels leaves
`YuzuAuditRetentionNotRunning` to page a dead reaper, but a window mixing
sentinels with `0` seeds — a crash-looping fresh install whose anchor read
intermittently fails — still fires HERE, because a failed read cannot
disprove never-ran (#2854 governance sec-F1; the earlier form was silent in
exactly that state; one measured exception is filed as #2997 — an oscillation
phase-locked at a 180–195 minute period can starve both rules' `for:`
clocks, so treat prolonged silence under a KNOWN mixed-seed loop as
unproven, not clear). To tell a mixed-seed loop from a plain fresh-install
boot loop, grep the boot log for the anchor-read warnings
(`"could not read the retention liveness anchor"`, `"...is not an integer"`,
`"...is implausible"`): those point at PostgreSQL connectivity/pool or a
corrupt anchor row — a different owning fix than an app crash loop.

**After a known anchor-loss event (restore, template rehydrate, manual
delete) with a reaper that was already dead, THIS is the alert to expect,
on its slow path**: the pre-wipe stamp keeps `YuzuAuditRetentionNotRunning`'s
left side and its grace clearing in step, so that rule never latches, and
this one fires only once the old stamp ages out of its window plus `for:` —
~6 hours after the wipe itself (~7 from the original boot; pinned by the
lost-anchor rewind case in the test file), and the handoff includes a genuine
alerting GAP of up to ~3 hours between `YuzuAuditRetentionNotRunning`
resolving and this rule latching — silence there is the slow path working,
not recovery. Budget response time accordingly; recovery of the anchor row
itself is `YuzuAuditRetentionAnchorNotSurviving` territory.

**During a staged rollout, expect this alert from old-but-anchored servers.**
A server build that exports the stamp but predates the seed-from-anchor
behaviour reads `0` after every restart even on a database with years of
passes — a crash-looping NOT-yet-upgraded server therefore pages here, with
a first-pass story that is FALSE for it. That is a rollout-ordering artifact,
not a fresh-install signal: upgrade the server (or check
`yuzu_server_audit_retention_passes_total`'s history for the truth) rather
than working this section's decision tree.

Recovery: the first completed pass writes a real stamp and the rule clears on
the next evaluation. Confirm with `yuzu_server_audit_retention_passes_total`
rising from 0.

## YuzuAuditRetentionAnchorNotSurviving

The retention guard has declined more than once in a 24-hour window for having
NO stored clock reading (`yuzu_server_audit_retention_bootstrap_declines_total`
rising past 1). Expect this AT MOST once per database, on the upgrade that adds
the reading — see "The bootstrap decline" above. Repeating means the durable
`last_pass_now` reading (`audit_store.audit_retention_meta`) is not surviving
between passes, so the restart-surviving half of the clock guard is not working
and each pass starts blind. **Nothing has been deleted by these passes** — this
is lost detection, not lost evidence.

Check `yuzu_server_audit_retention_persist_failed_total` first — if it is
FLAT, the row is being destroyed OUT OF BAND (a point-in-time restore or a
restore from a pre-v3 backup, a replica rehydrated from an older template, a
disk-level rollback, a manual `DELETE`/`TRUNCATE` on `audit_retention_meta`),
which that counter cannot see, since the write itself is succeeding each pass;
a flat counter is not evidence the anchor is fine, it only rules out one of
the two causes. If it is RISING, see `YuzuAuditRetentionStateNotPersisting`
below instead — that is the write actually failing (disk, permissions, a
read-only mount).

## YuzuAuditRetentionMetricMissing

No `yuzu_server_audit_retention_passes_total` series exists in this Prometheus at
all, so `YuzuAuditRetentionNotRunning` cannot fire for anyone: `increase()` over a
metric with no series is an empty vector, and an alert that selects nothing never
alerts. Retention is unmonitored until this is resolved.

**Check `up` for the Yuzu target first — this rule cannot tell these three states
apart.**

- **`up` is 0.** The server or its scrape is down. This is an OUTAGE, not a
  monitoring gap, and on a single-server Prometheus this rule may be the only one
  firing, because nothing in the shipped rule set alerts on `up` directly. Work
  the outage; this alert clears when scraping resumes.
- **`up` returns no series at all.** Two very different things look identical
  here, so do not assume the benign one:
  - this Prometheus was never configured to scrape a Yuzu server — **expected and
    ignorable** before the first one is stood up. Check the targets page.
  - the target has **left service discovery**. Under dynamic-port, IP-based or
    scheduler-managed SD that is exactly what a dead or deleted server looks
    like. An empty target list for a fleet you believe is running is an outage.
- **`up` is 1.** The metric itself is missing. Either the server predates it (the
  rules file is a copy you apply yourself, so it routinely runs ahead of the
  servers it points at), or a scrape config is dropping it. Confirm with
  `curl -s <server>/metrics | grep audit_retention_passes`, then check
  `metric_relabel_configs`.

It is **fleet-wide by construction**: `absent()` fires only when NO series exists
anywhere in this Prometheus, so one server going quiet among many is invisible
here — including the half-join variant where a relabel rule drops ONLY
`..._retention_passes_total` for one server while its stamp and other series
still flow: that server's liveness rule selects nothing, this rule stays
suppressed by the fleet's surviving series, and its dashboards look healthy.
(A relabel collision that MERGES two servers' stamp series pages
`YuzuAuditRetentionNotRunning` instead — any real stamp in the merged window,
positive or dead-CMOS negative, lifts the grace — so that misconfiguration is
loud, not silent.)

**An `up`-based target-down alert does not cover that**, and this page said it did
until #2553 pass 13. The server you are missing is alive and scraped - typically
an older build that does not export the counter yet, since the rules file is
applied by hand and routinely runs ahead of the servers - so its `up` is 1.
Measured: with one server exporting the counter and one not, neither retention
rule fires for either server. During a staged upgrade, confirm coverage directly
with `count(yuzu_server_audit_retention_passes_total)` against your expected
server count. A per-target rule is tracked separately.

## YuzuAuditRetentionStateNotPersisting

This alert's own `runbook_url` points at
[Audit Log § The retention clock guard](../user-manual/audit-log.md#the-retention-clock-guard),
not this page — that is the one home for it; not duplicated here.

## Verifying recovery

```
yuzu_server_audit_clock_anomaly_skips_total   # stops increasing
yuzu_server_audit_rows_deleted_total          # resumes increasing
yuzu_server_audit_retention_cap_reached_total # flat once the backlog drains
```

Read the skips and failed counters **together**. Both leave rows undeleted, so a
table that never shrinks looks identical either way; only the pair distinguishes
"the guard is protecting the table" from "cleanup is broken".
