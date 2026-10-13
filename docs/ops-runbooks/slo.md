# Service Level Objectives — Yuzu Server

Workstream D (Reliability, Availability, and Operational Readiness),
`docs/enterprise-readiness-soc2-first-customer.md` §3.4. Five SLOs, one per
required signal (`/readyz` availability, command dispatch latency, agent
heartbeat freshness, audit write success, PostgreSQL substrate degrade
events). Four of the five metrics are verified present in `server/core/src`
(grep citation on each) — none of those four is aspirational. **The fifth,
§1's `up{job="yuzu-server"}`, is a Prometheus *scrape* metric, not
something Yuzu itself emits** — verified present in the scrape config
(`deploy/prometheus/prometheus.yml` / `prometheus-uat.yml` /
`prometheus-full-uat.yml`), a different kind of verification than a grep
hit in `server/core/src`. Said explicitly in §1 below; do not read this
paragraph's "verified present" as covering all five uniformly.

**Total-outage blind spot (governance UP6-13/sre6p6-2, tracked #4290) — read
this before treating any SLO below as evidence of outage detection.** Every
metric in sections 1-5 below is emitted BY the process that fails closed.
During a total server or PostgreSQL outage, none of these series goes
*bad*: the five Yuzu-emitted series go **absent** (no process is left to emit
them), and a failed scrape sets Prometheus's own `up` to `0` — which only
helps if a rule actually reads it, and none of the SLO expressions below do.
An absent series computes as "budget not burned": a 30-day window spanning a complete outage reads as 100% met on
every one of the five SLOs. The one rule that would catch this — an
`up == 0` dead-man's-switch — is proposed in §1 below and **not shipped**.
This is not merely a §1 caveat: it applies identically to sections 2-5,
which do not separately restate it. **Do not present this document as
clean evidence of outage detection until #4290 ships** — it is evidence
that the instruments are individually correct (verified: every metric
exists at its cited line, every alert matches on `expr`, `for`, and
`severity`), which is a narrower claim than "these SLOs would have caught
the outage."

**Citation ref.** Every `file:line` citation in this document is pinned to
commit `c7f3a5bed9c969684b4c4b1799ad77149984c1c3` (this branch's merge-base
with `origin/dev`, 2026-09-12) — **not** the `v0.13.0` tag and not a moving
`dev`-HEAD. `server/core/src` churns fast; line numbers drift within days.
Re-verify any citation with `git grep -n <metric_name> c7f3a5bed -- server/core/src`
(or against your own ref) rather than trusting the number.

**PO decision 2026-09-07** — the targets in this document were set by the
product owner on that date and are to be **re-baselined after 90 days of
production data**. No production Yuzu fleet exists yet (`docs/capability-map.md`
context), so every "Current measurement" line below reads **not yet
baselined**; this document exists so a customer's security reviewer sees a
target and a real alert wired to it, not a promise with nothing behind it.

Windows are 30-day rolling unless stated otherwise. "Burn" means the rate at
which the SLO's error budget is being consumed, not the raw threshold alone —
each section names the existing Prometheus alert (`docs/prometheus/yuzu-alerts.yml`)
that **fires** on it, or says explicitly that no alert ships yet.
**"Fires" is not "pages" (governance sre3-1) and "exists in the file" is
not "is evaluated by a running Prometheus" (governance sre6-5) — see
"Verifying this file's claims" near the end of this document for both
distinctions before treating any "Alert: existing" line below as a
standing, routed, continuously-evaluated control.**

---

## 1. `/readyz` availability

**Metric:** no direct `/readyz`-content probe is shipped today (confirmed:
no blackbox_exporter anywhere in `deploy/`, no `up`-based dead-man's-switch
for the server process — `docs/ops-runbooks/audit-store-clock-guard.md`
names this gap explicitly under `YuzuServerRestartLoop`: *"There is no
dead-man's-switch (`up == 0`) rule for the server process in this file
today (tracked: #2956)"* (quoted verbatim as that doc currently reads).
**Correction (2026-09-10, governance-reproduced, C2-3):** #2956 is
CLOSED, and a prior revision of this document redirected the citation to
#2459 — but #2459 does not name this gap either (verified). The gap is now
tracked by **#4290** (open) — cite that, not #2956 or #2459. The practical proxy is
Prometheus's own scrape
health of the `/metrics` endpoint on the same server process: `up{job="yuzu-server"}`
(`deploy/prometheus/prometheus.yml` / `prometheus-uat.yml` / `prometheus-full-uat.yml`,
job name `yuzu-server`). This proves the HTTP listener is alive; it does
**not** prove `/readyz`'s own conjunctive store-health checks pass (a server
that is up but reporting a degraded store — e.g. `stores.audit` closed —
would still show `up == 1` here). Closing that gap needs a blackbox-exporter
job scraping `/readyz` directly and asserting on HTTP status, which is not
part of this change — tracked by #4290 (see the correction above).

**Target:** **99.5% / 30d for a single-replica deployment** (~3h39m of
allowed downtime/month) — what ships today. Target rises to **99.9% / 30d**
once ADR-2002 Phase B (second replica, `docs/user-manual/ha-postgres.md`)
lands; a single server process is a single point of failure for the
dashboard/REST/gRPC listener regardless of how available the PostgreSQL
substrate underneath it is (HA-Postgres protects the data plane, not this
listener — see that doc's "What you get").

**Window:** 30-day rolling.

**Alert:** none shipped today for this specific signal. **PROPOSED** (not in
`docs/prometheus/yuzu-alerts.yml` — that file is not owned by this change):

```yaml
# PROPOSED — NOT SHIPPED. Mirrors YuzuGatewayDown's up{job=~".*gateway.*"}==0
# pattern (docs/prometheus/yuzu-alerts.yml) applied to the server job. The
# gap this closes is tracked by #4290 (neither #2956, closed, nor #2459 names
# it — see the correction above) — proposed for the PO/workflow owner to route
# into the real file.
- alert: YuzuServerDown
  expr: up{job="yuzu-server"} == 0
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Yuzu server metrics endpoint is down"
    description: >-
      Prometheus cannot scrape the Yuzu server (:8080/:8443). Every dashboard,
      REST, and MCP request is failing while this holds.
```

**Current measurement:** not yet baselined.

---

## 2. Command dispatch latency (p99)

**Metric:** `yuzu_command_duration_seconds` — histogram, described
`server/core/src/server.cpp:600`, observed at
`server/core/src/agent_service_impl.cpp:1438` and `:1726`.

**Target:** p99 < 10s for ≥99% of 5-minute windows / 30d.

**Window:** 30-day rolling, evaluated over 5-minute buckets (matches the
alert's own window below).

**Alert:** existing — `YuzuHighCommandLatency`
(`docs/prometheus/yuzu-alerts.yml`):

```yaml
- alert: YuzuHighCommandLatency
  expr: |
    histogram_quantile(0.99, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le)) > 10
  for: 5m
  labels:
    severity: warning
```

**Current measurement:** not yet baselined.

---

## 3. Agent heartbeat freshness

**Metric:** `yuzu_agents_connected` − `yuzu_fleet_agents_healthy` (both
gauges, `server/core/src/agent_registry.cpp:191,349,369` and `:2237`
respectively; described `server.cpp:543` and `:1985` respectively). A positive value means agents are
connected but not producing a recent heartbeat. **Caveat:** the two gauges
are independently updated (connect/disconnect events vs. a periodic
healthy-count recomputation), so under churn — agents connecting and
disconnecting in the same window the healthy-count sweep runs — the raw
difference can transiently go **negative** (a stale, higher `healthy` count
briefly outpacing a just-dropped `connected` count). That's harmless for
the existing `> 0` alert threshold below (a negative value also fails
`> 0`, so it never falsely pages), but an SLO **error-budget quantity**
built from this metric should use `clamp_min(yuzu_agents_connected -
yuzu_fleet_agents_healthy, 0)` — treat "stale-connected agents" as never
less than zero — rather than the raw signed difference, which would
otherwise let a negative reading offset/cancel a real positive reading when
averaged over a window.

**Target:** 0 stale-connected agents for ≥99.5% of time / 30d (computed on
the `clamp_min(..., 0)` form above).

**Window:** 30-day rolling.

**Alert:** existing — `YuzuAgentDisconnected`
(`docs/prometheus/yuzu-alerts.yml`):

```yaml
- alert: YuzuAgentDisconnected
  expr: |
    (yuzu_agents_connected - yuzu_fleet_agents_healthy) > 0
  for: 2m
  labels:
    severity: warning
```

There is also a fleet-drop companion, `YuzuAgentFleetDrop` (>20% drop in
connected count over 5m, `severity: critical`), which is a different signal
(mass disconnection, not staleness) and not part of this SLO.

**Current measurement:** not yet baselined.

---

## 4. Audit write success

**Metric:** `yuzu_server_audit_emit_failed_total` (gauge-published counter,
`server/core/src/server.cpp:8098`, described `:2447`) and
`yuzu_server_audit_events_total{result}` (success/failure/denied/other,
`server.cpp:8089-8095`, described `:2432`) for the write-outcome breakdown.

**Target:** **0 emit failures / 30d — a fail-closed CONTROL, not a
percentage (SLO = 100%).** Per ADR-0040, every behavioural-PII REST route
using fail-closed audit-on-open (`guardian.device.view`, `dex.device.view`,
`dex.signal.view`, `dex.perf.device.view`, `network.device.view`) returns
`503` and withholds data **on that one request** the moment its own audit
emission fails — fail-closed here is a **per-request** decision
(`server/core/src/rest_audit.hpp`'s `emit_behavioral_audit`), not a
global switch that puts "those routes" into a standing outage state once
tripped. A transient blip that fails one write does not withhold data on
the next request whose own write succeeds; `yuzu_server_audit_emit_failed_total`
is a count of individually-rejected requests, not a boolean "the routes are
down" flag. The SLO target of zero is still the right target — it mirrors
the per-request design's own bar (every eligible request either audits
successfully or is refused) — but do not describe it, or read an alert
against it, as if a single failure takes down the feature fleet-wide.

**A deployment that never exercises the audited routes reads this section
as 100% met with zero evidence of anything.** `yuzu_server_audit_emit_failed_total{}=0`
over 30 days is also exactly what a deployment with **zero** guardian/DEX/network
device-view traffic reports — there is no way to tell "verified across N
audited requests, zero failed" from "zero audited requests occurred" by
reading this counter alone. Cross-check `yuzu_server_audit_events_total{result="success"}`
(or `="denied"`) is actually incrementing before treating a clean 30-day
window as evidence the control is exercising, not merely idle.

**Window:** 30-day rolling; the underlying alert **fires as a Prometheus
alert within minutes of any single failure** (see below) — this is not a
budget that "burns slowly." **Correction (governance sre3-1):** "fires"
is not "pages." Routing/paging requires an operator-provided Alertmanager
— none ships with this repo (issue #2857 lists Alertmanager as an open
follow-up, and every `severity:` label in `docs/prometheus/yuzu-alerts.yml`
"routes nowhere" until one is wired). See `docs/enterprise-readiness-soc2-first-customer.md`
WS-D for the current status. A firing alert is visible in Prometheus's own
UI/API (`/api/v1/alerts`) even with no Alertmanager — it does not reach an
on-call human until one is configured.

**Alert:** existing — `YuzuAuditPersistFailures`
(`docs/prometheus/yuzu-alerts.yml`, `severity: critical`):

```yaml
- alert: YuzuAuditPersistFailures
  expr: |
    increase(yuzu_server_audit_emit_failed_total[5m]) > 0
  for: 2m
  labels:
    severity: critical
```

Runbook: `docs/ops-runbooks/audit-store-clock-guard.md` (`YuzuAuditPersistFailures`
section) — also covers the retention-side clock guard family, which bounds
blast radius on the deletion path but is a separate control from write
success.

**Current measurement:** not yet baselined.

---

## 5. PostgreSQL substrate degrade events

Three related metrics, all described/published in
`server/core/src/server.cpp` — described at `:1712` (`yuzu_pg_pool_in_use`),
`:1716` (`yuzu_pg_pool_size`), `:1721` (`yuzu_pg_connect_failed_total`),
`:1729` (`yuzu_pg_acquire_wait_seconds`, histogram registered `:1736`); the
two pool gauges set at `:7684-7687`; the connect-failure counter incremented
at `:4051`; the acquire-wait histogram observed at `:4065` — split into three targets per PO ruling, since pool
saturation, acquire latency, and hard connect failure are different failure
modes with different tolerances.

### 5a. Pool saturation

**Metric:** `yuzu_pg_pool_in_use` / `yuzu_pg_pool_size` (gauges).
**Target:** <90% saturated for ≥99% of time / 30d.
**Alert:** existing — `YuzuPgPoolSaturated`:

```yaml
- alert: YuzuPgPoolSaturated
  expr: |
    yuzu_pg_pool_in_use / yuzu_pg_pool_size > 0.9
  for: 5m
  labels:
    severity: warning
```

### 5b. Acquire-wait latency

**Metric:** `yuzu_pg_acquire_wait_seconds` (histogram).
**Target:** p99 < 200ms for ≥99% of time / 30d — the heartbeat upsert deadline
is 250ms, so this is the leading indicator before persistence starts dropping
(per the alert's own comment).
**Alert:** existing — `YuzuPgAcquireWaitHigh`:

```yaml
- alert: YuzuPgAcquireWaitHigh
  expr: |
    histogram_quantile(0.99, rate(yuzu_pg_acquire_wait_seconds_bucket[5m])) > 0.2
  for: 5m
  labels:
    severity: warning
```

### 5c. Connect failures

**Metric:** `yuzu_pg_connect_failed_total` (counter).
**Target:** report the raw count; target **0 sustained failure episodes /
30d**. The alert is only an approximation of "sustained": `rate(...[5m]) > 0`
stays true for up to 5 minutes after even a **single** increment, so with
`for: 2m` one transient failure (e.g. one dropped TCP connection that
reconnects on the next pool acquire) CAN fire `YuzuPgConnectFailing`.
Judge a firing against the raw counter — a lone increment is a blip, not an
SLO breach; repeated increments across the window are.
**Alert:** existing — `YuzuPgConnectFailing`, `severity: critical`:

```yaml
- alert: YuzuPgConnectFailing
  expr: |
    rate(yuzu_pg_connect_failed_total[5m]) > 0
  for: 2m
  labels:
    severity: critical
```

**Current measurement (all three):** not yet baselined.

---

## Verifying this file's claims

**Correction (2026-09-10, governance-reproduced, C2-4):** this section
previously pointed at `docs/ops-runbooks/restore-drill-2026-09.md` for the
exact `promtool` invocation — that invocation is not in that file. The
actual command, run against this repo (no local `promtool` binary
required):

```bash
docker run --rm --entrypoint /bin/promtool \
  -v "$PWD/docs/prometheus:/r" \
  prom/prometheus:v3.2.1@sha256:6927e0919a144aa7616fd0137d4816816d42f6b816de3af269ab065250859a62 \
  check rules /r/yuzu-alerts.yml
```
Expected output at commit `c7f3a5bed` (this branch's merge-base with
`origin/dev`): `SUCCESS: 117 rules found` — 116 alert rules + 1 recording
rule; `promtool` counts both kinds together as "rules". The file churns, so
re-derive the split at your own ref rather than trusting these numbers:
`grep -cE '^\s*- alert:' docs/prometheus/yuzu-alerts.yml` and
`grep -cE '^\s*- record:' docs/prometheus/yuzu-alerts.yml` (see also
`docs/enterprise-readiness-soc2-first-customer.md` §3.4, which cites the
same count at the same ref).
See #2857 for why no shipped stack on this branch loads these rules at
all today. An attempt at wiring them into a running Prometheus — and the
real infrastructure defects that attempt found (a merge order and a
from-scratch startup path that both silently produce zero loaded rules;
verification commands that pass in exactly that broken case; reload
staleness; a missing self-scrape job; a missing retention flag) — is
tracked separately from this branch (issue #2857). The honest
claim on this branch is **"these 117 rules (116 alerts + 1 recording rule,
at `c7f3a5bed`) exist and parse"** (`promtool
check rules`, above — a real, CI-checkable fact) — **not** "these rules
are evaluated by a live system," which this branch cannot substantiate
regardless of what that separately-tracked work eventually proves.

## Related

- `docs/ops-runbooks/audit-store-clock-guard.md` — the audit-write and
  retention alert family in detail.
- `docs/user-manual/ha-postgres.md` — the separate, more specific RTO/RPO
  figures for the optional Patroni-managed HA-Postgres profile (failover
  RTO **~30-40 seconds** per that doc's own "What you get" section —
  correction, governance arch2-3: a prior revision said "~15-40s" here,
  which matched no source in this repo), RPO=0 under `quorum3`. Those numbers describe the
  **PostgreSQL substrate's own** failover; they are not a substitute for
  §5 above (the *server's* pool-level view of that substrate) or for §1
  (the server listener's own availability, which HA-Postgres does not
  address at all — see §1's ADR-2002 Phase B note).
- Restore drill and the corrected DR procedure (measured RTO/RPO for the
  non-HA, single-replica deployment this document's §1 target describes):
  tracked in issue #4135 — not part of this branch's documentation set.
- The server dead-man's-switch gap this document's §1 proposed alert would
  close is tracked by **#4290** (open) — `docs/ops-runbooks/audit-store-clock-guard.md`
  still cites #2956 for it, which is closed; #2459 does not name this gap
  either (see §1's correction). Cite #4290.
