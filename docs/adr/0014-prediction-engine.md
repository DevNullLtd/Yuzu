---
status: proposed
date: 2026-06-22
owner: Alex Young
deciders: pending HITL review
sibling: docs/adr/0013-attack-chain-correlation.md (the deterministic security counterpart;
  shares the routing/validation seams, not a core)
builds-on: docs/adr/0003-telemetry-capture-model.md (federated edge warehouse),
  docs/adr/0001-observed-grounded-reachability.md (low-FP cornerstone),
  docs/adr/0006-server-postgresql-substrate.md (new server stores default to Postgres),
  docs/dex-signal-catalog.md, docs/user-manual/network.md (measurement-first)
---

# 0014 — Prediction Engine: probabilistic reliability forecasting from the edge warehouse

> **Implementation status:** greenfield proposal. The *inputs* ship today (the DEX signal
> catalogue, the cross-platform state polls, the `dex_perf_breach` latches, the Echo `$Perf_Hourly`
> warehouse, the battery/SMART counters); the forecasting layer described here is **not built**.

## Context

Yuzu's DEX layer collects the precursors of most endpoint *reliability* failures and throws none
of them away — but reports them reactively. The observer surfaces the disk that is *already* full,
the battery *already* below 80% of design, the perf breach happening *now*. By the time the signal
fires the employee has already felt the pain.

The forward motion in the DEX market (commercial DEX and endpoint-analytics products) is
toward getting ahead of the failure: tell the operator a disk will fail, a battery will cross the
replace-threshold, a volume will fill, *before* the ticket exists. The inputs for this already sit
in the on-device warehouse — `$Perf_Hourly`, the `storage.low` free-space series, the
battery/SMART counters, the `dex_perf_breach` latch state.

The naive build — ship the time-series centrally and train fleet models — collides with three
standing commitments: **ADR-0003** (the raw firehose never reaches the server; the edge is a
federated warehouse), **ADR-0001 / measurement-first** (low false positives are the cornerstone;
the network-dashboard precedent withheld an unvalidated gauge until the real fleet validated it),
and the **works-council posture** (centralising behavioural time-series escalates surveillance
*capability* regardless of intent). So the design question is *where the forecast computes, how
honest it is about uncertainty, and how it stays on the right side of the privacy line.*

This ADR scopes **reliability forecasting only** — a probabilistic, regression-shaped problem
(extrapolate a continuous signal toward a threshold). The deterministic *security* counterpart
(chained-TTP campaign reconstruction) is a structurally different problem and is decided separately
in **ADR-0013**; the two share routing and validation plumbing but no core, and are governed,
gated, and shipped independently.

## Decision

### 1. Forecasts are computed at the edge, from each device's own warehouse

A device forecasts its own future from its own history and emits a thin `yuzu.forecast_*`
heartbeat fact carrying `{kind, horizon, confidence, evidence_summary}`. The server never sees the
raw series. This is the direct heir of ADR-0003's edge-aggregation and ADR-0005's "local proposes,
server confirms," and it is **N-independent** — per-device cost depends on one device's history,
not fleet size — so it scales to the 1.2M-host target for free.

### 2. A tiered model — ship only what has ground truth, outward-in

- **Tier 1 — deterministic extrapolation (ship first).** Failure classes with external, published
  ground truth or near-physical determinism, computed as a slope/threshold extrapolation with no
  learned model:
  - **Battery EOL** — capacity-fade over `FullChargedCapacity / DesignedCapacity` + `CycleCount`.
  - **Storage-full date** — least-squares slope on the `storage.low` free-space series.
  - **Disk failure** — `disk.smart_failure` (the vendor's own predictive flag) + a rising-rate
    trend on `disk.error` / `disk.port_reset`. The published large-fleet drive-failure statistics and hyperscaler SMART-to-failure
    literature gives this class **public, labelled ground truth**, which is why it qualifies for
    Tier 1.

  Tier 1 ships because each member can be validated against an *external* reference, not because we
  trust our own model.

- **Tier 2 — statistical trend (observe-only).** Rising crash rate (`process.crashed` /
  `service.crashed` / `os.bugcheck`), perf degradation trending toward chronic `perf.*` breach,
  boot-time (`os.boot`) regression. These surface as **"trending worse, watch this"** with no
  asserted horizon, and are **withheld from any gauge/alert** until §4 validates their precision on
  the real fleet — the literal retransmit-MIB discipline.

- **Tier 3 — learned models (deferred).** Multivariate models trained on the §4 outcome labels
  once they exist. Shipping a learned model before the fleet has validated it is the cardinal
  measurement-first violation; this ADR refuses to.

### 3. A forecast is a fact, not an alert

Mirroring the DEX invariant "observations are facts, not alerts": a forecast is a probabilistic
*fact* carrying `confidence`, `horizon`, and a human-readable `evidence_summary` ("free space fell
3.1 GiB/day over 14 days"), uniformly `info` severity. Framing and routing are separate and reuse
existing seams: fleet rollup into `yuzu_fleet_forecast_*` gauges via `recompute_metrics`; cohort
escalation (e.g. "47 devices began forecasting disk failure within 24h of KB5055555" —
patch-regression early warning) via the existing `dex_blast_radius`; per-kind operator routing via
`dex_alert_router`. Remediation is **manual / operator-gated only** (a forecast may *propose* —
back up the dying disk, schedule the swap — but never auto-acts).

### 4. The forecast-vs-outcome scoring loop is load-bearing

Every forecast is recorded; when its horizon elapses, the actual outcome is recorded against it,
and precision/recall is computed per kind. This loop is **the promotion gate** off observe-only
(measurement-first: the fleet's own outcomes validate a kind, not engineering confidence) **and**
the eventual Tier-3 training-label source. It is a **new server store, born on Postgres**
(ADR-0006, its own schema), holding only `{device, kind, forecast_at, horizon, predicted,
observed_outcome, observed_at}` — the raw per-device series stays in the edge warehouse and is
never copied in.

### 5. Privacy stays at the edge; machine-health only

Forecasts are **device-scoped machine-health**. The same edge-minimisation the collectors enforce
applies (backing-device identifier, never a mount path; no user-attributable content). Per-device
drill-down reuses the existing device-page DEX-lens gate (`GuaranteedState:Read` + audit-on-open
`dex.device.view`); fleet rollups are aggregate-only. (This benign posture is precisely what
diverges in ADR-0013, whose security signal is identity-bearing and gated differently — a reason
the two are separate features.)

## Business value

- **Ticket deflection / shift-left.** Most hardware tickets — dead batteries, failed disks, full
  drives — are predictable days out; converting an unplanned P1 into planned maintenance is the
  biggest operational lever the DEX vendors sell on.
- **Data-loss avoidance.** A disk-failure horizon is a window to evacuate and reimage before the
  failure.
- **Asset-lifecycle / capex optimisation.** Battery/disk forecasts drive refresh planning and
  warranty timing — replace neither too early nor too late.
- **Productivity protection.** Storage-full and perf-degradation forecasts catch the cliff before
  the user is blocked — cost that never appears in a ticket queue.
- **Sales / displacement.** "DEX that gets ahead of the failure" is the named criterion in
  displacement of commercial DEX products; predictive-*and*-privacy-preserving is a wedge in EU /
  works-council-sensitive accounts. Natural feeder for the agentic self-remediation track.

## Competitive comparison

| Capability | Commercial DEX products | Platform-vendor endpoint analytics | **Yuzu Prediction Engine** |
|---|---|---|---|
| Failure *forecasting* (a horizon, not a current score) | Partial — anomaly scoring, largely reactive | Battery/startup anomaly flags; no failure-date | **Tier-1 horizons + Tier-2 trends** |
| Where it computes | Centralised cloud ingestion | Cloud-only, Windows-centric | **Edge-computed; only thin facts centralise** |
| Telemetry / privacy cost | High | High | **Low — raw series never leave the device** |
| Explainability | Largely opaque | Opaque "anomaly" | **Explainable — Tier-1 is a stated slope/threshold + evidence** |
| False-positive discipline | Vendor-tuned | Vendor-tuned | **Measurement-first: Tier-2/3 observe-only until fleet outcomes validate** |
| Cross-platform parity | Windows-strong, mixed elsewhere | Windows-only in practice | **Same obs_types Win/Linux/macOS** |

The external precedent for Tier 1 is not the endpoint vendors but the **storage-ops literature** —
Published large-fleet drive-failure statistics and the hyperscaler SMART models prove disk-failure
prediction is real *and* give it public ground truth. Yuzu's differentiator is bringing that rigor
to the endpoint with **edge computation + works-council-grade privacy + explainable forecasts +
an agentic-remediation seam**.

## Options considered

- **Central time-series + fleet ML (rejected for v1).** Rejected on ADR-0003's grounds — firehose
  volume at fleet scale, plus the surveillance escalation. A seam is left to *export* forecast
  facts (not raw series) to an external ML/BI system.
- **Server-side forecasting over pulled warehouses (rejected).** Re-creates the pull volume
  edge-computation avoids; the math is a local slope.
- **Ship all tiers at once (rejected).** Tier-2/3 lack external ground truth on day one and must be
  observe-only behind §4.
- **Forecast as an alert/severity (rejected).** Preserves "observations are facts, not alerts."
- **Bundle with the security counterpart (rejected — see ADR-0013).** Opposite privacy model,
  different compute location, different buyer, different maturity; bundling couples a ship-now
  feature to a strategic bet.

## Consequences

- **New (agent):** a pure forecasting pass (pure extrapolation functions unit-tested on every host;
  the warehouse read is the impure shell) + a `yuzu.forecast_*` heartbeat block. **No proto
  change** — forecast kinds ride thin facts keyed by kind, as new DEX signals do.
- **New (server):** `yuzu_fleet_forecast_*` gauges; the Postgres scoring store; a forecast panel on
  `/dex` and per-device forecast section (behind the DEX-lens gate).
- **Reused:** `dex_blast_radius`, `dex_alert_router`, the heartbeat→gauge path, the DEX-lens gate,
  the edge warehouse, the `dex_perf_breach` latch.
- **Invariant — confidence + horizon + evidence on every forecast.** No bare prediction on any
  surface.
- **Invariant — Tier-2/3 stay off gauges/alerts until §4 validates.** Measurement-first, paid
  explicitly.
- **Invariant — raw series never centralise.** Only thin facts + outcome tuples leave the device.
- **Residuals:** small cloud/VM volumes already read `storage.low` noisily against the fixed 5 GiB
  floor — the storage forecast must use the *trend*, not the floor; insufficient-history must emit
  **no** forecast (a first-class state, not a weak guess); horizon confidence widens on
  sparse/offline history.

## Future (deferred)

- **Tier 3 learned models**, trained on §4 labels, kept **edge-evaluated** (ship the model to the
  device, not the device's data to the model).
- **Patch-/driver-regression attribution** as a product surface on top of the `dex_blast_radius`
  cohort path.
- **External forecast-export seam** for customer-owned ML/BI.
- **Agentic consumption:** forecasts as MCP facts so an autonomous worker can propose gated
  remediation.
