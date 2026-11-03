---
status: accepted
date: 2026-06-08
owner: "@lesault (Andy Younie)"
scope: platform — viz, vuln-scan graph, and IOC all depend on this
---

# 0003 — Telemetry capture: event-driven, edge-aggregated, federated edge warehouse

> **Implementation status (2026-06-18 conformance audit):** Accepted decision; the event-driven flow-telemetry engine is **not yet built in mainline** — implementation is spike-grade (PR #1206). See `docs/reviews/codebase-conformance-2026-06-18`.

## Context

Connection telemetry today is **poll-based** (`/proc/net/tcp`, `GetExtendedTcpTable`,
libproc on a 60s snapshot). Polling structurally misses short-lived connections — fatal for
attack-path evidence ("did A ever reach B?") and C2 detection. Polling was a PoC
convenience, not a design choice. This is a platform-level decision: the fleet visualiser,
the vuln-scan graph, and the IOC plugin all consume the same flow telemetry.

## Decision

Move to **event-driven capture**, with three platform collectors converging on one
flow-summary schema:

- **Linux: eBPF** (tcp_connect/accept tracepoints) — cgroup attribution free.
- **Windows: ETW** (Kernel-Network provider; Sysmon EID 3 reference) — Server-Silo
  attribution for process-isolated containers; Hyper-V-isolated opaque.
- **macOS: NetworkExtension** content filter — heavyweight (Apple entitlement + system
  extension + user consent); **deferred/optional**. macOS endpoints participate as
  host-granularity entry-point leaves on the existing poll path until/unless funded by
  other features.

Aggregate **at the edge** (the in-kernel-map / Cilium-Hubble / Datadog-NPM pattern) into
flow summaries `(src, dst, port, proto, first_seen, last_seen, count)` — lossless on flow
*existence* while keeping volume near today's poll volume. Summaries persist in the
**agent's local SQLite warehouse** (Echo `tcp_live` precedent), retained and **not flushed**;
each box is a leaf of a distributed SQL warehouse the server queries on demand. The raw
event firehose **never reaches the server**.

## Considered and rejected

- **Ship raw events to a central columnar store (ClickHouse/Timescale).** Rejected: the
  firehose volume at 1.2M agents is the problem edge-aggregation removes; centralising it
  buys nothing the federated edge warehouse doesn't.
- **eBPF-for-Windows as the Windows path.** Not mature enough to bet v1 on; ETW is the
  production path. Revisit if the projects converge.

## Consequences

- One shared collection stream feeds viz + scanner + IOC — implement once.
- `kernel boundary = visibility boundary` (ADR-0002) is enforced here: container attribution
  is platform-gated and best-effort.
- Detail is **pull-from-edge and online-only**; offline hosts answer only from last-known
  summaries persisted server-side (ADR-0004). The graph carries two edge fidelities —
  live-detail and last-known-summary (stale-flagged).
