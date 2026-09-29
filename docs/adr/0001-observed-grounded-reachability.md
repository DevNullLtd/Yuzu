---
status: accepted
date: 2026-06-08
owner: "@lesault (Andy Younie)"
---

# 0001 — The reachability graph is observed-grounded, not potential-based

> **Implementation status (2026-06-18 conformance audit):** Accepted decision; the reachability/attack-path engine is **not yet built in mainline** — implementation is spike-grade (PR #1206). See `docs/reviews/codebase-conformance-2026-06-18`.

> **Re-verified (2026-09-07 ADR reconciliation):** still not built in mainline — zero hits for `reachability_graph`/`ReachabilityGraph`/`service_node`/`host_node` in `server/`, `agents/`. Deferred, not withdrawn: re-homes into a use-case engine under ADR-1005 Phase 7 (not started, #4099); NOT grandfathered — faces ADR-1005 Decision 2 at implementation.

## Context

The vulnerability engine's differentiator is attack-path-aware prioritisation, which needs
a fleet reachability graph. The market splits on what "reachable" means: CTEM /
attack-path tools (XM Cyber) model **potential** reachability derived from network/firewall/
cloud config (high recall, high noise); the alternative is **observed** reachability —
edges backed by flows agents actually saw. An audit (2026-06-08) confirmed Yuzu collects
observed flows well (`fleet_snapshot.v1` + `FleetTopologyStore`) but **cannot** collect
potential reachability on-box: the firewall plugin only dumps rules as unstructured text,
and switch ACLs / cloud security groups / VLAN segmentation are invisible to an on-box
agent by construction.

## Decision

The graph's spine is **observed reachability**. We trade recall for trust on purpose —
observed flows undercount what is possible, and that is an accepted, written-down
limitation, because low false-positive results are Yuzu's cornerstone. **Host-firewall
potential reachability** is a later, clearly-labeled enrichment (it requires structured
firewall parsing we do not yet have) and is never merged into the observed edge set.
**Fabric-level potential reachability is out of scope**; a seam is left to *consume* it
from, or *publish* our observed graph to, an upstream source in a future iteration. Yuzu
never fabricates reachability it cannot observe.

## Consequences

- The honest headline limitation, stated in every surface: **a path that policy permits
  but no host ever exercised is invisible.** Segmentation min-cuts (ADR-0005) therefore cut
  *observed* paths only.
- The novelty claim is defensible *because* of this constraint, not despite it: we are the
  attack-path tool grounded in the defender's own observed telemetry.
- "Reachable" in Yuzu means **network/IPC-reachable host/service** — deliberately not the
  SCA call-graph sense ("is the vulnerable function invoked"). The term is kept unambiguous.
