---
status: accepted
date: 2026-06-08
owner: "@lesault (Andy Younie)"
---

# 0002 — Reachability graph data model: host + service nodes, two edge classes

> **Implementation status (2026-06-18 conformance audit):** Accepted decision; the reachability/attack-path engine is **not yet built in mainline** — implementation is spike-grade (PR #1206). See `docs/reviews/codebase-conformance-2026-06-18`. (Note: this is the canonical ADR-0002; the "gateway-scaling ADR-0002" cited in older notes does not exist.)

> **Re-verified (2026-09-07 ADR reconciliation):** still not built in mainline — zero hits for `reachability_graph`/`ReachabilityGraph`/`service_node`/`host_node` in `server/`, `agents/`. Deferred, not withdrawn: re-homes into a use-case engine under ADR-1005 Phase 7 (not started, #4099); NOT grandfathered — faces ADR-1005 Decision 2 at implementation.

## Context

An attack path is not "host A → host B"; it is "reach the *service* B exposes → exploit the
CVE *on that service* → own host B → pivot via B's outbound flows." A CVE on a package that
binds nothing is a finding but not a path. The data already supports a service-level model:
`fleet_snapshot.v1` collects `listeners[]` (host×port×pid) and `connections[]` whose
ESTABLISHED rows the viz already resolves to a destination listener.

## Decision

Two node tiers: **host nodes** and **service nodes** = `(host, listening port, protocol,
owning process)`. A CVE and asset value attach to the **service**; an inbound edge
terminates at a service. A host is **not** an atomic compromise unit — it is a **sub-graph
of service nodes joined by local-IPC edges**. Two edge classes: **network reachability
edges** (`src host → dst service`, observed flow, directional) and **local-IPC edges**
(`service → service` within a host: Unix socket, named pipe, shared memory, mmap, shared
file, setuid/sudo hop). **No identity/account nodes** — declared non-goal (no on-box
identity telemetry; that is the BloodHound space we do not enter).

Value is carried by the service and rolls up to the host by **max**; for path *scoring* the
captured value is the max over services **locally reachable from the entry service**, not
the host-max. **Trust zones** (operator-declared, ordered CIDR/site tiers) bracket the
graph on the source side; **crown jewels** (operator-declared, orthogonal to tags/MGs)
bracket it on the value side. Standing rule: **`kernel boundary = visibility boundary`** —
one agent sees one OS kernel; VMs, Hyper-V-isolated containers, and Docker-on-Mac Linux VMs
are opaque and need their own agent. Container attribution is best-effort and platform-gated
(Linux cgroup full; Windows process-isolated via silo partial; otherwise none).

## Considered and rejected

- **Flat host-only graph** — cannot express "the CVE is on the SSH service that is actually
  exposed" vs "a CVE on a library nothing listens on," which is the entire low-FP value of
  prioritisation.
- **Reusing the viz renderer's ephemeral `MachineNode`/`ProcessNode` types** — they are a
  60s-TTL rendering projection. The analytic graph shares the *raw observation model* but
  the derived layer (traversability, paths, chokepoints, value) is new vocabulary computed
  on a schedule; coupling the scorer to the renderer's throwaway types was rejected.

## Consequences

- Local-IPC edges beyond sockets are a collection-expansion workstream (rides ADR-0003).
- On-box *potential* reachability is feasible for the **local** graph (file/pipe/shmem ACLs
  are locally inspectable) even though it is not for the network graph — the home-field
  advantage inside the kernel boundary.
