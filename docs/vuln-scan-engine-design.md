# Modern Vulnerability Detection Engine — North Star Design & Roadmap

| | |
|---|---|
| **Status** | North Star — for review |
| **Domain owner** | @lesault (Andy Younie) — vulnerability management |
| **Eng partner** | TBD |
| **Created** | 2026-06-08 |
| **Last grilled** | 2026-06-08 (`/grill-with-docs`, fresh context — graph layer added) |
| **Supersedes** | the static PoC matcher in `agents/plugins/vuln_scan/` |
| **Builds on** | PR #1206 (spike — proved the rule-delivery plumbing) |
| **Decisions of record** | ADR [0001](adr/0001-observed-grounded-reachability.md) · [0002](adr/0002-reachability-graph-data-model.md) · [0003](adr/0003-telemetry-capture-model.md) · [0004](adr/0004-server-storage-substrate.md) · [0005](adr/0005-attack-path-and-chokepoint-scoring.md) · [1005](adr/1005-headless-platform-use-case-engines.md) · [0023](adr/0023-vulnerability-correlation-engine.md) · [4001](adr/4001-vulnerability-dashboard-attack-path-explorer.md) (placement — see reconciliation note below) · [4003](adr/4003-cavm-v20-adoption-on-reachability-graph.md) (§5.2's chokepoint formula, superseding ADR-0005's original) |
| **Glossary** | `CONTEXT.md` — Reachability, Asset value (Crown jewel), Trust zone, Entry point, Attack path, Chokepoint |
| **Plain-language version** | [`vulnerability-graph-explained.md`](vulnerability-graph-explained.md) — a non-technical intro to *why a graph*, for curious readers |
| **Related** | `docs/capability-map.md` §9, `docs/fleet-viz-invariants.md`, `docs/scope-walking-design.md`, `docs/agent-privilege-model.md`, `docs/data-architecture.md` |

> **ADR-1005 reconciliation (2026-07, updated 2026-07-08).** This document's
> **server-side placement is interim**: vulnerability interpretation (feed ingest,
> matching, findings, scoring) is long-term a **use-case engine module**, not a
> server capability. The in-server vuln stack is **absorbed into ADR-1005
> grandfathered surface #2** — placement-only, bounded to those ADRs' designed
> scope, outside-by-default beyond it — and re-homes via the strangler migration
> in `docs/adr-1005-execution-plan.md` § "Relationship to ADR-0023 and ADR-4001"
> (as recorded 2026-07-08 via PR #1987). Absorbed, illustratively: the shipped
> NVD sync/matching; the ADR-0023 correlation engine + `VulnFindingStore`; the
> ADR-4001 `/vuln` dashboard lens and its `attack_path_engine` — the one
> component carrying a lapse conditional, tied to ADR-4002's boundary review.
> The full enumeration lives in that plan section. Milestone vocabularies are
> distinct — the plan's **UCE M1–M4** vs `docs/vuln-scan-roadmap.md`'s in-server
> M1a/M1b + M2–M6 ladder, always qualify which; UCE M4's surpass-parity criterion
> mirrors this doc's quality bar, and the plan's pilot-readiness note cites this
> doc as the north-star. The **domain content stands**: the matcher quality bar
> (§ floor — parity scanner, low false positives on a patched fleet), the phased
> matcher roadmap, and the attack-path/graph differentiator remain the north star
> for what the module builds — the graph layer's core-vs-engine boundary analysis
> remains owed at ADR-4002's own merge (4001's surface is absorbed; 4002's
> scoring substrate is not).

---

## 0. North Star in one paragraph

The **floor** is a trustworthy parity scanner: collect inventory thin on the agent,
correlate rich on the server against NVD + distro/OVAL backports + OSV + CVSS/EPSS/KEV,
with a low false-positive rate on a real, patched fleet. The **differentiator** — the
reason this is a Yuzu feature and not a commodity scanner — is that every finding is
ranked by its **position on an observed attack path toward an operator-declared crown
jewel**, and the engine recommends the **patching/segmentation with the highest defender
ROI** (the chokepoints whose removal breaks the most attack paths). The whole thing is
grounded in **flows our agents already observe** and vulnerabilities the *same* agent's
inventory reveals — so it is low false-positive *by construction*, which is Yuzu's
cornerstone.

---

## 1. Two layers: the floor and the differentiator

### 1.1 The floor — a trustworthy parity scanner

"Trustworthy" is the whole game. A scanner that cries wolf — flagging packages that are
already patched — gets muted within a week. The bar is **low false-positive rate on a
real, patched fleet**, not raw CVE count. The floor (Phases 1–5) brings Yuzu to parity
with a credible commercial scanner's *detection* core. It is necessary and not
sufficient.

### 1.2 The differentiator — topology- and threat-graph-aware prioritization

Raw CVSS ranking is noise at fleet scale: a "critical" on an isolated leaf that nothing
can reach outranks a "medium" on a pivot one hop from the payments database. The graph
layer (Phases 6–8) inverts that. It builds a **reachability graph** of the fleet, scores
each finding by whether it sits on a **short, probable attack path** from an **entry
point** to a **crown jewel**, and surfaces the **chokepoints** where defender effort has
the highest payoff. This is attack-path-aware prioritization, not severity sorting.

### 1.3 The honest wedge (positioning)

Yuzu's wedge is **observed-grounded attack-path prioritization from telemetry the
defender's own agents already produce.**

- **vs XM Cyber / CTEM attack-path management** — they model *potential* reachability
  scraped from firewall/AD/cloud config (high recall, high noise, and off-box data we
  structurally cannot see). Yuzu scores paths from **flows our agents actually observed**
  and the vulnerable service identified by the *same agent's* inventory. We trade recall
  for trust on purpose.
- **vs BloodHound** — it maps Active-Directory *identity* attack paths. Yuzu models
  *network + local-IPC* reachability and explicitly does **not** build an identity graph
  (no on-box AD telemetry — a declared non-goal).
- **vs EPSS / CISA KEV** — not competitors but **inputs**; they weight per-hop exploit
  probability.
- **vs SCA "reachable vulnerability"** — that is *call-graph* reachability ("is the
  vulnerable function invoked"). Our "reachable" means **network/IPC-reachable
  host/service**. We keep the term unambiguous and never conflate the two.

The home-field advantage no config-scraping competitor has: **observed network
reachability *across* the kernel boundary + *potential* local reachability *inside* it**
(file/pipe/shared-mem ACLs, sudo, setuid — all locally inspectable), composed by
**scope-walking** into enforceable remediation targets, all on a platform the customer
already runs.

### Non-goals (this iteration)

- **Network/unauthenticated scanning.** On-box and agent-based on purpose.
- **Fabric-level potential reachability** — switch/router ACLs, cloud security groups,
  VLAN segmentation. An on-box agent cannot see it; we never fabricate it. A seam is left
  to *consume* it from, or *publish* our observed graph to, an upstream source later
  (ADR-0001).
- **Identity attack graphs** (the BloodHound space) — no on-box identity telemetry.
- **Full SBOM/SCA** of language-ecosystem deps — valuable, later (Phase 5).

---

## 2. The parity floor: *collect thin, correlate rich*

Modern agent-based scanners do **not** do the hard matching on the endpoint. The agent
reports *what is installed* in a canonical form; a backend service correlates that against
a rich, continuously-updated vulnerability data plane. This keeps the agent small and lets
the matching logic (the hard, fast-changing part) live where it can be updated without
touching every endpoint.

```
   ┌─────────────────────────────┐         ┌──────────────────────────────────────┐
   │  Agent (per endpoint)        │         │  Server — Vuln Correlation Service     │
   │  Inventory collector         │ inventory│  Identity normaliser (CPE/PURL)       │
   │   dpkg/rpm/apk/registry/...  ├─────────►│      ▼                                 │
   │   → name, version, source,   │  (CPE/   │  Correlation engine                    │
   │     arch, normalized id      │   PURL)  │   • version-range matching             │
   │  (kernel, OS build, apps as  │         │   • backport / fixed-status (OVAL)     │
   │   additional inventory rows) │         │      ▼                                 │
   └─────────────────────────────┘         │  Prioritiser (CVSS+EPSS+KEV+graph ctx) │
   Vuln data plane (synced server-side):    │      ▼                                 │
     • NVD (CPE + version ranges)           │  Findings store → dashboard/REST/MCP   │
     • Distro advisories / OVAL             └──────────────────────────────────────┘
       (Ubuntu USN, Debian, RHEL, Alpine)
     • OSV.dev (pre-merged, ecosystem)
     • CISA KEV, FIRST EPSS
```

PR #1206 put the matcher **on the agent** with a single-threshold rule list. That is the
part Phases 1–4 replace. The agent keeps the inventory collector (the #1206 `inventory`
action). **One deliberate, bounded exception** to collect-thin survives: a tiny **KEV-only
pre-filter** on the agent (§4.4) — justified because the KEV catalog is ~1,200 CVEs versus
NVD's 250k+, ~200× smaller — used *only* for graph pruning, never as an authoritative
finding (ADR-0005).

### 2.1 What the #1206 spike proved (keep this)

- **Runtime rule delivery**: `update_rules` + `<data_dir>/staged/cve_rules.json` + real
  SHA-256 integrity verification + `content_dist.stage` delivery. Rules refresh without
  re-shipping the agent.
- **Automated data refresh**: a weekly GitHub Actions workflow regenerates the ruleset
  from NVD and opens a CODEOWNERS-gated PR.
- **Inventory action**: `vuln_scan.inventory` emits `name|version` per package — the seed
  of *collect thin*.
- **Breadth of collection surface**: package managers across Win/Linux/macOS, kernel
  version, file-level binary version (PE VERSIONINFO / `.app` Info.plist), CIS config
  checks.
- **A version comparator** that understands Debian epochs, RPM/Alpine release suffixes,
  and semver pre-release ordering.

### 2.2 The engine gap (what the parity phases fix)

The matcher is still the PoC's `substring(product) && version < threshold`, fed a lossy
keyword subset of NVD. Concrete evidence from the generated `content/cve_rules.json`:

- **Coverage collapses silently.** 31 product keywords queried; only **10** produced any
  rule. Zero rules for `linux-kernel`, `windows`, `chrome`, `python`, etc. The
  `kernel_scan` and Windows paths have nothing to match against.
- **Lower version bound discarded.** NVD's "2.0 ≤ v < 2.4" becomes "v < 2.4"; hosts on
  unaffected older majors are flagged; range-less CVEs are dropped (false negatives).
- **No backport awareness.** A patched `openssl 3.0.2-0ubuntu1.18` is compared as upstream
  `3.0.2 < 3.0.8` and flagged. This alone makes output untrustworthy on any real Linux
  fleet.
- **Identity is a display-name substring**, not CPE/PURL: `python` matches `ipython`.
- **No CVSS vector / EPSS / KEV** — severity is a bare label.

These are the absence of the engine, and exactly where **Andy's domain judgment is the
input**.

---

## 3. The reachability graph — model (ADR-0002)

### 3.1 Observed spine (ADR-0001)

The graph's spine is **observed reachability** — edges backed by flows the fleet's own
agents actually saw. It deliberately **undercounts** what is possible (a path policy
permits but no host exercised is invisible); that recall trade-off is accepted because
low-FP is the cornerstone. **Potential reachability** enters only as a later, clearly
labeled enrichment and only for the **host-firewall** slice we can structurally collect
(§4.3). **Fabric-level reachability is out of scope** (§1 non-goals).

We are not starting from zero: the server **already** builds an observed host-to-host
graph today. `FleetTopologyStore` ingests `fleet_snapshot.v1` (per-host processes,
connections with full 4-tuple + state + owning pid, listeners), maintains a cross-fleet
**IP→agent_id map**, and classifies every edge `Local` / `InternalFleet` / `External`
with `dst_agent_id` resolved for intra-fleet edges. It is in-memory only (60s TTL, no
history) — so the graph layer is largely a **persistence + scoring** problem, not a
greenfield collection problem.

### 3.2 Nodes — host + service (two tiers)

- **Host node** — the agent/device. Carries identity, asset-value rollup, and the pivot
  capability (its outbound flows).
- **Service node** — `(host, listening port, protocol, owning process)`. Where a CVE
  attaches and where an inbound edge *terminates*.

A host is **not** an atomic compromise unit; it is a **sub-graph of service nodes joined
by local-IPC edges** (§3.3). **No identity/account nodes** (declared non-goal — no on-box
identity telemetry).

**Instance tiers and the kernel boundary.** One agent sees one OS kernel. Value may be
declared on any addressable instance — **bare-metal / VM / container** — and a host's
effective value is the **max** over its instances/services. Container attribution is
**best-effort and platform-gated** (Linux cgroup via eBPF: full; Windows process-isolated
via Server Silo: partial; **Hyper-V-isolated containers, Docker-on-Mac, and VMs are opaque
kernel boundaries** that need their own agent). Standing rule: **`kernel boundary =
visibility boundary`** — Yuzu never claims cross-kernel X-ray vision (ADR-0002, ADR-0003).

### 3.3 Edges — two classes

- **Network reachability edge** — `src host → dst service`, directional, observed flow.
  Carries the existing `Local`/`InternalFleet`/`External` scope plus (once trust zones are
  declared) the source trust tier.
- **Local-IPC edge** — `service → service` *within* a host: Unix domain socket, named
  pipe, shared memory, mmap, shared/world-writable file, setuid hop, sudo rule. The
  intra-host pivot surface. **Today only sockets are observed; the IPC classes are a
  collection-expansion workstream** that rides the event-capture rewrite (§4.2). This is
  also where **on-box *potential* reachability is feasible** — file/pipe/shmem ACLs and
  privilege boundaries are locally inspectable, unlike network potential reachability.

An edge is merely **reachable** until its destination service carries an exploitable vuln,
at which point it becomes **traversable** (the attack-path weight, §5.1).

### 3.4 Trust zones + entry points

**Trust zones** (`CONTEXT.md`) are an **operator-declared, ordered tier over labeled
CIDRs/sites** — `internet` < `partner-extranet` (MPLS/third-party) < `branch-campus`
(staff sites, weak physical controls) < `datacenter` (crown jewels). Declared, not
inferred: the operator labels the ranges; Yuzu matches them against the `local_ips` and
connection addresses it already collects. This disambiguates the blunt `External` edge
into `internet` / `partner-extranet` / `branch`.

**Entry points** are the *source set* for path enumeration: in v1, any service **exposed
across a trust-zone boundary** (reachable from a lower-trust zone), the lowest tier being
the public Internet. **Assume-breach** (any node as foothold) is a later, separate view
(Phase 8), not the v1 default.

### 3.5 Asset value / crown jewels

Value is **operator-declared** (with inference *hints*, never auto-applied), carried by
the **service**, rolled up to the host by **max**. Two uses of the same axis:

- **Host-max** — the operator-facing "how bad is this box" number.
- **Locally-reachable-max** — for path *scoring*, the value an attacker captures by
  landing on a node is the max over services **locally reachable from the entry service**
  (via §3.3 IPC edges), *not* the host-max. We don't credit an attacker with the crown
  jewel for landing on an unrelated service on the same box — strictly more honest, lower
  FP.

### 3.6 Access control (graph + authoring surfaces) — G7

The scored reachability graph is a **literal map of how to compromise the fleet** — strictly
more sensitive than the findings it ranks — and the trust-zone (§3.4) and crown-jewel (§3.5)
declarations are **new privileged authoring surfaces**. Both need RBAC before they ship, and
neither exists today: RBAC is uniformly `(securable_type, operation)` and there is **no
graph/topology securable type**.

- **Read** — the scored graph, attack paths, and chokepoint output get a **dedicated
  securable type**, gated *tighter* than findings. A path map is offensive intelligence; an
  operator who can read findings should not automatically read "here is the cheapest route to
  the crown jewel." **Read access is audited** — every graph query carries a principal and
  timestamp in the audit log (same envelope as findings access).
- **Write** — authority to declare/edit **trust-zone CIDR-site tiers** and **crown-jewel
  values** is restricted to a privileged role and **audited**. Mis-declaring a tier or a
  jewel silently distorts *every* ranking (it moves entry points and value sinks), so these
  are integrity-sensitive, not cosmetic, config.

Owned by the **auth-and-authz workstream (G7)**, not the scoring model — tracked so it lands
*with* the §3.4/§3.5 authoring surfaces rather than retrofitted after they ship.

---

## 4. Data sources & feasibility (audited 2026-06-08)

### 4.1 What we have, what we must add, what we can never get on-box

| Data | Status | Source / gap |
|---|---|---|
| Per-host processes (pid/ppid/name/cmdline/user) | **Have** | `fleet_snapshot.v1` |
| Per-connection 4-tuple + state + pid + PTR host | **Have** (observed) | `fleet_snapshot.v1`; **poll-based — misses short-lived flows** |
| Listening sockets (host×port×pid) | **Have** | `fleet_snapshot.v1` `listeners[]` |
| Cross-fleet IP→agent edge resolution | **Have** | `FleetTopologyStore` (in-memory, 60s TTL, no history) |
| Tags (role/env/location/service) | **Have** | `TagStore` (SQLite, scope-queryable) |
| **Crown-jewel / asset-value axis** | **Add** | new operator-declared axis (no `criticality` category today) |
| **Trust-zone CIDR/site labels** | **Add** | new operator-authoring surface |
| **Local-IPC edges** (pipe/shmem/file/…) | **Add** | rides event-capture rewrite (§4.2) |
| **Container/instance attribution** | **Add** | eBPF cgroup / Windows silo; opaque across kernel boundaries |
| **Event-driven flow capture** | **Add** | eBPF / ETW / NetworkExtension (§4.2) |
| Persisted reachability graph + history | **Add** | server Postgres + agent edge warehouse (§4.5, ADR-0004) |
| **Host-firewall potential reachability** | **Add (hard)** | firewall plugin reads rules as **unstructured text only**; no structured `(port,proto,CIDR,default-policy)` on any OS — needs real parsing |
| **Fabric reachability** (switch ACL, cloud SG, VLAN) | **Never on-box** | out of scope; upstream seam only (ADR-0001) |

### 4.2 Capture model: poll → event (ADR-0003)

Polling (`/proc/net/tcp`, `GetExtendedTcpTable`, libproc on a 60s snapshot) structurally
misses short-lived connections — fatal for attack-path evidence and C2 detection. Move to
**event capture**, three platform collectors converging on one flow-summary schema:

- **Linux: eBPF** (tcp_connect/accept tracepoints) — mature; cgroup attribution free.
- **Windows: ETW** (Kernel-Network provider; Sysmon EID 3 reference) — mature; silo
  attribution for process-isolated containers; Hyper-V-isolated opaque.
- **macOS: NetworkExtension content filter** — heavyweight (Apple entitlement + system
  extension + consent); **deferred/optional**, justified by other features if at all.
  (Endpoint Security has no network-flow event.)

**Edge-aggregation, not firehose.** Collapse the event stream **in-kernel/at the edge**
into flow summaries `(src, dst, port, proto, first_seen, last_seen, count)` (the
Cilium/Hubble, Datadog-NPM pattern). Lossless on *existence* of a flow (all reachability
needs) while keeping volume near today's poll volume. The summary history stays in the
**agent's local SQLite warehouse** (TAR `tcp_live` precedent), retained, **not flushed** —
each box is a leaf of a distributed SQL warehouse the server queries on demand.

**macOS plays a different graph role anyway.** Laptops are **entry points** (initial
access), not value sinks; their graph role needs only *outbound* flows, which the existing
poll path already gives. Data difficulty is anti-correlated with data need.

### 4.3 Potential reachability (later enrichment)

The firewall plugin today reads firewall on/off and dumps rules as **unstructured text**
(Linux iptables/ufw/firewalld, macOS pf) or partially-structured-but-incomplete (Windows
netsh, inbound only). It cannot compute "what would this host accept." A later enrichment
adds **structured host-firewall parsing** → per-host `(port, proto, allowed-source)` →
*host-firewall potential* edges, clearly labeled and never merged with observed edges.
This is also what would tighten segmentation min-cuts (§5.3). Fabric potential stays out
of scope.

### 4.4 The two-matcher split (ADR-0005)

| | Server-side authoritative matcher | Agent-side KEV pre-filter |
|---|---|---|
| Job | Trustworthy findings — backport-correct, CPE/PURL, version ranges | Cheap local self-flag: "I *might* have a KEV on an exposed service" |
| FP posture | Low-FP, authoritative (the product output) | FP-tolerant — a pruning hint, never a verdict |
| Edge data | none (collect-thin) | the KEV catalog only (~1,200 CVEs) |
| Justification | consistency, freshness control, don't ship NVD/OVAL to 1.2M endpoints | KEV is ~200× smaller than NVD — *that ratio is the line* |

The agent self-flag answers a **node/vuln** question (local, cheap); the **edge/graph**
questions (reachable-from-low-trust? reaches-a-jewel?) stay server-side propagation. The
flag makes a node a **candidate**, not a finding.

### 4.5 Storage substrate (ADR-0004)

- **Agent SQLite** — the federated edge flow-summary warehouse (retained, not flushed),
  queried on demand. The firehose never reaches the server.
- **Server PostgreSQL** — the derived scored graph + last-known endpoint state (offline
  answering) + the cross-store join that *is* the scoring operation
  (`edges ⨝ findings ⨝ value ⨝ guardian_state`) + pgvector (fuzzy software-identity →
  CPE matching, attacking §2.2's `python`/`ipython` problem). Justified for the server by
  Guardian volume at >1M agents and offline-state needs beyond what 24 separate SQLite
  stores serve.
- **Secrets caveat** — "off-box durable state" ≠ "secrets in a Postgres column." Secrets
  need envelope encryption / KMS, a separate decision and review.

### 4.6 Requirement ownership

| # | Requirement | Owner |
|---|---|---|
| R1 | Canonical identity (CPE 2.3 / PURL, not display name) | Eng, Andy validates key products |
| R2 | Version-range semantics (`versionStart*`/`End*`, multi-range) | Eng |
| R3 | Backport/fixed-status (USN/Debian/RHEL-OVAL/Alpine secdb) | **Andy** — feeds, distro order |
| R4 | Data sources & freshness SLO | **Andy** |
| R5 | Prioritisation (CVSS+EPSS+KEV+graph ctx) | **Andy** — scoring model |
| R6 | Coverage (full NVD + kernel + OS + apps) | Andy + Eng |
| R7 | Acceptance / quality bar (precision/recall, zero-FP ref box) | **Andy** |
| R8 | SBOM/SCA (later) | Andy + Eng (Phase 5) |
| **G1** | **Reachability data strategy** (observed spine, potential scope) | **Andy** (ADR-0001) |
| **G2** | **Trust-zone taxonomy** (the tiers, their CIDR/site labels) | **Andy** |
| **G3** | **Crown-jewel definition + inference hints** | **Andy** |
| **G4** | **Traversability probability function** (EPSS/CVSS-exploitability/KEV/auth → P) | **Andy** — heart of the model |
| **G5** | **Depth bound, entry-point definition, segmentation cost model** | **Andy** |
| **G6** | **Acceptance bar for rankings** (match expert intuition on a reference topology) | **Andy** |
| **G7** | **Access control** — graph/chokepoint read securable + trust-zone/crown-jewel authoring authority & audit (§3.6) | **Auth-and-authz workstream** |

---

## 5. Algorithms (ADR-0005)

We **do not enumerate attack paths** (the attack-graph state explosion). Instead:

### 5.1 Attack-path scoring — depth-bounded max-probability paths

Edge weight `w = -log P(traverse)` where `P(traverse)` = probability of exploiting the
**destination service** given reachability (from EPSS × CVSS-exploitability × KEV ×
network-vs-local × auth-required — **G4, Andy's model**). Non-negative weights ⇒
**most-probable path = shortest weighted path = Dijkstra**; top-k = **Yen's k-shortest
paths**; **depth-bounded** (`d ≈ 5`) because real breaches are 2–4 hops and depth-bounding
is both a tractability and a precision lever. Output: a **per-finding attack-path score
that replaces raw CVSS as the default ranking.**

### 5.2 Chokepoints — unweighted chain centrality, not Brandes betweenness (ADR-4003)

Generic betweenness is O(V·E) *and* wrong (weights all-pairs equally) — still rejected, unchanged. **Superseded formula (ADR-4003 Decision 5):** a chokepoint is a node appearing on the single least-complexity path for one or more `(entry point, crown jewel)` pairs; each pair contributes an equal, fixed share of credit (`1/(len(breach_points)·len(crown_jewels))`, split further across tied minimum paths for that pair) — a constant per-pair weight, not a per-node-participation-count normalization — bounded to the declared entry-point/crown-jewel surface, same complexity shape as §5.1's own Dijkstra search, still not Brandes betweenness. This is *not* a literal reuse of §5.1's output: chain centrality runs its own shortest-path search over the graph as extended by ADR-4003's host-privilege-state nodes, which §5.1's plain service-level search doesn't include. It replaces the original `crown-jewel value × path probability` defender-ROI sum (which undercounted a node touching several crown jewels relative to one touching a single valuable target) with equal credit per pair reached — value-weighting the credit was considered and reverted (crown-jewel membership is binary, so there's no gradient to weight by; see ADR-4003's Considered-and-rejected). Only the single lowest-complexity path per pair counts — a real, viable secondary route with strictly higher complexity earns zero credit, CAVM's own accepted design, not an approximation introduced here.

### 5.3 Segmentation — cost-weighted min-cut

Min-cut (Menger) between the entry-zone super-source and crown-jewel super-sink, on the
small relevant subgraph, with **capacities = defender operational cost** (a firewall rule
is cheap; isolating a prod host is expensive). Yields ranked "patch/isolate host X" (node
cut) or "block port X→Y" (edge cut). **Honest caveat:** cuts *observed* paths only;
policy-permitted-but-unobserved paths remain until §4.3 enrichment lands.

### 5.4 Multi-jewel campaign cost — Kruskal/Steiner (later)

For "cheapest campaign to take *all* the jewels," the minimum **Steiner tree** is NP-hard;
the 2-approximation is **MST (Kruskal) over the metric closure** of `{entry} ∪ {jewels}`.
A `≥2`-fan-out-toward-value local flag is a sensible **Steiner-branch-point** seed.
(Minimax/MST also gives a "patch the single hardest hop" weakest-link lens — a *different*
question from our multiplicative whole-chain model; offered as an alternate view.)

### 5.5 Edge pre-filter + server propagation; the scale story

Compute lives in a **server-side background thread** (the `PolicyEvaluator` pattern:
store-pointer deps, lock-released-before-IO, joined-before-stores), ticking on a *cadence*,
reading the Postgres graph into an in-memory adjacency.

**Tractability is N-independent** because (a) depth-bounding makes per-source cost depend
on the *d-hop neighborhood*, not on N, and (b) sources/sinks are bounded by the *declared*
entry/jewel surface, not fleet size. The remaining constraint is graph *loading* at
**1.2M hosts (HSBC scale target)** — solved by the **edge pre-filter**: every agent
self-flags `(has-KEV ∧ exposes-service)`, `(is-crown-jewel)`, `(on-cross-trust-boundary)`
as zero-message local facts, and **the server assembles only the flagged subgraph + its
connecting edges.** Even a pessimistic 5% survival = ~60k host-nodes — trivial for central
propagation. Value-reachability is computed by **O(depth)-round label propagation**
(distributed Bellman-Ford / Pregel "think-like-a-vertex"), run server-side over the pruned
graph. **Escape hatch:** if even the pruned set ever stops fitting centrally, push the
propagation to the agents (true distributed Pregel) — documented, not v1.

**The local tripwire proposes; the bounded propagation confirms.** A local-heuristic flag
is never shipped as a finding.

---

## 6. From finding to action — scope-walking

The graph layer *produces host sets* (hosts on a probable attack path to a jewel; the
chokepoint hosts). **Scope-walking materializes those as result sets**
(`from_result_set:<id>`) that are immediately actionable — patch them, target a Guardian
baseline at them, re-scan them, run an instruction — with `parent_id` lineage giving the
audit chain "this remediation targeted the output of that attack-path analysis." Scope-
walking is **not** how the graph is built (result sets hold device sets, not edges); it is
how the graph's **conclusions become enforcement** — a primitive no standalone scanner has.

---

## 7. Phased roadmap

Each phase is a shippable slice with an Andy-owned acceptance bar.

**Parity floor**

- **Phase 0 — Spike (DONE, #1206).** Rule-delivery plumbing, inventory action, collection
  breadth. *Outcome: plumbing proven; matcher acknowledged PoC-grade.*
- **Phase 1 — Server-side correlation MVP.** Inventory emits normalised identity
  (CPE/PURL + source + arch); server matches against an NVD mirror with **real
  version-range logic** for a pilot product set. *Acceptance: match parity vs a
  hand-labelled reference host; no lower-bound FPs.*
- **Phase 2 — Backport correctness (the FP killer).** Distro-advisory/OVAL correlation so
  patched packages report clean. *Acceptance: a fully-patched Ubuntu + RHEL box returns
  ZERO package CVEs.* This is what makes the product trustworthy.
- **Phase 3 — Prioritisation.** CVSS vector + EPSS + KEV on every finding; ship the `kev`
  flag in the rule + result schema (enables §4.4). *Acceptance: the scoring model and
  default thresholds.*
- **Phase 4 — Coverage breadth.** Full ingest; kernel (fix CPE identity), Windows (MSRC),
  endpoint apps; pgvector-assisted identity matching. *Acceptance: target product list
  covered; recall measured against a known-vulnerable set.*
- **Phase 5 — SBOM / SCA.** Language-ecosystem deps. *Acceptance: later.*

**Graph differentiator**

- **Phase 6 — Topology ingest & persistence.** Persist the observed reachability graph
  (server Postgres + agent edge warehouse, ADR-0004); event-capture rewrite begins
  (ADR-0003); **trust-zone authoring** + **crown-jewel authoring** surfaces.
  *Acceptance (Andy): the persisted graph faithfully reproduces a known reference topology;
  trust zones and crown jewels are authorable and queryable.*
- **Phase 7 — Attack-path scoring.** §5.1 + §5.5 (Dijkstra/Yen, edge pre-filter, server
  propagation). **Per-finding attack-path score replaces CVSS as the default ranking.**
  *Acceptance (Andy): on a reference topology, the top-ranked findings are the ones the
  expert agrees are scariest; the ranking inverts at least one "critical-CVSS-but-isolated
  < medium-CVSS-on-pivot" case correctly.*
- **Phase 8 — Chokepoints & segmentation.** §5.2 + §5.3 (chain-centrality chokepoints
  (ADR-4003), cost-weighted min-cut recs); assume-breach as a second view; Kruskal/Steiner
  multi-jewel campaign cost. *Acceptance (Andy): the #1 recommended segmentation actually
  breaks the most at-risk value per unit effort on a reference topology.*

---

## 8. Quality bar

- **Precision** ≥ target on a labelled fleet (backport FPs the main enemy; a patched
  reference box reports clean).
- **Recall** ≥ target against a known-vulnerable set — *and* an honest recall statement
  for the graph: observed reachability undercounts potential.
- **Freshness**: data-plane sync SLO (e.g. ≤ 24h from advisory publication).
- **On-box cost**: inventory + flow-summary aggregation bounded (CPU/mem/time per scan).
- **Scale**: tractable to **1.2M hosts** via edge pre-filter + depth-bounded propagation.
- **Honesty**: until Phase 2 lands, `capability-map.md` describes this as an early
  heuristic matcher, **not** "modern vulnerability scanning"; until Phase 7, no attack-path
  claims.

---

## 9. Open decisions for Andy (resolved ones marked ✓)

1. ✓ **Observed-grounded spine; fabric out of scope, upstream seam only** (ADR-0001).
2. ✓ **Node model: host + service; host = sub-graph of services + local-IPC edges; no
   identity nodes** (ADR-0002).
3. ✓ **Capture: event-driven (eBPF/ETW/NE), edge-aggregated, federated edge warehouse**
   (ADR-0003).
4. ✓ **Storage: server Postgres + agent SQLite edge warehouse; secrets separate**
   (ADR-0004).
5. ✓ **Value: service-carried, max-rollup, operator-declared + hints; crown jewel new &
   orthogonal.**
6. ✓ **Trust zones: operator-declared CIDR/site tiers; v1 default = cross-trust-zone
   exposure.**
7. ✓ **Algorithms: depth-bounded max-probability paths; path-set-frequency chokepoints;
   cost-weighted min-cut; Kruskal-Steiner for multi-jewel (later)** (ADR-0005).
8. **Primary correlation data source?** (OSV.dev vs NVD+OVAL composition.)
9. **Distro priority order** for backport feeds?
10. **G4 — the traversability probability function** (the scoring model's heart).
11. **G5 — depth bound, segmentation cost model.**
12. **G6 — acceptance thresholds + the reference fleet/topology.**
13. **Target product/coverage list** for Phase 1 pilot and Phase 4 breadth.

---

## Appendix A — Evidence from the #1206 spike

- Configured keywords: 31. Products with ≥1 generated rule: **10** (`apache, curl, log4j,
  nginx, openjdk, openssh, openssl, polkit, sudo, 7-zip`).
- Zero rules: `chrome, confluence, docker, dotnet, exim, firefox, git, grafana, jenkins,
  kubernetes, linux-kernel, mysql, postfix, postgresql, putty, python, samba, windows,
  winrar`.
- `kernel_scan` (Linux/macOS) and the Windows path have no rules to match.
- Matching primitive: `icontains(app.name, rule.product) && compare_versions(app.version,
  affected_below) < 0`. Rule schema collapses NVD ranges to a single `affected_below`,
  discarding lower bounds; CVEs without a single end bound are dropped.

## Appendix B — Decisions of record (ADRs)

- **ADR-0001** — Observed-grounded reachability (observed vs potential; fabric out of scope).
- **ADR-0002** — Reachability graph data model (host+service nodes, local-IPC edges, trust
  zones, crown-jewel value, kernel-boundary rule).
- **ADR-0003** — Telemetry capture model (poll→event eBPF/ETW/NE; edge aggregation;
  federated edge warehouse).
- **ADR-0004** — Server storage substrate (Postgres under the server; agent SQLite edge
  warehouse; secrets caveat).
- **ADR-0005** — Attack-path & chokepoint scoring (depth-bounded max-probability paths;
  cost-weighted min-cut; two-matcher KEV pre-filter; distributed-Pregel escape hatch).
  Its original chokepoint formula (path-set-frequency, defender-ROI-weighted) is superseded
  by ADR-4003 — see that ADR's own file for the amendment note.
- **ADR-1005** — Headless platform / use-case engines (this doc's server-side placement is
  interim — grandfathered surface #2; see the reconciliation note at the top).
- **ADR-0023** — Vulnerability correlation engine (in-server, absorbed-interim under ADR-1005).
- **ADR-4003** — CAVM v20 adoption on the reachability graph (§5.2's chain-centrality
  chokepoint formula, the host-privilege-state ladder, EUC, AMAPC/CPS — supersedes ADR-0005's
  original chokepoint formula specifically; attack-path scoring §5.1 and segmentation §5.3
  are unaffected).
- **ADR-4001** — Vulnerability dashboard + Attack Path Explorer (in-server lens,
  absorbed-interim under ADR-1005; ADR-4002's scoring substrate not absorbed).
