# Yuzu Context

Yuzu is an agentic enterprise endpoint management platform. It provides one control plane where humans and agentic workers can query, command, scan, patch, and enforce policy compliance across Windows, Linux, and macOS fleets.

## Agent daemon

The C++ endpoint process under `agents/core/` that runs on a managed device, maintains server or gateway connectivity, executes plugin actions, reports results, and enforces local policy.

## Governance agent

A review role used during the governance pipeline. In Claude these roles live under `.claude/agents/`; in Codex they are compact role prompts in `.codex/skills/governance/SKILL.md`.

## Agentic worker

An external LLM-driven client that operates Yuzu through MCP, REST, or the dashboard. Agentic workers need stable discovery, consistent error envelopes, auditable actions, and operator-equivalent workflows.

## Instruction

A typed unit of endpoint work. Instructions are defined as YAML-backed `InstructionDefinition` content, grouped into instruction sets and product packs, dispatched through the command protocol, and persisted with audit and response data.

## Product pack

A packaged set of instruction content that represents a coherent operational capability. Product packs are build-time embedded from `content/packs/*.yaml` and seed the server's instruction store on first boot.

## Scope

The device target expression for an instruction, policy, query, or workflow. Scopes compose filters such as tags, OS, management groups, and prior result sets; they are part of the authorization and audit boundary.

## Confinement (list-read confinement)

Management-group narrowing of a per-agent *list / fan-out* read (ADR-0017, the admit-then-filter list gate): **admit** an operator who holds the read securable in *any* scope — globally or via at least one management group — **then filter** the result to the agents their management groups make visible (descendant-ward). Distinct from a per-*device* ownership check (one `agent_id`) and from **Scope** (a device-set *target* expression): confinement is the read-side authorization boundary on a multi-agent result. Fails closed on a corrupt/load-failed `rbac.db` — an operator who cannot be scoped sees nothing, never the fleet. The single chokepoint is `RbacStore::authorize_list_read → DenyAll | AdmitAll | AdmitScoped(visible_set)`.

The global↔management-group **combining lattice** (frozen by #1715) is *cross-boundary additive*: a global **allow** admits all and overrides a group deny; a global **deny** does **not** override a group allow (authority to read a row comes *from* the group grant); deny-overrides applies only *within* a single group's assignments. One resolver backs the admit, the batched visible-set, and per-device `check_scoped_permission`, so list and per-device authorization can never diverge.

## Guardian

The Guaranteed State policy enforcement system. Guardian evaluates desired-state policy fragments, triggers checks or remediation, and can route sensitive actions through approval or quarantine flows.

## Guard

A single Guaranteed-State rule: a trigger (Spark), a desired-state check (Assertion), and an optional remediation. A Guard has its own enabled/disabled state, an Observe-or-Enforce mode, and optional Prerequisites. A Guard is a building block — on its own it is a definition only and is never deployed; it reaches devices only as a member of a Baseline.

## Baseline

A named, deployable collection of one or more Guards, targeted at devices via an **assignment**: a set of *included* management groups minus a set of *excluded* management groups (exclusion wins — a device in both an included and an excluded group is not targeted). The Baseline is the only deployable unit in Guardian — **individual Guards are never deployed on their own** (the same shape as a Jamf Configuration Profile, an Intune baseline, or a GPO). Deploying a Baseline applies its enabled member Guards to the assigned devices, subject to each Guard's Prerequisites.

## Assignment

A Baseline's device targeting: a set of *included* management groups minus a set of *excluded* management groups, where **exclusion wins** (a device in both an included and an excluded group is not targeted). Targeting is at whole-Baseline granularity — the same shape as a Jamf Configuration Profile's Scope (Targets − Exclusions) or an Intune assignment. A management group may be static (explicit members) or dynamic (criteria-defined, the equivalent of a Jamf Smart Group). Distinct from a Guard's **Prerequisites**, which gate applicability one level finer, per-Guard.

## Prerequisites

A Guard's technical applicability condition — a Scope expression over device facts (e.g. OS version, form factor, installed software) that must hold for the Guard to apply on a given device. Prerequisites are distinct from a Baseline's management-group targeting: a Guard applies on a device when the device is in the Baseline's management groups **and** the device satisfies the Guard's Prerequisites.

## Mode (Observe / Enforce)

A Guard's response posture. **Observe** detects and alerts on drift without writing back (the user-facing term; it replaces the earlier "Watch", and the still-older "audit" — the stored/wire value remains `audit`). **Enforce** additionally remediates — writing the expected state back, governed by the Guard's resilience policy. Mode is fixed when the Guard is authored; a different posture is a different Guard.

## Deploy

Applying Guardian policy to devices. Deploying a Baseline **converges every assigned device to its complete desired guard set** — the per-device union of the enabled member Guards of all deployed Baselines whose assignment includes that device, each gated by the device's Prerequisites. Convergence is to a device's *total* policy (as in Puppet/DSC/GPO), not to one Baseline's fragment; so removing a Guard from a Baseline and re-deploying actually removes it from any device no other deployed Baseline still delivers it to.

## TAR

Timeline Activity Record. TAR captures ordered endpoint activity and response history so operators and agentic workers can reconstruct what happened during investigation, remediation, and audit workflows.

## Gateway

The Erlang service under `gateway/` that scales agent connectivity and command fanout. It proxies registration and heartbeat traffic upstream to the server, exposes agent-facing gRPC, and provides management forwarding for server-dispatched commands.

## Gateway cluster

A **trust-zone- or region-scoped** set of gateway nodes forming one OTP cluster, fronting its own slice of the fleet (ADR-2002). The cluster is the unit of gateway topology: internal-vs-external-facing and regional gateways are **separate** clusters (Erlang distribution's shared-cookie mesh must not span a DMZ or a WAN), and intra-zone scale is more **nodes** in a cluster, not more clusters. An agent is **pinned to its zone's cluster** and never fails over across zones. Any server locates an agent's owning cluster via the Postgres **agent→gateway-cluster routing directory**, then reaches any healthy node of that cluster (OTP `pg` finds the exact node). Distinct from a bare **Gateway** (a single node/service): the cluster is the HA and multi-gateway boundary.

## Coordination substrate

The mechanism the **active–active core tier** uses to agree and signal across instances (ADR-2002): **leader election** (which core instance runs the singleton background work) and **cross-instance signalling** (waking peers to a new event). Owned by **core** (the sole `yuzu` authority) — presentation replicas never hold coordination locks or `LISTEN` connections. It sits behind a narrow seam with a **Postgres-backed default** — advisory-lock leadership + `LISTEN`/`NOTIFY`-as-hint over durable tables — pluggable for SaaS without touching call sites. Chosen because Postgres already bounds system availability, so a Postgres-backed default adds no new single point of failure. Distinct from the **storage substrate** (Postgres-as-database, ADR-0006): the coordination substrate is Postgres-as-coordinator.

## Server tier

The collective **active–active replicated server-role set** behind the operator plane (ADR-2002) — comprising **two distinct replication axes** under the accepted presentation/core/engine decomposition (ADR-0031/0032/0033): **presentation** replicas, which terminate HTTP/SSE/MCP and **front the operator-plane load balancer** (inside the bearer-credential trust boundary, no `yuzu`-database access of their own), and **core** replicas, the **API authority and sole `yuzu`-database writer** plus owner of the coordination substrate (leader lock, event outbox, background workers), sitting **behind** presentation. In today's monolith both roles are one binary; the split binds prospectively. **Not** a fused server+everything box, and **not** core alone. Distinct from **gateway clusters** (the agent-plane concentrator) and **engine replicas/jobs** (the UCE, with its own database) — both separate axes, and `yuzu`-database availability is distinct from engine-database availability. Server-tier HA and **storage HA** (HA Postgres) are orthogonal: either can exist without the other.

## Reachability

Whether one node in the fleet can initiate a network connection to another. Yuzu distinguishes two kinds and commits to one:

- **Observed reachability** — an edge backed by a network flow the fleet's own agents *actually saw* (a `fleet_snapshot.v1` connection whose destination resolves to another fleet member via the server's IP→agent map). This is the spine of Yuzu's reachability graph. It deliberately **undercounts** what is possible — a path that policy permits but no host ever exercised is invisible — and that recall trade-off is accepted because trustworthy, low-false-positive results are the product's cornerstone.
- **Potential reachability** — what the network/firewall *policy would allow*, independent of whether a flow was ever observed. Yuzu can only ever approximate the **host-firewall** slice of this (the set of `(port, protocol, allowed-source)` a host would accept), and only after structured firewall parsing that does not exist yet — it is a later, clearly-labeled enrichment, never conflated with observed edges.

**Fabric-level reachability** — what switch/router ACLs, cloud security groups, and VLAN segmentation permit — is **out of scope**: an on-box agent cannot see it and Yuzu never fabricates it. A seam is left to *consume* it from an upstream source or *publish* Yuzu's observed graph upstream in a future iteration.

Distinct from **Scope**, which is a device-*set* target expression, not a graph; reachability is about edges between nodes, not membership.

## Cohort

The comparison population for fleet-relative performance benchmarking: the set of reporting devices sharing a value for an **operator-chosen tag key** (e.g. every device tagged `model: Latitude 7440`, or `image: vanilla` vs `image: layered`). Cohorts are derived from tags — never from self-asserted inventory or a central hardware column — so hardware-model cohorts exist only where an operator (or an agentic worker, via the asset-tagging recipe) has tagged the fleet. A cohort below the statistical floor (10 reporting devices) is reported as too small rather than given noisy percentiles; devices carrying no value for the chosen key form an explicit untagged residual, never a silent omission. Distinct from **Scope** (a targeting expression) and from a Management Group (an authz/targeting grouping): a cohort is a read-side analytical grouping with no authorization meaning.

## Reporting population

The denominator that travels with every fleet-aggregate performance statistic: how many devices actually contributed values in the current cycle. A fleet average over 12 devices is never presented as fleet-wide truth without its population; a metric nobody reported is absent, never a fabricated zero.

## App-perf daily roll-up (B1)

The centralized per-device daily summary of a device's **resource-significant app-versions**: one record per `(device, app, version, UTC day)` carrying sample-weighted CPU and working-set averages, their peaks, and a sample count, derived on the agent from the on-device `procperf_hourly` warehouse and shipped daily. It is the fleet-queryable layer ("which devices ran v124, and how did it perform") that complements the on-device, federated-on-demand drill — distinct from **installed software** inventory (a complete app-presence census; B1 is performance over the top-N consumers only).

## App-perf fleet roll-up (B2)

The fleet-aggregate trend layer over [[App-perf daily roll-up (B1)]]: one record per `(app, version, UTC day)` summarising how that app-version performed **across all devices** that ran it that day — device count, fleet CPU/working-set means and maxima, and a fixed-bucket histogram of the per-device daily values from which fleet percentiles are derived. It deliberately drops the device dimension (no `agent_id`) — it answers "did v125 run hotter than v124 across the fleet", not "on which device". Distinct from B1 (per-device, 31-day, the drill-down source) by retention (180 days) and grain (fleet, not device).

## Resource-significant app-version

An `(application, version)` pair that appeared among a device's top-N CPU- or working-set-consuming processes during sampling, and therefore the unit B1 measures. The qualifier is load-bearing: B1 deliberately does **not** record every app that ran — only those significant enough to surface in `procperf` — so "ran on this device" in a B1 context always means "ran among its top resource consumers."

## Asset value (Crown jewel)

A risk-weighting of how much a node matters to defend — a *value* axis, **orthogonal** to tags, management groups, and scope (which are *targeting* axes). **Operator-declared**: the defender knows what matters and Yuzu does not guess it, though optional inference *hints* may suggest a value (never auto-apply it). Value is carried by the **service** — the process/listening unit where a vulnerability and an exposed port actually live — and may also be declared on an addressable instance (container, VM, bare-metal host). A host's **effective value is the maximum** of the values of the services/instances it carries: a box is as valuable a target as its most valuable tenant. A **crown jewel** is the high end of that axis — the service whose compromise is the attacker's objective and the defender's nightmare. New term; does not collide with any existing Yuzu concept. Built as a 3-tier operator-declared value (`crown-jewel`/`high`/`standard`) via a dedicated mechanism and RBAC securable, not the tag system (ADR-4003).

## Trust zone

An operator-declared, ordered trust tier over network positions — a labeled set of CIDRs and/or sites (e.g. `internet` < `partner-extranet` (MPLS / third-party via an extranet block) < `branch-campus` (staff sites with fewer physical controls) < `datacenter` (where crown jewels live)). Trust zones are **declared, not inferred**: Yuzu cannot tell that `10.50.0.0/16` is the branch LAN or that an off-fleet peer arrived over an MPLS extranet — the operator labels the ranges, which Yuzu matches against the host `local_ips` and connection addresses it already collects. This is what disambiguates the blunt `External` edge into `internet` / `partner-extranet` / `branch`. A flow crossing from a lower-trust zone into a higher-trust one is a **cross-trust-boundary** edge — the source side of attack-path enumeration and the cut side of segmentation analysis. **Orthogonal** to **Management Group** (device-grouping for authz/targeting) and to **Scope** (a device-set expression): a host sits in exactly one trust zone *and* any number of management groups. With **Asset value**, trust zones bracket the attack graph — value declares *what attackers are after*, trust zones declare *where they start*. CAVM's three breach-point categories (internet-facing / user-reachable / third-party) map directly onto entry points derived from crossing the lowest / a low-trust staff / a partner-extranet zone boundary respectively, rather than needing a separate breach-point classification (ADR-4003).

## Entry point

A service an attacker is assumed able to reach from outside a defended zone — the *source set* for attack-path enumeration. In v1, an entry point is any service **exposed across a trust-zone boundary** (reachable from a zone of lower trust than the service's own), the lowest tier being the public Internet; laptops in low-trust staff zones are entry points as phishing / initial-access landing nodes. **Assume-breach** entry — treating *any* node as a possible foothold to model post-initial-access lateral movement — is a later, explicitly separate view, not the v1 default.

## Attack path

A directed chain through the reachability graph from an **entry point** to a **crown jewel**, where each hop is an observed reachability edge whose destination service carries an exploitable vulnerability. Each hop is weighted by the probability an attacker can exploit the destination service on arrival; the path's score is the product of its hop probabilities — found as a shortest *weighted* path so the **most probable** route surfaces, depth-bounded to the few hops that constitute a real threat. A finding's rank is driven by whether it sits on a short, probable attack path to value — **not** by raw CVSS. Distinct from **TAR** (observed temporal activity): an attack path is a structural statement about *possible* compromise routes, grounded in observed reachability but oriented toward what *could* happen. **AMAPC** formalizes this same shortest-weighted-path concept as a fleet-level board metric — the per-crown-jewel minimum, averaged (ADR-4003).

## Chokepoint

A node or edge lying on many high-value attack paths, such that removing it — patching/isolating the host, or closing the port/flow — severs the most at-risk value for the least defender effort. **Ranked by unweighted chain centrality (ADR-4003):** for every (entry point, crown jewel) pair, equal credit accrues to every node on the single least-complex — equivalently, most probable (ADR-4003, citing CAVM Annex I.3) — path between them, summed across every pair a node sits on. This retired an earlier `crown-jewel value × path probability` formulation that excluded centrality outright; the current form gives credit to nodes sitting on paths to *multiple* crown jewels, not just one, rather than weighting by value — crown-jewel membership is binary (see **Asset value**), so there's no gradient within the set to weight by. The minimum-effort set of removals that fully severs a trust zone from crown jewels it should not reach is a **segmentation recommendation** (a cost-weighted min-cut). Because the graph is observed-grounded, a chokepoint severs *observed* paths; policy-permitted-but-unobserved paths are out of scope until host-firewall potential-reachability enrichment lands.

## EUC (Exploitation Utility Classification)

A per-instance classification of the attacker-state transition a specific finding enables on a specific service, given the attacker's current privilege state and the service's network position: **foothold** (initial access, no prior presence needed), **lateral movement** (presence on an adjacent node grants access here), **privilege escalation** (elevates privilege on the same host), or **data access** (exposes sensitive data without necessarily enabling further movement). Per-instance, not per-CVE — the same CVE produces a different EUC depending on where it's approached from — so EUC is a graph-**edge** property, computed at graph-construction time by `attack_path_engine`, never stored on a finding row (ADR-4003).

## AMAPC (Average Minimum Attack Path Complexity)

The board-level resilience metric: for each crown jewel with an evidenced **attack path**, the complexity of the single least-complex route from any entry point, averaged across every crown jewel that has one — always reported alongside the count of crown jewels with **no** evidenced path, never alone. Complexity is additive across hops and mathematically equivalent to the negative log of the path's success probability, so "least complex" and "most probable" are the same quantity (ADR-4003, CAVM Annex I). Distinct from **Chokepoint** (ranks nodes for remediation priority) and the **composite priority score** (ranks individual vulnerabilities) — AMAPC is a fleet-level outcome metric, not a ranking mechanism.

## Composite priority score (CPS)

The per-vulnerability ranking score a remediation queue is actually ordered by: a weighted blend of chain centrality, crown-jewel reachability, chained risk, and an EPSS-based attacker-prior component (CTI-weighted when available, EPSS-only otherwise) (ADR-4003). Distinct from **AMAPC** — CPS ranks individual findings for remediation ordering; AMAPC is the board-level aggregate those rankings are designed to improve.

## Graph coverage

CAVM's assurance measure underneath its other scoring outputs (ADR-4003): the confidence distribution across reachability edges, and the proportion of nodes carrying a confirmed asset identity across data sources. A rising **AMAPC** drawn from falling graph coverage is not evidence of anything — coverage qualifies every other CAVM metric and is reported alongside them, not beneath them. Measures the reachability *graph's* completeness, not CVE-assessment completeness — a deliberately distinct name from any per-endpoint finding-assessment coverage metric, so the two never sit ambiguously side by side on a dashboard.

## Gate state

A field on a `triaged` or `mitigated` finding (ADR-4004) marking whether it's under active remediation scheduling and, if so, how protected it is from being silently re-prioritized by routine rescoring: `none` (unscheduled), `scheduled` (a change record raised), `in_progress` (change window open, no rescore interrupts), or `deferred` (an explicit, TTL-bound pause). Null for every other disposition — it answers a narrower question than the disposition lifecycle itself.

## Assessment coverage

The vulnerability-management module's own coverage metric, named by ADR-4004: the UNKNOWN-fraction and LOW-provenance-fraction of a device's assessed packages, stamped as-of-inventory — the honest measure of "how much did we actually assess," not inferable from the vulnerability count (the underlying assessment axis is ADR-0019's). Measures per-endpoint CVE-assessment completeness specifically — a deliberately distinct name from any reachability-graph coverage metric, so the two never sit ambiguously side by side on a dashboard.

## Component inventory

The per-endpoint census of individual software *components* — including ones no package manager
or OS registry enumerates as a discrete product: a library bundled inside an installed
application, an embedded Electron/Chromium runtime, or a filesystem-resident language dependency
(`node_modules`, a venv, an on-disk JAR, a Go/Rust module graph). Distinct from **installed
software inventory** (the package-manager/registry-level, top-level-product census
`installed_software` already collects, ADR-0016) — a component inventory reaches one layer deeper,
into what a top-level product actually bundles or depends on. Stored in Yuzu's own relational
schema (ADR-0028); not the same thing as an **SBOM**.
_Avoid_: SBOM (as the name of the internal capability), dependency tree, software inventory (ambiguous with the top-level census).

## SBOM (Software Bill of Materials)

A standardized export/import **document format** (CycloneDX or SPDX) describing a software
component inventory. Yuzu does not store data natively in either format — SBOM names the interop
artifact a **component inventory** can be projected into (export) or parsed from (import), not the
internal collection capability or its storage format (ADR-0028 §Decision 6). Roadmap Issue 18.5
("SBOM Ingest") imports externally-produced SBOMs; ADR-0028 generates a component inventory
first-party; a future export feature would project ADR-0028's data into an SBOM document for the
first time.
_Avoid_: using "SBOM" loosely to mean the internal component inventory itself.

## Demo

A demonstration of Yuzu run **live against a real fleet** — never against fabricated findings. Yuzu's cornerstone is that it never invents data ("a metric nobody reported is absent, never a fabricated zero"); that rule holds **in demos too**. Realism comes from constructing a real **environment** that genuinely exhibits a condition (a device with a real pending reboot, a really-degraded link, a really-crashing service), then **observing it live and remediating it live**. Remediation runs through the **real approval and tier/RBAC gates** — the agentic worker executes only **after a human approves**, via the same `execute_instruction`/`execute_bundle` path a customer uses; there is **no demo bypass** (a demo-only write path would violate agentic-first the same way a fabricated read does). "Take the risk" means accepting that a live run may not behave exactly like a canned script would — **not** relaxing any safety gate. A "demo" is therefore a *staged environment plus a live, fully-gated operator/agentic-worker flow over the real tools*, not a special data path: there is **no fabricated-finding mode**. Distinct from the **golden-prompt pack** (`enterprise-it-v1`), which is a prompt-evaluation fixture set, not demo output. Cuts against the retired curated/`DEMO DATA` mode (PR #1653).

## Engine principal

A long-lived service principal representing an external consumer of the Yuzu server — a use-case engine or an agentic worker acting as a service (ADR-1005). Authenticates with its own credentials and carries its own least-privilege RBAC grants; an engine principal holding the union of its users' permissions is a design defect. Always written "engine principal", never bare "engine" — *engine* alone is already load-bearing in this codebase for internal components (Instruction Engine, Policy Engine, Scope Engine, SparkEngine, …). Distinct from the **agent daemon** (a managed endpoint) and from a human operator's session; audited as its own `principal_class`. Acting on a specific operator's initiative requires server-issued delegation, never an engine-asserted header.

## Use-case engine host (UCE)

The first-party deployable that hosts use-case modules (vulnerability management first; software asset management and others later) — auth/delegation plumbing, server-sync, and a UI shell shared by all modules (ADR-1005 Decision 6). Consumes the Yuzu server exclusively through the versioned REST/MCP surface as one or more engine principals — no shared database, no co-deployment assumption, no private seam. Ships as a separate artifact from `yuzu-server` (target ship shape); customers may take, replace, or omit it. "UCE" is the execution plan's shorthand (`docs/adr-1005-execution-plan.md`); the ADR itself spells out "use-case engine host". Stores only derived domain state — findings, license positions — never a fleet copy (execution-plan Decision 6).

## First-party UI

Collectively, the use-case engine host's UI and the in-server admin console (ADR-1005). First-party status confers no privilege: both compose the same public, versioned APIs as any external consumer — if our UI needs a capability, it becomes an API first. The existing full dashboard is a grandfathered surface, not first-party UI in this sense.

## Admin console

The thin in-server surface retained under the headless-platform direction (ADR-1005 Decision 7): the bootstrap/break-glass set — enrollment and device liveness, health/readiness, RBAC and principal management, settings, audit view. The list is **closed**; adding a console surface requires amending ADR-1005. Distinct from the existing full dashboard, which remains supported and shrinks toward the console via a strangler migration, never a forced one. Must function with zero dependency on any engine being reachable.

## Operator

The initiating principal of an action — human **or** agentic (ADR-1005 terminology). Where a rule applies only to humans, docs say "human operator". Complements the three-way "agent" disambiguation above (agent daemon / governance agent / agentic worker): an agentic worker acting through MCP/REST is an operator; the agent daemon is never one.
