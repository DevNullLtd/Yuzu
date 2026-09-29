# UCE host — v1 requirements (ADR-1005 exec-plan item 2c)

Status: **Draft for governance review** — the execution plan's item 2c
(`docs/adr-1005-execution-plan.md`, Phase 2). This document captures plan
Decisions 2–6, 11–12, and 14 as functional/non-functional requirements on the
use-case-engine (UCE) host, and lands two normative commitments the plan
forbids deferring past the module's first store-shipping milestone: the
Decision-14 confinement mechanism (§6) and the findings-store data-inventory
entry (§7). It is consumed
by the stack ADR (which follows as its own PR once these requirements settle)
and by track 2d (the vulnerability module build, M1–M4).

Citation convention (mirrors `docs/auth-engine-principals-design.md`): **"plan
Decision N"** = the execution plan's own decision log; **"ADR-1005 Decision N"**
= the ADR's numbered decisions. The two logs collide numerically and are *not*
the same; the plan's log entry 1 warns of this. (The 0022→1005 rename, PR #2035,
is merged to `dev`; the companion paths below are the live 1005 names, matching
`docs/auth-engine-principals-design.md`.)

Companion docs:
`docs/adr/1005-headless-platform-use-case-engines.md` (ADR-1005 — stable policy),
`docs/adr-1005-execution-plan.md` (phases + the plan Decision log this doc
implements), `docs/auth-engine-principals-design.md` (2b — supplies the §5
delegation primitive this doc's §6 builds on, and the §10 confinement
candidates), `docs/adr/0017-management-group-confinement-list-reads.md`
(ADR-0017 — the `authorize_list_read` confinement chokepoint whose outcome §6
must match), `docs/enterprise-readiness-soc2-first-customer.md` §3.5 (the data
inventory §7 registers into), `docs/vuln-scan-engine-design.md` (the vuln
module's north-star, referenced by plan Decision 5/13), `docs/uce-deployment-topology-design.md` (deployment topology decided 2026-07-12 — the concrete cross-origin login flow + PG isolation + implementation plan; deciding NF-2/NF-3/NF-7/NF-8/NF-9/§10).

---

## 1. Scope & charter

The UCE host is the separately-deployed runtime that hosts use-case engine
modules (vulnerability management first; software asset management and others
later) against the headless Yuzu server (ADR-1005). This document is the
committed requirements input plan Decision 11 makes a precondition for choosing
the host's runtime/language — that choice is the **stack ADR**, which follows
this doc as its own PR and is out of scope here.

**What this document decides.** Functional and non-functional requirements
derived from plan Decisions 2–6, 11–12, and 14; the concrete confinement
mechanism for Decision 14 (§6); the findings-store data-inventory entry (§7).
Each requirement carries a stable ID (`F-n` / `NF-n`), a one-sentence MUST/MUST
NOT invariant, a source citation, and a verification hook (a module milestone,
a phase gate, or a CI check) — the stack ADR and the 2d milestones cite these
IDs, so they are stable contract, not prose.

**Host-universal vs first-module — a labelling convention.** The UCE host is
**use-case-agnostic**; most requirements below are *host-universal* and bind every
module. A few are specific to the **first module (vulnerability management)** — its
data flow (F-1) and its findings-store lifecycle (§3.5, §7). Those are tagged
**[first module]** and are the concrete *instance* that satisfies a host obligation
(the exec-plan mandates 2c include "a data-inventory entry for the module's own
findings store"), **not** host-universal requirements — a second module (e.g.
software asset management) registers its own equivalents and is not bound by the
vuln module's internal data model. The host doc deliberately does **not** dictate a
module's storage/fidelity/roll-up choices (those are the module's design, e.g. 2d);
it constrains only the shared seams every module uses — the access layer, the ≥500k
query/fan-out, confinement, hand-off, deployment, and audit posture.

**What this document does NOT decide** (named so 2c does not silently re-open
settled hand-offs — sources: plan Decisions, 2b §10):

- The host runtime/language, web/UI stack, packaging, and migration tooling →
  the stack ADR (plan Decision 11).
- Internal-vs-external engine-credential classification mechanics → plan PR 4.3
  (2b §10; a store field is reserved there, not here).
- Quota beyond the minimum issuance interlock → Phase 8 (2b §10; interlock
  tracked #1973).
- ADR-0017 ladder sequencing and the #1715 deny-precedence decision →
  maintainer (2b §10). This doc consumes the `authorize_list_read` chokepoint's
  *outcome* as a contract and does not design or reorder it — with one named
  exception: INV-10 requires the chokepoint's response surface a completeness
  signal, a response-shape input to PR-A (called out at INV-10).
- Write-back, remediation dispatch, and engine-initiated result-set
  materialization → gated on ADR-1005 Decision 5 delegation (plan Decision 1;
  see §8 Non-goals).
- The Workstream-G customer-assurance deliverables plan Decision 13 names — the
  pilot-readiness "what's in / what's out" note and the security-whitepaper /
  shared-responsibility-matrix update for the UCE's new deployment topology. This
  doc is their **technical input, not their author**; named here (per 2b §10's
  "don't silently assume the exec plan's mention is enough") so they are not lost.
- The engine-principal **onboarding walkthrough** (mint → one-time reveal → get
  the secret into the module) → owed against plan PR 4.3 / the pilot-onboarding
  playbook (2b §10), not this doc. **The pilot-onboarding content owed to
  Workstream G is the FULL stand-up** — stand up the VM → provision the PG
  role/DB → configure cross-origin + SSO-via-Yuzu → mint the engine principal →
  connect (topology `docs/uce-deployment-topology-design.md` §5 T1–T5) — not only
  the engine-principal tail; and it must name the **operator-visible redirect** to
  the Yuzu origin at first login (a pilot-visible moment on a separately-branded
  surface) so admins/support are not caught out.
- **The vuln module's machine-callable "confirm-now" action** (a finding-scoped
  re-check an automated patching caller invokes) → a named **2d reconciliation
  item** against F-10/plan Decision 3 ("no machine consumer of the UCE"): the
  module design proposes it as a REST+MCP action, which F-10 forbids on the UCE
  surface — the reconciliation shape is to expose the machine-callable half
  **server-side** (it ultimately dispatches the server's `Vulnerability:Scan`
  refresh anyway), or to re-present Decision 3 to governance. Not resolved here.

---

## 2. Definitions & actors

- **UCE host** — the shared runtime hosting one or more engine modules; owns the
  fleet-data access layer (§3.1) and the confinement enforcement path (§6).
- **Module** — a use-case engine (e.g. the vuln module) storing only its own
  derived domain state.
- **Operator** — a human using the module's UI. An operator viewing findings
  through a UCE **keeps their own Yuzu identity end-to-end** (2b §3.4); the UCE
  never substitutes its own principal for the operator's when confinement is at
  stake.
- **Engine principal** — the module's own least-privilege machine identity
  (ADR-1005 Decision 5), used for the module's autonomous fleet-wide reads. A
  distinct principal class — never impersonation.
- **The three seams**, each with distinct requirements: the **module sync-read
  seam** (fleet-wide, engine-principal-authenticated — §3.1), the
  **findings-view seam** (per-operator, confinement-critical — §3.2, §6), and
  the **hand-off seam** (operator's own browser session writes a server-side
  object — §3.3).

---

## 3. Functional requirements

### 3.1 Fleet-data access (plan Decisions 5, 6)

- **F-1 — Two-tier candidate read, not fleet sync. [first module]** The vuln
  module derives findings by a **two-tier** cycle: sync CVE feeds → **tier 1**:
  coarse candidate filter against the server's `software_catalog` rollup at its
  *actual* grain — distinct names + device/version **counts**; the catalogue
  carries **no version strings** (verified: `SoftwareCatalogRow`,
  `server/core/src/software_inventory_store.hpp:91` — plan Decision 5's "distinct
  name/version pairs" wording assumed a grain that does not exist in code, and
  per-installation facts like distro/provenance could never live at catalogue
  grain anyway) → **tier 2**: for names that clear tier 1, per-device
  `query_software(name)` reads carrying the full identity the match needs
  (`SoftwareEntry`: version/ecosystem/epoch/release/arch/distro — all serialized
  through the public API) → persist findings. A finding is keyed by
  `(agent_id, CVE, installation identity)`; its lifecycle transitions are F-13,
  and the detailed matching model is the module design's, not this doc's. This is
  the vuln module's *instance* of the host-universal discipline in F-2 (no fleet
  replica; query-on-match; persist-derived-only) — a different module honours F-2
  with a different read shape. *Source:* plan Decision 5 (grain corrected against
  code) + the vuln-module design doc. *Verify:* M2
  acceptance.
- **F-2 — No fleet-inventory replica (host-universal).** No module may sync or
  persist a copy of per-device fleet inventory; a module reads fleet data
  on-demand through the shared access layer (F-3) and persists **only its own
  derived state**. A module's derived output that happens to be O(fleet) for a
  ubiquitous match (e.g. the vuln module's per-device findings for a
  glibc/openssl CVE) is the domain's *irreducible* result, not a replica — the
  invariant is **no fleet-inventory replica**, not sub-fleet output. *Source:*
  plan Decision 5. *Verify:* M2 acceptance + NF-1.
- **F-3 — One shared, cached, budgeted access layer.** The UCE host MUST expose
  a single shared fleet-data access layer for all modules — API-backed reads,
  cached, request-paced against **one shared budget** toward the server — and
  its interface MUST be shaped so a synced replica could slot in behind it later
  without a module-facing change. Modules store only their own derived domain
  state. The layer's sufficiency for a *future* module MUST be re-examined
  per-module, not inherited — plan Decision 6 flags software asset management's
  likely day-one device-grain-residency need as the first such re-examination.
  *Source:* plan Decision 6. *Verify:* stack ADR (interface shape); M2
  (budget behaviour).
- **F-4 — Scale validation at M2 (two-tier egress, re-derived).** Plan
  Decision 5's 10–50k egress estimate was computed against a version-pair
  catalogue grain that does not exist (F-1), so it MUST be **re-derived for the
  two-tier model** before it is load-bearing. M2 validates via **synthetic-load
  testing** (maintainer direction 2026-07-12: the ≥500k property is a
  design/architecture commitment — NF-1 — validated by synthetic testing as 2d
  schedules it; the test mechanism/rig is 2d implementation detail, **not a
  prerequisite named here**): (i) measure the tier-1 name-level candidate
  fan-out and the tier-2 per-matched-name device-expansion cost and confirm the
  combined read stays within the shared budget, and (ii) measure the
  findings-materialization egress and confirm it scales **linearly, not
  super-linearly**, with fleet size (mirroring plan M2's acceptance clauses),
  at the largest synthetic scale 2d stands up, extrapolated to the NF-1 target.
  *Source:* plan Decision 5 caveat (estimate re-derivation) + plan M2. *Verify:*
  M2 acceptance (synthetic).

### 3.2 Findings viewing & confinement (plan Decision 14)

> **RELOCATED by ADR-0031 (accepted 2026-07-14) — F-5, F-6, F-7 and §6.** The engine no longer
> re-derives ADR-0017 confinement. **Core confines the inputs; the engine composes them** (ADR-0031
> INV-31-2), and core records every release at read time (ADR-0032 Decision 11). §6's view-time
> scoped read-through mechanism is therefore not built. **M3 remains the parity gate**; its
> confinement leg **retargets** to core's release gate — what core released to the engine for an
> operator must equal what that operator could have read directly (the ADR-0017 evaluate-as-operator
> seam, #1716; ADR-0032 interlock item (b)). The requirement survives; the mechanism moved.

- **F-5 — Outcome equivalence with `/devices`.** For a management-group-confined
  operator and a given CVE, the findings page MUST show the **same device set
  `/devices` would show that operator for the same scope — never more**. The
  module's own reads being fleet-wide (F-1) MUST NOT leak into what an individual
  operator sees — this covers the per-CVE device set, the *set of CVEs shown*,
  and every count/aggregate (INV-7). *Source:* plan Decision 14. *Verify:* M3(d)
  equivalence test; **hard interlock — gates M3 acceptance and Phase 6**.
- **F-6 — Enforced by §6's mechanism.** Confinement MUST be enforced by the
  §6 view-time scoped read-through mechanism; the module MUST NOT implement a
  parallel confinement path. *Source:* plan Decision 14 + 2b §10. *Verify:*
  §6 invariants; M3(d).
- **F-7 — Per-view operator identity in Yuzu's audit.** Each confinement-gated
  findings read MUST be attributable, in Yuzu's audit, to the viewing operator
  (not the engine principal). *Source:* plan Decision 14 + 2b §3.4. *Verify:*
  M3(d); audit-row inspection.

### 3.3 Hand-off seam (plan Decision 2)

- **F-8 — Operator-session hand-off.** When the findings page hands off a device
  cohort, the resulting object (e.g. a result set) MUST be created via the Yuzu
  server's **public API, from the operator's own browser, against the Yuzu
  origin, using the operator's existing Yuzu session** — not a UCE-backend call.
  *Source:* plan Decision 2. *Verify:* stack ADR (flow); M3.
- **F-9 — No write-capable credential in the backend.** The UCE backend MUST NOT
  hold, proxy, or forward any write-capable credential or token on the
  operator's behalf. This is what keeps the module's v1 read-only property
  (plan Decision 1) real. *Source:* plan Decision 2. *Verify:* code review;
  security-guardian.

### 3.4 Consumer model (plan Decision 3)

> **VOIDED by ADR-0031 (accepted 2026-07-14).** The engine has no UI, so the "private UI seam" has
> no premise. Engine capabilities are reachable by humans **and** agentic workers through core's one
> public surface, under the same RBAC and audit chain. The `confirm-now` reconciliation item logged
> against this requirement resolves itself. F-11 (confinement) is untouched — it was never a
> carve-out.

- **F-10 — No machine consumer; private UI seam.** The UCE's only external
  interface is its human UI; **no machine consumer of the UCE exists** in v1.
  Agentic workers consume the Yuzu server directly over REST/MCP. The UCE-host
  UI ↔ backend seam is private (one product), and ADR-1005 parity/discoverability
  obligations discharge at the *server* surface, not inside the UCE. *Source:*
  plan Decision 3. *Verify:* architecture review; consistency-auditor.
- **F-11 — The parity carve-out does NOT cover confinement.** The Decision-3
  exemption is scoped to parity/discoverability only. ADR-0017 management-group
  confinement (F-5) is a **separate requirement the carve-out does not waive**.
  *Source:* plan Decision 3 (explicit) + Decision 14. *Verify:* M3(d).

### 3.5 Findings-store lifecycle — [first module]

> **[first module]** — F-12…F-14 and §7 are the **vulnerability module's** concrete
> findings-store requirements: the instance that satisfies the exec-plan-mandated
> data-inventory entry (§7) and its lifecycle. They are kept in 2c because item 2c
> mandates the data-inventory entry as host-doc content — but they are **not
> host-universal**. The host does not dictate a module's storage model, retention
> mechanics, or fidelity/roll-up choice; a second module registers its own
> derived-store requirements. What *is* host-universal for any module's store is
> the audit-perimeter posture (NF-6) and that confinement (F-5/§6) governs its
> read path.

- **F-12 — Findings store ships with its purge path wired at the store-ship
  milestone.** Timing is tied to the **event, not a milestone number**: the
  **store-ship milestone** is whichever module-ladder milestone first ships the
  findings store holding real (non-fixture) findings — the module's revised
  ladder places the store at its M3, with its M1 a source-ingestion skeleton, so
  "M1" is deliberately not hard-coded here. At store-ship the vuln module MUST
  wire: a resolved/superseded-finding reaper on a retention default (§7), and a
  **device-decommission purge path**. A new store MUST NOT be born inheriting the
  unwired-decommission gap (#1666) that the existing server inventory stores
  carry. *Source:* §7 + plan Decision 13's Phase-8 carve-out (which defers only
  the *broader* host retention posture, not the v1 findings-store commitment).
  *Verify:* store-ship acceptance; compliance-officer.
- **F-13 — Finding lifecycle transitions are specified, not implicit.** The
  store-ship reaper (F-12) depends on a defined open→resolved transition, so the module MUST
  specify: (i) **sync-supersede** — a finding whose `(device, CVE, product)` no
  longer matches in a later cycle transitions open→superseded, starting the §7
  retention clock; (ii) **departed-device aging** — open findings for a device
  gone silent (heartbeat/`last_seen` aged past a stated bound) MUST age via a
  liveness path, never persist forever inflating INV-7 counts; (iii)
  **re-enrollment reconciliation** — a device re-enrolling under a new `agent_id`
  MUST reconcile (supersede/merge) its old-`agent_id` findings, never leave
  phantom duplicates that double-count a confined view. The exec-plan M3 operator
  triage lifecycle (`new`/`triaged`/`accepted-risk`/`remediated`/`reopened`)
  layers on top: which triage states are "current" vs start the retention clock
  (e.g. does `accepted-risk` purge at 90 days or stay open as acknowledged
  residual risk?) is **reconciled at the module's triage milestone, named here not decided** — the store-ship reaper
  covers only (i)–(iii). *Source:* plan Decision 5 + plan M3. *Verify:*
  store-ship (i–iii); the module's triage milestone (reconciliation).
- **F-14 — Subject-erasure and legal-hold paths.** "Not inheriting #1666"
  (F-12) covers the **decommission** half only; a device-decommission purge is
  device-lifecycle, not subject-lifecycle. On person-assigned devices the store
  is GDPR-personal (§7), so the module MUST additionally wire a **subject-erasure
  (Art. 17 / DSAR) path**, distinct from decommission. And the reaper MUST be
  **legal-hold-aware**: a configured hold — or `vuln_findings_resolved_retention_days=0`
  as a forensic freeze (a proposed retention-disable convention) — suspends the
  reaper for the held scope, so a routine 90-day purge cannot destroy evidence
  under litigation/incident hold. *Source:* §7 + #1666. *Verify:* store-ship;
  compliance-officer.
- **F-15 — No unconfined findings view, ever; permitted interim mode until
  confinement lands.** The findings view MUST NOT show any operator a
  device/CVE/aggregate its §6 confinement would exclude. The **trigger** for
  confinement being load-bearing is the existence of a **management-group-confined
  operator** — an admin has assigned a group-scoped role, confining that operator
  to a subset of the *same customer's* fleet (ADR-0017). A single enterprise with
  regionally-scoped teams trips this exactly as an MSP does; **MSP multi-tenancy
  (many customers, one deployment) is the most extreme instance of the same
  intra-tenant mechanism, not a separate one** — so the requirement is keyed to a
  group-confined operator, never to "MSP" specifically. Because §6's mechanism
  cannot be built or M3(d)-verified before ADR-0017 PR-A lands (§6 dependency
  edge), the **permitted interim operating mode** until then is: the findings view
  MAY serve any tenancy in which **no operator is group-confined** (every operator
  holds fleet-wide read — today's common case; ADR-0017 records that
  group-confined operators barely exist in practice yet); the moment a
  group-confined operator would view findings, they MUST receive an honest
  **"findings confinement not yet available"** state — never an unconfined view.
  This makes F-15 enforceable **without** PR-A: the end-state (verified per-operator
  confinement) waits on PR-A + M3(d); the interim (no group-confined viewer is ever
  shown findings) is a plain gate that ships with the findings view. *Source:* plan Decisions 13, 14
  + ADR-0017. **Interim-gate mechanism (named, so "enforceable without PR-A" is
  not hand-waved):** "is the viewing operator group-confined?" is answerable from
  the operator's existing RBAC role assignments (the RBAC model already represents
  group-scoped roles) — it needs no per-device `authorize_list_read` (that is only
  the *confined-set* computation PR-A supplies). So the interim gate reads role
  data the platform already exposes; the end-state confined view is what waits on
  PR-A + M3(d). *Verify:* view-ship (interim gate — a group-confined operator is
  refused, not shown an unconfined view); M3(d) (end-state confinement);
  Workstream-G pilot-readiness gate.

---

## 4. Non-functional requirements

### 4.1 Scale (plan Decision 4, extended)

- **NF-1 — Design for ≥500,000 endpoints with no architectural ceiling.** Build
  for the near-term 2,000-device target, and **design for ≥500,000 endpoints
  with no architectural device-count ceiling** — meaning no seam may contain a
  **super-linear-in-fleet** term or a redundant **fleet-inventory replica**.
  Linear-in-fleet output is acceptable and sometimes irreducible: the findings
  materialization is O(hits) — linear in affected devices, and for a ubiquitous
  vulnerable package that is O(fleet) — which is the domain's irreducible output,
  not a replica (F-2). The two quantities that MUST be validated as *not*
  super-linear are (i) the two-tier read's combined egress — tier-1 candidate
  fan-out × tier-2 device expansion (F-4) — and
  (ii) the per-view confinement read shape (§6 — the device-list read is
  O(page); INV-7 aggregates are O(confined-set), bounded by operator scope).
  *Source:*
  plan Decision 4, **extended by maintainer direction 2026-07-11** (the plan's
  "up to 500,000" ceiling is superseded; a small plan-amendment PR records this
  separately — see §11 Decision-log entry 2 for the tracking follow-up).
  Until F-4's M2 measurement lands, ≥500k is a **design target, not a validated
  capacity claim** — it MUST NOT be cited as an affirmative capacity answer in
  customer/CAIQ material. *Verify:* the two named quantities via F-4's M2
  measurement, which retains 500,000 as its concrete test scale, and §6's
  page-bounded read.

### 4.2 Capacity & isolation (ADR-1005)

- **NF-2 — Engine load must not starve the server's real-time path.** The
  module's fleet-wide polling MUST be request-paced against the single shared
  budget (F-3) and MUST NOT starve the server's heartbeat ingest or command
  dispatch. The non-starvation guarantee MUST be backed by a **mechanism, not
  just stated as an outcome**: budget exhaustion MUST be handled by **bounded**
  backpressure — a bounded queue or shed, never an unbounded queue — and the
  budget MUST prioritize the server's real-time path so engine reads are
  throttled/shed **before** heartbeat ingest or command dispatch degrade (a
  reservation or engine-first-shed order). When production catalogue cardinality
  or expansion egress exceeds F-4's validated envelope, the module MUST degrade
  (throttle/defer sync) rather than consume the budget unbounded. **The shared
  PG instance (NF-3 topology) adds a second starvation seam the API budget cannot
  see:** findings-store write bursts share WAL/checkpoint/autovacuum/buffer
  resources with the server's own stores, so UCE database writes MUST be paced
  (bounded batch sizes, off-peak-biased sync scheduling) such that they cannot
  degrade the server's heartbeat-ingest or command-dispatch write path — same
  guarantee, DB tier. API-serving capacity is a first-class SLO input that MUST
  be assessed before engine GA.
  *Source:* ADR-1005 ("Capacity and isolation become first-class"). *Verify:* sre
  review; pre-GA capacity gate (Phase 8).

### 4.3 Deployment & repository shape (plan Decisions 11, 12)

- **NF-3 — Separate deployable, own database, no server coupling.** The UCE host
  MUST use **its own PostgreSQL database — never the server's connection pool**;
  MUST live in-repo under `engines/` (`engines/host`, `engines/modules/vuln`);
  MUST ship as a **separate deployable artifact** from `yuzu-server`; and CI MUST
  enforce that nothing under `engines/` includes or links against `server/`
  code. **Topology (maintainer decision 2026-07-12, accepted trade-off):** the UCE
  database is a **separate database on the same PostgreSQL instance** as the
  server's; the UCE deployable (backend + GUI, one artifact) runs on **its own VM
  in the same data centre**. Isolation mechanics are therefore load-bearing, not
  implicit: a dedicated PG role with its own pool; **cross-database access inside
  the shared instance is FORBIDDEN** (`postgres_fdw`, `dblink`, cross-DB grants —
  any of these is a private seam violating ADR-1005 Decision 3), enforced
  mechanically (`REVOKE CONNECT` each direction); remote PG access from the UCE VM
  is **TLS-only** with `pg_hba` scoped to that host. Full design:
  `docs/uce-deployment-topology-design.md`. *Source:* plan Decision 11 (as refined
  2026-07-12). *Verify:* CI include/link guard; a cross-DB-access-denied test;
  build review.
- **NF-4 — Declares and enforces a supported server API-version range.** The
  first-party engine MUST declare a min/max supported server API version and
  **refuse to start outside it**, and the refusal MUST emit an operator-actionable
  diagnostic (required range vs. actual server version), never a bare exit. The
  check is startup-only; a coordinated PG/server upgrade (topology §2.6) that moves
  the server's API version out of range mid-run is handled by the upgrade-
  coordination runbook, not by NF-4 — named so the gap is owned, not silent.
  *Source:* ADR-1005 ("first-party engine is a separate artifact declaring a
  min/max supported server API version"). *Verify:* startup check; integration
  test.

### 4.4 Security & audit posture (ADR-1005, 2b)

- **NF-5 — Server-issued delegation only; engine-asserted identity rejected.**
  Any UCE action serving a specific operator MUST rest on a **server-issued**
  delegation artifact (2b §5); an engine-asserted delegation (a header/field the
  UCE sets) MUST be rejected at the server, not merely ignored — the sole
  standing ledger exception is the four health-probe paths (ADR-1005 exception
  ledger). *Source:* ADR-1005 Decision 5 + Interim rules. *Verify:* the
  pre-routing chokepoint (exec-plan PR 1.1, already enforced across REST/MCP/gRPC);
  security-guardian.
- **NF-6 — UCE-resident derived data sits outside the server's audit perimeter
  and carries the host's own controls.** Findings and any other data the UCE
  re-serves leave the server's audit perimeter (ADR-1005 Decision 5), so the UCE
  host MUST provide its own audit/compliance controls for that data. Short-lived
  operator-bound artifacts (§6) are held **in memory for a view request only and
  never persisted**. The concrete UCE-side audit/compliance control set (owner,
  SOC 2 workstream, milestone) is a named stack-ADR/2d deliverable, tracked as an
  open question (§10), not resolved here. *Source:* ADR-1005 Decision 5 + §6.
  *Verify:* compliance-officer; §6 invariants; §7 inventory entry; §10 open
  question (control-set owner).

### 4.5 Operability

- **NF-7 — Operable as a first-class separate deployable.** The UCE host MUST
  expose health/readiness signals, logs, and metrics; their concrete shape is
  stack-ADR territory (existence committed here, form deferred). Note a stated
  availability coupling: because every confined render hard-depends on an
  affirmative server confinement response (INV-5), **UCE findings-view
  availability is bounded by the server's list-read availability** — an intended
  consequence of server-authoritative confinement, called out so it is an
  explicit SLO input, not a surprise. NF-9 adds **two further Yuzu-availability
  couplings** that belong in the same SLO input: **login** (Yuzu-as-IdP — Yuzu
  down ⇒ no new UCE session can be established at all) and the NF-9(d) **liveness
  ping** (Yuzu unreachable past the grace bound ⇒ even idle sessions terminate). The NF-3 topology adds a second, stronger
  coupling stated honestly: **the shared PG instance is one failure domain for
  both sides** — instance down ⇒ the server fails closed at boot (ADR-0007) AND
  the UCE store is dark; PG maintenance/major upgrades coordinate both. The
  "separate deployable" property isolates compute and release cadence, not the
  database failure domain. **v1 availability posture (maintainer decision
  2026-07-12): the UCE deployable is a single VM — accepted for v1** (VM loss
  darkens the findings UI only; no data on the VM; redeploy restores), and **an
  HA posture is a committed pre-GA requirement** (Phase-8 gate), not optional.
  *Source:* ADR-1005 ("Capacity and isolation become
  first-class") + NF-3. *Verify:* stack ADR; sre review; Phase-8 HA gate.
- **NF-8 — Observability floor (existence now, shape at stack ADR).** These
  signals MUST exist — each backs a v1 guarantee that is otherwise unenforceable;
  their metric names/labels are stack-ADR detail: (i) a **confinement-read
  latency** histogram and (ii) a **shared-budget-utilization / view-read-load**
  gauge — the §6 fallback trigger is unmeasurable without them; (iii) a
  **reaper-liveness** (last-successful-reap) + **findings-store row-count** signal
  — else the most-sensitive store grows unbounded on a stalled reaper with no
  alarm; (iv) an **"engine throttled / budget-exhausted"** signal (NF-2); (v) a
  **findings-store readiness** signal gated into the host readiness probe (the
  server "new load-bearing store in `/readyz`" precedent) plus a **sync-seam
  findings-freshness/staleness** indicator with a stated bound — else a
  stale-but-serving view silently under-reports a newly-vulnerable device; (vi)
  **per-database write-rate/connection visibility on the shared PG instance**
  (NF-3 topology), so the NF-2 DB-tier pacing guarantee is observable. Scope
  stated honestly: tuple-write-rate, connections, temp-file usage, and
  idle-in-transaction time ARE per-database attributable from stock PG telemetry
  (`pg_stat_database`); WAL generation and checkpoint pressure are
  instance-global in stock PostgreSQL — that half is **inferred by correlation**
  against the per-DB write signals, not attributed, and the residual gap is
  accepted rather than promised away; (vii) **login/session telemetry** (NF-9):
  login success/failure rate, an active-UCE-session gauge, and the NF-9(d)
  **liveness-ping failure rate** — alertable signals distinct from §10's
  login/session *audit* events, so an IdP misconfiguration or a mass-logout
  event (NF-9(d) transient-failure fork) is detectable without hand-diffing an
  audit log.
  *Source:* NF-2 + §6 fallback + F-13/F-14 + sre review. *Verify:* stack ADR
  (shape); sre.

### 4.6 Operator login & session (host-universal)

> **VOIDED IN ITS ENTIRETY by ADR-0031 (accepted 2026-07-14).** A headless engine has no browser
> origin, no login and no session, so every pin below (Yuzu-as-IdP, the cross-origin redeem flow,
> `state`/nonce binding, the liveness ping) secures a thing that no longer exists. Operators
> authenticate **once, to presentation**; the engine sees only a core-minted, audience-bound grant
> (ADR-0032). NF-3, NF-7 and NF-8(vii) are RE-SCOPED for the same reason; **NF-2, NF-5 and NF-6
> stand unchanged.**

- **NF-9 — Operator login & session security.** The UCE has **no user store**;
  operator login is **Yuzu-as-identity-provider** (the concrete cross-origin
  redirect flow is `docs/uce-deployment-topology-design.md` §3). These pins are
  **binding** on 2d and the stack ADR, not deployment detail:
  - **(a) No foreign token.** The UCE MUST NOT accept or validate a corporate-IdP
    token directly — only Yuzu's server-issued artifact redemption. **SSO is
    inherited transitively** (corporate IdP → Yuzu's shipped OIDC → UCE); the UCE
    never registers with the corporate IdP.
  - **(b) Login-callback integrity.** The login redirect MUST carry a
    `state`/nonce bound **per login attempt** (not a per-session shared value — two
    concurrent tabs must not overwrite each other's state) to a first-party
    pre-redirect UCE context, validated at redeem (anti-CSRF / anti-session-
    fixation); the redirect-back target MUST be a **server-side configured
    exact-match GUI origin** (the same origin allowlist), never a request-supplied
    `return_to` (anti-open-redirect / artifact exfiltration). The pre-redirect
    context storage (a first-party temp cookie/store on the GUI origin) MUST
    survive third-party-cookie blocking / storage-partitioning — the top-level
    redirect flow is chosen partly because it does; a stack-ADR implementation MUST
    NOT reintroduce a third-party-cookie dependency for the state binding.
  - **(c) Login artifact is identity-only.** It carries **no authority broader
    than the read-purpose artifact** (identity-attesting, read-scoped) — F-9 holds
    by construction. The **login** artifact and the **confinement-read** artifact
    (§6, 2b §5 read-purpose variant) are distinct uses of one primitive and MUST
    NOT be conflated; artifact **re-mint is browser-redirect-driven**, never a
    UCE-backend-held durable refresh capability (preserves INV-1's memory-only
    posture).
  - **(d) Session = bounded cache of Yuzu authority.** UCE session max-age **≤
    Yuzu's session max-age** (8 h today) — but note this compares config *ceilings*;
    the actual per-session bound comes from the liveness floor below, since a
    session minted late in a Yuzu session's life would otherwise outlive it
    (config-ceiling ≠ per-session lifetime). A **definitively** failed re-mint
    (Yuzu affirmatively denies) or a definitively revoked/expired-operator result
    on any read is **immediately session-terminating**; a re-mint that fails
    because Yuzu is *unreachable* is itself indeterminate and inherits the same
    bounded-retry/grace as the liveness path below (not an immediate tear-down —
    else a blip would mass-logout the subset re-minting at that instant). Because revocation-via-reads only propagates while reads
    flow, the UCE MUST **revalidate operator liveness against Yuzu on a fixed
    ≤ artifact-TTL interval, unconditionally** (not gated on user-driven reads —
    which removes any fuzzy "actively reading" boundary), the interval **jittered**
    to avoid a synchronized fleet-wide re-check burst. **Transient-failure posture
    (load-bearing):** an *indeterminate* liveness result (Yuzu unreachable/timeout,
    not a definitive revoke) MUST NOT terminate per-blip — it uses bounded
    retry/backoff and fails closed only after **N consecutive failures or a bounded
    grace window** (mirroring 2b §5's bounded-grace-on-indeterminate-backend, vs
    INV-5's hard fail-closed for a *definitive* denial) — so a brief Yuzu wobble
    does not log the whole operator fleet out at once (a cascading-failure
    amplifier), while a real revocation still lands within the grace bound. The
    retry/grace parameters are stack-ADR, their *existence* binding here.
  - **(e) Cookie-surface CORS.** If the CORS-credentialed variant is chosen
    (topology §3), the PR-#2060 **absent-Origin-allowed** sub-rule MUST NOT be
    ported — it is safe there only because MCP is bearer-token/non-browser; on a
    `SameSite=None` cookie surface the cookie auto-attaches, so absent-Origin on a
    state-changing request re-opens CSRF. Reject absent-Origin / require a CSRF
    token on state-changing cookie requests. (A CORS allowlist gates response
    *readability*, not request *admission* — it is not itself a CSRF control.)
  - **(f) Login-flow robustness (fail-closed + atomic).** The redeem →
    session-establish path is **fail-closed**: a valid redeem whose session-create
    fails leaves **no half-open session** (the operator re-auths); the login/redeem
    surface inherits INV-5's fail-closed doctrine, which otherwise governs
    confinement *reads* only. Artifact redeem ↔ single-use consumption
    (INV-9) MUST be **atomic and idempotent** so a callback replay / browser-back
    re-fires a fresh redirect rather than dead-ending on "artifact already used."
    The **F-8 hand-off** performed after the operator's Yuzu session has lapsed or
    been revoked MUST re-auth (redirect to Yuzu) rather than dead-end on a 401 —
    the hand-off is a browser→Yuzu write, so unlike a UCE read it is not caught by
    (d)'s session-terminating rule and needs its own re-auth path.
  - **(g) Time integrity & session residency.** The ≤ artifact-TTL (≤5 min)
    revocation bound is a **cross-host** security property, so the UCE VM and Yuzu
    MUST be clock-synchronised (NTP) and the artifact validation MUST carry a
    stated skew tolerance, failing closed beyond it — skew-behind must not silently
    lengthen the revocation window past its bound. Session **residency** (in-memory
    on the VM vs. the `uce` database) is a stack-ADR choice, but each posture's
    NF-7 implication is named: in-memory ⇒ a single-VM restart re-logs-in every
    operator (acceptable — no data loss); in-`uce`-DB ⇒ every request couples to
    the shared PG instance (weighs against NF-7's failure domain), and a
    DB-resident session row MUST store **identity + expiry only** — never the
    artifact or a refresh credential (preserves INV-1 memory-only / F-9).
  *Source:* topology §3 + security-guardian + architect + Gate-4/6
  (2026-07-12). *Verify:* stack ADR (T2b) + security-guardian gate; T2b acceptance
  MUST include that the NF-9 login/session audit events (§10) actually emit.

---

## 5. Candidate evaluation — Decision-14 confinement mechanism

2b §10 hands 2c three candidates and the evaluation criteria; 2c owns the
choice. Criteria, in the order 2b sets:

1. **Server remains the confinement authority.**
2. **Staleness window ≈ 0** — a scope change takes effect at next view.
3. **Per-view operator identity preserved in Yuzu's audit.**
4. **Operational cost at fleet scale.**

| Candidate | Sketch | Against the criteria |
|---|---|---|
| **(a) View-time scoped read-through** | Each findings-page render triggers per-operator reads to the Yuzu server carrying a short-lived operator-bound artifact (2b §5 primitive, read-purpose variant); the server evaluates confinement via ADR-0017 | (1) satisfied **by construction** — the same server path as `/devices`; (2) zero confinement staleness; (3) every view is a server-audited read as the operator; (4) per-view latency + server load, but see below — the cost is O(page) and scales with operators, not devices |
| **(b) Identity assertion / session exchange** | Operator's browser obtains an operator-bound artifact from Yuzu; the UCE backend exchanges it for a scoped read context covering the view session | Same authority + freshness *at exchange time*; between exchanges the UCE enforces from a held context — evaluation has moved into the interpretation layer for the context's lifetime, and views served from it never reach Yuzu's audit (per-session, not per-view). Fewer round-trips; more moving parts (exchange endpoint, context lifetime, revocation) |
| **(c) Synced confinement predicate** | Per-operator scope predicate synced alongside findings, re-validated on a short TTL | Confinement evaluated *by the UCE* against a cached predicate — weakest fit for "server authoritative" and "never stale", and **fails ADR-1005's mechanism-vs-interpretation boundary test**: confinement is an authorization *mechanism*, and (c) relocates its evaluation into the UCE (an interpretation-layer component). 2b already flags this |

Two Yuzu realities inform the choice. First, the browser must obtain the
operator-bound artifact from the Yuzu origin under **both** (a) and (b) — (b)
saves no browser/CORS complexity, it only amortizes server round-trips into a
staleness-plus-audit gap. Second, plan Decision 11 leaves the UCE UI stack
unconstrained, so the requirements doc must not assume a browser that can hold
session state cleverly; (a)'s stateless per-view shape is stack-agnostic.

2b's recommendation is the (a)/(b) family, with (c) surviving only if a concrete
latency/scale constraint defeats both, and then only with a stated TTL bound.

Cross-doc note: the vuln-module design doc (§4.4 there) independently proposes a
synced-confinement-predicate mechanism — that proposal **is candidate (c)** as
evaluated above, offered before this doc's commitment existed. 2c's answer is
the evaluation and commitment here: (c) relocates the authorization *mechanism*
into the interpretation layer and stays excluded per the ADR-1005 boundary test;
the (a)→(b) fallback ladder in §6 stands. Recorded so the module doc's proposal
is answered, not silently overridden.

---

## 6. Commitment 1 — confinement enforcement mechanism (normative) — [RELOCATED by ADR-0031]

> **RELOCATED by ADR-0031 (accepted 2026-07-14).** This section commits the *engine* to enforcing
> confinement by view-time scoped read-through. That mechanism is not built: confinement moves into
> **core**, which confines the inputs it releases (INV-31-2) and logs each release (ADR-0032
> Decision 11). Read this section as the historical record of the requirement, not as the design.


**2c commits to candidate (a): view-time scoped read-through.** The findings
page enforces confinement by asking the Yuzu server, per view, "which of these
candidate devices may this operator see for this CVE?" and rendering only the
returned subset. Rationale against the four criteria:

1. **Server authority — by construction.** Every view is a server-evaluated read
   through the same ADR-0017 admit-then-filter chokepoint that will back
   `/devices` list confinement (see the dependency edge below); F-5's
   outcome-equivalence is *literal*, not simulated. (b) satisfies authority only
   at exchange time; shrinking its context lifetime toward zero to close the gap
   converges to (a) while keeping (b)'s extra machinery.
2. **Staleness ≈ 0.** A scope change takes effect at the next view,
   unconditionally.
3. **Per-view identity.** Every view is a server-audited read *as the operator*
   (F-7), for free.
4. **Cost is bounded and sub-fleet.** Findings-view traffic is human-paced
   operator-UI traffic — it scales with operator count, not the NF-1 device
   ceiling — and the device-list read is **page-bounded**: the UCE sends the
   current findings page's candidate device ids (order tens to low hundreds) and
   receives the visible subset — O(page) per render. (INV-7's per-CVE aggregates
   are O(confined-set), bounded by the operator's *own* scope — irreducible for a
   global-scope operator, the same carve-out as F-2/NF-1's O(hits) output — never
   a function of total fleet size for a confined operator.) This is the criterion
   (a) is nominally weakest on, and it is exactly the one the ≥500k scale
   direction (NF-1) most requires (a) to satisfy — which it does.

**Normative invariants (binding on 2d):**

- **INV-1 — Read-purpose artifact, memory-only.** The UCE backend MAY hold the
  short-lived read-purpose operator-bound artifact (2b §5, read-purpose variant)
  in memory for the duration of a view request; it MUST NOT persist it. This
  does not conflict with F-9 (plan Decision 2): F-9 bans *write-capable*
  credentials, and the artifact is read-scoped and operator-bound.
- **INV-2 — Artifact TTL ≠ scope staleness.** The artifact attests *identity*;
  *scope* is evaluated server-side on every read. Reusing an unexpired artifact
  across reads introduces only operator-revocation staleness bounded by the
  artifact's TTL (the same class as the server's own session lifetime) — and
  **zero confinement staleness**. This distinction is what makes (a)'s per-view
  cost acceptable and MUST be preserved. Because that operator-revocation window
  *is* the artifact TTL, the TTL MUST be short and bounded (**≤ 5 minutes**,
  matching candidate (b)'s context bound); 2d MUST NOT choose a long-lived
  artifact (a revoked/disabled operator must not keep rendering the fleet's
  attack surface for hours).
- **INV-3 — Shared chokepoint.** The confinement read MUST resolve through the
  server-side ADR-0017 admit-then-filter list gate (charter name
  `authorize_list_read`) — the same single chokepoint `/devices` list reads are
  to resolve through — not a bespoke server-side filter that re-implements
  confinement. Which endpoint the UCE calls is 2d / stack-ADR detail;
  **chokepoint-sharing is the requirement.** (Status: that chokepoint is
  ADR-0017-chartered but **unbuilt today** — its PR-A..E ladder has zero code in
  the tree — so INV-3 carries the dependency edge below.)
- **INV-4 — No client-asserted confinement.** The visible subset MUST be
  computed server-side. The UCE MUST NOT accept a browser-supplied device set as
  the confinement result (a client cannot be the filter).
- **INV-5 — Fail closed on any non-affirmative confinement result.** If the Yuzu
  server is unreachable, **or returns a non-affirmative confinement response**
  (error, timeout, or a partial/incomplete result), the findings view MUST be
  unavailable/errored — it MUST NOT render from a last-known scope or a partial
  result (mirrors the sibling `software_inventory_store` "never a successful
  empty result" posture).
- **INV-6 — M3(d) verification is a direct equivalence test.** For a confined
  operator and a given CVE, the findings-page device set MUST equal the
  `/devices` device set for the same scope. This is F-5's verification and the
  Phase-6 interlock.
- **INV-7 — Confinement covers CVE membership and aggregates, not only per-CVE
  device sets.** The set of CVEs shown, and every per-CVE affected-device count,
  severity rollup, and other aggregate on a confined operator's view, MUST be
  computed over that operator's confined device set only — never over the
  fleet-wide findings store. A confined view MUST NOT disclose the existence of,
  or a nonzero count for, a CVE that affects only out-of-scope devices. INV-6's
  M3(d) equivalence test therefore extends to a **membership/count sub-check**:
  the CVE list and every per-CVE count a confined operator sees equal what their
  confined device set yields, not a fleet-wide value. Aggregates MUST be
  recomputed **per page render** over the operator's then-current confined set —
  never a view-open total held across pagination — so a mid-view scope *shrink*
  cannot leave a stale count disclosing now-out-of-scope devices.
- **INV-8 — Confined views are not cached across renders.** The rendered confined
  findings view MUST be served no-store and MUST NOT be replayed across renders —
  a view rendered before a scope *shrink* must never be re-served from a proxy,
  browser, or UCE render cache.
- **INV-9 — Read-purpose artifact is sender-constrained or single-use.** The
  artifact MUST be **sender-constrained** (channel/key-bound — e.g. mTLS- or
  DPoP-style; mechanism is stack-ADR detail) **or single-use**, so a leaked bearer
  artifact cannot be replayed as the operator within its (INV-2-bounded) TTL. The
  property is pinned here; the binding mechanism is 2d / stack-ADR.
- **INV-10 — Confinement-read response carries a completeness signal.** The
  server's confinement-read response MUST let the UCE distinguish **admitted /
  denied / not-evaluated** for every page candidate (not just return an admitted
  subset) — so a partial or incomplete evaluation is *detectable* and fails closed
  per INV-5. A bare admitted-subset, in which absence conflates "denied" with
  "not evaluated", is non-conforming (it makes INV-5's fail-closed-on-partial
  unenforceable). Note this makes INV-10 a **response-contract input into**
  ADR-0017 PR-A (the chokepoint must surface completeness), not merely a consumer
  of its outcome — the one place 2c names a shape requirement on the chokepoint
  rather than only consuming it (cf. §1).

**Dependency edge — ADR-0017 PR-A is a prerequisite.** The admit-then-filter
list chokepoint this mechanism resolves through (INV-3) is ADR-0017-chartered but
**not yet in code** (its PR-A..E ladder has zero call sites in the tree today;
2b records the same dependency edge for its delegated reads). Both sides of F-5's
equivalence — the findings-view read *and* `/devices` list confinement itself —
therefore land only once ADR-0017 PR-A ships. Consequence for scheduling: **the
§6 mechanism cannot be built or M3(d)-verified before ADR-0017 PR-A lands**, and
Phase 6's confinement interlock inherits that prerequisite. This does **not** dead-end
the feature pre-PR-A: F-15's interim operating mode ships a findings view to any
tenancy with no group-confined operators (today's common case) and refuses a
group-confined viewer with an honest "confinement pending" state — so what waits on
PR-A is *per-operator group confinement*, not the whole findings view. This doc does
not sequence the ADR-0017 ladder (a maintainer decision, §1) — it records the edge so
2d does not discover it mid-build.

**Fallback conditions (stated, not hedged).** If, at the design-target scale
(NF-1), measured p95 added view latency exceeds **250 ms**, or view-read load
becomes a named fraction of the NF-2 capacity SLO, fall back to (b) with a
**hard-bounded, revocation-checked context lifetime (≤ 5 minutes)** — preserving
INV-5 (fail-closed) and server authority *at exchange time*, but **relaxing
INV-3/INV-4 to per-context evaluation** (the UCE serves views from a held scoped
context between exchanges), at a bounded, disclosed staleness and per-context
(not per-view) audit-grain cost.
Candidate (c) stays excluded by the ADR-1005 boundary test unless *both* (a) and
(b) prove infeasible, and then only with an explicit TTL bound recorded by
amendment here (2b §10's condition, restated as binding). The 250 ms / 5-minute
figures are proposed thresholds; governance may set the final values.

---

## 7. Commitment 2 — findings-store data-inventory entry (normative) — [first module]

The module's findings store is registered in the SOC 2 data inventory
(`docs/enterprise-readiness-soc2-first-customer.md` §3.5) as a new UCE-host
subsection — a **separately-deployed store on its own PostgreSQL** (plan
Decision 11), not a server store, so it is a distinct subsection rather than a
row in the server tables. The registered entry (see that doc for the table row)
commits:

- **Classification — derived vulnerability findings; sensitive security data,
  device-attributable.** Per-device CVE exposure (`agent_id` × CVE × matched
  product/version, with severity/exploitability). It enumerates the fleet's
  exploitable attack surface, so it is treated as **more sensitive than the
  installed-software inventory it derives from** — a breach discloses what is
  attackable, not merely what is installed. No direct username/SID
  (machine-scope source, ADR-0016 §8), but device-attributable and therefore
  **personal data under GDPR when the device is person-assigned** — hence the
  subject-erasure (DSAR/Art. 17) path below; device-attributability keeps the
  works-council capability-to-monitor posture of its source data. It sits
  **outside the server's audit perimeter** (NF-6), so the UCE host's own
  audit/compliance controls govern it.
- **Retention default — open findings retained while current** (refreshed each
  sync cycle); **resolved/superseded findings 90 days** by default (mirrors the
  `recommendations.db` derived-store precedent in §3.5).
- **Deletion path — module-owned resolved-finding reaper and device-decommission
  purge, both wired at the store-ship milestone (F-12)**, plus a **subject-erasure (DSAR/Art. 17) path**
  distinct from decommission and a **legal-hold-aware reaper** (F-14) — explicitly
  not inheriting the #1666 unwired-decommission gap.
- **Config knob — `vuln_findings_resolved_retention_days`** (name provisional;
  final at store-ship).

The entry is **forward-declared** (the store ships at the module's store-ship
milestone, F-12), following the
`recommendations.db` *(proposed)* precedent; it is the single registered
inventory entry, and this §7 states the same commitments normatively.

---

## 8. Non-goals (v1)

Out of scope for this requirements doc and for the module's v1, named so they
are not re-litigated:

- Everything delegation-dependent: engine-initiated write-back, remediation
  dispatch, engine-side result-set materialization (plan Decisions 1, 13; gated
  on ADR-1005 Decision 5).
- Machine consumers of the UCE (F-10).
- A fleet-inventory replica / bulk changed-since delta sync (F-2; plan
  Decisions 5, 13).
- The vulnerability graph differentiator and attack-path scoring (plan
  Decision 13; ADR-4001/4002 own their scoping).
- SBOM ingest and compliance-framework report bundles (plan Decision 13).
- The host runtime/language and UI stack (plan Decision 11 → stack ADR).
- The host's broader data-processor/retention posture for Postgres-resident
  derived state *beyond* the v1 findings-store commitment (plan Decision 13 →
  Phase 8).
- The do-not-re-decide hand-offs in §1 (classification mechanics, quotas,
  ADR-0017 sequencing).

---

## 9. Requirement ownership & verification map

| ID | Requirement | Owner | Verified at |
|---|---|---|---|
| F-1 | Catalogue-grain join | module | M2 |
| F-2 | No fleet replica; findings only | module | M2 / NF-1 |
| F-3 | Shared cached budgeted access layer | host | stack ADR / M2 |
| F-4 | Catalogue-cardinality validation | module | M2 |
| F-5 | Findings-view outcome equivalence | host + server | **M3(d) — gates Phase 6** |
| F-6 | Enforced by §6 mechanism | host | §6 / M3(d) |
| F-7 | Per-view operator identity in audit | host + server | M3(d) |
| F-8 | Operator-session hand-off | host + server | stack ADR / M3 |
| F-9 | No write-capable credential in backend | host | code review |
| F-10 | No machine consumer; private UI seam | host | architecture review |
| F-11 | Carve-out excludes confinement | host | M3(d) |
| F-12 | Findings-store purge wired at store-ship | module | store-ship |
| F-13 | Finding lifecycle transitions specified | module | store-ship / triage milestone |
| F-14 | Subject-erasure + legal-hold paths | module | store-ship / compliance |
| F-15 | No unconfined view; interim mode until PR-A | host | view-ship interim / M3(d) end-state |
| NF-1 | ≥500k, no architectural ceiling | host + module | NF-1 traces / M2 |
| NF-2 | No starvation; bounded shed-order backpressure | host | sre / Phase 8 |
| NF-3 | Separate deployable, own DB, CI guard | host | CI guard |
| NF-4 | Server API-version range enforced + diagnostic | host | startup test |
| NF-5 | Server-issued delegation only | server + host | PR 1.1 chokepoint |
| NF-6 | Own audit controls for re-served data | host | compliance / §10 owner |
| NF-7 | Operable separate deployable | host | stack ADR |
| NF-8 | Observability floor (existence now) | host | stack ADR / sre |
| NF-9 | Operator login & session security | host | stack ADR (T2b) / security-guardian |

> **RETARGETED by ADR-0031/0032 (accepted 2026-07-14).** The summary rows and the restated interlock
> below still route confinement through the **§6 mechanism**, which is RELOCATED (see §6 and F-5/F-6):
> the engine does not confine — **core confines the inputs it releases** (INV-31-2) and logs each
> release (ADR-0032 Decision 11). M3(d) survives and now tests **core's release gate**, not a
> module-side re-derivation. Read F-5/F-6/F-15 and the interlock below with that substitution; F-10
> and NF-9 rows are VOID.

**Hard interlock (restated):** F-5/F-6/F-11 (confinement) and their §6 mechanism
gate M3's condition (d) and Phase 6 **unconditionally** — Phase 6 cuts the
module to fleet-wide-reading engine-principal credentials regardless of which
customer is live, so the gate fires on the mechanism's own built-and-verified
state, never on customer topology (plan Decision 14). **Prerequisite:** that
mechanism resolves through the ADR-0017 admit-then-filter chokepoint (§6 INV-3),
which is chartered-but-unbuilt today — so M3(d) is itself gated on ADR-0017 PR-A
landing (§6 dependency edge).

---

## 10. Open questions deferred to the stack ADR

- Host runtime/language and web/UI stack for the private UI↔backend seam.
- The concrete browser artifact-acquisition flow (redirect vs CORS-credentialed
  fetch) — §6's invariants (INV-1…INV-10) are pinned; the implementation shape is
  free within them. The NF-3 topology makes this flow **cross-origin by
  construction** (GUI origin = the UCE VM; Yuzu origin = the server), so a
  **Yuzu-server-side deliverable exists either way**: a CORS allowlist for the
  configured UCE origin and a session-cookie `SameSite` posture (or a
  redirect-based flow avoiding both) — scoped in
  `docs/uce-deployment-topology-design.md`, decided at the stack ADR, built on
  the server before the findings view ships.
- Findings-store schema detail, migration tooling, packaging, and the concrete
  metric/health-signal shapes (NF-7/NF-8).
- The final p95 latency / SLO-fraction thresholds in §6's fallback clause.
- The **owner, SOC 2 workstream, and milestone** for the UCE host's own
  audit/compliance control set (NF-6) — the boundary is stated; the control
  commitment is owed. This set MUST cover the new NF-9 login/session events:
  login success/failure, session-established, and **session-terminated-on-revocation**.
- The interaction between candidate (a)'s per-view artifact issuance and the
  deferred minimum-issuance/quota interlock (#1973) — per-render issuance must not
  rate-limit an operator's own paging (UP-15, backlog).

---

## 11. Decision log

1. **Confinement mechanism = candidate (a), view-time scoped read-through**
   (§6). Chosen over (b) because (a) keeps server authority, zero confinement
   staleness, and per-view audit by construction, at a cost that is O(page) and
   scales with operators not devices — the property the ≥500k direction most
   needs. (b) is the stated fallback under a named latency/SLO trigger; (c) stays
   excluded by the ADR-1005 boundary test.
2. **Scale target extended to ≥500,000 with no architectural ceiling** (NF-1),
   per maintainer direction 2026-07-11 — supersedes plan Decision 4's "up to
   500,000" ceiling. Recorded here now; a small plan-amendment PR carries it into
   the execution plan's Decision 4 once the ADR/exec-plan rename (PR #2035)
   settles, to avoid touching the mid-rename file from this PR. **Update
   2026-07-12: the amendment is drafted** — branch
   `docs/adr1005-exec-plan-d4-d11-amend` amends Decision 4 (this scale direction)
   and refines Decision 11 (deployment topology) in one small PR, discharging the
   tracking obligation this entry previously imposed (no separate issue needed;
   the drafted PR is the artifact).
3. **Findings-store retention default = 90 days for resolved/superseded**,
   mirroring the `recommendations.db` derived-store precedent; open findings
   retained while current. The device-decommission purge path is wired **at store-ship**
   (F-12) so the store never inherits the #1666 gap.
4. **Inventory placement = a new `####` UCE-host subsection in §3.5**, not a row
   in the server tables — the store is a separately-deployed own-Postgres store
   (plan Decision 11), matching the agent-side-edge-warehouse subsection
   precedent.
5. **This doc consumes, does not re-decide, the §1 hand-offs** (ADR-0017
   sequencing, classification mechanics, quotas) — it depends on the
   `authorize_list_read` outcome as a contract (INV-3).

---

## 12. Governance history

**Round 1** (2026-07-11 — Gate 2 security-guardian + docs-writer, Gate 3
architect). No CRITICAL/HIGH/BLOCKING. All three returned PASS on a faithful,
well-cross-referenced docs-only change; findings folded in a same-round
hardening pass:

- *security (MEDIUM)* — the confinement invariant covered only per-CVE device
  sets, leaving a residual over-disclosure path: a confined view's *CVE list* and
  *per-CVE counts/aggregates*, derived from the fleet-wide store, could reveal
  CVEs affecting only out-of-scope devices. Fixed: added **INV-7** (membership +
  aggregate confinement, with an M3(d) count/membership sub-check) and referenced
  it from F-5.
- *security (LOW×2)* — **INV-5** broadened from "unreachable" to any
  non-affirmative confinement response (error/timeout/partial); added **INV-8**
  (confined views no-store, never replayed across a scope shrink).
- *architect (SHOULD)* — corrected the O(fleet) claim: O(hits) findings for a
  ubiquitous package *is* O(fleet) and irreducible, so **F-2/NF-1** now say "no
  fleet-inventory replica / no super-linear term", not "sub-fleet egress";
  **F-4** now requires M2 to measure expansion egress at a concrete 500k scale.
  Corrected the §6 fallback to state candidate (b) **relaxes** INV-3/INV-4 (not
  "preserves" them). Added the tracking-issue requirement for the Decision-4
  scale amendment (Decision-log entry 2). Folded plan Decision 6's per-module
  re-examination warning into **F-3**.
- *docs (SHOULD)* — added the pending-#2035 rename note to the citation
  convention so today's `1005` companion paths are not read as dead links.

**Round 2** (2026-07-11 — Gate 2 security re-review, Gate 4 happy/unhappy/consistency,
Gate 6 compliance/sre/enterprise-readiness). Security re-review confirmed all
Round-1 fixes closed with no regression. No CRITICAL/HIGH/BLOCKING from any
agent; a broad SHOULD set folded in this hardening pass:

- *merge hygiene (consistency, git-proven)* — dev advanced during the run and
  PR #2035 (0022→1005 rename) **merged**, inverting Round-1's pending-#2035 note.
  Rebased the branch onto current `dev` (1005 paths now resolve in-branch) and
  replaced the note with a plain "rename merged" statement.
- *confinement/artifact (unhappy BLOCKING + security)* — **INV-2** now caps the
  read-purpose artifact TTL (≤ 5 min) so a revoked operator can't keep rendering;
  new **INV-9** requires the artifact be sender-constrained or single-use
  (leaked-bearer replay); new **INV-10** requires a confinement-read completeness
  signal (admitted/denied/not-evaluated) so INV-5's fail-closed-on-partial is
  enforceable; **INV-7** now recomputes aggregates per page (mid-view scope-shrink
  count leak).
- *capacity/observability (unhappy + sre)* — **NF-2** now mandates bounded
  queue-or-shed backpressure with an engine-first-shed/reservation order (not a
  bare non-starvation outcome) and production-envelope degradation; new **NF-8**
  makes the §6-fallback latency/load metrics, reaper-liveness + store-size,
  engine-throttled, and findings-store-readiness + sync-staleness signals
  existence-required now (shape at stack ADR); **NF-7** states the UCE-view ≤
  server-list-read availability coupling.
- *findings-store lifecycle (happy + unhappy + compliance)* — new **F-13**
  (sync-supersede, departed-device aging, re-enrollment reconciliation; M3 triage
  reconciliation named), **F-14** (subject-erasure/DSAR distinct from
  decommission; legal-hold-aware reaper), **F-15** (no unconfined view ever +
  the M2→M3(d) pre-cutover pilot-exposure prohibition, carried forward binding).
  F-1 now states the finding key.
- *compliance/enterprise (SHOULD)* — the §3.5 UCE row gains the "confinement not
  yet verified — not an affirmative CAIQ/CC6.1 answer" caveat its sibling rows
  carry; **NF-6** routes its UCE-side control-set owner/milestone to §10; **NF-4**
  requires an actionable version-mismatch diagnostic; **NF-1** gains the
  "design-target-not-validated-claim" hedge; §1 names the Workstream-G
  customer-assurance deliverables and the engine-principal onboarding walkthrough
  as owed hand-offs.

**Gate 8 re-verify** (2026-07-11 — security-guardian + consistency-auditor on the
Round-2 baseline). Both PASS, no CRITICAL/HIGH/BLOCKING; the unhappy-path BLOCKING
cluster (uncapped TTL / bearer replay / partial evaluation) confirmed closed by
INV-2/INV-9/INV-10. A final accuracy polish folded the LOW/NICE nits: clarified
that INV-7 aggregates are O(confined-set) (not O(page)) so §6/NF-1's cost claim is
precise; echoed F-14's DSAR + legal-hold-aware commitments into §7's deletion
bullet and the §3.5 row (single-registered-entry parity); named INV-10 as a
response-shape *input to* ADR-0017 PR-A (§1 + INV-10); softened F-14's
retention-disable precedent to "proposed convention"; added the F-15 clause-2
floor framing.

**Maintainer grill** (2026-07-11 — post-Gate-8 design review with the maintainer).
Two directed changes to **F-15** and the §6 dependency edge: (1) fixed the
"multi-group/MSP" phrasing that conflated MSP multi-tenancy with the general case —
the confinement trigger is the existence of a **management-group-confined operator**
(intra-tenant scoping; a regionally-scoped single enterprise trips it, MSP is just
the most extreme instance of the same ADR-0017 mechanism); (2) added a **permitted
interim operating mode** so the ADR-0017-PR-A dependency does not dead-end the
feature: pre-PR-A the findings view MAY serve any tenancy with no group-confined
operators (today's common case per ADR-0017:60), and a group-confined viewer gets an
honest "confinement pending" state rather than an unconfined view — enforceable at view-ship
without PR-A, with the verified end-state still gated on PR-A + M3(d).

A third outcome: the maintainer flagged that 2c is the **use-case-agnostic host**
doc and should not dictate a module's internal data model. Resolved by **labelling in
place** (not relocating): §1 states the host-universal vs **[first module]**
convention; F-1 and the §3.5 findings-store block (F-12…F-14, §7) are tagged
**[first module]** as the vuln instance of a host obligation (the mandated
data-inventory entry), explicitly not host-universal; F-2 was reworded to the
host-universal "no fleet replica" principle that F-1 instantiates. No requirement was
moved or renumbered — the exec-plan-mandated data-inventory entry stays 2c content.

**Topology + module-reconciliation revision** (2026-07-12 — maintainer + colleague
design decisions; the vuln-module design doc arrived from its owner). Changes:
(1) **Deployment topology decided** — the UCE database is a separate database on
the **same PostgreSQL instance** as the server's (accepted trade-off), and the UCE
deployable (backend + GUI, one artifact) runs on its **own VM in the same data
centre**. Folded into NF-3 (isolation mechanics + cross-DB-access ban), NF-2 (DB-tier
write-pacing seam), NF-7 (shared-instance failure domain, stated honestly), NF-8
(per-DB signals), §10 (cross-origin server-side CORS/`SameSite` deliverable). Full
design: `docs/uce-deployment-topology-design.md`; exec-plan Decision 11 amendment
drafted separately.
(2) **F-1/F-4 corrected against code** — `SoftwareCatalogRow` carries **no version
strings** (name/publisher/counts only), so plan Decision 5's "distinct name/version
pairs" grain does not exist; F-1 is now the module design's **two-tier read**
(tier-1 name-level candidate filter, tier-2 per-device `query_software(name)` full
identity) and F-4 re-derives the egress estimate for that model.
(3) **Milestone reties** — F-12/F-13/F-14/F-15, §7, and the §3.5 row now bind to
the **store-ship / view-ship events**, not a hard-coded "M1" (the module's revised
ladder places the store at its M3; its M1 is a source-ingestion skeleton).
(4) **Cross-doc reconciliations named, not silently resolved** — the module doc's
synced-predicate confinement proposal identified as candidate (c) and answered by
§5/§6; its machine-callable "confirm-now" action named as a 2d reconciliation item
against F-10/plan Decision 3 (§1).

**Topology delta round** (2026-07-12 — security-guardian + sre + consistency-auditor
on the topology fold + `docs/uce-deployment-topology-design.md` + the exec-plan
amendment). No CRITICAL/HIGH from security; sre 1 BLOCKING + consistency 1 BLOCKING,
all folded same-day: F-13/F-14's leftover hard-coded "M1" retied (completing §12
entry (3)'s claim); NF-8(vi) rescoped honestly (per-DB tuple/connection/temp-file
attribution via `pg_stat_database`; WAL/checkpoint = correlation, instance-global);
topology-doc hardening — `idle_in_transaction_session_timeout` + `statement_timeout`
+ `work_mem` caps now MUST-set (instance-wide xmin-horizon risk), PUBLIC-CONNECT
revoke corrected (`REVOKE ... FROM PUBLIC`, the bare role-revoke is inert),
`uce` role attributes pinned (NOSUPERUSER etc., no predefined-role memberships,
`scram-sha-256`), backup joint policy bound to F-14 retention + restore-time
re-purge + whole-instance-PITR caveat, T2 split into decision (needs T3) +
implementation, NF-8 un-stub + capacity baseline named (T5), redirect-flow CSRF/URL
pins, port-scoped firewall + cert-rotation obligation, CORS wording aligned to the
existing self-origin reflection; exec-plan amendment additionally corrects
Decision 5's disproven catalogue grain (pointing at F-1/F-4).

**Maintainer grill round 2 — topology** (2026-07-12, four decisions folded into
`docs/uce-deployment-topology-design.md` and NF-7/F-4 here): (1) **operator login
to the UCE GUI = Yuzu-as-identity-provider** — no UCE user store; the §3 redirect
flow doubles as login, and **SSO is inherited transitively** through Yuzu's shipped
OIDC (corporate IdP → Yuzu → UCE; the UCE never registers with the corporate IdP);
#1836's next-login deprovisioning residual inherited knowingly, bounded by INV-2.
(2) **Scale testing is synthetic and its mechanism is NOT a prerequisite of this
plan** — ≥500k is a design/architecture commitment (NF-1); F-4/T5 reworded
(largest-synthetic-scale + extrapolation; baseline informs, doesn't gate).
(3) **Single VM accepted for v1; HA is a committed pre-GA requirement** (Phase-8
gate) — NF-7 + topology §2.6; T1 carries the instance-restart outage note.
(4) **UCE session pins**: max-age ≤ Yuzu's; revocation propagates via the reads
(failed re-mint / revoked-operator read ⇒ session-terminating) — force-logout
reaches the UCE with no new server surface.

**Governance round — login/session/topology** (2026-07-12, Opus-driven full pass;
Gate 2 security-guardian + docs-writer, Gate 3 architect on the net state incl. the
maintainer-grill-round-2 folds). No CRITICAL/HIGH; no architectural BLOCKING;
docs 1 BLOCKING (SOC 2 row) + all fixed same-round. Folded: **new NF-9** promotes
the login/session security pins from topology-doc prose to binding host requirements
— (a) no foreign IdP token, (b) login-callback `state`/nonce + exact-match GUI-origin
redirect target, (c) login artifact identity-only + distinct from the confinement-read
artifact + browser-redirect re-mint (INV-1 memory-only), (d) session = bounded cache
of Yuzu authority with a **re-validation floor for idle sessions** (security-guardian:
revocation-via-reads only propagates while reads flow; architect: give the pins a
normative home), (e) cookie-surface CORS MUST NOT port PR-#2060's absent-Origin-allowed
rule (safe only for the bearer/non-browser MCP endpoint). §3.5 SOC 2 row gains the
shared-instance topology caveat (was overstating instance-level isolation for CAIQ);
companion-docs list + §10 NF-6 audit events updated; topology §5 now surfaces that
T2b ships only the F-15 *interim* view (the confined read still gates on ADR-0017
PR-A + M3(d)) and notes M2's engine-principal/F-3 cross-program edge; §2.2 denied-test
extended to role-attribute/extension drift; amendment D5 caveat re-pointed to tier-2.

**Governance round 2 — Gate 4 + Gate 6 on NF-9** (2026-07-12, Opus-driven; happy/
unhappy/consistency + compliance/sre/enterprise-readiness). Consistency PASS; no
CRITICAL/HIGH; the SRE + unhappy-path BLOCKING converged on one point — **NF-9(d)'s
re-validation floor lacked a transient-failure posture** — folded, plus a coherent
login/session-hardening cluster:
- **NF-9(d) rewritten** — the liveness floor is now **unconditional + jittered**
  (removes the fuzzy active/idle boundary), the max-age is called out as a config
  *ceiling* (per-session bound comes from the floor), and the **transient-failure
  posture** is pinned: an indeterminate liveness result uses bounded retry/backoff
  and fails closed only after N-consecutive/grace (2b bounded-grace vs INV-5 hard
  fail-closed for *definitive* denials) — so a Yuzu blip can't mass-logout the fleet.
- **NF-9(b)** — per-attempt state binding (concurrent-tab collision) + pre-redirect
  context storage that survives 3p-cookie blocking.
- **NF-9(f)** (new) — login-flow robustness: fail-closed redeem→establish, atomic/
  idempotent single-use redeem (callback-replay re-mints, no dead-end), F-8 hand-off
  on a lapsed Yuzu session re-auths (not a 401 dead-end).
- **NF-9(g)** (new) — cross-host clock-sync + artifact skew tolerance (a 5-min
  cross-host TTL); session residency (in-memory vs `uce`-DB) NF-7 implications named.
- **NF-7** coupling list extended (login + liveness-ping); **NF-8(vii)** login/session
  alertable telemetry added (distinct from §10 audit events); **NF-4** mid-run
  version-skew routed to the §2.6 upgrade runbook; **F-15** interim gate mechanism
  named (reads existing RBAC group-scoped-role data — needs no PR-A).
- Topology **§2.4** open-loop-backpressure + statement_timeout-vs-long-sync
  reconciliation; **§5** T2b now = login+view surface (populated view awaits
  store-ship) + audit-emit acceptance, T5 baseline gains the API path, restore
  re-purge gains a verify hook; **§1** pilot-onboarding hand-off widened to the full
  T1–T5 stand-up + the visible-redirect SSO UX. SOC 2 **§3.2** cross-refs NF-9 +
  the #1836 blast-doubling; **§3.5** gains an NF-9 "designed, not verified" CAIQ caveat.

**Gate 8 re-verify — round 2** (2026-07-12, security-guardian + consistency-auditor
on the NF-9 hardening). Both PASS, no CRITICAL/HIGH. Closing folds: NF-9(d)
qualifies "failed re-mint" as *definitively* failed (an unreachable-Yuzu re-mint is
indeterminate and inherits the liveness grace — else a blip mass-logs-out the
re-minting subset); NF-9(g) pins a DB-resident session row to identity+expiry only
(INV-1/F-9); topology §3's session-pin summary re-synced to NF-9(d)'s unconditional/
jittered floor + grace posture (dropping the now-non-equivalent idle-timeout
alternative); T5 names NF-8(vii). Security confirmed definitive-vs-indeterminate
does not contradict INV-5 (INV-5 governs *render*, the grace governs *teardown* —
complementary; a blip still blocks all rendering, leaks nothing).
