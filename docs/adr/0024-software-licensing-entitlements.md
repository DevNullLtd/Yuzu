---
status: accepted
date: 2026-07-06
owner: Alex Young
deciders: product-owner direction; planning Q&A 2026-07-04 (rev 2 same day); privacy & secrets review rounds 2026-07-06; grilling session 2026-07-06; industry-direction review 2026-07-08 (metric-typed quantities, Java/SWID surfaces, Direction section)
scope: capability §27 — agent licence discovery, the discovery stores and read surface, RBAC, and the per-user privacy carve-out (built in-server); multi-source entitlement ingestion, server-side compliance evaluation, usage metering & reclamation, and the compliance UI/MCP surfaces re-scoped to the SAM use-case-engine module per "Placement under ADR-1005"; plus the recorded target-state direction
context-refs: capability §27 issues #264–#267; #266 (entitlement-register reversal); ADR-0017 flip-wave (#1634, #1715); superseded standalone ADR PR #1870 (rev 1–5 review history); deferred — #1921 (KEK operator surface), #1922 (oidc_client_secret gap), #1923 (round-3 review items)
---

# 0024 — Software Licensing & Entitlements (SLE: agent-discovered licences + multi-source entitlements)

> **Implementation status (2026-09-07 ADR reconciliation):** Shipped — `ProductRegistryStore`/`SoftwareLicensingStore` (`server/core/src/product_registry_store.cpp`, `software_licensing_store.cpp` — not `license_store.cpp`, which is the dormant Yuzu product-licence store of ADR-0048), `sle_routes.cpp`, and the agent `license_scan` plugin all exist and are wired. Shipped: PR #1950 ("feat(sle): PR1a - Software Licensing & Entitlements discovery plane (ADR-0024)"), merged 2026-07-13. Scope note: this covers the in-server discovery plane per the frontmatter `scope:` split — the SAM use-case-engine-module portion (multi-source entitlement ingestion, compliance UI/MCP) remains re-scoped under ADR-1005, unaffected by this flip.

## Summary

**Capability §27 — Software Licensing & Entitlements (SLE)** lets a fleet answer: what
software licences are in use and of what type, what has lapsed, what renews or expires
soon, how purchases compare with deployment, and what is paid-for but unused. Under
ADR-1005 (the server is a headless platform — **mechanism, not interpretation**), §27
splits along that boundary: **this ADR builds the discovery mechanism in-server and
defers the interpretation half to the SAM use-case-engine (UCE) module** (see "Placement
under ADR-1005").

**In-server (this ADR) — the discovery mechanism:**
- **`license_scan` agent plugin** (D2) — probes every OS licensing surface (Windows WMI
  `SoftwareLicensingProduct` + Office C2R + an extensible ProbeSpec table + per-user
  hives; Linux rpm/dpkg/entitlement-certs/FlexLM; macOS receipts; the Java and
  ISO-19770-2 SWID tag surfaces are the named fast-follow, #2112); never persists or
  transmits key material.
- **`software_licensing` daily-sync source** (D3) — transports records on the ADR-0016
  framework (raw-blob hash-skip, forward-compatible, no proto change).
- **Two born-on-Postgres stores** (D4/D6) — `ProductRegistryStore` (canonical identities +
  deterministic `product_normalize` matching) and the raw `SoftwareLicensingStore`
  (per-agent discovered rows).
- **Read surface + RBAC** (D9/D10) — the `/sle` **Licences** view, the raw `/api/v1/sle/*`
  discovery reads (incl. the ancestor-aware `/sle/agents/{id}` drill) **and their MCP twin
  `query_software_licenses`**, and the new **`SoftwareLicensing`** securable.
- **Privacy + erasure** (D11) — pseudonymous-by-default `user_ref` (per-agent keyed-HMAC)
  and the **agent-decommission erasure cascade** (first production wiring of the five
  per-agent-store fan-out; the shared `ProductRegistryStore` is excluded — see D11).

**Deferred to the SAM UCE module — the interpretation half:**
- **Compliance evaluator** (D7/D8) — effective-state/lapse derivation, seat math, posture
  rollups, deduplicated notifications.
- **Entitlement plane** (D12/D14) — five sources, metric-typed quantities, CSV ingest.
- **M365 Graph connector** (D13) — tenant SKU sync + its SecretCodec secret storage (so
  **§27 carries no SecretCodec wiring**).
- **Usage metering & reclamation** (D15), and the **Compliance / Entitlements /
  Reclamation** SLE sub-views + the compliance MCP tool `get_license_compliance_summary` (D9).

**Maintainer sign-off required** (Ratification): (1) the Decision-11 per-user probing
deviation from ADR-0016's machine-scope/no-PII posture; (2) the ADR-1005 placement
re-scope.

## Background

Supersedes the roadmap Phase 10 sketch of capability §27 (a SQLite `CatalogStore`, a
hand-maintained entitlement register, a `software_usage` agent plugin, software tags,
and a compliance dashboard) with the design recorded here: agent-discovered licences on
the ADR-0016 daily-sync framework and born-on-Postgres discovery stores (built
in-server), plus multi-source entitlements, compliance evaluation, and the SLE
compliance surfaces (re-scoped to the SAM use-case-engine module — see "Placement under
ADR-1005"). It also renames the capability from the map's "Software Catalog & Licensing"
to **"Software Licensing & Entitlements" (SLE)** — the capability-map §27 entry is retitled
accordingly. It supersedes the closed standalone ADR PR #1870 (five review rounds; the
rev 1–5 history remains on that PR), and is numbered 0024 because 0021–0023 are
reserved by in-flight ADR branches. It records a single, contained deviation from ADR-0016's
machine-scope/no-PII posture — per-user licence probing on the licence source only
(Decision 11) — which requires maintainer sign-off. Yuzu's own product-licence
machinery (`LicenseStore`, the `License` RBAC securable, capability §22.3) is
untouched; all naming here uses `ProductRegistry*` / `SoftwareLicensing*` /
`SoftwareEntitlement*` / `SoftwareUsage*` and `software_license.*` /
`software_entitlement.*` event names.

**Placement note (post-ADR-1005):** this ADR is re-scoped to the headless-platform
boundary that landed after it was drafted — only the agent-side discovery mechanism and
its stores/read surface are built in-server; compliance evaluation, entitlements, the
M365 connector, usage reclamation, and the compliance UI/MCP surfaces are deferred to
the SAM use-case-engine module. See "Placement under ADR-1005" below, which governs
where each decision is built.

## Context

The platform cannot today answer five operator questions: what software licences are
in use on an asset and of what type; whether anything is running on a lapsed licence;
which licences and subscriptions are coming up for renewal or expiry; how what was
purchased compares with what is deployed; and what is being paid for but never or
rarely used. The capability map (§27, five sub-capabilities, all Not Started) and
roadmap Phase 10 sketched this in 2026-03, but three things have since changed under
that sketch. **The storage substrate moved:** ADR-0006/0007 forbid new SQLite server
stores; new stores are born-on-Postgres per the store contract (ADR-0012), so the
Phase 10 names (`CatalogStore (SQLite)`, `entitlement_store.cpp`) are stale. **The
ingestion substrate now exists:** ADR-0016's daily-sync framework is live with three
sources (`installed_software`, `app_perf`, `device_ci`), a shared server ingest seam
used by both the direct gRPC path and the Erlang gateway proxy, and typed Postgres
projections — and it explicitly anticipated "a future `last_used` usage source for
SAM/entitlement," which this design fulfils alongside licence discovery. **The product
decision changed:** the manual entitlement register drafted in issue #266 was first
rejected — licence data must be agent-discovered — then, at rev 2 (2026-07-04),
entitlements returned to scope as a *separate, multi-source* plane measured alongside
discovered licences, and the owner directed a brand-new top-level "SLE" page rather than
a tab on `/inventory`.

Name collisions constrain the design. `LicenseStore` and the `License` securable
already mean **Yuzu's own product licence** (§22.3) and stay untouched. "Software
catalog" already means the shipped `/inventory` rollup of *installed* software
(`SoftwareCatalogRow` / `SoftwareCatalogRollup`); the new canonical-identity store is
therefore a **registry**, not a catalog, and nothing in §27 borrows the "software
catalog" name — it keeps its existing `/inventory` meaning. The capability's RBAC
securable is named **`SoftwareLicensing`**, matching the renamed capability, the
`software_licensing` source, and the store family. Yuzu is effectively greenfield here
(small test labs, no customers on this surface), so there is no legacy-compatibility
burden beyond preserving ADR-0016 wire stability across mixed-version fleets.

## Terminology

- **Software licence** / **discovered licence** — endpoint software licensing state
  (product, type, channel, status, expiry) as observed by an agent. Always qualify:
  a **Yuzu licence** is the product's own licence (§22.3), a different thing.
- **SLE** — "Software Licensing & Entitlements," the §27 capability and the new page.
- **ProductRegistry** — canonical software-identity master data (deterministic
  matching of raw names → one product). Distinct from the `/inventory` "software
  catalog," which keeps its existing meaning.
- **Discovery plane** vs **entitlement plane** — the two data planes: what is
  *observed on endpoints* vs what is *purchased*.
- **Effective licence state** — the state (including lapse) the compliance evaluator
  (SAM UCE module, Decision 7) *derives* from agent-reported facts against "now"; not a
  raw agent field.
- **Entitlement** — a purchased right (a metric-typed quantity — seats in v1 —
  plus type, term, renewal, cost) from a manual, CSV, connector, or agent source.
- **Licence metric** — the unit an entitlement is denominated in (`seat`, `core`,
  `processor`, `employee`, `token`, …). The industry is moving off device-install
  counts; the schema is metric-typed from birth (Decision 12) even though the v1
  evaluator computes seat math only.
- **Unentitled** — a product with discovered licences but no entitlement data; never
  reported as "compliant." **Unreported** — an asset with no usage data; never
  reported as "unused."

## Placement under ADR-1005 (headless-platform boundary)

**Added after ADR-1005 landed on `dev`; load-bearing — it draws the core-mechanism
vs use-case-engine-interpretation line through every decision below and governs where
each is built.** ADR-0024 was drafted 2026-07-06 in mutual ignorance of ADR-1005
(`docs/adr/1005-headless-platform-use-case-engines.md`, `proposed`, same date), which
establishes that the Yuzu server owns **mechanism, not interpretation**: it collects,
enforces, and transports facts about the estate (core), while *interpreting* those
facts for a purpose — domain scoring, compliance-framework semantics, or joins with
external domain data — lives in an external **use-case engine (UCE)**. Its execution
plan (`docs/adr-1005-execution-plan.md`, Decision 6) names **software asset management
as the likely second UCE module**, and flags that module's per-device licence
attribution as needing a device-grain data-residency review as an explicit first step.

**Ruling — re-scope, not a carve-out.** Applying ADR-1005 Decision 2's boundary test
component-by-component, §27 splits cleanly, and this ADR is re-scoped to that split
rather than requesting an in-server exception:

| §27 element | ADR-0024 decision | ADR-1005 class | Justification (Decision 2 + tiebreakers) |
|---|---|---|---|
| `license_scan` plugin | D2 | **core** | Collection of estate facts — parallel to the `vuln_scan` plugin ADR-1005 keeps core. |
| `software_licensing` daily-sync | D3 | **core** | Transport of collected facts on the ADR-0016 framework. |
| Raw discovered-licence rows | D4 | **core** | An inventory store of raw estate facts. |
| `ProductRegistryStore` + `product_normalize` | D4/D6 | **core** | Deterministic identity resolution over pure fleet-internal aggregation (a generic engine, no external data) — the `software_catalog`-rollup tiebreaker. |
| Ingest seam | D5 | **core** | Untrusted-input transport plumbing. |
| Raw `/sle/agents/{id}` drill + discovery reads + their MCP twin `query_software_licenses` + `SoftwareLicensing` securable | D9/D10 | **core** | Raw-fact reads (like `/devices`), ancestor-aware scoped; the REST+MCP twin satisfies ADR-1005 D1. |
| Agent-decommission erasure cascade | D11 | **core** | Platform-wide data-lifecycle mechanism (all five per-agent stores). |
| Per-user `user_ref` discovery | D11 | **core** (collection) | Estate collection; carries behavioural-PII data-processor obligations (see re-home note). |
| Compliance evaluator (effective state, lapse, seat math, posture rollups) | D7 | **UCE** | Semantics baked into code — interpret facts for a purpose. |
| Lapse/expiry/renewal notifications | D8 | **UCE** | Evaluator-derived. |
| `SoftwareEntitlementStore` + entitlement plane | D12 | **UCE** | Purchased-rights domain data joined to fleet facts for compliance. |
| M365 Graph connector + its SecretCodec wiring | D13 | **UCE** | The canonical "join fleet data with external domain data." |
| CSV entitlement ingest | D14 | **UCE** | Entitlement-plane ingestion. |
| `SoftwareUsageStore` reclamation verdicts | D15 | **UCE** | Usage joined with entitlement data for a reclamation purpose. |
| Compliance / Entitlements / Reclamation SLE sub-views + the `get_license_compliance_summary` MCP tool | D9 | **UCE** | Domain use-case (compliance) product surfaces. |

**Consequences of the re-scope for the decisions below.** Decision 4 ships **two**
born-on-PG stores in-server (`ProductRegistryStore`, the raw `SoftwareLicensingStore`),
not four; `SoftwareEntitlementStore` and `SoftwareUsageStore` are the UCE module's
stores. Decision 9's SLE page ships **only its Licences (discovery) view** in-server;
the interpretation sub-views are the UCE host's UI. Decision 10's fan-out list reads
(`/sle/licenses/{key}/devices`, the posture list fragments) are UCE-module reads and are
not built here; only the raw `/sle/agents/{id}` drill and the raw discovery reads ship.
Decisions 7, 8, 12, 13, 14, 15 are deferred to the SAM UCE module in full — the designs
they record stand as that module's input, not as in-server work. In particular,
**SecretCodec's first production wiring does not happen under §27** (Decision 13 moves
with the connector), so the Decision-13 KEK deferral no longer bears on this ADR. Because
the SAM UCE host does not exist yet — engine principals, on-behalf-of delegation, and
bulk-egress primitives are all deferred by ADR-1005 — the interpretation half is a
scoped backlog, not an immediately-buildable target; §27 v1 is the discovery foundation
it will read from over the versioned `/api/v1/sle/*` contract.

**Store ownership follows the layer** (ADR-1005 Consequences): the raw discovery store
and product registry are permanently server-resident core; the entitlement and usage
stores are interpretation-owned and belong to the UCE module. The seam that makes the
future extraction a strangler, not a rewrite, is the evaluator's injected-provider
boundary — the module re-implements the pure decision functions and points them at the
versioned reads instead of in-process store handles, the same shape as the vuln module's
NVD re-home.

**Precedent.** This is the boundary question ADR-1005 already settled for the
vulnerability vertical: its grandfather clause reconciles the in-server ADR-0023
correlation stack and the ADR-4001 dashboard, and the execution plan's "Relationship to
ADR-0023 and ADR-4001" records the maintainer ruling. §27 differs only in resolution —
rather than an in-server carve-out, it re-scopes so the interpretation half is never
built in-server, the cleaner outcome Decision 2 points to when the work has not yet
shipped.

**Re-home / PII note.** The `/api/v1/sle/*` discovery reads are on the published
versioned contract from birth, so any later change to their placement follows the
standard deprecation cycle. When the SAM UCE module later consumes per-user `user_ref`
discovery, that behavioural PII crossing the server→engine boundary triggers ADR-1005
Decision 5's security-guardian design review and makes the module a data processor with
its own retention/deletion obligations, and the fail-closed per-open behavioural audit
(Decision 11) must be reproduced engine-side — recorded here as a first-step item for
that module's scoping, alongside the Decision-6 device-grain residency review.

## Decisions

Each decision is tagged for its ADR-1005 placement (see "Placement under ADR-1005"):
**[core]** ships in-server as discovery mechanism; **[UCE]** is deferred to the SAM
use-case-engine module — recorded here as that module's design input, not as in-server
work; **[split]** ships its discovery half in-server and defers its interpretation half.
Decision numbers are stable, since other documents cite them.

1. **Two data planes, kept deliberately distinct. [split]** Licence *discovery* is
   **agent-only** — there is no manual path to edit discovered state, so "truth on the
   endpoint" is never hand-massaged; this plane is the **in-server** mechanism §27 v1
   builds. *Entitlements* (what was purchased) accept **manual, CSV, and automated**
   input and are the **SAM UCE module's** plane. Purchased-vs-deployed math is computed
   only where entitlement data exists (discovered-only products stay honestly
   `unentitled`) and is UCE interpretation. The two planes never merge into one editable
   record. A consequence, stated as a gap rather than hidden: **a discovered reading has
   no operator override** — the remedy is a corrected probe in the next agent release;
   each record's confidence is surfaced precisely so operators can weight `heuristic`
   rows accordingly.

2. **Agent discovery is a new `license_scan` plugin that probes every available
   surface. [core]** Per-OS translation units with pure parsers split out; actions `list`
   (emit records) and `surfaces` (diagnostics — which surfaces are available and why
   not). Surfaces v1 (as shipped): Windows WMI `SoftwareLicensingProduct` (own bounded
   COM, never `WBEM_INFINITE`), Office ClickToRun registry, an extensible `ProbeSpec`
   table (MS server products, Autodesk, security/backup agents, VMware, open-source
   classification), and **per-user hives** (incl. `RegLoadKey` of offline
   `NTUSER.DAT`); Linux `rpm`/dpkg DEP-5 declared licence, RHEL entitlement certs,
   FlexLM `.lic` expiry; macOS `_MASReceipt` + machine-scope vendor plists.
   **Two surfaces the industry-direction review (2026-07-08) added are the named
   fast-follow, deliberately NOT in the shipped v1 (tracked #2112):** **Java
   runtimes** — vendor/distribution/version, Oracle JDK vs the OpenJDK builds, the
   single most audit-relevant probe in the current climate (the per-employee Java
   metric plus download-log enforcement makes "which Java is on which machine" the
   first question every audited estate is asked) — and, on all three OSes,
   **ISO 19770-2 SWID tag files** (`*.swidtag` in the standard tag directories), a
   cheap, standards-based surface whose parsed vendor artefacts qualify for
   `authoritative` confidence and which the leading commercial suites ingest as
   first-class recognition evidence. Both land as `ProbeSpec` extensions on the seam
   this decision builds — deferring them keeps the recorded v1 surface list honest
   against the shipped plugin (contract follows code) without shrinking the recorded
   aim. Adding a vendor later is one `ProbeSpec` row. Vocabularies are **closed and
   unknown-preserving** (the plugin never fabricates): `license_type`, `status`,
   `source`, and a `confidence` of `authoritative | probable | heuristic`
   (`authoritative` only from an OS/vendor licensing API or a parsed vendor artefact).
   **Licence key material is never persisted or transmitted** — only a `key_hint`
   (OS-provided partial or an in-memory hash prefix). `exe_hints` on each record is
   the authoritative product↔exe bridge for the usage join (Decision 15). Every field
   is strict-sanitised (strips delimiter/control bytes, clamps to 1024 B).

3. **Transport is a new `software_licensing` daily-sync source on the ADR-0016
   framework. [core]** Parse plugin output → canonical blob (records sorted + deduped,
   delimiter-joined) → SHA-256. **Unlike the three legacy sources, this source's
   hash-skip comparison is computed over the raw received blob bytes** (recomputed
   server-side — the claimed hash is never trusted), not over re-parsed rows — so
   skipping unknown record kinds cannot push a mixed-version agent into the permanent
   full-resend loop ADR-0016 documents for the parse-then-recompute sources, and the
   forward-compat rule below is genuinely loop-free in both directions. (One accepted
   consequence: a server-side projection fix does not re-project a stable estate by
   itself — the framework's `need_full` path remains the forced-resync lever.) The wire key
   rides `InventoryReport.plugin_data` — **no proto change, no gateway regen** (opaque
   `map<string,bytes>`). Interval 24 h; hash-skip is meaningful because licence
   estates are stable day-to-day. **Blob-stability rule:** the canonical blob contains
   only facts that change when discovered state changes — no collection timestamps, and
   countdowns (e.g. KMS grace minutes) are converted to an absolute UTC date so a
   ticking counter cannot defeat hash-skip. **Empty-vs-error:** zero rows is a
   legitimate state (a valid empty blob full-replaces to empty); the cycle is skipped
   only when a platform's *primary* surface reported an error — where "success" is
   structural, not inferred: the enumeration API itself completed (a query returning
   zero rows is success; access-denied or a failed call is error), and per-user hives
   are never a *primary* surface — so a real failure never wipes stored state and a
   privilege-stripped fleet can neither wipe state nor stall its syncs.
   **Forward-compatibility:** both the agent blob parser and the server seam **skip
   unrecognised record-kind prefixes**, so later record kinds (the `ent|` entitlement
   records, Decision 12) ride the same blob without breaking mixed-version fleets in
   either direction.

4. **Canonical discovery state lives in two born-on-Postgres stores in-server; the
   entitlement/usage stores are the UCE module's. [split]** In-server core:
   `ProductRegistryStore` (canonical identities + match links) and
   `SoftwareLicensingStore` (per-agent **raw discovered rows**). Per Placement under
   ADR-1005, `SoftwareEntitlementStore` (purchased state from five sources) and
   `SoftwareUsageStore` (usage facts) are interpretation-layer stores owned by the SAM
   UCE module and are **not** built in-server; the posture-rollup and alert-dedup tables
   the evaluator writes are likewise UCE-owned and move with the evaluator (Decision 7),
   so `SoftwareLicensingStore`'s in-server surface is its raw-discovery tables, kept
   physically separable from those rollup tables so the future extraction is a table-set
   split, not a rewrite. The in-server stores follow the full store contract: no new
   SQLite (ADR-0006/0007), born-on-Postgres (ADR-0012) — migrate-at-construction on a
   pinned lease, schema-qualified runtime SQL, bounded leases, fatal-on-open-failure,
   destruct-before-pool; **no cross-schema SQL or FKs**. Reads are authoritative (a
   degrade returns nullopt → 503/banner, never a silent empty list). *Rejected: extending
   `SoftwareInventoryStore` with licence columns — installed software and discovered
   licences have different lifecycles; one-store-per-typed-domain is the established
   precedent.*

5. **One ingest seam per source, shared by the gRPC and gateway paths, with a
   same-change typed-registry rule. [core]** The **licensing** ingest seam sits beside
   the existing inventory seams and is called from **both** the direct
   `ReportInventory` and the gateway `ProxyInventory` (the usage ingest seam ships with
   the usage source, Decision 15). Untrusted-input discipline
   before the store: blob and record caps, per-field UTF-8 scrub/clamp, enum whitelists
   (unrecognised → `unknown`), expiry plausibility-clamp. The server **recomputes** the
   hash over the raw received bytes — it never trusts the claimed one — and enum
   normalisation happens at store projection, after the hash comparison.
   **Load-bearing invariant:** each new wire key is added to
   `typed_inventory_sources.hpp` **in the same change** as its seam — omission
   double-stores the blob into the generic `InventoryStore` on the gateway path,
   readable under `Infrastructure:Read`, i.e. a leak past the `SoftwareLicensing`
   securable.

6. **Catalog matching is deterministic, not probabilistic. [core]** A pure
   `product_normalize` library (`normalize_title`, `normalize_vendor`, `norm_key`)
   feeds strictly-ordered tiers — `exact_norm` → `title_vendor` → `token_set` →
   `birth` (new product). **No fuzzy/Levenshtein matching in v1**: every decision is
   reproducible in unit tests. Aliases persist `method` + `confidence`, so manual
   curation and smarter matching can layer on later by editing aliases, without
   redesign. *Rejected: probabilistic matching in v1 — it trades away determinism and
   testability for accuracy the tiered matcher can approximate.*

7. **Compliance evaluation — deferred to the SAM UCE module. [UCE]** Per Placement
   under ADR-1005, deriving effective licence state (including lapse against "now"),
   purchased-vs-deployed seat math, and compliance verdicts is interpretation and is the
   SAM UCE module's job — **not built in-server** under §27. Recorded as that module's
   design input: a background evaluator (boot pass, then completion-spaced cadence,
   keep-last-good, stop/join before teardown) re-derives effective state including lapse
   against "now", so a device that *stopped syncing* before its licence lapsed still
   reads `expired`. The **honesty commitments are the module's load-bearing acceptance
   criteria**: discovered-only products stay `unentitled`, never "compliant"; absent
   usage is **Unreported, not Unused**; unknown quantities are `NULL`, never a fabricated
   zero; a non-seat metric is never coerced into seat math (its compliance is `unknown`
   until an evaluator for that metric exists); multi-source seat sums keep the per-source
   breakdown visible; and verdict *freshness* (the rollup's as-of time, observable
   staleness) is part of the posture — a wedged keep-last-good evaluator serving stale
   verdicts is the same fail-open class as a silent empty list. The evaluator's
   injected-provider seam (its I/O behind `Deps` providers, its clock behind `NowFn`, its
   decision logic as pure functions) is what lets the module re-point those reads at the
   versioned `/api/v1/sle/*` discovery surface instead of in-process store handles.

8. **Lapse/expiry/renewal notifications — deferred to the SAM UCE module. [UCE]** These
   are evaluator-derived (Decision 7), so they move with it. Recorded as module design
   input: `software_license.expiring/expired` and `software_entitlement.renewal_due` fire
   through the dual-sink pattern (notification store + webhook/offload event) **only** on
   a **worsening** bucket transition (30/14/7/1 days) or persistence past a 7-day re-arm;
   improving transitions never fire and a clear-then-re-assert inside the window is held
   down, so oscillating states cannot spam; the first evaluation of an estate fires once
   per product (a bounded burst, preferred over silently baselining pre-existing
   expiries). This is how the module satisfies "not dashboard-only" without daily noise.

9. **Access: the discovery (Licences) view + the raw read API ship in-server; the
   compliance/entitlement/reclamation surfaces are the UCE host's. [split]** In-server
   core: the `/sle` **Licences (discovery) view** on the shared guardian shell (cloning
   the `/inventory` provider model — nullopt → degrade banner, never an empty table;
   tables and KPI tiles, no charts in v1), the raw `/api/v1/sle/*` **discovery** reads
   **and their MCP twin `query_software_licenses`** (`SoftwareLicensing:Read`,
   management-group scoped like the raw drill — this is the both-REST-and-MCP twin
   ADR-1005 Decision 1 requires for the in-server discovery capability, shipped from day
   one, not deferred), and the new **`SoftwareLicensing` securable**. The destructive
   **`DELETE /api/v1/sle/agents/{id}`** erasure (Decision 11) is deliberately **REST-only**
   — a device purge is withheld from the agentic surface, so it is a *recorded exception*
   to ADR-1005 Decision 1's both-surfaces rule rather than a twin gap: the exception row
   (surface + tracking issue #2102 + revisit-by date) **is recorded** in ADR-1005's
   twin-existence exception ledger, alongside the SCIM-v2 REST-only precedent — entered
   pre-acceptance as voluntary early compliance, which ADR-1005's Binding-status note
   expressly invites. That erasure is authorized by a **CONJUNCTION over every
   securable the cascade erases THROUGH** — the caller must hold, per-device scoped, all
   of **`SoftwareLicensing:Delete` AND `Inventory:Delete` AND `GuaranteedState:Delete`**.
   The cascade's blast radius is wider than the route's name: of the five per-agent stores
   it erases, `SoftwareLicensingStore` is the licensing one; `InventoryStore`,
   `SoftwareInventoryStore` and `DeviceInventoryStore` are governed by the **`Inventory`**
   securable; and `AppPerfDailyStore` is DEX behavioural PII governed by
   **`GuaranteedState`** (its read routes gate on `GuaranteedState:Read`). Gating on the
   licensing securable alone would let an operator-authored role erase inventory data it
   cannot otherwise touch — and, worse, **destroy a device's per-app performance series it
   has no right even to READ**. This is latent under the seeded matrix (both Delete-holding
   roles — Administrator, ITServiceOwner — hold full CRUD on all three), so the conjunction
   changes nothing that ships, but RBAC is operator-editable and the gate must authorize for
   what the operation *destroys*, not for what it is *named*. The store list and the gate
   are pinned together by a drift guard (`test_agent_decommission.cpp`): adding a store to
   the cascade fails the build until its governing securable joins the conjunction.
   *Rejected: a dedicated device-level `Decommission` securable — the honest modelling of a
   cross-securable destructive operation, and the right answer once a second caller
   (enrollment removal, a fleet-management purge) needs it; deferred because it is a new
   seeded securable with a migration and a matrix change, for zero behavioural gain over the
   conjunction today. **Revisit if the conjunction ever reaches a fourth securable** — at
   that width the conjunction is the wrong shape and this decision reverses.* Per Placement under
   ADR-1005, the **Compliance, Entitlements, and Reclamation** sub-views and the
   **compliance MCP tool `get_license_compliance_summary`** are the SAM UCE host's UI and
   read API — not built in-server. The software
   catalog stays on `/inventory`, cross-linked. RBAC grants on the `SoftwareLicensing`
   securable follow the established per-role shape, stated so nothing is left to
   inference: **Viewer and PlatformEngineer Read; Operator Read + Write; ITServiceOwner
   full CRUD**; **ApiTokenManager none**; admin roles per their global pattern. **No MFA
   step-up anywhere in §27** — nothing here executes on endpoints; RBAC Write plus full
   audit (including denied rows) is the control. The nav entry and nav-drift
   reconciliation are bounded to the in-server Licences view; the UCE host owns its own
   navigation for the deferred surfaces. Connector configuration admin-gating moves with
   the connector (Decision 13, UCE). *Rejected: a tab on `/inventory` (rev 1) — reversed
   at owner direction.*

10. **List-read scoping follows ADR-0017. [split]** (Paths are shorthand for
    `/api/v1/sle/*`.) In-server core: the **single-agent raw drill `/sle/agents/{id}`**
    takes the working ancestor-aware per-device scoped gate from day one (the
    `device_routes` precedent: tier + management group, 403 outside scope) — it is also
    Decision 11's privacy-verification surface, so it gets real confinement immediately.
    The fleet-wide **posture** aggregates (`/sle/summary`, `/sle/licenses`, the posture
    Licences fragments) and the **fan-out list read** `/sle/licenses/{key}/devices` read
    the evaluator's rollup, so per Placement under ADR-1005 they are **UCE-module reads,
    not built in-server**. When the module builds them, its delegated reads pass the same
    ADR-0017 `authorize_list_read` chokepoint the operator would hit directly (ADR-1005
    Decision 5) — a globally-granted engine acting for a group-confined operator reaches
    only that operator's groups. SLE's in-server gates use the fail-closed
    `rbac_enforcement_in_effect()` primitive, not the `is_rbac_enabled()` shape whose
    corrupt-rbac.db fail-open is tracked by #1717. *Rejected: an ad-hoc per-row filter for
    the fan-out reads — exactly the pattern ADR-0017 exists to replace.*

11. **Per-user discovery is a contained ADR-0016 deviation, pseudonymous by default. [core]**
    At the owner's explicit direction ("probe everything"), the `software_licensing`
    source probes per-user surfaces and records may carry `user_scope=user` +
    `user_ref`, deviating from ADR-0016's machine-scope/no-PII posture — confined to
    **two fields on this one source**. `user_ref` is a local profile name only (never
    SIDs, emails, or directory identities — and "never SIDs" binds the **HMAC input**
    as well: a record whose profile name cannot be resolved ships with the identifier
    omitted, never a SID or its hash). A named knob controls it:
    **`--license-scan-user-ref=collect|hash|omit`**, **default `hash`** — a per-agent
    keyed pseudonym `HMAC-SHA256(k_agent, profile)` truncated to 16 hex, where `k_agent`
    is a 256-bit CSPRNG key persisted locally and **never transmitted or logged** (not
    an unsalted `sha256/12`, which a low-entropy name like `jsmith` makes trivially
    reversible). `collect` sends the raw name (opt-in); `omit` suppresses the
    *identifier*, not the *probe* (`user_scope` still distinguishes per-user
    discoveries). The per-agent key is a deliberate privacy property with a stated
    capability limit: pseudonyms **do not correlate across devices** (the same human
    on two machines yields two unrelated `user_ref`s), so `hash` mode can never feed
    fleet-wide named-user seat math — the `assigned_vs_purchased` basis stays
    connector-fed at tenant level (Decision 13), and any future cross-device user
    dimension (IdP-anchored identity for named-user metrics, see Direction) is a new
    decision with its own privacy review, never a quiet reuse of `user_ref`.
    GDPR posture stated plainly: a hashed `user_ref` is still personal data
    (Recital 26); erasure is knob-flip to `omit` (full-replaced within one 24 h cycle
    for syncing agents; offline agents purge on reconnect or via decommission) plus the
    **agent-decommission cascade** — the per-store `delete_agent` methods exist today with
    no production caller, so this capability builds the decommission fan-out and registers
    its stores with it. The fan-out covers the **five per-agent stores** (`InventoryStore`,
    `SoftwareInventoryStore`, `AppPerfDailyStore`, `DeviceInventoryStore`,
    `SoftwareLicensingStore`) and removes **only agent-scoped rows/links**;
    `ProductRegistryStore` holds fleet-wide canonical identities shared across agents and
    is **never** in the cascade (decommission drops an agent's match links, never a shared
    canonical product). There is **no row-level erasure API**, a stated gap. The cascade's
    production trigger is `DELETE /api/v1/sle/agents/{id}`, authorized by the scoped
    `SoftwareLicensing:Delete` **AND** `Inventory:Delete` **AND** `GuaranteedState:Delete`
    conjunction (Decision 9) — because this fan-out reaches the `Inventory`-securable
    stores and the `GuaranteedState`-governed `AppPerfDailyStore`, not only the licensing
    one. The effective mode is **centrally verifiable**: the
    stable effective-mode value rides the canonical blob as a config-stable record
    (verifiable fleet-wide from stored state, including for offline agents), while
    flapping surface diagnostics never touch the blob and are fetched live via the
    command path on the `/sle/agents/{id}` drill. Reads that render `user_ref` rows
    (that drill) join the per-open behavioral-audit tier (the `dex.device.view`
    convention: audited per open, fail-closed) and register in the enterprise read
    inventory; the in-server discovery stores and the `user_ref` data class register in
    the enterprise data inventory at implementation time. The **usage source and the M365
    connector do not inherit** this carve-out (both are UCE, Decisions 15/13). Maintainer sign-off on this deviation is
    required. *Rejected: raw-collect default (reversed at review) and unsalted
    `sha256/12` (dictionary-reversible).*

12. **Entitlements — deferred to the SAM UCE module. [UCE]** The entitlement plane joins
    purchased rights to discovered facts, so per Placement under ADR-1005 it is the
    module's, not built in-server. Recorded as module design input: five sources
    (`manual`, `csv`, `graph_m365`, `agent_flexlm`, `agent_kms`) with per-source
    identity/upsert (manual = UUID; csv = external_id/content-hash upsert-by-key; graph =
    `skuId` full-set upsert with soft-retire; flexlm/kms = host-derived keys). The
    load-bearing schema decision the module should honour: a **metric-typed quantity from
    birth** (`metric` ∈ `seat|core|processor|employee|token|unknown` + numeric
    `quantity`), never a bare `purchased_seats` integer — so adding non-seat evaluation is
    later evaluator work, not a breaking migration; a non-seat row is stored/summed with
    verdict `unknown`, never coerced into seats (the Decision 7 honesty rule at the
    schema). Connector/agent writes touch only observed fields and **never clobber
    operator annotations** (`cost_*`, `contract_ref`, `po_ref`, `notes`). The agent-side
    FlexLM/KMS `ent|` records still ride the **core** `software_licensing` blob opaquely
    (Decision 3 forward-compat) — collected as facts; their interpretation is UCE.
    *Rejected: replace-by-import CSV semantics — imports never delete.*

13. **M365 Graph connector + its secret — deferred to the SAM UCE module. [UCE]** The
    tenant-level Graph connector (`subscribedSkus`, `directory/subscriptions` — no
    per-user `licenseDetails` fan-out) is the canonical fleet×external-domain-data join,
    so it is UCE territory and is not built in-server. Consequently **SecretCodec's first
    production wiring does not land under §27** — the module owns its own secret storage
    (design recorded here as its input: a registered `SecretCodec` column, never
    `RuntimeConfigStore`; strict fail-closed boot order register→audit-hook→`init()`;
    encrypt-failure aborts the write, decrypt is fail-closed with no tamper/existence
    oracle) and its SSRF hardening (GUID/verified-domain validation, fixed token/Graph
    hosts, same-origin `@odata.nextLink` only, no redirect following, bounded
    size/timeout). The **Decision-13 KEK-operator-surface deferral (#1921) therefore no
    longer bears on this ADR**. The pre-existing `oidc_client_secret` plaintext gap is
    neither extended nor touched (separately tracked: #1922).

14. **CSV entitlement ingest — deferred to the SAM UCE module. [UCE]** Entitlement-plane
    ingestion. Recorded as module design input: one shared pure `csv_import` parser
    (RFC-4180 quoting/CRLF/BOM, case-insensitive header mapping, line-numbered errors)
    backing both a GUI upload and a REST raw `text/csv` endpoint, **upsert-by-key**
    (imports never delete — deletion is explicit), a **mandatory dry-run** (full
    validation, zero writes, default-ON), and hard caps (1 MiB, 10 000 rows, ≤100
    errors). Entitlement writes nudge the evaluator so the dry-run → import → verify loop
    is coherent.

15. **Usage metering and reclamation — deferred to the SAM UCE module. [UCE]** The
    reclamation verdicts (categories, candidates, coverage) join usage with entitlement
    data for a purpose, so they are UCE interpretation. The **usage collection** half — an
    opt-in (`--usage-sync-enable`, default off) machine-scope daily-sync source reading
    the agent's TAR warehouse locally through the plugin's sandboxed read-only `sql`
    action, user dimension dropped on-device — is agent-side fact collection and, if/when
    it ships, ships in-server as **mechanism only**; it is out of §27 v1. Recorded as
    module design input: usage **categories** (Used ≤30 d, Rarely 31–90 d, Unused >90 d,
    **Unreported** = no data) are policy-computed at read time so a threshold change never
    forces re-sync and **reclamation never fires on missing data**; reclamation surfaces
    lead with usage coverage and render zero coverage as explicit guidance, never as
    "nothing to reclaim". **Product tags on `ProductRegistryStore` stay core** (they drive
    tag-based views and time-boxed management-group rules). *Rejected: routing
    licence/usage data through TAR as a transport — usage reads TAR locally and pushes via
    daily-sync.*

16. **Out of scope.** Yuzu's own product-licence machinery (`LicenseStore`, the
    `License` securable, §22.3) is untouched. Per-user Graph `licenseDetails` fan-out is
    excluded (tenant-level seat math suffices). Probabilistic/fuzzy catalog matching is
    excluded in v1 (Decision 6). MFA step-up on §27 endpoints is excluded (Decision 9).
    Explicit source **precedence** for double-counted seats is excluded — the per-source
    breakdown is shown, not resolved, and explicit precedence can layer on later.
    Exclusions that are *out of v1 but inside the capability's aim* — non-seat metric
    evaluation, product use rights, catalog content operations, SaaS discovery
    breadth, closed-loop reclamation, audit-evidence export — are recorded with their
    rationale and layering seams in the **Direction** section below, so the v1
    boundary is a stated waypoint, not a silent ceiling.

## Example: discovered-licence data

*Illustrative — field names indicate the Decision 2/3 record shape, not a frozen wire
contract; `license_type`/`status`/`source`/`confidence` are closed, unknown-preserving
vocabularies.*

**What `license_scan` produces (agent-side, Decision 2).** Each surface emits
strict-sanitised records; the `list` action yields, e.g.:

```jsonc
// Windows OS licence from WMI SoftwareLicensingProduct — machine-scope, vendor API
{
  "kind": "lic", "product": "Windows 11 Pro", "publisher": "Microsoft",
  "license_type": "volume_kms", "status": "licensed", "channel": "KMS",
  "expires_at": "2026-10-14",      // KMS grace resolved to an absolute UTC date, never a ticking countdown
  "confidence": "authoritative",    // from an OS licensing API
  "source": "win_slp",
  "key_hint": "…-…-…-…-6TCXB",      // OS-provided partial only; full key never persisted or transmitted
  "user_scope": "machine", "exe_hints": []
}

// Per-user Autodesk licence from an offline NTUSER.DAT hive — pseudonymous by default
{
  "kind": "lic", "product": "AutoCAD 2025", "publisher": "Autodesk",
  "license_type": "subscription_named_user", "status": "active", "expires_at": "2026-03-31",
  "confidence": "probable",         // heuristic registry parse, not a vendor API
  "source": "user_hive", "user_scope": "user",
  "user_ref": "a3f9c1d47e0b8c21",   // HMAC-SHA256(k_agent, profile) truncated to 16 hex — never a SID/email; k_agent never leaves the device
  "exe_hints": ["acad.exe"]
}

// Oracle JDK via an ISO 19770-2 SWID tag — the audit-relevant probe. NB: the
// swidtag surface is the D-2 fast-follow (#2112), not emitted by the shipped v1
// plugin; #2112 also extends the closed vocabularies this record needs — `source:
// swidtag` and the Decision-12 metric-typed `license_type` here (`per_employee`) —
// in BOTH validators (plugin kSources/kLicenseTypes + the server ingest's).
{
  "kind": "lic", "product": "Oracle JDK 17", "publisher": "Oracle",
  "license_type": "per_employee", "status": "installed",
  "confidence": "authoritative",    // parsed vendor SWID artefact
  "source": "swidtag", "user_scope": "machine", "exe_hints": ["java.exe"]
}
```

**On the wire (Decision 3).** Records are sorted, deduped, and delimiter-joined into one
canonical blob (each line prefixed by kind, e.g. `lic|…`), which is SHA-256'd and rides
`InventoryReport.plugin_data` as opaque `map<string,bytes>` — no proto change. The blob
holds only facts that change with discovered state (no collection timestamps), so a
stable estate hash-skips day to day; unrecognised record kinds (e.g. future `ent|`
entitlement records, Decision 12) are skipped by both parser and seam, so mixed-version
fleets never loop.

**What gets stored (Decision 4).** The server recomputes the hash over the raw bytes,
resolves each raw name to one `ProductRegistry` product via the deterministic
`product_normalize` matcher (Decision 6), and upserts the raw row into
`SoftwareLicensingStore.agent_licenses`:

| agent_id | product_id | raw_product | license_type | status | expires_at | confidence | source | key_hint | user_scope | user_ref | last_seen |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `a91f…` | `prod_win11pro` | Windows 11 Pro | volume_kms | licensed | 2026-10-14 | authoritative | win_slp | `…6TCXB` | machine | — | 2026-07-12 |
| `a91f…` | `prod_autocad25` | AutoCAD 2025 | subscription_named_user | active | 2026-03-31 | probable | user_hive | — | user | `a3f9c1d47e0b8c21` | 2026-07-12 |

These raw rows are the **in-server core** discovery state. The SAM UCE module reads them
over `/api/v1/sle/*` to derive effective state, match against entitlements, and compute
the posture rollups — none of which is stored in-server (Placement under ADR-1005).

## Direction — the target state this v1 is the foundation for

The aim of this capability is a **first-class software licensing & entitlement
product measured against the leading commercial SAM suites** (deliberately unnamed,
per the parity plan's convention), not a checkbox feature. Four industry through-lines
(2024–2026) shape the ladder: licence metrics are **decoupling from device installs**
(per-employee, named-user, per-core, consumption credits); the **audit climate is the
buying trigger** (a majority of estates audited annually, with the sharpest activity
on Java, virtualization, and the largest desktop/datacenter publishers); analysts attribute the SAM tool
market's stagnation to **data-quality disappointment** — which makes Decision 7's
honesty commitments this product's wedge, not a nicety; and SAM, SaaS management, and
FinOps are **converging into one spend-and-compliance discipline**. Each item below
names the v1 seam it layers onto. These are recorded aims with rationale — each
becomes its own decision (ADR or issue) when picked up, and none licenses scope creep
into the v1 slices.

- **Non-seat metric evaluation** — the evaluator ladder over Decision 12's
  metric-typed schema: `core`/`processor` first (joins the hardware facts the
  inventory planes already collect; datacenter sub-capacity additionally needs a
  VM→host topology answer), then `employee` (an operator-supplied headcount input —
  the Java-style metric is an HR number, not an endpoint fact), then `token`
  consumption with burn-down. Schema work: none — that is what Decision 12 bought.
- **Product use rights** — downgrade, second-use, licence-mobility, virtualization
  and DR rights applied as curated content at evaluation time (registry + evaluator
  seam). Until this lands, verdicts on enterprise-agreement estates are conservative
  approximations and SLE surfaces must present them as such — the leading suites
  carry use-rights libraries at ~10⁶ scale, and this is the largest single gap
  between v1 math and a defensible enterprise ELP.
- **Catalog content operations** — the commercial moat is curated content (millions
  of products/SKUs, daily updates), not matching algorithms. Decision 6's alias layer
  (`method` + `confidence`) is the import seam: shareable curation packs, alias
  feeds, and SKU→product mappings (which also upgrade CSV/PO ingestion from
  product-key matching to purchase-order automation) layer on without redesign.
- **SaaS connector breadth and shadow-SaaS discovery** — further connectors under
  Decision 12's per-source identity pattern, and **SSO/IdP sign-in-log discovery**
  as a new source class (the discovery method the SaaS-management market
  standardised on). The analyst category has folded SaaS management into SAM;
  tenant-level M365 is the correct v1 anchor, not the destination.
- **An IdP-anchored user dimension for named-user metrics** — Decision 11's
  per-agent pseudonyms deliberately cannot correlate across devices, so fleet-wide
  named-user math requires a directory-sourced identity plane. Explicitly a future
  decision with its own security-guardian design review and data-processor posture;
  never a quiet extension of `user_ref`.
- **Licence-server live usage and denials** — v1 reads FlexLM `.lic` statics;
  the engineering-software segment expects checkout/denial telemetry (FlexLM-class,
  then RLM/Sentinel) feeding `inuse_vs_total` — denial events are the renegotiation
  evidence buyers act on. Extends the `agent_*` entitlement sources and the usage
  plane; no new transport.
- **EOL/EOS and vulnerability correlation** — end-of-support dates and advisory
  joins on `ProductRegistryStore` rows, converging with the vulnerability-scan
  engine design (PR #1206) rather than duplicating it. The converged
  asset-intelligence category treats this as table stakes; the registry is the
  natural join point.
- **Closed-loop reclamation** — the structural beat: incumbent suites *integrate
  outward* to third-party deployment tools to act on reclamation candidates; Yuzu
  **is** the execution plane. Candidates feed the existing instruction/approval
  machinery (operator-gated, preflight-checked) to uninstall or downgrade — and
  `prohibited` product tags (§27.4) become Guardian-enforceable policy, which no
  standalone SAM product can do. v1's stop-at-candidates scope is deliberate
  sequencing, not the end state.
- **Audit-evidence export** — a signed, timestamped licence-position snapshot with
  its evidence chain (discovery records, entitlement provenance, evaluator inputs),
  built on the existing audit-log machinery. The audit climate makes "regenerate
  what we told the auditor, as of that date" a first-class artefact.
- **FinOps alignment** — cost rollups over the `cost_*` annotations and a
  FOCUS-format export so licence spend joins cloud spend in the customer's existing
  FinOps tooling, following the SAM/FinOps convergence rather than building a
  parallel cost product.

Sequencing signal (not a commitment): the metric ladder and use rights are what
unblock enterprise datacenter estates; closed-loop reclamation and Guardian
enforcement are where Yuzu beats rather than meets. The agentic surface is honoured
from day one — the in-server discovery reads ship with their MCP twin
(`query_software_licenses`, Decision 9) per ADR-1005 Decision 1, and the compliance MCP
(`get_license_compliance_summary`) lands with the module — parity the incumbents are
still retrofitting.

## Consequences

- **In-server (§27 v1) answers the discovery questions** per asset and fleet-wide: what
  software licences exist, their types and channels. **The SAM UCE module answers the
  interpretation questions** — what has lapsed, what expires or renews within N days
  (with notifications), how purchases compare with deployment, and what paid software is
  going unused — reading the in-server discovery surface over the versioned
  `/api/v1/sle/*` API.
- Licence discovery (in-server) has **no manual path**; the entitlement plane (UCE) does
  (form, CSV, connector, agent-derived records). The two planes stay distinct so
  discovered "truth on the endpoint" is never hand-edited, and purchased-vs-deployed math
  is claimed only where entitlement data exists — discovered-only products stay honestly
  `unentitled`.
- The module's honesty commitments are its acceptance criteria: multi-source seat sums
  keep the per-source breakdown visible; unknown quantities are `NULL`, not a fabricated
  zero; absent usage is *Unreported*, never *Unused*; entitlement quantities are
  metric-typed from schema birth, so the market's shift off device-install metrics lands
  as evaluator work, never a breaking migration of the module's central table.
- **Two** born-on-Postgres **discovery** stores join the ladder in-server
  (`ProductRegistryStore`, the raw `SoftwareLicensingStore`); the server refuses to boot
  if their migrations fail, consistent with the substrate posture. The entitlement and
  usage stores are the UCE module's, not built here.
- The in-server SLE nav entry (the Licences discovery view) costs edits to the
  hand-duplicated nav copies (accepted at owner direction), with the long-standing nav
  drift reconciled rather than extended; the UCE host owns navigation for the deferred
  surfaces.
- The per-user carve-out (Decision 11) is a deliberate, contained ADR-0016 deviation
  requiring maintainer sign-off. Default posture is **pseudonymous** (keyed-HMAC); raw
  profile names are opt-in and full suppression of the identifier is one flag. A hashed
  `user_ref` is still personal data, and there is no row-level erasure API — both stated,
  not hidden. The agent-decommission cascade that completes the erasure story is built by
  this capability (it does not exist today) and is in-server core.
- The M365 connector and therefore **SecretCodec's first production wiring move to the
  SAM UCE module**; §27 carries no SecretCodec wiring, so the ADR-0010
  KEK-operator-surface deferral (#1921) no longer bears on this ADR. The legacy
  `oidc_client_secret` plaintext gap remains separately tracked (#1922) and is not
  extended.
- Fleet network cost is negligible: licence discovery blobs hash-skip on stable estates
  (the usage and Graph syncs belong to the deferred surfaces).

## Ratification

Acceptance of this ADR carries two explicit sign-offs beyond the design itself:
(1) the **Decision 11 deviation** from ADR-0016's machine-scope/no-PII posture
(per-user licence probing, pseudonymous by default, contained to two fields on one
source); (2) the **ADR-1005 placement re-scope** (see "Placement under ADR-1005") — a
maintainer ruling that §27's discovery mechanism is server-resident core while its
interpretation half (compliance evaluation, entitlements, the M365 connector, usage
reclamation, and the compliance UI/MCP surfaces) is deferred to the SAM
use-case-engine module. The **Decision 13 KEK deferral (#1921)** no longer needs
sign-off here: with the M365 connector re-scoped to the UCE module, §27 carries no
SecretCodec wiring.
