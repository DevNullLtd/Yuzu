---
status: accepted
date: 2026-07-06
owner: Dave Rae
deciders: Nathan Dornbrook (project owner), 2026-09-07; independent review of record: enterprise-architect adjudication 2026-09-07 + the approving review on the ADR-reconciliation PR (docs/agents/domain.md ADR Acceptance Convention); tracking issue #4099
scope: platform — consumer model, principal classes, UI/API boundary, use-case engine direction
---

# 1005 — Yuzu Server is a Headless Platform; Use-Cases Live in External Engines

Strengthens (does not supersede) `docs/agentic-first-principle.md`: A1's dashboard-parity invariant is hardened here to "UIs may only compose public APIs" for new capabilities. A1's existing scope clause ("existing fragments are not retroactively required to comply") remains in force via the grandfather rules below.

Related: ADR-0021 (Spark/Reflex architecture), ADR-0023 (in-server vulnerability correlation engine) + ADR-4001 (in-server vulnerability dashboard) (both absorbed into grandfathered surface #2, see below), ADR-0017 (management-group confinement of list reads), ADR-0006/0008/0012 (Postgres substrate and store contract), `docs/agentic-first-principle.md` (A1–A5), `docs/auth-architecture.md`, `docs/mcp-server.md`. See also: the [execution plan](../adr-1005-execution-plan.md) (program ladder + first-module scoping).

## Binding status

Nothing in this ADR binds reviews or blocks PRs until its status is **accepted**. (Exception-ledger entries may be recorded before acceptance — voluntary early compliance by implementing PRs; they become binding precedent only on acceptance.) On acceptance, Decisions 1–4 **and the Interim rules** bind — the Decisions prospectively (they govern new and changed capabilities from the acceptance date and do not retroactively condemn the grandfathered surfaces inventoried below), the Interim rules immediately and until their named follow-ups ship. Decisions 5–7 describe direction whose remaining binding force arrives with those follow-ups.

## Context

Yuzu's goal is use-case-agnostic scaffolding for an IT estate: highly performant primitives for query, command, detection, enforcement, and inventory across a fleet. The Spark/Reflex rebuild (ADR-0021) is already re-founding the detection/action kernel on use-case-agnostic terms.

Customers, however, expect a GUI and pre-packaged use-cases (vulnerability management, compliance reporting, software asset management, …). Building those into the server would pull domain semantics — vulnerability feeds, CVE matching, scoring, domain dashboards — into the C++ core, coupling its release cadence to interpretation logic that churns on a different clock, and privileging our own UI over the agentic workers the platform is designed for.

The agentic-first principle (A1: dashboard parity) already requires every dashboard capability to have an API twin. This ADR takes the next step: the server is *headless by design*, and every consumer — including our own UI — is an external client of the same versioned surface.

## Terminology

- **Engine principal** — a long-lived service principal representing an external consumer (a use-case engine or an agentic worker acting as a service). Always written "engine principal", never bare "engine": *engine* alone is already load-bearing in this codebase for internal components (Instruction Engine, Policy Engine, Scope Engine, SparkEngine, …).
- **Use-case engine host** — the first-party deployable that hosts use-case modules (Decision 6). The host authenticates to the server as one or more engine principals; whether modules share one principal or hold per-module principals (least-privilege and audit-attribution granularity) is decided in the delegation follow-up, not here.
- **First-party UI** — collectively, the use-case engine host's UI (Decision 6) and the in-server admin console (Decision 7).
- **Operator** — the initiating principal of an action, human or agentic. Where a rule applies only to humans, this ADR says "human operator".
- **Admin console** — the thin in-server surface of Decision 7. Distinct from the existing full dashboard, which is a grandfathered surface.

## Decision

### 1. Agentic first is a core principle

The server is designed to be driven by agentic AI as a first-class operator — MCP and REST are the primary control surfaces, not an integration afterthought. Every capability must be **discoverable, invocable, and observable** by an agentic worker without human mediation, with honest machine-readable error envelopes. This elevates the existing agentic-first invariants (A1–A4) from a per-surface checklist to a founding principle: humans with a GUI and agentic workers are peer classes of operator, and no capability may favour one over the other. New capabilities land on **both REST and MCP** or carry a recorded exception — a capability reachable on only one machine surface is a defect under this decision, not merely under A1.

### 2. The Yuzu server is a headless, use-case-agnostic platform

The server owns **mechanism, not interpretation**: device registry and transport, instruction/Spark/Reflex engines, scope, RBAC, audit, response and inventory stores, content plane, and the REST/MCP/event surfaces that expose them. It is *moving toward* containing no use-case domain logic — CVE analysis, compliance-framework semantics, and domain-specific scoring are being extracted over time, not asserted absent today (see Grandfathered surfaces and Consequences).

**Boundary test** for any proposed feature: *does it collect/enforce/transport facts about the estate (mechanism → core), or does it interpret those facts for a purpose (interpretation → use-case engine)?*

**Tiebreakers.** Interpretation whose semantics are **operator-authored content evaluated by a generic engine** (policy rules, preflight checks, scope expressions, Guards, Reflexes), and **pure aggregation of fleet-internal facts** (rollups, histograms, distinct-device counts), are *mechanism*. Interpretation whose semantics are **baked into code** (domain scoring, compliance-framework mappings) or that **joins fleet data with external domain data** (vulnerability feeds, threat intel) is *engine territory* — this classifies PolicyEvaluator, the `/auto` preflight/deploy engines, scope walking, and the DEX/software-catalogue rollups as core, matching ADR-0021. Infrastructure-supporting external fetches (NTP, CRL, OS-EOL metadata) are not "domain data". First-party-shipped content (build-time-embedded YAML) is judged by its **semantics**, not its packaging — a compliance-framework mapping does not become mechanism by shipping as bundled content. Boundary disputes are arbitrated by the maintainer; verdicts accrete into an examples appendix in this file.

### 3. All consumers are external principals on the versioned API

Use-case engines, agentic AI workers, automation scripts, and Yuzu's own first-party UI all consume the server through the same versioned REST/MCP surface, as authenticated principals subject to server-side authorization — **MCP tier policy and RBAC in the existing tier-before-RBAC order** (`docs/mcp-server.md`), kill switches included; engine principals get no exemption — plus audit and (future) rate limits. No consumer — first-party included — gets a **new** private seam: no shared database access, no co-deployment assumption, no linked-in shortcut. (The existing dashboard's in-process store access is a grandfathered surface, not a licence — see below.)

A customer may point their own use-case engine, or their own agentic AI, at the server. Our first-party UI must therefore prove the API surface is complete: **if our UI needs a capability, it becomes an API first.**

### 4. No UI-only capabilities

From acceptance, prospectively: no **new or changed** capability may be reachable only through a UI. Every capability's twin must be **machine-readable** — a versioned REST/MCP surface with A2 discoverability and the A4 error envelope. An HTML fragment endpoint is itself UI and does **not** satisfy this rule, even though it is public HTTP. This strengthens A1 from "dashboard capabilities must have API twins" to "UIs may only compose public APIs" for new work; grandfathered surfaces are governed by the inventory below, and modifying one in place is maintenance, not a violation — but the capability *added* in such a modification is new work.

### 5. Consumer trust tier: engine principals with on-behalf-of delegation

The principal model adds **engine principals** alongside human operators and agent daemons. This is an evolution of today's service-scoped API tokens (`docs/auth-architecture.md`), not a parallel invention: the genuinely new element is **on-behalf-of delegation**, not the existence of a service principal.

- Engine principals authenticate with their own credentials and carry their own RBAC grants, assigned least-privilege — an engine principal holding the union of its users' permissions is a design defect.
- **Delegation is server-verifiable.** When an engine principal acts on a specific operator's initiative, the delegated identity must be established by a server-issued artifact (token exchange or equivalent) — never by an engine-asserted header or field. Any action serving a specific operator's request MUST be performed as delegated; autonomous mode is for engine-scheduled work only. A confused-deputy engine principal must not be able to launder an operator-initiated action through its own broader grants.
- **Effective authority for delegated actions = intersection of permissions AND scope.** Management-group confinement (ADR-0017) applies: delegated list/fan-out reads pass through the same `authorize_list_read` chokepoint the operator would hit directly. A globally-granted engine acting for a group-confined operator reaches only that operator's groups.
- **Audit shape.** Every engine-principal action produces an audit row carrying: the engine principal id; an explicit `is_delegated` boolean (never a nullable operator field overloaded as "autonomous"); for delegated actions, the delegated operator identity, the delegation artifact id, and a per-row `delegation_verification_status` (`verified` / `unverified` / `failed`). Autonomous actions audit as the engine alone.
- The server's authorization (tier policy ∩ RBAC) remains the **single authority** over fleet actions. Engine-side checks may only *further restrict*, never substitute for, server authorization. Data an engine syncs and re-serves leaves the server's audit perimeter and requires the engine's own audit/compliance controls; **bulk sync of behavioral PII requires explicit security-guardian design review**, and any engine principal consuming DEX or other behavioral-PII endpoints inherits the full works-council control set (toggles, pseudonymization, retention, per-read audit — `docs/enterprise-readiness-soc2-first-customer.md` §3.5, once those controls are built) with no exception for machine consumers.
- **Credentials.** Engine credentials reuse the existing hashed API-token store unless a review concludes otherwise; each engine principal has a named responsible human owner for revocation; credentials are rotatable and individually revocable; engine↔server transport is TLS-mandatory, mTLS recommended. Lifetime/rotation ceilings are set in the auth follow-up. The #397/#403 self-target destruction guard must be extended to the effective delegated identity.

The concrete token/delegation mechanism is deferred to an auth-architecture follow-up; this ADR fixes the requirements and the audit shape.

### 6. First-party use-case engine: one host, many modules

Yuzu's own GUI/use-case product is a single **use-case engine host** (auth delegation, server-sync plumbing, UI shell) hosting use-cases as modules.

> **AMENDED by ADR-0031 (accepted 2026-07-14): the engine host has NO UI shell.** It is a headless capability provider — no UI, no machine surface of its own. Presentation is a separate binary owned by the platform; engine Use Cases register into core's capability catalogue and are consumed through the one public surface (REST + MCP + dashboard). The rest of this decision — one host, many modules — stands. Decision 7's break-glass console survives and re-homes: ADR-0031 Decision 6a gives core its own minimal break-glass ingress, so a presentation failure cannot lock operators out during an incident.
 Separate apps per use-case would reinvent that plumbing each time. "One host" is a product-packaging default only — it does not pre-decide principal granularity (see Terminology) or preclude later decomposition. The host's technology stack, internals, and delivery are out of scope and decided when the first module is scoped.

The expected first module is vulnerability management (external vulnerability-feed ingest joined against Yuzu software inventory) — the concrete choice lives in `docs/roadmap.md`, not here. Note this module *re-homes* already-shipped **server-side** capability (the NVD sync + CVE matching — see Grandfathered surfaces); the agent-side `vuln_scan` collection plugin is mechanism and stays core. Scoping the first module MUST include the egress-primitive decision (how engines read fleet data at scale); its server-facing half (bulk reads, engine auth) is gated on the auth follow-up and that egress decision — only its domain-logic half can start immediately.

### 7. Thin built-in admin console remains on the server

Headless does not mean zero UI. The server keeps a **minimal admin console** for platform operations — the bootstrap/break-glass set: enrollment and device liveness, health/readiness, RBAC and principal management, settings, audit view. **This list is closed**: adding a console surface requires amending this ADR. The console (target state) composes the same public APIs — a posture note: HTML surfaces moving onto REST flip their behavioural-PII audit posture from set-and-proceed to fail-closed (`server/core/src/rest_audit.hpp`); this flip is intended. The admin console, `/readyz`, and `/metrics` must function with **zero dependency on any engine being reachable**.

The existing full dashboard remains in place, maintained, and **fully supported for customers through any transition — no forced migration**. This ADR schedules no migration, but the direction is decided: the product UI's long-term home is the use-case engine, and the in-server dashboard shrinks toward the thin admin console (strangler, not big-bang). **Removal of an in-server dashboard surface is a breaking change requiring a full deprecation cycle once any customer depends on it** — no page disappears without notice, regardless of engine-migration progress. Content-plane authoring UI (Guards, Baselines, Reflexes, routes) is platform administration: its API is core (ADR-0021 D7); whether its UI's long-term home is the admin console or the engine host is decided with the migration plan.

## Grandfathered surfaces

The binding rules above are prospective. Pre-existing surfaces that do not comply are grandfathered — inventoried here so governance reviews have a citable list rather than a judgment call:

1. **The in-server dashboard's in-process store access** (`*_ui.cpp`, `/fragments/*`). Grandfathered until the strangler migration reaches each surface. No NEW private seam may be added; new capability on a grandfathered surface must be API-first (Decision 4).
2. **Server-side NVD sync + CVE matching** (capability-map 9.4, shipped). In-server interpretation by Decision 2's test; grandfathered until re-homed into the first use-case module. The agent-side `vuln_scan` collection plugin is mechanism (Decision 2) and is NOT grandfathered — it stays core. Roadmap phases 18.1 (CVE lifecycle store), 18.2 (auditor-ready compliance bundles), and 18.5 (SBOM CVE linkage) are **boundary-affected**: on acceptance they must be re-evaluated against Decision 2 before implementation. **Extended 2026-07-07:** the ADR-0023 in-server correlation stack (the shipped `NvdDatabase::assess()` and `VulnFindingStore`, and the `VulnCorrelationEngine` + triggers + `Vulnerability:Scan` securable + findings routes that ADR planned — 18.1-flavoured work authored in parallel with this ADR) is **absorbed into this same grandfathered surface**: interim capability, re-homed and deleted by the same strangler sequence. The absorption is **bounded**: it covers ADR-0023's designed scope only (vuln-roadmap M1a/M1b) and it is **placement-only** — Decision 4 (API-first), full governance, ADR-0017 confinement, and ADR-0023's own securable/audit obligations apply to every further in-server vuln PR undiminished. Anything not in this enumeration is **outside the grandfather by default**, classified in governance review, not by the proposing document; for the absorbed M1a/M1b scope the 18.1 re-evaluation above is discharged by this reconciliation, while 18.1-and-beyond work outside that scope still re-evaluates against Decision 2. **Further extended 2026-07-08 — a prospective carve-out, not grandfathering of existing code:** the ADR-4001 vulnerability dashboard (the `/vuln` lens with its `/fragments/vuln/*` surface, the versioned `/api/v1/vuln/*` REST + `query_vulnerabilities` MCP read twins, the `Vulnerability` securable, and the in-server `attack_path_engine`) is absorbed on the same terms — placement-only, bounded to ADR-4001's designed scope, outside-by-default beyond it. Unlike the 0023 extension's shipped components, **every ADR-4001 item is planned/design-only** (ADR-4001 carries `status: accepted` as of 2026-07-09 per the ADR Acceptance Convention, but none of its surfaces exist in code): this section's "pre-existing surfaces" framing does not apply to them — the carve-out pre-authorizes their *future* in-server implementation, activates as each surface ships, and is void for anything ADR-4001's ratification does not carry. Two riders: (a) unlike the legacy un-versioned `/api/nvd/*` routes, 4001's read surfaces are on the **published versioned API contract from birth**, so their Phase-7 re-home requires the full Phase 0.3 deprecation cycle with module-provided equivalents; (b) ADR-4002's scoring substrate is **not** absorbed here — it faces its own Decision 2 boundary review at its own merge. Reconciliation record: execution plan § "Relationship to ADR-0023 and ADR-4001".
3. Exceptions recorded here accrete into the "exception ledger" the standing review question refers to:
   - **2026-07-07 (Phase 1 implementation, pre-acceptance — see Binding status above for the pre-acceptance meaning):** the four HTTP liveness/readiness probe paths (`/livez`, `/readyz`, `/health`, `/api/health`) are **exempt from the Interim-rules on-behalf-of rejection**. Rationale (governance Gate 5, CH-3/UP-5): a mesh/SSO proxy that stamps a reserved header on every request must not be able to 403 the probes and crash-loop the pod — a probe performs no identity-bearing action, nothing consumes the header on that path, and a bricked orchestrator would hide the very misconfiguration the guard exists to surface. Every other path rejects. The set is **closed and exact-match** (`req.path ==` equality — `/health/detailed` or a trailing-slash variant does NOT inherit the exemption); any additional exempt path requires its own ledger entry with its own no-identity-bearing-action justification. Implementation **ships with the Phase-1 implementation PR (#1972)** — the pre-routing chokepoint in `server/core/src/server.cpp` plus the "On-behalf-of assertions rejected" section of `docs/auth-architecture.md`; this entry is recorded ahead of that merge as the exception's review trail, and the cross-references resolve once #1972 lands.

   - **2026-07-14 — class-level entry: Prometheus fleet-gauge families are
     observability, not capability (spark rung 1; retroactively covering
     `yuzu_fleet_net_*`, `yuzu_fleet_perf_*`, `yuzu_fleet_dex_*`).** New
     `yuzu_fleet_*` gauge families surfaced ONLY via `/metrics` carry no
     REST/MCP twin obligation: `/metrics` is a recognized platform machine
     surface (see "Platform surfaces" above), the families are machine-readable
     and enumerable by scrape, and no dashboard fragment ships alongside them —
     so there is no UI-only asymmetry to correct. The twin obligation ATTACHES
     when an operator-facing feature (a dashboard lens, a query surface, an
     automation hook) is built OVER the same data — at that point Decision 1/4
     applies in full to that feature. Recorded class-level so each future
     gauge-family PR cites this entry instead of relitigating (governance
     Gate-3 architect, spark rung-1 re-land).

   - **2026-09-07 — class-level entry: a compiled-in specification surfaced as
     REST route + MCP resource, with no MCP tool, satisfies the twin.** The
     plugin documentation manifests (`GET /api/v1/discover/plugin-docs` and
     `yuzu://plugin-docs`, byte-identical, `docs/plugin-readme-standard.md`
     rule 10) follow the 2g PR4 specs-as-resources shape: the resource is
     enumerable through `resources/list`, gated tier-then-permission like
     its REST twin, and the tool-level entry point is the `docs` summary
     `discover_plugins` already carries. Decision 4 asks for REST and MCP;
     a resource IS the MCP surface for static content. Recorded class-level
     so the next compiled-in catalog cites this entry (governance Gate-3
     architect + Gate-4 consistency-auditor, PR D.1 of the plugin docs
     programme). **Addendum, 2026-09-14 (#4108):** this entry extends
     verbatim to a compiled-in specification surfaced as a REST route + an
     MCP **resource template** (`resources/templates/list`), not only a
     static resource — `GET /api/v1/discover/plugin-docs/{name}` and
     `yuzu://plugin-docs/{name}` satisfy the twin the same way, enumerable
     via `resources/templates/list` in place of `resources/list`. Recorded
     as an addendum rather than a new entry because the underlying
     rationale (compiled-in content, tier-then-permission gated, the same
     `discover_plugins` tool-level entry point) is identical; only the
     listing method differs (governance Gate-4 consistency-auditor).

   - **2026-07-08 — SCIM v2 provisioning (`/scim/v2/*`, PR #2018).** REST-only,
     no MCP twin, and absent from route discovery (A2/A3) — a "no" on
     Decision 1/4's twin-surface requirement. Recorded rather than fixed
     pre-merge because:
     - **No MCP twin — tracked follow-up, not a permanent exception.**
       Operator-side user lifecycle (list/deactivate/reactivate a
       SCIM-provisioned account) is a plausible MCP tool, but SCIM's own
       wire protocol (RFC 7644) is IdP-driven push, not an operator-invoked
       action — the *twin* to build is an MCP-shaped view/administration
       surface over the same underlying accounts, not a literal SCIM-over-MCP
       mirror. Scoping and building that twin is out of scope for this slice;
       tracked as **#2021** (SCIM Groups→role mapping, slice 2 — the natural
       place to add an MCP-visible administration surface alongside it) and
       **#2022** (API-token revocation on deprovision, which also touches the
       same account-lifecycle surface). Until one of those lands with an MCP
       twin, this row stands as the open exception.
     - **RFC 7644 `scim+json` error schema instead of the A4 envelope —
       correct by mandate, not a gap.** SCIM is a standardized protocol
       consumed by third-party IdP connectors (Okta, Entra ID, OneLogin) that
       parse `urn:ietf:params:scim:api:messages:2.0:Error` bodies and
       specific `scim_type` values; returning an A4 envelope instead would
       break every conformant connector's error handling. This is a
       deliberate, permanent exception for this surface — SCIM is the one
       place in the API where an external RFC, not Yuzu's own convention,
       owns the wire shape.
     - **Path shape `/scim/v2/*`, not `/api/v1/...` — RFC-mandated, permanent
       exception.** RFC 7644 §3.2 fixes the SCIM base-path convention that
       IdP connector wizards auto-discover against; nesting it under
       `/api/v1/` would not be a conformant SCIM endpoint. Versioning for
       this surface instead rides SCIM's own schema/discovery mechanism
       (`ServiceProviderConfig`/`ResourceTypes`/`Schemas`).
     - Full design/threat-model record:
       `docs/security-reviews/scim-provisioning-2026-07-08.md`;
       operator-facing behavior: `docs/user-manual/scim-provisioning.md`;
       wire reference: `docs/user-manual/rest-api.md#scim-v2-provisioning`.

   - **2026-07-13 — SLE agent-decommission erasure
     (`DELETE /api/v1/sle/agents/{id}`, PR #1950).** REST-only, no MCP twin —
     a "no" on Decision 1's both-surfaces requirement. Recorded rather than
     fixed pre-merge because:
     - **The agentic surface is withheld deliberately, not overlooked.** The
       route is an irreversible per-device purge: it fans `delete_agent`
       across the five registered per-agent stores, erasing the device's
       inventory, installed-software, device-CI, app-perf and
       detected-licence rows, including the
       ADR-0024 Decision-11 pseudonymous `user_ref` personal data (this is
       the wired GDPR Art. 17 whole-device erasure path). Publishing a
       fleet-data destructor as an MCP tool hands an autonomous worker a
       one-call, unrecoverable data-loss primitive. The twin is withheld
       until an MCP destructive-operation gate exists (human confirmation /
       tier ceiling) that makes a guarded twin safe. Tracked as **#2102**;
       **revisit by 2027-01-13**.
     - **Scoped to the destructive verb only — the capability's read half
       has its twin from day one.** `GET /api/v1/sle/agents/{id}` ships
       alongside the MCP twin `query_software_licenses` (ADR-0024
       Decision 9), so SLE *discovery* is fully reachable on both surfaces.
       Only the erasure verb is REST-only; this is not a capability-wide
       twin gap.
     - **The exception relaxes no control.** The REST route keeps the
       per-device-scoped `SoftwareLicensing:Delete` **and** `Inventory:Delete`
       **and** `GuaranteedState:Delete` conjunction (the cascade erases through
       all three securables, so it authorizes for all three),
       audit-before-erase that **fails closed** (an
       attempt row that cannot persist means no erasure — an unaudited
       erasure would destroy its own evidence), and truthful per-store
       committed-delete status (a rolled-back store reports `Failed` → 500,
       never a false `decommissioned:true`).
     - Design record: `docs/adr/0024-software-licensing-entitlements.md`
       (Decisions 9 and 11); operator-facing behavior:
       `docs/user-manual/software-licensing.md`; wire reference: the
       OpenAPI document (`/sle/agents/{agent_id}`).

   - **2026-08-15 — upload-grant agent session routes (`POST
     /api/v1/uploads`, `PUT .../{upload_id}/chunk`, `GET .../{upload_id}`,
     `POST .../{upload_id}/commit`, `DELETE .../{upload_id}`, PR #3135, CC-06
     authenticated chunked-receive protocol / ADR-3004).** REST-only, no MCP
     twin — a "no" on Decision 1's both-surfaces requirement. Recorded as a
     **permanent** exception, not a tracked follow-up, because:
     - **The gap is structural, not an oversight.** These five routes
       authenticate on a grant/session BEARER CREDENTIAL
       (`X-Yuzu-Upload-Grant` / `X-Yuzu-Upload-Session`) minted by
       `mint_upload_grant`, never an operator session — but every MCP tool
       call authenticates as an OPERATOR (`auth_fn`/`perm_fn`,
       `tier_allows`/`requires_approval`). There is no operator identity to
       authenticate an MCP call AS on this surface; exposing these routes as
       MCP tools would mean either minting a second, parallel non-operator
       credential path into the MCP transport (the exact securable-asymmetry
       ADR-0031 exists to forbid, just inverted), or silently laundering the
       agent's session credential through an operator-authenticated call —
       both wrong for different reasons.
     - **The capability's operator half has its twin from day one.** The
       actual operator-facing action — mint a grant so an agent can push a
       file — ships with `mint_upload_grant`/`list_upload_grants`/
       `revoke_upload_grant` (this same PR). The exempted routes are the
       agent's OWN redemption of that grant, a mechanism step with no
       operator identity in the loop, not a second capability an operator
       is denied a twin for.
     - **The exception relaxes no control.** Each of the five routes still
       authenticates via `UploadGrantStore::authenticate_session`
       (constant-time secret compare against a stored SHA-256 hash) before
       any mutation, and the pre-auth body-cap table's `upload_session` row
       still bounds the chunk route before httplib buffers the body — MCP
       twin-or-not changes nothing about how these routes are gated.
     - Design record: `docs/adr/3004-artifact-blob-storage.md`; wire
       reference: `docs/user-manual/rest-api.md`'s upload-grant section.

   - **2026-08-15 — `GET /api/v1/guaranteed-state/status` fleet rollup
     (#2298 item 6d / #3038).** REST-only, no MCP twin — a "no" on
     Decision 1's both-surfaces requirement, already recorded in-code as
     "GRANDFATHERED" (`rest_api_v1.cpp`) since the route's `errored_rules`
     field was first made real, but not previously entered here. Recorded
     now rather than fixed, because:
     - **Pre-existing placeholder, not new capability.** The route existed
       pre-ADR-1005 returning a hardcoded `errored_rules: 0`; this ladder's
       #2298/item-6d work only made that one field real and, separately
       (#3038), fixed its authorization gate from a bare global permission
       check to the ADR-0017 admit-then-filter `AuthRoutes::require_list_read`
       chokepoint. Neither change adds a NEW capability — both are
       maintenance on an existing grandfathered surface (this ADR's own
       "modifying one in place is maintenance, not a violation" rule,
       "Prospective, not retroactive" section above).
     - **No MCP tool reads `errored_rules`/`total_rules`/`compliant_rules`/
       `drifted_rules` today** — the twin obligation has not yet attached in
       the sense the fleet-gauge-family entry above describes ("attaches
       when an operator-facing feature is built OVER the same data").
     - **The authorization fix (#3038) does not itself trigger re-evaluation
       against Decision 1/4** — it hardens the EXISTING REST surface's
       access control, it does not add a capability or a new consumer.
     - Design record: `docs/adr/0017-management-group-confinement-list-reads.md`;
       operator-facing behavior: `docs/user-manual/guaranteed-state.md`
       ("Fleet rollup" section), `docs/user-manual/server-admin.md` ("What a
       client sees"); wire reference: `docs/user-manual/rest-api.md` (`GET
       /api/v1/guaranteed-state/status`).

   - **2026-09-01 — legacy `/api/executions*` seven-route family (#3789).**
     REST-only surface, pre-existing since before ADR-1005; not a new
     capability, so Decision 1's both-surfaces requirement does not attach —
     same "hardening an existing gate is maintenance, not a violation"
     reasoning as the #3038 entry above.
     - **The MCP twin (`list_executions`) already exists and predates this
       PR.** #3789 hardens the REST surface's authorization gate
       (`require_permission` → `require_fleet_read`, ADR-0017
       admit-then-filter) to close a management-group confinement gap; it
       does not touch `list_executions`, whose own confinement takes a
       narrower, pre-existing shortcut (`dispatched_by`-only visibility,
       not the SQL EXISTS-pushdown this PR introduces on the REST side).
       The two surfaces are consequently NOT confined identically today —
       tracked as follow-up #3833 to backport the pushdown onto
       `list_executions`, not a twin-existence gap (the twin exists; its
       confinement mechanism is merely weaker).
     - **This fix does not itself trigger re-evaluation against Decision
       1/4** — it hardens an EXISTING surface's access control, it does not
       add a capability or a new consumer.
     - Design record: `docs/auth-architecture.md`'s "Fourth migration
       (#3789)"; wire reference: `docs/user-manual/rest-api.md`'s
       "Executions" section.

   - **2026-09-07 — 8 Settings read-twins (`GET /api/v1/settings/{tls,https,
     gateway,server-config,mcp,data-retention,analytics}` +
     `GET /api/v2/agent/plugin-policy` — its predecessor `/api/v1/agent/
     plugin-policy` deprecated by #4144 per `docs/api-versioning-policy.md`,
     not covered by this exception, #4028).** REST-only, no MCP twin — a
     "no" on Decision 1's both-surfaces requirement. Recorded rather than
     fixed pre-merge because:
     - **The gap is a deliberate, pre-existing security boundary, not a
       build-order gap.** #520 (this issue's own scoping note, echoed in
       `docs/mcp-server.md`'s MCP-tier reference) holds that MCP tokens are
       for fleet management and must not be used to administer the server
       itself — settings, users, TLS, OIDC. `mcp_policy.hpp`'s `tier_allows()`
       hard-denies the four securables gating these eight routes
       (`TlsConfig`/`PluginSigning`/`ServerConfig`/`AnalyticsConfig`) at
       EVERY MCP tier, including `readonly` — an admin-owned MCP token
       cannot read this data either. This PR's job was hardening the eight
       sub-areas onto REST v1 + dedicated RBAC securables (previously an
       undifferentiated `admin_fn_`-only gate on the dashboard fragment
       route alone); it did not — and, per #520, should not casually — add
       an MCP surface alongside that hardening.
     - **This entry corrects a same-PR ledger error, not a fresh
       classification call.** An earlier round of this PR flipped these 8
       rows straight to `status: "twinned"` in
       `scripts/ci/api-parity/settings.json` despite `mcp_twin: null`,
       understating the untwinned ratchet by 8
       (`scripts/ci/check-api-parity.py`'s `BASELINE_UNTWINNED` moved
       265 → 257) and recording the #520 decision nowhere this ADR's own
       exception-ledger mechanism could see it — an adversarial two-model
       review (`/home/dgr/advrev-4028`) caught the mislabel independently of
       the credential-leak finding on the same branch. The rows are now
       `status: "exception:#520"`, `BASELINE_UNTWINNED` is restored to 265,
       and this entry is the exception-ledger record ADR-1005's own
       Decision 1 requires for it.
     - **Not a tracked follow-up — revisit only if #520 itself is amended.**
       Unlike the SCIM entry above, there is no scoped MCP-surface work
       item to point at: adding an MCP twin here means amending #520's
       fleet-management/server-administration boundary, which
       `docs/mcp-server.md:21` already states explicitly requires "its own
       security-guardian-reviewed amendment... not a side effect of a
       routine REST-twin PR." This stands as a standing exception until
       that amendment happens, not a numbered issue with a revisit date.
     - **The exception relaxes no control.** Every route requires its
       dedicated RBAC securable (`Read`) and is floored in
       `authz_topology_floor.hpp` so an RBAC-off deployment stays
       admin-gated rather than silently widening to any authenticated user.
       Four of the eight (TLS, HTTPS, plugin-signing, analytics — the
       higher-sensitivity sub-areas) are additionally audited fail-closed
       (`settings.*.read` / `plugin_signing.*`, `settings_routes.hpp`'s
       dedicated `AuditFn`); the other four (gateway, server-config,
       data-retention, MCP) are deliberately unaudited, matching their
       pre-existing dashboard-fragment posture and #4028's own Evidence
       classification of that data as non-sensitive (each REST handler's
       comment states this explicitly). The MCP deny-list changes nothing
       about REST-side access control either way.
     - Design record: `server/core/src/mcp_policy.hpp`'s `#4028/#520`
       comment; `docs/auth-architecture.md`'s "Settings read-twins" section;
       wire reference: `docs/user-manual/rest-api.md`'s Settings routes,
       `docs/mcp-server.md`'s MCP-tier reference.

   - **2026-09 — the legacy unversioned `/api/*` admin plane, class-level
     entry (107 routes).** Enumerated by grepping every `sink.Get/Post/Put/
     Delete(...)` registration in `server/core/src` for an `/api/*` path
     that is NOT `/api/v1/*` (the `/api/executions*` family above and the
     four health-probe paths in the first ledger entry are separate,
     already-recorded exceptions and are excluded from the count). These
     routes predate ADR-1005 by construction — grandfathered under this
     ADR's prospective-only binding (see "Binding status" above), same
     "maintenance, not a violation" posture as the other entries in this
     ledger — but had never been individually inventoried, so a reviewer
     had no citable list distinguishing "known legacy debt" from "a new
     UI-only capability slipped in disguised as a settings route." This
     entry is that inventory, not a re-classification: nothing below
     changes behavior or authorization posture.
     - Only **2 of the 107** already have a genuine `/api/v1` twin (`GET
       /api/audit` → `GET /api/v1/audit`; `GET /api/me` → `GET
       /api/v1/me`) — both pre-existing, unrelated to this ledgering pass.
       Everything else is `/api/settings/*` admin/config surface (user
       management, OIDC/SAML/TLS/cert-upload config, enrollment tokens,
       pending-agent approve/deny, MFA admin, plugin signing, agent-update
       upload/rollout, MCP settings, DEX-alert routing, management-group
       create, CA import-chain/revoke) or a handful of sibling
       non-`/settings` admin routes (`/api/command`, `/api/policies*`,
       `/api/policy-fragments*`, `/api/webhooks*`, `/api/workflows*`,
       `/api/product-packs*`, `/api/notifications*`, `/api/nvd/*`,
       `/api/patches*`, `/api/deployment-jobs*`, `/api/discovery/*`,
       `/api/directory/*`, `/api/dashboard/*`, `/api/scope/*`,
       `/api/help*`, `/api/analytics/*`, `/api/instructions/*/execute`,
       `/api/compliance*`) — marked **settings-plane exception** with a
       **2027-Q1** proposed re-home target (PO-adjustable; no committed
       date until an owning module is scoped). `/fragments/*` surfaces
       (e.g. `/fragments/auto/*`, `/fragments/tar/*`,
       `/fragments/device/live/*`, `/fragments/executions`) remain under
       item 1 above; they carry no migration date — tracked separately.

     | Method | Path | Owning file | Replacement `/api/v1` path | Target quarter |
     |---|---|---|---|---|
     | POST | `/api/settings/ca/import-chain` | `ca_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/ca/revoke` | `ca_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/command` | `command_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/compliance` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/compliance/([^/]+)` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/policies` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policies` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/policies/([^/]+)` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/policies/([^/]+)` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policies/([^/]+)/disable` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policies/([^/]+)/enable` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policies/([^/]+)/evaluate` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policies/([^/]+)/invalidate` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policies/([^/]+)/remediate` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policies/invalidate-all` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/policy-fragments` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/policy-fragments` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/policy-fragments/([^/]+)` | `compliance_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/agents` | `dashboard_api_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/analytics/recent` | `dashboard_api_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/analytics/status` | `dashboard_api_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/audit` | `dashboard_api_routes.cpp` | `GET /api/v1/audit` | 2026-Q4 |
     | POST | `/api/export/json-to-csv` | `dashboard_api_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/me` | `dashboard_api_routes.cpp` | `GET /api/v1/me` | 2026-Q4 |
     | POST | `/api/scope/validate` | `dashboard_api_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/dashboard/execute` | `dashboard_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/dashboard/group-from-results` | `dashboard_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/dashboard/tar-execute` | `dashboard_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/deployment-jobs` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/deployment-jobs` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/deployment-jobs/([a-f0-9]+)` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/deployment-jobs/([a-f0-9]+)` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | PUT | `/api/directory/group-mappings` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/directory/status` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/directory/sync` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/directory/users` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/discovery/results` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/discovery/scan` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/patches` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/patches/deploy` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/patches/deployments` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/patches/deployments/([a-f0-9]+)` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/patches/deployments/([a-f0-9]+)/cancel` | `discovery_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/notifications` | `notification_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/notifications/(\d+)/dismiss` | `notification_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/notifications/(\d+)/read` | `notification_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/nvd/match` | `nvd_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/nvd/status` | `nvd_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/nvd/sync` | `nvd_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/help` | `page_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/help/autocomplete` | `page_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/help/html` | `page_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/help/palette` | `page_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/api-tokens` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/settings/api-tokens/(.+)` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/auto-approve` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/settings/auto-approve/(\d+)` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/auto-approve/(\d+)/toggle` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/auto-approve/mode` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/cert-paste` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/cert-upload` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/dex-alerts/blast` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/dex-alerts/cohort-export` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/dex-alerts/routing` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/enrollment-tokens` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/settings/enrollment-tokens/(.+)` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/enrollment-tokens/batch` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/management-groups` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/settings/management-groups/([a-f0-9]+)` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/mcp` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/mfa/disable` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/mfa/init` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/mfa/recovery-codes` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/mfa/verify` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/oidc` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/oidc/test` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/settings/pending-agents/(.+)` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/pending-agents/(.+)/approve` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/pending-agents/(.+)/deny` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/pending-agents/bulk-approve` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/pending-agents/bulk-deny` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/plugin-signing/clear` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/plugin-signing/require` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/plugin-signing/upload` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/tls` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/settings/updates/([^/]+)/([^/]+)/([^/]+)` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/updates/([^/]+)/([^/]+)/([^/]+)/rollout` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/updates/upload` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/users` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/settings/users/(.+)` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/settings/users/(.+)/role` | `settings_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/webhooks` | `webhook_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/webhooks` | `webhook_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/webhooks/(\d+)` | `webhook_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/webhooks/(\d+)/deliveries` | `webhook_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/instructions/([^/]+)/execute` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/product-packs` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/product-packs` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/product-packs/([^/]+)` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/product-packs/([^/]+)` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/scope/estimate` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/workflow-executions/([^/]+)` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/workflows` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/workflows` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | DELETE | `/api/workflows/([^/]+)` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | GET | `/api/workflows/([^/]+)` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |
     | POST | `/api/workflows/([^/]+)/execute` | `workflow_routes.cpp` | settings-plane exception | 2027-Q1 |

     `/fragments/*` surfaces remain under item 1; they carry no migration date — tracked separately.

   - **2026-09-16 — Hardware CI list/record (`GET /api/v1/hardware`,
     `GET /api/v1/hardware/{id}`, `POST /api/v1/hardware/{id}/sync`, PR
     `feat/hardware-ci-view`).** REST-only, no MCP twin, and absent from
     route discovery only in the sense that no `get_hardware_ci`/
     `list_hardware`/equivalent MCP tool exists yet — the REST routes
     themselves ARE in `openapi_spec()` and `GET /api/v1/routes` (A2/A3
     hold for the REST half). A "no" on Decision 1/4's both-surfaces
     requirement for the MCP half.
     - **No MCP twin — tracked follow-up, not a permanent exception.** An
       earlier draft of `hardware_routes.hpp`/`server.cpp` carried a
       comment claiming a `get_hardware_ci` MCP tool already existed,
       sharing the CI-detail closure via a `mcp_server_->set_hardware_fns`
       call — false; no such symbol exists anywhere in the tree, including
       `mcp_server.cpp`, which this branch never touches (governance Gate 3
       finding, both external reviewers and two internal domain agents
       independently confirmed the grep). The false comment was removed in
       the same PR. The 10 new `device.live.<kind>` physical-kit reads are
       NOT part of this gap — they reuse the pre-existing generic
       live-info/bundle dispatch mechanism, which already has its own MCP
       reachability via `execute_instruction`, unaffected by this row.
     - Scoping and building the list/detail/sync-dispatch MCP twin is out
       of scope for this PR; tracked as **#4456**. Until it lands, this row
       stands as the open exception.
     - Full design record: the round-3 hardware-ci-view plan
       (`docs/user-manual/inventory.md`'s Dashboard section describes the
       shipped REST/HTMX surface); wire reference:
       `docs/user-manual/rest-api.md`'s Hardware section.

## Interim rules (until the named follow-ups ship)

- **No engine principal class exists** until the auth-architecture follow-up lands. Until then, integrations authenticate as themselves via existing API tokens, and the server accepts **no** on-behalf-of assertion on any surface — any such header/field is rejected, not ignored.
- **No engine principal may be enabled in production until a minimum per-principal concurrency/quota cap exists.** The rate-limit mechanism is deferred; this interlock is not.
- **No engine credentials are issued to external parties before a published API versioning/deprecation policy exists.** Otherwise the first BYO-engine customer freezes whatever surface shape exists that day.
- If delegation ships incrementally, audit rows produced before verification is enforceable carry `delegation_verification_status=unverified` — the works-council/SOC 2 consequence below is conditional on verified delegation, and unverified rows must never be presented as attribution evidence.

## Out of scope (deliberately deferred)

- **Egress primitives** (durable/replayable event subscription, changed-since bulk sync for engines). Anticipated, not committed; the design lands with the first module's scoping (Decision 6) and must evaluate at least two consumer archetypes (batch join, streaming) even if only one ships. ADR-0021 work should avoid *precluding* external subscription in event-spine shapes, without building for it.
- Use-case engine host stack, packaging, and repo layout.
- Dashboard migration sequencing.
- Delegation token mechanics (auth-architecture follow-up; includes principal granularity, lifetime ceilings, the self-target-guard extension).
- Consumer rate limiting / quota design (mechanism only — the production interlock above is decided now).
- **Server-only topology** (no first-party engine) as a distinct supported deployment — test-surface and support-matrix implications.
- **Customer-facing integration assurance package** for BYO-engine consumers: conformance suite, sandbox/test environment, security-questionnaire language covering third-party principals.
- Published SLO numbers per surface (availability/latency). Decision 3 commits contract *stability* (versioning, back-compat, error envelopes), not SLO publication.

## Consequences

- **API surface becomes a product contract.** New REST/MCP surface added from now on (including during the ADR-0021 rebuild) is designed as externally consumable: versioned, discoverable, honest error envelopes (A2–A4). Compatibility posture: additive-preferred immediately; a formal compatibility freeze and deprecation policy must be published before the first external engine credential (see Interim rules); MCP tool versioning is part of that policy.
- **Governance gains a standing review question** for every **new or changed** server capability (grandfathered surfaces answer via the exception ledger, not ad hoc): *"Is every behavior of this capability reachable by an authenticated external principal over versioned REST **and** MCP (or a recorded exception), discoverable (A2/A3), with the A4 error envelope, no in-process-only behavior, and RBAC/audit enforced at the API?"* A "no" on any clause is a design defect.
- **ADR-0021 reconciliation.** 0021's sovereign consumers (Guardian, DEX, Reflex) are sovereign within core *mechanism* — agent detection, event spine, compiled policy wire all sit core-side of Decision 2's test. Their read-model dashboards are strangler targets; migrating in this direction is the declared intent — new work on these consumers should move toward the boundary, not deepen coupling to core.
- **Store ownership follows the layer.** Postgres migration under ADR-0006/0012 confers no core permanence: a store whose sole consumer is an interpretation layer moves out with that layer; until then, engines reach its data only via the versioned API (bulk egress deferred).
- **Capacity and isolation become first-class.** The headless shift moves all UI and engine reads onto the same finite HTTP + PG-pool path as the agent control plane (one shared bounded `PgPool`, ADR-0012). API-serving capacity becomes an explicit SLO input before any engine GAs, and whether API-serving and the agent control plane need separate resource budgets (pool/thread) is a tracked follow-up before engine GA — a hot-polling engine must not be able to starve heartbeat ingest or command dispatch. Request metrics for the surface carry a low-cardinality `principal_class` label (human / agent / engine, plus `none` for unauthenticated requests as shipped — see execution plan PR 1.2); per-principal identity stays in the audit envelope per `docs/observability-conventions.md`.
- **Ship shape (eventual):** headless `yuzu-server` (with thin admin console) as a supported standalone deploy; first-party engine as a separate artifact customers may take, replace, or omit. The first-party engine declares a min/max supported server API version and refuses to start outside it.
- **Data-processor status:** an engine holding a synced copy of fleet or behavioral data is a data processor in its own right; retention/deletion/DPA obligations for that copy fall to the engine operator and are not discharged by this ADR — SOC 2 Workstream E tracks this.
- **Works-council / SOC 2 posture is designed to improve** — one audit chokepoint recording every server-mediated actor (human, agent daemon, engine, engine-for-operator) — **contingent on** the delegation follow-up shipping server-verifiable delegation and the Decision 5 audit-row fields. It is not a completed control, and engine-internal redistribution of synced data remains outside this chokepoint (see Decision 5's perimeter caveat). Engine-principal credential lifecycle lands in SOC 2 Workstream B.

## Acceptance note (2026-09-07)

Accepted (tracking issue #4099). Shipped in-server: `on_behalf_guard.hpp`, `grpc_on_behalf_interceptor.hpp` (registered via `SetInterceptorCreators`, `server.cpp:7157-7166`), `principal_class.hpp`, `engine_principal_store.{hpp,cpp}`, `principal_quota_gate.hpp`, and the `StreamBudget` admission cap give Decisions 1–4 a live substrate to bind against. Accepted children ADR-0031 (`engine_principal_store`, builds-on), ADR-0031 (`presentation-core-engine-decomposition`, amends Decision 6), ADR-0032 and ADR-0033 (both depends-on) already rest on this ADR; acceptance closes that inversion.

Phase 7 (the vuln-management strangler re-home into a use-case engine under `engines/`, `docs/adr-1005-execution-plan.md`) has NOT started — no `engines/` directory exists. Grandfathered surface #2 is unchanged by this acceptance: it covers only the shipped NVD sync/matching and the absorbed ADR-0023 and ADR-4001 designed scopes, placement-only, outside-by-default beyond them (rider (b): ADR-4002 not absorbed). The remaining vuln ADRs (0001/0002/0005/0029/4002/4003/4004) are deferred into that future engine, not withdrawn, and are NOT grandfathered — each faces Decision 2 fresh at implementation. ADR-0028 (component inventory) is agent-side collection mechanism: deferred, but it stays core under Decision 2 and is not engine scope.

Interim rules at acceptance: rule 1's "no engine principal class" clause is discharged by ADR-0031 (`engine_principal_store`) while its on-behalf-of ban remains live (`on_behalf_guard.hpp`, unamended by ADR-0032); rule 2 is discharged by `principal_quota_gate.hpp`; rule 3 is discharged by the published `docs/api-versioning-policy.md`; rule 4 (unverified-delegation audit marking) remains live and conditional on the delegation follow-up. Decisions 1–4 bind prospectively from 2026-09-07.
