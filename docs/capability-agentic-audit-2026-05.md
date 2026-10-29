# Capability & Agentic-Readiness Audit

**Version:** 1.0 | **Date:** 2026-05-01 | **Status:** Draft

## What this document is

A capability-and-agentic-readiness audit of Yuzu against two bars: (1) feature parity with mature commercial endpoint-management platforms (real-time endpoint query and response, patch and configuration management, cloud device management, IT discovery, automation and orchestration, and endpoint detection and response products), and (2) the **agentic-first** thesis — every operation a human can perform via the dashboard must be performable by an authenticated LLM-driven worker through a documented, discoverable, machine-readable surface.

Companion docs:

- `docs/agentic-first-principle.md` — the four invariants (A1 dashboard parity, A2 discovery, A3 observability, A4 error envelope) referenced throughout this audit.
- `docs/capability-map.md` — capability inventory (this audit only edits §2.2 to remove a false gap).
- `docs/roadmap.md` — phase plan (this audit appends proposed Phase 17–18).

This audit makes recommendations only; it does not implement. The recommendations are tracked as proposed roadmap issues 17.x–18.x.

---

## 1. Executive Summary

**Capability state.** Per `docs/capability-map.md` §Progress at a Glance, Yuzu is **166/225 = 74%** complete. The headline number masks two realities: (a) the Foundation (33/33) and Advanced (101/101) tiers are at 100% feature presence but **not** at 100% production hardening — known gaps at the §-level include Tier-3 cert validation (1.1), configurable heartbeat (1.2), unified diagnostics bundle (1.3), runtime plugin install (1.5), and others; (b) the New tier (Phases 8–16) is at **1/41 = 2%**, with Echo Phase 15.A in flight and Guardian Phases 16.A PRs 1–2 shipped of a 17-PR ladder. The Advanced/Foundation tiers should be read as "scaffolded and functional" rather than "production-quality and proven-at-scale".

**Top three capability gaps (deal-blocking for enterprise):**

1. **Connector Framework (Phase 9, 0%)** — Without bidirectional sync to SCCM, Intune, ServiceNow, WSUS, vCenter, AD, O365, Yuzu is an island. Enterprises always integrate.
2. **System Guardian (Phase 16)** — 2 of 17 Windows PRs shipped; Linux/macOS not started. The "real-time, kernel-event-driven enforcement" story is the headline differentiator vs the existing 5-min PolicyStore poll. Until it lands, "this setting must never drift" rules are best-effort, not compliance-grade.
3. **Software Catalog & License Compliance (Phase 10, 0%)** — License posture is a top RFP item.

**Top three agentic gaps (block no-human-in-the-loop operation):**

1. **Dashboard fragments are HTML-only.** Routes under `/fragments/*` return `text/html` with no `Accept: application/json` content negotiation. Admin surfaces (user mgmt, enrollment-token administration, settings panels) are dashboard-only with no REST sibling — an agent cannot programmatically onboard another agent or assign roles without HTML parsing.
2. **No discovery surface beyond MCP `tools/list` + `/api/v1/openapi.json`.** Plugin actions, scope kinds, RBAC permissions, and live instruction-definition schemas are not enumerable from the live server; an agent must rely on out-of-band docs.
3. **MCP write surface is one tool.** `set_tag`, `delete_tag`, `approve_request`, `reject_request`, `quarantine_device` are present in `mcp_server.cpp` `kWriteTools` and `kToolSecurity` (`server/core/src/mcp_server.cpp:229-274`) but **only `execute_instruction` has a dispatch handler** (line 1313). The other five fall through to "Unknown tool". Issue 13.5 plans the wiring; until it lands, agentic workers must drop to Bearer-token REST for tag mutation and approval workflow.

---

## 2. Capability Tier Honesty

Per the cap map's own table (`docs/capability-map.md:30-71`):

| Tier | Domain count | Done | Partial | Not started | Total | % done |
|---|---:|---:|---:|---:|---:|---:|
| Foundation (T1) | 11 | 33 | 0 | 0 | 33 | 100% |
| Advanced (T2) | 9 | 101 | 0 | 0 | 101 | 100% |
| Future (T3) | 4 | 31 | 0 | 19 | 50 | 62% |
| New (Ph 8–16) | 7 | 1 | 3 | 37 | 41 | 2% |
| **Overall** | 31 | **166** | **3** | **56** | **225** | **74%** |

The audit recommends adding a "scaffolded vs production-quality" overlay to capability-map.md — a column or note clarifying that 100% on Foundation / Advanced means "feature implemented and functional", not "hardened, observable, and proven at enterprise scale". The audit at hand is the first read of the production-quality dimension; subsequent reviews should keep it current.

The cap map's "New (Ph 8–16) [=---] 1/41 done (2%)" line carries a parenthetical that lists three partials and three "in flight" items. The numerator and parenthetical disagree (1 vs at least 4 with movement). After this audit's §2.2 fix, the cap-map maintainer should re-tally the New-tier numerator against actual PR landings.

---

## 3. Verified Inconsistencies

This audit corrects facts in two predecessor sources: (a) the original draft plan I authored, and (b) the Ultraplan refinement that ran against an apparently-stale snapshot of the repo. The verified state below cites file:line for every code claim so future readers can re-verify.

| Claim | Verified state |
|---|---|
| Capability count: 184/150/82% | `README.md:239` says **184/150/82%** — stale; `capability-map.md:35` says **166/225/74%**. README is the artifact to fix. |
| Capability count: 208/165/79% | This number does not appear in the repo. (It was Ultraplan's artefact of reading an older snapshot.) |
| Roadmap stops at Phase 14 | Roadmap goes through **Phase 16** (`docs/roadmap.md:1483` Phase 15 Echo & Scope Walking; `:1552` Phase 16 System Guardian). |
| Echo is Issue 7.19 Done | Echo is **Phase 15** with Issue 15.A (page shell + retention list) **In Progress** and 15.B–15.H Open (`docs/roadmap.md:1487-…`). |
| `docs/scope-walking-design.md` / `echo-dashboard.md` / `echo-implementer.md` do not exist | All three exist in `docs/` and the first two are routed from `CLAUDE.md:354-355`. |
| Tag/scope filter targeting is not implemented (cap-map §2.2 gap) | `agent_registry.cpp:820-861` — `AgentRegistry::evaluate_scope` instantiates an `AttributeResolver` (lines 826-855) that resolves `ostype` (829), `hostname` (831), `arch` (833), `agent_version` (835), `tag:X` (838-847 — looks in in-memory `scopable_tags`, falls back to persistent `TagStore`), and `props.X` (849-853). The cap-map §2.2 "Gap" entries at lines 137 and 139 are **doc bugs**, not code gaps. |
| MCP Phase 2 not on roadmap | **Issue 13.5** in `docs/roadmap.md` plans `set_tag`, `delete_tag`, `approve_request`, `reject_request`, `quarantine_device` plus SSE for execution progress. |
| `set_tag`, `delete_tag` MCP tools are implemented | They appear in `kWriteTools` (`mcp_server.cpp:229-232`) and `kToolSecurity` (`mcp_server.cpp:267-273`). The misleading comment at `:227-228` says "Implemented: set_tag, delete_tag, execute_instruction" — only `execute_instruction` has a dispatch handler (`:1313`). The five other write tools fall through to the Unknown-tool branch. |
| `/events` SSE is unauthenticated | False. `server.cpp:1632-1644` resolves session for all routes; `/events` returns HTTP 401 JSON when no session is present (line 1636). The actual gap is **content shape** — the channel emits HTMX-friendly HTML fragments via `event_bus_` (`server.cpp:2450-2478`, consumed at `dashboard_ui.cpp:494,1259`), not JSON envelopes for machine consumption. |
| OpenAPI 3.0 spec exists | Yes — `rest_api_v1.cpp:167 openapi_spec()` returns the spec; route registered at `:496`. |
| 44 plugins / 65 YAML defs | **45** plugin dirs in `agents/plugins/`, **66** files matching `content/definitions/*.yaml`. |
| Authenticated SSE pattern doesn't exist | `rest_api_v1.cpp:2498-2501` exposes `/api/v1/guaranteed-state/events` — an authenticated SSE pattern that A3 backfill can extend rather than re-invent. |

---

## 4. Agentic-Readiness Scorecard

Per surface, what an authenticated agentic worker can do today vs cannot.

### 4.1 MCP

**Can do:**
- Discover all 23 MCP tools and their input schemas via `tools/list`.
- Discover 3 resources (`yuzu://server/health`, `yuzu://compliance/fleet`, `yuzu://audit/recent`) and 4 prompts.
- Execute 22 read tools (agents, audit, definitions, responses, inventory, tags, policies, compliance, mgmt groups, executions, schedules, scope preview, pending approvals — see `kTools[]` `mcp_server.cpp:120-220`).
- Execute one write tool: `execute_instruction` (`:1313`), auto-approved at `operator` tier.

**Cannot do:**
- Mutate tags (`set_tag`, `delete_tag` security-mapped but not dispatched).
- Drive the approval workflow (`approve_request`, `reject_request` security-mapped but not dispatched).
- Quarantine a device (`quarantine_device` security-mapped but not dispatched).
- Receive a usable approval ticket on `kApprovalRequired` — supervised-tier `execute_instruction` returns the error code without an approval id or status URL.
- Manage scope expressions, management groups, policies, users, tokens, sessions, or enrollments — none of these have MCP tools.

**Gap blocker.** Issue 13.5 plans the five missing write tools and SSE for execution progress — accelerating it closes the largest MCP gap.

### 4.2 REST API

**Can do:**
- Discover the REST surface via `/api/v1/openapi.json` (`rest_api_v1.cpp:496`, generated by `openapi_spec()` `:167`).
- 130+ routes covering agents, mgmt groups, tags, executions, responses, audit, inventory, schedules, approvals, API tokens, RBAC introspection, custom properties, guaranteed-state rules + events SSE.
- Subscribe to `/api/v1/guaranteed-state/events` for guardian-rule events (the one machine-readable SSE today, `rest_api_v1.cpp:2498-2501`).

**Cannot do:**
- Discover plugin actions, scope kinds, RBAC permission catalog, or live instruction-definition schemas — these are not enumerable.
- Mutate user accounts / approve enrollments / configure Entra/AD / upload certs — these are dashboard-only.
- Revoke a session — DB primitive exists but no `/DELETE /api/v1/sessions/{id}` route.
- Rotate a token through a pair-overlap workflow — only create+revoke is exposed.

### 4.3 Dashboard

**Can do (as a human):**
- Navigate every admin surface (user mgmt, enrollment, settings, executions, schedules, scopes, policies, Echo).

**Cannot do (as an agent):**
- Get JSON for any `/fragments/*` route — they return `text/html` only. No `Accept: application/json` content negotiation.
- Discover the route catalog — there is no sitemap or fragment index endpoint.
- Receive structured data on the SSE stream — `/events` (`server.cpp:2450`) emits HTML fragments designed for HTMX `sse-swap` (`dashboard_ui.cpp:494`), not JSON envelopes.

### 4.4 SSE / event channels

| Channel | Auth | Shape | Agent-friendly? |
|---|---|---|---|
| `/events` (`server.cpp:2450`) | Yes (cookie or token via `resolve_session`) | HTML fragments | No — content shape mismatch |
| `/api/v1/guaranteed-state/events` (`rest_api_v1.cpp:2498`) | Yes | JSON (polling, not streaming) | Yes |
| `/api/v1/events` (`rest_api_v1.cpp` — sprint W5.1, 2026-05-18) | Yes (`Execution:Read`) | JSON SSE with A3 envelope | **Yes — first surface that satisfies A3 + A4** |
| Workflow / executions SSE (`workflow_routes.cpp:735`) | Yes | text/event-stream (raw `ev.data`, dashboard-shaped) | Browser-friendly only |

`/api/v1/events` is the agentic-first SSE channel that A3 backfill kept asking for. It reuses the same `ExecutionEventBus` the dashboard channel rides on (no new bus), wraps each event in `{execution_id, event_id, timestamp_ms, type, payload}` per A3, and emits the A4 error envelope on every 4xx/5xx. W5.1 ships the skeleton (single-execution filter via `?execution_id=`); W5.2 extends with multi-execution / `?filter=` syntax and content negotiation on `/fragments/executions`.

### 4.5 Auth & identity

**Can do:**
- API tokens with mandatory expiration (≤90 days), 3-tier MCP policy (`readonly` / `operator` / `supervised`), per-IP rate limiting, audit attribution as `mcp.<tool>`.

**Cannot do:**
- Distinguish service accounts from human users — every token is owned by a human principal.
- Scope tokens to a subset of management groups, plugins, or operations.
- Rotate tokens via a pair-overlap workflow (only create+revoke).
- Self-recover from a `Permission denied` error — the envelope does not name the missing `securable_type:operation`.
- Self-recover from a `kApprovalRequired` error — no approval id or status URL is returned.

### 4.6 Error semantics

Every surface emits structured errors with `code` + `message`, but **none** include `correlation_id`, `retry_after_ms`, or `remediation`. Permission-denied errors do not name the missing permission. Approval-required errors do not return an approval ticket id. A4 closes these gaps; the cost is a small envelope rev + per-handler audit.

---

## 5. Agentic-First Invariants (A1–A4)

The architectural rule introduced by this audit is: **every operation an authorised human can perform via the dashboard must be performable by an authenticated agentic worker through a documented, discoverable, machine-readable surface**. Operationally:

- **A1 Dashboard parity** — new `/fragments/*` routes ship with a JSON variant or REST sibling.
- **A2 Discovery** — every tool, route, plugin action, scope kind, RBAC permission, instruction definition is enumerable from the live server.
- **A3 Observability** — long-running operations emit JSON SSE events on a documented agent-accessible channel.
- **A4 Error envelope** — failures include `correlation_id`, `retry_after_ms` (nullable), `remediation` (nullable), and on auth failures the missing `securable_type:operation`.

Full text and rationale: `docs/agentic-first-principle.md`. The `consistency-auditor` governance agent gets these added to its trigger list (CLAUDE.md change in this PR).

---

## 6. Doc Routing Gaps

`docs/` contains 34 top-level markdown files (excluding `docs/user-manual/`, which loads via `docs-writer`). 19 are routed from `CLAUDE.md` (line 343-355 routing table plus inline references). 15 are unrouted today. The four most consequential for agentic-first work:

| Doc | Why route it | To whom |
|---|---|---|
| `docs/architecture.md` | Cross-cutting design reference | `architect` on cross-cutting design changes |
| `docs/asset-tagging-guide.md` | Tag/scope DSL operator reference; the §2.2 reconciliation in this PR cites it | `dsl-engineer` on scope/tag-DSL changes |
| `docs/agentic-first-principle.md` (NEW) | A1–A4 invariants that this PR introduces | `consistency-auditor` on every PR |
| `docs/enterprise-parity-plan.md` | Detailed competitor parity matrix; complements capability-map | `architect` on capability-map / roadmap changes |

The remaining ~11 unrouted docs (`analytics-events.md`, `ci-cpp23-troubleshooting.md`, `ci-troubleshooting.md`, `clickhouse-setup.md`, `dependency-rollout-2026-04-14.md`, `dependency-updates.md`, `enterprise-edition.md`, `erlang-gateway-blueprint.md`, `erlang-gateway-review.md`, `echo-implementer.md`, `echo-warehouse-plan.md`, `test-coverage.md`) are operational/internal and route per their natural owner agents organically — no immediate action required.

---

## 7. Recommendations

### P0 — Doc reconciliation (this PR)

The seven file changes in this PR. See §11 for the specific diffs.

- Replace stale capability count in `README.md:239` with a pointer.
- Remove the false "scope/filter targeting" gap in `docs/capability-map.md` §2.2; cite the `agent_registry.cpp:820-855` resolver.
- Add scaffolded-vs-production caveat to capability-map header.
- Add agent-disambiguation glossary to `CLAUDE.md`; route `architecture.md`, `asset-tagging-guide.md`, `agentic-first-principle.md`, `enterprise-parity-plan.md`.
- Append proposed Phase 17 (Agentic Surface Hardening) and Phase 18 (Compliance & Lifecycle) to `docs/roadmap.md` — Phase 15/16 already exist, so the additions are 17+, not 15+.
- Fix the misleading `mcp_server.cpp:227-228` "Implemented" comment to match runtime dispatch.

### P1 — Unblock agentic operation (next 2–4 sprints)

These five items become roadmap issues 17.1–17.5 (proposed Phase 17 — Agentic Surface Hardening). They map directly to A1–A4.

- **17.1 Introspection endpoints** (A2). `/api/v1/discover/{routes,plugins,scope-kinds,permissions,instructions}` with mirrored MCP tools. Source from existing `openapi_spec()` and the agent-registered `PluginInfo` rather than re-walking handlers.
- **17.2 Dashboard JSON content negotiation** (A1). Add `Accept: application/json` honoring on `/fragments/*` page routes; admin-surface fragments (user mgmt, enrollment, settings) earmarked for first cut.
- **17.3 Agent-facing JSON SSE channel** (A3). Pattern after `/api/v1/guaranteed-state/events`; expose `/api/v1/events?since=&filter=execution_id:X|agent_id:Y`. Reuse `event_bus_` and the executions ladder's `ExecutionEventBus`. Decide separately whether to deprecate the HTML-fragment `/events` channel or keep both. **Sprint W5.1 (2026-05-18) shipped the skeleton** — single-execution filter via `?execution_id=`, A3 envelope, A4 errors, OpenAPI discovery row, Sec-Audit-Failed honouring. W5.2 finishes the multi-execution `?filter=` syntax and the fragment content negotiation.
- **17.4 Service-account principal type** (A2 + auth). `auth_db` migration to add `principal_type IN ('user','service_account')`. Service accounts can be scoped to mgmt-group / plugin / operation subsets.
- **17.5 Structured error envelope rev** (A4). `correlation_id`, `retry_after_ms`, `remediation`; on `kPermissionDenied` name the missing `securable_type:operation`; on `kApprovalRequired` return `approval_id` + `status_url`.

**Also accelerate the existing Issue 13.5** — it already plans the five missing MCP write tools and SSE for execution progress. Without it, A1/A3 are partial.

### P2 — Capability completion (3–9 months, against existing roadmap)

- **Phase 9 Connector Framework.** Largest enterprise gap. Start with SCCM, Intune, ServiceNow.
- **Phase 16 System Guardian.** Maintain Windows PR cadence (PRs 3–17); start Linux delivery once Windows soaks.
- **Phase 10 Software Catalog & License Compliance.** Depends on Phase 9 framework.
- **Phase 15 Scope Walking finishing.** 15.B (result-set store) → 15.C (`from_result_set:` scope kind) → 15.D (Echo SQL frame) — already designed in `docs/scope-walking-design.md`, just needs delivery.
- **Phase 8.2 / 8.3** — Visualization templates and offloading complete the visualization phase.

### P3 — Roadmap holes (proposed Phase 18)

Capabilities currently absent from any roadmap phase but commonly demanded:

- **18.1 Vulnerability lifecycle** — CVE → CVSS → owner → SLA → remediation tracking (today: vuln_scan plugin only).
- **18.2 Compliance reporting templates** — CIS, NIST 800-171, SOC 2 evidence packs (today: PolicyStore + audit foundation; no templates).
- **18.3 Certificate lifecycle** — auto-renewal, expiry alerts, revocation (today: inventory only).
- **18.4 Secrets-vault integration** — HashiCorp Vault, Azure Key Vault, AWS Secrets Manager (today: connector creds in SQLite).
- **18.5 SBOM ingest** — CycloneDX / SPDX import, component-level vuln linkage.
- **18.6 Hardware attestation** — TPM, Secure Boot, UEFI verification.

**Out of scope** (document explicitly):

- **MDM (mobile)** — partner integration only.
- **OS deployment / imaging / PXE** — partner integration only.
- **EDR-class telemetry at the agent** — integrate via Phase 9 connectors to existing EDR; do not re-implement.

---

## 8. Critical Files & Functions to Reuse

When implementing P1 / P2 / P3, the following existing primitives should be cited and extended rather than duplicated:

- `kTools[]` and `kToolSecurity` (`server/core/src/mcp_server.cpp:120-274`) — every new MCP tool extends these.
- `AttributeResolver` (`server/core/src/scope_engine.hpp` and the lambda at `agent_registry.cpp:826-855`) — canonical proof tag/property/OS scope works; new scope kinds extend the resolver.
- `openapi_spec()` (`rest_api_v1.cpp:167`, registered at `:496`) — feed the proposed `/api/v1/discover/routes` from this rather than re-walking handlers.
- `event_bus_` and `SseEvent` (`server.cpp:2450-2478`) — the existing SSE bus; A3 reuses it.
- `ExecutionEventBus` (per `docs/executions-history-ladder.md` and `workflow_routes.cpp:735`) — execution progress events for the agentic SSE channel.
- `auth_db` and `auth_routes` — service-account principal type (17.4) is a migration on `auth_db` plus a new principal-type field; existing token issuance and revocation flows extend.
- `consistency-auditor` agent (`.claude/agents/consistency-auditor.md`) — owns A1–A4 enforcement; extend its trigger list rather than create a new agent.

---

## 9. Verification Checklist

Before merging this PR:

1. `grep -E "184|150 done|82%" README.md` returns 0 matches outside any version-history section.
2. `grep -E "No scope/filter" docs/capability-map.md` returns 0 matches.
3. `grep -nE "agent daemon|governance agent|agentic worker" CLAUDE.md` returns ≥3 hits in the new glossary block.
4. `grep -nE "Phase 17|Phase 18" docs/roadmap.md` returns the new "Proposed" entries.
5. `grep -nE "Implemented dispatch:" server/core/src/mcp_server.cpp` returns the corrected comment; `grep -E "Implemented: set_tag" server/core/src/mcp_server.cpp` returns 0 matches.
6. `meson compile -C build-linux` succeeds.
7. `meson test -C build-linux --suite server --print-errorlogs` passes.
8. `docs/agentic-first-principle.md` is reachable from `CLAUDE.md` routed-concerns table.
9. `docs/capability-agentic-audit-2026-05.md` exists and every code-claim file:line cite resolves.
10. `git log --oneline -1` shows the new commit on `claude/refine-local-plan-0io2A`.

**Semantic check:** a fresh reader who reads only this audit should be able to (a) identify the three highest-impact agentic gaps, (b) find Issue 13.5 covering MCP Phase 2, (c) understand which capability-map gap claims are doc bugs vs real gaps, and (d) recognise the four agentic-first invariants without needing to read the principle doc.

---

## 10. Out of Scope for This PR

- Implementing any P1 item (introspection, dashboard JSON, agent SSE, service accounts, error envelope) — those become roadmap issues 17.1–17.5.
- Implementing Issue 13.5 MCP write tools — already a roadmap issue.
- Filing GitHub issues for proposed Phases 17–18 — listed here; user decides when to file.
- Reconciling the README's broader content beyond the capability count line.
- Editing user-manual docs.

## 11. Diff Summary (for the PR description)

```
NEW   docs/agentic-first-principle.md              ~150 lines, A1–A4 invariants
NEW   docs/capability-agentic-audit-2026-05.md     this audit
EDIT  README.md                                    line 239 capability count
EDIT  docs/capability-map.md                       header caveat + §2.2 false-gap removal
EDIT  CLAUDE.md                                    glossary + 4 new routing rows
EDIT  docs/roadmap.md                              append proposed Phase 17 + Phase 18
EDIT  server/core/src/mcp_server.cpp               line 227-228 comment correction
```

No runtime behaviour changes. The mcp_server.cpp edit is comment-only.
