# Yuzu REST API Reference

This document covers every HTTP endpoint exposed by the Yuzu server. Endpoints are grouped by functional area.

---

## API Versioning

The Yuzu REST API uses path-based versioning. Understanding the distinction between versioned and legacy endpoints is important for building stable integrations.

> **Formal policy:** the binding cross-surface versioning & deprecation policy — covering REST **and** MCP tools, the additive-vs-breaking test, the deprecation cycle (announcement channels + minimum window), and MCP tool naming on breaking changes — is [`docs/api-versioning-policy.md`](../api-versioning-policy.md). This section is the REST summary.

### Versioned API (`/api/v1/`)

All endpoints under the `/api/v1/` prefix are the **stable, versioned API**. These endpoints:

- Use the standard JSON envelope (`data`, `error`, `meta`, `pagination` fields)
- Return `"api_version": "v1"` in the `meta` object of every response
- Follow consistent error handling with structured error objects
- Are the recommended integration target for all new automation and tooling
- Will maintain backward compatibility within the v1 version; breaking changes will increment to v2

### Legacy API (`/api/` without version prefix)

Endpoints under `/api/` without the `v1` prefix are **legacy endpoints** that predate the versioned API. These endpoints:

- Remain available for backward compatibility
- Do **not** use the standard v1 JSON envelope
- May return inconsistent error formats
- Are **deprecated** and will be removed per the deprecation cycle in [`docs/api-versioning-policy.md`](../api-versioning-policy.md) (a feature release, after the announced window)
- Should be migrated to their v1 equivalents where available

### Migration Guidance

When writing new integrations, always use `/api/v1/` endpoints. If you have existing scripts using legacy endpoints, plan to migrate them to v1 equivalents. The [Legacy API Endpoints](#legacy-api-endpoints) section below documents each legacy endpoint and notes where a v1 replacement exists.

### Response Headers

Every API response (versioned and legacy) carries the standard Yuzu HTTP security response headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Strict-Transport-Security` (HTTPS only). These headers add roughly 700–900 bytes per response — JSON consumers should expect this overhead. See [HTTP Security Response Headers](security-hardening.md#http-security-response-headers) for details, the full header list, and how to extend the CSP via `--csp-extra-sources` for browser dashboards that integrate with the Yuzu API.

#### `Sec-Audit-Failed` and the behavioural-PII audit posture

Routes that serve per-person behavioural / compliance PII (the `dex.device.view`, `dex.device.app_perf.view`, `guardian.device.view`, and `dex.signal.view` verbs) audit the access **before** serving. If that audit row cannot durably persist (audit DB locked/full, or an allocation failure), the gap is surfaced — never silently swallowed — but the posture differs by surface, by design:

- **REST JSON endpoints fail closed:** they return `503` + `Sec-Audit-Failed: true` and serve **no** data, so a machine integration (CMDB / ServiceNow / agentic worker) never records evidence-less PII as audited. Distinguish this transient, retryable `503` from a non-transient misconfiguration `503` by the presence of the `Sec-Audit-Failed` header.
- **Dashboard HTMX fragments set-and-proceed:** they set `Sec-Audit-Failed: true` but **still render**, so a transient audit hiccup never blanks a human operator's lens.
- **MCP tools set-and-proceed** with an `audit_persisted: false` field in the result (absent on success) — JSON-RPC has no response-header channel.

This is intentional cross-surface behaviour: during an audit-store blip a browsing operator sees data while a wired REST integration receives `503`. Alert on `Sec-Audit-Failed: true` (or `audit_persisted: false`) from any surface as a SOC 2 CC7.2 evidence-gap signal. (Mutating routes such as token/session revoke use the related `audit_emitted` body field — see those endpoints.)

A separate, narrower shape applies to ordinary mutation routes that audit a change **after** it already durably committed (not the behavioural-PII read routes above): `POST /api/v1/software-packages`, `POST /api/v1/software-deployments`, and its `.../start`, `.../rollback`, `.../cancel` actions. These **always set-and-proceed** — the mutation cannot be un-committed, so the response stays `2xx` and only `Sec-Audit-Failed: true` signals a dropped audit row, with no `audit_emitted`/`audit_persisted` body field. Treat the header the same way as the behavioural-PII surfaces: a CC7.2 evidence-gap signal, not an error.

---

## Table of Contents

- [API Versioning](#api-versioning)
- [Authentication](#authentication)
- [JSON Envelope](#json-envelope)
- [Pre-Auth Request Body Caps](#pre-auth-request-body-caps-2407)
- [REST API v1 Endpoints](#rest-api-v1-endpoints)
  - [Current User](#current-user)
  - [Devices](#devices)
  - [Management Groups](#management-groups)
  - [API Tokens](#api-tokens)
  - [Engine Principals](#engine-principals)
  - [Sessions](#sessions)
  - [Quarantine](#quarantine)
  - [Internal CA](#internal-ca)
  - [KEK Rotation](#kek-rotation)
  - [Engine Principals](#engine-principals)
  - [RBAC](#rbac)
  - [Tags](#tags)
  - [Definitions](#definitions)
  - [Product Packs](#product-packs)
  - [Response Templates](#response-templates)
  - [Audit Log](#audit-log)
  - [Access Reviews](#access-reviews)
  - [Policy Fragments](#policy-fragments)
  - [Policies](#policies)
  - [Compliance](#compliance)
  - [Runtime Configuration](#runtime-configuration)
  - [Settings](#settings)
  - [Custom Properties](#custom-properties)
  - [Webhooks](#webhooks)
  - [Offload Targets](#offload-targets)
  - [Directory Sync](#directory-sync)
  - [Enrollment](#enrollment)
  - [Network Discovery](#network-discovery)
  - [Workflows](#workflows)
  - [Workflows, Executions & Schedules — v1 read twins (#4030)](#workflows-executions--schedules--v1-read-twins-4030)
  - [Command/Instruction Responses — v1 read twins (#2146 A2-R2)](#commandinstruction-responses--v1-read-twins-2146-a2-r2)
  - [OpenAPI Spec](#openapi-spec)
  - [Discovery (A2)](#discovery-a2)
  - [Inventory](#inventory)
  - [Result Sets](#result-sets)
  - [Forensics](#forensics)
  - [Software Licensing (SLE)](#software-licensing-sle)
  - [Execution Statistics](#execution-statistics)
  - [Live-Query Bundles](#live-query-bundles)
  - [Device Tokens](#device-tokens)
  - [Pre-flight & Deploy](#pre-flight--deploy)
  - [Software Deployment](#software-deployment)
  - [License Management](#license-management)
  - [Topology](#topology)
  - [Fleet Statistics](#fleet-statistics)
  - [File Retrieval](#file-retrieval)
  - [Guaranteed State](#guaranteed-state)
- [Legacy API Endpoints](#legacy-api-endpoints)
  - [Commands](#commands)
  - [Agents](#agents)
  - [Help](#help)
  - [Instructions](#instructions)
  - [Instruction Sets](#instruction-sets)
  - [Executions](#executions)
  - [Schedules](#schedules)
  - [Approvals](#approvals)
  - [Audit (Legacy)](#audit-legacy)
  - [Scope Engine](#scope-engine)
  - [Data Export](#data-export)
  - [Responses](#responses)
  - [Tags (Legacy)](#tags-legacy)
  - [Analytics and NVD](#analytics-and-nvd)
  - [SSE Event Stream](#sse-event-stream) — includes `GET /events`, `GET /sse/executions/{id}`, and the agentic `GET /api/v1/events`
  - [Dashboard TAR](#dashboard-tar)
- [MCP (Model Context Protocol)](#mcp-model-context-protocol)
- [Authentication Endpoints](#authentication-endpoints)
- [SCIM v2 Provisioning](#scim-v2-provisioning)
- [Health](#health)
- [Metrics](#metrics)

---

## Authentication

Every request must be authenticated using one of three methods:

| Method | Header / Cookie | Example |
|---|---|---|
| Session cookie | `yuzu_session` cookie | Set automatically after `POST /login` |
| Bearer token | `Authorization: Bearer <token>` | `Authorization: Bearer yzt_a1b2c3d4...` |
| X-Yuzu-Token header | `X-Yuzu-Token: <token>` | `X-Yuzu-Token: yzt_a1b2c3d4...` |

Unauthenticated browser requests are redirected to `/login`. Unauthenticated API requests receive a `401 Unauthorized` response.

API tokens are created via `POST /api/v1/tokens` and can be scoped to the creating user's permissions. The raw token value is returned exactly once at creation time.

**Reserved headers — do not send.** Five header names are reserved for future
server-verifiable delegation and are **rejected on every endpoint** (sole
exception: the four unauthenticated health-probe paths, which ignore them —
see `docs/auth-architecture.md`) with `403` + the standard error envelope
(ADR-1005): `On-Behalf-Of`, `X-On-Behalf-Of`,
`X-Yuzu-On-Behalf-Of`, `X-Yuzu-Delegated-Operator`,
`X-Yuzu-Delegation-Artifact` (case-insensitive). A client must never assert
that it acts on another principal's behalf via a header; see
`docs/auth-architecture.md` ("On-behalf-of assertions rejected") for rationale
and the evolution path.

---

## JSON Envelope

All REST API v1 responses use a standard JSON envelope.

**Success (single object):**

```json
{
  "data": { ... },
  "meta": { "api_version": "v1" }
}
```

**Success (list):**

```json
{
  "data": [ ... ],
  "pagination": {
    "total": 42,
    "start": 0,
    "page_size": 50
  },
  "meta": { "api_version": "v1" }
}
```

**Error (A4 envelope):**

```json
{
  "error": {
    "code": 403,
    "message": "human-readable message",
    "correlation_id": "req-18f2a1c3d-2a",
    "retry_after_ms": null,
    "permission": "GuaranteedState:Read"
  },
  "meta": { "api_version": "v1" }
}
```

HTTP status codes follow standard conventions: `200` for success, `201` for resource creation, `400` for bad requests, `401` for unauthenticated, `403` for forbidden, `404` for not found, `503` for service unavailable. Every `/api/v1/*` error response uses the structured **A4 error envelope** (per [`docs/agentic-first-principle.md`](../agentic-first-principle.md) §A4), with the `code` field matching the HTTP status. The envelope's fields:

| Field | Always present | Meaning |
|---|---|---|
| `code` | yes | HTTP status echoed into the body for self-describing frames. |
| `message` | yes | One-sentence human-readable summary. |
| `correlation_id` | yes | A `req-<hex-ms>-<hex-seq>` token, also echoed on the `X-Correlation-Id` response header — join the response to server logs / audit rows by grepping this token. |
| `retry_after_ms` | yes (nullable) | `null` unless the condition is retryable, in which case it advises how many milliseconds to back off (e.g. a `503` warm-up returns `5000`). |
| `remediation` | when a hint exists | Natural-language self-recovery hint. Key is **omitted** when there is no hint (absence carries the same "no recovery available" meaning). |
| `permission` | on permission denials | The `"SecurableType:Operation"` the caller was denied (e.g. `"Tag:Write"`) — the §A4 *kPermissionDenied* specialisation. Absent on whole-route admin gates that are not tied to a single securable, and absent on most service-scoped-token confinement denials even where the route IS tied to one — the caller is denied regardless of grant, so naming one would be a false self-remediation claim (`docs/adr/1006-service-scope-default-deny.md`). One documented exception: a confinement denial that fires *after* the route's own permission gate already confirmed the caller holds that exact grant still names it — there `.permission` is informational, not a remediation hint (`.claude/routed-concerns-access-control.md`, "Service-scoped API token confinement" clause 5(a)). `GET /api/v1/inventory/software` no longer illustrates this — its after-gate deny was retired (#3290, provably dead: it fired after `perm_fn`, and the route migrated onto `require_fleet_read` entirely). No live example currently exists: an exhaustive check of every remaining `deny_fleet_wide_service_scoped` call site (20 in `rest_api_v1.cpp`, 5 in `mcp_server.cpp` as of #3290 Phase 2 bucket 1a) found none currently match this exception's shape (`.claude/routed-concerns-access-control.md`, "Service-scoped API token confinement" clause 5) — `deny_service_scoped_schedule` and the one MCP site that did fire after its gate (`get_dex_group_app_perf`) were retired outright, not left as non-matching candidates. The exception clause still governs the next one that appears. |
| `approval_id` + `status_url` | reserved | The §A4 *kApprovalRequired* specialisation. Reserved for the Phase-2 approval re-dispatch flow; not populated by current denials (an approval-gated operation is denied with `permission` + `remediation` today, because no pollable approval exists yet). `status_url` points at `GET /api/v1/approvals/{id}`. |

The R2 A4 completion (2026-07) routed the RBAC/tier denial gates (`require_admin`, `require_permission`, and the service-scope denials in the auth layer) and the ~156 legacy `error_json` sites in `rest_api_v1.cpp` through this one envelope. The #1552 sweep PR-1 (2026-09) converted 8 more route files — `auth_routes.cpp` (including its MFA-flow branches), `workflow_routes.cpp`, `webhook_routes.cpp`, `settings_routes.cpp`, `file_retrieval_routes.cpp`, `viz_routes.cpp`, `offload_routes.cpp`, and `sle_routes.cpp` (audited, already compliant via its own local builder) — so it does **not** yet cover literally every path, but the remaining gap is now precisely enumerated rather than open-ended: 7 more route files (`compliance_routes.cpp`, `discovery_routes.cpp`, `command_routes.cpp`, `dashboard_api_routes.cpp`, `notification_routes.cpp`, `schedule_routes.cpp`, `nvd_routes.cpp`, tracked as #1552's PR-2), roughly 86 hand-rolled sites still inline in `server.cpp` itself (not yet decomposed into a `*_routes.cpp` file), and the pre-routing chokepoint's own "no session" 401 (`server.cpp`, `{"error":{"code","message"},"meta"}` with no `correlation_id` — every unauthenticated `/api/v1/*` request hits this before any route's own A4 gate runs; tracked as #2003). Automation crossing surfaces should treat the enrichment fields as present-when-available until all three close.

**Per-principal quota cap (PR 4.4, ADR-1005 class engine principals).** REST traffic from an **engine principal** session (`principal_kind=="engine"`, username `engine:<slug>`) is subject to a per-principal cap enforced at the server's single pre-routing chokepoint — before the request reaches any route handler. Two independent dimensions are checked: an in-flight **concurrency** cap and a per-principal token-bucket **rate** cap (see `docs/user-manual/engine-principals.md` for the operator-facing tuning guide). Exhausting either dimension returns `429` with the standard A4 envelope plus an HTTP `Retry-After` header (whole seconds, rounded up from `retry_after_ms`):

```json
{
  "error": {
    "code": 429,
    "message": "per-principal rate limit exceeded",
    "correlation_id": "req-18f2a1c3d-2a",
    "retry_after_ms": 150,
    "remediation": "retry after retry_after_ms; reduce request rate"
  },
  "meta": { "api_version": "v1" }
}
```

`retry_after_ms` is honest per dimension: a rate rejection carries the token bucket's actual refill time, a concurrency rejection carries a fixed short backoff (250ms) since there is no natural "when will a slot free up" estimate. Streaming/SSE endpoints (`GET /api/v1/events`, `GET /events`, `GET /sse/executions/{id}`) take a concurrency slot held for the stream's lifetime (released when the stream ends), plus the rate debit — the same two caps as any other engine request (UP-1; an earlier revision of this primitive released the slot early at routing hand-off and treated streaming as rate-only, which left an engine principal able to open an unbounded number of concurrent streams — that gap is closed). This gate applies **only** to engine-principal sessions; human, device-agent, and anonymous traffic is unaffected. It is enforced **per server process** — a multi-replica deployment's effective ceiling is `configured_cap x replica_count`, not the configured cap alone (each replica enforces independently; not a fleet-wide cap). A quota rejection is metric-only (`yuzu_server_principal_quota_exhausted_total{side,limit}`, see `docs/user-manual/metrics.md`) — it does not write an audit row (see `docs/user-manual/audit-log.md`); every admitted request also increments the companion `yuzu_server_principal_quota_admits_total{side}` counter.

> **⚠ Breaking wire-shape change (upgrade note).** Many of those legacy `/api/v1` errors were previously emitted as **`{"error":"<string>"}`** (the single-arg `error_json`) or the older nested `{"error":{"code","message"}}`. They are now uniformly the nested A4 object above. A client that read `error` as a *string* (`String(body.error)`, `body.error.startsWith(...)`) will break — `error` is always an **object** on these paths now. Migrate to `body.error.code` / `body.error.message`. See `docs/user-manual/upgrading.md`.

---

## Pre-Auth Request Body Caps (#2407)

Every request is checked against a per-route body-size cap **before authentication runs and before the body is read** — a single pre-routing chokepoint (`server.cpp`) resolves the caller's `(method, path)` against the policy table in `body_cap_policy.hpp` and rejects an oversized or unmeasurable body without buffering it. **The four health-probe paths (`/livez`, `/readyz`, `/health`, `/api/health`) are NOT exempt from this gate** — the cap is a single lambda, `enforce_pre_auth_body_cap` in `server.cpp`'s pre-routing handler, invoked from exactly two sites: once INSIDE the probe branch, before its early return, and once after the on-behalf-of guard and the rate limiter for every other route. One definition, two call sites — so the probes cannot drift out of coverage without deleting a call. `tests/unit/server/test_body_cap_policy.cpp`'s "POST /health … is rejected (D3)" case exercises that DECISION on a real socket, but against a test server that reproduces the gate rather than invoking the production one, so it does not pin the wiring: deleting either call site in `server.cpp` would leave the suite green. Treat the wiring as verified by review, not by test, until that gap is closed. Before this fix the probes' early-return sat above the cap entirely, making them the server's last unauthenticated 100 MiB buffer — closing that was the point. The probes remain exempt from the on-behalf-of guard and the rate limiter that run further below (a header-stamping proxy or orchestrator must not be able to crash-loop the server by tripping either on its own liveness check) — that exemption is unchanged; only the body cap now also reaches them. Three status codes:

| Status | Meaning |
|---|---|
| `413` | The body's **declared `Content-Length`** exceeds the resolved cap for this route's class. |
| `411` | The body cannot be **measured** in advance **by framing** — chunked `Transfer-Encoding`, or a POST/PUT/PATCH with no `Content-Length` at all — and this route's class refuses that. **Two classes refuse an unmeasurable body today: `/mcp/` and `upload_session`** (`PUT /api/v1/uploads/{id}/chunk` and its sibling agent-facing upload routes) — every other class below falls through and is admitted up to httplib's own 100 MiB backstop, because chunked request bodies are legal HTTP and this repo does not control every client population talking to public REST/SCIM/upload routes. This is a deliberate per-class opt-in (`requires_measurable`), not a blanket rule. `upload_session` opts in for the same reason `/mcp/` does: its session gate lives in the route HANDLER, after httplib would otherwise buffer the body, so the pre-routing bound is what actually stops an unauthenticated caller forcing a ~100 MiB buffer per connection — the agent uploader always sends an identity-encoded body with a `Content-Length` (the protocol's `Content-Range` header requires knowing it), so this costs a conforming client nothing. A non-`identity` `Content-Encoding` is judged separately — see `415` below, not this row. |
| `415` | The request carries a `Content-Encoding` header set to anything other than `identity` (case-insensitive). Refused **unconditionally, on every route class, regardless of `requires_measurable`** — unlike the framing rule above, this does not depend on a per-class opt-in. Why: this build compiles `CPPHTTPLIB_BROTLI_SUPPORT`, httplib decompresses transparently and enforces only its 100 MiB global limit against the **decompressed** size, so `Content-Length` on a compressed body measures the wrong thing and a sub-cap compressed body can expand to ~100 MiB before anything downstream sees it. No Yuzu route accepts a compressed request body today, so this costs a conforming client nothing — send the body identity-encoded by **omitting `Content-Encoding` entirely**. Do **not** send `Content-Encoding: identity` explicitly: `has_non_identity_content_encoding` correctly admits it past this gate (it isn't a compressed encoding), but httplib's own body reader then calls `create_decompressor("identity")` — which matches none of gzip/deflate/br/zstd, returns null, and httplib answers a bare `415` itself (`httplib.h`'s `prepare_content_receiver`), before this gate, any route handler, or the A4/SCIM envelope code ever runs. That response carries none of the structure this section promises — no A4 envelope, no `correlation_id`, no `yuzu_body_cap_rejected_total` increment. Until that gap is closed at the code level, the only conforming way to send an identity-encoded body is to omit the header. |

All three responses use the standard [A4 error envelope](#json-envelope) with a `remediation` hint (no `permission` field — the request is rejected before any principal is resolved) — **except the `scim` class**, which publishes SCIM's own RFC 7644 §3.12 error shape (`schemas`/`status`/`detail`) on `application/scim+json` instead of the generic envelope (`scim::error()`, `scim_json.hpp:192`; wired into all three status codes above in `server.cpp`'s pre-routing handler). This gate is separate from, and runs *before*, any route-local body check a handler may also carry (e.g. the SCIM/response-template 64 KiB checks below) — those still exist for defense-in-depth if a future edit widens this table's entry, but on the current table this pre-routing gate rejects first. **This is not purely a timing change for every affected class.** For most (response templates, CA import), an earlier rejection at the same byte count is the entire effect. SCIM is **no longer** an exception to that either (fixed as part of this change, D7): the pre-routing rejection's SCIM shape matches the wording of the handler's own (now-superseded, and unreachable — the pre-routing cap and the handler check the identical 64 KiB threshold, so the pre-routing gate always wins first) `413` check exactly, and extends the same shape to the `411`/`415` cases the handler-level check never covered.

### Post-Read Backstop (#2407)

The pre-routing gate above is what stops an oversized body from being buffered at all — but it can only act on a **declared** size. Its structural limit, recorded in `body_cap_policy.hpp`'s KNOWN LIMITATION paragraph: on the 21 of 23 classes below that don't set `requires_measurable`, a genuine chunked (or otherwise undeclared) body is not size-checked by the pre-routing gate at all — it is admitted, up to httplib's own 100 MiB backstop, without that table's cap being consulted.

A second stage, wired at httplib's `Server::set_pre_request_handler` in `server.cpp`, closes that gap from the other side. It runs inside httplib's `dispatch_request` — **after** `read_content` has consumed the body off the socket into `req.body`, and after the route has matched, but **before the route's own handler runs**. At that point the body's actual size is known, so this stage resolves the SAME `kBodyCapTable`/`resolve_body_cap` the pre-routing gate uses (no forked table) and, if the now-fully-read body is over the class's cap, refuses with the same `413` A4/SCIM envelope shape and the same 1-in-100 per-reason log throttle as the pre-routing gate (tagged `[#2407 post-read]` in the journal rather than `[#2407]`). The rejection reason is a new value, `over_cap_post_read`, on `yuzu_body_cap_rejected_total{path_class,reason}` — pre-seeded at 0 for every class, unconditionally, unlike `unmeasurable`; see `docs/user-manual/metrics.md`'s `yuzu_body_cap_rejected_total` row for the full description.

**What an operator observes.** A chunked (or otherwise undeclared) body that exceeds its route class's cap is now refused — where it previously reached the route handler uncapped, bounded only by httplib's 100 MiB backstop. That is the change: the 21-of-23-class gap the pre-routing gate leaves open is now closed for a body that turns out, once read, to be over cap.

**The two stages are mutually exclusive per request, not stacked.** httplib's `routing()` returns as soon as the pre-routing handler answers Handled, so it never calls `dispatch_request` for a request that gate already refused — a **measurable** over-cap body (a declared `Content-Length` above the cap) is still rejected by the pre-routing gate, before anything is buffered, exactly as before this stage existed. Do not describe this as "the cap now runs twice" — in practice `over_cap_post_read` fires almost exclusively for the chunked/unmeasurable case the pre-routing gate deliberately admits.

**Limitations — read before relying on this as complete coverage:**

- **Multipart is not covered.** httplib only appends to `req.body` on the non-multipart branch of `read_content` (`httplib.h:11002` swaps the receiver for the multipart parser once it detects a multipart body) — so `req.body.size()` reads 0 for ANY multipart request, regardless of the real bytes read off the wire. **No multipart class is covered** — stated as a rule rather than a list, because an earlier draft of this text enumerated a single class and was wrong: `/api/settings/updates/upload` (`ota_upload`) and `/api/settings/cert-upload` (no table entry, so the 4 MiB default) are multipart too. Their chunked-body gap is **not** closed by this stage. This is not a regression introduced here — it is exactly as exposed as it was before this stage existed — but do not read the post-read stage as having closed coverage for every class.
- **The stage only runs when a route matched.** `set_pre_request_handler` is invoked from httplib's `dispatch_request`, which only runs once routing has matched a route — a request to a path that 404s never reaches this handler at all. It is a backstop behind the pre-routing gate for matched routes, not a second universal pre-auth gate.

**Why not one global cap?** httplib's own `Server::set_payload_max_length` is a single server-wide knob shared by every route on the same listener, including the ~70 MiB live-query bundle route and the OTA agent-binary upload — a single small value would break those outright, and a single large value (httplib's 100 MiB default) leaves every small JSON/form route able to buffer up to 100 MiB from an unauthenticated caller. The table below exists so each route class gets a cap sized to what it actually needs.

### Per-class caps

Derived directly from `server/core/src/body_cap_policy.hpp`'s `kBodyCapTable` (longest matching `{method, path prefix}` wins; do not hand-copy these numbers elsewhere — that header is the source of truth):

| Method | Path prefix | Cap | `path_class` | Notes |
|---|---|---|---|---|
| any | `/mcp/` | 4 MiB | `mcp` | One of two classes with `requires_measurable=true` — see the 411 row above. |
| POST | `/api/v1/bundles` | 70 MiB | `bundles` | Sized to the live-query bundle route's own computed 64 MiB parameter-byte floor plus JSON overhead headroom. |
| any | `/api/v1/uploads` | 8 MiB | `upload_session` | The other `requires_measurable=true` class. Exact mirror of the PR1.6a chunked-receive protocol's own `kDefaultChunkMaxBytes` (`upload_grant_parsers.hpp`), bound to it by a `static_assert` in `file_retrieval_routes.cpp` so the two cannot drift. Any method — the session-open POST, chunk PUT, status GET, commit POST, and cancel DELETE all share this class; only the chunk PUT carries a large body, but scoping to PUT alone would silently drop the sibling verbs to the 4 MiB catch-all. |
| any | `/api/v1/plugin-config` | 256 KiB | `plugin_config` | † The store's own grammar caps a config value at 8 KiB and a secret plaintext at 64 KiB (`plugin_config_parsers.hpp`); 256 KiB covers the larger of the two plus JSON framing/escaping headroom, while keeping an unauthenticated flood against this surface two orders of magnitude under the 4 MiB catch-all. Any method — PUT config/secret writes, DELETE carries no body, GET/list are bodyless. |
| POST | `/api/settings/updates/upload` | 100 MiB | `ota_upload` | Kept at httplib's own backstop deliberately, not squeezed — OTA agent binaries are legitimately multi-ten-MB. |
| POST | `/api/export/json-to-csv` | 100 MiB | `json_to_csv_export` | Unbounded by design — converts a full exported dataset to CSV, and its size follows directly from the caller's own prior query. Kept at httplib's backstop, same treatment as `ota_upload`, rather than squeezed or given an arbitrary MiB judgment-call number. |
| POST | `/api/nvd/match` | 8 MiB | `nvd_match` | ‡ No aggregate contract; reasoned to this content's own realistic scale (one device's software census, generously overestimated at ~200 bytes/item ⇒ 40000+ items) rather than borrowed from a sibling class. |
| POST | `/api/v1/ca/import-chain` | 256 KiB | `ca_import_chain` | Mirrors the handler's own 256 KiB bound exactly. |
| POST | `/api/v1/ca/issue-code-signing` | 64 KiB | `ca_issue_code_signing` | Code-signing leaf issuance via CSR custody (gap-matrix #10); mirrors the handler's own `kMaxIssueCodeSigningBody` exactly. |
| POST | `/api/v1/ca/revoke` | 64 KiB | `ca_revoke` | Mirrors the handler's own `kMaxRevokeBody` exactly. |
| POST | `/api/v1/secrets/kek/` | 64 KiB | `kek_ops` | Covers both `/rotate` and `/rewrap` — both take zero body fields and share the handler's own `kMaxKekBody`. |
| POST | `/api/settings/ca/import-chain` | 512 KiB | `ca_import_chain_dashboard` | † 2× the REST JSON twin's cap — reasoned headroom for form-encoding overhead, not a measured worst case. |
| POST | `/api/settings/plugin-signing/upload` | 512 KiB | `plugin_trust_bundle` | † 2× the handler's 256 KiB parsed-content check — same reasoned multipart-framing headroom, not measured. |
| POST | `/scim/v2/` | 64 KiB | `scim` | Matches the handler's own `kMaxBodyBytes`; moves an existing after-buffer check to before it — but the rejection's error SHAPE changes, see the SCIM caveat above. |
| PUT | `/scim/v2/` | 64 KiB | `scim` | Same. |
| PATCH | `/scim/v2/` | 64 KiB | `scim` | Same. |
| POST | `/saml/acs` | 1 MiB | `saml_acs` | A legitimate signed `SAMLResponse` is well under 64 KiB; headroom against amplification, not judgment. |
| POST | `/api/v1/definitions/` | 64 KiB | `response_templates` | Widest literal prefix the segment-boundary matcher can key on for the regex-captured `{id}`/`{template_id}` routes underneath; a future mutation route added elsewhere under this prefix inherits it unless it gets its own, more specific entry. |
| PUT | `/api/v1/definitions/` | 64 KiB | `response_templates` | Same. |
| POST | `/api/dashboard/tar-execute` | 16 KiB | `tar_dashboard_sql` | † The handler checks the FORM-DECODED `sql` field at 4096 chars, not the raw body this gate sees — 3× worst-case percent-encoding of that 4096-char value, plus 4 KiB flat headroom for field-name framing and the companion `scope` field. The as-shipped 4 KiB cap matched the raw body to the decoded-field number directly and rejected legitimate queries (measured: a 4085-char query produced a 5078-byte body, 24% over that cap) — fixed here. |
| POST | `/api/v1/result-sets/from-tar-query` | 200 KiB | `tar_result_set_sql` | † The handler checks the JSON-PARSED `sql` field at 100000 chars; 2× that for JSON-escaping headroom plus the request's other keys. The as-shipped 100 KiB cap left only ~2400 bytes of margin over the 100000-char check, which JSON escaping alone can exceed — fixed here. The handler answers `400` for its own condition; this gate answers `413` for a raw body over 200 KiB — these are two different checks on two different values, not one check enforced twice. |
| POST | `/api/v1/guaranteed-state/rules` | 16 MiB | `guardian_rule_authoring` | ‡ **Judgment call, not a measurement** — no aggregate Guardian-rule-size contract exists yet anywhere in the codebase. |
| PUT | `/api/v1/guaranteed-state/rules/` | 16 MiB | `guardian_rule_authoring` | ‡ The sibling update route — same class, same bound. (As shipped, this route fell through to the 4 MiB catch-all, so a rule created up to 16 MiB could never be edited back through the same-sized route; fixed here.) |
| POST | `/api/workflows` | 16 MiB | `workflow_yaml` | ‡ Judgment call, same reasoning — arbitrary YAML/legacy `yaml_source` bodies with no size contract yet. No PUT/PATCH update route exists for this class today. |
| POST | `/api/product-packs` | 16 MiB | `product_pack_yaml` | ‡ Judgment call, same reasoning — a pack can hold multiple YAML documents, so it needs at least the same headroom as workflow authoring. No PUT/PATCH update route exists for this class today. |
| POST | `/api/instructions/import` | 16 MiB | `instruction_import` | ‡ No aggregate contract — the embedded `yaml_source` field IS hard-capped at 1 MiB, but an optional `responseTemplates` array supplied as native JSON has no size limit at all, so the whole-request bound is still a judgment call. Same 16 MiB peer bound as the three classes above. |
| POST | `/api/instructions/yaml` | 3076 KiB | `instruction_yaml` | † The handler checks the FORM-DECODED `yaml_source` field at 1048576 chars (`instruction_yaml.cpp:165`); 3× worst-case percent-encoding of that value, plus 4 KiB flat headroom for field-name framing and the `id` field (save only). |
| POST | `/api/instructions/validate-yaml` | 3076 KiB | `instruction_yaml` | † Same check, same margin — see above. |
| POST | `/fragments/instructions/yaml-preview` | 3076 KiB | `instruction_yaml` | † Same check, same margin — see above. |
| any | `/api/v1/hardware` | 4 KiB | `hardware` | The third `requires_measurable=true` class. Only `POST .../sync` carries a body (a single short `source` enum token); the bodyless `GET /api/v1/hardware` and `GET /api/v1/hardware/{id}` list/record routes share the class rather than falling to the 4 MiB catch-all. |
| any (catch-all) | *(empty prefix — matches everything not listed above)* | 4 MiB | `default` | Applies to ordinary JSON/form mutation routes not called out individually. |

† = a reasoned margin over a real, cited handler-level check — the pre-routing gate sees the RAW body while the handler checks a DECODED/PARSED value (form-decoded, JSON-unescaped, or multipart-extracted), so the two numbers are never expected to match exactly. Reasoned headroom, not a measured worst case; getting the margin wrong rejects legitimate traffic (the `tar_dashboard_sql`/`tar_result_set_sql` history above is a shipped example).
‡ = a generous, explicit, judgment-call bound because no aggregate size contract exists for that class yet, reasoned against that class's OWN realistic scale rather than copy-pasted from a sibling — **not** a fixed multiple below httplib's 100 MiB backstop: it ranges from ~12.5× for the 8 MiB `nvd_match` entry (just over one order of magnitude) down to 6.25× for the six 16 MiB entries (under one order of magnitude) — none of the ‡ entries reach two orders of magnitude. Do not read either footnote as license to invent a number for a different route — see the header block of `body_cap_policy.hpp`.

Counting by table **ROW** (one `BodyCapEntry` struct in `kBodyCapTable` = one row): **8 rows carry †** (`plugin_config`, `ca_import_chain_dashboard`, `plugin_trust_bundle`, `tar_dashboard_sql`, `tar_result_set_sql`, and all three `instruction_yaml` rows) and **6 rows carry ‡** (`nvd_match`, both `guardian_rule_authoring` rows, `workflow_yaml`, `product_pack_yaml`, `instruction_import`) — **14 rows total**, out of **27 rows** in the table overall. Counting by **CLASS** (`path_class`; several classes span multiple rows) that collapses to **6 † classes and 5 ‡ classes — 11 classes total**, out of **23 classes** overall. Every other row/class mirrors a cited, decoded-equals-raw byte count exactly (this now includes `upload_session`, added alongside `plugin_config` in this table — an exact protocol-constant mirror, not a reasoned margin, so it carries neither footnote). A third, unmarked category (`ota_upload`, `json_to_csv_export`) is pinned at httplib's own 100 MiB backstop as an explicit, reviewed decision rather than squeezed or given a judgment-call number — neither is "reasoned" in the † /‡ sense, since there is no smaller number to reason toward.

**Raising a cap.** Edit the table in `body_cap_policy.hpp` (with review) and update this table to match — never reach for `Server::set_payload_max_length`, which is global across every route on the listener (see "Why not one global cap?" above). See also `docs/user-manual/server-admin.md`'s upgrade note for this change and `docs/user-manual/metrics.md`'s `yuzu_body_cap_rejected_total` row for observing rejections.

---

## REST API v1 Endpoints

All endpoints are under the `/api/v1/` prefix.

---

### Current User

#### `GET /api/v1/me`

Returns the authenticated user's identity and role.

**Permission:** Authenticated session (no specific RBAC permission required).

**Response:**

```json
{
  "data": {
    "username": "admin",
    "role": "admin"
  },
  "meta": { "api_version": "v1" }
}
```

---

### Devices

The fleet device list and single-device identity read (#4033, #2146 API-parity Batch A) — the
REST twins of the `/devices` dashboard's `list_agents`/`get_agent_details`-shaped MCP tools.
Both routes are gated via `AuthRoutes::require_fleet_read` (the admit-then-filter chokepoint),
not a bare permission check — a management-group-confined operator and a correctly-confined
service-scoped token both see a real, filtered subset of the fleet rather than either the whole
fleet or an outright denial. Neither route is audited on a successful read: device identity
(hostname/OS/arch/version) is machine metadata, not behavioural PII — matching the
`/fragments/devices/list`, `/fragments/device/page`, and `/fragments/device/info` dashboard
fragments' own unaudited posture.

#### `GET /api/v1/devices`

List every device visible to the caller.

**Permission:** `Infrastructure:Read`, via `require_fleet_read`.

**Response:**

```json
{
  "data": {
    "devices": [
      {
        "agent_id": "a1b2c3d4e5f6",
        "hostname": "web-01",
        "os": "linux",
        "arch": "x86_64",
        "agent_version": "0.13.1"
      }
    ],
    "count": 1,
    "devices_omitted": 0
  },
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

`devices_omitted` counts agents dropped by the caller's management-group/service-scope
confinement (0 when unfiltered or nothing was dropped) — the same "out of my scope" vs. "not
present" signal `GET /api/v1/inventory/software`'s `devices_omitted` field carries.

---

#### `GET /api/v1/devices/{id}`

Fetch one device's identity.

**Permission:** `Infrastructure:Read`, via `require_fleet_read`.

**Response:**

```json
{
  "data": {
    "agent_id": "a1b2c3d4e5f6",
    "hostname": "web-01",
    "os": "linux",
    "arch": "x86_64",
    "agent_version": "0.13.1",
    "tags": [
      { "key": "environment", "value": "production", "source": "server" }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

`tags` is always present (`[]` when the device has no tags, or in the never-hit-in-production case
of an unwired TagStore). A device outside the caller's fleet-read scope returns the SAME 404 as a
genuinely nonexistent `agent_id` — an out-of-scope match is never distinguishable from "does not
exist" in the response body (matches the pre-existing MCP `get_agent_details` tool's
existence-oracle closure exactly).

---

### Management Groups

Management groups organize agents into a hierarchy for access scoping. Groups can be **static** (manually assigned members) or **dynamic** (membership determined by a scope expression evaluated against agent tags and properties).

#### `GET /api/v1/management-groups`

List all management groups.

**Permission:** `ManagementGroup:Read`

**Response:**

```json
{
  "data": [
    {
      "id": "a1b2c3d4e5f6",
      "name": "EU Production Servers",
      "description": "All production endpoints in EU datacenters",
      "parent_id": "",
      "membership_type": "static",
      "scope_expression": "",
      "created_by": "admin",
      "created_at": 1710849600,
      "updated_at": 1710849600
    },
    {
      "id": "f6e5d4c3b2a1",
      "name": "Windows Desktops",
      "description": "Dynamic group for all Windows endpoints",
      "parent_id": "",
      "membership_type": "dynamic",
      "scope_expression": "os = 'windows'",
      "created_by": "admin",
      "created_at": 1710850000,
      "updated_at": 1710850000
    }
  ],
  "pagination": { "total": 2, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/management-groups`

Create a new management group.

**Permission:** `ManagementGroup:Write`

**Request body:**

```json
{
  "name": "EU Production Servers",
  "description": "All production endpoints in EU datacenters",
  "parent_id": "",
  "membership_type": "static",
  "scope_expression": ""
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Unique group name |
| `description` | string | No | Human-readable description |
| `parent_id` | string | No | ID of parent group (empty for root) |
| `membership_type` | string | No | `"static"` (default) or `"dynamic"` |
| `scope_expression` | string | No | Scope engine expression for dynamic groups |

**Response (201):**

```json
{
  "data": { "id": "a1b2c3d4e5f6" },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/management-groups/{id}`

Get a single group's details including its current members.

**Permission:** `ManagementGroup:Read`

**Response:**

```json
{
  "data": {
    "id": "a1b2c3d4e5f6",
    "name": "EU Production Servers",
    "description": "All production endpoints in EU datacenters",
    "parent_id": "",
    "membership_type": "static",
    "scope_expression": "",
    "created_by": "admin",
    "created_at": 1710849600,
    "updated_at": 1710849600,
    "members": [
      {
        "agent_id": "agent-eu-prod-01",
        "source": "static",
        "added_at": 1710850000
      },
      {
        "agent_id": "agent-eu-prod-02",
        "source": "static",
        "added_at": 1710850100
      }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

The group row is read through `ManagementGroupStore::get_group_checked` and its
members through `get_members_checked` (#1762). A store-not-open /
pool-acquire-timeout / query-error degrade on EITHER read returns `503` (A4
envelope, `retry_after_ms: 2000`) rather than a `404` or an authoritative empty
`members: []`; `404` now always means the group does not exist. The MCP twin
`get_management_group` fails the same way.

---

#### `PUT /api/v1/management-groups/{id}`

Update a management group. Only the fields provided in the request body are changed; omitted fields retain their current values.

**Permission:** `ManagementGroup:Write`

**Request body:**

```json
{
  "name": "EU Production Servers (Renamed)",
  "description": "Updated description",
  "parent_id": "f6e5d4c3b2a1",
  "membership_type": "dynamic",
  "scope_expression": "os = 'linux' AND tag:environment = 'production'"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | New group name (must be unique) |
| `description` | string | No | Updated description |
| `parent_id` | string | No | New parent group ID (empty string for root-level) |
| `membership_type` | string | No | `"static"` or `"dynamic"` |
| `scope_expression` | string | No | Scope engine expression for dynamic groups |

**Validation rules:**

- The root group (`000000000000`, "All Devices") cannot be re-parented. Attempting to set `parent_id` on the root group returns `400`.
- **Self-parent:** A group cannot be set as its own parent. Returns `400`.
- **Cycle detection:** The new parent must not be a descendant of the group being updated. Moving a group under one of its own children would create a circular hierarchy and returns `400`.
- **Depth limit:** Re-parenting must not exceed the maximum hierarchy depth of 5 levels. Returns `400` if exceeded.

All validation runs at the `ManagementGroupStore` layer as well as the REST handler, so non-REST administrative callers cannot bypass cycle or depth checks.

**Response:**

```json
{
  "data": { "updated": true },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- cycle detected:**

```json
{
  "error": "re-parenting would create a cycle",
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- self-parent:**

```json
{
  "error": "group cannot be its own parent",
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- depth exceeded:**

```json
{
  "error": "maximum hierarchy depth (5) exceeded",
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- root group re-parent:**

```json
{
  "error": "cannot re-parent root group",
  "meta": { "api_version": "v1" }
}
```

**Error (503) -- store unavailable:**

Cycle and depth validation walk the hierarchy via recursive ancestor/descendant
reads against the `management_group_store` Postgres substrate (ADR-0042). If
those reads degrade (store not open, connection-pool acquire timeout, or a query
error) the re-parent cannot be validated safely, so it **fails closed with 503**
rather than risk applying an unvalidated move — the caller did nothing wrong, the
store did. This is distinct from the `400` validation errors above (a genuinely
bad request); retry a `503` once the substrate recovers.

```json
{
  "error": "management group store unavailable",
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/management-groups/{id}`

Delete a management group. The root group ("All Devices", ID `000000000000`) cannot be deleted and returns `403 Forbidden`. Deleting a group cascade-deletes all child groups, their membership records, and their role assignments.

**Permission:** `ManagementGroup:Delete`

**Response:**

```json
{
  "data": { "deleted": true },
  "meta": { "api_version": "v1" }
}
```

**Error (403) -- root group:**

```json
{
  "error": "cannot delete root group",
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/management-groups/{id}/members`

Add an agent to a static management group.

**Permission:** `ManagementGroup:Write`

**Request body:**

```json
{
  "agent_id": "agent-eu-prod-03"
}
```

**Response (201):**

```json
{
  "data": { "added": true },
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/management-groups/{id}/members/{agent_id}`

Remove an agent from a management group.

**Permission:** `ManagementGroup:Write`

**Response:**

```json
{
  "data": { "removed": true },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/management-groups/{id}/roles`

List role assignments scoped to this management group.

**Permission:** `ManagementGroup:Read`. This response is authorization
topology (who holds what role), so the fleet-wide arm actually authorizing
it is the floored `UserManagement:Read` (#2376), not `ManagementGroup:Read`
itself — see [the authorization topology floor](../security-reviews/authz-topology-floor-2026-08-05.md).
A caller lacking that also succeeds if they are `ITServiceOwner` **of this
specific group** (a scoped fallback, not the fleet-wide grant) — but a
service-scoped API token cannot use that fallback (guardian-confinement-2298
PR 3): the fallback checks group membership only, never the token's own
service-tag scope, and a service-scoped token is denied outright rather
than risk it reaching a group outside its own service.

**Response:**

```json
{
  "data": [
    {
      "group_id": "a1b2c3d4e5f6",
      "principal_type": "user",
      "principal_id": "jane.ops",
      "role_name": "Operator"
    },
    {
      "group_id": "a1b2c3d4e5f6",
      "principal_type": "user",
      "principal_id": "bob.viewer",
      "role_name": "Viewer"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/management-groups/{id}/roles`

Assign a role to a principal within this management group. Only the `Operator` and `Viewer` roles can be delegated. The caller must be a global Administrator or hold the `ITServiceOwner` role on this group.

**Permission:** Global `ManagementGroup:Write` or `ITServiceOwner` on this group. A service-scoped API token is denied outright, even one whose minter holds `ITServiceOwner` on this exact group (guardian-confinement-2298 PR 3) — the group-scoped fallback checks membership only, never the token's own service-tag scope.

**Request body:**

```json
{
  "principal_type": "user",
  "principal_id": "jane.ops",
  "role_name": "Operator"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `principal_type` | string | No | `"user"` (default) or `"group"` |
| `principal_id` | string | Yes | Username or group name |
| `role_name` | string | Yes | `"Operator"` or `"Viewer"` only |

**Response (201):**

```json
{
  "data": { "assigned": true },
  "meta": { "api_version": "v1" }
}
```

**Error (403) -- non-delegatable role:**

```json
{
  "error": "only Operator and Viewer roles can be delegated",
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/management-groups/{id}/roles`

Remove a role assignment from this management group.

**Permission:** Global `ManagementGroup:Write` or `ITServiceOwner` on this group. Same service-scoped-token denial as `POST` above.

**Request body:**

```json
{
  "principal_type": "user",
  "principal_id": "jane.ops",
  "role_name": "Operator"
}
```

**Response:**

```json
{
  "data": { "unassigned": true },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/management-groups/agent-count-preview`

Preview the number of currently-visible agents that would match a would-be management group's
filter criteria, before creating it (#4033, #2146 API-parity Batch A). REST/MCP/dashboard-fragment
twin of `/fragments/create-group-form`'s own live count. This route and its MCP twin call the same
shared builder (`group_agent_count_preview.hpp`), so those two cannot drift from each other; the
dashboard fragment keeps its own separate, behaviourally-equivalent inline implementation
(`DashboardRoutes::parse_filters`), unchanged by this PR — the number it shows and this route's
`agent_count` are expected to agree today, but are not structurally guaranteed to. MCP twin:
`preview_management_group_agent_count`.

**Permission:** `ManagementGroup:Write` — matching the fragment's own gate exactly (only an
operator who could create the group may preview it), **not** `ManagementGroup:Read`, even though
this route performs no mutation.

**Query parameters:**

| Parameter | Description |
|---|---|
| `command_id` | The response set's instruction/command id to count against. |
| `plugin` | Plugin name whose response columns the filter keys are matched against. |
| `<filter keys>` | Any other query param is treated as a filter, keyed by the SAME mangling the dashboard fragment's `f_<column>` params apply to a column name — lowercase, spaces/dashes replaced with underscores (e.g. `Local Addr` → `local_addr`). Unlike the fragment, this route's keys carry **no** `f_` prefix — supply `local_addr`, not `f_local_addr`. An unrecognised key is silently ignored. |

An empty filter set (no recognised filter keys supplied) returns a genuine `0` — no scoped count
to report, and no store read is made.

**Response:**

```json
{
  "data": { "agent_count": 42 },
  "meta": { "api_version": "v1" }
}
```

---

### API Tokens

API tokens provide non-interactive authentication for scripts and automation. Tokens are scoped to the creating user's permissions. The raw token string is returned exactly once at creation time and cannot be retrieved afterward.

**Storage failure:** if the server's token store database failed to open at startup (bad data directory, permissions), all three token endpoints return `503` with message `service unavailable` rather than `404` or an empty list, so automation can distinguish a server-side outage from a missing token. Note that Bearer-token *authentication* against an unavailable token store deliberately fails closed with `401`, not `503` — an automation client seeing unexpected `401`s during an outage should check server health (`/readyz` reports `api_token_store`) before rotating credentials.

#### `GET /api/v1/tokens`

List the current user's API tokens. Raw token values are never returned.

**Permission:** `ApiToken:Read`

**Response:**

```json
{
  "data": [
    {
      "token_id": "a1b2c3d4",
      "name": "CI Pipeline Token",
      "principal_id": "admin",
      "created_at": 1710849600,
      "expires_at": 1742385600,
      "last_used_at": 1710936000,
      "revoked": false
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

**Rotation fields (P2 #11):** `rotation_group`, `supersedes_token_id`, `overlap_expires_at`, and `confirmed_at` appear on an item **only** while a rotation is (or was) in flight for that token — a token that has never been rotated omits all four. `rotation_group` is present on **both** the predecessor and the successor row of an in-flight pair (it links them); `supersedes_token_id` is present only on the successor and equals the predecessor's `token_id`; `overlap_expires_at` is present on the predecessor while the overlap window is open (the epoch it is auto-revoked); `confirmed_at` is present once an explicit `credentials/confirm`-style confirmation (below) has closed the rotation. A caller that only checks for the absence of these fields on a fresh token needs no code change — they were not serialized before P2 #11 either.

---

#### `POST /api/v1/tokens`

Create a new API token. The raw token is returned in the response and is never shown again. Store it immediately.

**Permission:** `ApiToken:Write`

**Request body:**

```json
{
  "name": "CI Pipeline Token",
  "expires_at": 1742385600,
  "mcp_tier": "readonly"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Human-readable label |
| `expires_at` | integer | No | Unix epoch seconds. `0` or omitted = never expires. **Required** for MCP tokens (max 90 days). |
| `mcp_tier` | string | No | MCP authorization tier: `"readonly"`, `"operator"`, or `"supervised"`. Omit for standard API tokens. When set, `expires_at` is mandatory. |

`mcp_tier` is honored at mint time (a value outside `readonly`/`operator`/`supervised` is rejected). A tiered (`mcp_tier` set) or service-scoped token also requires a valid `expires_at` within the 90-day cap. Setting `scope_service` requires RBAC to be enabled and either a global `ManagementGroup:Write` grant or `ITServiceOwner` on the `"Service: <scope_service>"` management group — see [Service-Scoped Tokens](authentication.md#service-scoped-tokens).

**Validation errors (`400`):**

| Condition | Response |
|---|---|
| `mcp_tier` is not one of `readonly` / `operator` / `supervised` | `400` — `invalid mcp_tier: must be one of readonly, operator, supervised (or omitted)` |
| `mcp_tier` set (or `scope_service` set) but `expires_at` omitted / `≤ 0` | `400` — `expires_at is required for an MCP-tier or service-scoped token` |
| `mcp_tier` set and `expires_at` is more than 90 days out | `400` — `MCP token TTL cannot exceed 90 days` |

**Response (201):**

```json
{
  "data": {
    "token": "yzt_a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678",
    "name": "CI Pipeline Token"
  },
  "meta": { "api_version": "v1" }
}
```

> **Warning:** Copy the `token` value immediately. It cannot be retrieved after this response.

---

#### `DELETE /api/v1/tokens/{token_id}`

Revoke an API token. The token becomes immediately unusable.

**Permission:** `ApiToken:Delete`

**Ownership constraint:** A caller with `ApiToken:Delete` may only revoke tokens they created. The global `admin` role is the sole bypass and may revoke any token. Attempting to revoke another user's token returns `404 token not found` — identical to the response for a token that does not exist — so the endpoint cannot be used as an enumeration oracle by a non-owner with `ApiToken:Delete`. Denied attempts are recorded in the audit log with `action=api_token.revoke`, `result=denied`, and `detail=owner=<real owner>` so forensics can distinguish a probe from a legitimate self-revoke.

The same ownership constraint applies to the HTMX dashboard path `DELETE /api/settings/api-tokens/{token_id}`.

**Response:**

```json
{
  "data": { "revoked": true },
  "meta": { "api_version": "v1" }
}
```

**Error (404) -- token not found or not owned by caller:**

```json
{
  "error": {
    "code": 404,
    "message": "token not found"
  },
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/tokens/{token_id}/rotate`

Self-service overlap-pair rotation of a human-owned API token (P2 #11, SOC 2 CC6.3): mints a successor token while the existing (predecessor) token stays valid for an overlap window — at most **two** active tokens in the rotation group during the overlap. `{token_id}` in the path is the **predecessor's** id. The raw successor secret is returned exactly once per reveal (see the grace-window re-serve note below), the same discipline the engine-principal `credentials/rotate` route above uses. MFA step-up runs on **every** call to this route, including an idempotent re-serve.

**Permission:** `ApiToken:Rotate` — a DISTINCT operation from `ApiToken:Write` (round-4 security finding): `ApiToken:Write` also gates `POST /api/v1/tokens` (mint) and its settings twin, so a shared op would let an operator-tier MCP token mint a brand-new, caller-chosen-tier token — a privilege escalation, not a parity fix. See `mcp_policy.hpp`'s `tier_allows()` operator-tier comment for the full analysis. Under the default RBAC-off configuration, this permission is reachable by any non-admin owner (#2963 legacy self-service allowlist) — ownership, not role, is what actually gates who can succeed; see [Rotating a Token](authentication.md#rotating-a-token) for the operator-facing explanation.

**Ownership constraint — self-service only, no admin bypass:** unlike `DELETE /api/v1/tokens/{token_id}` above, there is **no** admin override here. A human token's raw successor secret authenticates *as that user*, so an admin rotating or confirming someone else's token would hand out (or complete the cutover of) a credential that impersonates them — identity takeover, not a permission gap an admin role could legitimately cross. An admin who needs to act on another user's token still has `DELETE` (revoke). Attempting to rotate a token you do not own returns `404 token not found` — identical to the response for a token that does not exist, closing the same enumeration-oracle gap the DELETE route closes. Denied attempts are recorded in the audit log with `action=api_token.rotate`, `result=denied`, and `detail=owner=<real owner>`.

**Request body (optional):**

```json
{ "overlap_secs": 604800 }
```

`overlap_secs` defaults to 7 days (`604800`), with the same 24-hour floor / 10-year ceiling as the engine-principal rotate route — a value outside that range is rejected (`400`), never silently clamped.

**Lifetime-neutral by design (SOC 2 CC6.3):** the successor token **always inherits the predecessor's `expires_at` verbatim** — a perpetual (never-expiring) token stays perpetual, a 30-day token stays a 30-day token measured from its *own* original grant, never recomputed as "90 days from now". There is **no request field** to override this; the store-level `successor_expires_at` override that exists internally for the engine-principal arm is deliberately not exposed on this route. Rotating a credential must never silently extend its authorization lifetime — an auditor reviewing rotation evidence for CC6.3 must be able to trust that rotation and grant renewal are two separate, independently-audited actions, never one fused into the other. A caller that genuinely needs a longer-lived replacement token should mint a fresh one via `POST /api/v1/tokens` instead.

**Response:** same `Cache-Control: no-store, no-cache, must-revalidate` + `Pragma: no-cache` headers as `POST /api/v1/tokens`, since the body carries a raw one-time secret.

```json
{
  "data": {
    "token": "yzt_...",
    "token_id": "...",
    "expires_at": 1742385600,
    "overlap_expires_at": 1710936000
  },
  "meta": { "api_version": "v1" }
}
```

`token_id` and `expires_at` describe the **successor**, found structurally — the active row whose `supersedes_token_id` equals `{token_id}` (the predecessor being rotated), never merely "any linked row of this principal's active set" and never by "most recently created" (which is second-resolution and can tie). A human principal routinely holds several unrelated tokens with independent in-flight rotations, so the match must be scoped to the exact predecessor in the path — a broader match can return a *different* rotation's successor.

`overlap_expires_at`, by contrast, describes the **predecessor** — consistent with the `GET /api/v1/tokens` field of the same name above (§"Rotation fields"): it is stamped on the predecessor row, not the successor, and is echoed here purely for the caller's convenience (the epoch at which the predecessor this call just rotated is auto-revoked). There is no separate `overlap_expires_at` on the successor row itself; do not expect one from `GET /api/v1/tokens` until the successor is itself rotated in turn.

**Success audit:** `action=api_token.reveal` — the reveal itself is the success event, mirroring the engine-principal route's `engine_principal.credential.reveal`; a grace-window re-serve gets its own row too, since every time the raw secret leaves the server is independently on the audit chain.

**Errors:**

| Condition | Response |
|---|---|
| No such token, or the token exists but is not owned by the caller | `404` — `token not found` (identical body; not an enumeration oracle) |
| The token exists and IS owned by the caller, but the caller's OWN current `mcp_tier`/`scope_service` (from their authenticated session) does not equal the token's own (the authority-inheritance guard), AND the caller holds SOME non-empty `mcp_tier`/`scope_service` of its own — a caller holding NO standing tier/scope at all (an untiered dashboard/cookie session) is instead admitted regardless of the token's own tier/scope (#2963; the successor still inherits the token's own tier/scope, never the caller's) | `400` — `no such token to rotate` (store-level; distinct from the route's own `404` pre-check above, and worded identically to the absent/not-owned case on purpose, so this is not an authority-probing oracle either — see [Rotating a Token](authentication.md#rotating-a-token) for the operator-facing explanation) |
| `overlap_secs` present in the body but not an integer (e.g. a string) | `400` — `overlap_secs must be an integer (seconds)` |
| Overlap window below the 24h floor, or above the 10-year ceiling | `400` |
| Overlap window would outlive the predecessor's or the successor's own expiry — by design, a token within 24h of its own expiry cannot be rotated (rotation is lifetime-neutral, so there is no way to shrink the overlap below the 24h floor to fit); mint a new token instead | `400` |
| The token is not a human-owned credential (an engine-principal credential somehow reached this route) | `400` — `token is not a human-owned credential` |
| The token is revoked or already expired | `400` — `credential is not currently active — nothing to rotate` |
| Two active tokens in the rotation group exist but are not a recognized predecessor/successor pair | `400` — resolve via revoke, not rotate |
| More than two active tokens in the rotation group | `400` — resolve manually before rotating |
| A rotation already in flight, initiated by a **different** operator | `409` |
| Grace window elapsed with no confirm | `409` — `grace window elapsed; confirm or revoke` |
| No active credential found to rotate | `503` — deliberately conflated with a transient read failure, same rationale as the engine-principal rotate route above |
| The rotation itself succeeded (a successor token now exists) but the follow-up read that locates it for the response came back empty | `503` — fails CLOSED rather than return a raw one-time secret with no `token_id` to ever confirm it against; retry, or check `GET /api/v1/tokens` |
| Advisory-lock acquire failure, CSPRNG failure, or a mint/stamp write that did not persist | `503` — retryable store failure |
| MFA step-up not satisfied | `401` |
| Missing `ApiToken:Rotate`, or the caller's own session is engine-classed (structural deny belt) | `403` |

---

#### `POST /api/v1/tokens/{token_id}/confirm`

Explicit maker-checker confirmation that a rotation's successor secret has been received and installed. `{token_id}` in the path is the **successor's** id — the value the `rotate` response above returned. On success, the predecessor token is revoked and the successor becomes the sole active token in the rotation group.

**Permission:** `ApiToken:Rotate` (same distinct-operation rationale as `rotate` above)

**Proof of possession (#3015, SOC 2 CC6.3) — BREAKING:** unlike before, a request body is now required — `{"secret": "<raw successor secret>"}`, the raw successor secret `rotate` returned. Confirm revokes the predecessor immediately, so it must never proceed on `token_id` alone — a caller who merely learned or guessed the (non-secret) successor `token_id` could otherwise force an immediate cutover without ever having received the new credential. A caller that previously confirmed with only the `{token_id}` path parameter now gets `400`. The check is performed immediately after auth/step-up, **before** the ownership/existence lookup below, so a missing secret is `400` even against an unowned or nonexistent token_id — it is never an enumeration oracle either way, since neither response discloses whether the token exists.

**Request body (required):**

```json
{ "secret": "yzt_..." }
```

`secret` is verified last, strictly after the ownership check and every store-side admission check (pair-state, the successor pin, the authority-inheritance guard) have passed — via a constant-time hash comparison against the successor's stored hash, read fresh inside the same advisory-locked transaction as the rest of this call. It is never persisted, logged, or echoed into an audit/error string.

**Ownership constraint:** the same self-service-only posture as `rotate` above — no admin bypass, `404 token not found` for both a nonexistent successor id and one owned by someone else, and the same `action=api_token.confirm`/`result=denied`/`detail=owner=<real owner>` audit row on a denied attempt.

**Response:**

```json
{
  "data": { "confirmed": true },
  "meta": { "api_version": "v1" }
}
```

**Errors:** the same state matrix as the engine-principal `credentials/confirm` route above (replay-after-success is a terminal `409`, an ambiguous empty/malformed-pair read is a retryable `503`, unresolved rotation metadata on the sole survivor is a terminal `409`), substituting `token is not a human-owned credential` / `principal has a non-human active credential` for the engine-kind equivalents. `401`/`403` follow the same step-up and permission rules as `rotate`. The same authority-inheritance `400` — `no such token to confirm` also applies here, as defence-in-depth only (see the `rotate` error matrix row above, including the #2963 empty-tier/scope exception). **This is not a same-session pin** — the caller confirming does not have to be the same session that called `rotate`; ownership and the raw successor secret (proof of possession) are the actual gates on who may confirm. The check re-verifies that the CALLER'S CURRENT `mcp_tier`/`scope_service` equals the successor's own (or the caller holds no standing tier/scope at all, #2963) — since the successor's tier/scope are fixed at mint time and cannot legitimately diverge from the predecessor's, this defense-in-depth check is not reachable as a live path today for a caller presenting the correct current authority, outside a future bypass of `rotate`'s own guard.

`secret` missing, empty, or not a string is `400` — `secret required` (checked before the `404` ownership belt, see above). A wrong secret is `403` — `rotation secret mismatch — the presented secret does not verify against the pending successor` — distinct from every other outcome, reachable only after every other admission check has already passed. If the authoritative successor row cannot be re-read to verify the secret (should not happen under the lock already held), that's a fail-closed `503` — `failed to verify rotation secret`, folded into the general store-failure `503` row above.

---

### Engine Principals

Engine principals are the durable identities behind autonomous use-case-engine modules (ADR-1005 item 2b) — a distinct principal class from human users and human-created API tokens, with a named responsible human owner, a grant justification captured at creation, and a required `internal`/`external` classification. Design reference: `docs/auth-engine-principals-design.md`. Every credential minted against an engine principal is hard-locked to MCP tier `readonly` and can never be granted the admin/wildcard role ("no admin, ever" — independently provable via the auditor route below).

**Every *mutating* route is admin + MFA-step-up gated.** The read routes (`GET`/list, `GET /{id}`, and `GET /audit/no-admin`) are admin + RBAC gated (`EnginePrincipal:Read` for the two engine-principal reads, `AuditLog:Read` for `/audit/no-admin`) but do **not** require a fresh MFA step-up. Beyond that, every route — reads included — structurally denies a caller whose *own* session is engine-classed (`principal_kind="engine"` or `auth_source="engine_token"`): an engine principal can never enumerate, read, or mutate any entry on this surface, not even itself. A denied engine-classed caller gets `403`; the corresponding audit verb is recorded with `result=denied`.

**Storage failure:** if the engine-principal store failed to open at startup (no PostgreSQL configured, or a migration failure), every route on this surface returns `503 service unavailable`.

**Audit-persist failure (fail closed on mutations):** these routes emit a privileged-action audit row, and a mutation that cannot record it must never look like a clean success. If the audit-store write itself fails, every **mutating** route (create, revoke, transfer-owner, `credentials`/`credentials/rotate`/`credentials/confirm`, and the role assign/unassign routes documented later) **fails closed** — it returns `503` with a `Sec-Audit-Failed: true` header instead of its normal `2xx` (ADR-1005 "mutations fail closed on audit failure"). The mutation may already have taken effect (the audit is emitted after the store write), so treat such a `503` as *unconfirmed* and reconcile via a read. This is a stricter posture than the software-package/deployment mutations elsewhere in this API, which set-and-proceed (stay `2xx` with `Sec-Audit-Failed`) on the same audit-drop: engine-principal management is a privileged-identity surface, so ADR-1005 holds it to fail-closed rather than proceed-and-signal.

The credential **mint** and **rotate** routes additionally **withhold the one-time secret** on this path — nothing is placed in the `503` body. Recovery differs by route: a **mint** whose audit dropped leaves a credential that exists but is unusable (no one holds its secret) — `GET` the principal to see it, then **rotate** it (mints an audited successor you can then confirm) to obtain a usable secret; a **rotate** whose reveal-audit dropped can be **rotated again within the overlap window** to re-serve the *same* successor secret (an audited re-serve, not a new credential). Note the compounding case under a *sustained* audit outage: repeated mint/rotate failures can leave two unconfirmed credentials, at which point the store's ≤2-active guard blocks further rotation — recover by revoking one unconfirmed credential and re-minting once the audit store is healthy.

The **read** routes (`GET`/list, `GET /{id}`, `GET /audit/no-admin`, `GET /{id}/roles`) and the engine-session denial above instead set the same `Sec-Audit-Failed: true` header but still serve their response — matching the MCP twins' `audit_persisted:false` body field. Reads proceed (rather than fail closed like the behavioural-PII device/network reads) because they commit no state and disclose only authorization **topology metadata** — principal ids, owners, role grants — not per-person behavioural PII; the fail-closed-on-read posture exists specifically to keep individual-identifying data off an unaudited response, which does not apply here. Alert on `Sec-Audit-Failed: true` from this surface as a SOC 2 CC7.2 evidence-gap signal (the same alert that covers the behavioural-PII routes fires on it), while noting the serve behaviour differs: these reads still return data, those withhold it.

**`{id}` convention:** on every route below (`GET /{id}`, `DELETE /{id}`, the `credentials`/`credentials/rotate`/`credentials/confirm`/`transfer-owner` sub-resources), `{id}` is the **full** `principal_id`, i.e. `engine:<slug>` (e.g. `GET /api/v1/engine-principals/engine:vuln-uce`) — none of these routes prepend the `engine:` prefix themselves. This is the opposite convention from the `.../{id}/roles` role-assignment sub-resource documented later in this file, where `{id}` is the **bare slug** and the server reconstructs the full id internally — don't assume the two sections share one convention.

#### `POST /api/v1/engine-principals`

Create a new engine-principal identity. `principal_id` is derived server-side as `"engine:" + slug` — the reserved `engine:` namespace.

**Permission:** `Security:Write`

**Request body:**

```json
{
  "slug": "vuln-uce",
  "display_name": "Vuln UCE",
  "owner_username": "alice",
  "classification": "internal",
  "justification": "First-party vulnerability-management use-case engine module"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `slug` | string | Yes | 1-128 chars; becomes `principal_id = "engine:" + slug`. |
| `display_name` | string | No | UI/audit label. |
| `owner_username` | string | Yes | Must reference an existing user (FK-validated before the row is written). |
| `classification` | string | Yes | Exactly `"internal"` or `"external"` — required at creation, no default and no silent fallback. |
| `justification` | string | Yes | Grant justification, feeds periodic access review. Rejected empty (store-level check, `400` — `justification cannot be empty`). |

`display_name` is accepted but **not actually enforced non-empty by the REST route or the store** — an empty/omitted `display_name` is persisted as-is; contrast with the `create_engine_principal` MCP tool, which additionally rejects an empty `display_name` at the tool layer (see `docs/user-manual/mcp.md`).

**Validation errors (`400`):**

| Condition | Response |
|---|---|
| `slug` empty | `400` — `slug is required` |
| `slug` longer than 128 chars | `400` — `invalid_input_length: slug exceeds 128 chars` |
| `slug` contains characters outside `[a-z0-9._-]` | `400` — store validation error (`principal_id slug may only contain lowercase letters, digits, '.', '_', '-'`) |
| `owner_username` empty or does not reference an existing user | `400` — `owner_username must reference an existing user` |
| `classification` missing or not `internal`/`external` | `400` — store validation error |
| `justification` empty | `400` — store validation error (`justification cannot be empty`) |
| The create audit row could not persist | `503` + `Sec-Audit-Failed: true` — the principal may already have been created (audit is emitted after the store write); reconcile via `GET` (see *Audit-persist failure* above) |

**Response (201):**

```json
{
  "data": { "principal_id": "engine:vuln-uce" },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/engine-principals`

List every engine principal (all lifecycle states), with each principal's active-credential count.

**Permission:** `EnginePrincipal:Read`

**Response:**

```json
{
  "data": [
    {
      "principal_id": "engine:vuln-uce",
      "display_name": "Vuln UCE",
      "owner_username": "alice",
      "classification": "internal",
      "lifecycle_state": "active",
      "created_at": 1710849600,
      "active_credential_count": 1
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 1 },
  "meta": { "api_version": "v1" }
}
```

**Errors:** `503` — engine-principal store not open (see Storage failure above). A transient read failure on an open store returns an empty list rather than an error — this route does not otherwise fail.

---

#### `GET /api/v1/engine-principals/{id}`

Get one engine principal's full identity row plus its active credentials (token id, name, timestamps, rotation group, overlap-expiry — never the raw secret; `token_hash` stays masked). `active_credentials` here is an **array** of credential objects — contrast with the list route above (`active_credential_count`, an integer) and with the MCP `get_engine_principal` twin, whose `active_credentials` field is an integer count under the same field name (see `docs/user-manual/mcp.md`).

**Permission:** `EnginePrincipal:Read`

**Errors:** `404` — engine principal not found. `503` — engine-principal store unavailable (not open, or the read itself failed).

---

#### `DELETE /api/v1/engine-principals/{id}`

Terminal, irreversible revoke. Every active credential is revoked **first**, then the identity's `lifecycle_state` flips to `revoked` — a caller can never observe a revoked identity with a still-valid credential. Idempotent in the sense that calling this on an already-revoked principal still returns `200` success (never an error) — but it is **not** audit-idempotent: a repeat call **re-emits** a fresh `engine_principal.revoke` success audit row each time, recording the repeat operator action (with `credentials_revoked=0` on the repeat, since there is nothing left to revoke), not just the original revoke.

**Permission:** `Security:Write`

**Request body (optional):**

```json
{ "superseded_by": "engine:vuln-uce-2" }
```

`superseded_by` is an optional successor-principal id recorded on this row for audit-trail continuity — recovery from a compromised or retired principal mints a fresh successor principal rather than un-revoking this one.

**Response:**

```json
{
  "data": { "revoked": true, "credentials_revoked": 1 },
  "meta": { "api_version": "v1" }
}
```

**Errors:** `404` — engine principal not found. `503` — a genuine store failure at any step of the sequence (the principal lookup, the credential-store revoke, or the identity revoke itself) — never an idempotent no-op; credentials are revoked strictly before the identity, so a `503` here never leaves the identity flipped to `revoked` while a credential is still live. `503` + `Sec-Audit-Failed: true` — the revoke audit row could not persist (see *Audit-persist failure* above); the revoke may already have taken effect, so reconcile via `GET`.

---

#### `POST /api/v1/engine-principals/{id}/credentials`

Mint the **first** credential for an engine principal. The raw secret is returned exactly once in this response — capture it immediately; it cannot be retrieved again, only rotated (below) or revoked. A second call against a principal that already has an active credential returns `409` — use the rotate route once a credential exists.

**Permission:** `Security:Write`

**Request body (optional):**

```json
{ "ttl_days": 90 }
```

`ttl_days` defaults to `90` and must be between `1` and `90` (`400` otherwise — the engine-credential ceiling matches the tiered-token 90-day cap elsewhere on this surface).

**Response (201):** headers carry `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache` so a shared proxy or browser history never retains the secret.

```json
{
  "data": { "token": "yzt_...", "token_id": "...", "expires_at": 1760000000 },
  "meta": { "api_version": "v1" }
}
```

`token` is the raw secret (shown once); `token_id` and `expires_at` let a pure-REST caller correlate the credential it just minted without a follow-up `GET`.

**Errors:** `404` — engine principal not found. `409` — engine principal is not active (revoked), **or** the principal already has an active credential (mint is single-shot; use `credentials/rotate` instead). `400` — `ttl_days` out of range. `503` — CSPRNG failure or any other store failure (a CSPRNG failure also sets `Retry-After: 5` and increments `yuzu_secure_random_failure_total{reason="prng_failure",site="engine_principal"}`). `503` + `Sec-Audit-Failed: true` — the mint audit row could not persist: the credential was created but its **one-time secret is withheld** (never in the body), so the credential exists but is unusable — see *Audit-persist failure* above for recovery.

---

#### `POST /api/v1/engine-principals/{id}/credentials/rotate`

Overlap-pair rotation (design doc §7): mints a successor credential while the existing (predecessor) credential stays valid for an overlap window — at most **two** active credentials per principal during the overlap. The raw successor secret is returned exactly once per **reveal** (see below for the grace-window exception). MFA step-up runs on **every** call to this route, including an idempotent re-serve — a rotate call is never exempt from step-up just because it returns a secret the caller already saw.

**Permission:** `Security:Write`

**Request body (optional):**

```json
{ "overlap_secs": 604800 }
```

`overlap_secs` defaults to 7 days (`604800`). The overlap window has a **24-hour floor** and a 10-year ceiling — a value below the floor (or above the ceiling) is rejected outright (`400`), never silently truncated up to the floor.

**Grace-window re-serve:** a same-caller retry within a ~120-second grace window after the original mint re-serves the **same** successor secret (rather than erroring or minting a second successor). Each successful return — the original reveal or a grace-window re-serve — is independently recorded under its own `engine_principal.credential.reveal` audit row, since every time the raw secret leaves the server is independently on the audit chain, whether or not the bytes are new. Once the grace window lapses, a further rotate call while a rotation is already in flight errors — the caller must fall back to `credentials/confirm` (below) or the principal-level revoke-and-replace runbook, never an indefinite retry loop.

**Response:** same no-store headers as the mint route; the `data` object adds `overlap_expires_at` (the epoch at which the predecessor is auto-revoked) alongside `token`, `token_id`, and `expires_at`.

**No `404` path:** unlike `credentials` (mint) and `transfer-owner`, this route never looks up `{id}` via a `get()` call before acting — it drives the rotation state machine straight off the principal's active credential rows. An unknown or revoked `{id}` therefore does **not** 404.

**Errors:**

| Condition | Response |
|---|---|
| Overlap window below the 24h floor, or above the 10-year ceiling | `400` |
| Overlap window would outlive the predecessor's or the successor's own expiry | `400` |
| Exactly one active credential exists, but the engine-principal referent it would mint a successor against is unknown or revoked | `400` — `engine principal not found or revoked` |
| Two active credentials exist but are not a recognized rotation pair (predecessor/successor linkage broken) | `400` — resolve via revoke, not rotate |
| More than two active credentials exist for this principal | `400` — resolve manually before rotating |
| A rotation already in flight, initiated by a **different** operator | `409` — a second operator cannot touch an in-flight rotation they didn't start |
| Grace window elapsed with no confirm | `409` — `grace window elapsed; confirm or revoke` |
| No active credential found for this principal to rotate | `503` — **not** `400`/`404`. Deliberately conflated with a transient read failure: the internal read that finds "no active credential" cannot be told apart from a silently-failed read, so a genuine "nothing to rotate" is classified as retryable (503) rather than a definitive client error — treating it as 400 could otherwise mislead a caller into minting a redundant second credential during what was actually a transient outage. |
| A non-engine-kind active credential is present for this principal (defensive check) | `503` |
| Advisory-lock acquire failure, CSPRNG failure, the engine-referent check itself being unreachable, or a mint/stamp write that did not persist | `503` — retryable store failure |
| The reveal audit row could not persist | `503` + `Sec-Audit-Failed: true` — the successor was minted but its **one-time secret is withheld**; rotate again within the overlap window to re-serve the *same* audited successor secret (see *Audit-persist failure* above) |
| MFA step-up not satisfied | `401` |
| Missing `Security:Write`, or the caller's own session is engine-classed (structural deny belt) | `403` |

---

#### `POST /api/v1/engine-principals/{id}/credentials/confirm`

Explicit maker-checker confirmation that a rotation's successor secret has been received and installed by its consumer. This is a **separate attestation** from the `rotate` reveal above — it is never inferred from a successful rotate call. On success, the predecessor credential is revoked and the successor becomes the principal's sole active credential (closing the overlap window early, ahead of the auto-revoke sweep).

**Permission:** `Security:Write`

**Proof of possession (#3015, SOC 2 CC6.3) — BREAKING:** the request body now also requires `secret`, the raw successor secret `rotate` returned. Confirm revokes the predecessor immediately, so it must never proceed on `token_id` alone — a caller who merely learned or guessed the (non-secret) successor `token_id` could otherwise force an immediate cutover without ever having received the new credential. A caller that previously confirmed with only `token_id` now gets `400`. The presented secret is verified last, strictly after every other admission check (ownership, pair-state, the `token_id` pin, and the initiator binding below) has passed — so a wrong secret from a caller who fails an earlier check gets that check's own non-disclosing error, never a secret-specific one; only a caller who has already cleared every other gate can reach the mismatch outcome.

**Request body:**

```json
{ "token_id": "a1b2c3d4e5f60718293a4b5c", "secret": "eng_..." }
```

`token_id` (required) is the successor's token id **returned by the `rotate` response above** — it pins this confirm to that exact rotation. A stale or mismatched id (for example a blind retry of an old confirm after a *second* rotation has started) is rejected with `409` and **no state change**, so a replayed confirm can never resolve a later rotation early. The success audit row records the confirmed id (`token_id=<id>`).

`secret` (required) is the raw successor secret from the `rotate` response — never persisted, logged, or echoed into an audit/error string. Missing, empty, or non-string is `400` — `secret required`. Verified via a constant-time hash comparison against the successor's stored hash, read fresh inside the same advisory-locked transaction as the rest of this call; a wrong secret is `403` — `rotation secret mismatch — the presented secret does not verify against the pending successor` — distinct from every other outcome below, since it is reachable only after every other gate has already passed.

Replaying a confirm **after its own success** (a network-dropped `200`, a double-submit) is a terminal `409` conflict, not a retryable `503`: once the rotation has resolved the successor is the sole active credential, and the confirm returns an explicit `already confirmed` / `already resolved` answer with no state change. Treat it as done and stop retrying (rotate again only if you genuinely need a fresh rotation). See the error table below for the full state matrix.

**Response:**

```json
{
  "data": { "confirmed": true },
  "meta": { "api_version": "v1" }
}
```

Like `credentials/rotate` above, this route never looks up `{id}` via a `get()` call before acting — there is no `404` path here either.

**Errors:**

| Condition | Response |
|---|---|
| `token_id` missing from the body, empty, not a string, or the body is malformed/non-object JSON | `400` — `token_id required` |
| `secret` missing from the body, empty, or not a string (#3015) | `400` — `secret required` — checked immediately after the `token_id` presence check, before the store is ever reached |
| The supplied `token_id` is not the pending rotation's successor (stale id from an earlier rotation, or the predecessor's id passed by mistake) | `409` — `token_id does not match the pending rotation successor; pass the token_id returned by rotate`. No state change. |
| Confirm attempted by a **different** operator than the one who initiated the rotation | `409` — `rotation in progress by a different operator` |
| The initiating operator cannot be resolved from either source — the in-memory grace-cache entry is gone (different replica, or this replica restarted) **and** the durable `rotation_initiator` column on the successor row is empty (the pair started rotating before the durable-binding migration shipped) — or the two sources are both present but disagree | `409` — `rotation confirmation unavailable — fall back to revoke`. A plain same-replica restart mid-overlap no longer triggers this: the successor row's own `rotation_initiator`, stamped durably at mint time, resolves the identity check when the in-memory grace cache is gone. |
| **Replay after the rotation already resolved** — the successor is now the principal's sole active credential and the supplied `token_id` matches it | `409`, terminal, **do not retry**: `rotation already confirmed - the supplied token_id is the sole active credential; nothing to confirm` (an explicit confirm resolved it) or `no rotation in flight - the supplied token_id is already the sole active credential; nothing to confirm` (never rotated, or resolved by the auto-revoke sweep or a manual revoke) |
| One credential is active with its rotation state clear, but the supplied `token_id` is a **different** id (the pinned rotation has moved on) | `409`, terminal — `no rotation in flight for the supplied token_id - the rotation was resolved (confirmed, revoked, or cut over); rotate again if a new rotation is needed` |
| One credential is active but still carries **unresolved rotation metadata** (a best-effort pair-resolve failed, or its partner expired before cleanup while the sweep was down) | `409` — `one active credential with unresolved rotation metadata - inspect the credential state and do not rotate; revoke only if it is confirmed stale`. Rotating from here would strand a malformed pair; **inspect before revoking** — in the sweep-outage case this sole credential is the good survivor. |
| **More than two** active credentials for this principal (one minted outside the rotation path) | `400` — `more than two active credentials for this principal - resolve manually before confirming` |
| No active credentials, or exactly two that aren't a recognized rotation pair | `503` — **not** `400`. Ambiguity-avoidance: an empty read can't be distinguished from a silently-failed read, and a malformed pair is kept conservative, so these stay retryable rather than a definitive client error. |
| A non-engine-kind active credential is present for this principal (defensive check) | `400` — `principal has a non-engine active credential` |
| **The presented `secret` does not hash-match the pending successor's stored secret (#3015 proof of possession)** — reached only after ownership/pair-state/the `token_id` pin/the initiator binding above have all passed | `403` — `rotation secret mismatch — the presented secret does not verify against the pending successor` |
| The confirm audit row could not persist | `503` + `Sec-Audit-Failed: true` — the rotation was confirmed (predecessor retired) but its audit row did not persist (see *Audit-persist failure* above); a retried confirm returns the terminal `409` (the rotation is already resolved — the replay row above), which itself confirms the mutation took effect |
| The authoritative successor row could not be re-read to verify the secret (should not happen under the lock already held; fails closed rather than assume a match) | `503` — `failed to verify rotation secret` |
| Advisory-lock acquire failure, or the confirm/predecessor-revoke/successor-clear write did not persist | `503` — retryable store failure |
| MFA step-up not satisfied | `401` |
| Missing `Security:Write`, or the caller's own session is engine-classed | `403` |

---

#### `POST /api/v1/engine-principals/{id}/transfer-owner`

Reassign the named responsible owner of an active engine principal. Admin-forced — deliberately does **not** depend on the outgoing owner's cooperation (an account under termination-for-cause cannot use engine-principal ownership as a lever to stall its own deprovisioning).

**Permission:** `Security:Write`

**Request body:**

```json
{ "new_owner": "bob" }
```

`new_owner` must reference an existing user (FK-validated).

**Response:**

```json
{
  "data": { "transferred": true },
  "meta": { "api_version": "v1" }
}
```

**Errors:** `400` — `new_owner must reference an existing user`. `404` — engine principal not found. `409` — engine principal is not active. `503` — the transfer call itself failed. `503` + `Sec-Audit-Failed: true` — the transfer audit row could not persist (see *Audit-persist failure* above); the transfer may already have taken effect, so reconcile via `GET`.

---

#### `GET /api/v1/engine-principals/audit/no-admin`

Auditor-runnable, independent proof that "no admin, ever" and "no all-permissions toggle" hold for every engine principal — not merely a claim about the write-path guard. Resolves each engine principal's actual role assignments and effective permissions against the live RBAC reference tables and reports any violation: a literal `admin`/`Administrator` role grant, any role flagged `is_system`, or a granted securable × operation set whose size reaches the full cross-product (functionally admin-equivalent even under a custom, non-system role name).

**Permission:** `AuditLog:Read` — deliberately **not** `Security`, since this is a read-only evidentiary query, not part of the write-path bar it verifies; a read-only auditor role can run it without holding engine-principal write access.

**Response:**

```json
{
  "data": { "ok": true, "violations": [] },
  "meta": { "api_version": "v1" }
}
```

An empty `violations` array with `ok:true` is the positive evidence. A non-empty `violations` array (each entry carrying `principal_id`, `role`, and `reason` — `admin_role` / `system_role` / `wildcard_grant`) indicates the write-path guard was bypassed (data corruption, direct DB write, or a code regression) and should be treated as a security incident.

**Error (503):** `rbac reference data unavailable — cannot verify` — the RBAC reference tables (`securable_types`/`operations`) could not be resolved, so the wildcard-grant bound cannot be computed. This is a fail-**closed** result: treat it as "unable to verify," never as "clean."

---

### Sessions

Operator and dashboard sessions are the cookie-based sessions issued by `POST /login`. The endpoints below let an admin force-log-out another user from every device, and let any authenticated principal sign out of every browser at once. They are the SOC 2 CC6.3 (revocation) and CC6.8 (termination) evidence path; both endpoints emit auditable actions distinguishable by SIEM correlation.

The DB primitive (`AuthDB::invalidate_all_sessions`) and the in-memory counterpart already fire when a user is removed (`DELETE /api/settings/users/{username}`) or when their role changes; these REST endpoints expose the same primitive standalone for incident response and operator self-service.

#### `DELETE /api/v1/sessions?username=<name>`

Revoke every active cookie session for a named user. The user remains valid (no role change, no account disable); they simply have to authenticate again to obtain a new session cookie. **API tokens belonging to the user are deliberately NOT revoked** — operators force-logging out a leaked cookie session typically want to leave CI/CD and automation tokens running. Use `DELETE /api/v1/tokens/{token_id}` (or the user's own `DELETE /api/v1/sessions/me`) to revoke those.

**Permission:** `UserManagement:Write`

**Self-target behaviour.** An admin invoking this with their own username is permitted (signing yourself out of every device is recoverable — re-authenticate and you are back), but the audit row is recorded as `session.revoke_all.self` instead of `session.revoke_all` so SIEM rules can split operator self-service from a sibling-admin force-logout. This is a deliberately weaker guard than the `#397/#403` self-target guard on `DELETE /api/settings/users/{username}`, which exists to prevent admin-role self-lockout (an unrecoverable state).

**Example:**

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "https://yuzu.example.com/api/v1/sessions?username=alice"
```

**Response (200):**

```json
{
  "data": {
    "username": "alice",
    "revoked": 2,
    "db_persisted": true,
    "audit_emitted": true
  },
  "meta": { "api_version": "v1" }
}
```

`revoked` is the number of sessions wiped (the fleet-wide durable count on a Postgres-backed deployment, or the local cookie count in the config-file-only fallback). `db_persisted` reports whether the durable session delete succeeded — since HA WS-1/1a this goes through the durable `SessionStore` (`invalidate_user`), never AuthDB. When `false`, the audit row is recorded with `result="partial"` and `detail` carries `db_error=true`. **Remediation: retry** — the durable delete is idempotent, so re-issuing the request converges. **A server restart does NOT revoke the sessions:** durable sessions survive a restart by design (ADR-2002 §4), so a session that failed to be revoked stays valid until its absolute 8-hour expiry, not "resurrected" by restart. The local cache is wiped on this replica regardless (the operator's "stop NOW" intent is honoured there immediately), but the durable rows — and any other replica's cache — are only cleared once the delete actually lands.

`audit_emitted` reports whether the SOC 2 CC6.6 audit row landed in the audit store. When `false` the response also sets the `Sec-Audit-Failed: true` header — SREs scraping for evidence-integrity gaps should alert on either signal. The revoke side-effect still completes when `audit_emitted=false` (operator's "stop NOW" intent is honoured); only the SOC 2 evidence chain is degraded for that request. This split was introduced in PR #883 (HIGH-2) to close a silent-failure window where a locked audit DB or disk-full condition produced a 200 OK that masqueraded as full evidence.

**Audit:** successful cross-user invocations emit `session.revoke_all` with `target_type=User`, `target_id=<username>`, and `detail=count=<N>` (or `count=<N> db_error=true` on partial failure). When the caller's own username is supplied, the action is `session.revoke_all.self` instead.

The admin route emits two distinct 400 bodies — operators scripting the endpoint should distinguish them.

**Error (400) -- missing `username` query parameter:**

```json
{
  "error": { "code": 400, "message": "username query parameter required" },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- malformed `username` value:**

```json
{
  "error": { "code": 400, "message": "invalid username format" },
  "meta": { "api_version": "v1" }
}
```

The `username` parameter accepts either a strict local username OR a durable SSO principal (`is_valid_principal`, #1852) — an **OIDC** principal (`oidc:<iss>#<sub>`) or, since ADR-2001 PR4a, a **SAML** principal (`saml:<entity_id>#<NameID>`), so an admin can force-log-out an SSO operator authenticated via either protocol. Local usernames stay on the strict alphanumeric/`._-` charset; an SSO principal permits the `: # / . _ - @ ~ % |` alphabet a real IdP issuer URL and opaque subject need. NUL bytes, control characters, newlines, and shell/SQL metacharacters (`;`, `=`, `\`, quotes, backtick, space) are rejected in both cases — passing them through to the SQL bind would silently truncate/diverge from the audited target string (sec-H1). A 400 with the `invalid username format` message indicates the client has malformed input; retrying with the same value will not succeed.

**SAML sessions are now force-loggable (ADR-2001 PR4a).** A SAML session's `Session::username` is the stable principal `saml:<entity_id>#<NameID>` (`saml_principal_id`, mirroring the OIDC shape exactly), not the raw NameID — `create_saml_session` mints it via the `saml:` reserved prefix, which `is_valid_principal` accepts on the same wider SSO charset as `oidc:`. An admin can therefore force-log-out a SAML operator with:

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "https://yuzu.example.com/api/v1/sessions?username=saml%3Aentity-id%23NameID"
```

(URL-encode the `:` and `#`.) SAML sessions are also revoked automatically as part of SCIM deprovision — see "SCIM ↔ SAML identity linkage" in `docs/user-manual/scim-provisioning.md`, which covers the NameID-Format precondition for that automatic linkage. This closes the gap previously tracked as #1859/#1860.

**Error (403) -- caller lacks `UserManagement:Write`:**

```json
{
  "error": { "code": 403, "message": "forbidden" },
  "meta": { "api_version": "v1" }
}
```

#### `DELETE /api/v1/sessions/me`

Self-revoke "Sign out everywhere". Wipes every cookie session belonging to the authenticated caller AND revokes every API token they own. This is intended as the lost-device recovery flow: every credential bearing the caller's identity is killed in one call.

**Permission:** Any interactive authenticated session (cookie). MCP-tier tokens and service-scoped automation tokens are explicitly rejected with 403 — those credential classes have no other write privilege and accepting them here would create a novel DoS surface against the human owner. Use the dashboard or a fresh password-authenticated session.

**Example:**

```bash
curl -s -X DELETE \
  -H "Cookie: yuzu_session=$COOKIE" \
  "https://yuzu.example.com/api/v1/sessions/me"
```

**Response (200):**

```json
{
  "data": {
    "revoked": 3,
    "api_tokens_revoked": 2,
    "db_persisted": true,
    "audit_emitted": true
  },
  "meta": { "api_version": "v1" }
}
```

The response sets `Set-Cookie: yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` so the client side completes the revocation by deleting the cookie from the browser jar. `audit_emitted` and the `Sec-Audit-Failed: true` header have the same semantics as on the admin route above — `false` means the revoke completed but the audit row was lost (locked DB / disk full / pipeline exception), and the SOC 2 CC6.6 evidence chain is degraded for that request.

**Error (403) -- non-interactive credential:**

The caller authenticated with an MCP-tier token (`X-Yuzu-Token` carrying a non-empty `mcp_tier`) or a service-scoped token. The denial is audited as `session.revoke_all.self` with `result=denied`.

```json
{
  "error": {
    "code": 403,
    "message": "self-revoke requires an interactive session, not an API token"
  },
  "meta": { "api_version": "v1" }
}
```

**Audit:** every successful invocation emits `session.revoke_all.self` with `target_type=User`, `target_id=<caller>`, `detail=count=<N> api_tokens_revoked=<M>` (with `db_error=true` appended on partial failure). The dashboard's "Sign out everywhere" button on the operator's own row in Settings → Users uses this endpoint and follows up with a redirect to `/login`.

---

### Users

#### `POST /api/v1/users/{username}/unlock`

Clear a user's account-lockout counter. After `--auth-lockout-threshold` consecutive failed local-password logins an account is temporarily locked (SOC 2 CC6.3 — see the [account-lockout flags](server-admin.md#server-cli-flags) in the server-admin guide). The lock already auto-expires after `--auth-lockout-window-secs`; this endpoint is the operability path for an admin who needs to restore access immediately (e.g. a locked-out VIP who can't wait out the window).

**Permission:** `UserManagement:Write` (plus MFA step-up when MFA is enrolled — parity with `DELETE /api/v1/sessions`).

**Self-target behaviour.** An admin invoking this with their own username is permitted — clearing your own lockout is recoverable. This is the same weaker-than-`#397/#403` guard reasoning as `DELETE /api/v1/sessions`.

**Body:** none.

**Example:**

```bash
curl -s -X POST \
  -H "Cookie: yuzu_session=$COOKIE" \
  "https://yuzu.example.com/api/v1/users/alice/unlock"
```

**Response (200):**

```json
{
  "data": {
    "username": "alice",
    "unlocked": true,
    "audit_emitted": true
  },
  "meta": { "api_version": "v1" }
}
```

`audit_emitted` and the `Sec-Audit-Failed: true` header have the same semantics as the session-revoke routes above — `false` means the unlock completed but the audit row was lost, degrading the CC6.3 evidence chain for that request.

**Errors:** `400` — username empty or malformed (e.g. contains a reserved `:`); `401` — MFA step-up required (stale or absent proof; see `meta.challenge_url`); `403` — caller lacks `UserManagement:Write`, or a SAML session (step-up is not available for SAML sessions); `500` — the AuthDB (Postgres) write failed (a best-effort `auth.lockout.cleared`/`error` audit is still attempted); `503` — the lockout subsystem is not wired (no `AuthDB`).

**Audit:** a successful unlock emits `auth.lockout.cleared` with `result=ok`, `target_type=User`, `target_id=<username>`, `detail=admin_unlock`. A failed write emits the same verb with `result=error`. Note that a lockout cleared automatically (no operator action) emits `auth.lockout.cleared` with `result=ok` and `detail=reset_on_successful_login` when the user next logs in successfully; the threshold crossing itself emits `auth.lockout.applied`. These two verbs are the durable CC6.3 evidence; blocked-while-locked attempts are tracked only via the `yuzu_auth_lockout_blocked_total` metric (no per-attempt audit row **or** analytics event) to avoid amplification under a sustained brute-force.

---

#### `POST /api/v1/users/{username}/elevation-eligibility`

Grant or revoke a user's **JIT-admin-elevation eligibility** — who may activate a time-boxed admin elevation via `POST /api/v1/elevate` (SOC 2 CC6.3/CC6.6). This is the per-user `users.elevation_eligible` flag, distinct from holding standing admin and enumerable for access reviews. See [JIT Admin Elevation](#jit-admin-elevation) below and `docs/auth-architecture.md` "JIT admin elevation".

**Permission:** admin (or an active elevation) **+ MFA step-up**. **Self-grant is blocked** — an operator cannot set their own eligibility (another admin must).

**Body:** `{"eligible": <bool>}`.

**Side effect:** setting `eligible=false` immediately terminates any in-flight elevation for that user.

Two route forms, same handler:

- **Path form** — `POST /api/v1/users/{username}/elevation-eligibility` — **local usernames only** in practice: both forms validate the target with `is_valid_principal` (#1852), but a path segment cannot carry the `/` and `#` an SSO principal contains, so only a local username reaches the handler this way.
- **Query form** — `POST /api/v1/users/elevation-eligibility?username=<principal>` — **required for a durable SSO principal** (`oidc:<iss>#<sub>`). A path segment cannot carry the `/` (in the issuer URL) and `#` an SSO principal contains — the server percent-decodes the path and strips the URL fragment before route matching, so the path form 404s for every real IdP identity. The query form accepts the same shapes as `DELETE /api/v1/sessions` above (`is_valid_principal`, #1852): a strict local username, or an SSO principal (URL-encode the `#` as `%23`; `/` does not need escaping in a query value).

This is an `UPDATE`-only operation against an existing `users` row, never an `INSERT` — an SSO principal only has a row once the operator has **logged in at least once** (first login auto-provisions it). Granting eligibility against a principal with no row yet returns `404`, which for an SSO principal specifically means "this operator has never signed in" rather than "no such user was ever created".

```bash
curl -s -X POST -H "Cookie: yuzu_session=$COOKIE" \
  -H "Content-Type: application/json" -d '{"eligible":true}' \
  "https://yuzu.example.com/api/v1/users/alice/elevation-eligibility"

# SSO principal — MUST use the query form; note the URL-encoded '#' (%23):
curl -s -X POST -H "Cookie: yuzu_session=$ADMIN_COOKIE" \
  -H "Content-Type: application/json" -d '{"eligible":true}' \
  'https://yuzu.example.com/api/v1/users/elevation-eligibility?username=oidc:https://idp.example.com/%23sub-4821'
```

**Response (200):** `{"status":"ok"}`.

**Errors:** `400` — invalid username/principal or non-boolean body; `401` — not authenticated, or MFA step-up required (stale or absent proof; see `meta.challenge_url`); `403` — not admin, self-grant, or a SAML session (step-up is not available for SAML sessions); `404` — user not found (for an SSO principal: the operator has never logged in); `503` — AuthDB unavailable (`--postgres-dsn` unset/unreachable).

**Audit:** `user.elevation_eligibility.set`, `result` in `{ok, denied, error}`, `detail=eligible=<bool>` (plus `elevations_cleared=<N>` when a revoke dropped active windows; `self_grant_blocked` on a 403).

---

### Quarantine

Quarantine isolates a device from receiving commands or participating in normal operations. Quarantined devices remain connected but are blocked from instruction execution.

> **Scoped per-target authorization (#1788).** All three routes below authorize
> per-device, matching the MCP `quarantine_device` tool: a management-group-confined
> operator holding `Security:Execute`/`Security:Read` only through a group can
> act on and see devices inside their own group(s), and is refused (`403`) for
> devices outside them. A global grant (or an unfiltered/legacy-RBAC-disabled
> deployment) still reaches every device, unchanged. If the per-target scope
> gate is ever left unconfigured, every request on these routes fails **closed**
> with a `500` rather than silently widening to a fleet-wide check.

#### `GET /api/v1/quarantine`

List currently quarantined devices visible to the caller — admit-then-filter:
a device outside the caller's management-group scope is omitted from the
list entirely, not merely hidden from write access.

**Permission:** `Security:Read`, scoped per-device

> **Fail-closed on a degraded read (ADR-0047).** A store/pool/query failure
> returns `503` (`"quarantine list unavailable — try again"`), never a
> silently-empty list — a device could still be actively contained while the
> caller would otherwise see "nothing quarantined". A **second, distinct**
> `503` cause exists for the per-record admit-then-filter scope check itself:
> if it hits an anomalous outcome partway through the list (neither an
> explicit allow nor an explicit deny — most commonly a transient
> engine-principal-store outage), the whole list fails closed with
> `"authorization check unavailable — try again"` rather than silently
> omitting the affected record(s). Only the first cause increments
> `yuzu_server_quarantine_read_degrade_total` — see
> `docs/user-manual/upgrading.md` and `docs/user-manual/metrics.md` for the
> full distinction.

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-compromised-01",
      "status": "active",
      "quarantined_by": "admin",
      "quarantined_at": 1710849600,
      "whitelist": "10.0.1.50,10.0.1.51",
      "reason": "Suspicious network activity detected",
      "last_applied_at": 1710849660,
      "last_confirmed_at": 1710849675
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

> **`last_applied_at`/`last_confirmed_at` (#3425), both `0` = never.** Endpoint-containment
> confirmation state written by `QuarantineContainmentReconciler`, the background component that
> re-applies a device's own firewall on reconnect. `last_applied_at` means a system re-dispatch of
> the stored whitelist was accepted (`agents_reached > 0`) — NOT proof of containment (a
> gateway-attached agent's `send_to` only queues the frame). `last_confirmed_at` is set only after
> a follow-up `quarantine.status` read reports `state|active` — but that read is the target
> agent's own self-report (cert-bound to its identity, not independently corroborated by any
> network-side signal), so treat it as strong operational evidence of containment, not proof. See
> `docs/user-manual/security-hardening.md` "Reconnect re-application (#3425)" for the full trust
> boundary.

---

#### `POST /api/v1/quarantine`

Quarantine a device.

**Permission:** `Security:Execute`, scoped per-device (see the note above)

> **Supervised MCP tokens are approval-gated here too.** A bearer token minted
> with `mcp_tier: "supervised"` gets `403` on this route (and on the `DELETE`
> release below): supervised `Security:Execute` requires an approval ticket,
> and the ticket-then-recall flow exists only on the MCP transport
> (`quarantine_device`). The REST route mirrors the denial so switching
> transports cannot bypass the approval gate (#520).

**Request body:**

```json
{
  "agent_id": "agent-compromised-01",
  "reason": "Suspicious network activity detected"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | Target device ID |
| `reason` | string | No | Human-readable reason for quarantine |
| `whitelist` | string | No | Comma-separated IPs still allowed to communicate. Validated server-side (#3425): ≤512 characters total, each token ≤45 characters and drawn from `[0-9A-Fa-f.:]` — the same charset the reconciler and MCP's `quarantine_device` retry path require before ever dispatching a stored whitelist. Rejected with `400`, not written. |

**Response (201):**

```json
{
  "data": { "quarantined": true },
  "meta": { "api_version": "v1" }
}
```

> **`400` vs `503` (ADR-0047).** A `400` means a business/state error (a
> missing `agent_id`, the device is already quarantined, or `whitelist` fails
> server-edge validation) — retrying the identical request will not succeed,
> and `error.retry_after_ms` is
> `null`. A `503` means a genuine store/pool failure — retrying is
> reasonable, and `error.retry_after_ms` carries a concrete `5000`
> hint (REST's envelope has no nested `data` object — that's MCP's JSON-RPC
> shape; REST matches the MCP `quarantine_device` twin's A5 behavior, not
> its exact field path).

> **This route records; it does NOT itself dispatch — and the twins have
> diverged on the already-quarantined case (#3127).** `POST /api/v1/quarantine`
> writes the quarantine record only, synchronously. The live plugin isolation
> is dispatched by the MCP `quarantine_device` tool, which has no REST twin.
> Two consequences for a client that treats the two transports as
> interchangeable:
>
> - A `201` here means **the record was written**, not that the device's
>   firewall is enforcing anything **yet**. To isolate a device immediately,
>   dispatch `quarantine.quarantine` through the normal execution routes as
>   well — see [Security Hardening](security-hardening.md#device-quarantine).
>   **As of #3425, "yet" is load-bearing: this route no longer leaves a
>   record permanently unenforced.** `QuarantineContainmentReconciler`
>   reconciles every active record regardless of which surface created it —
>   a record written here for a device that is (or later becomes) connected
>   is automatically dispatched the stored whitelist typically within one
>   reconciler tick (~20s) of the device being connected, without a second
>   call — a brand-new record isn't in the heartbeat fast path's cache until
>   the next periodic tick populates it, so a heartbeat arriving in that
>   narrow window doesn't shortcut the wait. A record created here for a
>   reachable device does not stay dormant — the one exception is a stored
>   `whitelist` the re-dispatch validator refuses. As of #3425 (`d1f71c58f`)
>   this route validates `whitelist` at write time (`400` instead of `201`
>   for a malformed value), the same rule MCP's `quarantine_device` already
>   enforced — so a fresh write here can no longer land in this state. A
>   `validation_failed` reconcile now points at a record written via this
>   route before `d1f71c58f` shipped, or — on a fleet with pre-#3623 history
>   — one migrated from a legacy `quarantine.db` by the since-retired
>   `migrate_from_sqlite` backfill (ADR-0047, which copied `whitelist`
>   verbatim with no validation), not a fresh call. Either way, every reconcile
>   attempt then counts `validation_failed` and nothing is ever dispatched.
>   That failure is loud, not silent — the device stays in
>   `yuzu_server_quarantine_endpoint_unconfirmed{reachability="connected"}`
>   and trips `YuzuQuarantineEndpointUnconfirmed` after 15 minutes — but it
>   is a real way for a record to go permanently unenforced through this
>   route. If record-only-without-live-isolation is the intent (e.g.
>   flagging for review), enforce it at the caller/workflow level; do not
>   rely on this route's absence of its own dispatch.
> - The MCP tool now treats an already-active record as a **retryable
>   re-dispatch**, not a terminal error; this route still answers `400`,
>   because with no dispatch of its own there is nothing for it to re-drive.
>   The `400`-vs-`503` split above is unchanged and still mirrors the twin;
>   the already-quarantined *outcome* no longer does.

> **A quarantined device is refused at dispatch (#881).** Once a device is
> quarantined, every dispatch route below — `POST /api/command`,
> `POST /api/instructions/{id}/execute`, and the scope/group/broadcast arms —
> drops that device before the command reaches the agent, increments
> `yuzu_server_dispatch_target_rejected_total{reason="quarantined"}`, and
> writes a `quarantine.dispatch_denied` audit row (`target_type=Security`;
> `target_id` is the device, or `*` on a fail-closed denial **and** on the
> summary row that follows a capped per-device fan-out — see
> [Audit Log](audit-log.md)).
>
> **`POST /api/command` reports what it withheld.** The success body carries
> `withheld_quarantined` and (#3424/#3511) `withheld_unknown_plugin` — both
> always present, `0` on a clean dispatch — so `agents_reached: 97` on a
> 100-device group is distinguishable from three devices being offline, and a
> MIXED partial dispatch (some reached, some plugin-absent) is never silently
> invisible in the response. The success body also carries `audit_emitted`
> (#2557), the same field every denial arm that calls `emit_behavioral_audit`
> on this route already carries (the body-type, targeting-shape,
> Destructive-untargeted, Destructive-no-visible-target, no-target-named and
> classification-denial 400/403/404 arms) — NOT the scope-parse 400 (an
> unrelated JSON shape with no audit call at all) or the sent==0 503 family,
> neither of which ever carried it — present and `false` only when the paired `command.dispatch`
> `result=success` audit row failed to persist (the response also sets
> `Sec-Audit-Failed: true` in that case), omitted entirely when no audit
> store is configured. Before #2557 the success path's audit call was
> unguarded against a throwing sink and never reported this field at all —
> the one response shape most likely to be read as "everything is fine" was
> also the one place a silent audit-persist failure was invisible to the
> caller. The dashboard's own execute console
> (`/api/dashboard/execute`, a separate HTML-fragment handler, not this route)
> now names the same containment/quarantine/plugin-absence causes on a
> zero-agents-reached dispatch; it does not yet surface withheld counts on a
> MIXED partial dispatch the way this route's success body does — tracked as a
> follow-up.
>
> **Its `503` now names the cause.** Four conditions previously shared one
> body ("failed to send command to any agent"), and two of them are
> fleet-wide/request-wide states rather than a transport failure:
>
> | `error.reason` | Meaning | `retry_after_ms` |
> |---|---|---|
> | `containment_unreadable` | The gate is failing closed: containment state cannot be read, so **every** target on **every** dispatch is refused. A server condition, not a device one. | `5000` |
> | `quarantined` | Every target named is contained. The dispatch was withheld, not attempted. | `null` — retrying will not help until the device is released |
> | `plugin_not_found` (#3511) | The dispatched plugin is absent from every target's reported inventory — a command guaranteed to fail, withheld before dispatch rather than reported as a false success. Permanent for the current plugin name. If the plugin name and spelling are correct and it genuinely is installed on the target, the agent's REPORTED inventory is stale: it is populated once at registration and does not refresh until the agent's management connection next re-registers (a reconnect — daemon restart, or any dropped/re-established connection) — this reason can persist until then even after installation completes. | `null` — retrying will not help; check the plugin name/spelling instead, or trigger a reconnect on the target agent if the plugin was only just installed |
> | *(absent)* | Genuinely no agent reachable — the pre-existing meaning. | *(absent)* |
>
> `reason` is a top-level key on the error object, not part of the A4
> `error.data` envelope. `POST /api/instructions/{id}/execute` carries the
> same three-`reason` `503` split as `POST /api/command` above
> (`containment_unreadable` / `quarantined` / `plugin_not_found`, same
> `retry_after_ms` values) — closed alongside the architect finding that its
> response-building code
> was reading `dispatch_outcome.command_id`/`.sent` only, discarding the
> richer fields already available on the same struct.
>
> **A fourth, structurally distinct condition — `invalid_scope` — is `400`,
> not part of the `503` table above.** This route (unlike `POST
> /api/command`) accepts a caller-supplied `scope` expression; a malformed
> one is a client mistake, not a fleet-state fact, so it reports
> `error.reason: "invalid_scope"` at `400` with `retry_after_ms: null`,
> checked before the `503` cascade so a bad expression is never shadowed by
> `containment_unreadable`. Its generic catch-all
> (no `reason` key, matching the *(absent)* row above) additionally covers
> ADR-1007's per-device concurrency-claim exclusion, unique to this route
> since it — unlike `/api/command` — accepts a `concurrency_mode`: for a
> `per-device` definition, every named target may have been excluded by an
> already-open claim rather than being unreachable at all; the message
> points at `yuzu_server_dispatch_concurrency_skipped_total`. The bundle and
> result-set producers still do **not** carry this split — their own
> response-building code was not extended to surface the richer per-arm
> result their shared dispatch closure now carries (a separate, smaller
> follow-up per route). The quarantine
> plugin's own four actions (`quarantine`, `unquarantine`, `status`,
> `whitelist`) are exempt so that release stays reachable, and so are four
> server-internal pushes that are not operator dispatch —
> `tar.fleet_snapshot`, `__guard__.push_rules`, `asset_tags.sync` and
> `__sync__.now`, a closed set counted (not per-event audited) by
> `yuzu_server_system_reserved_push_total`.
> Nothing else is.
> If containment
> state becomes unreadable for longer than a 60-second last-known-good
> window, dispatch fails **closed** and refuses every target fleet-wide —
> alert on `yuzu_server_quarantine_gate_total{outcome="fail_closed"}`, which
> is an outage signal rather than a quarantine one
> (see [Metrics](metrics.md)).

---

#### `DELETE /api/v1/quarantine/{agent_id}`

Release a device from quarantine.

**Permission:** `Security:Execute`, scoped per-device (see the note above)

**Response:**

```json
{
  "data": { "released": true },
  "meta": { "api_version": "v1" }
}
```

> **`400` vs `503` (ADR-0047).** Same distinction as `POST` above — `400`
> means the device is not currently quarantined (retrying will not help);
> `503` means a genuine store/pool failure (retrying is reasonable).

---

### Internal CA

The server's built-in certificate authority (see `docs/pki-architecture.md`) can
be managed via the **Settings → Internal CA** dashboard panel or the REST
endpoints below. `root` and `crl` are **public** (clients and browsers need
them to establish trust / check revocation before they have a session); the
inventory and revoke endpoints are gated by the `Security` securable.

> Note on `Security` operations: certificate **revocation** uses `Security:Delete`
> (a destructive operation on an issued cert), while device **quarantine** uses
> `Security:Execute`. A custom role scoped to security operations needs both.

#### `GET /api/v1/ca/root`

Download the CA root certificate (PEM) and add it to an OS/browser trust store.
**Public** — no authentication. Returns `Content-Type: application/x-pem-file`,
`Content-Disposition: attachment; filename="yuzu-ca.pem"`,
`Cache-Control: public, max-age=86400`. `404` if no CA root exists; `503` if the
CA store is unavailable (a genuine database error, distinct from no-root).

```bash
curl https://yuzu.example.com/api/v1/ca/root -o yuzu-ca.pem
openssl x509 -in yuzu-ca.pem -noout -fingerprint -sha256
```

#### `GET /api/v1/ca/crl`

Download the current certificate revocation list (DER). **Public** — no
authentication. Returns `Content-Type: application/pkix-crl`,
`Cache-Control: no-cache, must-revalidate`. `503` if no CRL has been published
yet (transient — the server pre-publishes at startup and republishes on each
revocation).

```bash
curl https://yuzu.example.com/api/v1/ca/crl -o yuzu.crl
openssl crl -inform DER -in yuzu.crl -noout -text
```

#### `GET /api/v1/ca/issued`

List certificates issued by the internal CA. **Permission:** `Security:Read`.
Query params `limit` (1–1000, default 200) and `offset` (default 0). The full
certificate PEM and enrollment reference are intentionally omitted. `503` if
the CA store is unavailable.

`meta.has_more` is `true` when more rows exist beyond the current page; when it is,
`meta.next_offset` carries the `offset` to pass for the next page. Iterate until
`has_more` is `false` (do **not** infer end-of-list from `count < limit`).

```json
{
  "items": [
    {
      "serial_hex": "3A4B5C6D...",
      "subject": "agent-prod-01",
      "san": "URI:yuzu://<ca-fp>/agent/agent-prod-01",
      "purpose": "agent",
      "status": "active",
      "not_after": 1780000000,
      "issued_at": 1710849600,
      "issued_by": "agent:agent-prod-01"
    }
  ],
  "count": 1,
  "meta": { "api_version": "v1", "limit": 200, "offset": 0, "has_more": false }
}
```

The MCP `list_issued_certs` tool mirrors this contract (same `has_more` / `next_offset`).

#### `POST /api/v1/ca/revoke`

Revoke a certificate by serial. **Permission:** `Security:Delete`. Revocation
takes effect server-side **immediately** (the mTLS accept gate reads `ca_store`,
not the CRL); the CRL is then republished. Request body (max 64 KB):

```json
{ "serial_hex": "3A4B5C6D...", "reason": "key compromise" }
```

`serial_hex` is required (1–64 hex digits, case-insensitive). Unknown JSON fields
are rejected. Response:

```json
{ "revoked": true, "serial_hex": "3A4B5C6D...", "crl_republished": true, "meta": { "api_version": "v1" } }
```

`crl_republished: false` means the revocation stands (the agent is refused on its
next gRPC call) but the public CRL could not be rebuilt — external CRL consumers
will not see it until the next successful publish. The server retries on its own:
the leader's freshness pass republishes on its next 15-second tick once the cause
clears (up to about 5 minutes later if that attempt fails too). Repeating the
`POST` is not a retry — it returns `404` because the serial is already revoked.
Errors: `400` (missing/invalid
serial, unknown field, bad JSON), `403` (missing `Security:Delete`), `404` (serial
not found or already revoked), `413` (body too large), `503` (CA unavailable).

#### `POST /api/v1/ca/issue-code-signing` (gap-matrix #10)

Issue a code-signing leaf certificate via CSR custody — the operator holds the
private key and submits only a PKCS#10 CSR; the server never sees the key. See
`docs/pki-architecture.md` "Code-signing certificate issuance" and
`docs/user-manual/agent-plugins.md` "Plugin Signing" for the full workflow.
**Permission:** `Security:Write`. MCP twin: `issue_code_signing_cert` (same
schema, supervised-tier + approval-gated like every other `Security:Write` MCP
tool). Request body (max 64 KiB):

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "label": "plugin-signer-2026",
  "validity_days": 365
}
```

`csr_pem` is required. `label` is required and becomes the leaf's subject CN —
must match `^[A-Za-z0-9._-]{1,64}$` (never an agent-style
`yuzu://…/agent/…` URI SAN). `validity_days` is optional, `[1, 730]`, default
`365`, refused outright (not silently clamped) if requested out of range;
always further clamped so the leaf cannot outlive the issuing CA. Unknown JSON
fields are rejected. Usage is hard-pinned to `codeSigning` only — never
`clientAuth`/`serverAuth` — which is what makes this route safe to expose while
the general `POST /api/v1/ca/issue` stays deferred (see `pki-architecture.md`).
Response:

```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "serial_hex": "3A4B5C6D...",
  "not_after": "2027-09-10T00:00:00Z",
  "purpose": "code-signing",
  "meta": { "api_version": "v1" }
}
```

`chain_pem` is the issuing cert plus, in subordinate-CA mode, the parent chain
above it — feed both `certificate_pem` and `chain_pem` to `openssl cms -sign
-certfile` to build a signature an agent can chain to its trust anchor. Errors
use the A4 envelope: `400` (missing/invalid `csr_pem`, invalid `label`,
`validity_days` out of range, a signing key below the strength floor — the
accepted set is RSA 2048-16384 bits or EC P-256/P-384/P-521; Ed25519 and Ed448
are rejected, since `openssl cms -sign` cannot use them — unknown field, bad
JSON), `403` (missing
`Security:Write`), `409` (no CA root — generate default certs first), `413`
(body too large), `503` (CA unavailable). Audited as `ca.cert.issued`
(`target_type=CodeSigningCertificate`, `target_id=<label or serial>`,
`detail` carries `purpose=code-signing`) — the same action name an agent-leaf
issuance uses, distinguished by `target_type` (`CodeSigningCertificate` vs
`AgentCertificate`), with `purpose` as a secondary discriminator. Revoking the issued leaf uses the
existing `POST /api/v1/ca/revoke` above; **revocation does not yet reach the
agent-side plugin-load verifier via the CRL** — see
`docs/pki-architecture.md`'s caveat before relying on this operationally.

#### Subordinate-CA (root your CA in an enterprise PKI)

By default Yuzu's CA is a self-signed install root (`trust mode: built-in`). An
enterprise can instead make Yuzu's issuing CA a **subordinate** of its own root,
so every Yuzu-issued certificate chains to the corporate trust anchor. The
issuing **key never changes** — the enterprise signs Yuzu's *existing* public
key — so certificates already issued keep validating across the switch.

Workflow:

1. **Export** Yuzu's CA signing request and have your enterprise root sign it as
   a subordinate CA (the signed cert **must** carry `basicConstraints: CA:TRUE`,
   `keyUsage: keyCertSign, cRLSign`).
2. **Import** the signed intermediate plus the parent chain (enterprise root and
   any intermediates above Yuzu's).

This is also available in **Settings → Internal CA → "Subordinate this CA…"**.

#### `GET /api/v1/ca/root-csr`

Export the install CA's PKCS#10 CSR (PEM), over its existing key, for an
enterprise root to sign. **Permission:** `Security:Read`. The CSR carries only
the CA's public key (already public via `GET /api/v1/ca/root`) and subject — no
secret. Audited (`ca.root_csr.exported`).

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://yuzu.example.com/api/v1/ca/root-csr -o yuzu-ca.csr
# → hand yuzu-ca.csr to your enterprise CA; it returns a signed intermediate.
```

Errors: `403` (missing `Security:Read`), `500` (CSR generation failed), `503`
(CA unavailable).

#### `POST /api/v1/ca/import-chain`

Import the enterprise-signed intermediate + parent chain, switching the issuing
identity to subordinate mode. **Permission:** `Security:Write`. Request body
(max 256 KB):

```json
{
  "intermediate_pem": "-----BEGIN CERTIFICATE-----\n... (Yuzu's key, signed by the enterprise) ...\n-----END CERTIFICATE-----\n",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n... (enterprise root [+ intermediates]) ...\n-----END CERTIFICATE-----\n"
}
```

The server validates that the intermediate (a) is a CA certificate, (b) carries
**this install's** CA public key (proof the enterprise signed the CSR you
exported), and (c) verifies up to the supplied parent chain — then swaps the
issuing cert and re-publishes the CRL under the new issuer. Response:

```json
{ "imported": true, "mode": "subordinate", "crl_republished": true, "meta": { "api_version": "v1" } }
```

Errors: `400` (bad JSON / missing field / unparseable intermediate), `403`
(missing `Security:Write`), `409` (no existing CA to subordinate — generate
default certs first), `422` (intermediate is not a CA / does not carry this CA's
key / does not verify to the chain), `413` (body too large), `500` (validated but
persistence failed), `503` (CA unavailable). A rejected import is audited
`ca.subordinate.imported` with `result=denied`; success with `result=success`.

> **Bring-your-own-leaf** (orthogonal): any surface given an explicit
> `--cert`/`--key`/`--ca-cert` (or `--https-cert`/`--https-key`) flag bypasses
> the internal CA for that surface entirely — unchanged behaviour, supported and
> independent of subordinate mode.

---

### KEK Rotation

Rotate the secrets key-encryption-key (KEK) that wraps every envelope-encrypted
secret column (ADR-0010). See `docs/user-manual/server-admin.md` "Key
management (secrets KEK)" for the full runbook (half-committed recovery,
rotation runaway control, stuck-lock diagnosis, DR drill, retirement
preconditions). Each route has an MCP twin sharing the same failure
classification, remediation wording, and — for `get_kek_status` — the
identical `live_versions`/`lock_held`/`lock_holder_pid` fields added by
#2530 (REST/MCP twin parity, ADR-1005): `rotate_kek`, `rewrap_secrets`,
`get_kek_status`.

#### `POST /api/v1/secrets/kek/rotate`

Mint a new KEK version (`secrets-kek-v<N+1>`) and re-wrap every registered
secret row's wrapped-DEK header under it (payloads untouched). **Permission:**
`Security:Write`. No request body (empty or `{}`).

```json
{ "new_version": 2, "rotation_complete": true, "meta": { "api_version": "v1" } }
```

`rotation_complete` is the honest completion signal (ADR-0010 §3) — the
response deliberately omits a rewrapped-row count; call `/rewrap` for one.
Errors: `400`/`413` (non-empty/oversized body), `403` (missing
`Security:Write`), `409` (**two distinct causes** — see below), `429`
(rotation cooldown, below), `503` (**three distinct causes** — see below).

> **Two different `409`s.** `"another KEK operation is in progress"` means
> another rotation or re-wrap holds the cluster-wide `secrets_kek_op`
> advisory lock — wait for it to finish and retry. `"the live KEK version
> ceiling has been reached"` (#2530) means `--kek-max-live-versions` has been
> hit — waiting never resolves this one; it needs an operator to explicitly
> raise the ceiling (documented as a deliberate, audited risk acceptance
> pending #2525 — see server-admin.md). Distinguish them from the message
> text, not the status code alone.

> **Three different `503`s.** `"KEK service unavailable"` (codec/Postgres not
> yet ready — retry once the server reports ready) is the original one.
> #2530 added two more, neither retryable on a fixed delay: `"a KEK query was
> canceled or exceeded its statement timeout"` (SQLSTATE `57014` —
> deliberately worded that way, not "timed out": Postgres also raises this
> for an administrator's `pg_cancel_backend`, and it is **not necessarily
> transient** — check `statement_timeout`, database load, cancellation
> activity, and the registered-column scan size before retrying), and `"the
> KEK rotation clock is untrustworthy"` (the newest `secrets.kek_meta` row is
> future-dated relative to the database server's own clock — investigate the
> database server's clock/NTP, not the KEK subsystem). The response body and
> server log report the observed skew **magnitude** in seconds, because the
> two possible skew directions behave differently: a **backward** skew
> self-clears once the clock reads sanely again, but a **forward** skew
> (the row was minted while the clock was already ahead — bad NTP, a VM
> restore, a failover to a host that's ahead) does **not** self-clear — it
> persists until real time catches up to the stored timestamp, blocking
> every `/rotate` for that whole duration with **no configuration bypass at
> all**. See server-admin.md "Clock-anomaly guard" for the full diagnostic
> procedure. None of the three carry `retry_after_ms`.

> **`500` half-committed — do NOT retry this route.** If rotation registers
> the new version but fails to finish re-wrapping every row, this returns
> `500` with a remediation telling you to call `POST
> /api/v1/secrets/kek/rewrap` to resume. Retrying `/rotate` instead would mint
> a second, spurious version on top of the half-rotated state. This
> classification **wins over** a `query_canceled` cause if the cancellation
> happened after the mint committed — you still get told to call `/rewrap`,
> never `/rotate`.

> **`429` rotation cooldown — durable and cluster-wide (#2530; #2530
> G7-S9 removed a weaker second tier).** An earlier cut of this hardening
> pass added a cheap process-local pre-check (5 minutes, in-memory)
> alongside the durable control, but it was removed: it was never the
> authoritative control (it was per-process and a restart cleared it), its
> hardcoded window could not be configured below 5 minutes, and it never
> populated an honest `retry_after_ms`. The sole authoritative rate limit
> today is read from `secrets.kek_meta.created_at` on the database server's
> own clock, cluster-wide and restart-persistent:
> `--kek-min-rotate-interval` (seconds, default `3600` = 1h). A fresh
> install's first rotate attempt is refused for up to this interval too —
> KEK v1 is minted at boot with `created_at = now()`. A failed
> attempt consumes the budget too — deliberately, because a failed rotation
> is exactly when you must not immediately rotate again: automation that
> retries `/rotate` on a `500` would otherwise mint a fresh version on every
> retry, and a KEK version can never be retired (#2525). **`/rewrap` is NOT
> rate-limited** and is the correct way to finish a half-committed rotation.
> Unlike the `409`/`503` cases above, this `429`'s `retry_after_ms` is
> **honest** — computed from the same durable database-clock timestamp, so
> waiting genuinely resolves it (the field is a `uint32` millisecond count
> that **saturates** at its maximum on an oversized configured interval
> rather than wrapping, so it can only come out over-long, never falsely
> short). Cluster-wide *correctness* (as opposed to rate limiting) still
> comes from the advisory lock, which returns `409`, not this.
>
> **`--kek-min-rotate-interval` is a runaway/abuse guard, not a rotation
> schedule — do NOT set it to your rotation cadence.** It exists to stop a
> looping caller (buggy automation, a compromised token) hammering
> `/rotate`, not to express how often you intend to rotate; most operators
> should never change the default. Raising it directly delays *emergency*
> re-rotation after a suspected KEK compromise, with no bypass (`/rewrap`
> only resumes an in-progress rotation, never mints a new version) — e.g.
> setting it to 90 days to "match" a quarterly policy means a routine
> rotation followed by a compromise the next day leaves you refused for the
> next three months, with no escape short of a restart at a lower value
> mid-incident. The 365-day upper bound is a fat-finger sanity ceiling, not
> a recommendation.

#### `POST /api/v1/secrets/kek/rewrap`

Idempotent resume: re-wrap every row still on a non-active KEK version under
the current active one. Safe to call repeatedly, including when there is
nothing left to do. **Permission:** `Security:Write`. No request body.

```json
{ "rows_rewrapped": 3, "meta": { "api_version": "v1" } }
```

`rows_rewrapped: 0` is a normal outcome, not an error. Errors: `400`/`413`,
`403` (missing `Security:Write`), `409` (advisory lock held), `503` (codec/
Postgres unavailable, **or** `"a KEK query was canceled or exceeded its
statement timeout"` — same #2530 SQLSTATE `57014` classification and
non-transient caveat as `/rotate` above; `/rewrap` never returns the ceiling
or clock-anomaly failures, those are rotate-only preconditions).

#### `GET /api/v1/secrets/kek/status`

Current KEK rotation status. **Permission:** `Security:Read`.

```json
{
  "active_version": 2,
  "oldest_in_use": 2,
  "rotation_complete": true,
  "live_versions": 2,
  "lock_held": false,
  "lock_holder_pid": null,
  "meta": { "api_version": "v1" }
}
```

`oldest_in_use` is `null` when no secret rows exist at all (trivially
complete). Read-only, not audited, and — unlike `/rotate`/`/rewrap` — this
route **deliberately never takes** the `secrets_kek_op` advisory lock, so it
never returns `409` for lock contention. Errors: `403` (missing
`Security:Read`), `503` (codec/Postgres unavailable, or the same
`query_canceled` classification as above while reading the oldest-referenced
version).

> **`live_versions`, `lock_held`, `lock_holder_pid` (#2530).** Diagnostic
> fields for diagnosing a wedged `secrets_kek_op` lock — before these
> existed, a stuck holder made every KEK operation `409` forever with no way
> to see why. `lock_held`/`lock_holder_pid` report the lock **in this
> server's own database** (the underlying query is filtered by
> `current_database()`, not cluster-wide — a same-named advisory lock held
> by an unrelated tenant database sharing the same Postgres instance is
> never reported here). They are **lock-free snapshots read at possibly
> different instants**, not one coordinated read — never derive a "safe to
> retire" conclusion from any combination of them (#2525), and never treat
> `lock_holder_pid` alone as sufficient grounds to terminate a backend: a
> healthy long-running re-wrap looks identical to a wedge from this field
> alone. The full diagnosis-and-remedy procedure (corroborate against
> `pg_stat_activity` before any DBA action) is in
> `docs/user-manual/server-admin.md` § "Diagnosing a stuck KEK op lock".
>
> **`live_versions` and `lock_held` are `null` — never a fabricated `0`/
> `false` — when the underlying query could not be determined.** The key is
> always present; `null` means "could not be determined", not a truthful
> negative. This matters most for `lock_held`: a `null` here **must never be
> read as "no lock is held"** — it means the lock state is UNKNOWN.
> Corroborate via `pg_stat_activity` before concluding anything, exactly as
> you would for a genuinely-held lock.
>
> **`lock_holder_pid` is `null` in THREE distinct situations — always check
> `lock_held` first to tell them apart:** (1) `lock_held: false` → genuinely
> unheld, nothing to report; (2) `lock_held: null` → undetermined, the
> holder query itself failed, the pid is meaningless (not "unheld"); (3)
> `lock_held: true` with `lock_holder_pid: null` → the lock **is** held, but
> the holder's backend pid could not be read from `pg_locks` at query time —
> there is no pid to corroborate against `pg_stat_activity`; instead query
> `pg_locks` directly for any granted holder of `secrets_kek_op` in the
> current database (see `docs/user-manual/server-admin.md`'s runbook for the
> exact query) and, if it also comes back empty or unreadable, escalate to a
> DBA inspection rather than waiting on a pid that may never arrive.

> **No retire endpoint — by design.** Yuzu does not expose a way to destroy an
> old KEK version, even though the codec's internal `retire_kek` exists and is
> tested. `SecretCodec::encrypt()` snapshots the active version and releases
> its lock before the caller persists the blob, so a retirement could pass its
> "zero references" check and delete a key an in-flight write is about to use
> — a permanent, unrecoverable loss (#2525). Old KEK files are expected to
> accumulate; they are required to restore older backups and must not be
> deleted by hand.

---

### Engine Principals

Fleet-wide RBAC role-assignment **authoring** surface for the `engine` principal
class — the durable identity behind an autonomous use-case-engine (UCE) module
(design doc `docs/auth-engine-principals-design.md`, ADR-1005 item 2b). This is
PR 4.2's "assignment authoring" deliverable (design §4.1): without it,
`RbacStore::assign_role` had no production caller for `principal_type="engine"`,
so a would-be grant could never take effect. There is **no CRUD for minting or
revoking engine principals themselves yet** — that lands in PR 4.3; these three
endpoints only manage the roles held by an *existing* engine principal.

`{id}` in every route below is the **bare slug**, without the `engine:` prefix
(mirrors `/management-groups/{id}` taking a bare group id) — the server
reconstructs the full `engine:<slug>` principal id internally. Grants are
**always fleet-wide** in this release; scoped (management-group) engine role
assignment is rejected pending the Phase-5 `authorize_list_read` extension
(design §4.3).

**Structural constraint (design §4.2, "no admin, ever"):** an engine principal
can never hold the `admin`/`Administrator` role, any other built-in system
role, or a wildcard role. `POST .../roles` **rejects** such a request outright
(`400`) — it is never silently narrowed to something safer.

#### `GET /api/v1/engine-principals/{id}/roles`

List the fleet-wide roles currently assigned to an engine principal.

**Permission:** `EnginePrincipal:Read`

**Response:**

```json
{
  "data": [
    { "principal_id": "engine:vuln-viewer", "role_name": "Viewer" }
  ],
  "meta": { "api_version": "v1" }
}
```

An unknown or revoked `{id}` is not distinguished here — it simply returns an
empty `data` array (no RBAC row can exist for a principal that was never
granted one). Errors: `403` (missing `EnginePrincipal:Read`), `503` (RBAC store
unavailable).

---

#### `POST /api/v1/engine-principals/{id}/roles`

Assign a fleet-wide role to an engine principal.

**Permission:** `Security:Write`, plus **admin + MFA step-up** (same gate class
as `POST /api/v1/ca/import-chain` — this route grants further RBAC authority to
a principal).

**Request body:**

```json
{ "role": "Viewer" }
```

| Field | Type | Required | Description |
|---|---|---|---|
| `role` | string | Yes | An existing RBAC role name. `admin`/`Administrator`/any built-in system role is rejected. |

**Response (201):**

```json
{
  "data": { "assigned": true, "principal_id": "engine:vuln-viewer", "role": "Viewer" },
  "meta": { "api_version": "v1" }
}
```

**Errors:** `400` — invalid JSON, missing `role`, unknown role name, or the
role is admin/built-in/otherwise rejected by `validate_assignment` (design
§4.2 — always a `4xx`, never a `500`); `401`/`403` — not authenticated, missing
`Security:Write`, or MFA step-up required/failed; `404` — no active (live,
non-revoked) engine principal exists at `{id}`; `503` — the RBAC or
engine-principal store is unavailable. A rejected assignment is audited
`engine_principal.role.assigned` with `result=denied`; success with
`result=success`. `503` + `Sec-Audit-Failed: true` — the assignment audit row
could not persist (see *Audit-persist failure* above): the grant may already be
in effect, so reconcile via `GET /{id}/roles`.

---

#### `DELETE /api/v1/engine-principals/{id}/roles/{role}`

Unassign a fleet-wide role from an engine principal.

**Permission:** `Security:Write`, plus **admin + MFA step-up**.

**Response:**

```json
{
  "data": { "unassigned": true },
  "meta": { "api_version": "v1" }
}
```

**Errors:** `400` — the role was not assigned to this principal (store-returned
error); `401`/`403` — not authenticated, missing `Security:Write`, or MFA
step-up required/failed; `503` — the RBAC store is unavailable. Audited
`engine_principal.role.unassigned` on success. `503` + `Sec-Audit-Failed: true`
— the unassign audit row could not persist (see *Audit-persist failure* above):
the grant may already be removed, so reconcile via `GET /{id}/roles`.

---

### RBAC

Role-Based Access Control endpoints for inspecting roles, permissions, and authorization decisions.

#### `GET /api/v1/rbac/roles`

List all defined roles.

**Permission:** `UserManagement:Read`

**Response:**

```json
{
  "data": [
    {
      "name": "Administrator",
      "description": "Full system access",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Operator",
      "description": "Can execute instructions and manage devices",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Viewer",
      "description": "Read-only access",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "ITServiceOwner",
      "description": "Can delegate Operator and Viewer roles within their management groups",
      "is_system": true,
      "created_at": 1710849600
    }
  ],
  "pagination": { "total": 4, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/rbac/roles/{role_name}/permissions`

List all permissions granted to a role.

**Permission:** `UserManagement:Read`

**Response:**

```json
{
  "data": [
    {
      "securable_type": "ManagementGroup",
      "operation": "Read",
      "effect": "allow"
    },
    {
      "securable_type": "ManagementGroup",
      "operation": "Write",
      "effect": "allow"
    },
    {
      "securable_type": "Tag",
      "operation": "Read",
      "effect": "allow"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/rbac/check`

Check whether the current user has a specific permission.

**Permission:** Authenticated session (no specific RBAC permission required).

**Request body:**

```json
{
  "securable_type": "ManagementGroup",
  "operation": "Write"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `securable_type` | string | Yes | The resource type to check |
| `operation` | string | Yes | The operation to check (`Read`, `Write`, `Delete`, `Execute`) |

**Response:**

```json
{
  "data": { "allowed": true },
  "meta": { "api_version": "v1" }
}
```

**Securable types:** `ManagementGroup`, `ApiToken`, `Security`, `UserManagement`, `Tag`, `InstructionDefinition`, `AuditLog`

**Operations:** `Read`, `Write`, `Delete`, `Execute`

---

### Tags

Tags are key-value pairs assigned to agents for categorization, scoping, and compliance tracking. Four structured categories are enforced: `role`, `environment`, `location`, and `service`. Custom keys are also supported.

Tag key constraints: max 64 characters, pattern `[a-zA-Z0-9_.:-]`. Tag value constraints: max 448 bytes.

#### `GET /api/v1/tag-categories`

List the structured tag categories and their allowed values.

**Permission:** `Tag:Read`

**Response:**

```json
{
  "data": [
    {
      "key": "role",
      "display_name": "Device Role",
      "allowed_values": ["server", "desktop", "kiosk", "virtual"]
    },
    {
      "key": "environment",
      "display_name": "Environment",
      "allowed_values": ["production", "staging", "development", "test"]
    },
    {
      "key": "location",
      "display_name": "Location",
      "allowed_values": []
    },
    {
      "key": "service",
      "display_name": "Service",
      "allowed_values": []
    }
  ],
  "meta": { "api_version": "v1" }
}
```

Categories with an empty `allowed_values` array accept free-form values.

---

#### `GET /api/v1/tag-compliance`

Identify agents missing required structured tag categories.

**Permission:** `Tag:Read`

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-untagged-01",
      "missing_tags": ["role", "environment", "location", "service"]
    },
    {
      "agent_id": "agent-partial-02",
      "missing_tags": ["service"]
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/tags?agent_id=X`

Get all tags for a specific agent.

**Permission:** `Tag:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | The agent whose tags to retrieve |

**Response:**

```json
{
  "data": {
    "role": "server",
    "environment": "production",
    "location": "eu-west-1",
    "service": "web-frontend",
    "custom.team": "platform-eng"
  },
  "meta": { "api_version": "v1" }
}
```

---

#### `PUT /api/v1/tags`

Set a tag on an agent. Creates the tag if it does not exist, or updates the value if it does. If the key matches a structured category with allowed values, the value is validated.

**Permission:** `Tag:Write`

**Request body:**

```json
{
  "agent_id": "agent-eu-prod-01",
  "key": "environment",
  "value": "production"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | Target agent |
| `key` | string | Yes | Tag key (max 64 chars, `[a-zA-Z0-9_.:-]`) |
| `value` | string | Yes | Tag value (max 448 bytes) |

**Response:**

```json
{
  "data": { "set": true },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- invalid value for structured category:**

```json
{
  "error": "invalid value 'bogus' for category 'role'; allowed: server, desktop, kiosk, virtual",
  "meta": { "api_version": "v1" }
}
```

**Service-scoped tokens:** a service-scoped token can never set the `service` key on any agent, in
or out of its own scope, regardless of the value being written -- `403`, no `Tag:Write` grant
admits it (#3289). The `service` tag defines the token's own confinement boundary; see
[Service-Scoped Tokens](authentication.md#service-scoped-tokens).

---

#### `DELETE /api/v1/tags/{agent_id}/{key}`

Delete a tag from an agent.

**Permission:** `Tag:Delete`

**Service-scoped tokens:** cannot delete the `service` key on any agent, for the same reason as
`PUT` above -- `403`, no `Tag:Delete` grant admits it (#3289).

**Response:**

```json
{
  "data": { "deleted": true },
  "meta": { "api_version": "v1" }
}
```

**Storage failure (all tag endpoints that read or write stored tags — `GET /api/v1/tag-categories` is compile-time static and exempt):** a degraded tag store returns `503 tag store
unavailable` (A4 envelope, `retry_after_ms: 5000`) — never an empty tag map, a `404`, or a
false success. Tags feed scope resolution and dispatch targeting, so a silently-empty answer
would mis-resolve decisions built on them (ADR-0050); retry a `503` once `/readyz` reports
`tag_store` healthy. `DELETE` returns `404 tag not found` only after a successful read found
no such tag. Failed and not-found mutations leave `tag.set`/`tag.delete` audit rows
(`failure`/`not_found`), matching the legacy and MCP twins.

---

### Definitions

Instruction definitions describe the schema and execution spec for operations that can be sent to agents.

#### `GET /api/v1/definitions`

List all instruction definitions.

**Permission:** `InstructionDefinition:Read`

**Response:**

```json
{
  "data": [
    {
      "id": 1,
      "name": "hardware.cpu-info",
      "description": "Retrieve CPU model, core count, and architecture",
      "plugin": "hardware",
      "action": "cpu-info",
      "version": "1.0.0",
      "created_at": "2025-03-19T12:00:00Z"
    },
    {
      "id": 2,
      "name": "network.interfaces",
      "description": "List all network interfaces with IP addresses",
      "plugin": "network",
      "action": "interfaces",
      "version": "1.0.0",
      "created_at": "2025-03-19T12:00:00Z"
    }
  ],
  "pagination": { "total": 2, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/instructions`

(#4029, api-parity Batch A) Twin of the legacy `GET /api/instructions` — the full filter set (`name`/`plugin`/`type`/`set_id`/`enabled_only`/`limit`), reconciled onto the same shared builder MCP's `list_definitions` tool calls (`instruction_definition_row_json`, `instruction_definition_model.hpp`) so REST and MCP cannot drift from each other by construction. A distinct route from `GET /api/v1/definitions` above (that route predates this issue and is unaffected by it).

**Permission:** `InstructionDefinition:Read`

**Query parameters:** `name`, `plugin`, `type` (`question`|`action`), `set_id`, `enabled_only` (bool), `limit` (default 100).

**Response:**

```json
{
  "data": [
    {
      "id": "def-abc123",
      "name": "hardware.cpu-info",
      "version": "1.0.0",
      "type": "question",
      "plugin": "hardware",
      "action": "cpu-info",
      "description": "Retrieve CPU model, core count, and architecture",
      "enabled": true,
      "instruction_set_id": "",
      "created_at": 1742385600,
      "updated_at": 1742385600
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

**503** if the instruction store is unavailable or the read fails (A4 envelope, `retry_after_ms: 5000`).

---

#### `GET /api/v1/instructions/{id}`

(#4029) Single-definition detail — the RECONCILED SUPERSET of the legacy `GET /api/instructions/{id}` fragment's fields (`gather_ttl_seconds`/`response_ttl_days`/`created_by`/timestamps) and MCP `get_definition`'s pre-existing fields (`approval_mode`/`parameter_schema`/`result_schema`/`yaml_source`) — both surfaces call the same builder (`instruction_definition_detail_json`) now, closing the field-set drift that existed between them before this issue.

**Permission:** `InstructionDefinition:Read`

**Response:**

```json
{
  "data": {
    "id": "def-abc123",
    "name": "hardware.cpu-info",
    "version": "1.0.0",
    "type": "question",
    "plugin": "hardware",
    "action": "cpu-info",
    "description": "Retrieve CPU model, core count, and architecture",
    "enabled": true,
    "instruction_set_id": "",
    "created_at": 1742385600,
    "updated_at": 1742385600,
    "gather_ttl_seconds": 300,
    "response_ttl_days": 90,
    "created_by": "operator@example.com",
    "approval_mode": "auto",
    "parameter_schema": "{}",
    "result_schema": "{}",
    "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n..."
  },
  "meta": { "api_version": "v1" }
}
```

**404** if no definition has that id. **503** if the instruction store is unavailable or the read fails (A4 envelope, `retry_after_ms: 5000`).

---

#### `GET /api/v1/instructions/{id}/export`

(#4029) Export a single instruction definition as its full JSON document (every field, including the operator-authoring-only fields `concurrency_mode`/`platforms`/`min_agent_version`/`required_plugins`/`readable_payload`/`visualization_spec`/`response_templates_spec`). Twin of the legacy `GET /api/instructions/{id}/export` route and the new MCP `export_definition` tool — all three now call the same builder (`instruction_definition_export_json`), which `InstructionStore::export_definition_json` itself delegates to as well. **Diverges from the legacy route on an unknown id:** the legacy route returns `200 "{}"` (a store-export quirk, never fixed since the field it checks was designed around "found but empty"); this route resolves the definition first and returns a real `404`.

**Permission:** `InstructionDefinition:Read`

**404** if no definition has that id. **503** if the instruction store is unavailable or the read fails (A4 envelope, `retry_after_ms: 5000`).

---

### Product Packs

(#4029, api-parity Batch A) A product pack is a bundle of `InstructionDefinition`/`PolicyFragment`/`Policy`/`Workflow` documents installed together (`POST /api/product-packs`, legacy — unversioned, unaffected by this issue). These two routes are read-only twins of the legacy `GET /api/product-packs[/{id}]` routes and of new MCP `list_product_packs`/`get_product_pack` tools, all three sharing one builder per shape (`product_pack_model.hpp`) so they cannot drift from each other by construction.

**Prerequisite fix (#4029):** `ProductPack` is used as the RBAC securable string gating every one of these routes, but was never seeded into RBAC's securable-types catalogue before this issue — no role, not even Administrator, could be granted `ProductPack:*` while RBAC was enabled. Fixed as part of this issue: `ProductPack` is now seeded with full CRUD granted to Administrator, and `Read` additionally granted to Operator/PlatformEngineer/Viewer (the same population that already holds `InstructionDefinition:Read`).

#### `GET /api/v1/product-packs`

List installed product packs.

**Permission:** `ProductPack:Read`

**Query parameters:** `name`, `limit` (default 100).

**503** on a genuine DB/lease fault (A4 envelope, `retry_after_ms: 5000`) — a validation/business-rule error is `400`, never retryable.

**Response:**

```json
{
  "data": [
    {
      "id": "pack-abc123",
      "name": "windows-baseline",
      "version": "1.0.0",
      "description": "Baseline Windows fleet content",
      "item_count": 3,
      "items": [
        { "kind": "InstructionDefinition", "item_id": "def-1", "name": "hardware.cpu-info" }
      ],
      "installed_at": 1742385600,
      "verified": true
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/product-packs/{id}`

Get a single installed product pack's detail, including the pack's own `yaml_source` (the full multi-document bundle) and each item's own `yaml_source`.

**Permission:** `ProductPack:Read`

**503** on a genuine DB/lease fault (A4 envelope, `retry_after_ms: 5000`) — a validation/business-rule error is `400`, never retryable.

**Response:**

```json
{
  "data": {
    "id": "pack-abc123",
    "name": "windows-baseline",
    "version": "1.0.0",
    "description": "Baseline Windows fleet content",
    "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: ProductPack\n...",
    "items": [
      {
        "kind": "InstructionDefinition",
        "item_id": "def-1",
        "name": "hardware.cpu-info",
        "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n..."
      }
    ],
    "installed_at": 1742385600,
    "verified": true
  },
  "meta": { "api_version": "v1" }
}
```

**404** if no product pack has that id.

---

### Response Templates

Named response-view configurations attached to an `InstructionDefinition` — column subset, sort order, and filter presets the dashboard's filter-bar dropdown surfaces (issue #254, Phase 8.2). Storage is the `response_templates_spec` JSON array column on `instruction_definitions`; the `__default__` template is synthesised on read from `spec.result.columns` (or the plugin's column schema) and never persists.

#### `GET /api/v1/definitions/{id}/response-templates`

List all response templates for the definition. The synthesised `__default__` is auto-prepended when no operator template is marked `default`.

**Permission:** `InstructionDefinition:Read`

**Response:**

```json
{
  "data": [
    {
      "id": "__default__",
      "name": "Default",
      "description": "Auto-generated default view derived from the result schema.",
      "columns": ["PID", "Name", "Path", "SHA-1"],
      "filters": [],
      "default": true
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/definitions/{id}/response-templates/{template_id}`

Fetch a single template. The reserved id `__default__` always returns the synthesised default (even when an operator default exists).

**Permission:** `InstructionDefinition:Read`

#### `POST /api/v1/definitions/{id}/response-templates`

Create a new template. Returns the canonicalised template (with auto-assigned `id` when omitted) and 201.

**Permission:** `InstructionDefinition:Write`

**Body:**

```json
{
  "name": "Failures only",
  "columns": ["Severity", "Title"],
  "sort": {"column": "Severity", "dir": "desc"},
  "filters": [{"column": "Severity", "op": "equals", "value": "high"}],
  "default": false
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | No | Auto-generated if omitted. The reserved id `__default__` is rejected. |
| `name` | string | Yes | Operator-facing label. Max 200 characters. |
| `description` | string | No | Optional longer description. |
| `columns` | array of strings | No | Subset of plugin column names. Empty / omitted means "show all". |
| `sort` | object | No | `{column: <name>, dir: asc\|desc}`. `dir` requires `column`. |
| `filters` | array of objects | No | `{column, op, value}` clauses. `op` ∈ `equals`, `not_equals`, `contains`, `starts_with`, `ends_with`. |
| `default` | boolean | No | At most one operator template may be marked default per definition. |

**Body size cap.** POST and PUT bodies are capped at **64 KiB**. Larger bodies receive a 413 response and a failure-audit emission with `reason=body_too_large` before parsing — preventing operator-tier JSON-bomb DoS against the single-process server.

**Errors:**

| Status | Reason |
|---|---|
| 400 | invalid JSON / missing name / unknown filter op / id collision / multiple default templates / `__default__` as authored id |
| 404 | Definition not found |
| 413 | Body exceeds 64 KiB cap |
| 500 | Persist failure (rare; see server logs) |
| 503 | Service unavailable |

#### `PUT /api/v1/definitions/{id}/response-templates/{template_id}`

Replace the named template in place.

**Permission:** `InstructionDefinition:Write`

Returns 400 when `template_id` is `__default__` (the synthesised default cannot be overwritten). Same 64 KiB body cap as POST.

**Errors:**

| Status | Reason |
|---|---|
| 400 | malformed id / `__default__` reserved / invalid JSON / validation failure |
| 404 | Definition or template not found |
| 413 | Body exceeds 64 KiB cap |
| 500 | Persist failure |
| 503 | Service unavailable |

#### `DELETE /api/v1/definitions/{id}/response-templates/{template_id}`

Remove a template. Returns 400 when `template_id` is `__default__`.

**Permission:** `InstructionDefinition:Write`

**Errors:**

| Status | Reason |
|---|---|
| 400 | malformed id / `__default__` reserved |
| 404 | Definition or template not found |
| 500 | Persist failure |
| 503 | Service unavailable |

**Audit events emitted:** `response_template.create`, `response_template.update`, `response_template.delete` — target type `InstructionDefinition`, target id = definition id, detail = template id (success) or `reason=<r>` (audit-path failure). 4xx branches emit `result=denied`; 500 persist failures emit `result=failure`; the 503 store-unavailable branch emits `result=error` (an infra degrade is not an operator denial — ADR-0058). See `audit-log.md` for the full reason vocabulary.

---

### Audit Log

Query the server audit trail. All state-changing operations are recorded with the acting principal, action, target, and result.

> **Reads deny on store degrade (ADR-0040).** The audit trail is the SOC 2 evidence chain, so the audit query endpoints (`GET /api/v1/audit`, `GET /api/v1/audit/auth-sample`, and the legacy `GET /api/audit`) **return `503` when the underlying store or connection pool is unavailable — never an empty `200`.** A reviewer, SIEM, or CMDB integration can therefore never mistake an infrastructure blip for "no audit activity"; treat a `503` here as a transient, retryable evidence-availability gap, not as an empty result set. This is the read-side counterpart to the fail-hard write posture (`503` + `Sec-Audit-Failed` on the behavioural-PII routes).

#### `GET /api/v1/audit`

Query audit events.

**Permission:** `AuditLog:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `limit` | integer | No | Max events to return (default 100, max 1000) |
| `principal` | string | No | Filter by acting user |
| `action` | string | No | Filter by action name |

**Response:**

```json
{
  "data": [
    {
      "timestamp": 1710849600,
      "principal": "admin",
      "action": "management_group.create",
      "result": "success",
      "target_type": "ManagementGroup",
      "target_id": "a1b2c3d4e5f6",
      "detail": "EU Production Servers"
    },
    {
      "timestamp": 1710849700,
      "principal": "admin",
      "action": "tag.set",
      "result": "success",
      "target_type": "Tag",
      "target_id": "agent-eu-prod-01:environment",
      "detail": "production"
    },
    {
      "timestamp": 1710849800,
      "principal": "jane.ops",
      "action": "quarantine.enable",
      "result": "success",
      "target_type": "Security",
      "target_id": "agent-compromised-01",
      "detail": "Suspicious network activity detected"
    }
  ],
  "pagination": { "total": 3, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

**`total` and `page_size` are not what they look like.** `total` is the
number of rows in this response's `data` array, not the number of rows that
matched — the route has no `offset` support, so a response at exactly
`limit` (max 1000) rows can be silently truncated, indistinguishable from a
complete answer. `page_size` is always `50`, regardless of the `limit` you
passed (tracked: [#2881](https://github.com/Tr3kkR/Yuzu/issues/2881)). If
you hit the cap, narrow with `principal=`/`action=`, or fall back to the
legacy `GET /api/audit` endpoint, which also accepts `offset`. `since`/`until`
alone only bounds the time window — it does not by itself guarantee
completeness inside that window if more rows matched than one call returns.
The reliable recipe is both together: freeze a bounded window with
`since`/`until` first, then page through it with `offset`.

**Errors:** `403` — caller lacks `AuditLog:Read`; `400` — `limit` parses to
less than 1 (a negative or zero limit; caught explicitly rather than reaching
PostgreSQL as an invalid `LIMIT`); `503` — the audit store is unavailable or
the query degraded (ADR-0040 deny-on-degrade — see the note above this
section; never a false-empty `200`). A non-numeric `limit` (e.g. `abc`) is
NOT a 400 here — it is silently caught and the request proceeds with the
default `limit` (100); the sibling `auth-sample` route below is stricter and
400s on the same input.

#### `GET /api/v1/audit/auth-sample`

Pseudo-random **sample** of authentication-surface audit events over an optional
time window — for SOC 2 **CC7.2** sampled-evidence export (auditor pulls a
representative sample of auth activity rather than the full log). Scoped to the
`auth.`, `mfa.`, `session.`, **and `engine_principal.`** action prefixes (logins,
MFA, session revocation, lockout, admin-gate denials, and every engine-principal
lifecycle/credential/audit event, since engine-principal identities are
themselves authentication-surface — a distinct principal class alongside human
users, not general application activity). Rows are returned in random
order so a bounded `limit` is a sample across the window, not just the latest N.

> **Sampling caveat (read before using as formal evidence).** The sample is
> drawn from at most the **10000 most-recent** matching events in the window.
> When the window holds more than that, the sample is **recency-biased** — it is
> a uniform sample of the newest 10000 events, *not* of the full window. The
> response `sampling` object reports this: `candidates_considered` (pool size the
> sample was drawn from), `scan_cap` (10000), and `recency_capped` (`true` when
> the pool hit the cap). For a uniform sample of a high-volume period, narrow the
> `from`/`to` window so it holds ≤ 10000 events. Samples are also
> **non-reproducible** (no seed) — re-running yields a different draw; the audited
> `audit.auth_sample.exported` row is the chain-of-custody record of what was pulled.

**Permission:** `AuditLog:Read` — note this is deliberately *not* admin-only, so
a dedicated read-only auditor role can pull evidence without full admin
(separation of duties).

The export is itself audited as `audit.auth_sample.exported` (who pulled which
window, and how many rows) so evidence access stays on the audit chain.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `from` | integer | No | Window start, epoch seconds, digits only (omit for unbounded) |
| `to` | integer | No | Window end, epoch seconds, digits only (omit for unbounded) |
| `limit` | integer | No | Sample size (default 100, max 1000) |

```bash
curl -s -G \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "from=1717200000" \
  --data-urlencode "to=1719792000" \
  --data-urlencode "limit=50" \
  "https://yuzu.example.com/api/v1/audit/auth-sample" | jq .
```

**Responses:** `200` sampled list — **same envelope and event field set as
`GET /api/v1/audit`** (`timestamp`, `principal`, `action`, `result`,
`target_type`, `target_id`, `detail`); the sample deliberately does **not**
widen what `AuditLog:Read` discloses (no `session_id` / `source_ip`). The
envelope additionally carries a `sampling` object (`candidates_considered`,
`scan_cap`, `recency_capped`). **Errors:** `403` — caller lacks
`AuditLog:Read`; `400` — `from`/`to` are not non-negative digits, `from >
to`, or `limit` is non-integer (unlike the sibling `GET /api/v1/audit`, a
non-numeric `limit` here IS a 400, not a silent fallback); `503` — the audit
store is closed (checked up front, before any query parameter is even
parsed) or the query itself degraded mid-request. If the export's own audit
row fails to persist, the response carries a `Sec-Audit-Failed: true` header
(the export still returns).

**Audit action names:**

| Action | Description |
|---|---|
| `audit.auth_sample.exported` | Auth evidence sample pulled via `GET /api/v1/audit/auth-sample`. `target_type=AuditLog`, `target_id=auth-sample`; `detail` carries `from=<epoch-or-0> to=<epoch-or-0> limit=<N> returned=<N>`. `result=success`. |
| `management_group.create` | Group created |
| `management_group.update` | Group updated (rename, re-parent, membership type change) |
| `management_group.delete` | Group deleted |
| `management_group.add_member` | Agent added to group |
| `management_group.remove_member` | Agent removed from group |
| `management_group.assign_role` | Role assigned on group |
| `management_group.unassign_role` | Role removed from group |
| `api_token.create` | API token created |
| `api_token.revoke` | API token revoked. Can carry `result=success` (token was revoked) or `result=denied` (a non-owner without the admin role attempted a cross-user revoke). Denied events include `detail=owner=<real owner>` so forensics can tell a legitimate self-revoke from an enumeration probe. |
| `user.create` | Local account created. `result` ∈ {`success`, `denied`}. Denied detail values: `duplicate_username` (409 — attempted create on an existing name), `weak_password` (400 — fewer than 12 characters). The `role` field is ignored on create — new users always land as `user`. To change role, use the dedicated `POST /api/settings/users/{username}/role` endpoint (audit action `user.role_change`). |
| `user.role_change` | Local account role changed via `POST /api/settings/users/{username}/role`. `result` ∈ {`success`, `denied`, `no_op`}. Denied detail values: `self_role_change_blocked` (403), `invalid_username` (400), `invalid_json` (400), `missing_role` (400), `invalid_role` (400), `user_not_found` (404), `db_failure` (500). `no_op` detail format `same_role={admin\|user}` (200) when the requested role equals the current role — recorded so compliance review can distinguish operator intent from inaction. Success detail format `old_role=user,new_role=admin`. |
| `user.delete` | Local account deleted. `result` ∈ {`success`, `denied`}. Denied detail values: `self_delete_blocked` (403), `invalid_username` (400), `user_not_found` (404). |
| `auth.admin_required` | Centralised denial event emitted by `AuthRoutes::require_admin` on every privileged-endpoint 403. `target_type=endpoint`, `target_id={req.path}`. SOC 2 CC7.2 evidence chain — captures rejected attempts that previously surfaced only in the request log. |
| `auth.lockout.applied` | Account locked after `--auth-lockout-threshold` consecutive failed local-password logins (SOC 2 CC6.3). Emitted **once** at the threshold crossing — not once per blocked attempt (those are tracked only by `yuzu_auth_lockout_blocked_total` to avoid audit flooding). `result=ok` (the lock was applied; the warning severity is carried by the metric + analytics event, not the audit result), `target_type=User`, `detail=threshold=<N> window_secs=<S>`. |
| `auth.lockout.cleared` | Account-lockout counter reset. `result` ∈ {`ok`, `error`}, `target_type=User`. `detail=admin_unlock` for `POST /api/v1/users/{name}/unlock`, or `reset_on_successful_login` when the user's next successful login clears a non-zero counter. |
| `execution.detail.fetch` | `GET /api/v1/executions/{id}` (REST v1 single-execution lookup). `result=denied` only (#1634) on the BARE route (no `include`) — emitted on the 404 branch, execution genuinely nonexistent OR out of the caller's management-group scope, non-distinguishing detail text; there is no `result=success` row on the bare route's 200 path. **As of #4030, this no longer holds for the whole URL pattern:** `?include=agents` on this same route, and the sibling `GET /api/v1/executions/{id}/responses`, both DO write `result=success` rows under this identical verb name on their 200 path (see `docs/user-manual/audit-log.md`'s `execution.detail.fetch` row for the full, current three-way split). |
| `execution.live_subscribe` | Server-Sent Events subscribe to `/sse/executions/{id}`. `result` ∈ {`success`, `denied`}. `success` emitted on every successful subscribe (no per-session-per-execution dedup currently — see #700). `denied` emitted (#1634) on the 404 branch — execution genuinely nonexistent OR out of the caller's management-group scope, using non-distinguishing detail text so the two cases stay audit-indistinguishable. The forensic-grade audit on first-load remains on `/fragments/executions/{id}/detail`'s `execution.detail.view`. |
| `api.v1.events.subscribe` | Agentic-first SSE subscribe to `/api/v1/events?execution_id=<id>` (sprint W5.1). `result` ∈ {`success`, `denied`}. `success` detail format: `correlation_id=req-<hex-ms>-<hex-seq>` so SIEM rules can join the audit row to the response's `X-Correlation-Id` header. Deliberately separated from `execution.live_subscribe` so the SIEM can distinguish browser-tier vs agentic-worker consumers. Same no-dedup policy (#700). `denied` emitted (#1634) on the 404 branch (unknown execution OR out of scope), using non-distinguishing detail text — corrects an earlier version of this row, which predated #1634 and said this 404 branch never audits. |
| `instruction.create` | Instruction definition created. `result` ∈ {`success`, `denied`, `error`}. Denied detail value: `duplicate_id` (409, explicit `id` already exists). `error` detail `db_error` on a genuine InstructionStore DB/lease failure (503, ADR-0058) — distinct from `denied`, since an infra degrade is not an operator denial. |
| `instruction.update` | Instruction definition updated via `PUT /api/instructions/{id}`. `result` ∈ {`success`, `denied`, `error`}. Denied detail value: `not_found` (404, unknown id). `error` detail `db_error` on a genuine DB/lease failure (503). A plain 400 validation error is not audited (matches `instruction.create`'s equivalent branch). |
| `instruction.delete` | Instruction definition deleted via `DELETE /api/instructions/{id}`. `result` ∈ {`success`, `denied`, `error`}. Denied detail value: `not_found` (404, unknown id). `error` detail `db_error` on a genuine DB/lease failure (503). |
| `instruction_set.delete` | Instruction set deleted via `DELETE /api/instruction-sets/{id}`. `result` ∈ {`denied`, `error`}. Denied detail value: `not_found` (404, unknown id). `error` detail `db_error` on a genuine DB/lease failure (503). Success is not audited (`create_set`/`delete_set` predate any audit coverage on this pair — tracked separately, #3598 — the 404/503 denial branches above are new with ADR-0058 and audited from the start rather than shipped asymmetrically). |
| `instruction.scope_resolution_failed` | Emitted at dispatch when a `from_result_set:` reference in the scope cannot be resolved (set absent, TTL-expired, or not owned by the dispatching principal). `result=failure`. Detail format: `INSTRUCTION_SCOPE_RESOLUTION_FAILED command=<command_id> ref=<id-or-alias> reason=...`. Fires on all scoped dispatch paths (generic REST, tracked, MCP) and increments the `yuzu_scope_resolution_failed_total` metric; as of governance M1 (2026-07-29) the **entire dispatch is aborted** — no devices are targeted, including from other scope atoms — recorded by a paired `scope.evaluation_aborted` row with `reason=owner_check_failed`. |
| `scope.evaluation_aborted` | Emitted when a scoped dispatch is aborted fail-closed before any device is targeted. `result=failure`. Reasons: `db_degraded` (a `from_result_set:<id>` alias/owner/membership read against the result-set store could not answer — ADR-0036 — **or** a `props.<key>` bulk preload against the custom-properties store could not answer — ADR-0045; both abort the same way and share this reason value), `owner_check_failed` (a referenced set is absent, expired, or not owned — paired with per-ref `instruction.scope_resolution_failed` rows), `principal_unresolved` (a tracked/MCP dispatch could not recover the dispatching operator). Fires on all three scoped dispatch paths, plus the no-principal tracked-closure guard (principal_unresolved only). |
| `bundle.dispatch` | Live-query bundle dispatched via `POST /api/v1/bundles` (ADR-0011). `target_type=Execution`. `result=success` (`target_id=<bundle-… correlation id>`, detail `agent=<id> steps=<n>`) or `result=failure` (dispatch threw — `target_id` empty, detail `agent=<id> error=<…>`). |
| `bundle.<plugin>.<action>` | One step of a live-query bundle, emitted per step at dispatch — the device-access lens. `target_type=Agent`, `target_id=<agent_id>`. `result=dispatched` (reached the agent) or `result=no_agents` (reached zero agents → `dispatch_failed` on collate). A bundle of N steps emits N of these, so it is exactly as auditable as N separate executions (works-council parity). Emitted on **both** the REST and MCP surfaces (the per-step verb is transport-agnostic; the MCP tool-call envelope additionally audits as `mcp.execute_bundle`). |
| `bundle.collate` | Live-query bundle collated via `GET /api/v1/bundles/{id}`. `target_type=Execution`, `target_id=<correlation id>`. `result=success` (detail `complete=0\|1`), `result=denied` (`not found or not owned` — the 404 covers both an unknown id and a non-owner, so the audit row is where the real reason is recorded), or `result=failure` (`response store degraded` — a 503, distinct from `denied`: the bundle WAS found and owned, the read just could not be served; retryable, `retry_after_ms:5000`). |
| `policy_fragment.create` | Policy fragment created. `result` ∈ {`success`, `denied`}. Denied detail value: `duplicate_name` (409, fragment with the same `name` already exists). |
| `policy.evaluate` | Compliance evaluation forced for a policy via `POST /api/policies/{id}/evaluate`. `result` ∈ {`success`, `error`}. Success detail format `execution_id=<id>`. Note: the `409` rejection (no check instruction / no matching agents) returns without emitting an audit row; the `503` degraded-evaluation case (`policy_evaluator_->evaluate_now` returning an error, e.g. an InstructionStore DB/lease failure per ADR-0058) DOES audit, `result=error` detail `degraded` — matches `policy.remediate`'s own `error`-vs-`denied` convention: an infra degrade is not an operator denial. |
| `policy.remediate` | Manual remediation triggered via `POST /api/policies/{id}/remediate`. `result` ∈ {`success`, `denied`, `error`}. Success detail `execution_id=<id> agents=<n>` (`agents` = delivered count, see the route doc); denied detail carries the reason (e.g. fragment defines no `fix` instruction, no non-compliant agents, a target is already claimed for remediation, or a target has reached its fix-retry cap for this policy); `error` is a genuine store/evaluator degrade, distinct from `denied`. |
| `quarantine.enable` | Device quarantined |
| `quarantine.disable` | Device released from quarantine |
| `ca.cert.issued` | Internal CA signed a per-agent client certificate at enrollment. `target_type=AgentCertificate`, `target_id=<serial>`, `result=success`. Also emitted by `POST /api/v1/ca/issue-code-signing` (gap-matrix #10) / MCP `issue_code_signing_cert`: `target_type=CodeSigningCertificate`, `target_id=<label>` on a rejected request or `<serial_hex>` on success, `detail` carries `purpose=code-signing`; `result=success`, `result=denied` (no CA root, or a bad/unparseable CSR), or `result=failure` (a genuine 5xx — key-load, signing, or `ca_store` write failure). |
| `ca.cert.revoked` | Certificate revoked via `POST /api/v1/ca/revoke`. `target_type` is derived from the revoked cert's `purpose` — `AgentCertificate` for an agent leaf, `CodeSigningCertificate` for a code-signing leaf (gap-matrix #10), or the neutral `Certificate` when the serial is not found or the `ca_store` read fails; `target_id=<serial>`. `result=success`; `result=denied` with `detail="serial not found or already revoked"` for an unknown/already-revoked serial (reject without state change, matches every destructive sibling); `result=failure` (ADR-0053) for a genuine ca_store DB/lease error — kept distinct from `denied` so a database outage is never audited as a rejected revoke attempt. |
| `ca.crl.published` | CRL (re)published after a revocation. `target_type=Security`, `target_id=<serial that triggered it>`. `result=success`, or `result=failure` when the CRL could not be rebuilt/recorded (the revocation still stands; the public CRL is momentarily stale). |
| `ca.root_csr.exported` | The install CA's CSR was exported via `GET /api/v1/ca/root-csr` (subordinate-CA setup). `target_type=CaRoot`, `target_id=root`. `result=success`, or `result=failure` if generation failed. |
| `ca.subordinate.imported` | An enterprise-signed intermediate was imported via `POST /api/v1/ca/import-chain` (or the dashboard wrapper). `target_type=CaRoot`, `target_id=root`. `result=success` on a validated switch to subordinate mode; `result=denied` when the uploaded material is rejected (not a CA / wrong key / does not chain); `result=failure` on a server-side persistence error. `detail` carries `reason=...` on rejection and `via=dashboard` for the panel path. |
| `tag.set` | Tag created or updated |
| `tag.delete` | Tag deleted |

---

### Access Reviews

Periodic access reviews (SOC 2 **CC6.2**) — a fleet-wide export of every
principal's current role grants, plus a durable attestation-campaign
workflow so a reviewer (manager/security) can sign off on each grant or
flag it for revocation. Covers all three RBAC principal types: **user**,
**group**, and **engine**.

> **#2225 chokepoint note.** These routes are deliberately gated on a
> **GLOBAL** `AccessReview:Read`/`AccessReview:Attest`, **not** the ADR-0017
> `authorize_list_read` admit-then-filter confinement chokepoint every new
> per-agent list read must use. A management-group-confined slice of the
> grant population would be **useless** as CC6.2 evidence — a reviewer
> certifying the fleet must see the *entire* grant population, not one
> operator's confined view of it. Access review is intentionally
> admin/auditor-only and unconfined by design, not an oversight. See
> `docs/auth-architecture.md` "Periodic access reviews" for the full
> rationale. `AccessReview` is a **dedicated** securable type (not a reuse
> of `AuditLog`) seeded only to `Administrator` and the `Reviewer` role — an
> earlier round of this feature gated it on `AuditLog:Read`/`AuditLog:Attest`
> instead, which over-disclosed the full grant population to the `Operator`
> and `PlatformEngineer` roles (both seeded `AuditLog:Read` for unrelated
> reasons, neither seeded `UserManagement:Read`/`EnginePrincipal:Read`, the
> permissions gating the equivalent-sensitivity `/rbac/roles` and
> `/engine-principals/{id}/roles` routes — the latter moved off the
> over-broad `Security:Read` in #2376). See
> `docs/security-reviews/access-reviews-2026-07-21.md` "#2225 round 2" for
> the finding and fix.

> **Engine-session denial, every route including reads.** Every route on
> this surface — `GET`/list, `GET .../export`, `GET .../{id}`, and every
> mutating route — structurally denies a caller whose *own* session is
> engine-classed (`principal_kind="engine"` or `auth_source="engine_token"`,
> the same `deny_engine_session` belt the engine-principals surface uses):
> an engine principal can never enumerate, read, or mutate any access-review
> campaign or pull the export, not even one it opened itself via an
> automation flow. A denied engine-classed caller gets `403`; the
> corresponding audit verb is recorded with `result=denied` and
> `detail="engine_session_denied"`.

**Grant-table-driven completeness.** The export and every campaign freeze
are driven by the grant table, not a roster walk — a principal with **zero**
role grants produces no row (the export answers "who currently has access",
not "who exists"), while a grant belonging to a principal that matches
nothing in any roster (a since-deleted user, a stale IdP row, an OIDC/SSO
principal minted outside every roster) is surfaced as a row with
`source="orphan"`, `lifecycle_state="unknown"`, `display_name` equal to the
raw `principal_id` — never silently dropped. See `docs/auth-architecture.md`
"Periodic access reviews" → "Grant-table-driven completeness" for the full
rationale and the non-atomic cross-substrate read caveat.

#### `GET /api/v1/access-reviews/export`

Stateless cross-principal grant export — every user/group/engine-principal's
**direct** role grants right now (user rows do not include group-inherited
access; that access appears on the group's own row). `?format=json|csv`
(default `json`).

**Permission:** `AccessReview:Read`.

The export is itself audited as `access_review.exported`.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `format` | string | No | `json` or `csv` (default `json`) |

**Responses:** `200` — JSON: `data[]` of `{principal_type, principal_id,
display_name, owner_or_email, roles[], effective_permission_count,
last_activity_ms, last_activity_kind, classification, lifecycle_state,
source}`. CSV: the same fields with a `Content-Disposition: attachment`
header. `400` if `format` is not `json`/`csv`. `403` without
`AccessReview:Read` (or an engine-classed caller — see the note above). `503` —
**fail-loud**: a read across users, groups, engine-principals, or tokens
failed. This endpoint never returns a silent partial export — an empty 200
always means "no grants", never "the read partially failed". If the
export's own audit row fails to persist, the response carries a
`Sec-Audit-Failed: true` header (the export still returns).

**CSV formula-injection neutralization.** Every CSV field is RFC-4180
escaped, and any field whose first byte is one Excel/Sheets treats as a
formula trigger (`=`, `+`, `-`, `@`, tab, CR) is additionally prefixed with
a literal `'` **before** the RFC-4180 quoting pass (CWE-1236). Several
fields on this export are influenceable by an external identity provider
(SCIM `userName`, an engine principal's `display_name`) — this is not a
theoretical input, and the neutralization applies unconditionally to every
row, orphan rows included.

Known scoping notes (accurate as shipped, not defects to "fix" reflexively):
`last_activity_kind` is `"n/a"` for every user row today — `AuthDB` has no
read accessor for last-login yet (a noted follow-up); `source="scim"` for
users is forward-compat and not yet populated by any write path; an orphan
row (grant with no matching roster entry — see "Grant-table-driven
completeness" above) always carries `last_activity_kind="n/a"` and
`classification=""` too, since there is no roster row to enrich it from. A
**disabled** user who still holds a live grant is a normal, roster-matched
row — `source="user"`, `lifecycle_state="disabled"` — never confused with
an orphan row; it is exactly the kind of finding a periodic access review
exists to surface.

#### `GET /api/v1/access-reviews`

List every review campaign's metadata (**not** its attestations — use
`GET /api/v1/access-reviews/{id}` for those), newest-first, capped at the
most recent 500. The surface an auditor needs to prove reviews ran on
cadence without already knowing a `campaign_id` out-of-band.

**Permission:** `AccessReview:Read`.

**Responses:** `200` — `{data: [{campaign_id, title, status, created_by,
created_at_ms, closed_by, closed_at_ms}], meta}`. `403` without
`AccessReview:Read` (or an engine-classed caller). `503` — the access-review
store is unavailable, or a genuine read failure.

Audited as `access_review.list`.

#### `POST /api/v1/access-reviews`

Open a review campaign — freeze the **current** cross-principal grant
population (the same rows `GET .../export` returns, expanded to one row per
`(principal, role)` grant) into a new, durable campaign. A grant created
after this call returns is out of scope for **this** campaign (review it in
the next one); a grant revoked afterward stays reviewable — the frozen row
is not re-derived from live state. This freeze-at-open property is what
makes "every grant that existed when the campaign opened has a reviewable
row" provable rather than assumed.

**Permission:** `AccessReview:Attest`.

**Request body:**

```json
{ "title": "Q3 2026 Access Review" }
```

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | string | Yes | Human-readable campaign name |

**Responses:** `201` — `{campaign_id, grant_count}`. `400` — invalid JSON,
or `title` missing/empty. `403` without `AccessReview:Attest` (or an
engine-classed caller). `503` — the access-review store is unavailable, or
the grant-population read failed.

Audited as `access_review.campaign_opened` (`detail` carries `grants=<N>`
on success).

#### `GET /api/v1/access-reviews/{id}`

Full evidentiary state of one review campaign: metadata plus every frozen
attestation row (`pending`/`attested`/`flagged_revoke`) plus `pending_count`
(the review-completeness number).

**Permission:** `AccessReview:Read`.

**Responses:** `200` —

```json
{
  "campaign": {
    "campaign_id": "...", "title": "...", "status": "open",
    "created_by": "alice", "created_at_ms": 0,
    "closed_by": "", "closed_at_ms": 0
  },
  "attestations": [
    {
      "principal_type": "user", "principal_id": "bob", "role_name": "Operator",
      "decision": "pending", "reviewer": "", "decided_at_ms": 0,
      "justification": "", "grant_snapshot": { "display_name": "bob", "...": "..." }
    }
  ],
  "pending_count": 1
}
```

`403` without `AccessReview:Read` (or an engine-classed caller). `404` — no
campaign with that id. `503` — the access-review store is unavailable, or a
genuine read failure.

Audited as `access_review.get`.

#### `POST /api/v1/access-reviews/{id}/attestations`

Record one reviewer decision against a grant frozen into an open campaign.

**Permission:** `AccessReview:Attest`.

**Request body:**

```json
{
  "principal_type": "user",
  "principal_id": "bob",
  "role_name": "Operator",
  "decision": "attested",
  "justification": "Confirmed still required for on-call rotation."
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `principal_type` | string | Yes | `user` \| `group` \| `engine` |
| `principal_id` | string | Yes | Principal identifier |
| `role_name` | string | Yes | Role being reviewed |
| `decision` | string | Yes | `attested` \| `flagged_revoke` |
| `justification` | string | No | Free-text reviewer note |

**`flagged_revoke` records evidence ONLY — it never itself revokes the
grant.** No RBAC/EnginePrincipal mutation happens on this path; acting on
the flag (unassigning the role, revoking the engine principal, etc.) is a
separate, explicit operator action performed after reading this evidence.
flag ≠ revoke.

**Responses:** `200` — `{recorded: true}`. `400` — `principal_type`,
`principal_id`, or `role_name` missing, or `decision` is neither `attested`
nor `flagged_revoke`. `403` without `AccessReview:Attest` (or an engine-classed
caller). `404` — no campaign with that id, no such frozen grant in it, or
the campaign is already closed. `503` — the access-review store is
unavailable, or a genuine write failure.

**This route is an UPSERT — a second call for the same `(campaign_id,
principal_type, principal_id, role_name)` overwrites the prior reviewer's
decision, reviewer, and justification.** The earlier decision is not
retained (mirrors `record_attestation`'s MCP `destructiveHint:true`, see
`docs/mcp-server.md`).

Audited as `access_review.attested` (decision `attested`) or
`access_review.flagged` (decision `flagged_revoke`) — the two outcomes are
separately countable/alertable, not one verb with a buried field.

#### `POST /api/v1/access-reviews/{id}/close`

Close an open review campaign. Does **not** require every attestation to be
decided first — a campaign closed with `pending` rows still outstanding is
itself evidence (an incomplete review), not something this route silently
forces to completion.

**Permission:** `AccessReview:Attest`.

**Responses:** `200` — `{closed: true}`. `403` without `AccessReview:Attest`
(or an engine-classed caller). `404` — no campaign with that id, or already
closed. `503` — the access-review store is unavailable, or a genuine write
failure.

Audited as `access_review.closed`.

**Audit action names:**

| Action | Description |
|---|---|
| `access_review.exported` | Cross-principal grant export pulled via `GET /api/v1/access-reviews/export`. `target_type=AccessReview`, `detail=format=<json\|csv> rows=<N>`. `result=success`. |
| `access_review.list` | Campaign list pulled via `GET /api/v1/access-reviews`. `target_type=AccessReview`. `result=success`. |
| `access_review.campaign_opened` | Review campaign opened via `POST /api/v1/access-reviews`. `target_id=<campaign_id>`, `detail=grants=<N>` on success. `result` ∈ {`success`, `failure`}. |
| `access_review.attested` | Reviewer recorded `decision=attested` via `POST /api/v1/access-reviews/{id}/attestations`. `target_id=<campaign_id>:<principal_type>:<principal_id>:<role_name>`. `result` ∈ {`success`, `failure`}. |
| `access_review.flagged` | Reviewer recorded `decision=flagged_revoke` via the same endpoint. Same target/result shape as `access_review.attested` — a separate verb so flagged grants are separately countable/alertable. **Evidence only — does not revoke.** |
| `access_review.closed` | Campaign closed via `POST /api/v1/access-reviews/{id}/close`. `target_id=<campaign_id>`. `result` ∈ {`success`, `failure`}. |
| `access_review.get` | Campaign evidentiary state read via `GET /api/v1/access-reviews/{id}`. `target_id=<campaign_id>`. `result=success`. |

Every `access_review.*` verb above additionally records `result=denied`
(`detail="engine_session_denied"`) when the caller's own session is
engine-classed — see the "Engine-session denial" note above.

MCP twins (JSON only — the REST `?format=csv` export path has no MCP
equivalent): `export_access_review`, `open_access_review`,
`record_attestation`, `get_access_review`, `list_access_reviews`,
`close_access_review`. See `docs/mcp-server.md`.

---

### Policy Fragments

Policy fragments are reusable check/fix/postCheck patterns that define compliance checks and auto-remediation actions.

#### `GET /api/policy-fragments`

List all policy fragments.

**Permission:** `Policy:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Filter by fragment name (substring match) |
| `limit` | integer | No | Maximum results (default 100) |

**Response:**

```json
{
  "fragments": [
    {
      "id": "frag-abc123",
      "name": "ensure-defender-enabled",
      "description": "Verify Windows Defender is active",
      "check_instruction": "security.defender-status",
      "fix_instruction": "security.enable-defender",
      "post_check_instruction": "",
      "created_at": 1710849600
    }
  ]
}
```

---

#### `POST /api/policy-fragments`

Create a new policy fragment from YAML.

**Permission:** `Policy:Write`

**Request body:**

```json
{
  "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n..."
}
```

**Response (200):**

```json
{
  "id": "frag-abc123",
  "status": "created"
}
```

**Response (400):** YAML missing required fields, oversized payload, invalid CEL compliance expression. Body is `{"error": "<reason>"}`.

**Response (409):** Returned when a fragment with the same `name` already exists. Body is `{"error": "policy fragment named '<name>' already exists"}`. Audit event recorded as `policy_fragment.create / denied / duplicate_name`. Choose a different name (existing fragments are immutable on rename).

**Response (503):** Policy store not yet initialized, or a genuine internal store failure on the write (safe to retry — distinct from the 400/409 rejections above, and the internal error string is never included in the body).

---

#### `DELETE /api/policy-fragments/{id}`

Delete a policy fragment.

**Permission:** `Policy:Delete`

**Response:**

```json
{
  "deleted": true
}
```

---

#### `GET /api/v1/policy-fragments`

REST v1 twin of `GET /api/policy-fragments` above (api-parity #4034) — same query
parameters, same row shape, A4-enveloped. MCP twin: `list_policy_fragments`.

**Permission:** `Policy:Read`

**Response:**

```json
{
  "data": [
    {
      "id": "frag-abc123",
      "name": "ensure-defender-enabled",
      "description": "Verify Windows Defender is active",
      "check_instruction": "security.defender-status",
      "check_compliance": "result.enabled == true",
      "fix_instruction": "security.enable-defender",
      "post_check_instruction": "",
      "created_at": 1710849600,
      "updated_at": 1710849600
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

**Response (503):** `{"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}}`

---

### Policies

Policies bind fragments to devices via scope expressions, triggers, and management group bindings.

#### `GET /api/policies`

List all policies.

**Permission:** `Policy:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Filter by policy name (substring match) |
| `fragment_id` | string | No | Filter by fragment ID |
| `enabled_only` | boolean | No | Return only enabled policies |
| `limit` | integer | No | Maximum results (default 100) |

**Response:**

```json
{
  "policies": [
    {
      "id": "pol-xyz789",
      "name": "baseline-security",
      "fragment_id": "frag-abc123",
      "scope_expression": "tag:environment = 'production'",
      "enabled": true,
      "management_groups": ["eu-production"],
      "triggers": [{"type": "interval", "config": {"interval_seconds": 300}}],
      "created_at": 1710849600,
      "updated_at": 1710849600
    }
  ]
}
```

---

#### `POST /api/policies`

Create a new policy from YAML.

**Permission:** `Policy:Write`

**Request body:**

```json
{
  "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: Policy\n..."
}
```

**Response (200):**

```json
{
  "id": "pol-xyz789",
  "status": "created"
}
```

**Response (400):** YAML missing required fields, unknown `fragment_id`, invalid scope expression. Body is `{"error": "<reason>"}`.

**Response (503):** A genuine internal store failure on the write — safe to retry, and the internal error string is never included in the body.

---

#### `GET /api/policies/{id}`

Get policy detail including compliance summary.

**Permission:** `Policy:Read`

**Response:**

```json
{
  "policy": {
    "id": "pol-xyz789",
    "name": "baseline-security",
    "fragment_id": "frag-abc123",
    "scope_expression": "tag:environment = 'production'",
    "enabled": true,
    "remediation_available": true,
    "management_groups": ["eu-production"],
    "triggers": [{"type": "interval", "config": {"interval_seconds": 300}}],
    "inputs": [{"key": "severity", "value": "high"}],
    "created_at": 1710849600,
    "updated_at": 1710849600
  },
  "compliance": {
    "compliant": 42,
    "non_compliant": 3,
    "unknown": 5,
    "fixing": 1,
    "error": 0,
    "total": 51
  }
}
```

---

#### `DELETE /api/policies/{id}`

Delete a policy and all associated compliance data.

**Permission:** `Policy:Delete`

**Response:**

```json
{
  "deleted": true
}
```

---

#### `POST /api/policies/{id}/enable`

Enable a previously disabled policy.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "status": "ok"
}
```

**Response (400):** `policy not found`. **Response (503):** a genuine internal
store failure on the write — safe to retry, internal error string never
included in the body.

---

#### `POST /api/policies/{id}/disable`

Disable a policy, pausing compliance checks.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "status": "ok"
}
```

**Response (400):** `policy not found`. **Response (503):** a genuine internal
store failure on the write — safe to retry, internal error string never
included in the body.

---

#### `POST /api/policies/{id}/invalidate`

Invalidate agent-side compliance cache for a specific policy. Resets all agent statuses to `pending`, forcing re-evaluation.

**Permission:** `Policy:Execute`

**Response:**

```json
{
  "status": "ok",
  "agents_invalidated": 42
}
```

**Response (503):** a genuine internal store failure on the write — safe to
retry, internal error string never included in the body.

---

#### `POST /api/policies/invalidate-all`

Invalidate compliance cache for all policies across all agents.

**Permission:** `Policy:Execute`

**Response:**

```json
{
  "status": "ok",
  "total_invalidated": 210
}
```

**Response (503):** a genuine internal store failure on the write — safe to
retry, internal error string never included in the body.

---

#### `POST /api/policies/{id}/evaluate`

Force an immediate compliance evaluation of a policy, ignoring its interval. The
server dispatches the bound fragment's `check` instruction to the policy's scope
and, once responses arrive (within a short grace window), evaluates the CEL
`check_compliance` per agent and writes `compliant` / `non_compliant` /
`unknown` / `error` to each agent's status — which is what
`GET /api/compliance` and `GET /api/policies/{id}` then report. Evaluation is
asynchronous: this returns immediately with the dispatch `execution_id`; the
verdicts appear a few seconds later.

**Permission:** `Policy:Execute`

**Response (202):**

```json
{
  "status": "dispatched",
  "execution_id": "polchk-a1b2c3d4e5f60718"
}
```

**Response (404):** policy not found. **Response (409):** the policy's fragment
has no `check` instruction, the policy matches no agents, or a check for this
policy is already in flight. **Response (503):** either the policy evaluator
isn't wired ("policy evaluation not available"), or a genuine internal store
failure occurred while reading the policy or fragment, recording the dispatch
claim, or (ADR-0058) resolving the check instruction against InstructionStore
("policy store degraded" / "policy evaluation degraded") — a transient failure
of this kind is safe to retry and is never reported as a 409.

**Audit:** `policy.evaluate` — including on the 503 degraded-evaluation case above
(`result=error`, detail `degraded`).

---

#### `POST /api/policies/{id}/remediate`

Manually remediate a policy's non-compliant agents. **Only available when the
bound fragment defines a `fix` instruction** (the `remediation_available` flag
on the policy detail) — this is the operator-gated "would you like to remediate
this?" action; remediation is never automatic. The server marks the targets
`fixing`, dispatches the `fix` instruction, then runs the `postCheck` (falling
back to `check`) and writes the verified post-fix verdict.

**Permission:** `Policy:Execute`

**Request body (optional):**

```json
{
  "agent_ids": ["agent-123", "agent-456"]
}
```

If `agent_ids` is omitted, every agent currently `non_compliant` for the policy
is remediated.

**Response (202):**

```json
{
  "status": "remediating",
  "execution_id": "polchk-9f8e7d6c5b4a3021",
  "agents": 2
}
```

The `agents` field counts targets the fix was actually **dispatched to**
(delivered). A claimed-but-undelivered target (offline / quarantined / plugin
absent) releases its claim without consuming a retry attempt and is excluded
from the count, so `agents` may be smaller than the number of `agent_ids`
requested.

**Response (404):** policy not found. **Response (409):** the fragment defines no
`fix` instruction, there are no non-compliant agents to remediate, or a target
could not be claimed — either it is already claimed for remediation (a durable
per-`(policy, agent)` claim in `PolicyStore`, safe across replicas, HA WS-3
3.4) or it has exhausted its fix-retry cap for this policy. The response body
message is `"remediation already in flight or retry cap reached for this
policy"`.
**Response (503):** either the policy evaluator isn't wired ("policy evaluation
not available"), or a genuine internal store failure occurred while resolving
the policy or its remediation targets, including (ADR-0058) InstructionStore
resolving the fix instruction ("policy store degraded" / "policy store
unavailable") — safe to retry, and distinguished from the 400/409 business
rejections above.

**Audit:** `policy.remediate` (`result` ∈ {`success`, `denied`, `error`} — `error`
is a store degrade, never a business rejection).

---

#### `GET /api/v1/policies`

REST v1 twin of `GET /api/policies` above (api-parity #4034) — same query
parameters, same row shape, A4-enveloped. MCP twin: `list_policies` (a narrower
5-field subset of this row shape — id/name/description/enabled/scope_expression
only).

**Permission:** `Policy:Read`

**Response:** same `data`/`pagination`/`meta` envelope shape as
`GET /api/v1/policy-fragments` above, wrapping the same per-policy row
`GET /api/policies` documents.

---

#### `GET /api/v1/policies/{id}`

REST v1 twin of `GET /api/policies/{id}` above (api-parity #4034) — flat
top-level fields (not nested under a `"policy"` key), A4-enveloped. MCP twin:
`get_policy`.

**Permission:** `Policy:Read`

**Response:**

```json
{
  "data": {
    "id": "pol-xyz789",
    "name": "baseline-security",
    "description": "",
    "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: Policy\n...",
    "fragment_id": "frag-abc123",
    "scope_expression": "tag:environment = 'production'",
    "enabled": true,
    "remediation_available": true,
    "inputs": { "severity": "high" },
    "triggers": [{ "id": 1, "type": "interval", "config": { "interval_seconds": 300 } }],
    "management_groups": ["eu-production"],
    "created_at": 1710849600,
    "updated_at": 1710849600,
    "compliance": {
      "compliant": 42,
      "non_compliant": 3,
      "unknown": 5,
      "fixing": 1,
      "error": 0,
      "total": 51
    }
  },
  "meta": { "api_version": "v1" }
}
```

**Response (404):** `{"error":{"code":404,"message":"policy not found"},"meta":{"api_version":"v1"}}`

---

### Compliance

Fleet and per-policy compliance status endpoints.

#### `GET /api/compliance`

Fleet compliance summary across all active policies.

**Permission:** `Policy:Read`

**Response (200):**

```json
{
  "compliance_pct": 92.5,
  "total_checks": 200,
  "compliant": 185,
  "non_compliant": 8,
  "unknown": 5,
  "fixing": 2,
  "error": 0
}
```

**Response (503):** `policy store degraded` — a genuine internal store failure,
distinct from a genuine 0% (no policies enabled yet reads as all-zero counts
with `200`, never a 503).

---

#### `GET /api/compliance/{policy_id}`

Per-policy compliance detail with per-agent statuses.

**Permission:** `Policy:Read`

**Response (200):**

```json
{
  "summary": {
    "compliant": 42,
    "non_compliant": 3,
    "unknown": 5,
    "fixing": 1,
    "error": 0,
    "total": 51
  },
  "agents": [
    {
      "agent_id": "agent-01",
      "status": "compliant",
      "last_check_at": 1710936000,
      "last_fix_at": 0,
      "check_result": "{\"realtime_protection\": true}"
    }
  ]
}
```

**Response (503):** `policy store degraded`, on either the summary or the
per-agent-status read.

---

#### `GET /api/v1/compliance`

REST v1 twin of `GET /api/compliance` above (api-parity #4034), A4-enveloped.
MCP twin: `get_fleet_compliance`.

**Permission:** `Policy:Read`

**Response:**

```json
{
  "data": {
    "compliance_pct": 92.5,
    "total_checks": 200,
    "compliant": 185,
    "non_compliant": 8,
    "unknown": 5,
    "fixing": 2,
    "error": 0
  },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/compliance/{policy_id}`

REST v1 twin of `GET /api/compliance/{policy_id}` above (api-parity #4034),
A4-enveloped, plus a `policy_id` sibling field the legacy route also returns
(the legacy route's own doc example above omits it — pre-existing doc drift,
not introduced by this route). **Authorization is `require_fleet_read`
(`Policy:Read`), not a bare permission check** — the per-agent `agents` array
is a fan-out read of per-agent data (routed-concerns RBAC row), so a
management-group- or service-scope-confined caller sees only the agents
visible to it, and `summary` is tallied from exactly that filtered set, never
the store's unfiltered fleet-wide aggregate. MCP twin: `get_policy_agent_statuses`
(same shape) — `get_compliance_summary` covers the `summary`-only half.

**Permission:** `Policy:Read` (fleet-read gate)

**Response:**

```json
{
  "data": {
    "policy_id": "pol-xyz789",
    "summary": {
      "compliant": 42,
      "non_compliant": 3,
      "unknown": 5,
      "fixing": 1,
      "error": 0,
      "total": 51
    },
    "agents": [
      {
        "agent_id": "agent-01",
        "status": "compliant",
        "last_check_at": 1710936000,
        "last_fix_at": 0,
        "check_result": "{\"realtime_protection\": true}"
      }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

**Audit:** `compliance.agent_statuses.view` — **fail-closed** (`503` +
`Sec-Audit-Failed: true`, never a `2xx` on an audit-persist miss), matching
this API's general behavioural-PII posture (see [`Sec-Audit-Failed` and the
behavioural-PII audit posture](#sec-audit-failed-and-the-behavioural-pii-audit-posture)
above). Unlike the five sibling routes above it, this route's `check_result`
field carries the raw, unrestricted output of whatever instruction the
bound fragment's `check_instruction` names — free-form and
operator-authored at fragment-creation time, not a fixed machine-scope
shape — so it cannot make the same "not behavioural PII" claim
`GET /api/v1/inventory/software` genuinely can. The MCP twin
(`get_policy_agent_statuses`) is unaffected: it follows MCP's own
convention of surfacing the same gap via an `audit_persisted:false` body
field rather than a header/status code.

---

### Runtime Configuration

Runtime configuration endpoints read and update a predefined set of server settings. Every accepted
write is persisted immediately; **whether it also takes effect immediately depends on the key** - see
[When a change takes effect](#when-a-change-takes-effect). In particular, writing an OIDC key through
this API does **not** re-initialise the running OIDC provider.

#### `GET /api/config`

Returns current configuration values and any active runtime overrides.

**Permission:** `Infrastructure:Read`

> **Secret values are never returned.** For an override whose key holds a credential
> (today: `oidc_client_secret`) the `value` field is **omitted entirely** and replaced
> by `"is_set": true|false`. It is not a placeholder string: a placeholder is a legal
> value, so a config-as-code or backup-restore client that read this and wrote it back
> would silently overwrite the real secret. `updated_by` and `updated_at` are still
> returned. `PUT /api/config/oidc_client_secret` sets it, and its 200 response omits
> the value too.

**Error (503) - runtime config store unavailable.** If the store is closed, failed to open, or a
read against an otherwise-open store fails (a transient database error), this returns 503 rather
than an empty `overrides`, so a degraded store is never read as "nothing is configured". This
route never decrypts `oidc_client_secret` to answer `GET` — `is_set` is derived from whether a
secrets-table row exists for the key, not from its (never-fetched) value — so a corrupted or
undecryptable secret cannot 503 this route; that failure mode is confined to server boot instead
(see `docs/adr/0060-runtime-config-store-postgres-migration.md`). Key presence and `is_set` are
still the only way to answer "is the OIDC secret set on this server?" - the question
[Security hardening](security-hardening.md#oidc-hardening) sends operators to before deciding
whether to rotate.

```json
{ "error": { "code": 503, "message": "runtime config store unavailable" }, "meta": { "api_version": "v1" } }
```

**Response** (shape corrected - the handler returns `config`, `overrides` and
`allowed_keys`, not a `data`/`meta` envelope):

```json
{
  "config": { "heartbeat_timeout": 120, "log_level": "info" },
  "overrides": {
    "log_level":          { "value": "debug", "updated_by": "admin", "updated_at": 1754150400 },
    "oidc_client_secret": { "is_set": true,   "updated_by": "admin", "updated_at": 1754150400 }
  },
  "allowed_keys": ["heartbeat_timeout", "log_level", "oidc_client_secret"]
}
```

`allowed_keys` above is abridged for readability; the real response lists every key in the
[allowed-keys table](#put-apiconfigkey). `config` reports effective values and `overrides` only the
keys with a stored override, so a key can appear in `config` without appearing in `overrides`.

---

#### `PUT /api/config/:key`

Update a single runtime configuration value. The key must be one of the allowed runtime-configurable keys.

**Permission:** `Infrastructure:Write`

**Allowed keys** (the full set; source of truth is `kAllowedKeys` in
`server/core/src/runtime_config_store.cpp`):

| Key | Type | Takes effect | Description |
|---|---|---|---|
| `heartbeat_timeout` | integer | immediately | Seconds before an agent is considered offline |
| `response_retention_days` | integer | **stored only, applied at next restart** | Days to retain command response data |
| `audit_retention_days` | integer | **stored only, applied at next restart** | Days to retain audit log entries |
| `guardian_event_retention_days` | integer | **stored only, applied at next restart** | Days to retain guaranteed-state events |
| `log_level` | string | immediately | Server log verbosity (`trace`, `debug`, `info`, `warn`, `error`) |
| `auto_approve_enabled` | boolean | **never - see note** | Accepted and stored, but no consumer reads it back |
| `plugin_signing_required` | boolean | **records intent only - see note** | Server-side record of the Settings "Require signed plugins" toggle |
| `oidc_issuer` | string | **see note** | OIDC issuer URL |
| `oidc_client_id` | string | **see note** | OIDC client ID |
| `oidc_client_secret` | string | **see note** | OIDC client secret (write-only through this API) |
| `oidc_redirect_uri` | string | **see note** | OIDC redirect URI |
| `oidc_admin_group` | string | **see note** | OIDC admin group ID |
| `oidc_skip_tls_verify` | boolean | **see note** | Skip TLS verification to the IdP (test only) |
| `dex_alert_routing` | string (JSON array) | **persisted only - see note** | Routed DEX observation types |
| `dex_blast_min_devices` | integer | **persisted only - see note** | Blast-radius alert threshold (clamped on apply) |
| `dex_blast_window_seconds` | integer | **persisted only - see note** | Blast-radius window |
| `dex_blast_cooldown_seconds` | integer | **persisted only - see note** | Blast-radius cooldown |
| `dex_cohort_export_key` | string | **persisted only - see note** | Cohort export tag key; `""` disables export |

##### When a change takes effect

Persisting a value and applying it are separate steps, and this endpoint only does the first for
most keys:

- **immediately** - only two keys. `heartbeat_timeout` is assigned into the live server config and
  re-read on every stale-session sweep; `log_level` is applied by `RuntimeConfigStore::set()` itself
  via `spdlog::set_level`.
- **stored only, applied at next restart** - `response_retention_days`, `audit_retention_days`,
  `guardian_event_retention_days`. The handler updates the in-memory config, so `GET /api/config`
  and the Settings page immediately report the NEW value - but each store captured its retention
  window when it was constructed and exposes no setter, so the store still enforcing retention keeps
  the old value until the server restarts. **The API reports the stored value, not the value being
  enforced.** Restart after changing a retention window.
- **records intent only** - `plugin_signing_required` is read in exactly two places, both of which
  render the Settings status badge. **No server or agent code consumes it to require signatures**,
  and it is not carried in any proto field, so it never reaches an agent. Agent-side enforcement is
  the agent's own `--plugin-require-signature` flag paired with an operator-distributed
  `--plugin-trust-bundle`. Setting this key records the operator's intent and changes what Settings
  displays; **it does not harden anything by itself**.
- **persisted only, applied at next boot or next DEX-alerts Settings save** - `dex_alert_routing`,
  `dex_blast_min_devices`, `dex_blast_window_seconds`, `dex_blast_cooldown_seconds`,
  `dex_cohort_export_key`. The live consumers (`DexAlertRouter`, the blast-radius detector, the
  cohort-gauge export key) are **cached in memory** and refreshed only by `apply_dex_alert_config()`,
  which runs at server startup and from the Settings -> DEX alerts save handler - never from this
  endpoint. A `PUT` through this API is inert on the running server until one of those two happens.
  To change DEX alerting and have it apply at once, use Settings -> DEX alerts.
- **never** - `auto_approve_enabled` is accepted by the allow-list and written to the store, but no
  code reads it back from there. `GET /api/config` reports `auto_approve_enabled` **derived from
  whether any auto-approve rule exists**, not from the stored value, so a `PUT` of this key can
  appear to have no effect - because it has none. Manage auto-approve through its own rules API.
- **OIDC keys (see note)** - persisted only, and **a restart does not apply them either.** The
  `OidcProvider` is constructed early in server startup (`server.cpp:1894`) from CLI/environment
  configuration, whereas the stored runtime-config overrides are not read until much later in the
  same startup (`server.cpp:3466`); nothing rebuilds the provider afterwards. So a value written
  through this API never reaches the live provider, on this boot or any later one.
  **Only Settings -> OIDC (`POST /api/settings/oidc`) applies OIDC settings**, because that handler
  constructs a new provider and swaps it in - but that swap is **process-local**. The startup path
  DOES read these keys out of the store, just too late to matter - the provider is already built and
  nothing rebuilds it - so a restart runs on whatever the command line or environment supplies. To
  change OIDC durably, update that value as well as saving through Settings. This matters most for a credential rotation: a `PUT` of
  `oidc_client_secret` returns `"applied": true` meaning *persisted and accepted*, never *in use*.

**Request body:**

```json
{
  "value": 180
}
```

**Response** (flat, not a `data`/`meta` envelope). `applied` means *persisted and accepted* - see
[When a change takes effect](#when-a-change-takes-effect) for whether the running server is using it
yet:

```json
{ "key": "heartbeat_timeout", "value": 180, "applied": true }
```

For a secret-valued key the response **omits `value`**, for the same reason `GET /api/config` does:

```json
{ "key": "oidc_client_secret", "applied": true }
```

**Removing a stored secret.** Send an empty value — `{"value": ""}` — and `GET /api/config` then
reports `"is_set": false` for that key. Two things to know before relying on this. It clears only the
stored **override**: an empty stored value is skipped at startup, so if `--oidc-client-secret` or
`YUZU_OIDC_CLIENT_SECRET` is still set, that value takes effect again on the next restart. And like
every write to this route, it does **not** reach the running OIDC provider — the process keeps using
whatever secret it started with until it restarts. Clearing the Settings → OIDC form field does *not*
remove the secret either: a blank field there means "leave the stored value unchanged".

**After clearing, do not save the Settings → OIDC form with the secret field blank.** That form falls
back to the secret the process is currently holding, rebuilds the live provider with it, and — because
the field was blank — does not write **the secret** back to the store (the form's other OIDC fields are
persisted as normal). The result is the previously loaded secret live in the running process while
`GET /api/config` still reports `"is_set": false`. If you have cleared the secret and need to change
another OIDC field, restart first so the process is not holding the old value.

> **Two different error sources, two different shapes.** The shared authorization gate in front of
> this route **does** emit the A4 envelope: a `401`, a `403` permission denial, or a `503`
> authorization-store failure carries `correlation_id` (echoed on `X-Correlation-Id`) like any other
> gated route. The bodies **the handler itself** emits do not — `/api/config` is a legacy
> non-`/api/v1` route, and its own errors are either a bare `error` string or a nested
> `{"error":{"code","message"},"meta":{"api_version"}}` object with no `correlation_id` and no
> `retry_after_ms`. Besides those shown below, the handler emits nested bodies for `400` "missing
> 'value' in request body", `400` "invalid JSON body", `400` "request body nests too deeply"
> (over 32 levels, `kMcpMaxJsonDepth`), and a `503` "runtime config store unavailable"
> when the runtime-config store is unavailable (`GET` and `PUT` now share the identical message; an
> earlier `GET`-side wording of "runtime configuration store unavailable" was a drift, not a
> deliberate distinction, and has been unified). Note `503` is emitted by **both** sources, so status
> alone does not tell you which shape you have: test for `error.correlation_id` rather than assuming
> it, on every status.

**Error (503) - runtime config store unavailable.** A genuine DB/crypto write failure, distinguished
from caller-input validation at the seam so it never returns a `400`-shaped body instead:

```json
{ "error": { "code": 503, "message": "runtime config store unavailable" }, "meta": { "api_version": "v1" } }
```

**Error (400) - key not configurable.** This one is a bare `error` string with no envelope:

```json
{ "error": "key 'foo' is not a configurable runtime setting" }
```

**Error (400) - bad value for an integer key**, which uses a nested error body:

```json
{
  "error": { "code": 400, "message": "value must be a non-negative integer" },
  "meta": { "api_version": "v1" }
}
```

A value of `0` for `heartbeat_timeout`, `response_retention_days` or `audit_retention_days` passes
the route's `>= 0` pre-check and is then rejected by the store's own `> 0` check, so it returns the
**bare** shape with a different message: `{ "error": "value must be a positive integer" }`.

**Error (400) - the redaction placeholder submitted as a secret.** `GET /api/config` omits a
secret's value and the startup log prints `<redacted>` in its place. Any value **containing** that
literal is refused for a secret-valued key, ignoring surrounding whitespace and control bytes, so
copying it back cannot destroy the stored credential. The rule is deliberately broad: a paste can
carry an invisible code point (a BOM, a zero-width space) that no trim list catches exhaustively,
and the two failure directions are not symmetric - refusing an implausible secret costs an error
message, while accepting a padded placeholder silently destroys a live credential. If your real
client secret contains `<redacted>`, rotate it at the IdP to a value that does not. Bare shape:

```json
{ "error": "value is the redaction placeholder, not a credential; send the real secret, or omit the key to leave it unchanged" }
```

**Audit:** a successful write emits `config.update` / `RuntimeConfig` with `target_id` = the key.
See [Audit log](audit-log.md) for the `detail` contract, which differs for secret-valued keys.

---

### Settings

**#4028 (api-parity programme #2146).** REST v1 read-twins for the eight `/fragments/settings/*`
dashboard sub-areas (TLS, HTTPS, gateway, server-config, MCP, data-retention, analytics,
plugin-signing) — previously gated by a whole-endpoint admin role check (`require_admin`) with no
RBAC securable and no REST twin at all. All eight routes are **read-only** and **Administrator-only
today** (see the per-route Permission line); broadening to another role is a separate, explicit
decision. Every builder is shared verbatim with the corresponding HTML fragment renderer
(`docs/api-twin-recipe.md` §1) — the REST and dashboard views cannot drift from each other.

**MCP.** None of these eight routes has an MCP twin, deliberately, and no MCP token can reach any of
them via REST either — at any tier, including readonly. Issue #520 established the rule via
`require_admin`'s own comment: "MCP tokens are for fleet management (queries, instruction execution)
and must not be used to administer the server itself (settings, users, TLS, OIDC)". Seven of these
eight routes are new and were never gated by `require_admin`; the eighth
(`/api/v2/agent/plugin-policy` — its predecessor `/api/v1/agent/plugin-policy` is deprecated,
frozen on `require_admin`; see below) is hardened off it onto `require_permission`. Gating via
`require_permission` alone is not sufficient to preserve #520's blanket MCP exclusion — an
admin-owned MCP token (any tier) satisfies `require_permission`'s topology-floor legacy-role check
the same way an interactive admin session does. #4028 closes that gap at the actual chokepoint:
`TlsConfig`, `PluginSigning`, `ServerConfig`, and `AnalyticsConfig` are excluded from every MCP tier
in `mcp_policy.hpp`'s `tier_allows()`, so an MCP token is denied before it ever reaches the
role-based fallback, on every transport that consults `tier_allows()` (REST today; MCP JSON-RPC too,
if a future tool ever names one of these securables). #4028 ships these eight sub-areas REST-only
rather than silently widening #520 — a future MCP carve-out for read-only settings visibility would
need its own security-guardian-reviewed amendment, not a side effect of this twin work. See
[MCP Server](../mcp-server.md) for the full #520 policy.

#### `GET /api/v1/settings/tls`

TLS/mTLS listener settings: enabled state, server cert/key/CA file paths, `insecure_skip_client_verify`,
and the management-listener TLS override paths.

**Permission:** `TlsConfig:Read`. **Audit:** `settings.tls.read` (fail-closed — TLS/mTLS posture and
cert paths are reconnaissance value for an attacker learning the mTLS enforcement posture).

```json
{
  "data": {
    "enabled": true,
    "server_cert_path": "/etc/yuzu/certs/server.pem",
    "server_key_path": "/etc/yuzu/certs/server.key",
    "ca_cert_path": "/etc/yuzu/certs/ca.pem",
    "insecure_skip_client_verify": false,
    "mgmt_server_cert_path": "",
    "mgmt_server_key_path": "",
    "mgmt_ca_cert_path": ""
  },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/settings/https`

HTTPS listener settings: enabled state, port, cert/key file paths, HTTP-redirect state.

**Permission:** `TlsConfig:Read` (same securable as `/settings/tls`). **Audit:** `settings.https.read`
(fail-closed).

```json
{
  "data": {
    "enabled": true,
    "port": 8443,
    "cert_path": "/etc/yuzu/certs/https.pem",
    "key_path": "/etc/yuzu/certs/https.key",
    "redirect": true
  },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v2/agent/plugin-policy`

Plugin code-signing trust bundle — **this is plugin-signing's REST twin**, not a separate
`/api/v1/settings/plugin-signing` route (deliberate: the acceptance criteria for #4028 hardens this
pre-existing, previously off-ledger route onto the A4 envelope + OpenAPI + the shared builder
rather than adding a parallel one). Superset of the `/fragments/settings/plugin-signing` fragment's
data — this route alone also returns the raw `trust_bundle_pem` bytes, for out-of-band agent-config
distribution (`--plugin-trust-bundle`).

**v1 is deprecated.** `GET /api/v1/agent/plugin-policy` predates #4028 and is FROZEN at its original
flat-body shape (`require_admin` gate, no `data` envelope, no audit, no A4 error shape) rather than
reshaped in place — #4144 caught that the original #4028 round did exactly that and violated
`docs/api-versioning-policy.md`. v1 keeps working through the announced deprecation window (see
`server-admin.md`'s vNEXT note); new integrations should target v2 below.

**Permission:** `PluginSigning:Read` (dedicated securable, deliberately distinct from the unrelated
`PluginConfig` securable, which gates per-plugin runtime kill-switch config — a different domain). No
MCP token, at any tier, satisfies this permission (see "MCP" above). **Audit:**
`settings.plugin_signing.read` (fail-closed) — CC6.1 least-privilege: a non-admin token holder
learning when the trust anchor rotates (sha256 changes) is useful reconnaissance for a supply-chain
attacker.

```json
{
  "data": {
    "enabled": true,
    "required": false,
    "cert_count": 2,
    "sha256": "a1b2c3...",
    "subjects": ["CN=Yuzu Plugin Signer, O=Example Corp"],
    "bundle_unreadable": false,
    "trust_bundle_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  },
  "meta": { "api_version": "v1" }
}
```

No bundle uploaded (still 200, not 404 — a normal operational state): `enabled: false`,
`cert_count: 0`, `sha256: ""`, `subjects: []`, `trust_bundle_pem: ""`. A bundle present on disk but
unreadable returns 500 (A4 error envelope) instead.

**Errors:** 503 (A4 envelope, `retry_after_ms` set) in two cases distinct from the audit fail-closed
503 above — the `required` flag's backing `runtime_config_store` read failed (the response would
otherwise be unable to distinguish a genuine outage from a healthy "not required"), or the trust
bundle was concurrently uploaded/cleared between this request's existence check and its PEM
re-read. Both are retryable, and neither affects real plugin-signature enforcement — see
[When a change takes effect](#when-a-change-takes-effect) above: `plugin_signing_required` "records
intent only," is read in exactly two places (this route and its dashboard fragment twin), and no
server or agent code consumes it to require signatures. Agent-side enforcement, where configured,
is that agent's own `--plugin-require-signature`/`--plugin-trust-bundle` flags, independent of this
route and its backing store.

#### `GET /api/v1/settings/gateway`

Erlang gateway upstream status: enabled state, listen address, gateway mode, live session count.

**Permission:** `ServerConfig:Read`. **Audit:** none — operational status, nothing secret.

```json
{
  "data": { "enabled": true, "listen_address": "0.0.0.0:50053", "gateway_mode": false, "active_sessions": 3 },
  "meta": { "api_version": "v1" }
}
```

`listen_address`/`gateway_mode`/`active_sessions` are defaulted (`""`/`false`/`0`) when
`enabled` is `false`.

#### `GET /api/v1/settings/server-config`

Core server configuration: gRPC/web addresses and ports, session timeout, max agents, rate limits,
OTA/gRPC tuning knobs. Nothing secret.

**Permission:** `ServerConfig:Read`. **Audit:** none.

```json
{
  "data": {
    "agent_grpc_address": "0.0.0.0:50051",
    "management_grpc_address": "0.0.0.0:50052",
    "web_address": "127.0.0.1",
    "web_port": 8080,
    "session_timeout_seconds": 3600,
    "max_agents": 10000,
    "auth_config_path": "/etc/yuzu/yuzu-server.cfg",
    "rate_limit_per_ip": 100,
    "login_rate_limit_per_ip": 10,
    "ota_max_concurrent_per_peer": 2,
    "ota_rate_refill_per_min": 1.0,
    "ota_rate_capacity": 20.0,
    "ota_max_concurrent_total": 64,
    "ota_max_peers_tracked": 50000,
    "ota_transfer_deadline_secs": 900,
    "ota_chunk_write_deadline_secs": 30,
    "grpc_max_concurrent_streams": 128,
    "grpc_max_resource_memory_mb": 512
  },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/settings/mcp`

MCP server status and the client-connection info shown on the dashboard (enabled/read-only state,
the `/mcp/v1/` endpoint URL).

**Permission:** `ServerConfig:Read`. **Audit:** none — low sensitivity; an MCP client with a valid
token already knows this endpoint exists. This route describes the MCP surface but is itself
REST-only — see the #520 note above.

```json
{
  "data": { "enabled": true, "read_only": false, "endpoint_url": "https://localhost:8443/mcp/v1/" },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/settings/data-retention`

Response/audit data retention windows, in days.

**Permission:** `ServerConfig:Read`. **Audit:** none — lowest sensitivity of the eight (two
integers).

```json
{
  "data": { "response_retention_days": 90, "audit_retention_days": 365 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/settings/analytics`

Analytics drain configuration and ClickHouse integration settings.

**Permission:** `AnalyticsConfig:Read`. **Audit:** `settings.analytics.read` (fail-closed) — mixed,
leans high (embedded-credential risk).

> **`clickhouse_url` is sanitized of embedded userinfo credentials** (a URL of the form
> `clickhouse://user:pass@host:9000/db` has the `user:pass@` segment stripped) before being
> returned — this closes a gap where the sibling HTML fragment previously rendered the URL
> verbatim, masking only the separate `clickhouse_password` field. The raw password is never
> returned at all; only `clickhouse_password_set` (a bool) is.

```json
{
  "data": {
    "enabled": true,
    "drain_interval_seconds": 10,
    "batch_size": 100,
    "clickhouse_configured": true,
    "clickhouse_url": "clickhouse://host:9000/yuzu",
    "clickhouse_database": "yuzu",
    "clickhouse_table": "yuzu_events",
    "clickhouse_username": "default",
    "clickhouse_password_set": true,
    "jsonl_export_path": ""
  },
  "meta": { "api_version": "v1" }
}
```

---

### Custom Properties

Custom properties are operator-defined key-value pairs on agents, separate from tags. Properties can have schemas that enforce a value type (`string`/`int`/`bool`/`datetime`) and an optional regex-pattern validation rule. Properties are available for use in scope expressions via the `props.<key>` prefix.

#### `GET /api/agents/:id/properties`

List all custom properties for a specific agent.

**Permission:** `Infrastructure:Read`, scoped to the agent (a global grant **or** a role assigned on
the agent's management group / an ancestor, **or** a service-scoped API token whose
`ITServiceOwner` role is admitted on agents matching its own service tag; RBAC-off legacy behavior
is unchanged). A degraded
confinement check (management-group store unavailable) denies with `403`, distinct from the `503`
below for a degraded properties-store read.

**Error (503) -- store degraded:** `custom_properties_store` is a migrated Postgres store
(authoritative posture); a transient database read failure returns `503` rather than an
empty/partial property list, so automation never mistakes a degraded read for "this agent has no
properties."

```json
{"error":{"code":503,"message":"custom properties store degraded"},"meta":{"api_version":"v1"}}
```

**Response:** a flat, unwrapped body — this legacy route family predates the `data`/`meta` v1
envelope and has not been migrated onto it.

```json
{
  "agent_id": "agent-042",
  "properties": [
    {
      "key": "department",
      "value": "Engineering",
      "type": "string",
      "updated_at": "2026-08-01T12:00:00Z"
    },
    {
      "key": "cost_center",
      "value": "CC-4200",
      "type": "string",
      "updated_at": "2026-07-15T09:30:00Z"
    }
  ]
}
```

---

#### `PUT /api/agents/:id/properties/:key`

Set or update a custom property value on an agent. If a property schema exists for the key, the value is validated against it.

**Permission:** `Infrastructure:Write`, scoped to the agent (a global grant **or** a role assigned on
the agent's management group / an ancestor, **or** a service-scoped API token whose
`ITServiceOwner` role is admitted on agents matching its own service tag; RBAC-off legacy behavior
is unchanged). A degraded
confinement check (management-group store unavailable) denies with `403`, distinct from the `503`
below for a degraded properties-store write.

**Request body:** `type` is optional (default `"string"`) and IS persisted, but a schema on this
key (below) takes precedence — if one exists, its own `type` overrides whatever the request sent
before the write, so the stored (and later `GET`-returned) `type` reflects the caller's value only
when no schema is registered for the key.

```json
{
  "value": "Engineering",
  "type": "string"
}
```

**Response:** flat, unwrapped (same family caveat as `GET` above).

```json
{
  "agent_id": "agent-042",
  "key": "department",
  "value": "Engineering",
  "type": "string"
}
```

**Error (400) -- schema validation failure:** the message depends on which schema constraint
failed -- a type mismatch (`int`/`bool`) or a `validation_regex` mismatch (`GET
/api/property-schemas` below):

```json
{"error": "value does not match validation pattern for 'department'"}
```

**Error (503) -- store outage:**

```json
{"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}}
```

**Note on database degrade:** a transient database failure during this write — store not open, a
pool/query failure on the property INSERT, or a failure on the schema-validation lookup itself —
now surfaces as this distinguishable `503`, matching `GET /api/agents/:id/properties` above.
Caller-input validation failures (invalid key/value shape, or a value rejected against an existing
schema) stay `400`. This closes a gap where every failure, including a genuine store outage,
collapsed to the same `400` a caller couldn't distinguish from their own bad input (gov Gate 8
finding, fjarvis re-review of PR #3065). A transient failure on the schema-validation lookup used
to be silently treated by the SQLite original as "no schema, accept any value" — that fail-open
was already closed by the original Postgres migration (it correctly rejects the write instead of
accepting it unvalidated); this change only affects which status code that rejection now uses.

---

#### `DELETE /api/agents/:id/properties/:key`

Delete a custom property from an agent.

**Permission:** `Infrastructure:Write`, scoped to the agent (a global grant **or** a role assigned on
the agent's management group / an ancestor, **or** a service-scoped API token whose
`ITServiceOwner` role is admitted on agents matching its own service tag; RBAC-off legacy behavior
is unchanged). A degraded
confinement check (management-group store unavailable) denies with `403` -- distinct from the `404`
degrade conflation noted below, which is a property-store issue on the delete path itself, not the
authorization check.

**Response:** flat, unwrapped (same family caveat as `GET`/`PUT` above).

```json
{
  "deleted": true,
  "key": "department"
}
```

**Note on database degrade:** a transient database failure during this delete currently surfaces
as the same `404` ("property not found") a genuine miss would return — not yet type-widened,
predates the Postgres migration. Unlike `PUT`/`POST` above (fixed to a distinguishable `503`),
this route's underlying `delete_property` was deliberately left unwidened — it's an
admin/operator-driven delete, not a scope/dispatch-feeding read, matching `custom_properties_store.hpp`'s
documented posture — so this stays a tracked gap rather than a fixed one.

---

#### `GET /api/property-schemas`

List all property schemas. Schemas define the allowed keys, types, and validation constraints for custom properties.

**Permission:** `Infrastructure:Read`

**Note on database degrade:** a transient database failure during this list currently surfaces as
a `200` with an empty `schemas` array — indistinguishable from "no schemas configured." Not yet
type-widened, predates the Postgres migration. Unlike `PUT`/`POST` above (fixed to a
distinguishable `503`), this route's underlying `list_schemas` was deliberately left unwidened —
it's an admin-surface read, not scope/dispatch-feeding, matching `custom_properties_store.hpp`'s
documented posture — so this stays a tracked gap rather than a fixed one.

**Response:** flat, unwrapped (same family caveat as the agent-properties routes above).

```json
{
  "schemas": [
    {
      "key": "department",
      "display_name": "Department",
      "type": "string",
      "description": "The employee's department",
      "validation_regex": ""
    },
    {
      "key": "cost_center",
      "display_name": "Cost Center",
      "type": "string",
      "description": "",
      "validation_regex": "^CC-[0-9]{4}$"
    }
  ]
}
```

`type` is one of `string`, `int`, `bool`, `datetime` -- `int`/`bool` values are type-checked on
write; `string`/`datetime` accept any text. A non-empty `validation_regex` (RE2 syntax, max 256
characters) is additionally applied via `RE2::FullMatch` regardless of `type`. An empty
`validation_regex` accepts any value of the declared type.

---

#### `POST /api/property-schemas`

Create or update a property schema. If a schema with the given key already exists, it is replaced.

**Permission:** `Infrastructure:Write`

**Request body:**

```json
{
  "key": "cost_center",
  "display_name": "Cost Center",
  "type": "string",
  "description": "The agent's billing cost center",
  "validation_regex": "^CC-[0-9]{4}$"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `key` | string | Yes | Property key (unique identifier) |
| `display_name` | string | No | Human-readable label |
| `type` | string | No | Value type: `string` (default), `int`, `bool`, `datetime` |
| `description` | string | No | Free-text description |
| `validation_regex` | string | No | RE2 pattern (max 256 chars) values must fully match; empty = no pattern constraint |

**Response (201):** flat, unwrapped (same family caveat as the routes above) -- echoes the
stored schema back, including any server-applied default (`type` defaults to `"string"` if
omitted).

```json
{
  "key": "cost_center",
  "display_name": "Cost Center",
  "type": "string",
  "description": "The agent's billing cost center",
  "validation_regex": "^CC-[0-9]{4}$"
}
```

**Error (503) -- store outage:**

```json
{"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}}
```

**Note on database degrade:** a transient database failure during this write (store not open, a
pool lease timeout, or a query failure) surfaces as this distinguishable `503`. Caller-input
validation failures (invalid key, unrecognized type, an invalid/oversized validation regex) stay
`400` (gov Gate 8 finding, fjarvis re-review of PR #3065 — the same fix as `PUT
/api/agents/:id/properties/:key` above).

---

### Webhooks

Webhooks deliver real-time HTTP POST notifications to external systems when events occur in Yuzu (e.g., agent registration, command completion, policy compliance changes).

#### `GET /api/webhooks`

List all configured webhooks.

**Response:**

```json
{
  "webhooks": [
    {
      "id": 1,
      "url": "https://example.com/hooks/yuzu",
      "event_types": ["agent.registered", "command.completed"],
      "has_secret": true,
      "enabled": true,
      "created_at": 1710849600
    }
  ]
}
```

`has_secret` reports whether a signing secret is configured — the secret itself is never returned by this or any other endpoint, encrypted or otherwise.

#### `POST /api/webhooks`

Create a new webhook subscription.

**Request body:**

```json
{
  "url": "https://example.com/hooks/yuzu",
  "event_types": ["agent.registered", "command.completed", "policy.violation"],
  "secret": "optional-hmac-secret"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | Endpoint to receive POST notifications (`http://` or `https://`; see the cleartext-HTTP warning below) |
| `event_types` | array | Yes | Events to subscribe to (see the table below) |
| `secret` | string | No | HMAC-SHA256 secret for payload signing |

**Event types** (the `event_types` filter matches these literal strings):

| Event type | Fired when | Notable payload fields |
|---|---|---|
| `agent.registered` | An agent enrolls or re-enrolls | `agent_id`, `hostname`, `os`, `arch`, `agent_version` |
| `command.completed` / `execution.completed` | An instruction finishes across its targets | command/execution identifiers |
| `policy.violation` | A policy evaluation finds a non-compliant device | policy + device identifiers |
| `dex.blast_radius` | N distinct devices report the same DEX signal `(obs_type, subject)` within the window — thresholds are operator-tunable under Settings → DEX alerts (defaults 5 devices / 15 min; see [DEX fleet incident alerts](dex.md#fleet-incident-alerts-blast-radius)) | `obs_type`, `subject`, `device_count`, `window_seconds` |
| `dex.signal` | A device reports a DEX signal type the operator routed to alerts (Settings → DEX alerts; once per device per hour — see [Routing signals to alerts](dex.md#routing-signals-to-alerts)) | `obs_type`, `subject`, `agent_id` |

`agent.registered` fires on *every* gRPC reconnect, not only first enrollment — a server restart, a network blip, or a gateway bounce that strands and reconnects a fleet produces one delivery per reconnecting agent, not one per genuinely new device. A target wired to a low-tolerance channel (e.g. a Slack alert intended for "new device joined the fleet") should filter or debounce on the receiving end if reconnect noise matters; the dashboard's own "Agent Enrolled" notification does not have this problem (it fires once, on first enrollment only).

If a `secret` is provided, each delivery includes an `X-Yuzu-Signature` header containing the HMAC-SHA256 hex digest of the request body.

**Security — secret storage, and a legacy file's disposal.** A configured signing secret
is envelope-encrypted at rest (AES-256-GCM, ADR-0010) — a stolen database backup alone cannot
recover it. There is no rotation endpoint today: to change a secret, delete the webhook and
recreate it. No production fleet ever ran a pre-Postgres build of this store (#3623), so a
legacy SQLite `webhooks.db` genuinely holding real data should not exist — but if one is
somehow found on disk at boot (hardened to 0600, main file and any `-wal`/`-shm`/`-journal` sidecars, and
warned about in the log), it still holds any signing secrets in **plaintext** and is never
automatically deleted or rotated. If you find one and don't need it, delete it yourself; if any
webhook it names might still be relying on that secret, rotate (delete-and-recreate) the
corresponding webhook's secret via this store first.

**Cleartext HTTP warning.** When `url` is `http://` (not `https://`), the delivered event
payload is transmitted in cleartext. Production deployments should use `https://` only. The
store accepts `http://` for development convenience — same posture as Offload Targets below.

**Errors.** `400` for an empty/missing `url`, invalid JSON, or a URL that isn't `http://`/`https://`.
`503` for a store/database degradation. Every error response is audited (`webhook.create`,
result `failure`, a distinct detail string per cause).

#### `DELETE /api/webhooks/{id}`

Delete a webhook by numeric ID. `200` on success, `404` if no webhook has that id, `503` on a
store/database error. Every outcome (including `404`) is audited as `webhook.delete`; a
successful delete's audit detail carries the webhook's URL (captured just before deletion), so
the record of where a webhook pointed survives its removal.

#### `GET /api/webhooks/{id}/deliveries`

List recent delivery attempts for a webhook, newest first. Includes HTTP status code, response
time, and any error message for failed deliveries. `?limit=` defaults to 50 (any non-positive
value also falls back to 50) and is capped at 10000; no `offset`/pagination parameter exists. A
degraded read renders an empty list rather than a `503` — delivery history is audit convenience,
not a decision surface.

**Usage guide:**

1. Create a webhook targeting your SIEM, Slack, or automation endpoint.
2. Subscribe to the event types relevant to your workflow.
3. Optionally set an HMAC secret and verify the `X-Yuzu-Signature` header on receipt.
4. Monitor delivery history via `GET /api/webhooks/{id}/deliveries` to detect failures.

---

### Offload Targets

Response-offload control plane (issue #255, Phase 8.3). Targets are named external HTTP endpoints that receive a copy of the same events webhooks do (see the event-types table in the Webhooks section above) as they fire — heavier-duty than webhooks: typed auth (none / bearer / basic / hmac) and server-side batching for SIEM / data-warehouse ingestion that prefers fewer, larger requests.

A target is identified by a unique `name` so a definition can reference it via `spec.offload.targets` in YAML (see [yaml-dsl-spec.md](../yaml-dsl-spec.md#specoffload)).

`agent.registered` fires on *every* gRPC reconnect, not only first enrollment — same caveat as the Webhooks section above, and the same event-type table, since both sinks fire off the identical set of events. A target wired to a low-tolerance channel should filter or debounce on the receiving end if reconnect noise matters.

All five endpoints require the `Infrastructure` securable type — `Read` for `GET`, `Write` for `POST`/`DELETE`. The `auth_credential` is **never** returned in any response (redacted from `list()` and from `get()`, not even as the encrypted-at-rest blob) — a `has_credential` boolean instead reports whether one is configured. Audit events: `offload_target.create` (success or denied) and `offload_target.delete`.

#### `GET /api/v1/offload-targets`

List all configured offload targets. 503 on a degraded read (distinguishable from a genuine empty list).

**Response:**

```json
{
  "offload_targets": [
    {
      "id": 1,
      "name": "siem-primary",
      "url": "https://siem.example.com/ingest",
      "auth_type": "bearer",
      "has_credential": true,
      "event_types": "execution.completed",
      "batch_size": 50,
      "enabled": true,
      "created_at": 1714501234
    }
  ]
}
```

#### `GET /api/v1/offload-targets/{id}`

Fetch a single target by numeric id. `auth_credential` is redacted (`has_credential` reports whether one is configured). 404 when no such id exists, 503 on a degraded read.

#### `POST /api/v1/offload-targets`

Create a new offload target. Returns 201 + `{id, status}` on success, 400 when validation fails (invalid URL scheme, empty `name`, `batch_size < 1`, duplicate `name`, a control byte in a free-text field, a present-but-wrong-typed field such as `batch_size` sent as a string, or an unrecognized `auth_type`).

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Unique stable identifier referenced from `spec.offload.targets`. |
| `url` | string | Yes | `http://` or `https://` POST endpoint. |
| `auth_type` | string | No (`none`) | One of `none`, `bearer`, `basic`, `hmac`. |
| `auth_credential` | string | No | Bearer token (Bearer), `user:pass` (Basic), shared secret (Hmac). Never returned by any endpoint. |
| `event_types` | string | No (`*`) | Comma-separated list of event types or `*` for all. Same semantics as webhooks. |
| `batch_size` | int | No (1) | Accumulate up to N events into a single POST body. `1` = no batching. |
| `enabled` | bool | No (true) | When false, no events are dispatched until re-enabled. |

**Auth headers (set per `auth_type`):**

- `none` → no Authorization header.
- `bearer` → `Authorization: Bearer <auth_credential>`.
- `basic` → `Authorization: Basic <base64(user:pass)>`.
- `hmac` → `X-Yuzu-Signature: sha256=<hmac-sha256(auth_credential, body)>`. Mirrors the webhook shape so receivers can share verification code.

Every delivery also carries `X-Yuzu-Event` and `X-Yuzu-Event-Count` headers; batched bodies are JSON of shape `{"events":[…]}`.

#### `DELETE /api/v1/offload-targets/{id}`

Delete a target. Cascades on `offload_deliveries`. Pending events buffered for batching are dropped — operator who deletes the target asked for it.

#### `GET /api/v1/offload-targets/{id}/deliveries`

Recent delivery attempts for a target (default 50, override via `?limit=N`). Each row records `event_type`, `event_count`, `payload`, `status_code`, `delivered_at` (epoch seconds), and `error` (set on connection failure or exception).

**Usage guide:**

1. Register a target — e.g. a generic webhook collector, Datadog Logs HTTP endpoint, Elastic Common Schema ingest URL, or any in-house aggregator that accepts JSON over HTTP(S).
2. Set `event_types` to the events you actually need; `execution.completed` is the typical analytics feed, `agent.registered` for inventory hydration.
3. Tune `batch_size` to your downstream ingestion preference. SIEMs commonly prefer 50–500 per POST; real-time alerting wants `batch_size=1`.
4. Monitor delivery via `GET /api/v1/offload-targets/{id}/deliveries`. Repeated `connection_failed` errors mean the receiver is down or the URL/auth is wrong.

**Validating a new target.** There is no synthetic-test endpoint in this revision. To validate, set `batch_size=1`, run any instruction that produces an `execution.completed` event, then poll `GET /api/v1/offload-targets/{id}/deliveries` for the resulting row.

**Authentication interop — known limitations.**

- **Splunk HEC** uses the non-standard header `Authorization: Splunk <token>`. Yuzu's `bearer` mode emits `Authorization: Bearer <token>`. Splunk HEC will reject these with HTTP 401. Use `auth_type=none` + a Splunk HEC token enabled for "no authentication" (network-layer controls only) or front Splunk with a small reverse proxy that rewrites the header.
- **AWS S3 / EventBridge / Kinesis** require AWS Signature v4 (Sigv4). Yuzu does not generate Sigv4 signatures in this revision; direct PUTs to S3 buckets and EventBridge endpoints **will not work**. Front them with a Sigv4-signing reverse proxy (e.g. `aws-sigv4-proxy`).
- **Azure Monitor / Sentinel** use AAD token flow. Not directly supported. Front with a token-refresh shim.

**Cleartext HTTP warning.** When `url` is `http://` (not `https://`), the entire JSON payload — including potentially sensitive instruction response data (file paths, registry values, software inventory, security findings) — is transmitted in cleartext. Production deployments containing customer endpoint data should use `https://` only. The store accepts `http://` for development convenience and to maintain parity with the webhook precedent.

**Operator trust model.** Any principal with `Infrastructure:Write` can register an offload target pointing at any URL the server can resolve, including RFC1918 / loopback / link-local destinations. There is no URL allowlist or network-egress mitigation in this revision; the trust model is "Infrastructure:Write operators are trusted to choose where data goes." For multi-tenant managed deployments this is a known limitation tracked as a roadmap follow-up.

---

### Directory Sync

AD/Entra directory integration (Phase 7). Backed by `DirectorySync` (`directory_sync.{hpp,cpp}`).

#### `POST /api/directory/sync`

Trigger a directory sync. Requires `Directory:Write`.

**Request (`provider: "entra"`):**

```json
{
  "provider": "entra",
  "tenant_id": "...",
  "client_id": "...",
  "client_secret": "..."
}
```

`tenant_id`/`client_id`/`client_secret` are all required for `entra`; a `provider: "ldap"` request instead takes `server`/`port`/`base_dn`/`bind_dn`/`bind_password`/`use_ssl`, but `sync_ldap` is not yet implemented and always returns `501`. Any other `provider` value is `400`.

**Response (200):** `{"status": "completed", "provider": "entra", "user_count": <n>, "group_count": <n>}`

**Response (409, ADR-1007):** `{"error": "sync already in progress"}` — `sync_entra` holds a single in-process re-entrancy guard for the duration of one sync call; a second `POST` that arrives while a sync is already running is rejected immediately rather than racing it. See "Diagnosing a stuck directory sync" in `docs/user-manual/server-admin.md` for how long a legitimate sync can hold the guard and what a stuck one looks like. Not queued or retried automatically — the caller decides when to retry.

**Response (400):** malformed body, or a missing required Entra field.

**Response (503):** `directory_sync` is unavailable (store not open).

**Response (500):** a genuine sync failure (e.g. Graph API error) — the error message is passed through from `sync_entra`'s result.

#### `GET /api/directory/users`

List directory-synced users from the last successful sync. Requires `Directory:Read`. Optional `?group_id=` query param filters to members of one synced group.

**Response (200):** `{"users": [{"id","display_name","email","upn","enabled","groups":[...],"synced_at"}], "count": <n>}`

**Response (503):** `directory_sync` unavailable.

#### `GET /api/directory/status`

Sync status plus the last-synced group list (there is no separate `GET /api/directory/groups` route — groups are embedded here). Requires `Directory:Read`.

**Response (200):** `{"provider","status","last_sync_at","user_count","group_count","last_error","groups":[{"id","display_name","description","mapped_role","synced_at"}]}`

**Response (503):** `directory_sync` unavailable.

#### `PUT /api/directory/group-mappings`

Configure group-to-role mappings (which RBAC role a synced group's members receive). Requires `Directory:Write`.

**Request:** `{"mappings": [{"group_id": "...", "role_name": "..."}]}`. `role_name` is NOT required per entry — an entry with an empty/omitted `role_name` REMOVES that group's mapping rather than being rejected; a non-empty `role_name` configures (creates or overwrites) it. An entry with an empty `group_id` is silently skipped and not counted.

**Response (200):** `{"mappings": [{"group_id","role_name"}], "count": <n>}` — the FULL current mapping set after applying this request's changes (not the size of the batch just submitted).

**Response (400):** malformed body, or a missing `mappings` array.

**Response (503):** `directory_sync` unavailable.

#### `GET /api/v1/directory/users`

REST v1 twin of `GET /api/directory/users` above (#4031) — same underlying data, the versioned A4 envelope, and a real MCP twin (`list_directory_users`). Optional `?group_id=` query param filters to members of one synced group.

**Permission:** `Directory:Read`

Every call is audited (`directory.users.view`) — this closes a real pre-existing gap: the legacy route above returned this same email/UPN/group-membership PII with no audit call at all until this change. The route **fails closed (503)** if the audit row cannot be persisted, per the [`Sec-Audit-Failed` behavioural-PII posture](#sec-audit-failed-and-the-behavioural-pii-audit-posture) above.

**Response:**

```json
{
  "data": [
    {
      "id": "8f3c...",
      "display_name": "Alice Chen",
      "email": "alice.chen@example.com",
      "upn": "alice.chen@example.com",
      "enabled": true,
      "groups": ["g-engineering"],
      "synced_at": 1735689600
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

**Response (503):** directory sync not available, or the audit subsystem is unavailable (`Sec-Audit-Failed: true`).

#### `GET /api/v1/directory/status`

REST v1 twin of `GET /api/directory/status` above (#4031), with a real MCP twin (`get_directory_status`). No per-person PII (counts + synced-group metadata only) — unaudited, matching the legacy route's own posture.

**Permission:** `Directory:Read`

**Response:**

```json
{
  "data": {
    "provider": "entra",
    "status": "completed",
    "last_sync_at": 1735689600,
    "user_count": 42,
    "group_count": 5,
    "last_error": "",
    "groups": [
      { "id": "g-engineering", "display_name": "Engineering", "description": "", "mapped_role": "Operator", "synced_at": 1735689600 }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

**Response (503):** directory sync not available.

**Prerequisite fix (#4031):** `Directory` was used as an RBAC securable on every route in this section but was never seeded into `RbacStore`'s securable-type catalogue — under RBAC-enabled deployments, no role (not even Administrator) could actually be granted `Directory:Read`/`Write`. This is now seeded (Administrator via the CRUD grant loop, Viewer for read — the same population that reads `UserManagement`) and mirrored into `mcp_server.cpp`'s RBAC securable catalogue.

---

### Enrollment

Auto-approve rules (agent-enrollment bypass criteria) and the pending/denied agent-enrollment queue. Both were previously reachable only via `admin_fn_`-gated HTMX dashboard fragments (`GET /fragments/settings/auto-approve`, `GET /fragments/settings/pending`) with no REST v1 or MCP surface (#4031). Backed by `auth::AutoApproveEngine` and `auth::AuthManager::list_pending_agents()`.

**MCP:** REST-only — no MCP twin. `admin_fn_` (the gate these fragments used, and the new `Enrollment` securable's sole initial grant) explicitly excludes MCP tokens from administering server settings/enrollment policy (`auth_routes.cpp`, #520); this is the same reviewed exception the sibling settings-fragment issue #4028 records for its own `admin_fn_`-gated fragments. See [MCP (Model Context Protocol)](#mcp-model-context-protocol) for the general MCP-tier policy.

**RBAC-off note:** the new `Enrollment` securable is Administrator-only today, and — because the underlying gate moved from a role check (`admin_fn_`, always admin-only) to an RBAC permission check — the `(Enrollment, Read)` pair is in `authz_topology_floor.hpp`'s floor set so an RBAC-off deployment (the default) cannot silently widen this from admin-only to any authenticated user.

#### `GET /api/v1/enrollment/auto-approve-rules`

**Permission:** `Enrollment:Read` (Administrator only)

Audited (`enrollment.auto_approve.view`, non-blocking) — the rule set is auto-enrollment bypass criteria, reconnaissance-valuable to an attacker but not per-person data, so the posture is a plain audit log entry rather than the fail-closed behavioural-PII posture above.

**Response:**

```json
{
  "data": {
    "rules": [
      { "index": 0, "type": "hostname_glob", "value": "*.prod.example.com", "label": "Production hosts", "enabled": true }
    ],
    "require_all": false
  },
  "meta": { "api_version": "v1" }
}
```

`index` is the rule's position in the engine's list — the same handle the existing toggle/delete mutation routes (`POST/DELETE /api/settings/auto-approve/{index}`) key on (there is no separate rule id).

#### `GET /api/v1/enrollment/pending-agents`

**Permission:** `Enrollment:Read` (Administrator only in the default seed)

Do not conflate with the unrelated existing MCP tool `list_pending_approvals`, which serves `ApprovalManager`'s maker-checker action-approval queue — a different domain entirely. Audited (`enrollment.pending_agents.view`, non-blocking) — device-identity fingerprint data, a lighter version of the `device_ci` GDPR-personal-data-adjacent class the agent daily-sync framework already flags for serial/UUID/MAC.

**Confinement (ADR-0017):** unlike every other route in this section, each row here carries genuine per-agent identity (`agent_id` plus hostname/os/arch/agent_version), so this route gates on the admit-then-filter chokepoint (`AuthRoutes::require_fleet_read`), not a bare permission check. A holder of a management-group-scoped `Enrollment:Read` grant (rather than a global one) is admitted and gets the real visible-agent intersection — typically the empty list, since a pending (not-yet-approved) agent normally has no management-group membership yet, but this is a workflow expectation, not a data-model guarantee: an agent pre-assigned to a group before approval yields a non-empty, correctly-confined result instead. This closes a defect where such a grant was previously denied outright (403) instead of admitted with its correct, confined result — see `docs/auth-architecture.md`'s ADR-0017 migration list.

**Response:**

```json
{
  "data": [
    { "agent_id": "a1b2c3d4", "hostname": "host1.example.com", "os": "linux", "arch": "x86_64", "agent_version": "1.4.2", "requested_at": 1735689600, "status": "pending" }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

### Network Discovery

Network-discovered devices (Issue 7.18) — raw scan results agents report before an operator promotes a device to a managed agent. Backed by `discovery_store` on the shared PostgreSQL substrate (ADR-0044). Not to be confused with [Discovery (A2)](#discovery-a2) above, which is the unrelated agentic self-discovery family (`/api/v1/discover/*`).

#### `POST /api/discovery/scan`

Store discovery scan results. Requires `Infrastructure:Write`. Upserts one row per device by `ip_address` — `mac_address`/`last_seen`/`subnet` always refresh on a re-scan; `hostname` refreshes only when the new value is non-empty; a re-scan never touches an existing row's `managed`/`agent_id`/`discovered_at`/`discovered_by`.

**Request:**

```json
{
  "subnet": "10.0.0.0/24",
  "discovered_by": "agent-scanner-01",
  "devices": [
    {"ip_address": "10.0.0.5", "mac_address": "aa:bb:cc:dd:ee:ff", "hostname": "workstation-05"}
  ]
}
```

`devices[].ip_address` is required per entry; an entry with an empty `ip_address` is silently skipped and not counted.

**Response (200, all or partial success):**

```json
{"status": "ok", "devices_stored": 1, "devices_failed": 0}
```

A partial batch failure (e.g. under a degraded Postgres pool) still returns `200` but `"status": "partial"` with `devices_failed > 0`, and audits `discovery.scan` as `"partial"`:

```json
{"status": "partial", "devices_stored": 1, "devices_failed": 1}
```

**Response (503, every attempted device failed):**

```json
{"error":{"code":503,"message":"discovery scan storage degraded"},"meta":{"api_version":"v1"}}
```

Returned only when every device the request attempted to persist failed — an entry skipped for an empty `ip_address` is not counted as an attempt, so an all-skip batch still returns `200`/`"ok"`. Audits `discovery.scan` as `"failure"`.

Re-sending the exact same request body after a `503` or a `"partial"` response is safe: `upsert_device` is idempotent per `ip_address` (see the upsert semantics above), so a byte-identical retry does not double-count or corrupt already-stored devices. This is narrower than "safe to re-scan": a fresh scan is not a replay, and `mac_address`/`subnet` overwrite unconditionally on every upsert (unlike `hostname`, which only refreshes on a non-empty value) — a re-scan that this time fails to resolve a device's MAC (e.g. a transient ARP miss) will blank a previously known-good `mac_address`, not merely retry the failed write.

There is currently no scan-path-specific Prometheus degrade signal (unlike `GET /api/discovery/results`, which increments `yuzu_server_discovery_read_degrade_total`) — `devices_failed` in the response body, and the audit trail's `"partial"`/`"failure"` outcomes, are the per-request evidence today; the shared `yuzu_pg_*` connection-pool metrics are the closest backend-health proxy. A write-path degrade counter is tracked as a follow-up.

#### `GET /api/discovery/results`

List discovered devices. Requires `Infrastructure:Read`. Optional `?subnet=` query param filters to one subnet; omitted returns every discovered device, newest-`last_seen`-first.

**Response (200):**

```json
{
  "devices": [
    {
      "id": 1,
      "ip_address": "10.0.0.5",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "hostname": "workstation-05",
      "managed": false,
      "agent_id": "",
      "discovered_by": "agent-scanner-01",
      "discovered_at": 1714501234,
      "last_seen": 1714501234,
      "subnet": "10.0.0.0/24"
    }
  ],
  "total": 1
}
```

**Response (503, degraded read):** `{"error":{"code":503,"message":"discovery read degraded"},"meta":{"api_version":"v1"}}`. `discovery_store` is an authoritative store (ADR-0012 §1) — a query/pool failure surfaces as `503`, never as a silently-empty device list. See `yuzu_server_discovery_read_degrade_total{reason}` (`store_not_open`/`pool_acquire_timeout`/`query_error`).

`mark_managed` and `clear_results` exist on the underlying store but have **no REST route today** — dead surface, noted in ADR-0044's Follow-ups.

---

### Workflows

Workflows define multi-step instruction sequences that execute in order against a set of agents. Each step references an instruction definition and can include parameter overrides.

#### `GET /api/workflows`

List all workflows. Supports `?name=<search>` for a substring name filter and `?limit=<n>` to cap
the number of rows returned (default 100; `limit` must be a positive integer — `0` or negative is a
`400`, matching the existing non-numeric-`limit` `400`). A soft-deleted workflow (see `DELETE`
below) never appears in this list.

**Response (400):** `{"error":{"code":400,"message":"limit must be a positive integer"},"meta":{"api_version":"v1"}}` — non-numeric `limit` returns the sibling `"invalid numeric query parameter"` `400` instead.

**Response (503, degraded read):** `{"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}}` — `workflow_engine` is a migrated Postgres store (ADR-0064); a genuine pool/query failure surfaces as `503`, never a silently-empty list.

**Response:**

```json
{
  "workflows": [
    {
      "id": "abc123",
      "name": "Patch and Reboot",
      "description": "Install patches then reboot if required",
      "steps": [
        { "instruction": "windows-update-install", "parameters": {} },
        { "instruction": "system-reboot", "parameters": { "delay": "60" } }
      ],
      "created_at": 1710849600
    }
  ]
}
```

#### `POST /api/workflows`

Create a workflow from YAML. The request body is the raw YAML text with `Content-Type: text/x-yaml` or `application/json` with a `yaml_source` field.

#### `GET /api/workflows/{id}`

Get a single workflow by ID, including its full step definitions. `404` for an unknown or
soft-deleted id; `503` on a genuine store degrade (ADR-0064).

#### `DELETE /api/workflows/{id}`

Delete a workflow by ID. **Soft-delete (ADR-0064):** the workflow is retired, not physically
removed — its execution history stays intact and remains readable via `GET
/api/workflow-executions/{id}` indefinitely, and a deleted workflow's id can never be
re-used. Response body is unchanged: `{"deleted": true}` on the first delete of an existing
workflow, `{"deleted": false}` (still `200`) for an unknown id or a repeat delete of an
already-deleted one. A genuine store-unavailable condition now returns `503` instead of the
pre-migration `{"deleted": false}`.

#### `POST /api/workflows/{id}/execute`

Execute a workflow against targeted agents. Fails (workflow-not-found, `400`) if the workflow
does not exist or was soft-deleted; a genuine store degrade returns `503` (ADR-0064).

**Request body:**

```json
{
  "scope": "os = 'windows' AND tag:environment = 'production'",
  "parameters": {}
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `scope` | string | Yes | Scope expression selecting target agents |
| `parameters` | object | No | Override parameters for workflow steps |

#### `GET /api/workflow-executions/{id}`

Get the status of a running or completed workflow execution, including per-step and per-agent
results. `404` for an unknown execution id; `503` on a genuine store degrade (ADR-0064).
Execution history survives its workflow being deleted — this route stays readable for an
execution whose workflow was later soft-deleted.

**Permission:** `Workflow:Read`, fleet-read confined as of #4030 — same record-level gate and
`agent_ids`/`agents_reached` narrowing as the v1 twin below (a caller with no agent visible in
the execution's `agent_ids` gets the same `404` as a nonexistent id). Unlike the v1 twin and the
MCP tool, this legacy route writes **no audit row on any path** (pre-existing; out of scope for
the #4030 confinement fix).

**Usage guide:**

1. Define a workflow with ordered steps (each step maps to an instruction definition).
2. Execute the workflow against a scope expression to target specific agents.
3. Monitor execution progress via `GET /api/workflow-executions/{id}`.
4. Each step runs sequentially; if a step fails on an agent, subsequent steps for that agent are skipped.

---

### Workflows, Executions & Schedules — v1 read twins (#4030)

Versioned REST + MCP twins of the legacy `/api/workflows*` routes above, the `/fragments/executions`
and `/fragments/executions/{id}/detail` dashboard fragments, and the `/fragments/schedules`
fragment — closing the last gaps in that domain's `docs/api-parity-ledger.md` row set. Every route
here shares its JSON row builder with its MCP tool twin (`docs/api-twin-recipe.md` Rule 1), so the
two surfaces cannot drift on JSON **shape** independently. This does not by itself guarantee the two
surfaces admit the same **result set** for a given caller: `GET /api/v1/executions`'s confined
branch (below) is materially broader than the pre-existing MCP `list_executions` confinement
(own-dispatches-only) — a disclosed, pre-#4030 difference, not a silent one (`docs/user-manual/mcp.md`).

**Prerequisite fix bundled with this PR:** `Workflow` was used as an RBAC securable throughout
`workflow_routes.cpp` but was never seeded into `RbacStore`'s securable-types catalogue — meaning
no role, including Administrator, could ever be granted `Workflow:Read` while RBAC was enabled.
This PR seeds it and grants `Read` to Administrator (via the standard CRUD seed), PlatformEngineer,
Operator, ITServiceOwner, and Viewer — the same role footprint `Schedule:Read` already has. This
applies automatically on upgrade (no migration step, no opt-out) — an existing RBAC-enabled
deployment picks up these four grants on its next restart; review your role assignments first if
you've already narrowed them.

#### `GET /api/v1/workflows`

**Permission:** `Workflow:Read`. List workflows — the v1 twin of `GET /api/workflows` above (same
`name`/`limit` query parameters), MCP twin `list_workflows`.

**Response:**

```json
{
  "data": [
    { "id": "abc123", "name": "Patch and Reboot", "description": "...",
      "steps": [ { "index": 0, "instruction_id": "windows-update-install", "condition": "",
                   "retry_count": 0, "retry_delay_seconds": 5, "foreach": "", "label": "",
                   "on_failure": "abort" } ],
      "step_count": 1, "created_at": 1710849600, "updated_at": 1710849600 }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/workflows/{id}`

**Permission:** `Workflow:Read`. Fetch one workflow's full detail, including `yaml_source`. The v1
twin of `GET /api/workflows/{id}` above, MCP twin `get_workflow`. `404` for an unknown or
soft-deleted id.

#### `GET /api/v1/workflow-executions/{id}`

**Permission:** `Workflow:Read`, gated on the fleet-read chokepoint (the legacy route now shares
this same gate — see below). Record-level confinement: a caller with no agent visible in
`WorkflowExecution.agent_ids` gets `404`, byte-identical to a genuinely nonexistent id (never a
narrower-but-still-present record) — not merely a field-level `agent_ids` filter. An admitted
confined caller's `agent_ids` array is narrowed to their visible agents, and each step's `result`
has its `agents_reached` count stripped (it's the step's full target-agent count, not the caller's
visible subset — emitting it verbatim would disclose the true out-of-scope agent count by simple
arithmetic). The v1 twin of `GET /api/workflow-executions/{id}` above (which now applies the same
confinement + `agent_ids`/`agents_reached` narrowing, previously unfiltered), MCP twin
`get_workflow_execution`. Audited as `workflow_execution.detail.fetch`, set-and-proceed (not
REST's usual fail-closed-on-audit-failure posture — this file's `AuditFn` predates the checked-bool
`try_persist_audit`/`emit_behavioral_audit` helpers the Executions family below uses).

**Response:**

```json
{
  "data": {
    "id": "exec-wf-1", "workflow_id": "wf-1", "status": "completed",
    "agent_ids": ["agent-A"], "current_step": 1,
    "started_at": 1735689600, "completed_at": 1735689620,
    "steps": [
      { "step_index": 0, "instruction_id": "windows-update-install", "status": "success",
        "result": { "status": "dispatched", "command_id": "cmd-1" },
        "started_at": 1735689600, "completed_at": 1735689610, "attempt": 1 }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

For an unconfined (global-grant) caller, each step's `result` also carries `agents_reached` (the
step's dispatch-time target-agent count) — stripped above for a confined caller, as described.

#### `GET /api/v1/executions`

**Permission:** `Execution:Read`, gated on the fleet-read chokepoint (ADR-0017) — **not** the plain
permission check `GET /fragments/executions` uses; a confined caller sees only executions
involving at least one visible agent (or that they dispatched). The v1 twin of
`GET /fragments/executions`, MCP twin `list_executions` (widened by this PR to the same field set).
Accepts `definition_id`, `status`, and `limit` (capped at 500) query parameters.

**Response:**

```json
{
  "data": [
    { "id": "exec-1", "definition_id": "def-1", "definition_name": "Collect OS Info",
      "status": "completed", "dispatched_by": "alice", "dispatched_at": 1735689600,
      "agents_targeted": 2, "agents_responded": 2, "agents_success": 1, "agents_failure": 1,
      "completed_at": 1735689620, "rerun_of": "", "error_preview": "boom" }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/executions/{id}?include=agents`

**Permission:** `Execution:Read` (same gate as the bare route, `docs/executions-history-ladder.md`).
`?include=agents` is the #4030 per-agent status/duration expansion decided for this row: a query
parameter on the existing detail route rather than a new one, so the fragment's aggregate +
per-agent capability stays a single genuine REST+MCP twin (MCP twin: `get_execution_status` with
`"include":["agents"]`). Adds a confined `agents` array (`agent_id`, `status`, `dispatched_at`,
`first_response_at`, `completed_at`, `exit_code`, `error_detail`) and a `kpi` object (`total`,
`succeeded`, `failed`, `p50_ms`, `p95_ms` — `null` percentiles when no agent has a usable duration
yet). Unlike the bare request, this expansion **is** audited (`execution.detail.fetch`, REST
fail-closed 503 on an audit-persist failure) because it discloses raw agent identities. Response
bodies are a **separate** route (below), not part of this expansion.

#### `GET /api/v1/executions/{id}/responses`

**Permission:** `Response:Read`, gated on the fleet-read chokepoint — deliberately a **different**
securable than the detail route's `Execution:Read`, so folding this into the detail-route expansion
above would have over-disclosed response bodies to a caller who holds `Execution:Read` but not
`Response:Read`. The v1 twin of MCP `query_responses`' `execution_id`-scoped filter (no new MCP
tool — `query_responses` already covers this shape). Accepts `agent_id`, `status`, `since`, `until`,
`limit` (capped at 1000) query parameters. **Does not accept `offset`** — matching `query_responses`
exactly: the result set orders by a non-unique, actively-growing timestamp while an execution is
non-terminal, so offset-based paging would silently skip or duplicate rows; a caller-supplied
`offset` is rejected with `400`, not silently ignored. Scope pushdown mirrors `query_responses`
exactly: the caller's visible agent set is resolved and pushed into the store query before `limit`
(ADR-0017 INV-3) — never filtered after the fact. Audited as `execution.detail.fetch`. **Row shape
does NOT mirror `query_responses`** — this route returns the narrower 5-field shape
(`agent_id/execution_id/status/output/timestamp`); `query_responses` was widened to 10 fields by
#2146 A2-R2 on both its `instruction_id` and `execution_id` paths, but this REST route was not
retrofitted onto the wider shared builder (tracked as #4647). The "twin"/"mirrors" language above
is about query-parameter and scope-pushdown semantics only.

#### `GET /api/v1/executions/{id}/children` (#2146 A2-R1)

**Permission:** `Execution:Read`, gated on the fleet-read chokepoint - same gate, same confinement
rules, and the same `execution_child_row_json` shared builder as the legacy
`GET /api/executions/{id}/children` route documented above (`docs/api-twin-recipe.md` Rule 1). MCP
twin: `get_execution_children`. An invisible or nonexistent parent returns `404` with no existence
oracle; under a confined grant, each child is checked against the caller's visibility
**independently** of the parent's own visibility - a visible parent does not by itself disclose a
child dispatched by, or targeting, someone else (#3789). Not audited on a successful read (matches
the legacy route's own posture); a confined denial is audited as `execution.read`. The underlying
query is hard-capped at 100 rows (governance Gate 8 re-review fix, #2146 A2-R1; no caller-visible
limit/cursor), with the cap now pushed down TOGETHER WITH the caller's own visibility scope, before
`LIMIT` - a confined caller's cap applies to their own visible children, not the fleet-wide raw row
set, so an invisible sibling can no longer displace a visible child out of the capped window;
`data.result_truncated_by_cap: true` means that scoped row set exceeded the cap.

**Response:**

```json
{
  "data": {
    "children": [
      { "id": "exec-2", "status": "completed", "dispatched_at": 1735689700 }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

When the 100-row (scoped) cap drops rows, `data.result_truncated_by_cap` is added (`true`):

```json
{
  "data": {
    "children": [ { "id": "exec-2", "status": "completed", "dispatched_at": 1735689700 } ],
    "result_truncated_by_cap": true
  },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/schedules`

**Permission:** same two-stage gate as `GET /fragments/schedules`: a service-scoped API token is
denied the fleet-wide list outright (schedules carry no per-agent axis for `fleet_read_fn` to
confine against), then `Schedule:Read`. The v1 twin of `GET /fragments/schedules`, MCP twin
`list_schedules` (widened by this PR to include `execution_count`). Accepts `definition_id` and
`enabled_only` query parameters (#2146 A2-R1). `enabled_only` is a real boolean here (`true`/`1` or
`false`/`0`; any other value 400s), matching the #4034 precedent already set on `GET
/api/v1/policies` and MCP `list_schedules` - **not** the legacy unversioned `GET /api/schedules`
route's parsing, where any presence of `enabled_only` is treated as true regardless of value. This
route remains a distinct, separately-ledgered twin of `GET /fragments/schedules`, not of `GET
/api/schedules` documented above.

**Response:**

```json
{
  "data": [
    { "id": "sched-1", "name": "nightly-scan", "frequency_type": "interval", "enabled": true }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

The underlying query is hard-capped at `kScheduleListCap` (100) rows with no `limit`/cursor
parameter on this route (ADR-0031 WS-A4 schedule seam). When the cap drops rows,
`pagination.result_truncated_by_cap` is added (`true`) — note this sits under `pagination`, **not**
nested inside `data` the way the `/executions/{id}/children` cap flag above does; the two routes
chose different envelope placements and a caller should not assume one shape from the other:

```json
{
  "data": [ { "id": "sched-1", "name": "nightly-scan", "frequency_type": "interval", "enabled": true } ],
  "pagination": { "total": 100, "start": 0, "page_size": 50, "result_truncated_by_cap": true },
  "meta": { "api_version": "v1" }
}
```

The dashboard fragment (`GET /fragments/schedules`) and the MCP twin (`list_schedules`) share this
same cap and the same underlying query, and each surfaces the truncation in its own shape: the
fragment renders a partial-list HTML notice, MCP's `structuredContent` carries its own
`result_truncated_by_cap` field. See [Dashboard UI — Schedules
tab](instructions.md#13-dashboard-ui) for the fragment's rendered behaviour.

---

### Command/Instruction Responses — v1 read twins (#2146 A2-R2)

Versioned REST + MCP twins of the legacy, unversioned `GET /api/responses/{id}` family
(command/instruction-ID-keyed — **not** the execution-ID-keyed `GET /api/v1/executions/{id}/responses`
documented above, a different, already-shipped capability). The legacy routes
(`response_routes.cpp`) are frozen reference code for this PR — the query/aggregate/export
semantics below mirror them exactly, but the legacy handlers themselves are unmodified. `GET
/api/v1/responses/{id}` and MCP `query_responses` share one JSON row builder
(`response_query_row_json`, `docs/api-twin-recipe.md` Rule 1); `GET /api/v1/responses/{id}/aggregate`
and MCP `aggregate_responses` share another (`response_aggregate_row_json`).

**Two deliberate corrections vs. the legacy routes**, both scoped to the new v1/MCP surfaces only
(the legacy routes are unmodified and keep their pre-existing behavior):

- `limit` is clamped on **both** bounds on the two routes below that accept it — `GET
  /api/v1/responses/{id}` (`[1,1000]`, default 100 when omitted) and `GET
  /api/v1/responses/{id}/export` (`[1,10000]`, default 10000 when omitted);
  `GET /api/v1/responses/{id}/aggregate` has no `limit` parameter. The legacy export route
  (`GET /api/responses/{id}/export`) only floors its own *default* at 10000 — a caller-supplied
  `?limit=` there has no ceiling at all and can attempt an unbounded fetch. Not fixed on the legacy
  route (out of scope for this PR); not propagated to `GET /api/v1/responses/{id}/export`.
- `offset` is rejected with `400` on `GET /api/v1/responses/{id}` and `GET
  /api/v1/responses/{id}/export` (the two routes below with a row-level result set), matching
  `GET /api/v1/executions/{id}/responses` and MCP `query_responses` above: the result set orders by
  a non-unique, actively-growing `timestamp`, so offset-based paging can silently skip or duplicate
  rows. The legacy routes accept (and silently mis-serve) `offset` today — a pre-existing gap this
  PR does not fix on those routes.

`status` is the response status enum (`1`=SUCCESS, `2`=FAILURE; `0` is an in-flight RUNNING frame),
same enum as the bundle-steps `status` field documented above.

A caller cannot tell a complete result from a capped one from row count alone: `GET
/api/v1/responses/{id}` and `GET /api/v1/responses/{id}/export` both set
`pagination.result_truncated_by_cap: true` (a response header, `X-Result-Truncated-By-Cap: true`, on
the export route's CSV format, which has no JSON envelope to carry the field in) when the served row
count equals `limit` — matching MCP `query_responses`' own `hit_cap` convention. Page past a
truncated result with `since`/`until`, not `offset` (rejected, see above).

Audit posture: all three routes below emit a `response.read` audit event, **REST fail-closed** (503
on an audit-persist failure, `docs/api-twin-recipe.md` §4) — a deliberate addition vs. the legacy
routes, which only audit a management-group scope-drop, never a plain successful read. A scope-drop
still emits its own distinct `denied` row (CC7.2 evidence), as the legacy routes already do.

#### `GET /api/v1/responses/{id}`

**Permission:** `Response:Read`, gated on the fleet-read chokepoint (ADR-0017) — resolve-then-scope:
the caller's visible agent set is resolved and pushed into the store query before `limit`, never
filtered after the fact. The v1 twin of `GET /api/responses/{id}` above, MCP twin `query_responses`'s
`instruction_id` path. Accepts `agent_id`, `status`, `since`, `until`, `limit` (clamped to
`[1,1000]`, default 100) query parameters. Does not accept `offset` (see above).

**Response:**

```json
{
  "data": [
    { "id": 42, "instruction_id": "instr-1", "agent_id": "agent-A", "execution_id": "exec-1",
      "status": 1, "output": "ok", "error_detail": "", "timestamp": 1735689600,
      "plugin": "shellexec", "received_at_ms": 1735689600123 }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/responses/{id}/aggregate`

**Permission:** `Response:Read`, same resolve-then-scope confinement (filter-before-aggregate) as
the query route above. The v1 twin of `GET /api/responses/{id}/aggregate` above, MCP twin
`aggregate_responses`. `group_by` is `status` or `agent_id`; `op` is one of `count`/`sum`/`avg`/
`min`/`max` (default `count`); `op_column` (only meaningful for `sum`/`avg`/`min`/`max`) is one of
`timestamp`/`status`/`id`, defaulting to `id` when omitted. An invalid `group_by`/`op_column` is a
`400`, validated against `ResponseStore`'s own allow-list before the aggregate query runs — never
mapped to a `503` (a client typo must not read as store degradation).

**Response:**

```json
{
  "data": {
    "instruction_id": "instr-1",
    "groups": [ { "group_value": "0", "count": 2, "aggregate_value": 1735689700.0 } ],
    "total_groups": 1,
    "total_rows": 2
  },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/responses/{id}/export`

**Permission:** `Response:Read`, same resolve-then-scope confinement as the routes above. The v1
twin of `GET /api/responses/{id}/export` above (no MCP twin — export is a REST-only shape). `format`
is `json` (default) or `csv` — an unrecognised value falls through to `json`, matching the legacy
route's own behavior exactly (neither route rejects an unknown `format` with `400`); `limit` is
clamped to `[1,10000]` on both bounds (see the correction above). Does not accept `offset` (see
above) — rejected with `400`, same non-unique-timestamp-ordering rationale as `GET
/api/v1/responses/{id}`. Unlike the legacy export's
narrower 7-column CSV, both formats here carry the same field set as `GET /api/v1/responses/{id}`
(`id, instruction_id, agent_id, execution_id, status, output, error_detail, timestamp, plugin,
received_at_ms`) — this is a brand-new endpoint with no positional-column consumer to keep
compatible. Both formats set `Content-Disposition: attachment`. The JSON format's envelope is the
standard v1 `{data, pagination, meta}` shape (same as `GET /api/v1/responses/{id}` above) -
distinct from the legacy export's bespoke `{instruction_id, count, responses}` body. A cap-hit
(served rows == `limit`) is most consequential here since bulk export is this route's whole
purpose — see `pagination.result_truncated_by_cap`/`X-Result-Truncated-By-Cap` above; there is no
built-in way to page past 10,000 rows other than narrowing with `since`/`until`/`agent_id`/`status`.

**Response** (`format=json`):

```json
{
  "data": [
    { "id": 42, "instruction_id": "instr-1", "agent_id": "agent-A", "execution_id": "exec-1",
      "status": 0, "output": "ok", "error_detail": "", "timestamp": 1735689600,
      "plugin": "shellexec", "received_at_ms": 1735689600123 }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

### OpenAPI Spec

#### `GET /api/v1/openapi.json`

Returns the OpenAPI/Swagger specification for the v1 API as JSON.

**Permission:** `Infrastructure:Read` (#2057 — was unauthenticated; now matches the MCP `yuzu://openapi` resource twin's gate, `mcp_server.cpp`).

**Response:** OpenAPI 3.x JSON document describing all v1 endpoints, schemas, and authentication methods.

---

### Discovery (A2)

Agentic-first discovery family (roadmap Issue 17.1, `docs/agentic-first-principle.md` §A2): "an agentic worker should be able to learn what is possible from the live server alone, without a side-channel doc fetch." Like `GET /api/v1/openapi.json` above, every endpoint here is **authenticated** and gates `Infrastructure:Read` (`/discover/instructions` gates `InstructionDefinition:Read` instead). Each response body IS the catalog object directly — no `data`/`meta` envelope wrapper, matching the `GET /api/v1/guaranteed-state/schemas` discovery precedent this family is modeled on.

All seven share the same revalidation contract: a content-derived `ETag` header; send `If-None-Match: <etag>` to get a cheap `304 Not Modified` instead of re-downloading. `instructions`, `routes`, `scope-kinds`, `plugin-docs` and `plugin-docs/{name}` are `Cache-Control: public, max-age=300`; `permissions` and `plugins` are `private` with a `Vary` header because their bodies depend on the caller. Five are mirrored as read-only MCP tools of the same name (`discover_permissions`, `discover_instructions`, `discover_routes`, `discover_scope_kinds`, `discover_plugins`); `/discover/plugin-docs` is mirrored as the MCP resource `yuzu://plugin-docs`, and `/discover/plugin-docs/{name}` as the MCP resource template `yuzu://plugin-docs/{name}` (`resources/templates/list`). REST and MCP share the same builder functions internally, so they cannot drift from each other.

#### `GET /api/v1/discover/permissions`

RBAC permission catalog. The response has **two halves with different permissions** (#2376):

- the **taxonomy** — `securable_types` and `operations`, i.e. what the RBAC model can express —
  requires only the route's own `Infrastructure:Read`. It says nothing about who holds what, and an
  agentic worker needs it to author a grant at all (A2 discovery).
- the **role grid** — `roles[].permissions[]`, every role's actual granted securable/operation/effect
  — additionally requires **`UserManagement:Read`**. That grid *is* authorization topology, and it is
  strictly more than `GET /api/v1/rbac/roles` discloses, so it carries the same permission the
  authorization-topology floor applies there.

A caller holding `Infrastructure:Read` but not `UserManagement:Read` still gets `200` and the full
taxonomy; the grid is replaced by `"roles_omitted": true` plus a `roles_omitted_reason`. **The
omission is declared, never silent** — `roles` absent with no `roles_omitted` flag would mean
"no roles exist", which is a different fact.

**Permission:** `Infrastructure:Read` (taxonomy) · `UserManagement:Read` (role grid)

**Caching:** because the body varies with the caller's grants, this route responds
`Cache-Control: private, max-age=300` with `Vary: Authorization, Cookie` — never `public`.
A shared cache must not store one caller's representation and serve it to another.
`GET /api/v1/discover/plugins` is `private` for the same reason (its `parameter_schema`
enrichment is gated on `InstructionDefinition:Read`); the caller-independent catalogues
(`instructions`, `routes`, `scope-kinds`) remain `public, max-age=300`. `Vary` names all
three credential channels this server accepts — `Cookie`, `Authorization` and
`X-Yuzu-Token` — because a caller-local cache keyed on only some of them can serve one
API-token caller's representation to another.

**Response:**
```json
{
  "version": 1,
  "description": "RBAC permission catalog: ...",
  "securable_types": ["Infrastructure", "InstructionDefinition", "Execution", "..."],
  "operations": ["Read", "Write", "Execute", "Delete", "Approve", "Push", "Attest", "Rotate"],
  "roles": [
    {
      "name": "Administrator",
      "description": "...",
      "is_system": true,
      "permissions": [
        {"securable_type": "Infrastructure", "operation": "Read", "effect": "allow"}
      ]
    }
  ]
}
```

Without `UserManagement:Read` the `roles` key is replaced by:
```json
{
  "roles_omitted": true,
  "roles_omitted_reason": "requires UserManagement:Read (#2376 authorization-topology floor); the securable_types and operations taxonomy above is unaffected"
}
```

503 (`{"error":"service unavailable"}`) when the RBAC store is unavailable.

#### `GET /api/v1/discover/instructions`

Published (`enabled_only=true`) `InstructionDefinition` catalog — the commands an agentic worker may dispatch via `execute_instruction` (MCP) or `POST /api/v1/instructions/execute` (REST). A disabled definition is excluded; there is no flag distinguishing "excluded because disabled" from "never existed."

**Permission:** `InstructionDefinition:Read`

**Response:**
```json
{
  "version": 1,
  "description": "Published (enabled) InstructionDefinition catalog: ...",
  "count": 42,
  "truncated": false,
  "instructions": [
    {
      "id": "def-abc123",
      "name": "Get Hostname",
      "plugin": "system_info",
      "action": "query",
      "description": "...",
      "parameter_schema": {"type": "object", "properties": {}},
      "platforms": "windows,linux,darwin",
      "approval_mode": "auto"
    }
  ]
}
```

`parameter_schema` is a nested JSON Schema **object** (not a string) when the stored value parses as JSON *and* is itself a JSON object; `null` when the stored value fails to parse (the authoring path always stores at least `{}`, so this case needs a non-standard write to reach), or when it parses to something other than an object — e.g. an array or string (reachable via the ordinary create/update/import paths, which don't validate the stored value's shape). Same rule `GET /api/v1/discover/plugins` already follows for its inline `parameter_schema`.

#### `GET /api/v1/discover/routes`

REST route catalog — a subset of the SAME OpenAPI document `GET /api/v1/openapi.json` serves (they read the identical compiled-in spec, so they cannot disagree), reshaped to `{method, path, summary, tags, description}` rows.

**Permission:** `Infrastructure:Read`

**Response:**
```json
{
  "version": 1,
  "source": "openapi",
  "description": "REST route catalog, subset of the SAME document GET /api/v1/openapi.json serves...",
  "caveat": "This catalog is derived from the hand-maintained OpenAPI document, NOT generated from the live route table. A route that exists but was never documented in the OpenAPI spec will be under-reported here too. ...",
  "count": 210,
  "routes": [
    {"method": "GET", "path": "/api/v1/discover/routes", "summary": "REST route catalog (A2 discovery)", "tags": ["Discovery"], "description": "..."}
  ]
}
```

Read the `caveat` field: this is a snapshot of a hand-maintained document, not a generated live route table — treat it as informative, not exhaustive.

#### `GET /api/v1/discover/scope-kinds`

Scope DSL kinds, operators, and syntax the Scope Engine (`server/core/src/scope_engine.hpp`) and `AgentRegistry::evaluate_scope` accept when building a `scope` expression for a dispatch, policy, or Baseline. Fully static — answers even when every store is unavailable.

**Permission:** `Infrastructure:Read`

**Response:**
```json
{
  "version": 1,
  "description": "Scope DSL kinds and operators recognized by ...",
  "ground_kinds": [
    {"kind": "__all__", "syntax": "__all__", "example": "__all__", "description": "Every enrolled agent."},
    {"kind": "group:<name>", "syntax": "group:<name>", "example": "group:finance-laptops", "description": "..."}
  ],
  "attribute_kinds": [
    {"kind": "tag:<key>", "syntax": "tag:<key> <op> <value>", "example": "tag:department == \"finance\"", "description": "..."}
  ],
  "operators": [
    {"token": "==", "name": "Eq", "description": "Case-insensitive equality."}
  ],
  "extended_forms": [
    {"form": "LEN(<attr>) <op> <value>", "example": "LEN(hostname) > 5", "description": "..."}
  ],
  "combinators": ["AND", "OR", "NOT"]
}
```

See also `docs/scope-walking-design.md` and `docs/asset-tagging-guide.md` for the fuller narrative treatment of the DSL.

#### `GET /api/v1/discover/plugins`

Plugin/action catalog observed across currently-connected agents (deduplicated by plugin name; the richest reported action list wins). **Not** a build-time manifest of every plugin that could ever load — a plugin no currently-connected agent reports is absent.

**Permission:** `Infrastructure:Read`

**Response:**
```json
{
  "version": 3,
  "description": "Plugin/action catalog observed across currently-connected agents ...",
  "limitation": "An action carries an inline parameter_schema only when it has a published InstructionDefinition (matched on plugin+action) AND the caller holds InstructionDefinition:Read; otherwise name+description only. GET /api/v1/discover/instructions is the full schema-bearing catalog.",
  "actions_enriched_with_schema": 1,
  "plugins": [
    {"name": "processes", "version": "1.0", "description": "...", "actions": [
      {"name": "list", "description": "...", "parameter_schema": {"type": "object", "properties": {}}}
    ]}
  ],
  "commands": ["processes", "processes list", "..."]
}
```

An action carries an inline `parameter_schema` **only** when it has a published `InstructionDefinition` (matched on plugin + action) **and** the caller holds `InstructionDefinition:Read`; a caller with only `Infrastructure:Read` gets each action's `name` + `description` and no schema. The top-level `actions_enriched_with_schema` counts how many actions were enriched. For the complete schema-bearing catalog, use [`GET /api/v1/discover/instructions`](#get-apiv1discoverinstructions).

> **Consumer note:** this catalog is now `"version": 3` (was `1`; v2 added the inline `parameter_schema` and top-level `actions_enriched_with_schema` fields). The revision is additive; treat `version` as a **minimum** (`>= 1`), not `== 1`, so future additive revisions do not break your client.

Each plugin entry also carries `docs`: a build-embedded documentation summary `{summary, kind, platforms, readme, resource}` (`kind` = `{collector, mutating, gathered}`) when the plugin has adopted the README standard (`docs/plugin-readme-standard.md`), or an explicit `null` when it has not (catalog `version` 2 → 3). `resource` names the per-plugin endpoint below (or the MCP resource template of the same shape). The full manifest is that endpoint, or the whole-catalog one above it.

#### `GET /api/v1/discover/plugin-docs`

Per-plugin documentation as data: one manifest per agent plugin that has adopted the README standard, generated by `tools/plugin-doc-gen` from `agents/plugins/<name>/README.md` and embedded at build time (`docs/plugin-readme-standard.md` rule 10). Each manifest carries how the plugin works, per-OS support/rung/mechanism per action (from the CI-verified capability matrix), privileges, inputs, output columns with vocabularies and examples, sample rows per OS, caveats and source paths. Fully static — compiled-in content only, never fleet-derived — so it answers during warmup like `/discover/scope-kinds`, and it is byte-identical to the MCP resource `yuzu://plugin-docs`. A plugin absent here has not adopted the standard yet.

**Permission:** `Infrastructure:Read`

**Response:**
```json
{
  "catalog": "plugin-docs",
  "version": 1,
  "source": "build-embedded",
  "description": "Per-plugin documentation as data ...",
  "plugin_count": 2,
  "skipped_invalid": 0,
  "plugins": [
    {
      "manifest_version": 1,
      "name": "disk_actions",
      "version": "1.0.0",
      "description": "Reports physical drive health and the mapping between drives and the logical volumes they back",
      "kind": {"collector": true, "mutating": false, "gathered": false},
      "platforms": {"windows": "supported", "macos": "constrained", "linux": "unsupported"},
      "security": [{"action": "smart", "securable": "Inventory", "operation": "Read", "risk_tier": "Low", "dispatch_class": "ReadOnly", "mutability": "None", "execute_gate": "None"}],
      "actions": [{"action": "smart", "definition_ids": ["crossplatform.storage.smart"], "legs": {"windows": {"support": "supported", "rung": "1", "mechanism": "IOCTL_STORAGE_QUERY_PROPERTY ...", "fallback": "..."}}}],
      "definitions": [{"id": "crossplatform.storage.smart", "display_name": "Drive Health", "platforms": ["windows", "darwin"], "approval_mode": "auto", "execute_roles": ["endpoint-admin", "endpoint-operator"]}],
      "inputs": [],
      "outputs": [{"definition_id": "crossplatform.storage.smart", "columns": [{"name": "health", "type": "string", "values": ["ok", "warning", "failing", "unknown", "unsupported"], "example": "ok", "platforms": ["windows"]}]}],
      "how_it_works": "Both actions are reads. ...",
      "outputs_note": "Pipe-delimited rows, one per drive or volume. Field 0 is a literal discriminator ...",
      "privileges": [{"os": "Windows", "runs_as": "...", "grant": "None. ...", "measured": "...", "if_refused": "..."}],
      "result_status": [{"status": "`CONSTRAINED`", "completeness": "partial", "provenance": "`macos:iokit:health_unread`", "when": "..."}],
      "where_the_data_goes": ["**Instruction result only.** ..."],
      "samples": {"macos": {"stamp": {"os": "macos", "os_version": "macOS 26.6.2 arm64", "host_class": "bare-metal", "date": "2026-09-07", "privilege": "euid 501", "leg_hash": "f062fb9a3dfd"}, "actions": [{"action": "smart", "rows": ["smart|disk0|APPLE SSD AP0512Z|nvme|ssd|unknown|-|-|..."], "row_count": 2, "result_status": {"status": "CONSTRAINED", "completeness": "PARTIAL", "provenance": "macos:iokit:health_unread"}}]}},
      "caveats": ["**Health is NVMe-only on Windows.** ..."],
      "source": {"plugin": ["agents/plugins/disk_actions/src/disk_actions_plugin.cpp"], "tests": ["tests/unit/test_disk_actions_local_dispatcher.cpp"]},
      "readme": "agents/plugins/disk_actions/README.md",
      "leg_hash": "f062fb9a3dfd"
    }
  ]
}
```

Same ETag / `Cache-Control: public, max-age=300` / `If-None-Match` → `304` contract as `/discover/scope-kinds` (the body is identical for every caller). `inputs[]` entries carry `{definition_id, name, type, required, default, constraints, description}`, where `constraints` is the parameter's DSL `validation` object or `null`; the key set of each manifest is the "Manifest schema" table in `docs/plugin-readme-standard.md`, which the docs suite binds to the generator.

#### `GET /api/v1/discover/plugin-docs/{name}`

One plugin's manifest, narrower than the whole-catalog route above (#4108) — the exact same object the catalog carries at `plugins[]` for that name, byte-identical. Same `manifest_by_name` builder as the catalog and as the MCP resource template `yuzu://plugin-docs/{name}`, so all three cannot drift from each other. The permission gate runs BEFORE the name lookup, so a caller without `Infrastructure:Read` learns nothing about which plugin names exist.

**Permission:** `Infrastructure:Read`

**Response:** the single manifest object shown above for `disk_actions` (same key set, no wrapping envelope — no `catalog`/`version`/`plugins[]`).

**Errors:** `404` (A4 envelope) when no manifest documents that name.

Same ETag / `Cache-Control: public, max-age=300` / `If-None-Match` → `304` contract as the catalog route.

---

### Inventory

Inventory data is structured per-plugin telemetry collected from agents and stored server-side. The generic store (`InventoryStore`, ADR-0037) is Postgres-backed with an AUTHORITATIVE read posture — a store/pool/query degrade returns **503**, never a silent empty result.

#### `GET /api/v1/inventory/tables`

List all inventory tables (one per plugin that reports inventory data).

**Permission:** `Inventory:Read`

**Response:**

```json
{
  "data": [
    {
      "plugin": "hardware",
      "agent_count": 142,
      "last_collected": 1711900800
    }
  ],
  "pagination": { "total": 12 },
  "meta": { "api_version": "v1" }
}
```


**Errors:**

| Status | Reason |
|---|---|
| 503 | Inventory store unavailable or degraded |

#### `POST /api/v1/result-sets/from-inventory-query`

Creates an owner-scoped result set from an inventory query (scope-walking
producer; see `docs/scope-walking-design.md` for the full result-set surface).
One behavior worth calling out here: when the underlying inventory read hits
the server row cap or 8 MiB aggregate payload cap, the route returns **503**
("inventory query truncated ... refusing to materialise a partial result set") rather than
persisting a silently-incomplete set — a fleet-targeting set is never silently
narrowed. **(#4496)** A candidate inventory record excluded by the JSON depth
guard (a poisoned/over-nested `data_json` row; the exclusion check runs
before condition matching, so a record's plugin/fields need not relate to
the query's conditions to trigger it; see json-dump-depth-guard below) gets
the identical treatment: the route returns **503**
("inventory record(s) excluded for nesting too deeply ... refusing to
materialise a result set narrower than the true match set") rather than
silently dropping the poisoned agent from membership: this is a
DELIBERATE choice, unlike the read-only `POST /api/v1/inventory/evaluate` and
`POST /api/inventory/query` routes below, which surface the same exclusion as
a `results_excluded_by_poison` count field, this route materialises its
match set into a *durable* result set other operators/dispatches consume
later, so a flag on this response would never reach them. **(#4496
follow-up)** A candidate inventory record excluded because its `data_json`
failed to parse as JSON at all gets the SAME **503** treatment
("inventory record(s) excluded for failing to parse as JSON ... refusing to
materialise a result set narrower than the true match set"), as a
distinctly-named sibling refusal, checked in a fixed sequence AFTER the
depth-guard one above: a candidate set carrying both problems reports only
the depth-guard (`poison_excluded`) refusal on that call, and the
parse-error refusal surfaces on a subsequent retry once the poisoned record
is fixed - so a caller is always told which cause remains, never that both
have cleared at once.

**Permission:** `Inventory:Read` (guardian-confinement-2298 PR 3 — this
route had NO authorization check of any kind before this fix, CWE-862: any
authenticated session could query up to 5000 fleet-wide inventory records
with zero scoping. Unlike the async producers below, it is a synchronous
read, not a dispatch, so it gates on the same securable as `GET
/api/v1/inventory/software` rather than `Execution:Execute`. **Unlike its
result-set siblings, a service-scoped token is admitted and confined here,
not denied outright** - see the "Result Sets" section below for the exact
gate and the tracked cross-service-reach gap, `#4307`). The owner-scoped
result-set row it creates is only readable/mutable by its own creator
through the routes below, which — like their HTMX dashboard twins — also
deny a service-scoped token outright: `session->username` is the *minting*
principal's identity, not the token's own service tag, so without this a
service token could reach any other token the same minter held.

#### `POST /api/v1/result-sets/from-tar-query`<br>`POST /api/v1/result-sets/from-instruction-result`<br>`POST /api/v1/result-sets/{id}/re-eval`

The three **asynchronous** result-set producers. Unlike `from-inventory-query`,
which answers from server-side inventory, these **dispatch a command to agents**
and materialise the set once the responses land — so they are operator dispatch
surfaces, not reads. `from-tar-query` runs SQL on TAR agents; `from-instruction-result`
runs an `InstructionDefinition` and filters responders by `matcher`; `{id}/re-eval`
re-runs a set's own source query and creates a **sibling** (same parent, new id).

**Permission:** `Execution:Execute`, **confined per device**

> **Per-device confinement (#1788).** These routes admit on a global
> `Execution:Execute` grant and then reach the fleet by scope (`parent_id`) or
> `__all__` broadcast, so the caller's derived visible set is their only
> per-device authorization. A service-scoped token reaches only agents tagged
> with its own service; devices outside the caller's reach are dropped from the
> send set rather than refused individually. A global administrator or a
> JIT-elevated session keeps full-fleet reach — that is their actual authority.

**Targeting:** omit `parent_id` to dispatch to `__all__` deliberately. A
**supplied** `parent_id` that is empty, non-string, or `null` is refused with
`400 RESULT_SET_BAD_PARENT` rather than silently widening to the fleet.

**`{id}/re-eval` field bounds (#4373).** The original set's re-run fields are
rechecked against the same bound values used elsewhere, because the original
row may have been minted through `POST /api/v1/result-sets` directly (which
carries no `source_kind` allowlist) rather than through
`from-tar-query`/`from-instruction-result`, and so may never have been
validated at all: `sql` (tar_query) at 100 KiB, the bound `from-tar-query`
itself already enforces at creation time; and `instruction_id`
(instruction_result) at 256 bytes plus `params` at 32 keys / 256-byte keys /
64 KiB values, the same bounds REST's own `from-instruction-result` route now
also enforces at creation time (#4373), matching the MCP tool
`create_result_set_from_instruction_result`. A `params` that is present but
not a JSON object (a string, array, or number) is refused outright rather
than silently dispatching with an empty params map. A type-mismatched
`sql`/`instruction_id` value (not a JSON string) is treated as absent, taking
the existing missing-field 400 path, rather than surfacing as an uncaught
exception (#4406, fixed on both `from-tar-query` and `from-instruction-result`
in the same change).

**`{id}/re-eval` is refused, never broadcast, when the recorded parent is gone (#4306).**
`re-eval` synthesises the sibling's dispatch scope from the original's *live* `parent_id`
FK, which is nulled (`ON DELETE SET NULL`) if the parent set is later deleted. An absent
`parent_id` reaching dispatch synthesis normally means "broadcast to `__all__`" — the same
rule the parent_id-empty guard above enforces for a caller-supplied empty string — so
letting that happen here would silently turn "re-ask the same narrow question" into "ask
the whole visible fleet". If the live parent is gone **and** the original's stored
`source_payload` shows it was narrowed at creation time (a non-empty `scope_input_id` --
recorded by every result-set create route that accepts `parent_id` — `from-tar-query`/
`from-instruction-result`/`from-inventory-query` (which always build a well-formed object
payload) and the generic `POST /api/v1/result-sets` (#4306 follow-up), except when the
generic route's caller-supplied `source_payload` is itself not a JSON object, in which case
re-eval's own sql/instruction_id-presence check independently refuses such a row before
dispatch regardless), the
call is refused rather than re-resolved (the recorded value may be an alias that has since
been re-bound to a different, newer set) or silently broadcast. A genuinely parentless
original (no `parent_id` was ever supplied, by any creation path) still broadcasts on
re-eval, unchanged.

**Errors:**

| Status | Reason |
|---|---|
| 400 | `RESULT_SET_BAD_PARENT` — `parent_id` supplied but names no parent set; or missing `sql` / `instruction_id`. `parent_id` exceeding 64 bytes also returns 400, but without this code prefix (bare "parent_id must be at most 64 bytes") |
| 400 | `RESULT_SET_BAD_REQUEST`: on `from-instruction-result` or `re-eval`, `instruction_id` exceeds 256 bytes, `params` exceeds 32 keys / a key exceeds 256 bytes / a value exceeds 64 KiB, or `params` is present but not a JSON object. On `re-eval` only, the original's `sql` may also exceed 100 KiB (#4373) |
| 400 | `RESULT_SET_BAD_REQUEST`: on `re-eval` only, the original's live parent set was deleted and its persisted `scope_input_id` shows it was narrowed at creation (#4306) — audited `result_set.create\|denied`, `reason=parent_gone` |
| 400 | `sql`/`instruction_id`/`name` present but not a JSON string (a clean 400 rather than an uncaught exception, #4406); `name` over 256 bytes on `from-tar-query` or `from-instruction-result` |
| 404 | Unknown `instruction_id`, unknown parent set, or (on re-eval) a set the caller does not own |
| 429 | `RESULT_SET_QUOTA_EXCEEDED` — owner is at the per-owner set cap |
| 500 | `RESULT_SET_GATE_UNCONFIGURED` — the server's dispatch-visibility gate is not wired. Fails **closed**: nothing is dispatched, and the refusal is audited. An operator seeing this has a server misconfiguration, not an authorization problem |
| 500 | `RESULT_SET_STORE_FAULT_AFTER_DISPATCH` — a real command already dispatched to agents, but the store fault persisting the pending result-set row afterward (#4306; previously `400`, corrected — this is a server fault, not a client error, once a command has already been sent). Do **not** re-send; poll `GET /api/v1/executions/{id}` for the dispatched command's outcome instead |
| 503 | `RESULT_SET_NO_AGENTS` — no agents were reached in the target scope. Deliberately indistinguishable from "every resolved target was outside your reach": a distinct status would disclose devices the caller may not see |
| 503 | `RESULT_SET_STORE_UNAVAILABLE` (pre-dispatch) — the per-owner quota could not be verified before dispatch (Postgres degraded, #4306). Nothing was dispatched; safe to retry (`Retry-After` header present) |
| 503 | `RESULT_SET_DISPATCH_UNAVAILABLE` / `RESULT_SET_DISPATCH_FAILED` — dispatch not wired, or the dispatch itself raised |

#### `GET /api/v1/inventory/{agent_id}/{plugin}`

Get inventory data for a specific agent and plugin.

**Permission:** `Inventory:Read`

**Response:**

```json
{
  "data": {
    "agent_id": "agent-001",
    "plugin": "hardware",
    "data": { "cpu_count": 8, "ram_gb": 32 },
    "collected_at": 1711900800
  },
  "meta": { "api_version": "v1" }
}
```

The `data` field contains the plugin-specific structured inventory blob as parsed JSON (or a string if the blob is not valid JSON).

**Errors:**

| Status | Reason |
|---|---|
| 404 | No inventory data found for this agent+plugin |
| 503 | Inventory store unavailable or degraded |

#### `POST /api/v1/inventory/query`

Query inventory data across agents with filters.

**Permission:** `Inventory:Read`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | No | Filter by agent ID |
| `plugin` | string | No | Filter by plugin name |
| `since` | integer | No | Unix timestamp — only records collected after this time |
| `until` | integer | No | Unix timestamp — only records collected before this time |
| `limit` | integer | No | Max results (default 100, max 1000) |

**Response:** List of inventory records matching the query, plus top-level
`result_truncated_by_cap`. When that flag is `true`, the server's row or 8 MiB aggregate
payload budget was reached and the returned fleet result is incomplete; callers must not
interpret omitted rows as absence.

**Errors:**

| Status | Reason |
|---|---|
| 503 | Inventory store unavailable or degraded |

#### `POST /api/v1/inventory/evaluate`

Evaluate inventory conditions across agents. Returns agents whose inventory data matches the specified conditions.

**Permission:** `Inventory:Read`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | No | Scope to a single agent |
| `combine` | string | No | `"and"` (default) or `"or"` — how to combine multiple conditions |
| `conditions` | array | Yes | List of condition objects |

Each condition object:

| Field | Type | Description |
|---|---|---|
| `plugin` | string | Plugin name to query |
| `field` | string | JSON field path within the inventory data |
| `op` | string | Operator: `eq`, `neq`, `gt`, `lt`, `gte`, `lte`, `contains` |
| `value` | string | Value to compare against |

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-001",
      "match": true,
      "matched_value": "8",
      "plugin": "hardware",
      "collected_at": 1711900800
    }
  ],
  "meta": { "api_version": "v1" }
}
```

`result_truncated_by_cap` (bool, optional) — emitted at the **top level of the
envelope** (alongside `data`), present and `true` when the underlying inventory
read hit its row cap (5,000 for this route) or 8 MiB aggregate payload cap:
absent devices may simply not have
been read rather than not matching. (The typed software route carries the same
flag inside `data` — placement alignment is tracked with #2633.)

`results_excluded_by_poison` (integer, optional, #4496): emitted at the same
top level, present and non-zero when one or more candidate inventory records
were excluded because their stored `data_json` nested past the JSON depth
guard (a poisoned/over-nested row; the exclusion check runs before condition
matching, so a record's plugin/fields need not relate to the query's
conditions to trigger it; see json-dump-depth-guard below). The returned
matches may be missing some the caller cannot detect any other way.
Distinct from `result_truncated_by_cap` (a row/byte cap on the underlying
read, not a per-record exclusion); either, both, or neither may be present
on a given response.

`results_excluded_by_parse_error` (integer, optional, #4496 follow-up):
emitted at the same top level, present and non-zero when one or more
candidate inventory records were excluded because their stored `data_json`
failed to parse as JSON at all (a syntax defect, not over-nesting). A
distinctly-named sibling of `results_excluded_by_poison` above, kept separate
so a caller can tell WHICH guard excluded a record - the two causes are
different (malformed JSON vs. over-nested JSON) and both, either, or neither
may be present on a given response alongside `result_truncated_by_cap`.

**Errors:**

| Status | Reason |
|---|---|
| 503 | Inventory store unavailable or degraded |

#### `GET /api/v1/inventory/software`

Fleet-wide read of the typed installed-software inventory (ADR-0016, `SoftwareInventoryStore`). **Distinct** from the generic `/inventory/*` routes above, which read the generic per-source blob store (`InventoryStore`, also Postgres-backed as of ADR-0037, but a separate schema/table). This is the REST sibling of the `query_installed_software` MCP tool — same data, same scope contract.

**Permission:** `Inventory:Read`, gated SOLELY by `AuthRoutes::require_fleet_read` (#3290 Phase 2 — never stacked with a separate permission check). A service-scoped API token (bound to one IT service's agents) is no longer denied outright: it gets a real filtered `200` scoped to its service-tagged agents, intersected with any management-group confinement that also applies (`meet(management-group, service-scope)`). A management-group-confined operator (no global grant) also now gets a genuinely filtered `200` instead of the fleet-wide/denied split of earlier releases.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Exact software-name filter |
| `agent_id` | string | No | Exact agent filter |
| `limit` | integer | No | Max rows (default 100, min 1, max 1000) |

Omit both `name` and `agent_id` for a fleet-wide scan.

**Response (200):**

```json
{
  "data": {
    "software": [
      {"agent_id": "agent-001", "name": "bash", "version": "5.2.21", "publisher": "Fedora Project",
       "install_date": "2026-01-15", "kind": "package", "ecosystem": "rpm", "epoch": "0",
       "release": "3.fc40", "arch": "x86_64", "signature_status": "signed",
       "distro_id": "fedora", "distro_version": "40"},
      {"agent_id": "agent-002", "name": "Google Chrome", "version": "124.0", "publisher": "Google LLC",
       "install_date": "2026-01-15", "kind": "app", "ecosystem": "windows", "epoch": "",
       "release": "", "arch": "", "signature_status": "", "distro_id": "", "distro_version": ""}
    ],
    "count": 2,
    "devices_omitted": 0,
    "result_truncated_by_cap": true
  },
  "meta": { "api_version": "v1" }
}
```

Every row carries the **blob-v2 package fields** (`kind`, `ecosystem`, `epoch`, `release`, `arch`, `signature_status`, `distro_id`, `distro_version`) alongside the original four. A field the source ecosystem does not store is `""` — **never synthesised** (a Windows/macOS app row is honestly empty on every NEVRA/signature/distro field, as in the second example above). These 8 keys are **always present in every row** (never absent) — integration code should test for an empty-string value, not key absence. See `docs/user-manual/inventory.md` for the full per-ecosystem availability matrix.

`devices_omitted` is always present (0 when no scope filtering occurred). `result_truncated_by_cap` is present only when `count == limit` and more rows may exist past the cap (keyset pagination is a follow-up, #1634). `audit_persisted: false` is present only when the audit row could not be persisted (set-and-proceed posture — the data is still served, the lost-evidence flag is surfaced honestly).

Results carry a **per-agent scope drop filter** — the `require_fleet_read` gate's own composed `meet(management-group, service-scope)` visibility set (#3290): out-of-scope devices are dropped and their distinct count returned in `devices_omitted`. A positive `devices_omitted` means matching software exists **outside** your scope — an empty or short result does **not** mean the software is absent fleet-wide. This confinement is now **effective**, not a foundation: a management-group-confined operator and a correctly-confined service-scoped token both see a genuinely narrowed result, matching the ADR-0017 admit-then-filter model this route was the first to adopt in Phase 2.

**Error responses:**

| Status | Condition |
|---|---|
| 400 | `limit` is not a valid integer |
| 401 | Unauthenticated |
| 403 | No management-group grant for `Inventory:Read`; or a service-scoped token whose RBAC/ITServiceOwner grant is missing, or whose RBAC enforcement is disabled fleet-wide (a service-scoped token always hard-denies when RBAC is off) |
| 503 | The gate's own RBAC/tag-store lookup is unavailable or degraded, the software inventory store is unavailable or degraded, or the `require_fleet_read` gate itself is unwired (server misconfiguration) — all A4 envelope with `correlation_id`, `retry_after_ms: 5000` where retryable — **never an empty 200** |

On a `503` the store (or the confinement check itself) could not be read; do **not** treat it as "not installed anywhere" (ADR-0016 §7 authoritative reads). A genuine empty result is `200` with `count: 0`.

---

### Result Sets

The result-set lifecycle routes (list/create/inspect/pin/delete). See [scope-walking-design.md](../scope-walking-design.md) for the full design and the four **producer** routes documented above under [Inventory](#inventory) (`POST /api/v1/result-sets/from-inventory-query`, `from-tar-query`, `from-instruction-result`, `{id}/re-eval`). `ResultSetStore` (ADR-0036) is always constructed in a running server (Postgres is mandatory; a construction failure halts startup rather than degrading serving, ADR-0012 §1) — these routes are always registered.

**JSON nesting depth bound (json-dump-depth-guard fix), all four producers plus re-eval.** `nlohmann::json::dump()` is unboundedly recursive; the [MCP transport's 32-level guard](../mcp-server.md) (#2437) checked only the live `/mcp/` request body, leaving a gap on REST. `POST /api/v1/result-sets`, `/from-inventory-query`, `/from-tar-query`, and `/from-instruction-result` now reject (`400 RESULT_SET_BAD_REQUEST`) a request body nesting deeper than 32 levels before it is parsed, reusing the same `kMcpMaxJsonDepth` constant MCP enforces so the two surfaces cannot drift apart. `POST /api/v1/result-sets/{id}/re-eval` applies the same check to the row's **stored** `source_payload` before parsing it, since the table is shared with MCP's `reevaluate_result_set` and a row poisoned by any write path (including one predating this fix) would otherwise be re-dumped on a later read. **Heal on reject (#4493).** This specific re-eval attempt still fails with `400 RESULT_SET_BAD_REQUEST`, but the route now also discards the poisoned `source_payload` in place (status-agnostic - `materialized` and `failed` rows are healed too, not just `pending`) before returning, so every subsequent read of the row is safe instead of re-detecting the same poison forever; the row's `status` and members are never touched. The response body says "...and has been discarded..." only when the heal write actually committed - a rare heal-write failure returns a differently-worded `400` and leaves the row unchanged for the next retry.

**MCP twins (#2146 Batch B2):** every one of these 12 REST v1 operations has an MCP tool twin (`list_result_sets`, `create_result_set`, `create_result_set_from_inventory_query`, `create_result_set_from_tar_query`, `create_result_set_from_instruction_result`, `reevaluate_result_set`, `get_result_set`, `get_result_set_members`, `get_result_set_lineage`, `pin_result_set`, `unpin_result_set`, `delete_result_set`) — see [mcp-server.md](../mcp-server.md)'s "Result sets" tool family. The three async producer tools share the exact same `Execution:Execute` + per-device confined-dispatch gate (#1788) as their REST twins below; 8 of the remaining 9 are owner-scoped exactly like the REST routes (a service-scoped API token is denied outright). **`create_result_set_from_inventory_query`/`POST /api/v1/result-sets/from-inventory-query` are the one exception**: both gate via the admit-then-filter `fleet_read_fn` chokepoint, whose service-scope branch admits-and-confines a service-scoped token rather than hard-denying it - since the created result set is still owner-scoped to the minting token, a service token can mint a set the minter's other tokens/session can then read, a real cross-service-reach gap tracked in #4307.

`ResultSet` is not a seeded RBAC securable; every route below is session-authenticated and **owner-scoped** instead (a result set is only readable/mutable by the principal that created it). A service-scoped API token is denied outright on every route (`403`): ownership keys on `session->username`, which for a service token is the **minting operator's** identity, not the token's own service tag — without this deny, any other service token the same operator holds could reach the same owner-scoped result sets.

**Example `ResultSet` object** (returned by several routes below):

```json
{
  "id": "rs_a1b2c3d4e5f6",
  "name": "Ubuntu fleet, patched",
  "owner_principal": "alice",
  "created_at": 1711900800,
  "ttl_at": 1712505600,
  "last_used_at": 1711900800,
  "pinned": false,
  "parent_id": "",
  "source_kind": "manual_curate",
  "status": "materialized",
  "source_execution_id": "",
  "device_count": 42
}
```

`parent_id` is `""` when the set has no parent. `source_kind` is one of `manual_curate` (direct `POST /result-sets`), `inventory_query`, `tar_query`, or `instruction_result`. `status` is `pending` until an asynchronous producer's dispatch responses land, then `materialized` (or `failed` if the dispatch could not be materialized).

#### `GET /api/v1/result-sets`

List the caller's owned result sets, most recently used first (`last_used_at` then `created_at`, both descending — not creation order).

**Permission:** Session-authenticated (owner-scoped; no RBAC permission).

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `cursor` | string | Opaque pagination cursor from a previous response |
| `limit` | integer | Max results (default 50, max 500) |

**Response:**

```json
{
  "data": { "result_sets": [ { "...": "ResultSet objects, see above" } ], "next_cursor": "" },
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Status | Reason |
|---|---|
| 403 | Service-scoped API token — result-set listing cannot be confined to the token's service |
| 503 | `RESULT_SET_STORE_UNAVAILABLE` — a store-level read failure while listing |

A store-level read failure now answers `503 RESULT_SET_STORE_UNAVAILABLE` (fail-closed, #4306) rather than a silent empty `200` array.

#### `POST /api/v1/result-sets`

Create a result set directly from a pre-computed device-id list (e.g. an operator with a CSV of device ids). Synchronous — lands `materialized` immediately, no dispatch involved.

**Permission:** Session-authenticated (owner-scoped).

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Human-readable name |
| `source_kind` | string | No | Defaults to `manual_curate` |
| `source_payload` | object | No | Stored as JSON; defaults to `{}` — if `parent_id` is also supplied AND `source_payload` is itself a JSON object, a `scope_input_id` key recording it is merged in (overwriting any caller-supplied key of that name), #4306 |
| `parent_id` | string | No | Must reference a set the caller owns (else `404`) |
| `device_ids` | array of string | No | The initial member set |

**Response (201):** A `ResultSet` object (see above).

**Errors:**

| Status | Reason |
|---|---|
| 400 | `RESULT_SET_TOO_MANY_MEMBERS` (`device_ids` exceeds the per-set cap), or another `ResultSetError` (every non-quota `create_materialized` failure — including a store-level error — maps to `400`, not `503`) |
| 400 | `name`/`source_kind` present but not a JSON string, or over the MCP-matching length cap (`name` 256 bytes, `source_kind` 64 bytes) - checked before `create_materialized` is ever called, not a `ResultSetError` (#4373) |
| 400 | `RESULT_SET_BAD_PARENT` — `parent_id` supplied but empty/non-string. `parent_id` exceeding 64 bytes also returns 400, but without this code prefix (bare "parent_id must be at most 64 bytes") |
| 403 | Service-scoped API token |
| 404 | `parent_id` supplied but not owned/found |
| 429 | `RESULT_SET_QUOTA` — owner is at the per-owner set cap |

#### `GET /api/v1/result-sets/{id}`

Fetch one result set by id.

**Permission:** Session-authenticated (owner-scoped, `load_owned`).

**Response (200):** A `ResultSet` object (see above).

**Errors:**

| Status | Reason |
|---|---|
| 403 | Service-scoped API token |
| 404 | `RESULT_SET_NOT_FOUND` — no such set, or not owned by the caller (identical body either way — no enumeration oracle) |
| 503 | Result-set store unavailable |

#### `DELETE /api/v1/result-sets/{id}`

Delete a result set.

**Permission:** Session-authenticated (owner-scoped, `load_owned`).

**Response:** `{"data": {"deleted": true}, "meta": {"api_version": "v1"}}`

**Errors:**

| Status | Reason |
|---|---|
| 403 | Service-scoped API token |
| 404 | No such set, or not owned by the caller. Also returned if the delete itself fails after ownership is confirmed (e.g. a store write error) — that failure is not currently distinguished from not-found. |
| 409 | `RESULT_SET_PINNED` — unpin the set before deleting it |
| 503 | Result-set store unavailable (ownership lookup only) |

#### `GET /api/v1/result-sets/{id}/members`

Page through a result set's member device ids.

**Permission:** Session-authenticated (owner-scoped, `load_owned`).

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `cursor` | string | Opaque pagination cursor |
| `limit` | integer | Max results (default 1000, max 10000) |

**Response:** `{"data": {"device_ids": [...], "next_cursor": ""}, "meta": {"api_version": "v1"}}`

**Errors:**

| Status | Reason |
|---|---|
| 403 | Service-scoped API token |
| 404 | No such set, or not owned by the caller |
| 503 | Result-set store unavailable |

#### `GET /api/v1/result-sets/{id}/lineage`

Read a result set's ancestor chain (walks `parent_id` links up to the root).

**Permission:** Session-authenticated (owner-scoped, `load_owned`).

**Response:** `{"data": {"chain": [{"id": "...", "name": "...", "source_kind": "...", "device_count": 0}]}, "meta": {"api_version": "v1"}}`

**Errors:**

| Status | Reason |
|---|---|
| 403 | Service-scoped API token |
| 404 | No such set, or not owned by the caller |
| 503 | Result-set store unavailable |

#### `POST /api/v1/result-sets/{id}/pin`<br>`POST /api/v1/result-sets/{id}/unpin`

Pin (exempt from TTL expiry) or unpin a result set.

**Permission:** Session-authenticated (owner-scoped, `load_owned`).

**Response (200):** The updated `ResultSet` object (`pinned` flipped).

**Errors:**

| Status | Reason |
|---|---|
| 403 | Service-scoped API token |
| 404 | No such set, or not owned by the caller. Also returned if the pin/unpin write itself fails after ownership is confirmed (e.g. a store write error) — that failure is not currently distinguished from not-found. |
| 409 | `PIN_LIMIT` — owner is at the per-owner pin cap (pin only) |
| 503 | Result-set store unavailable (ownership lookup only) |

---

### Forensics

The **per-agent app-usage** discovery surface (Wave 7 PR7.2, ADR-0016 §5). Data is derived on the agent from TAR's `usage_daily` fold via the read-only `app_usage` plugin and synced daily into `AppUsageStore`, projecting each executable's retained-window first/last-seen plus a trailing-30-day run-count/total-seconds window. `Forensics` is **Administrator-only by design** — deliberately absent from the seeded Viewer read-list.

#### `GET /api/v1/forensics/agents/{agent_id}/app-usage`

One device's per-executable last-used projection — the per-agent drill. Because it renders behavioural data, every open is **audited fail-closed**: if the `app_usage.agent.view` audit row cannot persist, the request is refused (`503` + `Sec-Audit-Failed`) and no data is served.

**Permission:** `Forensics:Read` — **per-device scoped** (management-group confinement; `403` for an in-fleet device outside your scope).

**Response (200):**

```json
{
  "data": {
    "agent_id": "agent-001",
    "apps": [
      {"exe_key": "chrome.exe", "first_seen": 1751000000, "last_seen": 1751600000,
       "run_count_30d": 42, "total_seconds_30d": 86400}
    ],
    "collected_at": 1751600000
  },
  "meta": { "api_version": "v1" }
}
```

`first_seen`/`last_seen` are **within TAR's retained usage window** (31 days default, operator-tunable) — never a value spanning the executable's full run history. An executable absent from `apps` has not run inside that retained window; it does not mean the executable has never run. An agent that genuinely reported no rows for the window is `200` with `apps: []`.

**Error responses:**

| Status | Condition |
|---|---|
| 401 | Unauthenticated |
| 403 | Caller lacks per-device-scoped `Forensics:Read` for this agent |
| 503 + `Sec-Audit-Failed` | The per-open audit row could not persist — fail-closed, no data served |
| 503 | Store unavailable or degraded (A4 envelope with `correlation_id`, `retry_after_ms: 5000`) — **never an empty 200** |

Decommissioning the agent erases this store's rows too — see [Software Licensing (SLE)](#software-licensing-sle)'s `DELETE /api/v1/sle/agents/{agent_id}` (the six-store cascade).

---

### Software Licensing (SLE)

The **detected software-licence** discovery surface (ADR-0024; per its "Placement under ADR-1005" only the discovery mechanism is in-server — the compliance/entitlement/posture reads ship with the SAM use-case-engine module). Data is collected by the agent `license_scan` plugin and synced daily into `SoftwareLicensingStore`; see [Software licence detection](software-licensing.md) for what is collected and the per-user privacy carve-out. **Not** Yuzu's own product licence (that is [License Management](#license-management)).

#### `GET /api/v1/sle/agents/{agent_id}`

One device's detected licences — the per-agent drill. This is the **only** surface that serves the per-user `user_scope`/`user_ref` fields (ADR-0024 Decision 11 personal data); its MCP twin `query_software_licenses` returns machine-scope facts with those fields omitted. Because it renders personal data, every open is **audited fail-closed**: if the `sle.agent.view` audit row cannot persist, the request is refused (`503` + `Sec-Audit-Failed`) and no licence data is served.

**Permission:** `SoftwareLicensing:Read` — **per-device scoped** (management-group confinement; `403` for an in-fleet device outside your scope).

**Response (200):**

```json
{
  "data": {
    "agent_id": "agent-001",
    "licenses": [
      {"product": "Office 365 ProPlus", "vendor": "Microsoft", "version": "16.0.1",
       "license_type": "subscription", "state": "subscription_active", "expiry_at": 1893456000,
       "channel": "KMS", "key_hint": "XXXXX-B7GJQ", "detector": "wmi_slp",
       "confidence": "probable", "exe_hints": "winword.exe;excel.exe",
       "user_scope": "machine", "user_ref": "",
       "collected_at": 1751000000, "first_seen": 1751000000, "last_seen": 1751600000}
    ],
    "count": 1
  },
  "meta": { "api_version": "v1" }
}
```

`key_hint` is an OS-provided partial key — full key material is never collected, stored, or served. `expiry_at` is epoch seconds (`0` = none). On a per-user row, `user_scope` is `"user"` and `user_ref` carries the profile identifier as minimised on-device (`hash` mode default — a per-agent keyed-HMAC pseudonym; see the [privacy limits](software-licensing.md#per-user-detection-and-privacy)). `first_seen`/`last_seen` are server receipt times.

**Error responses:**

| Status | Condition |
|---|---|
| 401 | Unauthenticated |
| 403 | Caller lacks per-device-scoped `SoftwareLicensing:Read` for this agent |
| 503 + `Sec-Audit-Failed` | The per-open audit row could not persist — fail-closed, no data served |
| 503 | Store unavailable or degraded (A4 envelope with `correlation_id`, `retry_after_ms: 5000`) — **never an empty 200** |

A genuinely licence-free (or unknown) device is `200` with `count: 0`; a `503` means the store could not be read — do **not** treat it as "nothing licensed".

#### `DELETE /api/v1/sle/agents/{agent_id}`

**Destructive.** The audited whole-device erasure trigger: fans `delete_agent` across **all six per-agent stores** (generic inventory, installed-software, device-CI, app-perf, detected-licence, and app-usage), durably erasing the decommissioned device's rows — including the Decision-11 `user_ref` personal data. This is the wired GDPR Art. 17 whole-device erasure path (row-level / per-subject DSAR erasure is a stated gap, #1666). Deliberately REST-only — no MCP twin (recorded ADR-1005 exception, #2102).

**Permission:** a single **per-device-scoped `Decommission:Delete`** securable (ADR-0024 Decision 9, amended Wave 7 PR7.2) — one grant authorizing for the cascade's whole blast radius, replacing the earlier per-store conjunction. A role lacking it is `403`'d, naming `Decommission:Delete` (the seeded Administrator/ITServiceOwner roles hold it by default; a custom role that had assembled the old per-store `Delete` grants must be granted this securable too — the three old grants no longer suffice).

Two durable audit events: `sle.agent.decommission|attempt` is written **before** the erasure and **fails closed** — if it cannot persist, nothing is erased (`503` + `Sec-Audit-Failed`); the outcome row (`success`/`partial`) follows with the per-store breakdown.

**Response (200)** — every store's delete committed:

```json
{
  "data": {
    "agent_id": "agent-001",
    "decommissioned": true,
    "stores": {"inventory": "deleted", "software_inventory": "deleted",
               "app_perf_daily": "deleted", "device_inventory": "skipped",
               "software_licensing": "deleted", "app_usage": "deleted"},
    "deleted": 5,
    "skipped": 1,
    "failed": 0
  },
  "meta": { "api_version": "v1" }
}
```

Per-store outcomes: `deleted` (the DELETE **committed**), `skipped` (store not configured on this deployment), `failed` (rolled back or threw — the delete did **not** happen). Each store reports its true commit status, so a rolled-back erasure is never reported as done.

**Error responses:**

| Status | Condition |
|---|---|
| 401 | Unauthenticated |
| 403 | Caller lacks the per-device-scoped `Decommission:Delete` permission |
| 500 | One or more stores `failed` — the A4 body carries the per-store breakdown in `error.details.stores`; the cascade is **idempotent**, re-issue the DELETE to retry the failures |
| 503 + `Sec-Audit-Failed` | The attempt audit row could not persist — fail-closed, **nothing was erased** |
| 503 | Scope gate or cascade not configured (A4 envelope) |

A `200` with `decommissioned: true` is confirmed erasure across every configured store; deleting an unknown `agent_id` is a no-op `200` (nothing to erase). Erasure does not unenroll the agent — a still-enrolled device re-syncs on its next daily cycle, so decommission the device first. This guarantee is scoped to the stores the cascade actually fans across — a leftover legacy `inventory.db` on disk (only possible outside ADR-0009's "no fleet ever ran pre-Postgres" assumption) was never part of it: `InventoryStore::delete_agent()` stopped scrubbing that file when its one-time backfill was retired (#3623), since the erasure branch existed only to serve the backfill.

---

### Execution Statistics

Fleet-wide and per-entity execution metrics.

#### `GET /api/v1/execution-statistics`

Get fleet-wide execution summary.

**Permission:** `Execution:Read`

**Response:**

```json
{
  "data": {
    "total_executions": 15420,
    "executions_today": 230,
    "active_agents": 142,
    "overall_success_rate": 0.973,
    "avg_duration_seconds": 4.2
  },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/execution-statistics/agents`

Get per-agent execution statistics.

**Permission:** `Execution:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `agent_id` | string | Filter to a single agent |
| `since` | integer | Unix timestamp — only executions after this time |
| `limit` | integer | Max results (default 100, max 1000) |

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-001",
      "total_executions": 324,
      "success_count": 310,
      "failure_count": 14,
      "success_rate": 0.957,
      "avg_duration_seconds": 3.8,
      "last_execution_at": 1711900800
    }
  ],
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/execution-statistics/definitions`

Get per-definition execution statistics.

**Permission:** `Execution:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `definition_id` | string | Filter to a single definition |
| `since` | integer | Unix timestamp — only executions after this time |
| `limit` | integer | Max results (default 100, max 1000) |

**Response:**

```json
{
  "data": [
    {
      "definition_id": "os-info-query",
      "total_executions": 5200,
      "total_agents": 142,
      "success_rate": 0.995,
      "avg_duration_seconds": 1.2
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

### Execution Visualization

Render an execution's response set as chart-ready JSON, using the `spec.visualization` block configured on the associated `InstructionDefinition` (issue #253). The endpoint is the data source for the dashboard's chart cards and is also suitable for external consumers (Grafana scripted-panel datasources, custom dashboards) that can read JSON over HTTP.

#### `GET /api/v1/executions/{id}/visualization`

**Permission:** `require_fleet_read("Response","Read")` (ADR-0017 admit-then-filter — #1634, replaced the flat `Response:Read` gate)

**Confined (#1634).** A management-group-confined operator is admitted and sees only their in-scope agents' rows in the rendered chart — real cross-operator isolation, not the earlier inert per-row filter. The visible-agent set is resolved and pushed into the underlying SQL query before the row cap (ADR-0017 INV-3), so `rows_capped` (below) reflects the CALLER's own scoped cap hit, not a raw-then-filtered one that could fire entirely inside another operator's rows. On a **corrupt or unavailable RBAC store** the endpoint still fails **closed** (`403`/`503`) rather than exposing the whole fleet. When rows are dropped, a SEPARATE `result=denied` audit row fires (`detail` carries `scope_dropped=<N>`), paired with the `result=success` row for the same request — this fires under ordinary operation for a confined caller whose execution spans agents outside their groups, not only on RBAC-store corruption.

**Path parameters:**

| Param | Description |
|---|---|
| `id` | The response-store key (the `command_id` returned at dispatch time). |

**Query parameters:**

| Param | Type | Required | Description |
|---|---|---|---|
| `definition_id` | string | Yes | ID of the `InstructionDefinition` that holds the `spec.visualization` (or `spec.visualizations`) block. Required because Yuzu keys responses by `command_id`, not by `executions.id` — the caller supplies the link. Must match `[A-Za-z0-9._-]+`. |
| `index` | integer | No | Chart index when the definition declares multiple visualizations. Default `0`. Returns 404 if out of range. |

**Response (200):**

```json
{
  "data": {
    "chart_type": "pie",
    "title": "Service States",
    "labels": ["running", "stopped", "paused"],
    "series": [{ "name": "Count", "data": [42, 7, 1] }],
    "meta": {
      "responses_total": 50,
      "responses_succeeded": 50,
      "responses_failed": 0
    },
    "chart_index": 0,
    "chart_count": 1
  },
  "meta": { "api_version": "v1" }
}
```

`chart_index` and `chart_count` (issue #587) let clients iterate when the definition declares multiple charts. For `datetime_series` charts, `labels` is replaced by `x` (epoch-seconds array) and `"x_axis": "datetime"` is added.

When the underlying response set exceeds the per-request row cap (10000), the response payload includes `"rows_capped": true` and `"rows_cap": 10000` so the client can surface a "showing first N rows" banner.

**Errors:**

| Status | Cause |
|---|---|
| `400` | `definition_id` query parameter not provided, or `index` is not a non-negative integer. |
| `404` | Definition not found, has no `spec.visualization` configured, or the requested `index` is out of range. |
| `500` | The visualization spec parses but cannot be applied (invalid processor / invalid chart type). |
| `503` | Response store or instruction store unavailable, or the response store's read degraded (transient Postgres outage — retryable, `retry_after_ms:5000` in the A4 body; audited as `reason=response_store_degraded`). |

**Audit:** every successful and failed render emits an `execution.visualization.fetch` audit event with `target_type=execution`, `target_id=<execution_id>`, `detail=<definition_id> index=<N>` on success, or `<definition_id> reason=<r>` on the failure path. When out-of-scope agents' rows were dropped, a SEPARATE `result=denied` row on the same action fires alongside the success row, `detail=<definition_id> scope_dropped=<N>` — not appended to the success detail.

**Example:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://yuzu.example.com/api/v1/executions/cmd-os_info-abc123/visualization?definition_id=crossplatform.service.inspect"
```

See `docs/yaml-dsl-spec.md` § `spec.visualization` for the full configuration schema.

---

### Live-Query Bundles

Fan **one** instruction out into several plugin actions on **one** device and collate the results — server-side async fan-out (ADR-0011). Use this instead of issuing N separate `execute_instruction` / `POST /api/instructions/{id}/execute` calls when you need to refresh a single device (e.g. a ServiceNow CI sync): N round-trips collapse to one dispatch plus one (or a few) polls.

The server expands the bundle into N ordinary plugin commands, each dispatched under one shared `bundle-…` correlation id. **The agent is unchanged — it never sees a "bundle", only ordinary commands.** Dispatch is **async**: it returns immediately, and a slow plugin step never withholds the others. The MCP tools `execute_bundle` / `get_bundle_result` are the exact parity of these two endpoints.

#### `POST /api/v1/bundles`

Dispatch a bundle. Returns the correlation id immediately; poll `GET /api/v1/bundles/{id}` for the collated result.

**Permission:** `Execution:Execute`, scoped per-device (management-group-confined operators are admitted for devices in their own group(s)). The caller's derived visibility is also enforced a second time at dispatch (#1788, defense-in-depth) — a target outside it is treated as unreached (`result=no_agents`, `state=dispatch_failed` on collate) rather than reaching the device.

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | The single target device — a bundle targets one device. |
| `steps` | array | Yes | 1–32 step objects, executed in request order. Duplicate `(plugin, action)` is allowed (e.g. two `registry/get_value` reads with different params) — each step gets its own command_id and collates back in order. |
| `steps[].plugin` | string | Yes | Plugin name, lowercased `[a-z0-9_]`, ≤ 64 chars. |
| `steps[].action` | string | Yes | Action name, same charset / length rule. |
| `steps[].params` | object | No | String→string parameter map (non-string values are coerced to strings). |

**Response (202 Accepted):**

```json
{
  "data": { "bundle_id": "bundle-1a2b3c4d5e6f7a8b", "agent_id": "agent-001", "expected": 2 },
  "meta": { "api_version": "v1" }
}
```

`bundle_id` is the `bundle-…` correlation id — pass it to `GET /api/v1/bundles/{id}` to collate. It is **not** an `ExecutionTracker` `execution_id`: a bundle is deliberately not a tracked execution, so feeding `bundle_id` into `GET /api/v1/events` / execution-status endpoints returns 404. `expected` is the number of steps dispatched.

**Errors:**

| Status | Cause |
|---|---|
| `400` | Invalid JSON, missing/empty `agent_id`, missing/empty `steps`, more than 32 steps, an unsafe plugin/action identifier, a param key/value over the size cap (key ≤ 256 B, value ≤ 64 KiB, ≤ 32 params/step), or a request body nesting deeper than 32 levels (`kMcpMaxJsonDepth`). |
| `500` | The authenticated session resolved to an empty principal (a bundle must be attributable to its dispatcher). |
| `503` | Command dispatch or response store unavailable. |

**Audit:** each step emits a `bundle.<plugin>.<action>` event with `target_type=Agent`, `target_id=<agent_id>`, `result=dispatched` (the step reached the agent) or `result=no_agents` (the step reached zero agents — it will read `dispatch_failed` on collate) — the device-access lens, so a bundle is exactly as auditable as the N executions it replaces. One `bundle.dispatch` (`target_type=Execution`) envelope records the dispatch itself (`result=success`, or `result=failure` with the error detail if dispatch threw).

#### `GET /api/v1/bundles/{id}`

Collate a dispatched bundle into a server-grouped result.

**Permission:** `Response:Read`

**Path parameters:**

| Param | Description |
|---|---|
| `id` | The `bundle-…` correlation id returned by `POST /api/v1/bundles`. |

**Response (200):**

```json
{
  "data": {
    "complete": true,
    "received": 2,
    "succeeded": 2,
    "expected": 2,
    "steps": [
      { "plugin": "os_info", "action": "uptime",  "state": "responded", "status": 1, "output": "up 3 days" },
      { "plugin": "os_info", "action": "os_name", "state": "responded", "status": 1, "output": "Windows 11" }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

Steps are returned in **request order** (not arrival order), so duplicate or same-plugin steps stay unambiguous. `state` is one of `pending` (no response yet), `responded` (a response landed), or `dispatch_failed` (the step reached no agent — terminal; it does not hold the bundle open). `status` is the response status enum (`1`=SUCCESS, `2`=FAILURE; `0` is an in-flight RUNNING frame — only meaningful when `state=responded`). `received` counts steps with any response; `succeeded` counts only steps that responded with status SUCCESS. Plugin `output` is transcoded to UTF-8 — any bytes that are not valid UTF-8 (e.g. binary or a non-UTF-8 codepage) are replaced with U+FFFD so the JSON always serializes.

> **`complete` is terminal, NOT success.** A bundle to an **offline device** completes (`complete=true`) with `received=0`, `succeeded=0`, and every step `dispatch_failed`. A caller deciding "did the refresh work" must check `succeeded == expected` (or inspect each `steps[].state`/`status`) — never `complete` alone. Polling `complete` to mark a record refreshed would silently treat an unreachable device as a success.

**Errors:**

| Status | Cause |
|---|---|
| `404` | Bundle not found, **or** the caller did not dispatch it and is not an admin. The two are deliberately indistinguishable (no enumeration oracle); the real reason is recorded in the audit log. |
| `503` | The bundle manifest WAS found and owned, but the response store could not be read (transient Postgres degrade) — distinct from a 404, and retryable: `retry_after_ms:5000` in the A4 body. Poll again after the hint rather than treating this as terminal. |

**Audit:** `bundle.collate` (`target_type=Execution`, `target_id=<id>`), `result=success` (carrying `complete=0|1`), `result=denied` (not found / not owned), or `result=failure` (response store degraded, the 503 case above).

**Notes:**

- A bundle is **not** a tracked execution — it does not appear in the live executions drawer, and `notify_exec_tracker` skips its `bundle-…` correlation id. The collate poll is the sole completion authority.
- v1 bundle state (the step map) is **per-surface and in-memory**: a bundle dispatched over REST is collated over REST (MCP→MCP). A server restart mid-bundle loses the in-flight step map (the responses survive in the response store, but attribution does not), and the caller must re-dispatch. A durable Postgres manifest for HA + cross-surface collation is a committed follow-up (ADR-0011).

**Error handling and retry (for integrators):**

- **Poll cadence:** poll `GET /api/v1/bundles/{id}` with a short backoff (e.g. 1s, 2s, 4s) until `complete` is `true`, then read `succeeded`/`steps`.
- **Manifest TTL ≈ 10 minutes, sliding.** Each successful collate refreshes the window, so a bundle you are actively polling never expires; only an abandoned bundle (no poll for the full window) is swept.
- **A 404 on a poll that previously returned 200** means the manifest expired (you stopped polling past the TTL) **or** the server restarted (in-memory state lost). The correct recovery is to **re-dispatch the bundle** — the already-executed step responses are harmless (idempotent reads). Do not treat the 404 as a hard failure.

**Example:**

```bash
# dispatch
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-001","steps":[{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}]}' \
  "https://yuzu.example.com/api/v1/bundles"
# -> {"data":{"bundle_id":"bundle-…","agent_id":"agent-001","expected":2}, ...}

# collate (poll until data.complete == true)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://yuzu.example.com/api/v1/bundles/bundle-1a2b3c4d5e6f7a8b"
```

---

### Device Tokens

Device tokens are scoped authentication tokens that restrict execution to a specific device and instruction definition. Used for unattended agent operations. `DeviceTokenStore` is currently not
constructed by the server (capability 18.8 is deliberately shelved — same family as [License
Management](#license-management), `docs/adr/0052-device-token-store-postgres-migration.md`
Context), so these routes do not register today; documented for when a future change re-wires
them.

**`principal_id` vs `device_id`.** These are two different identities. `principal_id` is the
**issuing operator's** username — set from the authenticated session at creation time, never
supplied in the request body. `device_id` is the **agent** the token is bound to (set from the
request body's `device_id` field) — this is the identity a presenting agent is validated against
when the token is used, and the identity the re-registration revoke below acts on.

**Re-registration revoke (#823/#3401).** When the agent named by a token's `device_id` re-registers
with the server, every still-valid token bound to that `device_id` is revoked before the new
session is installed — closing the window where a briefly-impersonated agent (an mTLS-disabled
registration) could otherwise replay a token issued to the legitimate agent. This is independent
of who issued the token (`principal_id`). If the revoke sweep itself fails (a database fault), the
registration is refused rather than proceeding with stale tokens left live; the agent's normal
reconnect/retry behavior applies.

#### `GET /api/v1/device-tokens`

List all device tokens.

**Permission:** `DeviceToken:Read`

**Response:**

```json
{
  "data": [
    {
      "token_id": "a1b2c3d4e5f6",
      "name": "Kiosk daily update",
      "principal_id": "admin",
      "device_id": "kiosk-001",
      "definition_id": "windows-update-install",
      "created_at": 1711900800,
      "expires_at": 1714492800,
      "last_used_at": 1711987200,
      "revoked": false
    }
  ],
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| A genuine database read failure | `503` |

#### `POST /api/v1/device-tokens`

Create a device-scoped token. The raw token value is returned exactly once at creation time.

**Permission:** `DeviceToken:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Human-readable token name |
| `device_id` | string | No | Restrict token to a specific agent |
| `definition_id` | string | No | Restrict token to a specific instruction definition |
| `expires_at` | integer | No | Unix timestamp for token expiration |

**Response (201):**

```json
{
  "data": { "raw_token": "ydt_a1b2c3d4e5f6..." },
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| Malformed JSON body | `400` — `invalid JSON` |
| `name`/`device_id`/`definition_id` exceeds 256 chars | `400` — `invalid_input_length: ...` |
| CSPRNG entropy exhaustion | `503` + `Retry-After: 5` — `CSPRNG unavailable: ...` |
| A genuine database write or token-hashing failure | `503` + `Retry-After: 5` — `service unavailable` |

#### `DELETE /api/v1/device-tokens/{id}`

Revoke a device token.

**Permission:** `DeviceToken:Delete`

**Response:**

```json
{
  "data": { "revoked": true },
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| No token with this id | `404` — `token not found` |
| A genuine database write failure | `503` — `service unavailable` |

---

### Pre-flight & Deploy

REST twins of the `/auto` pre-flight ASSESS stage's saved-runs rail and the deploy ACT stage's
go/warn preview — see [Pre-flight readiness checks](preflight.md) for the full workflow these
routes are read-only slices of. Both are **owner-scoped** (your own runs/deployments only) and
confirmed inert — neither creates a run or a deployment. MCP twins: `list_preflight_runs` /
`get_deployment_preview` (`docs/mcp-server.md`).

#### `GET /api/v1/preflight/runs`

Your own saved pre-flight runs, newest first. This is the saved-runs-rail HALF of
`GET /fragments/auto`'s payload only — the config-options half (available management groups for
the scope dropdown) is not duplicated here; see [Management Groups](#management-groups) for that
identical catalogue (`groups_fn_` sources from the exact same `list_groups()` call both routes
share).

**Permission:** `Infrastructure:Read`

**Parameters:**

| Name | In | Required | Description |
|---|---|---|---|
| `limit` | query | No | Max runs to return (default 12, matching the dashboard rail; capped at 100; a 0 or negative value is silently clamped to 1, not rejected) |

**Response:**

```json
{
  "data": [
    {
      "run_id": "a1b2c3d4e5f6a7b8",
      "name": "AcmeVPN 4.2.0 rollout",
      "scope_label": "Sales laptops",
      "status": "complete",
      "created_at_ms": 1758000000000,
      "deadline_at_ms": 1758001800000,
      "completed_at_ms": 1758001200000,
      "total": 40,
      "go": 35,
      "warn": 2,
      "nogo": 1,
      "incomplete": 2
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 12 },
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| `limit` cannot be parsed as an integer (e.g. non-numeric) | `400` — a parseable but out-of-range value (0, negative, or > 100) is clamped, not rejected |
| A service-scoped API token — this owner-scoped read cannot be confined to the token's service | `403`, audited under `preflight.run.view` (a distinct verb from `preflight.run`, the run-**creation** verb — see the audit note below) |
| Pre-flight run store never configured on this server (permanent) | `503` (A4 envelope, no `retry_after_ms` — this is a deployment-config condition, not one a client can retry past) |
| Pre-flight run store degraded (transient) | `503` (A4 envelope, `retry_after_ms: 2000` — matches the MCP twin's own `kMcpStoreFaultShortRetryMs`) |

**Audit:** unaudited on a successful read (run scope/lifecycle metadata, not per-agent behavioural
PII — matches the fragment's own posture); a service-scoped-token denial is audited under
`preflight.run.view`, deliberately **not** the reused `preflight.run` verb — that verb is the run
**creation** audit (`POST /fragments/auto/run`'s success event), and reusing it here would make a
denied list read indistinguishable from a run being created in the audit log.

---

#### `GET /api/v1/deployments/preview`

The deploy-config go/warn preview for one pre-flight run's cleared cohort — how many devices are
ready to receive an installer, before you configure and start a deployment.

**Permission:** `SoftwareDeployment:Read`

**Parameters:**

| Name | In | Required | Description |
|---|---|---|---|
| `run` | query | Yes | The source pre-flight run id |

**Response:**

```json
{
  "data": { "run_id": "a1b2c3d4e5f6a7b8", "name": "AcmeVPN 4.2.0 rollout", "go": 35, "warn": 2 },
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| Missing `run` parameter | `400` |
| A service-scoped API token — this owner-scoped read cannot be confined to the token's service | `403`, audited under `deployment.config.view` |
| No such run, or it belongs to another operator | `404` — indistinguishable by design (closes the existence oracle) |
| Pre-flight run store never configured on this server (permanent) | `503` (A4 envelope, no `retry_after_ms` — this is a deployment-config condition, not one a client can retry past) |
| Pre-flight run store degraded (transient) | `503` (A4 envelope, `retry_after_ms: 2000` — matches the MCP twin's own `kMcpStoreFaultShortRetryMs`) |

**Audit:** unaudited on a successful read (same rationale as the runs list above); a
service-scoped-token denial is audited under `deployment.config.view` — already distinct from
`deployment.create` (this route never creates a deployment).

---

### Software Deployment

Manage software packages and their deployments to agents. `SoftwareDeploymentStore` is
currently not constructed by the server (capability 7.6 is deliberately shelved — same family
as [License Management](#license-management), `docs/adr/0051-software-deployment-store-postgres-migration.md`
Context), so these routes do not register today; documented for when a future change re-wires
them.

#### `GET /api/v1/software-packages`

List all registered software packages.

**Permission:** `SoftwareDeployment:Read`

**Response:**

```json
{
  "data": [
    {
      "id": "pkg-001",
      "name": "Firefox ESR",
      "version": "115.8.0",
      "platform": "windows",
      "installer_type": "msi",
      "content_hash": "sha256:abcdef...",
      "size_bytes": 58720256,
      "created_at": 1711900800,
      "created_by": "admin"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| A genuine database read failure | `503` |

#### `POST /api/v1/software-packages`

Register a new software package.

**Permission:** `SoftwareDeployment:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Package name |
| `version` | string | Yes | Package version |
| `platform` | string | No | Target platform (default `"windows"`) |
| `installer_type` | string | No | Installer type (default `"msi"`) |
| `content_hash` | string | No | SHA-256 hash of the installer |
| `content_url` | string | No | Download URL for the installer binary |
| `silent_args` | string | No | Silent install arguments (e.g. `/qn /norestart`). Same validation rules as `verify_command` — max 512 chars, rejects shell metacharacters and control characters. |
| `verify_command` | string | No | Post-install verification command. Max 512 chars. Rejects shell metacharacters (`;` `&` `|` `` ` `` `$` `<` `>` `(` `)`), C0 control characters (newline, tab, etc.), and DEL at REST input time to prevent fleet-RCE via shell injection (#771). Examples that pass: `msiexec /x {GUID} /qn`, `reg query HKLM\Software\App`, `dpkg -s firefox`. |
| `rollback_command` | string | No | Rollback command on failure. Same validation rules as `verify_command`. |
| `size_bytes` | integer | No | Installer file size in bytes |

**Response (201):**

```json
{
  "data": { "id": "pkg-001" },
  "meta": { "api_version": "v1" }
}
```

May carry `Sec-Audit-Failed: true` — see [`Sec-Audit-Failed`](#sec-audit-failed-and-the-behavioural-pii-audit-posture) above.

**Errors:**

| Condition | Response |
|---|---|
| Malformed JSON body, a required field wrong-typed or empty, or `verify_command`/`rollback_command`/`silent_args` fails the shell-metacharacter/length check | `400` |
| A genuine database write failure | `503` |

#### `GET /api/v1/software-deployments`

List software deployments, optionally filtered by status.

**Permission:** `SoftwareDeployment:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `status` | string | Filter by status: `staged`, `deploying`, `verifying`, `completed`, `cancelled`, `rolled_back`, `failed` |

**Response:**

```json
{
  "data": [
    {
      "id": "dep-001",
      "package_id": "pkg-001",
      "status": "completed",
      "created_by": "admin",
      "created_at": 1711900800,
      "started_at": 1711901400,
      "completed_at": 1711902000,
      "agents_targeted": 50,
      "agents_success": 48,
      "agents_failure": 2
    }
  ],
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| A genuine database read failure | `503` |

#### `POST /api/v1/software-deployments`

Create a new software deployment. Starts in status `staged`.

**Permission:** `SoftwareDeployment:Execute`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `package_id` | string | Yes | ID of the registered software package |
| `scope_expression` | string | No | Scope expression selecting target agents |

**Response (201):**

```json
{
  "data": { "id": "dep-001" },
  "meta": { "api_version": "v1" }
}
```

May carry `Sec-Audit-Failed: true` — see [`Sec-Audit-Failed`](#sec-audit-failed-and-the-behavioural-pii-audit-posture) above.

**Errors:**

| Condition | Response |
|---|---|
| Malformed JSON body, or `package_id` empty | `400` |
| `package_id` does not reference a registered package | `400` |
| A genuine database write failure | `503` |

#### `POST /api/v1/software-deployments/{id}/start`

Start a `staged` deployment (transitions to `deploying`).

**Permission:** `SoftwareDeployment:Execute`

**Response:** `{"data": {"started": true}, "meta": {"api_version": "v1"}}` — may carry `Sec-Audit-Failed: true` (see above).

**Errors:**

| Condition | Response |
|---|---|
| No deployment with this id, or it is not `staged` | `400` |
| A genuine database write failure | `503` |

#### `POST /api/v1/software-deployments/{id}/rollback`

Roll back a `deploying`, `verifying`, or `completed` deployment (transitions to
`rolled_back`).

**Permission:** `SoftwareDeployment:Execute`

**Response:** `{"data": {"rolled_back": true}, "meta": {"api_version": "v1"}}` — may carry `Sec-Audit-Failed: true` (see above).

**Errors:**

| Condition | Response |
|---|---|
| No deployment with this id, or it is not `deploying`/`verifying`/`completed` | `400` |
| A genuine database write failure | `503` |

#### `POST /api/v1/software-deployments/{id}/cancel`

Cancel a `staged` or `deploying` deployment (transitions to `cancelled`).

**Permission:** `SoftwareDeployment:Execute`

**Response:** `{"data": {"cancelled": true}, "meta": {"api_version": "v1"}}` — may carry `Sec-Audit-Failed: true` (see above).

**Errors:**

| Condition | Response |
|---|---|
| No deployment with this id, or it is not `staged`/`deploying` | `400` |
| A genuine database write failure | `503` |

---

### License Management

Manage Yuzu license entries, seat counts, and alerts. `LicenseStore` is currently not
constructed by the server (licensing is deliberately shelved — `docs/adr/0048-license-store-postgres-migration.md`
Context), so these routes do not register today; documented for when a future change re-wires
them.

#### `GET /api/v1/license`

Get the active license details, or `{"status": "none"}` if no license is active.

**Permission:** `License:Read`

**Response:**

```json
{
  "data": {
    "id": "lic-001",
    "organization": "Acme Corp",
    "seat_count": 500,
    "seats_used": 142,
    "issued_at": 1704067200,
    "expires_at": 1735689600,
    "edition": "enterprise",
    "status": "active",
    "days_remaining": 275
  },
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| A genuine database read failure | `503` |

#### `POST /api/v1/license`

Activate a license.

**Permission:** `License:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `organization` | string | Yes | Organization name |
| `seat_count` | integer | Yes | Licensed seat count |
| `edition` | string | No | License edition (default `"community"`) |
| `expires_at` | integer | No | Unix timestamp for license expiration |
| `features_json` | string | No | JSON array of enabled feature flags |
| `license_key` | string | Yes | License activation key |

**Response (201):**

```json
{
  "data": { "id": "lic-001" },
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| Malformed JSON body | `400` — `invalid JSON` |
| `license_key` or `organization` empty | `400` |
| `license_key` already activated on another license | `400` — `license key already activated` |
| A genuine database write failure | `503` |

#### `DELETE /api/v1/license/{id}`

Remove a license entry.

**Permission:** `License:Write`

**Response:** `{"data": {"removed": true}, "meta": {"api_version": "v1"}}`

**Errors:**

| Condition | Response |
|---|---|
| No license with this id | `404` |
| A genuine database write failure | `503` |

#### `GET /api/v1/license/alerts`

List license alerts (expiration warnings, seat limit approaching, etc.).

**Permission:** `License:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `unacknowledged` | flag | If present, return only unacknowledged alerts |

**Response:**

```json
{
  "data": [
    {
      "id": "alert-001",
      "license_id": "lic-001",
      "alert_type": "expiration_warning",
      "message": "License expires in 30 days",
      "triggered_at": 1711900800,
      "acknowledged": false
    }
  ],
  "meta": { "api_version": "v1" }
}
```

**Errors:**

| Condition | Response |
|---|---|
| A genuine database read failure | `503` |

---

### Topology

#### `GET /api/v1/topology`

Get infrastructure topology data. For full topology rendering, use the HTMX fragment endpoint `/frag/topology-data`. The REST endpoint provides a pointer for external callers.

**Permission:** `Infrastructure:Read`

---

### Fleet Visualization (3D)

The fleet-visualization endpoints expose a single aggregate `fleet_topology.v1` document that the `/viz/fleet` 3D renderer consumes. The endpoint dispatches `tar.fleet_snapshot` to every connected agent on cache miss, aggregates per-agent snapshots into machine cubes + interior process nodes + connection edges, and applies a 60 s LRU-of-2 cache (keyed on `include_vuln`).

#### `GET /viz/fleet`

Browser-facing page that renders the 3D fleet topology. The page itself is auth-gated only; per-request RBAC enforcement happens when the page's JS hits `GET /api/v1/viz/fleet/topology` (see below).

**Permission:** Session auth only (`require_auth`); redirects to `/login` on no session. The `--viz-disable` / `YUZU_VIZ_DISABLE` kill switch disables only the API endpoint, not the page shell — the page continues to load and the `503` from the disabled API surfaces in the browser console.

**Browser requirements:** importmap support is required (Chrome 89+, Firefox 108+, Safari 16.4+, Edge 89+). On unsupported browsers the page detects via `HTMLScriptElement.supports('importmap')` and surfaces a visible error overlay instead of a blank canvas.

**Cache posture:** the response sets `Cache-Control: no-cache, no-store, must-revalidate`. Vendored static assets (Three.js, OrbitControls, yuzu-viz.js) cache for 24 hours; the page itself revalidates on every navigation so a server upgrade cannot leave operators with a stale page that references the new assets.

**Deployment constraint:** the page hard-codes static asset paths (`/static/three.module.min.js`, `/static/three-orbit-controls.js`, `/static/yuzu-viz.js`) and the API path (`/api/v1/viz/fleet/topology`). Reverse-proxy deployments under a sub-path (e.g. `location /yuzu/`) are not currently supported — the absolute paths would 404 against the rewritten origin. Mount Yuzu at the root path of its host or fronting domain.

**Controls:**
- Drag — rotate camera around scene origin (OrbitControls)
- Mouse wheel — dolly in/out (clamped to `[4, 400]` units)
- `W`/`A`/`S`/`D` — pan the view in camera screen space (window-level listener; suppressed when a text-editable target has focus, so typing in a future overlay-panel input does not eat keystrokes)
- **Hover a machine cube body** — surfaces a fixed-position tooltip with the cube's hostname, OS, process count, and connection count. The cube tooltip is shown only when no interior process dot is intersected (process dots are raycasted first; see the process tooltip below). The wireframe outline overlay is excluded from hit-testing. Tooltip follows the cursor with a small offset to avoid flicker.
- **Hover a process dot (interior of a cube)** — surfaces a process tooltip with the process's pid, name, user account, and category. Process dots are raycasted *before* cube meshes so an operator can hover a dot through the translucent cube face and still see process details (otherwise the cube's outer face would always win by ray distance and dots would be unreachable). Agent-controlled fields (name, user, category) are HTML-escaped before render and capped at 256 characters before escaping to bound CPU cost on pathological 1MB cmdline-as-comm payloads.

**Renderer behaviour (PR 6):**

The page renders one translucent cube per fleet machine on a deterministic grid. Per-OS palette: Linux `#f0c674`, macOS/Darwin `#a0a0a0`, Windows `#5294e2`, default `#666666`. Live agents render at opacity `0.18`; stale agents (no response within the 5 s `tar.fleet_snapshot` deadline) render at opacity `0.08` so they remain visible without competing for attention. Hostname labels appear above each cube as `Sprite` text and always face the camera; labels longer than 24 characters truncate with an ellipsis (the full hostname is visible in the hover tooltip). Layout is seeded by an FNV-1a 32-bit hash of `agent_id` so the same fleet renders identically across reloads even when the server returns rows in a different order.

**Renderer behaviour (PR 7):**

Each machine cube contains interior `SphereGeometry` dots, one per process reported in the `processes` array of the topology payload. Dots are coloured by process category using a fixed six-colour palette: system `#6e7681`, browser `#58a6ff`, database `#d29922`, web `#56d364`, runtime `#bc8cff`, other `#8b949e`. Category values in the JSON payload are lowercase strings matching `category_to_string()` in the server's process classifier (`server/core/src/process_category.hpp`); the renderer normalises with `String(category).trim().toLowerCase()` and uses `Object.prototype.hasOwnProperty.call` for the palette lookup so unknown / mixed-case / whitespace-padded values fall through to `other` and prototype keys (`constructor`, `__proto__`) cannot poison the colour pipeline.

Dot positions are deterministic across reloads — `hash(pid|ppid)`-mod-bucket layout inside 78% of the cube's interior volume, with per-process `hash('j|pid')` jitter to break visual stripes. Per-machine processes are attached as a named child group (`yuzu-processes`) of each cube so they orbit and pan with the cube under OrbitControls without synchronisation overhead. To bound the worst-case render cost on heavily-threaded hosts (e.g. JVM thread pools), the renderer soft-caps at **1000 dots per cube**; the cube tooltip's `processes` count still reflects the true total reported by the agent.

Hover-then-tooltip is rAF-throttled — `mousemove` fires up to ~120 Hz on macOS trackpads but the bidirectional raycast (process dots + cube meshes) only runs once per `requestAnimationFrame` tick (~60 Hz) so the dominant CPU cost stays bounded even at large fleets.

To suppress process-level visibility for specific agents (privacy-sensitive hosts, regulated workloads, etc.), set `process_enabled=false` on those agents via `tar.configure` — see [`docs/user-manual/agent-plugins.md`](agent-plugins.md) §TAR for the per-source enable/disable surface. The `tar.fleet_snapshot` action will skip the process collector on those agents and the corresponding cubes will render with no interior dots (cube body and hover tooltip remain functional).

**Browser error handling.** When the JS renderer's fetch to `/api/v1/viz/fleet/topology` fails, the renderer surfaces a visible overlay (`#viz-error.shown`) on the canvas rather than leaving the scene blank. Any previously-rendered cubes are removed before the overlay is shown so the operator does not see "live data" cubes alongside a denial message.

| API response | Overlay message |
|---|---|
| `401` | "Session expired. Please reload the page." |
| `403` | "Access denied. Your role no longer permits viewing the fleet topology." |
| `413` | "Fleet exceeds the configured `machines_max` cap. Ask an administrator to raise `--viz-machines-max` or scope the request via a management group." |
| `503` | "Fleet visualization is currently disabled by an administrator." |
| Other 4xx/5xx | "Failed to fetch fleet topology (HTTP <status>). Try reloading." |
| Network failure | "Cannot reach server: <message>" |
| Truncated JSON / malformed body | "Malformed JSON from server (truncated response or proxy issue): <message>" |
| Schema mismatch | "Unexpected topology schema: <schema>. Reload the page (Ctrl+Shift+R) to pick up the new dashboard." |
| Empty `machines` field (server bug) | "Server returned no machines field. This is a server-side bug; check the server log." |

These overlays are in addition to the standard browser console entry. Previous releases (PR 5 and earlier) left the scene blank on every error condition.

#### `GET /api/v1/viz/fleet/topology`

Returns the full topology as JSON.

**Permission:** `Response:Read`.

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `include_vuln` | bool (`0`/`1`) | `0` | When `1`, the per-process `worst_severity` and `cve_count` fields are populated from NVD CPE matching. (PR 2 hardening note: this overlay is wired but inert today because the agent payload doesn't carry installed versions; PR 10 of the ladder activates it.) Selects a separate cache slot from the default. |
| `fresh` | bool (`0`/`1`) | `0` | When `1`, the cache slot is invalidated before the get. A separate audit row (`viz.fleet_topology.invalidate`) is emitted. Use sparingly — concurrent `?fresh=1` storms force every dispatch to wait on the single-flight refill. |
| `machines_max` | integer in `[1, 100000]` | `5000` | Soft cap on the number of fleet machines returned. If the materialised snapshot has more than this, the route returns `413` rather than truncating (truncation would mislead operators about which subset they're seeing). |

**Responses**

| Status | When | Body |
|---|---|---|
| `200` | Success | `fleet_topology.v1` JSON envelope (see schema below) |
| `400` | `machines_max` non-numeric, out of `[1, 100000]`, or overflows `int` | `{"error":{"code":400,"message":"..."}, "meta":{"api_version":"v1"}}` |
| `403` | RBAC denied | Standard auth error envelope |
| `413` | Snapshot exceeds `machines_max` | `{"error":{"code":413,"message":"fleet topology exceeds machines_max..."}, "meta":{"api_version":"v1"}}` |
| `503` | Kill switch on (`--viz-disable`) or store unavailable | `{"error":{"code":503,"message":"..."}, "meta":{"api_version":"v1"}}` |

**Schema (`fleet_topology.v1`)**

```json
{
  "schema": "fleet_topology.v1",
  "schema_minor": 3,
  "generated_at": 1715299200,
  "include_vuln": false,
  "machines": [
    {
      "agent_id": "...",
      "hostname": "host-1",
      "os": "linux",
      "local_ips": ["10.0.0.1"],
      "ts": 1715299200,
      "stale": false,
      "processes": [
        {"pid": 1234, "ppid": 1, "name": "postgres", "user": "postgres", "category": "database"},
        {"pid": 5678, "ppid": 1, "name": "psql",     "user": "alice",    "category": "database"}
      ],
      "listeners": [
        {"proto": "tcp", "port": 5432, "pid": 1234, "process_name": "postgres", "local_addr": "0.0.0.0"}
      ],
      "connections": [
        {"proto": "tcp", "src_pid": 1234, "src_addr": "10.0.0.1", "src_port": 5432,
         "dst_addr": "10.0.0.2", "dst_port": 54321, "scope": "internal_fleet",
         "dst_agent_id": "...", "state": "ESTABLISHED"},
        {"proto": "tcp", "src_pid": 1234, "src_addr": "127.0.0.1", "src_port": 5432,
         "dst_addr": "127.0.0.1", "dst_port": 53210, "scope": "local",
         "dst_pid": 5678, "state": "ESTABLISHED"}
      ]
    }
  ]
}
```

`schema_minor` is bumped (not `schema`) on additive evolution; renderers MUST ignore unknown keys.

**`schema_minor` history:**

| Version | Change |
|---|---|
| 1 | Initial shape (PR 2–7) |
| 2 | PR 8 — `dst_pid` (uint32) added to `ConnectionEdge`. Present only on `scope: local` edges with a resolved peer process on the same machine; omitted (not zero) on non-local edges. Unmatched `local` edges (no reciprocal half visible in the same snapshot) are dropped server-side before serialisation, so a `local` edge in the response always carries a non-zero `dst_pid`. Strict-validating consumers pinned to minor version 1 should relax their validator to `minimum: 1` rather than exact-match. |
| 3 | PR 9 — `listeners[]` array added to each `MachineNode`. Each entry is a `ListenerSocket` (`proto`, `port`, optional `pid`, optional `process_name`). LISTEN-state rows continue to appear in `connections[]` during the deprecation window so consumers filtering `connections` by `state: LISTEN` are not broken; a future release will remove them from `connections[]` with a `Breaking` CHANGELOG entry. Strict consumers should migrate to `listeners[]` now. Ingestion path also flipped: agents push `tar.fleet_snapshot` JSON via `HeartbeatRequest.fleet_snapshot_json` every 30 s (PR 10), so cache-miss latency drops from ~800 ms (full agent dispatch) to ~2 ms (in-process map walk). The dispatch path remains as a cold-start fallback. |
| 4 | PR 12 — `ListenerSocket` grows an optional `local_addr` field (the kernel-reported bind address: `0.0.0.0`, `::`, a NIC IP, `127.0.0.1`, etc., bounded server-side at 64 bytes per field). Omitted from the wire envelope when the agent did not populate it (older snapshots). The renderer reads this field and drops loopback-only listeners (`127.0.0.0/8`, `::1`, including bracketed and v4-mapped-in-v6 forms `[::ffff:127.x]`) from the cube-surface socket ring — those sockets are by definition not reachable from any other instance. `0.0.0.0` and `::` survive the filter; specific NIC IPs survive. Strict consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. |

**Audit emissions**

Every request produces a `viz.fleet_topology` row (target_type `FleetTopology`, target_id empty). `?fresh=1` additionally produces a `viz.fleet_topology.invalidate` row immediately before the get. See [Audit Log](audit-log.md) for the full vocabulary.

**Metrics**

- `yuzu_viz_topology_request_seconds` (histogram) — end-to-end request latency on the success path (auth + RBAC + store + serialisation + response).
- `yuzu_viz_topology_fetch_duration_seconds` (histogram) — duration of the inner agent-dispatch path (`tar.fleet_snapshot` fan-out + response aggregation), measured only on cache-miss refills. Use to distinguish slow agent dispatch from slow auth / serialisation. Observed even on fetcher exception so a hung fetcher produces a visible upper-bound observation. (PR 6 / OBS-2.)
- `yuzu_viz_cache_hit_total` / `yuzu_viz_cache_miss_total` (counters).
- `yuzu_viz_oversize_response_total` (counter) — 413 cap-check fires.
- `yuzu_viz_agent_dispatch_timeout_total` (counter) — agents that didn't respond within the 5 s fetcher deadline.
- `yuzu_viz_refill_oversize_drops_total` (gauge) — store-level 256 MiB cap exceeded; refill not cached.
- `yuzu_viz_refill_wait_timeouts_total` (gauge) — single-flight waiters that timed out on the refill.
- `yuzu_viz_refill_waiters_total` (gauge) — single-flight piggyback depth.
- `yuzu_viz_topology_pushed_total{via=direct|gateway}` (counter, PR 10) — agent-pushed `fleet_snapshot.v1` payloads accepted via heartbeat. `via=direct` counts direct-to-server agents; `via=gateway` counts gateway-routed agents. A zero value across both labels after agents have been running for >30 s indicates agents have not upgraded to push-enabled binaries; the server falls back to the dispatch path automatically.
- `yuzu_viz_topology_push_parse_errors_total{via=direct|gateway}` (counter, PR 10) — agent-pushed payloads rejected by the shared parser (oversized > 2 MiB, `processes[]`/`connections[]` exceeding the 4096-row cap, or malformed JSON). A non-zero value indicates agent/server version skew, a corrupt heartbeat, or a compromised agent attempting to inject malformed data. Each rejection also emits a `topology.push.rejected` audit event. The parser also length-clamps every agent-controlled string field (`hostname`, process `name`/`cmdline`/`user`, connection meta strings) — truncation is logged but not counted here.
- `yuzu_viz_topology_push_rejected_total` (gauge) — pushes rejected by the IP-spoof guard because a claimed `local_ip` is owned by a *live* agent (an agent that has pushed within the 5-minute reclaim window). Non-zero signals a spoofing campaign or a NAT/DHCP misconfiguration.
- `yuzu_viz_pushed_cap_evictions_total` (gauge) — `pushed_` map entries evicted because the map hit the 100 000-agent hard cap. The victim is the least-recently-seen agent by *server* receipt time (not the agent-controlled `ts`); each eviction emits a `topology.push.evicted_for_cap` audit event.
- `yuzu_viz_pushed_map_size` (gauge) — current `pushed_` map occupancy; the memory-pressure signal to alert on before evictions begin.

**`fleet_snapshot.v1` (agent-emitted payload).** The `fleet_topology.v1` document above is the server-aggregated shape; the per-agent payload the agent pushes (via `HeartbeatRequest.fleet_snapshot_json`) or returns from a dispatched `tar.fleet_snapshot` is `fleet_snapshot.v1`. Its `schema_minor` is at **2** — the `1 → 2` bump added an optional `connections[].last_seen_seconds_ago` field, emitted only when non-zero, alongside the operator-tunable TAR plugin config key `fleet_snapshot_window_seconds` (default `3600`): connections seen within that window are merged into the snapshot even if not ESTABLISHED at the exact `/proc` sample instant. `fleet_snapshot_window_seconds` is a TAR plugin config key set via `tar.configure`, not a server CLI flag.

**Example**

```bash
curl -H 'Authorization: Bearer <token>' \
     'http://localhost:8080/api/v1/viz/fleet/topology?include_vuln=0&machines_max=2000'
```

#### `GET /fragments/viz/fleet/topology`

Identical data, wrapped in `<script type="application/json" id="viz-data">...</script>` for HTMX-driven swap-and-parse rendering. The `<` characters in JSON strings are escaped (`<\/`) before wrapping so an agent-controlled hostname or `cmdline` containing `</script>` cannot break out of the script element.

**Permission, query params, status codes:** identical to the JSON route above.

**Content-Type:** `text/html; charset=utf-8` (the body is HTML wrapping JSON, not JSON proper).

#### `GET /api/v1/viz/host/<agent_id>/topology`

Returns a single host's topology — one `MachineNode` sliced out of the
current fleet snapshot — for the per-host IPC-graph drill-down page. The
`agent_id` is taken from the path.

**Permission:** `Response:Read`.

**Responses**

| Status | When | Body |
|---|---|---|
| `200` | Success | `host_topology.v1` JSON envelope (see schema below) |
| `404` | No machine with that `agent_id` in the current snapshot | `{"error":{"code":404,"message":"host not found"}, ...}` |
| `403` | RBAC denied | Standard auth error envelope |
| `500` | Topology fetch threw or returned null | `{"error":{"code":500,"message":"..."}, ...}` |
| `503` | Kill switch on (`--viz-disable`) or store unavailable | `{"error":{"code":503,"message":"..."}, ...}` |

**Schema (`host_topology.v1`)**

```json
{
  "schema": "host_topology.v1",
  "schema_minor": 1,
  "generated_at": 1715299200,
  "stale": false,
  "machine": { "agent_id": "...", "hostname": "host-1", "...": "MachineNode — same shape as a fleet_topology.v1 machines[] entry" }
}
```

The `stale` flag is promoted from `machine.stale` to the envelope so a
renderer can decide whether to show a stale banner without reaching into
`machine`. The embedded `machine` object is byte-for-byte the same
`MachineNode` shape served by `/api/v1/viz/fleet/topology`.

**Audit emissions:** every request produces a `viz.host_topology` row
(target_type `HostTopology`, target_id = `agent_id`), with result
`success` / `denied` / `failure` and a detail of `kill_switch`,
`store_null`, `fetch_threw`, `snap_null`, `not_found`, or `fragment=1`.

**Example**

```bash
curl -H 'Authorization: Bearer <token>' \
     'http://localhost:8080/api/v1/viz/host/cedar-01/topology'
```

#### `GET /fragments/viz/host/<agent_id>/topology`

Identical data, wrapped in `<script type="application/json" id="viz-data">...</script>`
for HTMX rendering — same escaping and `Content-Type` posture as
`/fragments/viz/fleet/topology`. Permission and status codes identical to
the JSON route above.

#### `GET /viz/host/<agent_id>`

Browser-facing per-host drill-down page (the 2D Cytoscape IPC graph above
the TAR process tree), opened by double-clicking a cube in `/viz/fleet`.
Auth-gated only (`require_auth`); redirects to `/login` on no session.
The `agent_id` path segment is allow-listed to `[A-Za-z0-9._-]` — any
other character returns `400` — before it is templated into the page
shell. Per-request RBAC is enforced when the page's JS fetches
`/api/v1/viz/host/<agent_id>/topology`.

---

### Fleet Statistics

#### `GET /api/v1/statistics`

Get an aggregated view of fleet execution statistics.

**Permission:** `Infrastructure:Read`

**Response:**

```json
{
  "data": {
    "executions": {
      "total": 15420,
      "today": 230,
      "success_rate": 0.973,
      "avg_duration_seconds": 4.2
    },
    "active_agents": 142
  },
  "meta": { "api_version": "v1" }
}
```

---

### File Retrieval

**`POST /api/v1/file-retrieval` has been REMOVED (PR1.5c/1.6c).** The legacy
handler trusted a body-supplied `agent_id` as an unauthenticated metadata-only
"upload" that stored nothing and had no relationship to actual bytes sent. It
is replaced by the authenticated one-time upload-grant + chunked-receive
protocol below (`docs/adr/3004-artifact-blob-storage.md`): the operator
mint/list/revoke routes at `/api/v1/upload-grants*`, and the agent-facing
session/chunk/status/commit/cancel routes at `/api/v1/uploads*`.

#### `POST /api/v1/upload-grants`

Mint a one-time upload grant for an agent. Operator-facing.

**Permission:** `UploadGrant:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | The agent authorised to redeem this grant |
| `declared_max_size` | integer | Yes | Upper bound on the upload size in bytes — a CAP, not an equality requirement; the actual upload may be smaller |
| `source_path` | string | No | Informational only — never used to derive the destination key |
| `expected_sha256` | string | No | Optional expected content hash, 64 lowercase hex characters |
| `retention_class` | string | No | `standard` (default), `extended`, or `transient` |
| `ttl_secs` | integer | No | Grant expiry override; server default applies when omitted (<= 15 min) |

**Response (`201`):**

```json
{
  "grant_id": "a1b2c3...",
  "grant_secret": "d4e5f6...",
  "expires_at": 1735689600,
  "destination_key": "standard/a1b2c3..."
}
```

`grant_secret` is returned **exactly once** — the store persists only its
SHA-256 digest.

#### `GET /api/v1/upload-grants`

List upload grants. **Permission:** `UploadGrant:Read`, routed through
`RbacStore::authorize_list_read` (admit-then-filter — never a bare global
permission check).

#### `DELETE /api/v1/upload-grants/{grant_id}`

Revoke a grant before it is redeemed. **Permission:** `UploadGrant:Delete`.
Returns `204` on success, `404` if the grant does not exist or is no longer
revocable (already redeemed, expired, or already revoked).

#### The agent-facing upload session (`/api/v1/uploads*`)

Agent-authenticated via the grant credential — never the operator auth
session. TLS is required for every route below.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/uploads` | Redeem a grant (`X-Yuzu-Upload-Grant: <grant_id>.<grant_secret>`), atomically single-use. Returns `upload_id`, a one-time `session_secret`, `chunk_max_bytes`, `offset: 0`. |
| `PUT` | `/api/v1/uploads/{upload_id}/chunk` | Stream one chunk (`X-Yuzu-Upload-Session: <upload_id>.<session_secret>`, `Content-Range: bytes <start>-<end>/<total>`). Accepts only `start == recorded_offset`. |
| `GET` | `/api/v1/uploads/{upload_id}` | Session status/resume: `{state, offset, expires_at}`. |
| `POST` | `/api/v1/uploads/{upload_id}/commit` | Verify and finalize (`{"sha256": "..."}`) — total size and both hashes must agree. |
| `DELETE` | `/api/v1/uploads/{upload_id}` | Cancel; discards the partial blob. |

See `docs/adr/3004-artifact-blob-storage.md` for the full frozen wire
protocol (error envelope, the ten closed `reason` values, expiry semantics).
The `content_dist` agent plugin's `upload_file` action is the reference
client — see its [InstructionDefinition](../../content/definitions/t2_capabilities.yaml)
for the operator-facing parameters (`path`, `grant_id`, `grant_secret`).

---

### Guaranteed State

Operator-facing surface for the Guardian (Guaranteed State) policy engine. See [Guaranteed State](guaranteed-state.md) for the feature guide and YAML rule schema. The Windows registry guard is live end-to-end (detect → enforce write-back → event ingest); per-guard fleet compliance aggregation on the `/status` endpoints lands in Guardian PR 4.

**RBAC matrix:**

| Role | Read | Write | Execute | Delete | Approve | Push |
|---|---|---|---|---|---|---|
| Administrator | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ITServiceOwner | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| PlatformEngineer | ✓ | ✓ | | ✓ | | ✓ |
| Operator | ✓ | | | | | ✓ |
| Viewer | ✓ | | | | | |

Administrator and ITServiceOwner inherit Execute and Approve on `GuaranteedState` from the cross-type CRUD seed loop — those operations have no active Guardian handler today but the grants exist in the DB. PlatformEngineer's grants are explicit (Read/Write/Delete/Push only). `Push` is a Guardian-specific operation (distribute an existing rule set to scoped agents) that separates deploy authority from authoring authority.

#### `GET /api/v1/guaranteed-state/rules`

List all Guaranteed State rules.

- **Permission:** `GuaranteedState:Read`
- **Response:** `data[]` of `GuaranteedStateRule` objects (see OpenAPI schema).
- **4xx:** `403` if a service-scoped API token queries this route — the rule catalogue isn't owned by any one IT service, so there's no per-target shape to confine against; the bare permission gate alone checks only the token's ITServiceOwner role, never its own service-tag scope.
- **5xx:** `503` if the store is unavailable (A4 envelope, `retry_after_ms: 5000`).
- **Audit:** `guaranteed_state.rule.read` (`denied` only — an ordinary successful list read is not audited).
- **MCP twin:** `list_guardian_rules` (#4037) — same store call, same service-scoped-token deny.

#### `POST /api/v1/guaranteed-state/rules`

Create a rule.

- **Permission:** `GuaranteedState:Write`
- **Request body:**

A rule may be authored **structured** (the agent-enforceable form) or **legacy** (`yaml_source` only, stored but not agent-enforced). Supply *either* a `spark`+`assertion` pair *or* a `yaml_source`.

| Field | Type | Required | Description |
|---|---|---|---|
| `rule_id` | string | Yes | Stable operator-chosen id. Must match `[A-Za-z0-9._-]+`, at most 256 bytes. Enforced at creation (#4665) — a violation returns `400`, not just documented convention. |
| `name` | string | Yes | Human-readable name (unique per server). |
| `spark` | object | Structured | `{type, params}` trigger block, e.g. `{"type":"registry-change"}` or `{"type":"file-change"}`. |
| `assertion` | object | Structured | `{type, params}` desired-state block, e.g. `registry-value-equals`, `file-exists`, `file-hash-equals`. |
| `remediation` | object | No | `{type, params}` — `alert-only` (default) or `enforce`. `params` carries the **resilience policy** (`mode`, `max_attempts`, `backoff_*`, …) and `event_debounce_ms`. |
| `yaml_source` | string | Legacy | Full rule YAML; required only when no structured `spark`+`assertion` is given. The server generates `yaml_source` from the structured form otherwise. |
| `version` | integer | No | Starting version (default `1`). |
| `enabled` | boolean | No | Default `true`. |
| `enforcement_mode` | string | No | `enforce` (default) or `audit`. **Set once at creation — immutable on update** (see PUT below). |
| `severity` | string | No | `low` / `medium` (default) / `high` / `critical`. |
| `os_target` | string | No | Empty (any) or `windows` / `linux` / `macos`. |
| `scope_expr` | string | No | Scope DSL expression selecting target agents. |

The catalog of valid `spark` / `assertion` / `remediation` types and their `params` (including the resilience-policy bounds) is discoverable at [`GET /api/v1/guaranteed-state/schemas`](#get-apiv1guaranteed-stateschemas).

- **Response:** `201` with `data.rule_id`.
- **4xx:** `400` missing required fields, invalid JSON, a request body nesting deeper than 32 levels (`kMcpMaxJsonDepth`), a `rule_id` that doesn't match `[A-Za-z0-9._-]+` or exceeds 256 bytes (#4665), or an **invalid resilience policy** (e.g. Bounded `max_attempts` < 1, `backoff_initial_ms` > `backoff_max_ms`) — returned as the A4 structured error envelope; `409` on duplicate `rule_id` or duplicate `name`; `403` if a service-scoped API token calls this route (same reasoning as the `GET` list above — no per-target shape to confine against).
- **Audit:** `guaranteed_state.rule.create` (`success` / `denied`; an invalid `rule_id` is audited as `denied` too — #4665).
- **MCP twin:** `create_guardian_rule` (#2146 Batch B1) — same store write and validation.

#### `GET /api/v1/guaranteed-state/rules/{rule_id}`

Fetch a single rule.

- **Permission:** `GuaranteedState:Read`
- **Response:** `data` is a `GuaranteedStateRule` object.
- **4xx:** `404` if the rule does not exist; `403` if a service-scoped API token queries this route (same reasoning as `GET .../rules` above).
- **5xx:** `503` if the store degrades (A4 envelope, `retry_after_ms: 5000`).
- **Audit:** `guaranteed_state.rule.read` (`denied` only).
- **MCP twin:** `get_guardian_rule` (#2146 Batch B1) — same store read.

#### `PUT /api/v1/guaranteed-state/rules/{rule_id}`

Update a rule. Version is incremented on every successful update regardless of whether any field changed.

- **Permission:** `GuaranteedState:Write`
- **Request body:** Any subset of the create-body fields *except* `enforcement_mode` (absent fields retain their current values). A body carrying structured `spark`/`assertion`/`remediation` blocks **re-authors** the Guard (re-deriving the canonical spec and re-validating the resilience policy) rather than dropping them; a metadata-only body leaves the existing spec intact.
- **`enforcement_mode` is immutable.** A body whose `enforcement_mode` differs from the stored value is rejected with `400` (`enforcement_mode is immutable — create a new Guard for a different posture (Watch vs Enforce)`); a different posture is a different Guard. A no-op echo of the current value is accepted.
- **Response:** `200` with `data.updated = true` and `data.version`.
- **4xx:** `400` invalid JSON, a request body nesting deeper than 32 levels (`kMcpMaxJsonDepth`), an invalid resilience policy (A4 envelope), or an `enforcement_mode` change; `404` rule not found; `409` on name conflict; `403` if a service-scoped API token calls this route (same reasoning as the create route above).
- **5xx:** `503` if the pre-update rule lookup hits a degraded store (A4 envelope, `retry_after_ms: 5000`).
- **Audit:** `guaranteed_state.rule.update`.
- **MCP twin:** `update_guardian_rule` (#2146 Batch B1) — same validation and version-bump. No optimistic-concurrency check against concurrent writers on either transport (tracked in #4303).

#### `DELETE /api/v1/guaranteed-state/rules/{rule_id}`

Delete a rule.

- **Permission:** `GuaranteedState:Delete`
- **4xx:** `404` if the rule does not exist; `403` if a service-scoped API token calls this route (same reasoning as create/update above).
- **Audit:** `guaranteed_state.rule.delete`.
- **MCP twin:** `delete_guardian_rule` (#2146 Batch B1). Does NOT automatically push an unarm to agents already enforcing the rule (tracked in #4304).

#### `GET /api/v1/guaranteed-state/rules/{rule_id}/status`

Per-guard fleet-wide agent-status drilldown (#4037, api-parity #2146 Batch A) — agent_id/state/updated_at for **every** agent that has reported this ONE rule's state. Machine-readable twin of the dashboard's per-guard fleet compliance census (`/guardian/guard/{id}`).

- **Permission:** `GuaranteedState:Read` via `AuthRoutes::require_list_read`, this route's **sole** authorization gate (ADR-0017 admit-then-filter) — the same chokepoint `GET .../status` uses, not a bare `perm_fn`. A service-scoped API token is refused outright (a rule has no single owning IT service to confine to); a management-group-confined grant's visible-agent set filters the returned rows.
- **Response:** `data[]` of `{agent_id, state, updated_at}`, `pagination.total`. Raw census — does **not** apply the dashboard fragment's own offline-agent-folds-to-unknown rollup (same posture `GET .../status` already established for the identical class of data).
- **4xx:** `404` if `rule_id` names no rule; `403` for a service-scoped token or no `GuaranteedState:Read` grant anywhere.
- **5xx:** `503` if the store is degraded (A4 envelope, `retry_after_ms: 5000`), the gate is unwired, or the `guaranteed_state.rule.view` audit row cannot persist (fail-closed, `Sec-Audit-Failed: true`, also `retry_after_ms: 5000`).
- **Audit:** `guaranteed_state.rule.view` (`success`/`not_found`), `target_type=GuaranteedState`, `target_id=<rule_id>` — the SAME verb the per-guard dashboard drilldown emits (not `guardian.device.view`; a fleet-wide-per-rule read is a different shape from a per-device read). MCP twin: `get_guardian_rule_status` (`audit_persisted:false` posture instead of fail-closed).

#### `GET /api/v1/guaranteed-state/agents/{agent_id}/rules`

Per-device all-guards view (#4037, api-parity #2146 Batch A) — every guard's state for ONE device, unscoped to any Baseline. Machine-readable twin of the dashboard's per-device Guardian lens (`/fragments/device/guardian`). Genuinely distinct from `GET .../device-compliance` below, which answers "is this device compliant with this ONE named Baseline" (requires both `agent_id` **and** `baseline`, and returns a baseline-shaped response) — this route has no `baseline` parameter and returns every guard the device has EVER reported, regardless of Baseline membership.

- **Permission:** `GuaranteedState:Read`, per-device scoped (management-group aware) — same `scoped_perm_fn(GuaranteedState, Read, agent_id)` gate `GET .../device-compliance` and the dashboard Guardian device lens both use.
- **Response:** `data.agent_id`, `data.guards[]` of `{rule_id, name, state, updated_at}`, `data.total_guards`. A device with no reported guards returns an empty `guards[]`, not an error.
- **5xx:** `503` if the scoped-permission gate is unwired, the store is degraded (A4 envelope, `retry_after_ms: 5000`), or the `guardian.device.view` audit row cannot persist (fail-closed).
- **Audit:** `guardian.device.view`, `target_type=Agent`, `target_id=<agent_id>` — the SAME verb `GET .../status/{agent_id}` and the dashboard Guardian device lens emit. MCP twin: `get_guardian_device_guards` (`audit_persisted:false` posture instead of fail-closed).

#### `POST /api/v1/guaranteed-state/push`

Queue a push of the active rule set to scoped agents. Returns `202 Accepted` — agent delivery is asynchronous. The fan-out is live: the server resolves `scope` to the in-scope agents and delivers each a per-agent filtered rule set (only rules whose `os_target` and `scope_expr` match that agent).

- **Permission:** `GuaranteedState:Push`
- **Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `scope` | string | No | Scope DSL selector. Empty = all agents. |
| `full_sync` | boolean | No | If `true`, agents replace their rule set; otherwise they merge. |

- **Response:** `202` with `data.queued = true`, `data.rules` (server-side rule count), `data.agents` (number of agents the push was dispatched to), `data.scope`.
- **4xx:** `400` if the JSON body is present but not an object, or if `scope` fails to parse as a Scope DSL expression; `403` if a service-scoped API token calls this route — the single most severe instance of this confinement-gap class on this branch, since a `full_sync` push mutates what every OTHER service's agents enforce, not merely reads it.
- **5xx:** `503` if the Guaranteed-State rule store is degraded or unreachable (A4 envelope, `retry_after_ms: 5000`) — the push is refused rather than fanned out empty (ADR-0038). Retry once the store recovers; a `503` here means "cannot read the rules," never "zero rules configured." The heartbeat reconcile applies the same fail-closed rule (it declines to re-push rather than push an empty set).
- **Audit:** `guaranteed_state.push` (`success` / `denied`). A server-initiated re-push to a lagging agent on heartbeat reconnect is audited separately under `guaranteed_state.reconcile` (principal `system`).
- **MCP twin:** `push_guardian_rules` (#2146 Batch B1) — same gate, same scope-string push mechanism (not the shared `command_dispatch_fn`/`check_targeting_shape` chokepoint). Genuinely non-idempotent, annotated `idempotentHint:false`.

#### `GET /api/v1/guaranteed-state/events`

Query Guaranteed State events (rule violations, remediations, agent sync events).

- **Permission:** two gated shapes behind one route. A query with a non-empty `agent_id` (max 256 chars, no control characters) requires per-device-scoped `GuaranteedState:Read` — management-group aware, and a service-scoped API token is confined to its own service's agents. A query with no `agent_id` (fleet-wide) requires global `GuaranteedState:Read` **and** denies a service-scoped token outright (`403`): the fleet fan-out returns every reporting agent's `agent_id` + `detail_json`, which the bare service-token role check alone would not confine.
- **Query parameters:** `rule_id`, `agent_id`, `severity`, `limit` (default 100, capped at 1000), `offset` (default 0).
- **Response:** `data[]` of event objects. Each object: `event_id`, `rule_id`, `agent_id`, `event_type`, `severity`, `guard_type`, `guard_category`, `detected_value`, `expected_value`, **`detail_json`**, `remediation_action`, `remediation_success`, `detection_latency_us`, `remediation_latency_us`, `timestamp`. `detail_json` is a structured JSON string: for DEX observations it carries the uniform keys `subject`/`reason`/`symbolic`/`component`/`metric`/`platform` (plus, for `process.crashed`, the legacy `process`/`exception_code`/`faulting_module`); empty string for plain drift events. Per-signal shapes are documented in [`docs/dex-signal-catalog.md`](../dex-signal-catalog.md).
- **4xx:** `400` on non-integer or negative `limit` / `offset`, or on an `agent_id` over 256 characters / containing a control character. `403` if a service-scoped token queries the fleet-wide shape, or names a device outside its own service's scope.
- **Ruleless DEX signal observations share this endpoint.** Filter `rule_id=__observation__` to retrieve `event_type=<obs_type>` rows (`process.crashed`, `process.hung`, `service.crashed`, `os.boot`, … — fleet-wide signals recorded independent of any rule; `severity` is a fixed `info`; `expected_value` empty). See [DEX signal observations](guaranteed-state.md#dex-signal-observations) and the [DEX dashboard](dex.md).
- **Audit (behavioral PII):** BOTH shapes emit a **`dex.device.view`** audit row on every read — the per-device shape returns that device's signal history (`detail_json` reveals which apps a person runs) and audits `target_type=Agent`, `target_id=<agent_id>` (the same verb as the dashboard per-device drill-down); the fleet-wide shape returns every reporting agent's rows and audits `target_type=GuaranteedState`, `target_id=` (empty — no single agent). **Fail-closed on both shapes:** the audit fires before the data is serialized; if the audit row cannot persist, the endpoint returns `503` + `Sec-Audit-Failed: true` and serves no data (parity with `GET /api/v1/dex/devices/{id}`). A service-scoped token denied the fleet-wide shape also gets a `dex.device.view` `denied` audit row, so a rejected probe still leaves a trace.
- **MCP twin:** `list_guardian_events` (#4037) — same dual gate shape, same query params. `audit_persisted:false` posture instead of REST's fail-closed (JSON-RPC has no `Sec-Audit-Failed` header channel). The fleet-wide branch's confinement gap (#3238) is **not** closed by this twin — it deliberately keeps the same bare-`perm_fn` posture REST has today rather than inventing a different MCP-only gate.

#### `GET /api/v1/guaranteed-state/status`

Fleet-wide status rollup. `errored_rules` is real (#2298 item 6d): the count of
distinct rule_ids with at least one agent currently reporting state `errored` in
the `guardian_agent_rule_status` census, intersected against the live rule catalogue
(a census row for a since-deleted rule is excluded) — the source of truth also
behind the dashboard's Unhealthy Guards card, not the (reaped, 30-day) event log.
`compliant_rules` and `drifted_rules` stay `0` deliberately — full status ingest
(`action=="status"`) lands in a later rung. This route's SOLE authorization gate is
`AuthRoutes::require_list_read` (ADR-0017 admit-then-filter; never the flat
`require_permission`, which does not consult management groups and cannot be
stacked with a separate confinement check — the two do not compose). A
**service-scoped API token is denied (`403`) outright**: this route aggregates
across every agent's census, and a token scoped to one service must not read the
fleet-wide count. For every other caller, the route is **management-group-confined**:
a global `GuaranteedState:Read` grant sees the fleet-wide count, a
management-group-confined grant sees `errored_rules` scoped to that operator's
visible agents only (applied in SQL before the aggregate, ADR-0017 INV-3), and a
caller with no grant anywhere is refused with `403`. `total_rules` is never
confined — it is the size of the global rule catalogue, which has no agent or
management-group dimension. **A real grant that resolves to ZERO visible agents
(an empty or agent-less management group) is still `200` with `errored_rules: 0`**
(ADR-0017 INV-2 — a narrow-but-real grant is not a denial); do not read a `0` as
"fleet healthy" without also confirming the caller's management-group scope
actually covers the agents it should.

- **Permission:** `GuaranteedState:Read` (non-service-scoped; management-group confined via `AuthRoutes::require_list_read`, ADR-0017)
- **Response keys:** `total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules` (field names match the agent-side proto `GuaranteedStateStatus`).
- **4xx/5xx:** `403` for a service-scoped token, a caller with no `GuaranteedState:Read` grant anywhere, **or an unreachable/corrupt RBAC or management-group store for an ordinary caller** — `authorize_list_read` fails closed to the SAME `403` as a genuine no-grant denial, not a `503`, for every non-engine caller (the two are not currently distinguished in the response code). `503` only for: an unwired list-read gate or a null Guaranteed State store (server misconfiguration, no `retry_after_ms`); a Guaranteed State store query-time degrade (transient, `retry_after_ms: 5000`); or, for an **engine-principal** caller specifically, an unreachable/unopened RBAC store (engine sessions get a distinct `503` here, unlike human/service sessions) — never a silent `0`.
- **MCP twin:** `get_guardian_status` (#4037) — calls the SAME `guardian_status_rollup` builder and the SAME `require_list_read` gate (via `McpServer::set_list_read_fn`, wired from the identical server.cpp lambda REST uses), so REST and MCP cannot observe a different admit decision or a different rollup for the same caller.

#### `GET /api/v1/guaranteed-state/status/{agent_id}`

Per-agent status. `errored_rules` and `total_rules` are BOTH real and BOTH intersected
against the live rule catalogue (a census row for a since-deleted rule counts toward
neither) — `total_rules` is the count of rules with any census entry for this agent
still present in that catalogue, not the fleet catalogue size. `compliant_rules`/`drifted_rules` stay `0` for the same reason as the fleet
route. Per-device behavioral read: scoped the same
way as `GET /guaranteed-state/device-compliance` (a global grant passes fleet-wide,
otherwise the caller must hold Read via a management group the device is in), and
audited as `guardian.device.view` — **fail-closed**: `503` + `Sec-Audit-Failed: true`
if the audit row cannot persist.

- **Permission:** `GuaranteedState:Read`, per-device scoped
- **Response keys:** `agent_id`, `total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules`.
- **5xx:** `503` on an unwired scope gate/store, an audit-persistence failure, or a degraded store (A4 envelope, `retry_after_ms: 5000`) — never a silent `0`.
- **MCP twin:** `get_guardian_agent_status` (#2146 Batch B1) — calls the SAME `guardian_agent_status_rollup` builder and the SAME `scoped_perm_fn` gate, so REST and MCP cannot observe a different admit decision or a different rollup for the same caller.

#### `GET /api/v1/guaranteed-state/device-compliance?baseline={name}&agent_id={id}`

Name-anchored, device-applicable Guardian compliance — the machine-readable sibling of the dashboard Baseline page, built for embedding a device's compliance against a curated Baseline into an external CMDB / ITSM record. Looks the Baseline up by **name** and returns the Guards **actually applicable to the device**, each with that device's last reported verdict.

- **Why name, not id.** An integration pins one stable constant (e.g. `ServiceNow Compliance`) once. Baseline names are unique and survive reseeds/rebuilds, where a `baseline_id` churns — so there is no per-environment id to reconfigure.
- **Permission:** `GuaranteedState:Read`, **per-device scoped** — a global grant passes fleet-wide; otherwise the caller must hold `Read` via a management group the device is in (mirrors the dashboard Guardian device lens, so a group-scoped operator/service account is not locked out of in-scope devices). _Upgrade note:_ a previously **group-scoped** token now receives `403` for devices outside its group(s) — earlier builds gated this route on a flat global check that would have passed them. A **global** `GuaranteedState:Read` token (the documented ServiceNow service-account setup) is unaffected.
- **Audit:** `guardian.device.view` (target type `Agent`) — same verb the dashboard per-device Guardian lens emits, so one SIEM filter catches both surfaces. (Behavioural per-device data.) A scoped-permission **denial** is audited separately at the auth layer as `auth.scoped_permission_required`.
- **MCP twin:** `get_guardian_device_compliance` (#2146 Batch B1) — calls the SAME `guardian_device_compliance_rollup` builder and the SAME `scoped_perm_fn` gate; all four underlying reads complete before the access audit fires on either transport, so a degrade can never surface after an audited "success".
- **Evidence integrity — fail-closed (CC7.2).** This is a behavioural-PII read, so if the `guardian.device.view` audit row cannot persist (locked store, disk-full, or a pipeline exception — including a throwing audit pipeline) the endpoint **refuses to serve**: it returns **`503` + `Sec-Audit-Failed: true`** with an A4 envelope carrying a `retry_after_ms` hint, and **withholds the compliance body** — parity with `GET /api/v1/dex/devices/{id}`. Serving audited per-device compliance while the evidence row is known-lost is exactly what audit-on-open prevents. The `503` is returned **before** the `404`, so an audit outage never reveals baseline existence without durable evidence. A CMDB integration should treat `Sec-Audit-Failed: true` as "retry after the audit subsystem recovers," not a permanent error; an audit-off deployment (no audit callback wired) serves normally. (The realistic failure modes also increment `yuzu_server_audit_emit_failed_total` and log to `spdlog`.) **Blast radius:** because this is the fleet-polled CMDB endpoint and there is no degraded-serve fallback, a *sustained* audit-store outage 503s **every** poll fleet-wide — size audit-store availability for the polling load, and expect a compliance-data blackout (not stale data) for the duration. (Per-route retry jitter to avoid synchronized retries across pollers is a tracked platform-wide hardening, #1647.)
- **Query params:** `baseline` (the Baseline **name**, unique; URL-encode spaces, e.g. `ServiceNow%20Compliance`), `agent_id` (the device). Both required.
- **`400`** if either param is missing, exceeds 256 chars (`auth::kMaxAgentIdLength` — the enrolled-agent-id ceiling, so a valid device id is never falsely rejected), or contains control characters (bytes `< 0x20`); **`403`** if the caller lacks `Read` on the device's scope (checked **before** the baseline lookup, so an out-of-scope caller gets `403` even for an unknown name — no name-existence oracle); **`404`** if no Baseline has that name; **`503`** if the route is misconfigured (its stores or scoped-permission function are unwired — non-transient, do not auto-retry, no `retry_after_ms`) **or if the baseline store or the guaranteed-state store itself faults** (DB locked/corrupt — *retryable*, A4 envelope with `retry_after_ms: 5000`; a transient store fault returns `503`, not the `404` a CMDB would otherwise read as "no such baseline → delete this CI"). The `400`/`404`/`503` bodies use the A4 envelope (`correlation_id`); the `403` is emitted by the shared auth/RBAC layer and carries that layer's denial body, not the A4 envelope (no `correlation_id`; exact shape varies by denial reason — RBAC vs service-scope). For a robust integration, branch on the HTTP `403` status and treat the body as opaque/diagnostic — do not structurally parse it (the `error` field may be a JSON string or an object depending on the denial reason).
- **Response keys:**
  - `baseline` — `{ baseline_id, name, lifecycle }`.
  - `deployed` — `true` when the Baseline's lifecycle is `deployed`. When `false`, `guards` is empty and `total_guards` is `0` — render a "No Baseline Deployed" placeholder.
  - `assessable` — **machine-readable go/no-go.** `true` only when the Baseline is `deployed` **and** at least one applicable Guard has reported (`total_guards > 0`). `false` for a draft Baseline, or a deployed Baseline this device has reported no applicable Guard against (newly-enrolled / offline / all out-of-scope). **When `assessable` is `false`, do not compute or render a compliance percentage** — branch a business rule on this flag instead of reconstructing the `deployed`+`total_guards`+`last_updated` conjunction. It is the machine signal that closes the `0/0` green-wash.
  - `agent_id`.
  - `total_guards`, `compliant`, `drifted`, `errored`, `pending` — counts over the Guards **applicable to this device** (see Semantics + the **compliance-percentage caution** below). Invariant: `total_guards == compliant + drifted + errored + pending`.
  - `snapshot_total` — the Baseline's full deployed-member count (the **superset** across all devices, an upper bound — **not** this device's in-scope count). `total_guards <= snapshot_total`; a gap is expected for a per-machine-scoped Baseline, but a large gap is a cue that this device's coverage may be partial.
  - `last_updated` — the newest `updated_at` across the guards (a "compliance as of" stamp); `null` **only when this device has reported no applicable guard**. A guard the device *did* report contributes its timestamp even if its verdict token is unrecognized (`pending`).
  - `guards[]` — `{ rule_id, name, status, updated_at }` per **applicable** Guard. `status` is `compliant` | `drifted` | `errored` | `pending`; `updated_at` is the ISO-8601 time this device last reported that Guard's verdict, `null` **only when this device has not reported the guard** (a reported guard carries its timestamp even when `status` is `pending`).

**Semantics — device-applicable subset.** One Baseline can carry a **superset** of Guards, each with its own `scope_expr`; the push fan-out arms a **different subset on each machine**. This endpoint returns only the Guards **actually applicable to the device** — the Baseline's `deployed_snapshot` intersected with the Guards the device has reported. A Guard that is out of scope for this device (never armed → never reported) is **absent** (not `pending`), so `total_guards` and `guards[]` reflect *this machine's* applicable set: different machines, querying the **same** Baseline name, legitimately see different Guards. (`pending` therefore means a Guard the device reported with an unrecognized verdict — normally `0`; an elevated `pending` after a partial fleet upgrade can indicate **agent/server version skew** — a newer agent emitting a verdict token this server build does not yet recognize, which upgrading the server resolves. The Guard still carries its real `updated_at` in that case.) Verdicts are the device's last *reported*, Observe-mode state, with no device-liveness fold.

> **Report-driven caveats.** Applicability is inferred from what the device has *reported*, with two consequences: (1) an in-scope Guard on an **offline** device is absent (not `pending`) until it reports — track device online/offline yourself and use `last_updated` for freshness; (2) a Guard that was **re-scoped out and re-deployed** keeps its last reported row, so it lingers on the CI until that row is overwritten or cleared (the forward direction — tag a device so a Guard *starts* applying — appears promptly; the reverse lags). The honest fix for both — evaluating each Guard's `scope_expr` against the device so in-scope-unreported shows `pending` and out-of-scope never shows — is a tracked computed-denominator upgrade.

> ⚠️ **Compliance percentage — do not gate on it (yet).** Because the denominator is *reported* applicable Guards, an in-scope Guard the agent has not yet reported drops **out of** `total_guards` rather than counting against it. So `compliant / total_guards` **over-estimates** compliance — a device reporting 3 of its 10 in-scope Guards, all compliant, reads as **100%** — and it over-estimates worst exactly when Guards are broken or the device is flaky. **Do not gate automated remediation or a CMDB compliance flag on this percentage** until the per-device `scope_expr` computed denominator ships (tracked follow-up). Treat the numbers as advisory: branch on `assessable`, watch the `snapshot_total − total_guards` gap as a partial-coverage cue, and cross-reference `last_updated` and your own device-liveness signal. (The `assessable:false` / `0/0` case below is the *zero*-coverage corner of this same caveat.)

> ⚠️ **Do not rename a referenced Baseline.** This route resolves the Baseline by **name**; renaming a Baseline that an integration pins (e.g. `ServiceNow Compliance`) makes every poll `404` until that integration is reconfigured to the new name — silently, until CIs stop updating. Treat the Baseline name as a **stable external identifier**; see the rename note in [Guaranteed State](guaranteed-state.md).

**Setup.** The Baseline must be **deployed** (a draft returns `deployed: false`), and **member edits appear here only after a re-deploy** rewrites the `deployed_snapshot`. Branch on the **`deployed`** flag (not `total_guards`) to decide "No Baseline Deployed": a deployed Baseline with zero applicable Guards legitimately returns `deployed: true, total_guards: 0`. **Treat `deployed: true` with `total_guards: 0` and `last_updated: null` as _not assessable_, not compliant** — it means no applicable Guard has reported yet (the device is offline / newly-enrolled, or every Guard is out of its scope). Do **not** compute a compliance percentage from a zero denominator, and do not render `0/0` as a pass — an unreachable or dead device would otherwise read as green. Per-machine variation is driven by each Guard's `scope_expr` (tag / OS / group) — see [Guaranteed State](guaranteed-state.md).

**Bulk CMDB sync.** This is a point-in-time, **single-device** read (not a push/subscription). To populate many CI records, poll per-device on a cadence (15–60 min is typical for a CMDB) rather than bursting every CI at once — concurrent fleet-wide polls contend on the same store locks the agent-heartbeat ingest path uses, so a synchronized stampede can delay heartbeat processing.

**Example:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" --get \
  "$YUZU_URL/api/v1/guaranteed-state/device-compliance" \
  --data-urlencode "baseline=ServiceNow Compliance" \
  --data-urlencode "agent_id=$AGENT_ID"
```

```json
{
  "data": {
    "baseline": {"baseline_id": "ab12cd34ef56", "name": "ServiceNow Compliance", "lifecycle": "deployed"},
    "deployed": true,
    "assessable": true,
    "agent_id": "031e63a1-3139-48e6-beb6-50e3db062d0f",
    "total_guards": 3,
    "snapshot_total": 3,
    "compliant": 2, "drifted": 1, "errored": 0, "pending": 0,
    "last_updated": "2026-06-20T13:45:00Z",
    "guards": [
      {"rule_id": "g-fw",  "name": "Windows Firewall on", "status": "compliant", "updated_at": "2026-06-20T13:45:00Z"},
      {"rule_id": "g-rdp", "name": "RDP NLA required",    "status": "drifted",   "updated_at": "2026-06-20T12:30:00Z"},
      {"rule_id": "g-blk", "name": "BitLocker enabled",   "status": "compliant", "updated_at": "2026-06-20T13:44:00Z"}
    ]
  },
  "meta": {"api_version": "v1"}
}
```

#### `GET /api/v1/guaranteed-state/alerts`

Guaranteed State alerts (placeholder; alert aggregation lands in Guardian PR 11).

- **Permission:** `GuaranteedState:Read`
- **Response:** empty list in PR 2.

#### `GET /api/v1/guaranteed-state/schemas`

Guard authoring schema catalog — the static registry of `spark` / `assertion` / `remediation` types with per-type JSON Schemas. Driven by the same param-spec table the server-side validator uses, so the discovery surface and the validator cannot diverge. Drives dynamic authoring forms and agentic clients (the dashboard is one consumer).

- **Permission:** `GuaranteedState:Read`
- **Response:** `200` with `{version, schemas[]}`, each entry `{kind, type, json_schema}`. Includes the discriminated `registry-value-equals` encoding (per `value_type`), the `file-hash-equals` `expected_hash` hex format, and the `service-running` / `service-stopped` assertion schemas (with `service_name` pattern validation mirroring the agent's accepted service-name charset). The catalog is the source of truth for which spark/assertion/remediation types the agent actually implements — author against what it lists.
- **Caching:** carries a content-derived `ETag` and `Cache-Control: public, max-age=300`; a conditional request with `If-None-Match` returns `304 Not Modified`. The catalog is compiled-in, so this endpoint answers even when the rules store is unavailable.

---

### DEX (Digital Employee Experience)

The DEX aggregation endpoints are the machine-readable equivalent of the [DEX dashboard](dex.md): the same store rollups the HTMX fragments render, JSON-shaped for agentic workers. The signal endpoints read the ruleless `__observation__` projection (the same data the [events](#get-apiv1guaranteed-stateevents) endpoint exposes per-row); the perf endpoints aggregate registry heartbeat state at request time. All are gated on the same `GuaranteedState:Read` securable. The signal endpoints accept a `window` query parameter — one of `24h`, `7d`, `30d`, `all` (default `7d`; any other value resolves to `7d`) — and an optional `os` filter (`windows`/`linux`/`macos`; omitted or any other value = every OS), which scopes them to one OS's own signals exactly as the dashboard catalogue OS filter does; the perf endpoints are now-views with no window.

**Audit boundary.** The catalogue rollup, per-OS scope and the perf endpoints are aggregates / machine-health telemetry and are **not** audited. The per-signal drill-down returns a most-affected **devices** list (`agent_id`s — behavioral, individual-identifying) and emits a **`dex.signal.view`** audit row (`target_type=ObsType`, `target_id=<obs_type>`) on every call — the same verb as the dashboard per-signal view and consistent with the `agent_id`-filtered events query.

#### `GET /api/v1/dex/signals`

Whole-catalogue rollup — every observation type present in the window.

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `window`; `os` (`windows`/`linux`/`macos` narrows the rollup to that OS's own signals; omitted = every OS).
- **Response:** `data[]` of `{obs_type, count, distinct_devices, last_seen}`. `obs_type` is the stable machine key (e.g. `process.crashed`, `os.boot`); map your own labels. Not audited.

#### `GET /api/v1/dex/scope`

Per-OS signal coverage — how many distinct observation types each platform reports, with total event count (the live cross-OS coverage the dashboard derives).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `window`.
- **Response:** `data[]` of `{platform, distinct_types, total_events}`. Not audited.

#### `GET /api/v1/dex/signals/{obs_type}`

One signal type's drill-down.

- **Permission:** `GuaranteedState:Read`
- **Path parameter:** `obs_type` — must match `[A-Za-z0-9._-]{1,64}`.
- **Query parameters:** `window`; `os` (`windows`/`linux`/`macos` scopes `subjects[]`, `devices[]` and `by_day[]` to that OS; `by_os[]` stays cross-OS since it IS the split; omitted = every OS); `limit` (caps `subjects[]` and `devices[]`, default 50, clamped to 500).
- **Response (`200`):** an object `{obs_type, os, subjects[], by_os[], devices[], by_day[]}` where `os` echoes the applied filter (`all` when unscoped), `subjects[]` is `{subject, count, distinct_devices, last_seen}`, `by_os[]` is `{platform, count, distinct_devices}`, `devices[]` is `{agent_id, count, last_seen}`, and `by_day[]` is `{day, count}`. A well-formed `obs_type` with no observations in the window returns `200` with empty arrays (it is a read-model query, not an entity lookup).
- **4xx:** `400` on a malformed `obs_type` or a non-integer / negative `limit`. `403` if a service-scoped API token queries this route — the `devices[]` array is fleet-wide (every agent exhibiting this signal), with no single agent to confine a per-target check against, so a service-scoped token is denied outright (the bare permission gate alone checks only the token's ITServiceOwner role, never its own service-tag scope).
- **Audit (behavioral PII):** the `devices[]` array names the `agent_id`s exhibiting this signal, so the endpoint emits **`dex.signal.view`** (`target_type=ObsType`, `target_id=<obs_type>`) before serving — see the audit boundary note above. A denied service-scoped token also emits `dex.signal.view` (`result=denied`, `target_id=` empty) so a rejected probe still leaves a trace. **Fail-closed:** if the audit row cannot persist, returns `503` + `Sec-Audit-Failed: true` and serves no device list (parity with `GET /api/v1/dex/devices/{id}`).

#### `GET /api/v1/dex/perf/fleet`

Fleet device-performance now-stats — the same numbers as the `yuzu_fleet_perf_*` Prometheus gauges and the `/dex` Performance tab, computed at request time.

- **Permission:** `GuaranteedState:Read`
- **Response:** an object `{cpu_pct, commit_pct, disk_lat_ms, reporting, windows_online, linux_online, macos_online, reporting_windows, reporting_linux, reporting_macos}` where each metric is `{avg, p50, p90, max, n}` **or `null`** when no device reported it this cycle (absent, never 0). `reporting` counts devices contributing at least one metric; `windows_online`/`reporting` are byte-identical to their historical values — only the trailing fields are new. `linux_online`/`macos_online` are the same online-count per OS, and `reporting_windows`/`reporting_linux`/`reporting_macos` split the reporting population by OS, closing the previous known limitation where `reporting` could legitimately exceed the Windows-only `windows_online` denominator on a mixed fleet. `reporting_macos` is always 0 today — `macos_online` counts real online macOS agents, but no macOS perf collector exists yet (honest absence, not a bug). Not audited.

#### `GET /api/v1/dex/perf/cohorts`

Fleet-relative performance percentiles per **cohort** — the distinct values of an operator-chosen tag key (see [Cohort benchmarking](dex.md#performance)).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `key` — the cohort tag key (`[A-Za-z0-9_.:-]{1,64}`, default `model`).
- **Response:** `{key, floor, cohorts[], available_keys[]}`. Each cohort row is `{cohort, devices, suppressed}` plus, when not suppressed, per-metric stats as in `/perf/fleet`. Cohorts under `floor` (10) reporting devices carry `suppressed: true` with their population and **no stats**; devices without the key form the explicit `cohort: ""` (untagged) residual. `available_keys` lists the fleet's tag keys for picker UIs. `400` on an invalid key. Not audited.

#### `GET /api/v1/dex/perf/cohort-diff`

The direct **A-vs-B** cohort comparison (e.g. `image_type` vanilla vs layered, or `model` X vs Y) — where `/perf/cohorts` benchmarks each cohort against the *fleet*, this diffs two cohorts head-to-head. Closes the cohort-vs-cohort half of the benchmarking residual. *(The fleet-per-app benchmark — per-app perf over time across the fleet — is the separate **app-performance-over-time** surface below: `GET /api/v1/dex/perf/apps` / `app` / `group`, reading the retained Postgres aggregate.)*

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `key` — the cohort tag key (`[A-Za-z0-9_.:-]{1,64}`, default `model`); `a`, `b` — the two cohort values to compare (**both required**; an empty value is the untagged residual).
- **Response:** `{key, floor, found_a, found_b, a, b, delta_pct}`. `found_a`/`found_b` are `false` when a cohort has no reporting devices (its side is `null`). `a`/`b` are cohort rows `{cohort, devices, suppressed}` plus per-metric stats when not suppressed. `delta_pct` is `{cpu_pct, commit_pct, disk_lat_ms}` where each is A's p50 relative to B's p50 (B the baseline; positive = A higher), or `null` unless **both** cohorts expose that metric (neither suppressed below the 10-device floor). `400` on an invalid key or missing `a`/`b`. Not audited.

#### `GET /api/v1/dex/perf/devices`

The one device list behind every Performance drill: worst devices by a metric (default), the not-reporting complement, or one cohort's members.

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `metric` (`cpu` / `commit` / `disk_lat`, default `cpu`); `filter=not_reporting` (devices of an OS with a real perf collector — Windows and Linux today — that had no perf sample this cycle; a macOS device never appears, collector or not); `cohort_key` (display key — always resolved, default `model`, so rows carry real cohort values); `cohort_value` (**when present**, restricts to that cohort; an empty value selects the untagged residual); `limit` (default 50, clamped to 500).
- **Response:** `data[]` of `{agent_id, cohort, cpu_pct?, commit_pct?, disk_lat_ms?, fleet_pctile?, os}`, worst-first by the sort metric (`fleet_pctile` is the device's nearest-rank position among all reported values; omitted when the device did not report the metric; `os` is the normalized token — `windows`/`linux`/`macos`/empty for unrecognized). `400` on an invalid `cohort_key` or `limit`. `403` if a service-scoped API token queries this route (fleet-wide `agent_id` rows, no single agent to confine against — same rationale as `dex/signals/{obs_type}` above).
- **Audit (behavioral PII):** each row is an `agent_id` + its perf metrics, individual-identifying, fleet-wide — emits **`dex.perf.device.view`** (`target_type=GuaranteedState`, `target_id=` empty) before serving. A denied service-scoped token also emits this verb (`result=denied`). **Fail-closed:** if the audit row cannot persist, returns `503` + `Sec-Audit-Failed: true` and serves no device list.

### Application performance over time

Per-application CPU / working-set **by version, over the retained window**, across the fleet or one management group — reading the retained Postgres aggregate (B1 per-device daily / B2 fleet rollup), not the live federated device drill. Per-app sampling is opt-in (`procperf_enabled`, off by default); a device contributes only after its first completed UTC midnight. The aggregate surfaces gate `GuaranteedState:Read` and are **not** audited (cohort posture); the per-device drill is behavioural PII and is audited fail-closed (see below). The same shared transform backs these endpoints, the `get_dex_app_perf` / `get_dex_group_app_perf` MCP tools, and the dashboard so the numbers cannot disagree.

> **Percentile + suppression semantics (all three trend endpoints).** Each `points[]` entry's `cpu_p50`/`cpu_p95`/`ws_p50`/`ws_p95` is either `null` (absent — empty population, **not** zero) or `{value, lower_bound}`. `lower_bound: true` means the percentile fell in the open top histogram bucket, so `value` is a **floor** — render it as "≥ value", never an exact quantile. `hist_stale: true` means the row was stamped under a superseded histogram scheme, so percentiles are withheld (the exact mean/max still stand). **Cohort floor:** any `(version, day)` point covering fewer than **10** devices (`kDexCohortFloor`) is suppressed — its stats are withheld and only `device_count` is honest (a sub-floor aggregate would single out an individual). This applies to **both** the fleet and the group endpoints.

#### `GET /api/v1/dex/perf/apps`

The picker: applications that currently have retained fleet data, so a worker discovers which `app=` values are answerable (A2 discoverability).

- **Permission:** `GuaranteedState:Read`
- **Response:** `{apps[], truncated}` where each app is `{app_name, versions, last_day}` (`versions` = distinct retained versions; `last_day` = most recent UTC-midnight epoch day with data). `truncated: true` when the distinct-app set exceeded the picker cap. `503` (with `retry_after_ms`) when the store provider is unwired or the read degrades. Not audited.

#### `GET /api/v1/dex/perf/app`

The fleet trend for one application — one point per `(version, UTC day)` over the B2 window (**up to 180 days**).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `app` — **required**, ≤ 512 bytes, no control characters (a `400` otherwise; a NUL would truncate the bound query). `version` — optional; omitted = every version interleaved, each point tagged with its canonicalized `version`; same length/charset rule.
- **Response:** `{app, version, points[]}`. Each point: `{version, day, device_count, suppressed}` plus the full stat fields (`cpu_mean, cpu_max, cpu_p50, cpu_p95, ws_mean, ws_max, ws_p50, ws_p95, hist_stale`) **only when `suppressed` is false** — a sub-floor `(version, day)` point (fewer than 10 devices) carries `device_count` only, the same suppression the group endpoint applies (see the percentile/suppression note above). `400` on a missing/invalid `app` or `version`; `503` on store degrade. Not audited.

#### `GET /api/v1/dex/perf/app/devices`

The version-row "which devices" drill: unlike `/perf/app` above, each row here names an `agent_id` — a fleet-wide fan-out of identified per-device data (B1, up to 31 days) — so this route's authorization posture is entirely different from its aggregate sibling. Devices reporting one EXACT `(app, version)` among their retained top-N daily summaries, one row per device at its most recent reporting day for that version. **Not a census**: a device absent here may still run this app-version, just not among its top-N resource consumers that day (use the [software inventory](inventory.md) endpoints for a full install census).

- **Permission:** `GuaranteedState:Read`, gated on `AuthRoutes::require_fleet_read` (ADR-0017 admit-then-filter) as the **sole** gate — never stacked with a bare permission check. A management-group- or service-scoped caller gets the real, narrowed `agent_id` intersection pushed into the store query itself (never a post-fetch filter), so a confined caller never sees an unfiltered page and a fully-confined-empty caller sees zero rows, not the whole fleet.
- **Query parameters:** `app` — **required**, ≤ 512 bytes, no control characters. `version` — **required and present** (unlike `/perf/app`'s "omit = all versions" convention): this drill is always scoped to exactly one version; pass an empty string for the unknown-version bucket (the only bucket Linux agents report today — Linux procperf does not yet capture a file version) rather than omitting the parameter, which is rejected with `400`.
- **Response:** `{app, version, truncated, devices[]}` where each device is `{agent_id, last_day, samples, cpu_avg, ws_avg_bytes}`. Rows are ordered by descending `cpu_avg` and capped; `truncated:true` means only the highest-CPU devices are returned, not an arbitrary subset. `400` on a missing/invalid `app`/`version`; `403` if the caller lacks `GuaranteedState:Read`; `503` on store degrade or a dropped audit row (`Sec-Audit-Failed: true`).
- **Retention mismatch:** per-device data (B1) retains only 31 days, shorter than the fleet trend's 180-day (B2) window above — a version last reported more than a month ago legitimately returns `devices: []` even though `/perf/app` still shows aggregate history for it. This is expected, not a bug; the two stores retain independently.
- **Headers:** `X-Correlation-Id` echoed on every response path.
- **Audit:** emits `dex.app_perf.devices.view` (`target_type=GuaranteedState`, `target_id=""`, `detail` carries `app=<name> version=<token> devices=<n> cid=<correlation_id>`) **after** the read (so the count is honest) but **before** the response is sent — fail-closed: a persist failure returns `503` + `Sec-Audit-Failed: true` and serves no device data, same contract as `GET /api/v1/dex/devices/{id}/app-perf`. **MCP twin:** `list_dex_app_perf_devices`, set-and-proceed (`audit_persisted:false` in the body on a dropped row, no `Sec-Audit-Failed` header channel).

#### `GET /api/v1/dex/perf/group`

The same trend shape, aggregated **on-the-fly over one management group's member devices** (B1, **up to 31 days** — shorter than the fleet's 180-day B2 window, so a group series is shorter for the same app).

- **Permission:** `GuaranteedState:Read`. Gated on the **global** permission (like the cohort surface), not the per-device scope gate: the global check excludes management-group-scoped-only principals, so only a fleet-wide-Read caller — who can already compute every fleet/cohort aggregate — reaches it. No cross-operator exposure **on that axis**. A service-scoped API token is a DIFFERENT axis, though: `ITServiceOwner` holds a global `GuaranteedState:Read` grant regardless of scope, so the global-permission reasoning above does not confine it — it could otherwise supply any `group_id`, including one outside its own service. Found by this branch's own governance review (PR #3156), while re-verifying the external review's separate findings on this same file; a service-scoped token is now denied outright (`403`).
- **Query parameters:** `group_id` — **required**, ≤ 512 bytes, no control characters. `app` — **required**, same rule. `version` — optional, same rule.
- **Response:** `{group_id, app, version, floor, points[]}` where `floor` is the suppression threshold (10). Each point: `{version, day, device_count, suppressed}` plus the full stat fields **only when `suppressed` is false**. An empty/unknown group returns `200` with `points: []` (not a `503`). `400` on a missing/invalid parameter; `503` on store degrade.
- **Audit:** `dex.perf.group.view` (`denied` only — an ordinary successful read is not audited, matching this route's existing aggregate/cohort posture).

#### `GET /api/v1/dex/perf/tag`

The same trend shape as `/dex/perf/group` above, aggregated **on-the-fly over the devices carrying one tag VALUE** instead of a management-group id (B1, up to 31 days) — the REST/MCP twin of the dashboard's device-model cohort filter, mutually exclusive with the group scope. A tag-value cohort (e.g. one hardware model) is equally a "named set of specific devices", so it shares `/dex/perf/group`'s exact confinement, floor, and service-scoped-denial posture.

- **Permission:** `GuaranteedState:Read`. Same global-permission gate and the same DIFFERENT-axis service-scoped-token caveat as `/dex/perf/group` — see that section. A service-scoped API token is denied outright (`403`).
- **Query parameters:** `key` — optional tag key, default `"model"`; must match `^[A-Za-z0-9_.:-]{1,64}$` (`400` otherwise). `value` — **required**, ≤ 512 bytes, no control characters (an omitted or empty `value` is `400` — there is no "every value" wildcard). `app` — **required**, same rule. `version` — optional, same rule.
- **Response:** `{key, value, app, version, floor, points[]}` where `floor` is the suppression threshold (10). Each point: `{version, day, device_count, suppressed}` plus the full stat fields **only when `suppressed` is false**. An unknown tag value returns `200` with `points: []` (not a `503`) — indistinguishable from a genuinely empty cohort. `400` on a missing/invalid parameter; `503` on store degrade.
- **Audit:** `dex.perf.tag.view` (`denied` only — an ordinary successful read is not audited, matching `/dex/perf/group`'s posture).

#### `GET /api/v1/dex/perf/compare`

The **`/auto` VERIFY** before/after comparison: did upgrading `app` from `baseline` to `candidate` change how the **same machines** in `group` perform? For each machine that ran *both* versions in the window, a per-machine CPU and working-set delta is computed (each device's own baseline-version window vs its own candidate-version window, the window anchored to that machine's transition, not to "today"), then the per-machine deltas are aggregated. A machine that ran only one version in-window is excluded and counted. **Evidential only** — no verdict, no threshold, no pass/fail. The same pure engine backs this endpoint, the `compare_app_perf_versions` MCP tool, and the dashboard VERIFY stage, so the numbers cannot disagree.

- **Permission:** `GuaranteedState:Read`, gated on the **global** permission (same posture as `/dex/perf/group`, including the same DIFFERENT-axis caveat for service-scoped tokens — see that section). A service-scoped API token is denied outright (`403`); found by this branch's own governance review (PR #3156), while re-verifying the external review's separate findings on this same file. The near-individual nature of this endpoint (real canaries are often 2-3 devices) makes the gap especially severe for it.
- **Query parameters:** `group` — **required**, ≤ 512 bytes, no control characters; the management group whose members are the cohort. `app`, `baseline`, `candidate` — **required**, same validation; `baseline` and `candidate` must differ (`400` if equal after canonicalization). `window` — optional integer days, default `7`, clamped `1`–`31`.
- **Response (`200`):** `{app, group_id, baseline_version, candidate_version, window_days, cohort_size, paired, baseline_only, candidate_only, no_data, small_cohort, insufficient, truncated, cpu{before_mean, after_mean, delta_median, before_p95, after_p95}, ws{…}, distribution{up, flat, down}}`. `truncated:true` means the cohort exceeded the 100,000-row read cap — the counts are **incomplete and may mis-pair** machines (a device that ran both versions can be mis-reported as one-version-only); treat the result as unreliable and narrow the group or shorten the window. A zero-sample machine (one that measured nothing in-window) is excluded from pairing rather than counted as a 0%-CPU pair. `cohort_size` = group members; `paired` = ran both (the comparison population); `baseline_only`/`candidate_only` = excluded (one version only); `no_data` = `cohort_size − paired − baseline_only − candidate_only`. `small_cohort:true` = `paired` non-zero but below the 10-device floor — **not** suppressed (canaries are deliberately small; the surface marks it *indicative*). `insufficient:true` = `paired == 0` (no machine ran both — the `cpu`/`ws`/`distribution` values are zero and should not be displayed). `cpu.*` are percent (float); `ws.*` are bytes (int64); `delta_median` is the median per-machine delta (positive = candidate heavier). `distribution.{up,flat,down}` count machines whose per-machine CPU delta exceeded / stayed within / fell below ±0.3 pp.
- **No per-machine identity in the response** — the aggregate carries no `agent_id`. The per-machine pairs are a **dashboard-only** drill (`/fragments/auto/verify/drill`, audited `dex.app_perf.compare.drill`); there is **no REST or MCP per-machine surface** in this slice (a REST audited-fail-closed per-machine drill is a deferred follow-up).
- **Error paths:** `400` on a missing/invalid required parameter or `baseline == candidate`; `403` if a service-scoped API token calls this route; `503` on store degrade or startup warmup (the A4 body's `retry_after_ms` carries the suggested delay).
- **Headers:** `X-Correlation-Id` on every response path; `Sec-Audit-Failed: true` when the audit row could not persist (the read still proceeds — operational set-and-proceed).
- **Audit:** emits **`dex.app_perf.compare`** (`target_id=<group_id>`, `detail` carries `app=<name> base=<v> cand=<v> cohort=<N> paired=<N> view=aggregate cid=<cid>` — `paired=` so a singleton (paired=1) aggregate, which is effectively per-machine, is distinguishable in the log). Because VERIFY has no cohort floor, this recorded read is the accountability that replaces suppression (operational set-and-proceed, not fail-closed — the aggregate carries no per-machine identity, so a lost row leaks no PII). A service-scoped-token denial is also recorded under this same verb (`result=denied`, `target_id=` empty). The MCP twin is recorded under the generic `mcp.compare_app_perf_versions` tool-call audit on SUCCESS, which carries the same subject in its detail (group/app/versions/cohort/paired) and sets `audit_persisted:false` in the result body on a dropped row (MCP has no `Sec-Audit-Failed` header channel) — but a service-scoped-token DENIAL over MCP is recorded under `dex.app_perf.compare` too, matching the REST verb rather than the generic one (the deny-path convention every REST/MCP twin pair in this doc uses).

#### `GET /api/v1/dex/devices/{id}`

Per-device DEX read model — the machine-readable equivalent of the **DEX** lens on the `/device?id=` dashboard page.

- **Permission:** `GuaranteedState:Read`, scoped to the device's management group (a REST worker is held to the same per-device scope as the dashboard lens).
- **Path parameter:** `id` — the agent's `agent_id`.
- **Query parameters:** `window` — one of `24h` / `7d` / `30d` / `all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{agent_id, window, score, signals[]}` — `score` is the device's DEX experience score (0–100; `-1` = n/a, treat as "no data", **not** a low score); `signals[]` each `{obs_type, count, distinct_devices, last_seen}` for the window. An unknown `agent_id` returns `200` with `score:-1` and empty `signals` (the scope gate, not existence, decides access). `403` when the device is outside the operator's management scope. `503` when the store is unavailable, `503` with header `Sec-Audit-Failed: true` when the audit row cannot persist (see Audit below), **or** `503` (`retry_after_ms: 2000`, no `Sec-Audit-Failed`) when the underlying signal-summary read **degraded** (store closed / pool-acquire timeout / query error, #4855) — a degrade is a retryable error, never a `200` with a fabricated `score:0`/`100` and no signals. This is a NAMED exception to the general "#2659 DEX reads degrade to empty" posture described in [guaranteed-state.md](guaranteed-state.md) — this one read fails closed instead.
- **Headers:** `X-Correlation-Id` is echoed on **every** response path (matches `/api/v1/events`); the value also appears as `correlation_id` in error bodies.
- **Audit:** emits `dex.device.view` (`target_type=Agent`, `target_id=<agent_id>`, `detail` carries `cid=<correlation_id>`) **before** the behavioral PII is served (audit-on-open). **Fail-closed:** if the audit row cannot persist (audit DB locked/full/corrupt), the endpoint returns `503` + `Sec-Audit-Failed: true` and serves **no** device data — serving audited PII while the evidence row is known-lost is exactly what audit-on-open prevents (SOC 2 CC7.2 / works-council).

#### `GET /api/v1/dex/devices/{id}/app-perf`

One device's retained per-`(app, version, day)` performance history (B1) — the per-device companion to the fleet/group trend. This is behavioural PII (which applications a person runs, over time), so unlike the aggregate endpoints it is scoped + audited fail-closed. This endpoint also backs the `/device` dashboard DEX drill's *Application performance over time* panel (same `dex.device.app_perf.view` verb, dashboard set-and-proceed posture). **MCP twin:** `get_dex_device_app_perf` (#4035) closed the earlier MCP-only gap — see the MCP tool table below; the MCP surface follows its own set-and-proceed / `audit_persisted:false` posture rather than this route's fail-closed 503 (different surface, different posture — `docs/api-twin-recipe.md` §4).

- **Permission:** `GuaranteedState:Read`, scoped to the device's management group.
- **Path parameter:** `id` — the agent's `agent_id`.
- **Query parameter:** `app` — optional display filter applied **in memory** to the device's returned rows (not a bound query parameter — the device's retained rows are fetched by `agent_id`, then narrowed by `app`), so there is no length/charset gate or `400` on it. Omitted = every resource-significant app-version on the device.
- **Response:** `data` object `{agent_id, rows[]}` where each row is one retained daily summary `{app_name, version, day, samples, instances_max, cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes}`. An unknown `agent_id` returns `200` with empty `rows`. `403` outside the operator's scope; `503` when the store is unavailable, or `503` + `Sec-Audit-Failed: true` when the audit row cannot persist (serving **no** data).
- **Headers:** `X-Correlation-Id` echoed on every response path.
- **Audit:** emits `dex.device.app_perf.view` (`target_type=Agent`, `target_id=<agent_id>`, `detail` carries `cid=<correlation_id>`) **before** the PII is served — kept a separate verb from `dex.device.view` / `dex.device.procperf.query` so usage-class reads stay separately countable for works-council evidence. Fail-closed as above.

#### `GET /api/v1/dex/devices/{id}/history`

Per-device raw signal history — the distinct signal-**history** capability from `GET /api/v1/dex/devices/{id}` above (same device, different data: every observation row, not just the rollup score). The machine-readable equivalent of the `/device` dashboard DEX lens's Signal history table.

- **Permission:** `GuaranteedState:Read`, scoped to the device's management group.
- **Path parameter:** `id` — the agent's `agent_id`.
- **Query parameter:** `window` — one of `24h`/`7d`/`30d`/`all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{agent_id, window, crashes, hangs, signals, distinct_apps, last_seen, history[]}` — `history[]` each `{event_id, observed_at, obs_type, subject, reason, symbolic, component, metric}` (raw facts; no pre-formatted display string — derive your own summary from the fields, the fragment's "what happened" column is presentation-only). `403` outside scope; `503` on store unavailable or a dropped audit row (`Sec-Audit-Failed: true`).
- **Audit:** emits **`dex.device.view`** — the SAME verb `GET /api/v1/dex/devices/{id}` uses (a deliberate reuse: the dashboard fragment audits this exact signal-history capability under this exact verb too). Fail-closed as above.

#### `GET /api/v1/dex/devices/{id}/observations/{event_id}`

Single-observation detail — every captured projection field for one event (the device-history row's click target).

- **Permission:** `GuaranteedState:Read`, scoped to the device's management group.
- **Path parameters:** `id` (agent_id), `event_id`.
- **Response:** `data` object `{event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, component, version, metric, platform}`. `404` when the event does not exist **or** belongs to a different device — same response either way (a foreign/guessed `event_id` reveals nothing beyond what the scope gate already allowed, matching the dashboard fragment's oracle-closed contract).
- **Audit:** emits **`dex.observation.view`** (`target_type=Agent`, `target_id=<agent_id>`). Fail-closed as above.

#### `GET /api/v1/dex/app`

App blast-radius drill — crash/hang summary, faulting modules, exception codes, and the affected-device list for one application. The machine-readable equivalent of the `/fragments/dex/app` dashboard drill.

- **Permission:** `GuaranteedState:Read`. The `devices[]` array is confined to the caller's management-group scope (ADR-0017 World A), exactly like `/fragments/dex/app`; the crash/hang/module/exception counts remain fleet-wide aggregates.
- **Query parameters:** `name` — **required**, process image name (e.g. `chrome.exe`). `window`.
- **Response:** `data` object `{process_name, window, crashes, hangs, signals, distinct_devices, first_seen, last_seen, modules[], exceptions[], devices[]}`. `400` on missing `name` or an off-enum `window`. `403` — a service-scoped API token is denied outright: `devices[]` has no single agent to confine the token's own service-tag scope against (a separate axis from the management-group confinement above).
- **Audit:** emits **`dex.app.view`** before serving (fail-closed 503 + `Sec-Audit-Failed: true` on a dropped row) — the dashboard fragment audits only the service-scoped *denial* under this verb (not an ordinary success), so this REST route deliberately carries MORE rigor than its own fragment (matching the sibling per-signal/per-device-perf routes' fail-closed posture on an identical device-id-list shape).

#### `GET /api/v1/dex/apps`

App-centric stability list — every application with a crash/hang signal in the window, ranked by activity. The machine-readable equivalent of the `/dex` **Apps** tab.

- **Permission:** `GuaranteedState:Read`.
- **Query parameters:** `window` — one of `24h`/`7d`/`30d`/`all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{window, apps[]}` — `apps[]` each `{subject, crashes, hangs, distinct_devices, last_seen}`. No per-agent identity (a distinct-device **count** per app, never an `agent_id`) — not audited.

#### `GET /api/v1/dex/catalogue/group`

One signal family's member signals (Catalogue View 2) — per-type monitored/not-collected state, coverage platforms, event count + blast radius, plus the family's own health-score slice. See [`docs/dex-signal-catalog.md`](../dex-signal-catalog.md) for the family names.

- **Permission:** `GuaranteedState:Read`.
- **Query parameters:** `name` — **required**, exact family name (e.g. `App reliability`). `os` (`all`/`windows`/`linux`/`macos`, default `all`). `window` — one of `24h`/`7d`/`30d`/`all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{group_name, os, window, monitored_count, total_type_count, health_score, active_events, max_signal_devices, types[]}` — `types[]` each `{obs_type, monitored, coverage_platforms, count, distinct_devices, last_seen}`; `health_score` is `null` when nothing is monitored or the scoped denominator is 0. `400` on missing `name` or an off-enum `window`. `404` on an unknown family name. `503` when the store is unavailable. Not audited (no per-agent identity).

#### `GET /api/v1/dex/health`

The derived/**secondary** composite health score (100 minus weighted per-family deductions). The machine-readable equivalent of the `/dex` **Health score** tab.

- **Permission:** `GuaranteedState:Read`.
- **Query parameters:** `weighting` — one of `default`/`stability`/`productivity`/`security` (default `default`; an off-list value resolves to `default`). `window` — one of `24h`/`7d`/`30d`/`all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{weighting, window, reporting, total_crashes, crash_free_pct, score, band, deductions[]}` — `score`/`band`/`crash_free_pct` are `null` when `reporting` (reporting Windows agents) is 0, never a fabricated `100`; `deductions[]` each `{name, severity, deduction}` in catalogue order. `400` on an off-enum `window`. `503` when the store is unavailable. Not audited (no per-agent identity).

#### `GET /api/v1/dex/trends`

Cross-OS comparison + per-family day-by-day event counts (the small-multiples/heatmap source data). The machine-readable equivalent of the `/dex` **Trends** tab.

- **Permission:** `GuaranteedState:Read`.
- **Query parameters:** `window` — one of `24h`/`7d`/`30d`/`all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{window, total_catalogued_types, windows_reporting, crash_free_pct, os_cards[], days[], families[]}` — `os_cards[]` each `{platform, live, distinct_types, total_events}` for `windows`/`macos`/`linux` (fixed order); `families[]` each `{name, total, counts[]}`, `counts[]` index-aligned with `days[]`. Not audited (no per-agent identity).

#### `GET /api/v1/dex/overview`

Fleet DEX overview — the `/dex` landing page's fleet summary: per-device experience score distribution + the Device/App/Network composite, the measured crash-free rate, top apps, and the most-affected-devices list.

- **Permission:** `GuaranteedState:Read`. The `top_devices[]` array is confined to the caller's management-group scope (ADR-0017 World A), exactly like `/fragments/dex/overview`; every other field remains a fleet-wide aggregate.
- **Query parameters:** `window` — one of `24h`/`7d`/`30d`/`all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{window, overall_experience, device_score, app_score, network_score, great, fair, poor, unscored, coverage_monitored, coverage_total, crash_free_pct, windows_reporting, crashes_per_1k_device_days, total_crashes, devices_impacted, total_online, active_signal_types, health_score, os_reporting_count, segments[], crashes_by_day[], top_apps[], top_devices[], os_table[]}`. `unscored` (#4855) counts connected devices whose per-device score could not be computed (no store, or a degraded per-device signal-summary read) — a non-zero value means `great`/`fair`/`poor`/`overall_experience` cover fewer devices than are actually connected, not a healthier fleet than reported. `403` — a service-scoped API token is denied outright: `top_devices[]` has no single agent to confine the token's own service-tag scope against (a separate axis from the management-group confinement above).
- **Audit:** emits **`dex.overview.view`** before serving (fail-closed 503 + `Sec-Audit-Failed: true` on a dropped row) — same "REST adds more rigor than its own fragment" rationale as `GET /api/v1/dex/app` above (the dashboard fragment audits only the service-scoped denial, not an ordinary success).

#### `POST /api/v1/dex/devices/{id}/live`

Dispatches a read-only instruction to the live agent **now** and synchronously returns the result (~20 s). The machine-readable equivalent of the dashboard **"Get live info"** button. **POST, not GET** — it has a side effect (it dispatches a command), so it must not be fired speculatively by prefetchers/proxies/retry libraries.

- **Permission:** `GuaranteedState:Read` **and** `Execution:Execute`, both scoped to the device's management group.
- **Path parameter:** `id` — the agent's `agent_id`.
- **Query parameter:** `kind` — **required**. `uptime` dispatches `os_info/uptime`; `processes` dispatches `processes/list_hashed` (`proc|pid|name|sha256|path`; the SHA-256 is of each on-disk executable, resolved from the kernel, not argv[0], bounded at 512 MiB per image).
- **Dashboard-only kinds:** the dashboard **"Get live info"** grid renders ten additional card kinds (`process_tree`, `services`, `users`, `netconfig`, `arp`, `dns_cache`, `listening`, `connections`, `capture_sources`, `disk`). These are **not yet available on this REST endpoint** — passing any of them returns `400`. REST/JSON parity for all ten is deferred to [#1649](https://github.com/Tr3kkR/Yuzu/issues/1649); to probe e.g. the process tree via REST today, dispatch `processes/list_tree` directly through the async execution surface.
- **Response:** `data` object — `kind=uptime` → `{kind, uptime_display, uptime_seconds}`; `kind=processes` → `{kind, processes[].pid/name/sha256/path}`.
- **Errors:** `400` — `kind` missing/unrecognised. `403` — outside the operator's scope, or missing `Execution:Execute`. `429` — too many concurrent live queries server-wide (back off `retry_after_ms`). `502` — the device reported an error or the query failed. `503` — the device is offline (no connected agent), **or** `503` + `Sec-Audit-Failed: true` when the audit row cannot persist (the command is **not** dispatched — see Audit). `504` — the device did not respond within the timeout (`retry_after_ms`).
- **Headers:** `X-Correlation-Id` is echoed on **every** response path.
- **Audit:** emits `device.live.uptime` or `device.live.processes` (`target_type=Agent`, `target_id=<agent_id>`, `result=requested`, `detail` carries `cid=<correlation_id>`) **before** the command is dispatched — the operator's *request* is the works-council-relevant event, kept separately countable per kind. **Fail-closed:** if the audit row cannot persist, the endpoint returns `503` + `Sec-Audit-Failed: true` and the command is **not** dispatched (no usage-class probe without durable evidence). The dispatch outcome (reached an agent / offline) is carried by the HTTP response, not the audit row; `command_id` is recoverable from the response store / metrics by `cid`.

> **Scope boundary.** This is the **interactive, single-device** probe and is **concurrency-capped server-wide** (over-budget callers get `429`). It is **not** the fleet-scale path — do not fan a synchronous `/live` call out across thousands of devices. To read many devices at once, dispatch the equivalent read-only instruction to a *scope* via the async execution surface and collect results by `execution_id` (the cap deliberately keeps fan-out off this endpoint).

---

### Network

The machine-readable siblings of the `/network` dashboard fragments (A1 — fleet link health must be answerable without scraping HTML). Same render-time aggregation over heartbeat network facts, same `GuaranteedState:Read` gate. **The edge ships facts, never a verdict:** these report measured RTT / retransmit / throughput and *measured co-occurrence* counts, never a causal "it's the network" attribution.

> **Note — cohort parameter naming.** The network surface uses `key` for the cohort tag dimension (empty = no cohort, length-guarded), where the DEX performance surface uses `cohort_key` (validated, defaults to `model`). The difference is intentional and reflects each surface's cohort-resolution model — network cohorting is opt-in, DEX's always resolves. There is no `/api/v1/network/cohorts` endpoint (network has no per-cohort statistical aggregation); discover valid tag keys via the tag API.

#### `GET /api/v1/network/fleet`

Fleet network-quality now-stats — the same numbers as the `yuzu_fleet_net_*` Prometheus gauges and the `/network` Overview cards, computed at request time.

- **Permission:** `GuaranteedState:Read`
- **Response:** an object `{rtt_ms, retrans_pct, throughput_bps, reporting, rtt_reporting, online, cooccurrence, available_keys}` where each metric is `{avg, p50, p90, max, n}` **or `null`** when no device reported it this cycle (absent, never 0). `reporting` counts devices contributing at least one metric; `rtt_reporting` is the **honest RTT denominator** (smoothed RTT is Linux-only today, so it is smaller than `reporting`); `online` is the total snapshot population. `cooccurrence` is `{degraded, also_device, also_app, network_only}` — counts of net-degraded devices that also show device-perf pressure / app instability (measured co-occurrence, never a cause; dormant until the degraded classification lands). `available_keys` lists the fleet's tag keys for a cohort-picker UI (parity with the `/network` dashboard fragment and `GET /dex/perf/cohorts`'s `available_keys`). Not audited.

#### `GET /api/v1/network/devices`

The one device list behind every network-quality drill: worst devices by a metric (default), the not-reporting complement, a co-occurrence band, or one cohort's members.

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `metric` (`rtt` / `retrans` / `throughput`, default `rtt`); `filter=not_reporting` (devices with no network sample this cycle); `cooc` (`device` / `app` / `network_only` / `degraded` — a co-occurrence band over net-degraded devices); `key` (cohort tag key — resolves the per-device cohort value; does not filter by itself); `cohort_value` (**when present**, restricts to that cohort; an empty value selects the untagged residual); `limit` (default 50, clamped to 500).
- **Response:** `data[]` of `{agent_id, platform, cohort, rtt_ms?, retrans_pct?, throughput_bps?, net_degraded, under_pressure, app_unstable, fleet_pctile?}`, worst-first by the sort metric (`under_pressure` / `app_unstable` are the co-occurring facts shown inline for correlation, never a verdict; `fleet_pctile` is the device's nearest-rank position, omitted when it did not report the metric). `400` on an invalid `limit`. `403` if a service-scoped API token queries this route (fleet-wide `agent_id` rows, no single agent to confine against — same rationale as `dex/signals/{obs_type}` above).
- **Audit (behavioral PII):** each row is an `agent_id` + its network perf/correlation facts, individual-identifying, fleet-wide — emits **`network.device.view`** (`target_type=GuaranteedState`, `target_id=` empty) before serving. A denied service-scoped token also emits this verb (`result=denied`). **Fail-closed:** if the audit row cannot persist, returns `503` + `Sec-Audit-Failed: true` and serves no device list.

---

### Patch Management

**`GET /api/patches`** — Query missing/installed patches.

- **Permission:** `Patch:Read`
- **Query params:** `agent_id`, `severity`, `status`, `limit` (default 100)

> **Note:** patch inventory is populated only by `PatchManager::record_patches()`, which has no
> production caller today — this endpoint returns an empty result in every real deployment, not
> because the fleet has no missing patches. See `docs/capability-map.md` §8.5/§8.7 and #3676.

**`POST /api/patches/deploy`** — Create a patch deployment targeting specific agents.

- **Permission:** `Patch:Write`
- **Request body:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `kb_id` | string | Yes | — | KB identifier (format: `KBnnnnnnn`) |
| `agent_ids` | string[] | Yes | — | Target agent IDs (max 5000 after de-duplication; a longer list is rejected with `too many target agents`) |
| `reboot_if_needed` | bool | No | `false` | Reboot agents after patching |
| `reboot_delay_seconds` | int | No | `300` | Seconds to wait before reboot (clamped to 60–86400). A desktop notification warns the user before reboot. |
| `reboot_at` | int64 | No | `0` | Optional epoch timestamp for scheduled reboot. Must be in the future. `0` = use delay instead. |

- **Response (201):** `{"deployment_id": "...", "kb_id": "...", "target_count": N, "status": "pending"}`

> **Note:** this creates a deployment record + a `pending` row per target — there is no server-side
> scan/install/verify/reboot orchestration (`PatchManager::execute_deployment()` was removed;
> ADR-0062, `docs/capability-map.md` §8.3/§8.4/§8.6, tracking issue #3669). Nothing advances a
> target past `pending` except `POST /api/patches/deployments/:id/cancel` (→ `cancelled`).
> `reboot_if_needed`/`reboot_delay_seconds`/`reboot_at` are accepted, clamped, and stored, but
> nothing acts on them.

Successful deploys are recorded in the audit log with `action=patch.deploy`, `result=success`.
A validation rejection (invalid KB format, an oversized `agent_ids` list, or a failed
transaction) is recorded with `result=denied` and `detail` carrying the error message — see
`docs/user-manual/audit-log.md`'s `patch.deploy` row for the known gaps (#3705) in this
outcome's granularity.

**`GET /api/patches/deployments/:id`** — Deployment details with per-target status.

- **Permission:** `Patch:Read`
- **Response includes:** `reboot_delay_seconds`, `reboot_at`, and per-target `status` — always `pending`
  or `cancelled` today (the fuller `scanning`/`downloading`/`installing`/`verifying`/`rebooting`/
  `completed`/`failed`/`skipped` vocabulary is reserved by the schema but nothing currently sets
  it). `completed_targets`/`failed_targets` are set once at creation and never recalculated.

**`GET /api/patches/deployments`** — List deployments (paginated, default limit 50).

- **Permission:** `Patch:Read`

**`POST /api/patches/deployments/:id/cancel`** — Cancel a pending/running deployment.

- **Permission:** `Patch:Write`

---

### Settings — OIDC Configuration

**`POST /api/settings/oidc`** — Save OIDC / Entra ID SSO configuration.

- **Permission:** Admin only
- **Request body (form-encoded):**

| Field | Type | Required | Description |
|---|---|---|---|
| `issuer` | string | Yes | OIDC issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`) |
| `client_id` | string | Yes | Application (client) ID from Azure portal |
| `client_secret` | string | No | Client secret value. If empty and a secret already exists, the existing secret is preserved. |
| `redirect_uri` | string | No | Callback URL. If empty, auto-computed from web address/port. |
| `admin_group` | string | No | Entra group object ID for admin role mapping |
| `skip_tls_verify` | string | No | `"true"` to disable TLS cert verification for OIDC endpoints (insecure, dev only) |

- **Response:** Re-rendered Settings fragment (HTMX). Returns toast notification on success.
- **Effect:** Immediately reinitializes the OIDC provider with the new configuration - in THIS process only. The swap is NOT durable: the provider is rebuilt at the next startup from the command-line/environment value, not from the stored runtime config, so a restart reverts to that value. Rotating a credential durably requires updating `--oidc-client-secret` / `YUZU_OIDC_CLIENT_SECRET` as well - see [When a change takes effect](#when-a-change-takes-effect).

**`POST /api/settings/oidc/test`** — Test OIDC discovery connectivity.

- **Permission:** Admin only
- **Request body (form-encoded):** `issuer`, `skip_tls_verify`
- **Response:** HTML feedback span — green on success, red on failure with specific error.

#### `GET /api/v1/settings/oidc`

REST v1 read twin of `GET /fragments/settings/directory` (#4031) — note that despite its legacy fragment path, this is pure OIDC SSO config, **not** the AD/Entra directory-sync feature documented under [Directory Sync](#directory-sync) above. Deliberately gated on a freshly-minted `OidcConfig` securable, never `Directory`, to avoid colliding with that unrelated capability.

**Permission:** `OidcConfig:Read` (Administrator only — matches the previous `admin_fn_` gate)

**MCP:** REST-only — no MCP twin, same #520 exception as the [Enrollment](#enrollment) routes above.

The client secret is **never** disclosed — only a boolean `client_secret_configured` reports whether one is set, matching the existing fragment's own non-disclosure posture (a `********` UI placeholder, never the real value).

Audited (`settings.oidc.view`, non-blocking) — IdP/admin-group configuration carries recon value to an attacker but is not per-person data.

**Response:**

```json
{
  "data": {
    "configured": true,
    "issuer": "https://login.microsoftonline.com/{tenant}/v2.0",
    "client_id": "abcd-1234",
    "client_secret_configured": true,
    "redirect_uri": "https://yuzu.example.com/auth/callback",
    "admin_group": "grp-object-id",
    "skip_tls_verify": false
  },
  "meta": { "api_version": "v1" }
}
```

### Settings — Certificate Management

**`POST /api/settings/cert-upload`** — Upload PEM certificate file.

- **Permission:** Admin only
- **Request body (multipart/form-data):** `type` (cert|key|ca), `file` (.pem/.crt/.cer)

**`POST /api/settings/cert-paste`** — Paste PEM certificate content.

- **Permission:** Admin only
- **Request body (form-encoded):**

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `cert` (server certificate), `key` (private key), or `ca` (CA certificate) |
| `content` | string | Yes | PEM-encoded content (must contain `-----BEGIN`) |

- **Response:** Re-rendered TLS Settings fragment (HTMX). Returns toast notification on success.
- **Effect:** Writes PEM content to the server cert directory. Key files are set to 0600 permissions. Config is updated immediately; HTTPS cert hot-reload will pick up changes within the polling interval.

---

### Settings — Plugin Code Signing

These endpoints drive the **Settings → Plugin Code Signing** card. The four `/api/settings/plugin-signing/*` routes are admin-only HTMX paths that return fragment HTML; the agent-facing distribution endpoint at `/api/v2/agent/plugin-policy` returns JSON (its predecessor `/api/v1/agent/plugin-policy` is deprecated — see below). See *user-manual/agent-plugins.md → Plugin Code Signing* for the operator workflow and *user-manual/server-admin.md → vNEXT* for the upgrade notes. See also [Settings](#settings) below — `/api/v2/agent/plugin-policy` is plugin-signing's REST read-twin (#4028, #4144); it is documented in both places because it predates the Settings read-twins programme and keeps its original path rather than moving under `/api/v1/settings/...`.

**`GET /fragments/settings/plugin-signing`** — Render the Plugin Code Signing card fragment.

- **Permission:** Admin only
- **Response (200):** HTML fragment showing status badge (Disabled / Trust bundle loaded / Enforced), bundle metadata (cert count, SHA-256, up to 16 subjects), upload form, require-flag toggle, and Remove button.

**`POST /api/settings/plugin-signing/upload`** — Upload a PEM trust bundle.

- **Permission:** Admin only
- **Request body (multipart/form-data):** `file` (.pem/.crt; max 256 KB)
- **Validation:** the server validates the PEM with OpenSSL on the way in — at least one parsable X.509 certificate must be present, BEGIN/END markers required.
- **Response (200):** Re-rendered fragment, `HX-Trigger: showToast level=success`. Bundle is written atomically to `<cert-dir>/plugin-trust-bundle.pem` (temp + rename).
- **Response (400):** Validation failure. Body: `<span class="feedback-error">Rejected: …</span>`. Audit row emitted with `result=failure`, `target_type=PluginTrustBundle`, detail = the validation error.
- **Response (500):** I/O failure (cannot create cert dir, write tmp file, or rename to destination). Body: `<span class="feedback-error">…</span>`.

**`POST /api/settings/plugin-signing/clear`** — Remove the trust bundle and reset the require flag.

- **Permission:** Admin only
- **Request body:** None (HTMX hx-confirm)
- **Effect:** Two-phase commit — writes `plugin_signing_required=false` to `runtime_config` first, then removes `<cert-dir>/plugin-trust-bundle.pem`. If the DB write fails the file is **not** removed (prevents disk/DB desync) and a 500 is returned.
- **Response (200):** Re-rendered fragment, `HX-Trigger: showToast level=info`. Audit `plugin_signing.bundle.cleared` / `success`.
- **Response (500):** DB write failure. Audit `plugin_signing.bundle.cleared` / `failure` with the store error in `detail`. Bundle file untouched.

**`POST /api/settings/plugin-signing/require`** — Toggle the require-signature flag.

- **Permission:** Admin only
- **Request body (form-encoded):** `required` = `true`/`on` (checkbox checked) or absent (checkbox unchecked, treated as false).
- **Effect:** Writes `plugin_signing_required=<true|false>` to `runtime_config`.
- **Response (200):** Re-rendered fragment, `HX-Trigger: showToast level=success`. Audit `plugin_signing.require.changed` / `success`, `target_type=RuntimeConfig`, `target_id=plugin_signing_required`, `detail=<new_val>`.
- **Response (500):** DB write failure with the store error.

**`GET /api/v2/agent/plugin-policy`** — Distribution endpoint for operator agent-config flows, and plugin-signing's REST read-twin (#4028, #4144). Returns the current trust bundle PEM and require flag as JSON.

**v1 deprecated.** `GET /api/v1/agent/plugin-policy` predates #4028, is now DEPRECATED, and stays on its original flat-body shape (no `data` envelope, `require_admin` gate instead of `PluginSigning:Read`, no audit row, the old bespoke error shape) — see `server-admin.md`'s vNEXT note for the announced removal window. #4028 originally hardened this route's shape in place; #4144 corrected that into the v1/v2 split below, since an in-place envelope reshape is a breaking change per `docs/api-versioning-policy.md`.

- **Permission:** `PluginSigning:Read` (Administrator-only via the `rbac_store.cpp` seed; floored in `authz_topology_floor.hpp` so an RBAC-off deployment stays admin-gated — the same practical posture the prior admin-only gate had for interactive sessions and non-MCP API tokens). **No MCP token, at any tier, can satisfy this permission** — `PluginSigning` is one of four server-administration securables `mcp_policy.hpp`'s `tier_allows()` denies outright, regardless of Read/Write, so an admin-owned MCP token that would otherwise fall through the legacy role check is stopped before it gets there. The bundle holds X.509 certificates only (no private keys), but the SHA-256 fingerprint and the trust-anchor identity are operationally sensitive — non-admin token holders are not authorized to see when the trust anchor rotates. Future automatic agent-side fetch will introduce a dedicated agent identity for this endpoint.
- **Audit:** fail-closed. `settings.plugin_signing.read` is persisted before the response is built; if the audit subsystem is unavailable the route returns 503 rather than serve settings data without durable evidence.
- **Stability:** pilot-stable. The field set is unlikely to shrink (forward-compatible additions only). `cert_count`/`sha256`/`subjects`/`trust_bundle_pem` are derived from a single filesystem read (#4144) — they cannot describe two different bundle versions on a concurrent-upload race, unlike v1.
- **Response (200, bundle uploaded):**

  ```json
  {
    "data": {
      "enabled": true,
      "required": false,
      "cert_count": 2,
      "sha256": "abc123…",
      "trust_bundle_pem": "-----BEGIN CERTIFICATE-----\nMIIB…\n-----END CERTIFICATE-----\n"
    },
    "meta": {"api_version": "v1"}
  }
  ```

- **Response (200, no bundle uploaded):**

  ```json
  {"data": {"enabled": false, "required": false, "trust_bundle_pem": ""},
   "meta": {"api_version": "v1"}}
  ```

  (Status is 200, not 404 — "no bundle uploaded" is a normal operational state, not a fetch failure.)

- **Response (500, bundle on disk is unreadable):** standard A4 error envelope.

  ```json
  {"error": {"code": 500, "message": "Trust bundle on disk is unreadable",
             "correlation_id": "…", "retry_after_ms": null},
   "meta": {"api_version": "v1"}}
  ```

- **Response (503, audit subsystem unavailable):** same A4 error shape with `code: 503`.

- **Response (503, two further cases, #4028 fix round):** the `required` flag's backing
  `runtime_config_store` read failed (distinguishes a genuine outage from a healthy "not required" —
  see [When a change takes effect](#when-a-change-takes-effect) above: `plugin_signing_required`
  "records intent only," no server or agent code consumes it to require signatures, so a degraded
  read here does not affect real enforcement), or the trust bundle was concurrently
  uploaded/cleared between this request's existence check and its PEM re-read. Both are retryable
  (A4 envelope, `retry_after_ms` set).

- **Operator usage:** curl this into a local file on each agent host, then point the agent at that file with `--plugin-trust-bundle`:

  ```bash
  curl -fsSL -H "Authorization: Bearer $YUZU_ADMIN_TOKEN" \
    https://server.example.com:8443/api/v2/agent/plugin-policy \
    | jq -r .data.trust_bundle_pem > /etc/yuzu/plugin-trust-bundle.pem
  ```

---

### Settings — Multi-Factor Authentication (MFA / TOTP)

These endpoints drive the **Settings → Multi-Factor Authentication** card. They are legacy (no `/v1/` prefix) and return HTMX fragments rather than JSON. All five require an admin session and target `#mfa-section` for swap-in. SOC 2 CC6.6 — see `docs/auth-mfa-design.md`.

**`GET /fragments/settings/mfa`** — Render the MFA card for the logged-in admin.

- **Permission:** Admin only.
- **Response (200):** HTML fragment showing current status (`Not enrolled` / `Enabled` / `Disabled`), recovery codes remaining, and the operative action buttons.

**`POST /api/settings/mfa/init`** — Begin TOTP enrollment.

- **Permission:** Admin only.
- **Effect:** Generates a fresh 20-byte CSPRNG secret and stores it provisionally (`mfa_enrolled_at` stays NULL). Re-running on an already-provisional row rotates the secret; refused if the user is already enrolled (`MfaAlreadyEnrolled` → 200 with error message in the fragment).
- **Response (200):** HTML fragment containing the `otpauth://` URI + base32 secret as a one-time reveal, plus the verify-code form. Response carries `Cache-Control: no-store, private`, `Pragma: no-cache`, and `Referrer-Policy: no-referrer` so browsers / proxies / CDNs cannot retain the material.
- **Audit:** `mfa.enroll.initiated` / `ok` (or `error` on failure).

**`POST /api/settings/mfa/verify`** — Confirm enrollment by submitting the first TOTP code.

- **Permission:** Admin only.
- **Request body (form-encoded):** `code=<6-digit TOTP from authenticator>`.
- **Effect on success:** Sets `mfa_enrolled_at = CURRENT_TIMESTAMP`, advances `mfa_last_counter` to the matched counter (replay defence), generates 10 single-use recovery codes (PBKDF2-SHA256 hashed in `mfa_recovery_codes`).
- **Response (200, success):** HTML fragment with the 10 recovery codes as a one-time reveal (`XXXX-XXXX-XXXX-XXXX`, 80 bits each). Same `Cache-Control: no-store` headers as `init`.
- **Response (200, failure):** Re-renders the verify form with an instruction to wait for the next 30 s code. Provisional row survives so the operator's authenticator app keeps working; the secret is NOT re-revealed.
- **Audit:** `mfa.enroll.verified` + `mfa.recovery_codes.generated` on success; `mfa.enroll.failed` on rejection; `mfa.enroll.race` when a concurrent verify already enrolled the account (benign race, distinct from a rejected code — CC7.2).

**`POST /api/settings/mfa/recovery-codes`** — Regenerate the 10 recovery codes.

- **Permission:** Admin only. Requires existing enrollment.
- **Effect:** Atomic DELETE + 10×INSERT inside a Postgres transaction, serialized on the caller's `auth.users` row (`SELECT … FOR UPDATE`) so two concurrent regenerations cannot interleave (#3779). All prior codes (consumed and unconsumed) are invalidated. If the account has been deactivated, the codes are **not** reissued and the request fails.
- **Response (200):** HTML fragment with the fresh 10 codes as a one-time reveal. Same `Cache-Control: no-store` headers.
- **Audit:** `mfa.recovery_codes.generated` / `ok` (detail = `10 codes issued (rotation)`).

**`POST /api/settings/mfa/disable`** — Clear MFA state for the logged-in admin.

- **Permission:** Admin only.
- **Effect:** Atomic UPDATE users (clears `mfa_totp_secret`, `mfa_enrolled_at`; stamps `mfa_disabled_at`) + DELETE `mfa_recovery_codes` inside a `BEGIN IMMEDIATE / COMMIT` transaction. **Self-target guard (PR 3):** while `--mfa-enforcement` protects the caller's role (`required` → all roles; `admin-only` → admins), the disable is refused — the operator cannot strip the MFA that policy requires of them.
- **Response (200):** HTML fragment showing the "Not enrolled" state, or, when the self-target guard fires, the unchanged "Enabled" fragment with an inline "MFA is required by policy" message.
- **Audit:** `mfa.disabled` / `ok` (or `error` on DB failure, or `error` + detail `blocked: mfa_enforcement=<mode>` when the self-target guard refuses the disable).

> **Note — admin force-disable for other users:** the PR 1 endpoints are self-service only. An admin cannot disable another user's MFA via the dashboard or REST in this release; that feature is planned. For emergency lockout recovery use the break-glass procedure in `docs/ops-runbooks/auth-db-recovery.md` § Emergency MFA disable.

---

### Settings — User Management

These endpoints drive the **Settings → Users** tab. They are legacy (no `/v1/` prefix) and return HTMX fragments rather than the standard JSON envelope. All three require an admin session and the dashboard swaps the response body into `#user-section`.

The handler enforces a **self-target guard** on destructive operations: the currently authenticated operator cannot delete or demote their own account, even via a hand-crafted HTTP request that bypasses the dashboard. See `docs/user-manual/server-admin.md` → "Deleting a User" for the operator-side recovery procedure.

**`GET /fragments/settings/users`**

Render the user table fragment.

- **Permission:** Admin only
- **Response (200):** HTML fragment of the user table. The row matching the caller's session username renders an italic `Current user` badge in place of the Remove button. All other rows include an `hx-delete` attribute targeting the DELETE endpoint below.
- **Response (401):** Returned defensively when the admin gate passes but the session cannot be re-resolved (e.g., concurrent logout). The dashboard should redirect to login.
- **Response (500):** Returned when the resolved session has an empty username — defense-in-depth against an upstream auth misconfiguration (e.g., OIDC returning empty `preferred_username`). Server log records the cause.

**`POST /api/settings/users`**

Create a new local account.

> **Breaking change in v0.12.0:** The `role` field is now **ignored**. New users
> are always created as `user`. To assign or change a role use the dedicated
> `POST /api/settings/users/{username}/role` endpoint documented below — this
> closes security finding C1 (privilege escalation via the role parameter on
> create). Operators that scripted user-create with `role=admin` should expect
> the user to land as `user` and explicitly promote via the role endpoint.

- **Permission:** Admin only
- **Request body (form-encoded):**

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | Yes | Account name. 1-64 chars, alphanumeric + `.` `_` `-` only. |
| `password` | string | Yes | New password. Minimum 12 characters. |
| `role` | string | (ignored) | Field is parsed but discarded; new users always land as `user`. Documented for backwards-compatibility — scripts that pass `role=admin` will not error, but the field has no effect. |

- **Response (200):** Re-rendered user table fragment with the new account visible. `HX-Trigger: {"showToast":{"message":"User created","level":"success"}}`. Audit event recorded as `user.create / success`.
- **Response (400):** Returned when `username` is invalid, `password` is empty, or password is shorter than 12 characters. Audit `user.create / denied / weak_password` (or `invalid_username`).
- **Response (409):** Returned when `username` already exists. Body is the re-rendered user table fragment with the duplicate-username toast. Audit `user.create / denied / duplicate_username`.
- **Response (401):** Defensive — admin gate passed but session not re-resolvable.
- **Response (500):** Defensive — session resolved with empty username.

**`POST /api/settings/users/:username/role`**

Change the role of an existing user. Dedicated endpoint introduced in
v0.12.0 to give role transitions their own audit chain (governance C1).

- **Permission:** Admin only
- **Request body (JSON):**

```json
{ "role": "admin" }
```

The `role` field must be exactly `admin` or `user`.

- **Response (200) success:** Role changed. Body is the re-rendered user table fragment. `HX-Trigger: {"showToast":{"message":"Role updated","level":"success"}}`. Audit `user.role_change / success` with `detail=old_role=user,new_role=admin` (or vice versa). **All active sessions for the target user are invalidated atomically** — the user must re-authenticate.
- **Response (200) no-op:** Same role requested as already assigned. Body is the re-rendered fragment with `HX-Trigger: {"showToast":{"message":"Role unchanged","level":"info"}}`. Audit `user.role_change / no_op` with `detail=same_role={admin\|user}`.
- **Response (400) invalid request:**
  - `invalid_username` — `:username` fails the allowlist (alphanumeric + `.` `_` `-`, 1-64 chars).
  - `invalid_json` — body is not valid JSON.
  - `missing_role` — body has no `role` field, or `role` is not a string.
  - `invalid_role` — `role` value is not `admin` or `user`.

  Each branch emits `user.role_change / denied / <reason>`.

- **Response (403):** Self-target rejected. Body is the re-rendered fragment with `HX-Trigger: {"showToast":{"message":"Cannot change your own role","level":"error"}}`. Audit `user.role_change / denied / self_role_change_blocked`. To demote yourself, create a second admin, log out, log in as the second admin, and use this endpoint to demote the first.

- **Response (404):** `:username` does not match any persisted user. Audit `user.role_change / denied / user_not_found`.

- **Response (500):** AuthDB write failed. Audit `user.role_change / denied / db_failure`.

**Example — promote `bob` to admin:**

```bash
curl -X POST https://yuzu-server:8080/api/settings/users/bob/role \
  -H "Content-Type: application/json" \
  -H "X-Yuzu-Token: yzt_..." \
  -d '{"role":"admin"}'
```

**`DELETE /api/settings/users/:name`**

Delete the named account.

- **Permission:** Admin only
- **Response (200):** Account deleted. Body is the re-rendered user table fragment. `HX-Trigger: {"showToast":{"message":"User deleted","level":"success"}}`. Audit event recorded as `user.delete / success`.
- **Response (400):** `:name` fails the username allowlist (e.g. contains `$`, `:`, or other disallowed bytes). Audit `user.delete / denied / invalid_username`.
- **Response (404):** `:name` does not match any persisted user. Audit `user.delete / denied / user_not_found`. Returned with a `User not found` toast in the re-rendered fragment.
- **Response (403):** Returned when `:name` matches the caller's own session username — the **self-deletion guard**. Body is the re-rendered user table fragment. Header includes:

  ```
  HX-Trigger: {"showToast":{"message":"Cannot delete your own account","level":"error"}}
  ```

  Audit event recorded as `user.delete / denied / self_delete_blocked`. The rejected attempt is logged at warn level on the server. To delete the account you are signed in as, create a second admin, sign out, sign in as the second admin, then delete the original.

- **Response (401):** Defensive — admin gate passed but session not re-resolvable.
- **Response (500):** Defensive — session resolved with empty username.

| HTTP status | Condition |
|---|---|
| 200 | Account deleted successfully |
| 400 | Username failed the allowlist regex |
| 404 | No persisted user matched `:name` |
| 403 | Target equals the caller's own username (self-delete guard) |
| 403 | Caller is not an admin (rejected by admin gate before handler) |
| 401 | Defensive — admin gate / session callbacks disagree |
| 500 | Defensive — session has empty username |

**Example — attempt self-delete (will be rejected):**
```bash
curl -X DELETE https://yuzu-server:8080/api/settings/users/admin \
  -H "X-Yuzu-Token: yzt_..." \
  -v
# HTTP/1.1 403 Forbidden
# HX-Trigger: {"showToast":{"message":"Cannot delete your own account","level":"error"}}
```

---

## Legacy API Endpoints

The following endpoints are under `/api/` (without the `v1` prefix). They predate the versioned API and remain available for backward compatibility. These endpoints return JSON but do not use the standard v1 envelope.

---

### Commands

#### `POST /api/command`

Send a command to one or more connected agents.

**Request body:**

```json
{
  "plugin": "hardware",
  "action": "cpu-info",
  "agent_ids": ["agent-01", "agent-02"],
  "params": {},
  "stagger": 30,
  "delay": 5
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `plugin` | string | Yes | -- | Target plugin name. |
| `action` | string | Yes | -- | Action within the plugin. |
| `agent_ids` | array of string | No | -- | Target agent IDs. **Omit the field** to broadcast. A supplied `[]`, a non-array value, or a non-string entry returns `400` (#2500). |
| `params` | object | No | `{}` | Key-value parameters passed to the plugin. (This table previously named the field `parameters`; the handler has always read `params`, so a client written to the old text silently dispatched with no parameters at all.) |
| `scope` | string | No | -- | Scope expression for device targeting (alternative to `agent_ids`), or `__all__` for every enrolled agent. A supplied `""` or non-string value returns `400` (#2500). |
| `stagger` | integer | No | `0` | Max random delay in seconds per agent before execution. Prevents thundering herd on large-fleet dispatch. `0` = no stagger. |
| `delay` | integer | No | `0` | Fixed delay in seconds per agent before execution. Added before the random stagger. `0` = immediate. Total agent wait = `delay` + random(`0`, `stagger`). |

**Targeting: omitted means everything, supplied-but-empty is an error (#2500).**
Omitting **both** `agent_ids` and `scope` broadcasts to all connected agents, as does an
explicit `"scope": "__all__"`. Supplying either field with a value that names no device is
refused with `400` rather than widened — an empty `agent_ids`, a non-array `agent_ids`, a
non-string entry, an empty `scope`, or a non-string `scope`. Before this, a client emitting
numeric device ids (`"agent_ids": [1,2,3]`) or one whose device filter matched nothing
(`"agent_ids": []`) dispatched to the **entire fleet** and received a success response.

`agent_ids` and `scope` are **alternatives — supply exactly one, or neither.** Supplying
`agent_ids` together with a real `scope` returns `400` (`reason=target_conflict`). They used to
resolve by precedence, with the scope winning and the explicit id list silently discarded, so
`{"agent_ids":["dev-a"],"scope":"tag:prod"}` ran on every device matching `tag:prod` rather than
on `dev-a` — the same "the executed set is not the requested set" defect this section is about,
reached by two selectors disagreeing instead of by one being erased.

The single exception is `"scope": "__all__"` alongside `agent_ids`: `__all__` is the broadcast
*request* rather than a narrowing selector, and the explicit id list wins.

Refusals increment `yuzu_server_dispatch_target_rejected_total{route="command",reason=...}` and
write a `command.dispatch` audit row with `result=denied` and `detail=reason=<reason>`. The body
must be a JSON object; anything else is `400`.

**Destructive-class capabilities require explicit, non-empty `agent_ids` — broadcast and `scope`
fan-out are refused (#3685).** The command catalogue currently classifies 19 `plugin.action` pairs
`Destructive` (e.g. `tar.purge_source`, `filesystem.delete_lines`, `registry.delete_key`); dispatching
any of them with `agent_ids` omitted or empty, or with `scope` present at all — including
`"__all__"` — is refused **before** the command reaches an agent. This is a narrower carve-out
than the general targeting rule two paragraphs above: for an ordinary (non-Destructive) row,
`"scope": "__all__"` supplied alongside `agent_ids` is the one case where the explicit id list
wins and the call proceeds; for a Destructive row, supplying `scope` at all is refused even when
`agent_ids` is also present and non-empty — the `__all__`-alongside-`agent_ids` exemption does
not apply here.

```json
{"error": {"code": 400, "message": "destructive action requires explicit in-scope agent_ids; broadcast and scope fan-out are refused"}, "meta": {"api_version": "v1"}, "audit_emitted": true}
```

**Forensics-class capabilities are SINGLE-TARGET — exactly one explicit, in-scope `agent_id`,
no `scope` (Wave 7 PR7.2).** A row on the `Forensics` securable (e.g. `execution_artifacts.
shimcache`) is `ReadOnly`, not `Destructive`, but a forensic read is per-device by nature: naming
zero ids, more than one id, or any `scope` (including `"__all__"`) is refused before the read
reaches an agent, with its own distinct message:

```json
{"error": {"code": 400, "message": "forensic read requires exactly one explicit in-scope agent_id; broadcast and scope fan-out are refused"}, "meta": {"api_version": "v1"}, "audit_emitted": true}
```

A Forensics read that names its one target confines to the caller's visible agents exactly like
a Destructive row — the 404 `no reachable in-scope agent` body above answers an out-of-group id
the same way.

`audit_emitted` follows this file's usual convention (see `DELETE /api/v1/sessions?username=<name>` above):
present and `false` only when the paired `command.dispatch` audit row failed to persist (the response also
sets `Sec-Audit-Failed: true` in that case), and omitted entirely when no audit store is configured — absent
means no claim, not `false`.

The elevated securable/operation this row's catalogue entry names (per-row, e.g.
`Infrastructure:Delete` for `tar.purge_source`) is checked via `require_permission` **before**
this refusal — a caller lacking the grant gets the ordinary `403` first, preserving the
pre-#3685 403-before-400 ordering. A caller who *is* authorized but named explicit `agent_ids`
is then confined to their currently visible agents (management-group scope); an id list that
confines to nothing returns:

```json
{"error": {"code": 404, "message": "no reachable in-scope agent"}, "meta": {"api_version": "v1"}, "audit_emitted": true}
```

(#2557) This 404 is now counted
(`yuzu_server_dispatch_target_rejected_total{route="command",reason="destructive_no_visible_target"}`)
and audited (`command.dispatch`, `result=denied`, same `audit_emitted` convention as every other
denial on this route) — previously it carried neither, so an incident review of "an operator
tried to dispatch a Destructive action at devices they cannot see" found nothing at all.
Distinct from `destructive_untargeted` above: that reason means the caller named no target at
all; `destructive_no_visible_target` means a non-empty `agent_ids` list WAS supplied, but every
named id fell outside the caller's visible-agent confinement.

A `plugin.action` pair the registry cannot classify (`Unclassified`/`Ambiguous`) is **not**
independently denied by this gate — it falls through to the same dispatch chokepoint that denies
every other unclassified pair, so a classify miss never silently reaches an agent through this
path. Refusals are counted the same way as every other targeting refusal on this route
(`yuzu_server_dispatch_target_rejected_total{route="command",reason="destructive_untargeted"}`)
and audited (`command.dispatch`, `result=denied`).

MCP `execute_instruction` enforces the identical rule (same refusal message, same
`agent_ids`-only requirement) — see `docs/mcp-server.md`. The dashboard exec console
(`POST /api/dashboard/execute`) enforces it too: it refuses the same three shapes — `__all__`,
a `group:<id>` scope, and no target selected at all — with the same two messages, confines an
explicit selection to the operator's visible agents, and counts refusals on
`yuzu_server_dispatch_target_rejected_total{route="dashboard",reason="destructive_untargeted"}`.
Because that surface answers htmx fragments rather than the A4 JSON envelope, its refusal is a
`200` carrying the message in the console's result line, not a `400`/`404`. `POST
/api/instructions/{id}/execute` and MCP `execute_bundle` do not yet enforce this gate.

Scheduled and background dispatch is deliberately **not** covered by it. A schedule targets by
scope expression by construction (it has no `agent_ids`), so a scheduled destructive instruction
keeps working exactly as before; it is gated instead by the schedule's own fire-time
re-verification of the arming principal and, where configured, its approval ticket.

**Response (403): unauthorized dispatch.** Two distinct causes share the `403` status but carry
different messages (#1398) — an incident review can tell them apart from the audit trail's
`detail=reason=<reason>` field alone (`forbidden` vs `approval_required`), even without the
response body.

A plain RBAC denial (the caller holds no grant for the pair's classified securable/operation):

```json
{"error": {"code": 403, "message": "permission denied: Execution:Execute"}, "meta": {"api_version": "v1"}}
```

A caller who *does* hold the grant but is dispatching one of the ~50 `plugin.action` pairs a
compiled `ExecuteGate` marks `AdminOrApproval`/`AlwaysApproval` (e.g. `script_exec.exec`,
`filesystem.delete`, `registry.set_value`), with no approval provenance and no admin role:

```json
{
  "error": {
    "code": 403,
    "message": "approval required for script_exec.exec — this action requires either an admin caller or an approved request; dispatch it via POST /api/instructions/{id}/execute instead, which supports the approval workflow"
  },
  "meta": {"api_version": "v1"}
}
```

The governed path this message points at (`POST /api/instructions/{id}/execute`) supports the
approval workflow this route deliberately does not — `/api/command` mints no approval ticket of
its own (one core-owned approval primitive, ADR-1005). An admin caller, or a caller redispatching
with a redeemed approval ticket via the governed path, is not subject to this denial.

---

### Agents

#### `GET /api/agents`

List all currently connected agents with their metadata (hostname, OS, IP, connected plugins).

---

### Help

#### `GET /api/help`

Returns a catalog of all available plugins and their supported actions, as reported by connected agents.

---

### Instructions

#### `GET /api/instructions`

List instruction definitions stored in the server. Query params: `name`, `plugin`, `type`,
`set_id`, `enabled_only`, `limit`.

**Response (503):** InstructionStore not yet initialized, or a genuine database/lease failure
(ADR-0058) — the list is never silently rendered empty on a degraded store.

#### `GET /api/instructions/{id}`

Get a single instruction definition by ID.

**Response (404):** Unknown id.

**Response (503):** A genuine database/lease failure (ADR-0058), distinct from 404.

#### `POST /api/instructions`

Create a new instruction definition from JSON. The `id` field is optional —
when omitted the server generates a UUID; when supplied it is validated for
uniqueness against existing definitions.

**Permission:** `InstructionDefinition:Write`

**Response (200):** `{"id": "<id>"}` for the newly-created definition.

**Response (400):** Validation error (missing required field, invalid
`approval_mode`, malformed JSON, a request/`parameter_schema`/`visualization_spec`/
`response_templates_spec` body nesting deeper than 32 levels (`kMcpMaxJsonDepth`),
or an `id` under the reserved `mcp.` prefix). Body is `{"error": "<reason>"}`.

The `mcp.` definition-id prefix is **reserved** (#2442): it names MCP approval
tickets, and a definition authored under that prefix could line up with an MCP
tool's canonical arguments (`docs/mcp-server.md` documents the recall's full
match, which also binds origin and submitter). Every authoring route that
accepts an explicit id refuses it — this one, `POST
/api/instructions/yaml`, and `POST /api/instructions/import` — and boot-time
auto-import skips such a definition. Product-pack install is unaffected: it
never carries a declared id through, so the store always assigns one.

The store applies this at **create time**, so an id that predates the rule stays
executable and can still be saved through `PUT /api/instructions/{id}`, because
an update cannot originate an id. Note the dashboard's YAML editor is stricter
than the store here: `POST /api/instructions/yaml` validates a declared id on
every save, so an existing `mcp.`-prefixed definition cannot be edited through
it unless its document omits `metadata.id`.

**Response (409):** Returned when an explicit `id` is supplied that already
exists in the store. Body is
`{"error": "instruction definition '<id>' already exists"}`.
Audit event recorded as `instruction.create / denied / duplicate_id`. To
update the existing definition use `PUT /api/instructions/{id}`.

**Response (503):** Instruction store not yet initialized, or a genuine database/lease failure
(ADR-0058) — distinct from the validation/conflict cases above, and worth a client retry.
Audit event recorded as `instruction.create / error / db_error`.

#### `PUT /api/instructions/{id}`

Update an existing instruction definition.

**Permission:** `InstructionDefinition:Write`

**Response (400):** Validation error (same shape as `POST` above).

**Response (404):** Unknown id. Body is `{"error": "not_found: definition not found: <id>"}`.
Audit event recorded as `instruction.update / denied / not_found`.

**Response (503):** A genuine database/lease failure (ADR-0058) — distinct from 404, and worth
a client retry. Audit event recorded as `instruction.update / error / db_error`.

#### `DELETE /api/instructions/{id}`

Delete an instruction definition.

**Permission:** `InstructionDefinition:Delete`

**Response (200):** `{"deleted": true}`.

**Response (404):** Unknown id. **Breaking change (ADR-0058):** prior to this store's
PostgreSQL migration, a missing id returned `200 {"deleted": false}`; it now returns 404. Any
automation keying off the old `deleted: false` shape must be updated to handle 404 instead.
Audit event recorded as `instruction.delete / denied / not_found`.

**Response (503):** A genuine database/lease failure (ADR-0058) — distinct from 404, and worth
a client retry. Audit event recorded as `instruction.delete / error / db_error`.

#### `GET /api/instructions/{id}/export`

Export an instruction definition in a portable format.

**Response (200) on an unknown id:** `{}` (an empty JSON object, not an error) — pre-existing
behavior, unchanged by ADR-0058; unlike every other route on this store, an unknown id here
returns `200 {}` rather than `404`. Callers must check for an empty body, not a status code,
to detect not-found.

**Response (503):** A genuine InstructionStore database/lease failure (ADR-0058) reading the
definition, distinct from the empty-body not-found case above, and worth a client retry.

#### `POST /api/instructions/import`

Import an InstructionDefinition (JSON envelope). Requires `InstructionDefinition:Write`.

**Signature enforcement** (since #1073 / W7.4 sibling-gap closure): the server rejects unsigned imports by default. Mirrors the [`POST /api/product-packs`](#post-apiproduct-packs) `--allow-unsigned-packs` model — closes the equivalent fleet-RCE surface where an operator with import permission can otherwise publish a definition carrying an arbitrary plugin invocation that dispatches on every targeted agent.

**Signed request body (recommended):**

| Field | Type | Required | Description |
|---|---|---|---|
| `id`, `name`, `type`, `plugin`, `action`, etc. | various | yes | Standard `InstructionDefinition` fields. |
| `yaml_source` | string | yes (when signed) | The verbatim YAML source — this is the signed-content carrier. Every persisted column is derived from it on the canonical path; signing `yaml_source` transitively covers the dispatch. |
| `signature` | string | optional | Hex-encoded Ed25519 signature over `yaml_source`'s bytes. |
| `publicKey` | string | optional | Hex-encoded Ed25519 public key (64 hex chars). |

**Signing rules:**

- `signature` + `publicKey` both present + valid → accepted.
- `signature` + `publicKey` both present + invalid → `400 signature verification failed for instruction — yaml_source may have been tampered with`.
- Exactly one of `signature` / `publicKey` present → `400 instruction-import has incomplete signing metadata — both signature and publicKey must be present together (or both absent)`.
- Neither present, signature enforcement on (default) → `400 instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)`.
- Neither present, signature enforcement off → accepted as **unverified** (operator opt-out via [`--allow-unsigned-definitions`](server-admin.md), emits `server.unsigned_definitions_allowed` audit row at startup).

A failed signature ALWAYS rejects, even when enforcement is off — `--allow-unsigned-definitions` only widens the unsigned-path policy, it does not skip crypto on present signatures.

**Audit:** every import attempt emits `instruction.import` with `result=success` on success, `result=denied` on rejection. The `target_id` is the definition's `id` on success; empty on rejection.

**Response (503):** A genuine database/lease failure (ADR-0058) — audited the same as every
other rejection above, distinct from a signature/validation/conflict `400`/`409`.

#### `POST /api/instructions/yaml`

Create or update an instruction definition from raw YAML source (the dashboard
New Definition panel's Save endpoint). Form-encoded: `yaml_source` carries the
document verbatim (stored as the definition's source of truth); an optional
`id` parameter switches to update mode. Responses are HTML fragments (this is
a dashboard surface), plus an `HX-Trigger` toast header. Requires
`InstructionDefinition:Write`.

The queryable columns are derived schema-aware from the YAML — both the
canonical nested schema and the flat form the panel's structured form
generates are accepted, with this precedence:

| Column | Canonical | Fallback |
|---|---|---|
| id | `metadata.id` (create only; honoured, **409** on conflict) | store-generated |
| name | `metadata.displayName` | `metadata.name`, then `metadata.id` |
| plugin / action | `spec.execution.plugin` / `.action` | `spec.plugin` / `spec.action` |
| approval | `spec.approval.mode` | scalar `spec.approval` (default `auto`) |
| version / type / concurrency | `metadata.version` / `spec.type` / `spec.execution.concurrency` | defaults `1.0.0` / `question` / `per-device` |

On update, a `yaml_source` whose `metadata.id` differs from the `id` parameter
is rejected. Explicit ids must match `[A-Za-z0-9._-]{1,128}`. Save and
validate-yaml share one validation contract — YAML that passes validation
always saves.

**Audit:** emits `instruction.create` / `instruction.update` (`result=success`),
and `instruction.create` with `result=denied` / `duplicate_id` on conflict.

#### `POST /api/instructions/validate-yaml`

Validate YAML against the `yuzu.io/v1alpha1` DSL schema without persisting it.
Requires `InstructionDefinition:Read`. Runs the same validation contract as
the Save endpoint above (required fields, `type`/`approval` enums, explicit
`metadata.id` charset/length, size cap, scope-walking gates), so a document
that validates green is guaranteed to save.

#### `POST /api/instructions/{id}/execute`

Execute an instruction definition by dispatching it to agents. Requires `Execution:Execute` permission.

**Request body:**
```json
{
  "agent_ids": ["agent-uuid-1"],
  "params": {"key": "value"}
}
```

- `agent_ids` (optional) — array of agent IDs to target. **Omit** to broadcast; a supplied `[]`,
  a non-array value, or a non-string entry returns `400` (#2500).
- `scope` (optional) — scope expression (e.g., `group:servers`), or `__all__` for every enrolled
  agent. A supplied `""` or non-string value returns `400`.

> **Behaviour change (#2500).** This endpoint previously documented "empty string + empty
> `agent_ids` = broadcast", and an explicitly empty `agent_ids` did broadcast. It is now `400`.
> **Omit both fields** (or send `"scope": "__all__"`) to target the whole fleet deliberately.
> Refusals increment `yuzu_server_dispatch_target_rejected_total{route="instruction_execute"}`
> and write an `instruction.execute` audit row with `result=denied`. The body must be a JSON
> object; anything else is `400`.
- `params` (optional) — key-value parameters passed to the plugin

**Response (200):**
```json
{
  "command_id": "plugin-hexid",
  "agents_reached": 3,
  "definition_id": "filesystem.exists"
}
```

**Response (202 -- Approval Required):**

Returned when the definition's `approval_mode` is `role-gated` or `always` and the caller does not have direct-execute permission. The execution is queued for approval.

```json
{
  "status": "pending_approval",
  "approval_id": "abc123...",
  "definition_id": "def456..."
}
```

**Errors:** 404 (definition not found), 400 (invalid body), 202 (approval required -- execution queued, not yet dispatched), 403 (workflow blocked by approval-gated instruction and caller lacks execute-bypass permission), 503 (no agents reached or store unavailable).

---

### Instruction Sets

#### `GET /api/instruction-sets`

List all instruction sets.

**Response (503):** InstructionStore not yet initialized, or a genuine database/lease failure
(ADR-0058) — the list is never silently rendered empty on a degraded store.

#### `POST /api/instruction-sets`

Create a new instruction set (a named collection of definitions).

**Permission:** `InstructionSet:Write`

**Response (200):** `{"id": "<id>"}` for the newly-created set. The id is always
server-generated (this route does not accept a caller-supplied `id`), so the `409` case below
is not reachable via normal use of this endpoint today — documented for API-contract
consistency with the sibling `POST /api/instructions` route, not because it fires in practice.

**Response (400):** Validation error.

**Response (409):** A set with that id already exists (gov Gate 4/6, fixed to match
`POST /api/instructions`'s equivalent branch — the response no longer leaks the raw internal
`conflict:` prefix).

**Response (503):** A genuine database/lease failure (ADR-0058).

#### `DELETE /api/instruction-sets/{id}`

Delete an instruction set. Definitions that referenced the deleted set have their
`instruction_set_id` cleared, not deleted.

**Permission:** `InstructionSet:Delete`

**Response (200):** `{"deleted": true}`.

**Response (404):** Unknown id. **Breaking change (ADR-0058):** prior to this store's
PostgreSQL migration, a missing id returned `200 {"deleted": false}`; it now returns 404.

**Response (503):** A genuine database/lease failure (ADR-0058).

**Audit:** `instruction_set.delete` on the 404 (`result=denied` detail `not_found`) and 503
(`result=error` detail `db_error`) branches; the 200 success path is not audited (see the audit
table entry above).

---

### Executions

All seven routes below are management-group confined as of #3789 (`docs/auth-architecture.md`'s
"Fourth migration"): a caller holding `Execution:Read`/`Execute` through a management group only
sees/acts on executions it dispatched itself or that involve at least one agent it can see. A
global grant is unrestricted. An execution outside the caller's visibility and a nonexistent one
return the identical `404` (no existence oracle).

**Response (503):** any of the seven routes returns `503` with `retry_after_ms` on either (a) the
RBAC/management-group store being degraded when a confinement decision must be made
(`require_fleet_read` fails closed, replacing the pre-#3789 flat `403`), (b) the execution tracker
itself being unreadable (`ExecutionTracker`'s `_checked` accessors), or (c) — under a confined
grant only — the caller's session identity failing to resolve after admission, which fails closed
rather than silently falling through to agent-only visibility. Retry after the given interval; a
persistent `503` indicates a store outage, not a permission problem.

#### `GET /api/executions`

**Permission:** `Execution:Read`. List executions. Accepts `definition_id`, `status`, and `limit`
(capped at 500) as query parameters. Under a confined grant, `agents_targeted`/`agents_responded`/
`agents_success`/`agents_failure` are recomputed from only the caller's visible agents.

#### `GET /api/executions/{id}`

**Permission:** `Execution:Read`. Get details of a single execution. Under a confined grant,
`scope_expression` and `parameter_values` are redacted (`"(redacted - confined view)"`) and the
four agent counts are recomputed from only the visible agents; `status`/`dispatched_by`/
`dispatched_at`/`completed_at`/lineage stay truthful. **Response (404):** unknown or
outside-scope id.

#### `GET /api/executions/{id}/summary`

**Permission:** `Execution:Read`. Get an execution summary (counts of targeted, responded,
success, failure agents, `progress_pct`). **Response (404):** unknown or outside-scope id.

#### `GET /api/executions/{id}/agents`

**Permission:** `Execution:Read`. List agents involved in an execution, filtered to the caller's
visible agents under a confined grant. **Response (404):** unknown or outside-scope id.

#### `GET /api/executions/{id}/children`

**Permission:** `Execution:Read`. List child executions spawned from a parent execution. Each
child is independently checked against the caller's visibility — a visible parent does not by
itself disclose a child dispatched by, or targeting, someone else. **Response (404):** unknown or
outside-scope parent id. The underlying query is hard-capped at 100 rows (governance Gate 8
re-review fix, #2146 A2-R1; no caller-visible limit/cursor), with the cap now pushed down TOGETHER
WITH the caller's own visibility scope, before `LIMIT` - a confined caller's cap applies to their
own visible children, not the fleet-wide raw row set. `result_truncated_by_cap: true` is added
alongside `children` when that scoped row set exceeded the cap.

#### `POST /api/executions/{id}/rerun`

**Permission:** `Execution:Execute` AND `Execution:Read` (the mutation's target-visibility check
runs through the Read fleet gate). Re-execute a previously run instruction with the same
parameters and targets. Under a confined grant, every targeted agent must be visible to the
caller — a partially-visible or not-yet-fully-reported execution is refused, with a `404`
(deliberately non-distinguishing from a nonexistent id, to avoid disclosing a hidden cohort). A
global (unconfined) grant is unaffected by this check and keeps the pre-existing `400 {"error":
"original execution not found"}` response for an unknown id. **Escape hatch:** same as `cancel`
below — an execution whose targeted cohort never fully reports can permanently fail the
complete-cohort admission check for a confined caller; a **global** grant is never subject to it.

#### `POST /api/executions/{id}/cancel`

**Permission:** `Execution:Execute` AND `Execution:Read`, same confinement rule as `rerun`.
**Response (404):** unknown execution id (this route no longer reports a false success for a
nonexistent id), outside-scope, or an incomplete/partial target cohort. **Escape hatch:** an
execution whose targeted cohort never fully reports (an agent gone offline mid-run, for example)
can permanently fail the complete-cohort admission check for a confined caller — cancel it with a
**global** `Execution:Execute`+`Execution:Read` grant instead, which is never subject to this
confinement rule.

---

### Schedules

A schedule fires unattended through the background `ScheduleRunner` poller with no
further permission check at fire time — so schedule creation, and re-enabling a
disabled schedule, are the only gates against a Schedule:Write-only principal reaching
fleet-wide command dispatch. Delete and enable/disable are owner-scoped: they only
affect a schedule whose `created_by` matches the caller.

#### `GET /api/schedules`

List schedules. Accepts `definition_id` and `enabled_only` as query parameters. Requires `Schedule:Read`.

#### `POST /api/schedules`

Create a recurring schedule for an instruction definition. Requires **both**
`Schedule:Write` and `Execution:Execute` — a schedule is a fleet-wide command-dispatch
primitive (empty `scope_expression` targets every agent; `requires_approval` defaults to
`false`).

#### `DELETE /api/schedules/{id}`

Delete a schedule you created. Requires `Schedule:Delete`; a schedule created by another
principal is left untouched (reports `deleted: false`, same as a nonexistent id).

#### `POST /api/schedules/{id}/enable`

Enable or disable a schedule you created. Requires `Schedule:Write`; enabling (but not
disabling) additionally requires `Execution:Execute`, since enabling arms the schedule to
fire — an operator can always disable a schedule to stop it even without
`Execution:Execute`.

---

### Approvals

#### `GET /api/v1/approvals/{id}`

Fetch a single approval by id. This is the **A4 `status_url` target**: when an operation is denied with an approval-required envelope, a worker polls this endpoint for the current status rather than re-issuing the gated request. Requires `Approval:Read`. Read-only — it never mutates the approval lifecycle.

**Response (200):** the standard v1 envelope wrapping an `Approval` object:

```json
{
  "data": {
    "id": "…",
    "definition_id": "…",
    "status": "pending",
    "submitted_by": "alice",
    "submitted_at": 1735689600,
    "reviewed_by": "",
    "reviewed_at": 0,
    "review_comment": "",
    "scope_expression": "tag:prod"
  },
  "meta": { "api_version": "v1" }
}
```

`status` is one of `pending` | `approved` | `rejected` | `expired`. The response always carries an `X-Correlation-Id` header.

**Errors:** `404` (no approval matches the id — A4 envelope), `503` (approval store not initialised — A4 envelope with `retry_after_ms: 5000`).

#### `GET /api/v1/approvals`

REST v1 twin of the legacy unversioned `GET /api/approvals` below and the widened MCP `list_pending_approvals` tool. This route, the single-fetch `GET /api/v1/approvals/{id}` route, and MCP `list_pending_approvals` share one JSON-row builder (`approval_row_json`) so those three cannot drift from each other; the legacy route below is a separate, unmigrated implementation that emits the same field set today by convention, not by construction. **Permission:** bare `Approval:Read` — approval requests carry no per-agent axis for the ADR-0017 admit-then-filter `fleet_read_fn` chokepoint to confine against (same rationale as `GET /api/v1/schedules` above), so this list is fleet-wide for anyone holding the permission; a reviewer approving or rejecting a ticket needs to see the ticket's full `scope_expression` to make that decision, so confinement-filtering this list would break the maker-checker function itself. Accepts `status` and `submitted_by` query parameters, same as the legacy route. **Omitting `status` returns ALL statuses** — unlike MCP `list_pending_approvals`, which defaults to `pending`-only when its own `status` argument is omitted; a caller wiring both a REST dashboard and an MCP agent against the same queue with no filter gets two different result sets. A supplied `status` outside `pending`/`approved`/`rejected`/`expired` is rejected with `400` (governance fix — previously silently produced an empty result, indistinguishable from a genuinely empty match). The underlying query is hard-capped at 100 rows (no caller-visible limit/cursor); `pagination.result_truncated_by_cap` is added when more than 100 approvals match, so `pagination.total` is never presented as the true match count.

**Response (200):**

```json
{
  "data": [
    {
      "id": "…",
      "definition_id": "…",
      "status": "pending",
      "submitted_by": "alice",
      "submitted_at": 1735689600,
      "reviewed_by": "",
      "reviewed_at": 0,
      "review_comment": "",
      "scope_expression": "tag:prod"
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

**Errors:** `400` (invalid `status` value); `503` (a genuine store failure, never a false empty list — A4 envelope, `retry_after_ms: 5000` on a transient failure such as pool exhaustion, `retry_after_ms: null` — will NOT clear on retry — on a permanent one such as schema drift or disk-full).

#### `GET /api/v1/approvals/pending/count`

REST v1 twin of the legacy unversioned `GET /api/approvals/pending/count` below and the new MCP `get_pending_approval_count` tool. Requires `Approval:Read`.

**Response (200):**

```json
{
  "data": { "count": 3 },
  "meta": { "api_version": "v1" }
}
```

**Errors:** `503` (a genuine store failure, never a false zero count — A4 envelope, `retry_after_ms: 5000` on a transient failure such as pool exhaustion, `retry_after_ms: null` — will NOT clear on retry — on a permanent one such as schema drift or disk-full).

#### `GET /api/approvals`

List approvals. Accepts `status` and `submitted_by` as query parameters. Response shape:
`{"approvals": [...]}` — a bare array under one key, not the v1 `{data, pagination, meta}`
envelope above. **Not migrated onto the checked read path**: on a genuine Postgres failure this
route silently returns `{"approvals": []}` — indistinguishable from a real empty queue — rather
than a `503`; prefer `GET /api/v1/approvals` or MCP `list_pending_approvals` for failure-honest
polling. `status` is validated against the same enum as the v1/MCP twins — an unrecognized value
is rejected with `400` (#2146 A2-R4).

#### `GET /api/approvals/pending/count`

Return the count of instructions awaiting approval. Response shape: bare `{"count": N}`, not the
v1 `{data, meta}` envelope above. **Not migrated onto the checked read path**: on a genuine
Postgres failure this route silently returns `{"count": 0}` — indistinguishable from a genuinely
empty queue — rather than a `503`; prefer `GET /api/v1/approvals/pending/count` or MCP
`get_pending_approval_count` for failure-honest polling.

#### `POST /api/approvals/{id}/approve`

Approve a pending instruction execution.

#### `POST /api/approvals/{id}/reject`

Reject a pending instruction execution.

---

### Audit (Legacy)

#### `GET /api/audit`

Query audit events. Legacy route — **not** merely `GET /api/v1/audit` without
the v1 envelope; the response shape and accepted parameters both genuinely
differ. Accepts `principal`, `action`, `target_type`, `target_id`, `since`,
`until`, `limit`, and `offset` (more than the v1 route's `limit`/`principal`/
`action`). Response is `{"events": [...], "count": N, "total": <number-or-
null>}` (field names `events`/`count`/`total`, not v1's `data`/`pagination`/
`meta`), and each event row additionally carries `id`, `principal_role`, and
`source_ip`, which v1's row shape omits. `total` is a best-effort second read
taken after the page itself succeeds — it is `null`, not `0` or the page
size, when that second read degrades; do not treat `null` as "unknown but
probably zero".

**Errors:** `403` — caller lacks `AuditLog:Read`; `400` — a `since`/`until`/
`limit`/`offset` query parameter is not a valid integer, or `limit < 1` /
`offset < 0`; `503` — the audit store is closed, or the page-rows query
degraded (ADR-0040 deny-on-degrade; never a false-empty `200`).

---

### Scope Engine

#### `POST /api/scope/validate`

Validate a scope expression without executing it.

**Request body:**

```json
{
  "expression": "os = 'windows' AND tag:environment = 'production'"
}
```

#### `POST /api/v1/scope/validate`

Versioned twin of the legacy route above (#2146 Batch B2) — and of the MCP
`validate_scope` tool. All three call the same `yuzu::scope::validate()`, so
none of them can silently diverge on what counts as a valid expression.

**Permission:** Session-authenticated only — no RBAC gate (a syntax-only
check with no data disclosure), matching the legacy route and `validate_scope`
exactly.

**Request body:** same shape as the legacy route above.

**Response:** `{"data": {"valid": true, "expression": "..."}, "meta": {"api_version": "v1"}}`, or
`{"data": {"valid": false, "error": "..."}, "meta": {"api_version": "v1"}}` for a syntactically invalid
expression (still a `200` — the *response* reports validity, the request itself is well-formed).

**Errors:**

| Status | Reason |
|---|---|
| 400 | `expression` missing or empty |

#### `POST /api/v1/scope/preview`

Versioned twin of the MCP `preview_scope_targets` tool (#2146 Batch B2) — no
legacy unversioned twin exists (`POST /api/scope/estimate` below is a
*different* capability: a matched/total **count** only, for the workflow
builder's own confined `scope_fn`). Both this route and `preview_scope_targets`
call the same `preview_scope_targets()` builder (`scope_preview.hpp`), so the
matched-agent set cannot drift between transports. A `tag:<key>` atom in the
expression resolves from the persistent tag store **only** — unlike a real
dispatch, which also falls back to a connected agent's own live self-report —
see [Tag source precedence](../asset-tagging-guide.md). **`from_result_set:<id>`
and `props.*` atoms are not resolved by this preview** - the resolver only
populates `os`/`arch`/`hostname`/`agent_version`/`tag:*`, so any other atom
(including `from_result_set:`, this feature's own headline scope-walking
primitive) is treated as unset and never matches, silently returning
`matched_count: 0` for a composed expression that uses one - a genuine
dispatch resolves `from_result_set:` correctly (`agent_registry.cpp`). Do not
rely on this preview for an expression containing `from_result_set:` or
`props.`; tracked in `#4307`.

**Permission:** `Infrastructure:Read`, via the admit-then-filter fleet-read
chokepoint (ADR-0017) — this route discloses agent identities, unlike the
syntax-only validate route above, so a management-group-confined caller's
`matched_agents`/`matched_count` are narrowed to their own visible devices
before the preview builder runs, never the whole fleet.

**Request body:** `{"expression": "..."}`

**Response:**

```json
{
  "data": {
    "expression": "os = 'windows'",
    "matched_count": 42,
    "matched_agents": ["agent-001", "agent-002"],
    "warning": "scope matches 63 agents (>50). Phase 2 write operations targeting this scope will require approval."
  },
  "meta": { "api_version": "v1" }
}
```

`warning` is present only above the 50-agent display threshold.

**Errors:**

| Status | Reason |
|---|---|
| 400 | `expression` missing/empty, or fails to parse/validate |
| 503 | The expression references a `tag:<key>` atom and the bulk tag-store preload degraded (`retry_after_ms: 5000`) — never silently under-reports the match set |

#### `POST /api/scope/estimate`

Estimate how many agents match a scope expression.

**Request body:**

```json
{
  "expression": "os = 'windows' AND tag:environment = 'production'"
}
```

A `from_result_set:<id-or-alias>` reference in the expression is resolved against the authenticated principal's owned result sets before the estimate is computed (see the [scope DSL §9.3](../yaml-dsl-spec.md)). An alias that resolves to an absent, expired, or unowned set counts as zero members.

---

### Data Export

#### `POST /api/export/json-to-csv`

Convert a JSON result set to CSV format for download.

---

### Responses

#### `GET /api/responses/{id}`

Get command responses for a specific command ID.

#### `GET /api/responses/{id}/aggregate`

Aggregate response data for a command (counts, summaries).

#### `GET /api/responses/{id}/export`

Export response data in CSV format.

**Confined (#1634).** All three readers are gated by `require_fleet_read` (ADR-0017 admit-then-filter) — a management-group-confined operator is admitted and sees only their in-scope agents' rows, real cross-operator isolation rather than the earlier inert per-row filter. `/export` and the catch-all GET push the visible-agent set into the underlying SQL query before `LIMIT`/`OFFSET` (ADR-0017 INV-3), so a confined caller's page reflects only their own visible rows. All three now share ONE gate's failure posture: a **null/unopened response store** returns `503`; an **open but corrupt RBAC store** fails **closed** with `403` (`rbac_enforcement_in_effect` holds, so `require_fleet_read`'s underlying permission check denies rather than falling through to the legacy read path) — for all three readers alike, not the differentiated no-rows-vs-503 split of the pre-migration gate. Scripted/Grafana consumers that start receiving `503`/`403` after an upgrade should check `/readyz` and the server log for `RbacStore` open/migrate errors.

---

### Tags (Legacy)

#### `GET /api/tags`

Get tags for an agent. Requires `agent_id` query parameter. Returns tags as an array of `{key, value, source, updated_at}` objects (different format from the v1 envelope).

#### `POST /api/tags/set`

Set a tag on an agent. Request body: `{"agent_id": "...", "key": "...", "value": "..."}`. A
service-scoped token cannot set the `service` key on any agent -- `403` (#3289); see
[Service-Scoped Tokens](authentication.md#service-scoped-tokens).

#### `POST /api/tags/delete`

Delete a tag from an agent. Request body: `{"agent_id": "...", "key": "..."}`. A service-scoped
token cannot delete the `service` key on any agent -- `403` (#3289).

#### `POST /api/tags/query`

Query agents that have a specific tag. Request body: `{"key": "...", "value": "..."}`. Returns `{"agents": [...], "count": N}`.

**Storage failure (all four legacy routes):** a degraded tag store returns `503`
(`{"error":{"code":503,"message":"tag store unavailable"}}`) instead of an empty
result or a false success (ADR-0050). Unlike the v1 `DELETE`, `POST /api/tags/delete`
has **no 404** — a not-found tag remains `200 {"deleted": false}`; only the
store-degrade path is new. `POST /api/tags/set` previously returned `200
{"status":"ok"}` even when the write failed; it now returns `400` (validation) or
`503` (store degrade) honestly.

---

### Inventory (Legacy)

Requires `Inventory:Read` (global — not per-agent/management-group scoped; every caller
holding the permission sees fleet-wide data, unlike the confined `Responses` routes above).
Predates, and is distinct from, `/api/v1/inventory/*` (§ above) — the v1 routes cover the
same three operations (`tables`, `{agent_id}/{plugin}`, `query`) wrapped in the standard A4
envelope; prefer the v1 surface for new integrations. These legacy routes retain their
historical, non-A4 response shapes and remain live for existing callers.

#### `GET /api/inventory/tables`

List available inventory data types across the fleet: `{"tables": [{"plugin", "agent_count",
"last_collected"}, ...], "count": N}`.

#### `GET /api/inventory/{agent_id}/{plugin}`

Get the most recent inventory record for one agent+plugin pair: `{"agent_id", "plugin",
"data", "collected_at"}`. `data` is the plugin's raw collected payload, parsed as JSON when
valid, else returned as a raw string. `404` if no record exists for that agent+plugin pair.

#### `POST /api/inventory/query`

Query inventory records across agents. Request body (all fields optional):
`{"agent_id": "...", "plugin": "...", "since": <epoch>, "until": <epoch>, "limit": N}`.
`limit` is capped at 1000 regardless of the requested value. Returns `{"results": [...],
"count": N, "result_truncated_by_cap": bool, "results_excluded_by_poison": N}`.
`result_truncated_by_cap` is `true` when more matching rows existed than `limit`
allowed; `results_excluded_by_poison` (#4496) is the count of matching rows
excluded because their stored `data_json` nested past the JSON depth guard (a
poisoned/over-nested row), emitted unconditionally (`0` when none were
excluded) so a short `count` can never be mistaken for "nothing else
matched": the two truncation causes are otherwise indistinguishable from the
response alone.

**Storage failure (all three routes):** a null/unopened inventory store returns `503`
(`{"error":{"code":503,"message":"inventory store not available"}}`); a store that opens
but degrades mid-call also returns `503` (`"inventory store degraded"`) — distinct from the
`404` on `GET /{agent_id}/{plugin}`, which means the store answered but the record doesn't
exist. `POST /query` returns `400` on a malformed request body.

---

### Analytics and NVD

#### `GET /api/me`

Returns current user info (legacy version; prefer `/api/v1/me`).

#### `GET /api/analytics/status`

Requires `Infrastructure:Read`. Returns the status of the analytics event pipeline:
`{"enabled":true,"pending_count":N,"total_emitted":N}`, or `{"enabled":false,"pending_count":0,"total_emitted":0}`
when analytics collection is disabled (`--no-analytics`). Degrade-distinguishable (ADR-0049): a
Postgres read failure returns `503` — `{"error":{"code":503,"message":"analytics store degraded"},"meta":{"api_version":"v1"}}`
— rather than a possibly-inaccurate `200`.

#### `GET /api/analytics/recent`

Requires `Infrastructure:Read`. Returns recent analytics events. Accepts `limit` as a query
parameter (default 50). `{"events":[...],"count":N}` on success, `{"events":[],"count":0}` when
analytics collection is disabled. Degrade-distinguishable (ADR-0049): a Postgres read failure
returns `503` with the same envelope shape as `/api/analytics/status` above, rather than a
possibly-inaccurate `200`.

#### `GET /api/nvd/status`

Returns the status of the NVD (National Vulnerability Database) sync.

Response fields: `enabled`, `syncing`, `last_sync_time`, `last_error`,
`total_cves`, `backfill_complete`, and `backfill_oldest_published`.
`enabled` reflects whether NVD **sync** is configured on (i.e. `--no-nvd-sync` was
*not* passed) — not merely whether the local mirror DB is open. Under `--no-nvd-sync`
the mirror stays queryable (`/api/nvd/match` still works against seeded/previously-synced
data) but `enabled` is `false` and `POST /api/nvd/sync` returns an error. Only `enabled`
and `total_cves` are guaranteed present; the sync-progress fields (`syncing`,
`last_sync_time`, `last_error`, `backfill_complete`, `backfill_oldest_published`) are
omitted when sync is disabled, and the whole body is `{"enabled":false}` when the mirror
DB is closed.
**`total_cves` is a count of distinct CVEs** in the local store.
(Prior to the CPE-range-matching change it counted one row per affected
product, so a multi-product CVE inflated the figure — after upgrade the number
reads lower even once fully synced, and reads near-zero briefly after the
one-time schema migration until the next sync repopulates the mirror. This is
expected, not data loss.)

`backfill_complete` (boolean) reports whether the newest-first catalog backfill
has reached its configured floor **and the catalog holds real NVD-sourced CVEs** —
the built-in fallback rules seeded at startup do **not** count, so `total_cves` can
be non-zero while `backfill_complete` is still `false`. A mirror with no NVD CVEs is
never reported complete, so a fresh or rate-limited deployment (or one whose upstream
NVD fetches have not yet returned data) shows `false` with the cursor at the floor
until real NVD data lands. That is expected, not a stall.
`backfill_oldest_published` (ISO 8601 string)
is the progress cursor — the `published` date of the oldest CVE fetched so far,
walking backwards. During the initial backfill `total_cves` climbs continuously
and `last_sync_time` advances after **every** successful fetch window — so a
non-empty `last_sync_time` does **not** mean the mirror is complete. Use
`backfill_complete` (with the `backfill_oldest_published` cursor for progress) as
the authoritative "initial mirror built" signal, not `last_sync_time`.

`last_error` (string, present only while sync is enabled) surfaces the most recent
sync-health problem and is cleared at the start of the next sync tick — a non-empty
value is a transient, self-healing condition, not a product bug. Values you may see:
a transient fetch failure (`NVD backfill fetch failed (<reason>) — retrying (mirror
incomplete)` or `NVD freshness fetch failed (<reason>) — retrying`, where `<reason>` is
one of `connection`/`http_429`/`http_403`/`http_other`/`parse` — cleared once a fetch
succeeds; a persistent `http_403` means a bad/revoked `--nvd-api-key`, so rotate it, and
`http_429` is expected rate-limiting that self-heals via backoff); a local persist failure
(`NVD backfill window persist failed — mirror
incomplete` / `NVD freshness window persist failed` — a disk/DB issue; the mirror holds
its cursor and stays `backfill_complete: false` rather than dropping the fetched CVEs);
a prolonged upstream outage (`NVD returning empty responses — mirror not populated`); and
re-confirmation of a suspicious empty window (`re-confirming a suspicious empty NVD window
(n/N)` — an older published-date window returned empty *after* real data had already
landed; the backfill holds, staying `backfill_complete: false`, and re-checks it before
trusting it, so a stale cache/proxy serving an empty page can't make it skip a populated
range and falsely report complete).
These are operational states, not product bugs — the mirror recovers automatically
once the underlying condition clears.

#### `POST /api/nvd/sync`

Trigger a manual NVD database sync. Requires `Infrastructure:Execute` (held by Administrator
and ITServiceOwner, not Administrator alone). Runs asynchronously and returns immediately.

#### `POST /api/nvd/match`

Match installed software against known CVEs in the NVD database. Matching
evaluates full CPE version ranges (`versionStartIncluding/Excluding`,
`versionEndIncluding/Excluding`, exact and wildcard). Product identity is
matched by name (case-insensitive); vendor-precise CPE identity is a planned
enhancement (ADR-0018), so name-collision false positives are possible.
In each match, `fixed_in` carries the range's **exclusive upper bound**
(`versionEndExcluding`) when present; it is empty for inclusive-end, exact,
or wildcard matches — empty means "no fix boundary derivable from the range
shape", not "no fix available". Distro revision markers (e.g. Debian `~` in
`1.0.0~deb1`) are compared as plain separators rather than pre-release
markers, so distro-backported versions can produce false negatives until
backport-aware matching (M1b/OVAL) lands.

---

### SSE Event Stream

#### `GET /events`

Server-Sent Events stream for real-time dashboard updates. Events include agent connections/disconnections, command responses, and system notifications.

**Example (curl):**

```bash
curl -N -H "Cookie: yuzu_session=abc123" https://yuzu.example.com/events
```

**Event format:**

```
event: agent_connected
data: {"agent_id":"agent-01","hostname":"web-server-01"}

event: command_response
data: {"agent_id":"agent-01","command_id":"cmd-abc","status":"COMPLETED"}
```

#### `GET /sse/executions/{id}`

Per-execution Server-Sent Events stream introduced in v0.12.0. Backs the
inline drawer's live updates on the **Instructions → Executions** tab.

- **Permission:** `Execution:Read` (RBAC) or admin role
- **`{id}`:** the execution id returned by `POST /api/instructions/:id/execute` or visible in the executions list (regex: `[A-Za-z0-9_-]{1,128}`).
- **Content-Type:** `text/event-stream`
- **Headers:** `Cache-Control: no-cache`, `X-Accel-Buffering: no` (so reverse proxies don't buffer the stream into chunks).

**Management-group confinement (#1634).** Gated by `require_fleet_read`/`fleet_read_fn` (ADR-0017 admit-then-filter), not a flat global `Execution:Read` check — a management-group-confined operator is admitted and then sees only their in-scope agents' events. The caller who **dispatched** the execution is always admitted to the stream (visibility only — avoids a false 404 on a just-dispatched execution with zero responses yet), but that ownership never bypasses the per-event redaction below. RBAC-off → unrestricted (legacy-open). **This gate is evaluated once, at subscribe time** — it is not re-checked for the life of the connection. If your scope is narrowed, or your session is revoked, mid-stream, an already-open subscription is not automatically disconnected (tracked: #3788); a full server restart is the only thing that currently drops every live stream.

**Reconnect / replay:** the server keeps a per-execution ring buffer of up to 1000 events covering ~30 seconds of activity. Browsers' `EventSource` automatically sends `Last-Event-ID` on reconnect; the server replays events whose monotonic id is greater than that value before resuming live publication.

**Cross-replica delivery (HA WS-2a-2).** On a multi-replica HA deployment, events that originate on another server replica are delivered onto this replica's live stream by a ~2s cross-replica poll, so a subscriber sees live progress driven from any replica; this delivery is at-least-once (a duplicate may be re-sent, never dropped). The `id:` field is unchanged — it stays a per-channel monotonic value assigned in publish order, so `Last-Event-ID` / `?since` reconnect works exactly as before on the replica you are connected to. Reconnect *across* replicas after a failover is not yet loss-free — see `docs/executions-history-ladder.md`. Single-replica deployments are unaffected.

**Event types:**

| Event | Emitted on | Payload (JSON in `data:`) |
|---|---|---|
| `agent-transition` | One per agent state change (`update_agent_status` write) | `AgentExecStatus` snapshot — `agent_id`, `status`, `exit_code`, `duration_ms`, `error` |
| `execution-progress` | Every `refresh_counts` recompute | counts snapshot — `total`, `succeeded`, `failed`, `running`, `pending` |
| `execution-completed` | Crossing the all-agents-responded threshold OR `mark_cancelled` | terminal status — `{"status":"succeeded"\|"completed"\|"cancelled"}`. Client should close the EventSource after this event. |

**Confined-subscriber event projection (#1634).** A management-group-confined subscriber (not the execution's dispatcher) does not receive the raw event stream verbatim — a shared projector (`execution_event_scope.hpp`) applies one of three treatments per event, so a subscriber can never learn about agents outside their visible set:

| Event | Confined treatment |
|---|---|
| `agent-transition` | Filtered by `agent_id` — only transitions for agents in the caller's visible set are forwarded; others are silently dropped. |
| `execution-progress` | Dropped entirely — the counts snapshot is execution-wide and carries no `agent_id` to filter by, so it cannot be safely narrowed. |
| `execution-completed` | Sanitized, not dropped — the real terminal `status` is preserved (so the client still knows to close its stream) but nothing else is added. |

**Status-code map:**

| HTTP status | Condition |
|---|---|
| 200 | Stream attached; events follow |
| 401 | No session / token |
| 403 | RBAC `Execution:Read` denied |
| 404 | `{id}` does not exist in the execution tracker, **or exists but is not visible within the caller's management-group scope** — the two are deliberately indistinguishable (no existence oracle, #1634) |
| 410 | Execution is already in a terminal status (succeeded / completed / cancelled / failed). Tells `EventSource` to stop reconnecting. |
| 429 | Shared held-open-stream budget exhausted (ADR-0034). Body is plain text (`too many live streams open — close a tab and retry`) with a `Retry-After: 5` header — note this surface predates the A4 envelope and does not use it. |
| 503 | The per-execution event bus is not configured (test harness opt-out, or a configuration path that omits the bus). Returned at request time so the operator does not silently freeze waiting on a missing publisher. |

This stream holds an HTTP worker thread for as long as the drawer stays open, so it leases
from the **same** `--max-sse-streams` budget as `GET /mcp/v1/`, MCP streamed POST,
`GET /api/v1/events`, and the legacy `/events` stream (ADR-0034). That means enough open
drawers — or enough traffic on any of the other surfaces — can cause a *new* drawer to be
refused with `429`. A live stream is never evicted to make room.

**Audit:** every successful subscribe emits one `execution.live_subscribe` audit event (`target_type=Execution, target_id={id}, result=success`). A subscribe request against an execution that is genuinely nonexistent OR merely out of the caller's scope (the 404 case above) also emits a `result=denied` row on the same action, using non-distinguishing detail text — the two cases must remain audit-indistinguishable, matching the response HTTP status. Per-session-per-execution dedup is **not** currently implemented (#700) — operators on the SOC 2 evidence chain receive a row per reconnect; the forensic-grade audit on first-load remains on `/fragments/executions/{id}/detail`'s `execution.detail.view`.

**Example (curl):**

```bash
curl -N -H "Cookie: yuzu_session=abc123" \
  https://yuzu.example.com/sse/executions/exec-abc123
```

**Example output (running execution, two agents, one in progress):**

```
event: agent-transition
id: 1
data: {"agent_id":"a-1","status":"running","exit_code":null,"duration_ms":null}

event: agent-transition
id: 2
data: {"agent_id":"a-1","status":"success","exit_code":0,"duration_ms":4218}

event: execution-progress
id: 3
data: {"total":2,"succeeded":1,"failed":0,"running":1,"pending":0}

event: agent-transition
id: 4
data: {"agent_id":"a-2","status":"success","exit_code":0,"duration_ms":5102}

event: execution-progress
id: 5
data: {"total":2,"succeeded":2,"failed":0,"running":0,"pending":0}

event: execution-completed
id: 6
data: {"status":"succeeded"}
```

#### `GET /api/v1/events`

Agentic-first JSON SSE channel introduced in sprint W5.1 (2026-05-18). This is the sibling of `/sse/executions/{id}` aimed at **external LLM-driven workers** (Claude, GPT, in-house) rather than a browser EventSource. Both routes subscribe to the same per-execution `ExecutionEventBus` and emit the same event taxonomy; the differences are:

- **`/api/v1/events`** wraps every event in a structured JSON envelope so the worker can discriminate events without out-of-band context.
- **A4 error envelope** on every 4xx/5xx — `correlation_id`, optional `retry_after_ms`, optional `remediation`.
- **No fragment rendering** — pure machine-consumable JSON.

The browser-oriented `/sse/executions/{id}` route is preserved for the dashboard drawer and is unchanged.

**Permission:** `Execution:Read`.
**Auth:** Bearer token, `X-Yuzu-Token` header, or session cookie. Same auth surface as every other `/api/v1/*` endpoint.

**Management-group confinement (#1634).** Gated by `require_fleet_read`/`fleet_read_fn` (ADR-0017 admit-then-filter), not a flat global `Execution:Read` check — a management-group-confined operator is admitted and then sees only their in-scope agents' events. The execution's dispatcher is always admitted to the stream (visibility only — avoids a false 404 on a just-dispatched execution with zero responses yet), never a bypass of the per-event redaction below. RBAC-off → unrestricted (legacy-open). This route shares one event projector (`execution_event_scope.hpp`) with the dashboard's `/sse/executions/{id}` sibling — see that section for the drop/sanitize table (`agent-transition` filtered by `agent_id`, `execution-progress` dropped, `execution-completed` sanitized to `status` only), and for the same subscribe-time-only gate staleness caveat (tracked: #3788) — this route shares that gap.

**Required query parameter:**

| Parameter | Type | Description |
|---|---|---|
| `execution_id` | string `[A-Za-z0-9_-]{1,128}` | Execution to subscribe to. Multi-execution / `?filter=execution_id:X\|agent_id:Y` syntax is sprint W5.2. |

**Optional replay parameters:**

| Parameter | Type | Description |
|---|---|---|
| `since` (query) | integer ≥ 0 | Replay events with `id > since`. Overrides `Last-Event-ID`. Non-integer values silently degrade to 0 (no replay) — mirrors the dashboard sibling. |
| `Last-Event-ID` (header) | string | Browser EventSource auto-reconnect header. Used only when `?since` is absent. |

**Event envelope (every `data:` line):**

```json
{
  "execution_id": "exec-abc",
  "event_id": 12,
  "timestamp_ms": 1716000000000,
  "type": "agent-transition",
  "payload": {"agent_id": "a-1", "status": "success", "exit_code": 0}
}
```

The `type` field is the canonical taxonomy: `agent-transition`, `execution-progress`, `execution-completed` (real bus events) plus three synthetic types the worker should handle:

| Synthetic type | When emitted | Meaning |
|---|---|---|
| `heartbeat` | Every ≤3s of provider idle | Liveness check; `data:` is empty. Workers should ignore. |
| `replay-gap` | First frame on reconnect if the ring buffer has evicted events with `id ≤ since` | Worker missed events `[missing_from..missing_to]` — state may be inconsistent. Payload: `{execution_id, type:"replay-gap", missing_from, missing_to}`. |
| `events-dropped` | Per-connection queue cap (500) was exceeded | A burst of events was dropped from THIS connection (not the bus). Payload: `{execution_id, type:"events-dropped", dropped_count, reason}`. Reconnect with `?since=<last_id>` to re-read what was dropped (subject to the bus ring-buffer window). |

**Status-code map and error envelope:**

| HTTP | Body | Condition |
|---|---|---|
| 200 | SSE stream begins | Stream attached, events follow |
| 400 | A4 envelope | Missing or malformed `execution_id` |
| 401 | (auth layer) | No session / token |
| 403 | (perm layer) | RBAC `Execution:Read` denied |
| 404 | A4 envelope | Execution does not exist, **or exists but is not visible within the caller's management-group scope** — deliberately indistinguishable (no existence oracle, #1634) |
| 410 | A4 envelope | Execution already terminal |
| 429 | A4 envelope with `retry_after_ms:5000` | Shared held-open-stream budget exhausted (ADR-0034). Remediation text: `close an existing /api/v1/events stream, or raise --max-sse-streams` |
| 503 | A4 envelope with `retry_after_ms:5000` | Tracker or event bus not initialised (server warmup window) |

This endpoint holds an HTTP worker thread open for the life of the subscription, so it
leases from the **same** `--max-sse-streams` budget as `GET /mcp/v1/`, the dashboard
executions drawer, MCP streamed POST, and the legacy `/events` stream (ADR-0034). A cap hit rejects the
*new* stream with `429` — a live stream is never evicted to make room.

A4 envelope shape:

```json
{
  "error": {
    "code": 503,
    "message": "event bus unavailable",
    "correlation_id": "req-184c8a9012-7",
    "retry_after_ms": 5000,
    "remediation": "retry after server warmup; live events are unavailable until the bus is initialised"
  },
  "meta": {"api_version": "v1"}
}
```

**Response headers (always set on 200 and on most error responses):**

| Header | Value | Purpose |
|---|---|---|
| `X-Correlation-Id` | `req-<hex-ms>-<hex-seq>` | Grep token tying the response to the audit row and server-side spdlog rows. Echoed inside the A4 envelope on errors. |
| `Cache-Control` | `no-cache` | Prevents proxy / browser cache buffering. |
| `X-Accel-Buffering` | `no` | Tells nginx and similar proxies not to buffer the SSE stream. |
| `X-Content-Type-Options` | `nosniff` | Belt-and-braces against MIME sniffing. |
| `Sec-Audit-Failed` | `true` (only when audit persist failed) | SOC 2 CC6.6 evidence contract: subscription proceeded even though the audit row failed to persist (matches the PR #883 / W1.1 partial-failure pattern). |

**Audit:** every successful subscribe emits one `api.v1.events.subscribe` audit event (separate verb from the dashboard sibling's `execution.live_subscribe` so SIEM filters can distinguish browser vs agentic consumers). A subscribe request against an execution that is genuinely nonexistent OR merely out of the caller's scope (the 404 case above) also emits a `result=denied` row on the same action, using non-distinguishing detail text — the two cases must remain audit-indistinguishable, matching the response HTTP status. Per-session-per-execution dedup is **not** currently implemented (Deferred-5 / #700); a worker reconnecting frequently generates one row per reconnect.

**Restart behaviour:** the bus is in-process and in-memory. On server restart, every `Last-Event-ID` is invalidated — replays against an event id assigned by a previous process instance return nothing even if the execution is still active. Workers should fall back to `GET /api/v1/executions/<id>` to recover terminal state after a 503 or a long disconnect.

**Example (curl):**

```bash
curl -N \
  -H "Authorization: Bearer $YUZU_TOKEN" \
  -H "Accept: text/event-stream" \
  "https://yuzu.example.com/api/v1/events?execution_id=exec-abc123"
```

**Example output (running execution, A3 envelopes):**

```
id: 1
event: agent-transition
data: {"execution_id":"exec-abc123","event_id":1,"timestamp_ms":1716000000000,"type":"agent-transition","payload":{"agent_id":"a-1","status":"running"}}

id: 2
event: agent-transition
data: {"execution_id":"exec-abc123","event_id":2,"timestamp_ms":1716000002034,"type":"agent-transition","payload":{"agent_id":"a-1","status":"success","exit_code":0,"duration_ms":4218}}

event: heartbeat
data:

id: 3
event: execution-progress
data: {"execution_id":"exec-abc123","event_id":3,"timestamp_ms":1716000005112,"type":"execution-progress","payload":{"total":2,"succeeded":1,"failed":0,"running":1,"pending":0}}

id: 4
event: execution-completed
data: {"execution_id":"exec-abc123","event_id":4,"timestamp_ms":1716000010301,"type":"execution-completed","payload":{"status":"succeeded"}}
```

**Example output (late reconnect — replay-gap envelope):**

```
id: 41
event: replay-gap
data: {"execution_id":"exec-abc123","type":"replay-gap","missing_from":41,"missing_to":118}

id: 119
event: agent-transition
data: {"execution_id":"exec-abc123","event_id":119,"timestamp_ms":...,"type":"agent-transition","payload":{...}}
```

**Known limitations (sprint W5.1 skeleton; tracked as follow-ups):**

- No multi-execution / wildcard subscription — open one connection per execution, or wait for W5.2.
- No per-principal connection cap — operators expecting >10 concurrent agentic subscriptions should size the httplib worker pool accordingly.
- Replay/subscribe race window: a publish that arrives between the `replay_since` and `subscribe` calls is silently lost. A bus-side `subscribe_with_replay` is filed as a follow-up against both this route and the dashboard sibling.
- ~~The MCP `execute_instruction` tool currently returns `command_id`, not `execution_id`~~ — **closed by #1088.** Both the MCP `execute_instruction` tool and REST `POST /api/instructions/{id}/execute` now return `execution_id` alongside `command_id`. The full agentic dispatch-to-observe loop is functional.

---

### Dashboard TAR

#### `POST /api/dashboard/tar-execute`

Execute a TAR warehouse SQL query against targeted agents. Returns HTMX HTML fragments: a `thead` OOB swap with dynamic column headers and sets up an SSE stream for result rows.

**Permission:** `Execution:Execute`

**Request body (form-encoded):**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `sql` | string | Yes | A SELECT query using `$`-prefixed table names (e.g., `$Process_Live`, `$TCP_Hourly`). |
| `scope` | string | No | Target scope. An agent ID, `group:<expression>`, or `__all__` for all agents. Defaults to all connected agents. |

**Example (curl):**

```bash
curl -X POST https://yuzu.example.com/api/dashboard/tar-execute \
  -H "Cookie: yuzu_session=abc123" \
  -d "sql=SELECT name, pid FROM \$Process_Live LIMIT 10" \
  -d "scope=__all__"
```

**Response:** HTMX HTML fragments. The response contains:
1. A `<thead>` element with `hx-swap-oob="innerHTML:#tar-results-head"` containing dynamic column headers derived from the query result schema.
2. An SSE stream setup that delivers result rows as `<tr>` fragments.

**Safety controls:**
- Server-side: validates SELECT-only queries and applies a keyword blocklist (no INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, REINDEX).
- Agent-side: untrusted queries run on a dedicated **read-only** SQLite connection through a `sqlite3` authorizer that permits only `SELECT`/`READ` of registry-known warehouse tables (`$Process_Live`, `$TCP_Hourly`, …) and scalar/aggregate functions. Writes, `ATTACH`, `PRAGMA`, schema-table reads (`sqlite_master`), recursive CTEs, and multi-statement input are denied at prepare time — the read-only connection makes writes structurally impossible regardless of the query text. `$`-prefixed table names are translated only outside string literals and comments, so the executed query always matches the validated form. Queries exceeding 4KB are rejected. A blocked query returns `query rejected: operation or table not permitted`.

#### `GET /tar`

Render the TAR dashboard page. Requires an authenticated session (302 redirect to `/login` otherwise). The page hosts the retention-paused source list, the ad-hoc TAR SQL frame, and the process tree viewer (a per-host process tree reconstructed from the device's local TAR warehouse; see `docs/user-manual/tar.md`).

**Permission:** Session-only (the page itself; embedded fragment endpoints carry their own permission gates — see below).

#### `GET /fragments/tar/retention-paused`

Render an HTML table fragment of the calling operator's most-recent TAR retention scan. Empty-state placeholders distinguish "no scan yet" from "scan returned no paused sources." **Scope caveat (ADR-0017):** this list gates on the *global* `Infrastructure:Read` permission — management-group confinement of this list/fan-out view is **not yet effective** (a confined operator is denied at the global gate rather than shown a narrowed list); when RBAC is disabled the list is the full enrolled fleet. Per-device confinement remains genuine only on the per-device `reenable` endpoint below.

**Permission:** `Infrastructure:Read`.

**Request:** no parameters.

**Response:** HTML fragment.

#### `POST /fragments/tar/retention-paused/scan`

Dispatch a `tar.status` command to the operator's visible-agent set and record the new command_id in the per-username scan slot. The next `GET /fragments/tar/retention-paused` picks up the responses.

**Permission:** `Execution:Execute`. Reading the resulting list still requires only `Infrastructure:Read`, but dispatching a command to the fleet is an Execute action.

**Request:** no parameters. The dispatch gates on the *global* `Execution:Execute` permission; management-group confinement of the dispatch target is **not yet effective** (ADR-0017 — a confined operator is denied at the global gate, not narrowed). When RBAC is disabled, the target is the full enrolled fleet.

**Response:** HTML fragment showing the dispatched-agent count or an empty-state placeholder.

**Audit:** Emits `tar.status.scan` with detail `dispatched to <N> agent(s) in scope`.

#### `POST /fragments/tar/retention-paused/reenable`

Dispatch a single-device `tar.configure` with `<source>_enabled=true`. Per-source independence is preserved — re-enabling `process` does not affect `tcp` / `service` / `user`.

**Permission:** `Execution:Execute`. Per-device RBAC visibility is verified before dispatch; out-of-scope `device_id` values collapse to the same 404 response as not-connected agents (no enumeration oracle).

**Request body (form-encoded):**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `device_id` | string | Yes | The agent ID. Must be in the operator's visible-agent set; otherwise rejected with 404 (same body as not-connected). |
| `source` | string | Yes | One of `process`, `tcp`, `service`, `user`. Other values rejected with 400 to prevent forged form submissions. The retention-paused list covers the always-on four; opt-in sources (`arp`, `dns`, `procperf`, `netqual`, `module`) are enabled/disabled via the **Capture sources** frame (below), not this route. |

**Response:**
- 200 OK with empty body and an `HX-Trigger` toast on success.
- 400 with explanatory body for missing/invalid params.
- 404 with body `Agent not reachable.` for both out-of-scope `device_id` and not-connected agent. Audit detail records the real reason (`scope_violation` vs `agent_not_connected`) server-side.

**Audit:** Emits `tar.source.reenable` with `result=success` and `detail` carrying `device=<id> source=<src>` on success, or `result=failure` with the real rejection reason on rejected attempts.

#### `POST /fragments/tar/retention-paused/purge`

Dispatch a single-device `tar.purge_source` that **permanently drops every warehouse row** for a source (`<source>_{live,hourly,daily,monthly}`) while leaving the collector **paused** — the "we have what we need; drop the rows but keep collection off" case (Phase 15.A). This is a **destructive, irreversible** operation.

**Permission:** `Infrastructure:Delete` (a higher tier than re-enable's `Execution:Execute`). Per-device RBAC visibility is verified before dispatch; out-of-scope `device_id` values collapse to the same 404 response as not-connected agents (no enumeration oracle).

**Confirmation:** the dashboard requires the operator to type the device hostname before this POST fires (a native `prompt()`, CSP-safe). The confirmation is **client-side** — scripted callers that POST directly are still gated by the permission, the per-device visibility check, and the agent-side paused-guard.

**Paused-guard (authoritative, agent-side):** the agent refuses the purge (`source_not_paused`) unless the source currently reports disabled. This closes the scan→purge TOCTOU (a source re-enabled between the operator's scan and the purge is not dropped). The server does **not** enforce a `SOURCE_NOT_PAUSED` check — the retention-paused list is an ephemeral live scan with no persisted paused-state.

**Request body (form-encoded):**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `device_id` | string | Yes | The agent ID. Must be in the operator's visible-agent set; otherwise rejected with 404 (same body as not-connected). |
| `source` | string | Yes | One of `process`, `tcp`, `service`, `user`. Other values rejected with 400 to prevent forged form submissions. |

**Response:**
- 200 OK with a `Purge dispatched — Scan to refresh.` fragment and an `HX-Trigger` toast on success. The source row remains (purge does not re-enable); a subsequent **Scan** reconciles the now-zero counts.
- 400 with explanatory body for missing/invalid params.
- 404 with body `Agent not reachable.` for both out-of-scope `device_id` and not-connected agent. Audit detail records the real reason (`scope_violation` vs `agent_not_connected`) server-side.
- 503 if command dispatch is unavailable.

**Audit:** Emits `tar.source.purge` with `result=success` and `detail` carrying `device=<id> source=<src>` on success (`rbac_denied` on the permission gate; `result=failure` with `scope_violation`/`agent_not_connected` on rejected attempts). Dispatch is fire-and-forget: `rows_deleted` is computed agent-side and appears in the command's **response record** (keyed by `command_id`), not in this dispatch audit row.

**Metric:** `yuzu_tar_source_purge_total{result}` (counter) — counts dispatch outcomes.

**Agent version:** requires an agent that implements the `tar.purge_source` action (v0.14.0+). An older agent returns `error|unknown action: purge_source` in its response record (no crash); because dispatch is fire-and-forget the dashboard still shows "Purge dispatched" — verify the outcome via **Scan**.

#### `POST /api/v1/tar/retention-paused/purge`

The **agentic-first (A1) structured surface** for the same destructive purge — for automation / MCP workers / scripted callers that need a JSON contract and a `command_id` rather than the HTML fragment above. Same effect: permanently drop a paused source's warehouse rows on one device, leaving the collector paused. **Irreversible.**

**Permission:** `Infrastructure:Delete`, enforced **per-device and management-group-scoped** (the scoped gate; an out-of-scope or unauthorized device is refused, not enumerated). Fail-closed if the scope gate is unwired.

**Request body (JSON):**

| Field | Type | Required | Description |
|---|---|---|---|
| `device_id` | string | Yes | The target agent. Must be within the caller's management scope. |
| `source` | string | Yes | One of `process`, `tcp`, `service`, `user`. Others → 400. |

**Responses:**
- **202 Accepted** — `{"data":{"command_id","device_id","source","agents_reached"},"meta":{"api_version":"v1"}}`. Async: the agent computes `rows_deleted` (and the agent-side `source_not_paused` refusal if the source was re-enabled) into the command's **response record** — poll it by `command_id`; it is not in the 202 body. `X-Correlation-Id` header on every response.
- **400** — invalid JSON / missing `device_id`/`source` / source not in the allowlist (A4 error envelope).
- **403 / 404** — permission denied or device out of scope (scoped gate; A4 envelope).
- **404** — dispatch reached zero agents (device offline).
- **503** — command dispatch unavailable, or the audit row could not be persisted (`Sec-Audit-Failed` header; the purge is **not** dispatched without durable evidence).

**Audit:** `tar.source.purge` `result=requested` is written **before** dispatch (fail-closed). **Metric:** `yuzu_tar_source_purge_total{result}`. **Agent version:** same `tar.purge_source` (v0.14.0+) requirement as the fragment.

#### `GET /api/v1/tar/process-tree`

**API-parity read twin (#4027).** The **agentic-first (A1) structured surface** for the process-tree viewer's device picker — JSON twin of the operator-scoped device list `GET /fragments/tar/process-tree` renders into its host-picker `<select>`.

**Permission:** `Infrastructure:Read`. A service-scoped API token is denied outright (403, `tar.device_picker.view` denied) — the fleet-wide device-enumeration guard shared with `GET /api/v1/tar/capture-sources` below, since neither route names a single `agent_id` to confine a service-scoped token's own tag against.

**Request:** no parameters.

**Response:** `{"data":{"devices":[{"agent_id","hostname","os","arch","agent_version","online"}]},"meta":{"api_version":"v1"}}`. Every row carries `online`, which is **always `true` today** — the sole wired provider sources this list from the live-session registry, so a disconnected enrolled device is not included (#4027 fix round, CDX-P1-02/K1 — an earlier revision of this doc claimed offline-inclusive; that was aspirational, not the shipped behavior). Unlike the HTML picker, this list does not additionally hide any row by online status — a future offline-inclusive provider (tracked follow-up) would make that distinction meaningful.

**Audit:** none on success — a device identity/online list, not per-device behavioral content (matches the fragment's own today-unaudited posture).

#### `GET /api/v1/tar/capture-sources`

**API-parity read twin (#4027).** Same shape and gates as `GET /api/v1/tar/process-tree` above — JSON twin of the operator-scoped device list `GET /fragments/tar/capture-sources` renders into its host picker (ADR-0015).

**Permission:** `Infrastructure:Read`. Same service-scoped-token 403 as the process-tree twin.

**Response:** `{"data":{"devices":[{"agent_id","hostname","os","arch","agent_version","online"}]},"meta":{"api_version":"v1"}}`.

#### `GET /api/v1/tar/retention-paused`

**API-parity read twin (#4027).** JSON twin of `GET /fragments/tar/retention-paused`: the **calling operator's** most recent `tar.status` scan (per-username state), filtered to their visible agents, one row per (agent, paused source).

**Permission:** `Infrastructure:Read`.

**Request:** no parameters.

**Response:** `{"data":{"scan_id","scan_count","scan_at","agents_responded","agents_with_no_paused_sources","agents_filtered_out_of_scope","store_degraded","rows":[{"agent_id","agent_display","source","paused_at","live_rows","oldest_ts","value_error","enabled_raw"}]},"meta":{"api_version":"v1"}}`. `scan_id` is `""` when the operator has not dispatched a scan yet — `POST /fragments/tar/retention-paused/scan` is dashboard-only today (a mutating dispatch route, out of scope for #4027).

**Headers:** `Cache-Control: no-store, private` + `Vary: Cookie` — per-operator-scoped data, same UP-11 posture as the fragment.

**Audit:** none on success — scan/config metadata, not per-device behavioral content (matches the fragment's own today-unaudited posture).

**Not twinned (#4027 exception, recorded in `scripts/ci/api-parity/tar.json`):** `GET /fragments/tar/process-tree/result` and `GET /fragments/tar/process-tree/detail` are deliberately not given REST/MCP twins by #4027 — deferred as scope, not impossibility. `/detail`'s cache `token` is a CSPRNG value minted and principal-bound only inside the `/result` handler itself; no other path mints one, so a `/detail` twin genuinely has no usable input today. `/result`'s `pcmd`/`tcmd` command-id pair is an ordinary `tar sql` dispatch result (`Infrastructure:Read`, no execute gate) and could in principle be obtained by an operator through the already-twinned generic dispatch surface (`execute_instruction` / `POST /api/command`) by reproducing the two canned `$Process_Live`/`$TCP_Live` queries verbatim — but that is not a dedicated API path, and a real `/result` twin would still need a new async "not ready yet" polling contract (REST/MCP have no htmx auto-reissue equivalent). Both routes are otherwise reachable today only via the dashboard-only `GET /fragments/tar/process-tree/run` route, itself excluded (a dispatch-shaped GET batched with a later dispatch-twin effort, #3994). Revisit once that later batch ships `/run` (and `/result`) twins that mint these artifacts directly over the API.

#### `GET /fragments/tar/capture-sources`

Render the **Capture sources** frame body for `/tar` (ADR-0015): an operator-scoped device picker plus a target the per-source toggle table loads into on host change.

**Permission:** `Infrastructure:Read`.

#### `GET /fragments/tar/capture-sources/load`

Self-re-issuing poll that dispatches `tar.status` + `tar.compatibility` to one selected device and renders the per-source toggle table (enable state, live-row count, per-OS support, category). First call dispatches and returns a polling fragment carrying the two command IDs; subsequent calls (`scmd`/`ccmd`/`n` params) poll until both complete.

**Permission:** `Infrastructure:Read` (scoped to the device) + `Execution:Execute` (the read dispatches a live query). **Audit:** `tar.sources.read` at dispatch.

**Query params:** `device` (agent ID); `scmd`/`ccmd`/`n` (poll continuation, server-supplied).

#### `POST /fragments/tar/capture-sources/push`

Apply staged capture-source enable/disable changes. The dashboard stages toggles client-side; Push dispatches one `tar.configure <source>_enabled=<bool>` per changed source (the accidental-enable guardrail — nothing dispatches until Push).

**Permission:** `Infrastructure:Read` (scoped) + `Execution:Execute`. Source names are validated against a fixed allowlist; values constrained to `on`/`off`.

**Request body (form-encoded):** `device` (agent ID); `changes` (comma-separated `source=on|off`, e.g. `arp=on,dns=on`).

**Audit:** `tar.sources.configure` — **one row per changed source**, `detail` = `<source>_enabled=<bool> command_id=<id>`.

#### `GET /fragments/tar/process-tree/device-net`

Self-re-issuing poll that dispatches read-only `tar.sql` over `$DNS_Live` + `$ARP_Live` to the selected host and renders the device-level **DNS-cache** and **ARP-table** panels embedded in the process-tree pane (ADR-0015). **Device-level, not per-process** (the DNS cache carries no pid).

**Permission:** `Infrastructure:Read` (scoped) + `Execution:Execute`. **Audit:** `tar.dns.read` **and** `tar.arp.read` (distinct verbs — DNS is usage-class PII, separately countable) at dispatch.

**Query params:** `device`; `dcmd`/`acmd`/`n` (poll continuation, server-supplied).

---

## Product Packs

Product packs are bundles of `InstructionDefinition`, `PolicyFragment`, `Policy`, and other content shipped as a single signed multi-document YAML file. Pack signature enforcement is **on by default** (#802 / W7.4) — unsigned packs are rejected at install. See [server-admin.md](server-admin.md) for the `--allow-unsigned-packs` escape hatch and [upgrading.md](upgrading.md) for the pack-signing migration recipe.

#### `POST /api/product-packs`

Install a product pack from a multi-document YAML bundle.

**Permission:** `ProductPack:Write`.

**Request body (form-encoded or multipart):**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `yaml_bundle` | string | Yes | Multi-document YAML; each `---`-separated document is parsed for its `kind:` and delegated to the matching store (`InstructionDefinition` → instructions, `PolicyFragment` → policies, etc.). A `ProductPack` document carries the pack metadata (`name`, `version`, `description`, optional `signature` + `publicKey`). |

**Optional request header (#3481):** `Idempotency-Key` (max 200 characters). A retry carrying the same key and a `yaml_bundle` **identical after sanitization** (the same sanitize-on-write step every free-text column goes through — invalid UTF-8/embedded NULs are normalized before comparison, so this is not a literal byte-for-byte check) returns `201` with the *original* pack id — no sibling-store install delegation runs again. The same key reused with a **different** `yaml_bundle` is rejected as `400` (see below). The key is global (not scoped per-caller/principal), so use a value unlikely to collide across callers (a UUID, for example). Omitting the header preserves prior behavior exactly: every call mints a fresh pack id with no dedup. A narrow race remains between two concurrent installs sharing the same not-yet-used key: both can pass the pre-check before either commits, in which case the loser hits the partial unique index as an ordinary persist failure and is compensated via the same path as any other late failure. A client retry then converges — to the winner's id if the retried body matches the winner's, or to the `400` idempotency-conflict error below if it differs (the loser's original body, not the winner's, is what gets retried in practice).

**Response:**
- `201 Created` `{"id": "<pack-id>", "status": "installed"}` on success, or on an idempotent replay (same key, same body). **Partial success (#3479):** `install_fn` tolerates a single document failing without failing the whole bundle — when at least one document failed alongside ones that succeeded, the body additionally carries `"errors": [...]` (one entry per failed document, in bundle order — `"<kind>: <reason>"` for a document whose `install_fn` delegate rejected it, or a bare `"document <N> has no kind"` for one with no inferrable `kind:` at all), `"installed_count"` (how many succeeded), and `"total_items"` (item documents in the bundle, excluding the `ProductPack` metadata document itself). These three fields are OMITTED entirely when every item document succeeded — a client checking `body.errors` (or its absence) can distinguish a clean install from a partial one without parsing anything else. An idempotency-key replay never populates them (`install_fn` doesn't re-run on a replay), even if the ORIGINAL install that minted the key was itself partial (gov Gate 4, unhappy-path UP-1) — the two attempts' audit rows will disagree (the original's `success` row names a failed/total count in `detail`, the replay's does not), which is expected: the replay is reporting "no new install_fn work happened," not re-asserting the original outcome. Check the ORIGINAL attempt's audit row (same `target_id`) for the authoritative partial-failure detail, not the replay's.
- `400 Bad Request` — malformed YAML, missing required fields, item-install delegation failures, a signature rejection, or an idempotency-key conflict. Distinct error messages:
  - `no items installed: <reason>; <reason>; ...` — EVERY item document in the bundle failed to install (each `<reason>` is `<kind>: <install_fn's rejection>`, or a bare `document <N> has no kind` for one with no inferrable `kind:` at all — same two shapes as the partial-success `errors[]` array above). `#3479`: every document's reason is joined here (`; `-separated, bundle order), not just the first — a bundle with several independently-wrong documents used to only ever surface one.
  - `pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)` — the install was refused because the pack carried no `signature:` field and the server is enforcing signatures (default since #802). Either sign the pack or set the escape-hatch flag.
  - `signature verification failed for pack '<name>' — content may have been tampered with` — the signature was present but did not verify against the supplied public key.
  - `pack '<name>' has signature but no publicKey — cannot verify` — the bundle carried a `signature:` field but no `publicKey:`.
  - `duplicate item id in bundle: '<item_id>' (compensated N/M item(s))` — two documents in the bundle were assigned the same item id (by their `install_fn` delegate). Detected before any database interaction; this condition is deterministic, so a retry with the same bundle always fails the same way — never retry, fix the bundle instead. The `(compensated N/M item(s))` suffix (#3481, gov Gate 6) is appended whenever a compensation attempt actually ran (the real REST route always supplies `compensate_fn`, so in practice this always appears here) — `N == M` means every already-installed item was cleaned up; `N < M` means a residual orphan needs manual/operator cleanup (see the compensation metric below).
  - `idempotency key already used with a different request body` (#3481) — the `Idempotency-Key` header matches a prior install whose `yaml_bundle` differs from this request's. Use a fresh key for a genuinely new install.
  - `Idempotency-Key header too long (max 200 characters)` (#3481) — rejected before the store is touched; not audited (see below).
- `503 Service Unavailable` — the product pack store is unreachable (down/unmigrated) or a database error occurred persisting the pack. The response body carries only a generic `"service unavailable"` message; the specific database error is logged server-side, never echoed to the caller (migrated store — ADR-0054, mirrors `sw_deploy_client_message`/`device_token_client_message`'s established rationale for not leaking `PQerrorMessage()` fragments). **Since #3481:** any sibling-store items already installed before this failure are now best-effort compensated (rolled back) rather than silently orphaned — see `yuzu_server_product_pack_install_compensation_total` in the metrics reference.
- Both the `400` and `503` bodies use the standard **A4 error envelope** (`{"error": {"code", "message", "correlation_id", ...}, "meta": {"api_version": "v1"}}`, see [JSON Envelope](#json-envelope) above). **Breaking change (ADR-0054):** pre-migration, a rejected install returned a bare `{"error": "<message>"}` body — a client parsing that flat shape (rather than treating the body as opaque diagnostic text) must switch to reading `error.message`.

**Audit:** Emits `product_pack.install` with `result=success` and `target_id=<pack-id>` on an accepted install OR an idempotent replay, or `result=denied` with `target_type=ProductPack`, empty `target_id`, and the rejection message in `detail` on any rejection that reaches `ProductPackStore::install()` — this covers every `400`/`503` above **except** an oversized `Idempotency-Key` header, which is rejected before `install()` is ever called and is not audited, the same pre-existing convention this endpoint uses for a malformed request body or an unavailable store (see `audit-log.md`). On a partial success (#3479), the `success` row's `detail` additionally carries `"<failed>/<total> item(s) failed to install"` — an auditor doesn't need to re-fetch the response body to know a partial failure occurred, only its count; the specific per-item reasons live in the response body only.

#### `GET /api/product-packs`

List installed packs.

**Permission:** `ProductPack:Read`.

**Response:**
- `200 OK` — JSON array of `{id, name, version, description, installed_at, verified}` objects.
- `503 Service Unavailable` — the store is unreachable or the list query failed. A4 error envelope, generic message (see the `POST` route above for the no-raw-DB-error-to-caller rationale).

#### `GET /api/product-packs/:id`

Get a single pack with its items.

**Permission:** `ProductPack:Read`.

**Response:**
- `200 OK` — the pack JSON object including the `items[]` array (each `{kind, item_id, name}`).
- `404 Not Found` — no pack with that id. A4 error envelope.
- `503 Service Unavailable` — the store is unreachable or the read failed. A4 error envelope, generic message.

#### `DELETE /api/product-packs/:id`

Uninstall a pack, removing all delegated items.

**Permission:** `ProductPack:Delete`.

**Response:**
- `200 OK` `{"status": "uninstalled"}` on success.
- `404 Not Found` — no pack with that id. A4 error envelope. **Breaking change (ADR-0054):** the pre-migration route always returned a bare `{"error": "<message>"}` body at `400` for a missing id; automation that special-cased `400` or parsed the flat body shape on this route must switch to `404` + `error.message`.
- `503 Service Unavailable` — the store is unreachable or the delete failed. A4 error envelope, generic message.

**Audit:** Emits `product_pack.uninstall` with `result=success` and `target_id=<pack-id>` on success, or `result=denied` with `target_type=ProductPack`, `target_id=<pack-id>`, and the rejection message in `detail` on any `404`/`503` rejection (ADR-0054 — pre-migration, a rejected uninstall was not audited at all).

---

## MCP (Model Context Protocol)

The MCP endpoint enables AI models and automation tools to interact with Yuzu via JSON-RPC 2.0. Authentication is via Bearer token with an MCP tier. See [Authentication > MCP Tokens](authentication.md#mcp-tokens) for token creation details.

#### `GET /mcp/v1/`

The MCP Streamable HTTP **SSE channel** — the server→client half of a session minted by
`initialize`. Carries heartbeats, replayed frames on reconnect, and
`notifications/progress` frames for any `POST /mcp/v1/` call on this session that
requested progress tracking and isn't being delivered as a streamed POST instead (see
below).

**Permission:** the same credential as `POST /mcp/v1/`, plus the session's
`Mcp-Session-Id` header. The credential is re-checked once per tick (~3 s), whether or
not a heartbeat frame is emitted, so revoking it ends a *live* stream, not just future
ones.

**Required headers:** `Mcp-Session-Id` (from `initialize`), `Accept: text/event-stream`.
**Optional:** `Last-Event-ID` to resume.

**Status codes:**

| Code | Meaning |
|---|---|
| `200` | SSE stream (`text/event-stream`, chunked, held open) |
| `400` | `Mcp-Session-Id` absent (`-32600`) |
| `404` | Session unknown, expired, another principal's, **or** the `Last-Event-ID` cursor is outside the replay window (`-32007`) — re-initialize |
| `403` | `Origin` not in `--mcp-allowed-origin` (`-32008`) |
| `405` | Streaming disabled (`--mcp-no-streaming`) |
| `406` | `Accept` did not include `text/event-stream` (`-32011`) |
| `429` | Concurrent-stream cap, or a superseded stream on this session is still closing (`-32012`; honour `retry_after_ms`) |

```bash
curl -N -H "Authorization: Bearer $TOKEN" \
     -H "Mcp-Session-Id: $SID" \
     -H "Accept: text/event-stream" \
     https://yuzu.example.com/mcp/v1/
```

Every error body carries the A4 envelope (`correlation_id`, nullable `retry_after_ms`,
`remediation`). Streams end with a JSON-RPC `notifications/yuzu.stream_closed` notification
(a normal `message` on the stream, not a bespoke `event: stream-closed` frame) whose `params`
name the reason in that same A4 shape.

#### `DELETE /mcp/v1/`

Ends the session named by `Mcp-Session-Id` (and closes its stream). `200` on success;
`404` if the session is unknown or belongs to another principal; `400` if the header is
absent.

#### `POST /mcp/v1/`

JSON-RPC 2.0 endpoint for MCP tool calls, resource reads, and prompt requests.

**Permission:** Bearer token with `mcp_tier` set (readonly, operator, or supervised). The tier determines which tools are accessible, enforced before RBAC.

**Request body (tool call):**

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "list_agents",
    "arguments": {}
  },
  "id": 1
}
```

**Response (success):**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[{\"agent_id\":\"abc-123\",\"hostname\":\"workstation-01\",\"os\":\"windows\",\"status\":\"online\"}]"
      }
    ]
  },
  "id": 1
}
```

**Response (error):**

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "MCP is disabled on this server"
  },
  "id": 1
}
```

**Available methods:**

| Method | Description |
|---|---|
| `tools/list` | List available MCP tools for the current tier |
| `tools/call` | Invoke an MCP tool by name with arguments |
| `resources/list` | List available MCP resources |
| `resources/templates/list` | List available MCP resource templates |
| `resources/read` | Read an MCP resource by URI, or a resource template with a parameter substituted |
| `prompts/list` | List available MCP prompts |
| `prompts/get` | Get a prompt template by name |

**Phase 1 tools (22 read-only):**

| Tool | Description |
|---|---|
| `list_agents` | List connected agents with status |
| `get_agent_details` | Detailed info for a specific agent |
| `query_audit_log` | Search audit events with filters |
| `list_definitions` | List instruction definitions |
| `get_definition` | Get a specific instruction definition |
| `query_responses` | Collect responses by `execution_id` (one dispatch) or `instruction_id` |
| `aggregate_responses` | Aggregate response data |
| `query_inventory` | Query inventory data with filters |
| `list_inventory_tables` | List available inventory tables |
| `get_agent_inventory` | Get inventory for a specific agent |
| `get_tags` | Get tags for a device |
| `search_agents_by_tag` | Find agents matching tag criteria |
| `list_policies` | List all policies |
| `get_compliance_summary` | Compliance summary for a device |
| `get_fleet_compliance` | Fleet-wide compliance overview |
| `list_management_groups` | List management groups |
| `get_execution_status` | Status of a specific execution |
| `list_executions` | List recent executions |
| `list_schedules` | List instruction schedules |
| `validate_scope` | Validate a scope expression |
| `preview_scope_targets` | Preview which agents match a scope |
| `list_pending_approvals` | List pending approval requests |
| `get_pending_approval_count` | Count pending approval requests |

`query_inventory`, `list_inventory_tables`, and `get_agent_inventory` read the Postgres-backed generic `InventoryStore` (ADR-0037) and now return a JSON-RPC internal-error response (code `-32603`) when the store is unavailable or degraded (previously a silent empty result).

**Additional read-only tools (post-Phase-1).** Beyond the Phase 1 set the server also exposes the DEX signal/perf, network, and inventory read tools. The **application-performance-over-time** tools (this release) are:

| Tool | Description |
|---|---|
| `list_dex_perf_apps` | Applications with retained fleet app-perf data (the picker) |
| `get_dex_app_perf` | Fleet trend for one application, by version, over time |
| `list_dex_app_perf_devices` | The version-row "which devices" drill — the MCP twin of `GET /api/v1/dex/perf/app/devices`. Required `app` AND `version` (version is present-required, unlike `get_dex_app_perf`'s "omit = all versions"; pass `""` for the unknown-version bucket). Unlike its aggregate siblings in this table, each row names an `agent_id`, so it gates on `require_fleet_read` (ADR-0017) instead of a bare permission check, confining a management-group/service-scoped caller to their visible devices with the filter pushed into the store query. Emits the dedicated `dex.app_perf.devices.view` audit verb (set-and-proceed, `audit_persisted:false` on a dropped row) plus the generic `mcp.list_dex_app_perf_devices` call audit. `truncated:true` means only the highest-CPU devices are returned. |
| `get_dex_group_app_perf` | One management group's app trend (sub-floor-suppressed at 10 devices). A service-scoped API token is denied outright (`kPermissionDenied`) — found by this branch's own governance review (PR #3156); the same DIFFERENT-axis gap as its REST twin `GET /api/v1/dex/perf/group`. This tool's own interim deny call was retired as provably dead code (guardian-confinement-2298 PR 3 "the flip", #3290 Phase 2 bucket 1a): the shared `perm_fn` (`AuthRoutes::require_permission`) already denies any service-scoped token outright for `(GuaranteedState, Read)` before this tool-specific branch is reached, since the service-scope global-safe allow-list is seeded empty. That denial is audited under the generic `auth.permission_required` verb, not `dex.perf.group.view` (REST's twin route denies BEFORE `perm_fn` via its own `deny_fleet_wide_service_scoped` call, so REST's deny IS recorded under `dex.perf.group.view`). |
| `get_dex_tag_app_perf` | The device-model tag-value cohort twin of `get_dex_group_app_perf` — the MCP twin of `GET /api/v1/dex/perf/tag`. Required `value` and `app`; optional `key` (default `"model"`, pattern `^[A-Za-z0-9_.:-]{1,64}$`) and `version`. An absent `key` defaults; a PRESENT `key` (including `""`) is validated like REST's `has_param`, so `key=""` `400`s identically on both transports rather than MCP silently substituting the default. Same sub-floor suppression, same service-scoped denial (`kPermissionDenied`) and the same retired-interim-deny-call / generic-`auth.permission_required`-verb posture as `get_dex_group_app_perf` above — not `dex.perf.tag.view` (REST's twin denies before `perm_fn` and IS recorded under that dedicated verb). |
| `compare_app_perf_versions` | Cohort-paired before/after comparison (the `/auto` VERIFY stage). Parameters `group`, `app`, `baseline`, `candidate` (all required) + `window` (integer days, default 7). Returns the same identity-free aggregate shape as `GET /api/v1/dex/perf/compare`. A successful call is **recorded under the generic `mcp.compare_app_perf_versions` tool-call audit** (not the REST `dex.app_perf.compare` verb) — but a service-scoped API token is denied outright (`kPermissionDenied`, found by this branch's own governance review, PR #3156) and that denial IS recorded under `dex.app_perf.compare`, matching its REST twin's deny-path verb rather than the generic one. |
| `get_dex_device_score` (#4035) | Per-device DEX read model — the MCP twin of `GET /api/v1/dex/devices/{id}`. Score (-1 = no store configured) + this device's own signal summary. Ancestor-aware SCOPED `GuaranteedState:Read` gate (like `query_software_licenses`); every call emits `dex.device.view` (set-and-proceed, `audit_persisted:false` on a dropped row — MCP has no `Sec-Audit-Failed` header, unlike the REST twin's fail-closed 503). **#4855:** a DEGRADED signal-summary read (store closed / pool-acquire timeout / query error) returns a retryable `kInternalError` (`retry_after_ms`) instead of a result — never conflate this with the `-1` "no store" case above; the `dex.device.view` behavioral-PII audit row still records `success` (the access happened), while the separate `mcp.get_dex_device_score` tool-invocation audit flips to `failure`. |
| `get_dex_device_app_perf` (#4035) | Per-device retained daily app-perf series — the MCP twin of `GET /api/v1/dex/devices/{id}/app-perf` (closes the gap this section previously documented as "no MCP twin"). Optional `app` narrows to one app. Same SCOPED gate + `dex.device.app_perf.view` audit posture as `get_dex_device_score`. |
| `get_dex_app` (#4035) | App blast-radius drill — the MCP twin of `GET /api/v1/dex/app`. Required `name`, optional `window`. `devices[]` is confined to the caller's management-group scope (ADR-0017 World A), same as the REST twin. `deny_fleet_wide_service_scoped` (the separate service-scoped-token axis) + fail-closed `try_persist_audit` under `dex.app.view` (`audit_persisted:false` on a dropped row), matching the REST twin's posture even though the dashboard fragment only audits the denial. |
| `list_dex_apps` (#4035) | App-centric stability list — the MCP twin of `GET /api/v1/dex/apps`. No per-agent identity — not audited. |
| `get_dex_catalogue_group` (#4035) | Signal-family drill (Catalogue View 2) — the MCP twin of `GET /api/v1/dex/catalogue/group`. Required `name`, optional `os`/`window`. An unknown family name returns `kInvalidParams`. Not audited (no per-agent identity). |
| `get_dex_device_history` (#4035) | Per-device raw signal history — the MCP twin of `GET /api/v1/dex/devices/{id}/history`; the distinct signal-**history** capability from `get_dex_device_score` above (same device, different data). Ancestor-aware SCOPED gate, same shape as `get_dex_device_score`. Emits `dex.device.view` — the SAME verb `get_dex_device_score` uses (both the fragment and this pair deliberately reuse one verb across the two distinct per-device capabilities). |
| `get_dex_observation` (#4035) | Single-observation detail — the MCP twin of `GET /api/v1/dex/devices/{id}/observations/{event_id}`. Required `agent_id`/`event_id`. A foreign or guessed `event_id` returns `kInvalidParams` — same no-oracle contract as the REST 404 (indistinguishable from a genuinely-absent event). Ancestor-aware SCOPED gate; emits `dex.observation.view`. |
| `get_dex_health` (#4035) | Derived composite health score — the MCP twin of `GET /api/v1/dex/health`. Optional `weighting`/`window`. Not audited (no per-agent identity). |
| `get_dex_trends` (#4035) | Cross-OS + per-family day-by-day trend — the MCP twin of `GET /api/v1/dex/trends`. Optional `window`. Not audited (no per-agent identity). |
| `get_dex_overview` (#4035) | Fleet DEX overview — the MCP twin of `GET /api/v1/dex/overview`. Optional `window`. `top_devices[]` is confined to the caller's management-group scope (ADR-0017 World A), same as the REST twin. `deny_fleet_wide_service_scoped` (the separate service-scoped-token axis) + fail-closed `try_persist_audit` under `dex.overview.view`, same "REST/MCP add more rigor than the fragment" rationale as `get_dex_app` above. |

The first three gate `GuaranteedState:Read` and are not audited (cohort posture) on success; `get_dex_group_app_perf`'s REST twin is audited on a service-scoped-token deny under the dedicated verb, but the MCP tool itself is not — its deny is recorded under the generic `auth.permission_required` verb instead (see above). `compare_app_perf_versions` also gates `GuaranteedState:Read`; because it has no cohort floor it **is** accountable — but over MCP that accountability is the generic `mcp.<tool>` tool-call audit, and the tool exposes only the identity-free aggregate (no per-machine drill — that is dashboard-only, see `GET /api/v1/dex/perf/compare`). The per-device app-perf drill (`GET /api/v1/dex/devices/{id}/app-perf`) is reachable via REST, the `/device` dashboard DEX drill (the *Application performance over time* panel), **and now MCP** (`get_dex_device_app_perf`, #4035) — the REST route stays fail-closed (503 on a dropped audit row), while the MCP twin follows the set-and-proceed / `audit_persisted:false` posture every other DEX MCP read tool uses (different surface, different posture — see `docs/api-twin-recipe.md` §4). See the *Application performance over time* REST section above for the shared percentile/suppression semantics.

**Resources:**

| URI | Description |
|---|---|
| `yuzu://server/health` | Server health status |
| `yuzu://compliance/fleet` | Fleet-wide compliance data |
| `yuzu://audit/recent` | Recent audit events |

**Prompts:**

| Name | Description |
|---|---|
| `fleet_overview` | Generate a fleet status overview |
| `investigate_agent` | Investigate a specific agent |
| `compliance_report` | Generate a compliance report |
| `audit_investigation` | Investigate audit trail activity |

**Server-side controls:**

| CLI Flag | Effect |
|---|---|
| `--mcp-disable` | Reject all `/mcp/v1/` requests |
| `--mcp-read-only` | Allow only read-only tools regardless of token tier |

**Streamed responses (progress tracking).** A `tools/call` for `execute_instruction`
carrying `_meta.progressToken` (see `docs/user-manual/mcp.md`'s `progressToken`
definition for the type/length contract; an out-of-spec value is silently treated as
absent — no error, no progress) opts into progress tracking — **this requires an
active session**: a non-empty `Mcp-Session-Id` header from a prior `initialize`. A
`Mcp-Session-Id` that is present but invalid (unknown, expired, or another
principal's) fails the **entire call** with `404`/`-32007` before progress tracking is
even considered — that is a property of every non-`initialize` method on this
endpoint, not specific to progress tracking, and is covered above under `GET /mcp/v1/`.
The table below assumes a valid session or none at all; where progress *is* tracked,
delivery depends on the request's `Accept` header and whether the server has
`--mcp-enable-streamed-post` enabled (on by default; opt out with `--no-mcp-streamed-post`):

| `_meta.progressToken` | `Mcp-Session-Id` | `Accept: text/event-stream` | Server answers |
|---|---|---|---|
| present | sent, valid | present, streamed POST enabled | this POST response held open as an SSE stream — `notifications/progress` frames, then the JSON-RPC result last, then EOF |
| present | sent, valid | absent, or streamed POST disabled | plain JSON now; progress frames go to the session's `GET /mcp/v1/` stream instead |
| present | not sent | any | plain JSON, byte-identical to a call with no progress tracking |
| absent | any | any | plain JSON, byte-identical to a call with no progress tracking |

A streamed POST's response headers are `Content-Type: text/event-stream`,
`Cache-Control: no-cache`, `X-Accel-Buffering: no` (nginx only — Envoy/HAProxy/ALB/
Cloudflare need their own response-buffering opt-out, or the proxy will buffer the
whole stream and the server cannot detect that the client has gone), `X-Correlation-Id`,
and `X-Content-Type-Options: nosniff`. **Capacity** denials reuse `-32012` / HTTP `429`
— the same code and `retry_after_ms`/`Retry-After` A4 shape as the `GET` channel above,
but a longer fixed value (30s vs. the `GET` channel's 5s: none of these causes is
likely to clear within a second or two) and a distinct set of causes (a shared
cross-surface budget, this principal's own streamed-call allowance, a server-wide
capacity ceiling, or this session's own slots). A duplicate request id or an unknown
session get their own codes (`409`/`-32600`, `404`/`-32007`) instead — see
`docs/user-manual/mcp.md` "`-32012`: Stream limit reached" for the full cause-by-cause
remediation, and `docs/mcp-server.md` "Streamed POST — SSE on the response" for the
admission/refusal table, close reasons, and resume/recovery rules. A denial
caused by the server disabling/shutting down streaming, or an allocation failure,
degrades silently to the plain (non-streamed) response instead of erroring — see the
same admission table for which causes degrade vs. answer. Every session open, close,
and denial is recorded in the audit log under `mcp.session.open` / `mcp.session.close`
/ `mcp.session.reject` (`target_type = McpSession`) — see `docs/user-manual/mcp.md`
"Audit". Progress is best-effort regardless of delivery mode: admission (the same
`reserve()` call this table describes) runs whether or not the request is a streamed
POST, but only the streamed-POST arm answers a capacity rejection with an explicit
`429` — the identical causes silently degrade to a plain response, with no progress
delivered anywhere and no error surfaced, when progress is being delivered on the
`GET` channel instead (streamed POST not requested, or not enabled). A caller must
therefore still be prepared to poll (`query_responses` / `get_execution_status`)
regardless of which delivery mode it used.

---

## Authentication Endpoints

These endpoints manage user sessions and SSO flows.

#### `POST /login`

Authenticate with username and password.

**Permission:** None (unauthenticated).

**Request body (form-encoded):**

```
username=admin&password=secretpass
```

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` + `Set-Cookie: yuzu_session=…` | Credentials valid; user has no MFA enrolled and no enforcement applies | `{"status":"ok"}` |
| `202` (`mfa_required`) | Credentials valid; user **has** TOTP MFA enrolled | `{"status":"mfa_required","mfa_pending_token":"<opaque>","expires_in":120}` — complete the challenge by posting the pending token + TOTP code (or recovery code) to `POST /login/mfa` |
| `202` (`mfa_enrollment_required`) | Credentials valid; user is **un-enrolled** and `--mfa-enforcement` (`admin-only` for admins / `required` for all) requires MFA | `{"status":"mfa_enrollment_required","mfa_pending_token":"<opaque>","otpauth_uri":"otpauth://...","secret_base32":"...","qr_svg":"<inline SVG, or empty>","expires_in":120}` — show the QR/secret and complete enrollment via `POST /login/mfa/enroll` |
| `401` | Invalid credentials | `{"error":{"code":401,"message":"Invalid username or password"}}` |
| `503` | Enforcement applies but the auth store is unavailable (fail-closed; no session minted) | `{"error":{"code":503,"message":"MFA enrollment is required but the authentication store is unavailable"}}` |
| `503` | The in-memory pending-challenge map is at capacity (server under a `/login` flood; transient load-shed) | `{"error":{"code":503,"message":"too many pending authentications, retry shortly"}}` — retry after a short back-off; emits `yuzu_auth_mfa_pending_load_shed_total` |
| `503` + `Retry-After: 2` | A login-path auth-store read/write was unavailable — fail-closed, **no session minted** | `{"error":{"code":503,"message":"authentication store is temporarily unavailable","retry_after_ms":2000},"meta":{"api_version":"v1"}}` — the `mfa_status` decision read first rides out a transient Postgres blip with a bounded acquire-retry (the call that otherwise denies *all* logins on a blip); a persisted 503 means the outage outlasted it, or another login-path acquire failed, so honour `Retry-After` (see `docs/auth-architecture.md` §"Availability coupling"). Increments `yuzu_auth_read_degrade_total{route="login",reason}` (reason = `pool_acquire_timeout` / `query_error` / `secret_unavailable`) |

**Distinguish the two 202 variants by the `status` field**: `mfa_required` routes to `POST /login/mfa` (the user already has a secret); `mfa_enrollment_required` routes to `POST /login/mfa/enroll` (the user must enroll first). The `qr_svg` field on the enrollment variant is a server-rendered inline SVG QR code encoding `otpauth_uri` — inject it into the DOM **without** HTML-escaping (it is pure shape geometry, no user content). If `qr_svg` is the empty string, QR encoding failed; fall back to displaying `secret_base32` / `otpauth_uri` for manual entry. The `mfa_pending_token` is a 32-byte hex (64-char) opaque random; its lifetime is `cfg.mfa_login_pending_secs` (default 120 s). The pending state lives in process memory and is lost on server restart, and is not shared across HA replicas without sticky sessions.

**Errors:** a `503` from this endpoint can also mean the enrolled user's MFA secret could not be read (PG/KEK unavailable, tamper, or a rotated/unresolvable key) rather than the pending-challenge-map load-shed above — this fails closed rather than silently falling back to "not enrolled." See `docs/auth-architecture.md` § "MFA fails closed on secret-read failure."

#### `POST /login/mfa`

Complete a pending MFA login. Called after receiving HTTP 202 from `POST /login`.

**Permission:** None (unauthenticated — the pending token is the bearer).

**Request body (form-encoded):**

```
mfa_pending_token=<64-hex>&code=<6-digit TOTP or XXXX-XXXX-XXXX-XXXX recovery code>
```

The endpoint distinguishes TOTP from recovery by code shape — exactly 6 ASCII digits is interpreted as TOTP; anything else routes through recovery-code validation. Each pending token allows at most 5 attempts before being invalidated; once invalidated the operator must start over from `POST /login`.

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` + `Set-Cookie: yuzu_session=…` | Code accepted | `{"status":"ok"}` |
| `401` | Invalid or expired pending token, or rejected code | `{"error":{"code":401,"message":"Invalid verification code"}}` — the wire body is identical for all failure modes so an attacker cannot distinguish "this pending token is valid; my code was wrong" from "this pending token is unknown." The distinguishing detail is in the audit `detail` column only. |
| `503` | The user's MFA secret could not be read/decrypted (PG outage mid-read, tamper, an unresolvable/rotated KEK, or a corrupt blob) | `{"error":{"code":503,"message":"auth_db unavailable"}}` |

An enrollment-pending token issued by the `mfa_enrollment_required` branch is **rejected** here (use `POST /login/mfa/enroll`); a login-challenge token is likewise rejected at the enroll endpoint.

**Errors:** the `503` above is a deliberate fail-closed outcome, never collapsed into the `401` "code rejected" case (which would burn one of the user's limited verification attempts against a transient outage). See `docs/auth-architecture.md` § "MFA fails closed on secret-read failure."

#### `POST /login/mfa/enroll`

Complete enforced TOTP enrollment for an un-enrolled user. Called after receiving HTTP 202 `mfa_enrollment_required` from `POST /login` (only reachable under `--mfa-enforcement=admin-only|required`). The `POST /login` 202 already revealed the `otpauth_uri` + `secret_base32` for the user to scan; this endpoint confirms the first code, promotes the provisional secret to enrolled, mints the session, and returns the one-time recovery codes.

**Permission:** None (unauthenticated — the enrollment-pending token is the bearer).

**Request body (form-encoded):**

```
mfa_pending_token=<64-hex>&code=<6-digit TOTP>
```

Only a 6-digit TOTP code is accepted (recovery codes do not exist until enrollment completes). Shares the `is_login` per-IP rate-limit bucket and the 5-attempts-per-pending cap.

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` + `Set-Cookie: yuzu_session=…` | Code accepted; enrollment complete, session minted | `{"status":"ok","recovery_codes":["XXXX-XXXX-XXXX-XXXX", … 10 total]}` — revealed **once**; save them |
| `401` | Invalid/expired pending token, wrong token type, malformed or rejected code, attempts exhausted, **or the auth store is not configured at all** (null DB) | `{"error":{"code":401,"message":"Invalid verification code"}}` (uniform body; discriminator in the audit `detail`) |
| `503` | Auth store reachable but the secret could not be verified — decrypt/store failure (e.g. KEK unresolvable) | `{"error":{"code":503,"message":"authentication store is temporarily unavailable"}}` |
| `409` | The account was already enrolled by a concurrent verify before this pending token committed — a benign race, not a rejected code | `{"error":{"code":409,"message":"MFA is already enrolled on this account"}}` — no session minted; complete login normally |

A null auth store returns `401`, **not** `503`, deliberately: a distinct status would confirm "this pending token is valid" to an attacker holding one during a store outage. The reason is recorded in the audit `detail` only. The `503` above is reserved for the case where the store answered but the secret could not be decrypted or verified — that one is fail-closed and never burns an enrollment attempt. The `409` is only reachable by the caller who already holds a valid enrollment-pending token for that account (minted after their own password login), so it discloses nothing new, and it deliberately does **not** burn an enrollment attempt.

**Audit:** on success `mfa.enroll.verified` + `mfa.recovery_codes.generated` + `auth.login`; on a rejected code `mfa.enroll.failed`; on the benign already-enrolled race `mfa.enroll.race` (result `ok`).

#### `POST /login/mfa/stepup`

Refresh a session's MFA proof so the next high-risk REST/Settings mutation is accepted within the `mfa_step_up_window_secs` window (PR 2 of the MFA ladder). Called automatically by the dashboard HTMX layer when a request to a step-up-gated endpoint returns `401 mfa_step_up_required`; programmatic clients invoke it directly.

**Permission:** Existing session cookie (local or OIDC `auth_source`). API token / MCP token principals are step-up-exempt — they receive `400` here ("step-up is for session-cookie callers only — re-issue the API token to refresh MFA proof").

**Request body (form-encoded):**

```
code=<6-digit TOTP or XXXX-XXXX-XXXX-XXXX recovery code>
```

Same strict-shape gate as `POST /login/mfa`: exactly 6 ASCII digits is interpreted as TOTP, anything else as a recovery code. There is no per-request attempts cap (the session is itself the credential and is rate-limited at the server layer via the shared `is_login` bucket).

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` | Code accepted; session's `mfa_verified_at` refreshed to now | `{"status":"ok"}` |
| `400` | Missing `code`, or principal is an API/MCP token, or an **OIDC** session (OIDC re-proves via SSO, not local step-up — the body points to `/auth/oidc/start`) | `{"error":{"code":400,"message":"missing code"}}` / `step-up is for session-cookie callers only` / `OIDC sessions re-prove MFA by re-authenticating with the identity provider …` |
| `401` | No session cookie, or rejected code | `{"error":{"code":401,"message":"MFA step-up failed"}}` |
| `503` | `auth_db` unavailable (transient) | `{"error":{"code":503,"message":"auth_db unavailable"}}` |

**Errors:** the `503` above includes the case where the session owner's MFA secret specifically could not be read/decrypted (PG/KEK unavailable, tamper, or a rotated/unresolvable key) — `require_mfa_step_up` fails closed on this rather than treating it as "not enrolled." See `docs/auth-architecture.md` § "MFA fails closed on secret-read failure."

**Audit verbs:** `mfa.step_up.passed` on success (`detail=method=totp` or `method=recovery`); `mfa.step_up.failed` on each rejection with the rejection reason in `detail`.

**Example:**

```bash
# After a high-risk request returned 401 + mfa_step_up_required, post your
# current TOTP code (or a recovery code) to refresh the session's MFA proof:
curl -s -X POST https://yuzu.example.com/login/mfa/stepup \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --cookie "yuzu_session=<session>" \
  -d "code=123456"
# 200 {"status":"ok"}
```

#### Step-up envelope on high-risk endpoints

The following endpoints return `401` with an MFA step-up envelope when the calling session's `mfa_verified_at` is older than `mfa_step_up_window_secs` (the last two bullets, the JIT-elevation routes, use a 300s window instead when that flag is `0` or less):

- `POST /api/v1/tokens` (mint API token)
- `DELETE /api/v1/tokens/{id}` (revoke API token)
- `POST /api/v1/tokens/{id}/rotate` (rotate an API token)
- `POST /api/v1/tokens/{id}/confirm` (confirm an API-token rotation)
- `DELETE /api/v1/sessions` (admin force-logout another user)
- `POST /api/v1/software-packages` (upload software package)
- `POST /api/v1/software-deployments/{id}/start` (start deployment)
- `POST /api/v1/guaranteed-state/rules` (create Guardian rule)
- `PUT /api/v1/guaranteed-state/rules/{id}` (update Guardian rule)
- `DELETE /api/v1/guaranteed-state/rules/{id}` (delete Guardian rule)
- `POST /api/v1/guaranteed-state/push` (fan out Guardian rules)
- `DELETE /api/settings/users/{username}` (delete user)
- `POST /api/settings/users/{username}/role` (change user role)
- `POST /api/v1/engine-principals/{id}/roles` (assign a fleet-wide role to an engine principal)
- `DELETE /api/v1/engine-principals/{id}/roles/{role}` (unassign a fleet-wide role from an engine principal)
- `POST /api/v1/engine-principals` (create an engine principal)
- `DELETE /api/v1/engine-principals/{id}` (revoke an engine principal)
- `POST /api/v1/engine-principals/{id}/credentials` (mint the first credential)
- `POST /api/v1/engine-principals/{id}/credentials/rotate` (rotate a credential)
- `POST /api/v1/engine-principals/{id}/credentials/confirm` (confirm a rotation cutover)
- `POST /api/v1/engine-principals/{id}/transfer-owner` (reassign the responsible owner)
- `POST /api/v1/users/{username}/unlock` (clear an account lockout)
- `POST /api/v1/users/{username}/elevation-eligibility` and `POST /api/v1/users/elevation-eligibility?username=` (grant or revoke JIT-elevation eligibility)
- `POST /api/v1/elevate` (activate a JIT admin elevation)

For **OIDC** sessions the envelope's `challenge_url` is `/auth/oidc/start` (and the remediation points at re-SSO) instead of `/login/mfa/stepup` — an external identity has no local TOTP secret to step up against. An OIDC session whose IdP did not attest MFA at all (no `amr`) passes the gate under `--mfa-enforcement=optional`, but is **gated** (re-SSO) under `required` (or `admin-only` for an admin) — symmetric with a local user being forced to enrol.

Envelope shape:

```json
{
  "error": {
    "code": 401,
    "message": "MFA step-up required",
    "correlation_id": "req-...",
    "remediation": "POST /login/mfa/stepup with current TOTP code or a recovery code, then retry"
  },
  "meta": {
    "api_version": "v1",
    "mfa_step_up_required": true,
    "challenge_url": "/login/mfa/stepup"
  }
}
```

`meta.mfa_step_up_required` is the boolean discriminator that distinguishes this 401 from an "unauthenticated" 401; `meta.challenge_url` tells the client where to re-prove — `/login/mfa/stepup` for local sessions, `/auth/oidc/start` for OIDC sessions. API token / MCP token principals **never see this 401** — the gate skips them entirely (the bearer credential was issued as part of an authenticated session and is itself the step-up).

### JIT Admin Elevation

Activate a time-boxed admin elevation (SOC 2 CC6.3/CC6.6) — see `docs/auth-architecture.md` "JIT admin elevation". Eligibility is granted separately by an admin via [`POST /api/v1/users/{username}/elevation-eligibility`](#post-apiv1usersusernameelevation-eligibility).

#### `POST /api/v1/elevate`

Promote the **current cookie session** to admin for a bounded window. The session's effective role becomes `admin` until the window lapses, then auto-reverts.

**Permission:** an authenticated **cookie** session only (a Bearer/MCP-token caller gets `401` — automation credentials can never elevate); the caller must be `elevation_eligible` (eligibility is keyed on a `users` table row — an OIDC identity with no such row is denied here, not later; provision it first via `POST /api/v1/users`). A second factor is mandatory, branched strictly on the session's identity source (never a local namesake's enrollment for an OIDC caller):

- **Local session:** MFA must be enrolled (unconditionally, not gated on `--mfa-enforcement`) and a fresh MFA step-up (TOTP) is required.
- **OIDC session:** ⚠️ **temporarily unavailable** — since the `oidc:<iss>#<sub>` identity re-key (#1837/#1857), an OIDC session has no local `users` row and is denied at the eligibility gate (`403`, `"eligibility read failed"`); restoration is tracked in #1852. *The `amr` behaviour described here is the intended path #1852 restores:* a seeded `amr`-asserted MFA proof from the *current* IdP login satisfies the second-factor requirement — no local TOTP enrollment is consulted (default `--jit-oidc-amr-elevation=true`). A single-factor (no-`amr`) OIDC session is denied (`"no MFA in SSO login"`), and a seeded-but-stale proof still triggers the step-up challenge rather than a silent grant. With `--no-jit-oidc-amr-elevation`, OIDC sessions cannot elevate at all (`"OIDC-amr elevation is disabled"`) — they cannot present a local TOTP step-up (their step-up challenge is re-SSO), so the operator must switch to a local-authenticated session with local TOTP.

**Body:** `{"justification": "<string, required>", "duration_secs": <int, optional>}`. `justification` must be non-empty (control bytes are sanitised to space; capped to 1 KiB). `duration_secs` defaults to `--jit-max-elevation-secs` when absent or `0`; a value above the cap is clamped; a negative value is a `400`.

```bash
curl -s -X POST -H "Cookie: yuzu_session=$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"justification":"prod incident #42","duration_secs":600}' \
  "https://yuzu.example.com/api/v1/elevate"
```

**Response (200):** `{"status":"ok","expires_in":<seconds>,"expires_at":"<RFC3339 UTC>"}`. `expires_in` is the TRUE remaining time computed after the grant (not an echo of the requested `duration_secs`) — the window is clamped to `--jit-max-elevation-secs` **and** to the session's own absolute expiry (an elevation can never outlive the cookie session that carries it), so `expires_in` is always `<=` the requested duration. `expires_at` is the wall-clock projection of that same window.

**Errors:** `400` — blank/missing justification, wrong-typed field, or negative duration; `401` — not authenticated, no cookie (token caller), the session dissolved mid-request, **or the session is already at/past its own absolute expiry** (a dead-window guard: rather than granting a zero-or-negative-length window and misleading a scripted caller with a `200 ok`, this is rejected the same way as "session vanished between validate and elevate"); `403` — not eligible, eligibility read failed (fail-closed), **no MFA enrolled** (local session), **no MFA in the SSO login** (OIDC session with no `amr` proof), or **OIDC-amr elevation is disabled** (`--jit-oidc-amr-elevation` off); the MFA step-up itself returns the standard step-up `401` challenge envelope (see `/login/mfa/stepup`); `500` with `Sec-Audit-Failed: true` — the mandatory grant audit could not persist, so the elevation was rolled back and **not** granted; `503` — the auth store is unavailable.

**Audit:** `role.elevation.granted` (`detail=duration_secs=<N> mfa=<oidc_amr|local_totp> expires_at=<RFC3339 UTC> justification=<sanitised>` — the machine-parsed `mfa=` and `expires_at=` tokens are placed before the free-text `justification=` field so a crafted justification can't forge either) on success; `role.elevation.denied` on a `403`, with a distinct `detail` reason per cause (not eligible / no MFA enrolled / no MFA in SSO login / OIDC-amr elevation disabled / mfa_step_up_refused). A window that later lapses PASSIVELY (no manual revoke) is audited lazily as `role.elevation.expired` on the operator's next authenticated request — see `docs/user-manual/audit-log.md`.

#### `POST /api/v1/elevate/revoke`

Step an active elevation down early (reduces privilege; no MFA step-up required). Body: none. Always `200 {"status":"ok"}`; whether a window was actually active is recorded as `was_elevated=<bool>` in the `role.elevation.revoked` audit detail, not the response body.

#### `POST /logout`

Destroy the current session. Clears the `yuzu_session` cookie.

#### `GET /auth/oidc/start`

Begin the OIDC SSO login flow. Redirects to the configured identity provider.

#### `GET /auth/callback`

OIDC callback endpoint. The identity provider redirects here after authentication. Exchanges the authorization code for tokens and creates a local session.

#### `GET /auth/saml/start`

Begin the SAML 2.0 SP-initiated login flow. Builds an `<samlp:AuthnRequest>` and redirects the browser to the configured IdP via HTTP-Redirect binding. Available only when all five `--saml-*` flags are set and the server is running on Linux or macOS.

#### `POST /saml/acs`

SAML Assertion Consumer Service endpoint. The IdP POSTs the `<samlp:Response>` here after authentication (HTTP-POST binding). The server validates the signed assertion (signature, audience, recipient, expiry, `InResponseTo` single-use) and mints a session cookie on success. On validation failure, the browser is redirected to `/login` with an error. Available only when SAML is enabled (see `GET /auth/saml/start`). When SCIM linkage is configured (ADR-2001 §4/PR4b), a login whose linked SCIM resource resolves deprovisioned is also refused here — see `auth.saml.deprovisioned_denied` below and `docs/user-manual/scim-provisioning.md` "Deny-at-login: a deprovisioned SAML identity cannot re-authenticate".

---

## SCIM v2 Provisioning

RFC 7643/7644. A **separate protocol surface** from the `/api/v1/` JSON API
above — its own RFC-defined schema (`application/scim+json`), its own
bearer-token credential, and its own `scim-service` audit principal. Full
design detail (provenance guard, deprovision/reactivation semantics, storage
decision, deferred items) is in `docs/auth-architecture.md` "SCIM v2
provisioning"; operator setup walkthrough is
[docs/user-manual/scim-provisioning.md](scim-provisioning.md). This section
is the wire-level endpoint reference.

**Enablement:** entirely inert (routes not registered) unless
`--scim-enable` (`YUZU_SCIM_ENABLE`) is set; requires `--scim-token`
(`YUZU_SCIM_TOKEN`) and HTTPS, or the server refuses to start. **Prefer the
`YUZU_SCIM_TOKEN` env var over `--scim-token`** — an argv value is visible
to any local user via `ps`; the env var is not.

**Permission:** every endpoint below, including the three discovery
endpoints, requires `Authorization: Bearer <scim-token>` — validated
constant-time against the configured token's hash. Missing/invalid → `401`
+ `WWW-Authenticate: Bearer`. This is unrelated to session cookies, API
tokens, or RBAC — there is no `role`/permission check on these routes, only
the bearer credential.

#### `GET /scim/v2/ServiceProviderConfig`

Discovery — static capability document (patch/filter/bulk support flags).

#### `GET /scim/v2/ResourceTypes`

Discovery — a SCIM `ListResponse` describing the User and Group resource
types.

#### `GET /scim/v2/Schemas`

Discovery — a SCIM `ListResponse` describing the core User and Group
schemas.

#### `POST /scim/v2/Users`

Provision a new user. Body: a SCIM User resource (only `userName` and
`externalId` are read; other fields real IdPs send — `name`, `emails`, etc. —
are tolerated and ignored).

> **`userName` must be a slug, not an email address.** Yuzu usernames are
> alphanumeric plus `.`/`_`/`-` — no `@`. Stock Okta/Entra provisioning
> defaults `userName` to the user's email and will `400` here; remap
> `userName` to a non-email slug attribute in the IdP's attribute-mapping
> config before assigning users. The `400` body's error message calls out
> the offending character(s).

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `201` + `Location` + `ETag` | Created | SCIM User representation |
| `409` (`scim_type=uniqueness`) | `userName` already provisioned on a **currently-active** account | SCIM error envelope |

Created with a discarded CSPRNG password — the account authenticates via
SSO, never a local password. Role defaults to `user`, recomputed
immediately against `--scim-admin-group` membership (see Groups → role
mapping below) — created `role=admin` iff already a member of that group at
creation time. If the `userName` instead matches an existing
SCIM-provisioned account that is currently **deactivated**, `POST` revives
that account (a returning-employee reprovision) rather than `409`ing.

#### `GET /scim/v2/Users/{id}`

Read a single provisioned user by its SCIM `id`.

| Status | Condition |
|---|---|
| `200` | Found — SCIM User representation |
| `404` | Unknown `id` |

#### `GET /scim/v2/Users?filter=userName eq "x"&startIndex=&count=`

Existence check + pagination, the standard "does this user already exist"
call a connector makes before create. **Only `userName eq "value"` is
supported** (case-insensitive attribute/operator, double-quoted value); any
other filter expression is rejected `400` (`scim_type=invalidFilter`).
Response is a SCIM `ListResponse` envelope; `startIndex` is 1-based per RFC
7644 §3.4.2.

#### `PUT /scim/v2/Users/{id}`

Replace the mutable identity fields (`externalId`, `active`). **If `active`
differs from the account's current state, this triggers the identical
deactivate/reactivate semantics documented under `PATCH` below** — some IdP
connectors issue `PUT` rather than `PATCH` for lifecycle changes.

| Status | Condition |
|---|---|
| `200` | Replaced — SCIM User representation |
| `400` (`scim_type=mutability`) | Body includes a `userName` change — rename is out of scope this slice |
| `404` | Unknown `id`, or the provenance/role guard rejects the target (see below) |

#### `PATCH /scim/v2/Users/{id}`

The primary lifecycle path. Both the pathless `{"value":{"active":false}}`
and explicit `{"path":"active","value":false}` PatchOp forms are accepted.

- **`active:false`** deprovisions — soft-deletes the auth account and
  cascades session revocation.
- **`active:true`** reactivates — restores the account and clears any stale
  lockout. MFA is **not** restored; the user re-enrolls on next login.

| Status | Condition |
|---|---|
| `200` | Applied — SCIM User representation |
| `404` | Unknown `id`, or the provenance/role guard rejects the target (see below) |

#### `DELETE /scim/v2/Users/{id}`

Deprovision (equivalent to `PATCH`/`PUT active:false` for IdPs that issue a
hard delete). `204` on success; `404` if unknown or guard-rejected.

#### Provenance guard

Every deactivate/reactivate/update/delete call above re-verifies **both**
`provisioning_source == "scim"` **and** `role == "user"` on the target
account immediately before mutating it, and refuses with **`404` — never
`403`** (a `403` would confirm the resource exists; `404` is indistinguishable
from "no such SCIM resource") plus a `scim.user.provenance_denied` audit row.
This is what makes it safe to point an IdP's SCIM connector at this surface
at all: a locally-created admin, or the `--break-glass-user` account, can
never be deactivated by a SCIM call; the only path from a SCIM request to
`role=admin` is Groups → role mapping below, bounded to the single
configured `--scim-admin-group`, so a compromised IdP cannot create an
admin outside that mapping; and the `role` check means an operator-elevated
former-SCIM account (later promoted by a human via the dashboard, or via
Groups → role mapping) also drops out of SCIM's write authority until it is
back to `role=user`. See `docs/auth-architecture.md` "SCIM v2 provisioning"
for the full threat discussion.

#### Groups → role mapping

`Group` is advertised in `/scim/v2/ResourceTypes` and `/scim/v2/Schemas`
(schema urn `urn:ietf:params:scim:schemas:core:2.0:Group`). Gated by
`--scim-admin-group` (`YUZU_SCIM_ADMIN_GROUP`, default empty — no SCIM group
grants admin). Full design detail (role-resolution, provenance guard
interaction, deprovision-ordering) is in `docs/auth-architecture.md` "SCIM v2
provisioning" § Groups → role mapping; operator walkthrough is
[docs/user-manual/scim-provisioning.md](scim-provisioning.md#groups--role-mapping).

#### `POST /scim/v2/Groups`

Create a group. Body: `displayName` (required), optional `members[]`
(each `{"value": "<scim-user-id>"}`).

| Status | Condition | Body |
|---|---|---|
| `201` + `Location` + `ETag` | Created | SCIM Group representation |
| `409` (`scim_type=uniqueness`) | `displayName` already in use | SCIM error envelope |

#### `GET /scim/v2/Groups/{id}`

Read a single group by its SCIM `id`. `200` + Group representation, or
`404` if unknown.

#### `GET /scim/v2/Groups?filter=displayName eq "x"&startIndex=&count=`

List groups. Same pagination contract as `GET /scim/v2/Users`
(`startIndex`/`count`, SCIM `ListResponse` envelope, `startIndex` 1-based per
RFC 7644 §3.4.2). Optional `filter=displayName eq "..."` (case-insensitive
attribute/operator, double-quoted value); any other filter expression is
rejected `400` (`scim_type=invalidFilter`).

#### `PUT /scim/v2/Groups/{id}`

Replace a group (`displayName`, `members[]`). `200` + Group representation;
`404` if unknown; `409` (`scim_type=uniqueness`) if the replace would rename
onto a `displayName` already used by a different group.

#### `PATCH /scim/v2/Groups/{id}`

Add/remove members — RFC 7644 §3.5.2 PatchOp on the `members` path
(`"op": "add"` / `"op": "remove"`, `"path": "members"`). `200` + Group
representation, or `404` if unknown.

#### `DELETE /scim/v2/Groups/{id}`

Delete a group. `204` on success; `404` if unknown.

Any Group `POST`/`PUT`/`PATCH`/`DELETE` that changes a user's membership of
the `--scim-admin-group` group recomputes that user's role immediately
(`scim.user.role_changed` audit row, see below) — there is no separate
"apply role changes" step.

#### Audit actions

Audit `result` is `success` | `failure` | `denied` (not `ok`/`error`).

| Action | Result | When |
|---|---|---|
| `scim.user.provisioned` | `success` / `denied` / `failure` | `POST` succeeds (incl. a revived reprovision) / rejected `409` against an active account / rolls back `500` |
| `scim.user.updated` | `success` / `failure` | `PUT /scim/v2/Users/{id}` succeeds / fails `500` |
| `scim.user.deactivated` | `success` / `failure` | `PATCH`/`PUT`/`DELETE` sets the account inactive; `failure` (set-and-proceed) if the audit write itself could not persist |
| `scim.user.reactivated` | `success` / `failure` | `PATCH`/`PUT` sets `active:true`; `failure` on an audit-write error (set-and-proceed) |
| `scim.user.deleted` | `success` / `failure` | `DELETE /scim/v2/Users/{id}` succeeds / audit-write failure (set-and-proceed) |
| `scim.user.provenance_denied` | `denied` | A mutating call targets an account failing the provenance or role guard |
| `scim.auth.denied` | `denied` | Bearer-auth validation fails on any `/scim/v2/*` route, including discovery |
| `scim.group.created` | `success` / `denied` / `failure` | `POST /scim/v2/Groups` succeeds / rejected `409` — `displayName` collision / rolls back `500` |
| `scim.group.updated` | `success` / `denied` / `failure` | `PUT`/`PATCH /scim/v2/Groups/{id}` succeeds / rejected `409` — rename onto an existing `displayName` / fails `500` |
| `scim.group.deleted` | `success` / `failure` | `DELETE /scim/v2/Groups/{id}` succeeds / audit-write failure (set-and-proceed) |
| `scim.user.role_changed` | `success` / `failure` | A user's role is recomputed to a new value on user create or a Group create/replace/patch/delete (records `old_role`→`new_role`, `reason=group`) |
| `scim.user.deprovision_role_refused_with_link` | `failure` | ADR-2001 D1: a role-refused deprovision (`deprovision_role_ok` 404 — the slug's role is not `user`) for a slug with ≥1 active linked OIDC identity, whose tokens are therefore NOT auto-revoked. Always written alongside `yuzu_scim_deprovision_role_refused_with_active_link_total` — see `docs/auth-architecture.md` "SCIM ↔ OIDC identity linkage for deprovision". |
| `auth.oidc.deprovisioned_denied` | `failure` | ADR-2001 §4/PR3: an OIDC login was refused because its linked SCIM resource resolved deprovisioned (deactivated, orphaned by a hard-deleted `scim_resources` row, or the store could not answer — fail-closed). Emitted from `GET /auth/callback`, not a `/scim/v2/*` route — listed here because it is part of the same ADR-2001 linkage. `detail` carries `reason=linked_scim_resource_inactive;scim_id=<id>` when a resolved resource (deactivated, or orphaned by a hard-deleted `scim_resources` row) drove the denial, or `reason=scim_store_unavailable` when the store could not answer (fail-closed — no `scim_id` to name); and — only on the post-mint re-check path (a concurrent deprovision landed after the primary check) — `post_mint_recheck=true;sessions_invalidated=<N>` (+`db_persisted=false` if that session invalidation itself failed to persist). The two `reason` values keep a genuine deprovision (CC6.8 evidence) distinguishable from a store outage. Pairs with `yuzu_auth_oidc_deprovisioned_denied_total`. |
| `auth.saml.deprovisioned_denied` | `failure` | ADR-2001 §4/PR4b, the SAML analogue of the row above: a SAML login was refused at `POST /saml/acs` because its linked SCIM resource resolved deprovisioned (deactivated, orphaned by a hard-deleted `scim_resources` row) or because `ScimStore` could not answer at all (fail-closed). Principal is the `saml:<entity_id>#<NameID>` string. `detail` uses the identical shape the OIDC row above uses: `reason=linked_scim_resource_inactive;scim_id=<id>` when a resolved resource drove the denial, or `reason=scim_store_unavailable` (no `scim_id`) when the store itself could not be asked; and — only on the post-mint re-check path — `post_mint_recheck=true;sessions_invalidated=<N>` (+`db_persisted=false` if that session invalidation itself failed to persist). Pairs with `yuzu_auth_saml_deprovisioned_denied_total`. |
| `auth.saml.link_unmatched` | `failure` | ADR-2001 #3072: on a SAML login with a linkable (stable-Format) NameID, the identity-link lookup ran but found either zero active SCIM resources matching the NameID as an `externalId` (`reason=no_active_external_id_match;name_id_format=<format>`) or more than one (`reason=ambiguous_active_external_id_match;name_id_format=<format>`, ADR-2001 §2 mis-link guard). **Observe-and-proceed — the SAML login still succeeds** (login-time linking is fail-open by contract; this is not the PR4b deny-at-login path). The two causes pair with separate counters, `yuzu_scim_saml_link_unmatched_total` and `yuzu_scim_saml_link_ambiguous_total` respectively, despite sharing one audit action. Emitted from `POST /saml/acs`. See `docs/auth-architecture.md` "SAML D2 observability (#3072)". |
| `auth.saml.link_lookup_failed` | `failure` | ADR-2001 #3072: on a SAML login with a linkable NameID, the `ScimStore` active-`externalId` lookup itself could not answer (`reason=scim_store_unavailable`) — distinct from `auth.saml.link_unmatched`'s genuine zero-match answer. **Observe-and-proceed — the SAML login still succeeds.** Pairs with `yuzu_scim_saml_link_lookup_failures_total`. Emitted from `POST /saml/acs`. |

#### Metrics

`yuzu_scim_requests_total{op,status}` (now including group ops),
`yuzu_scim_auth_failures_total`, `yuzu_scim_audit_write_failures_total`,
`yuzu_scim_provenance_denied_total`, `yuzu_scim_role_changes_total`,
`yuzu_scim_role_change_failures_total` (a role change that was decided but
failed to durably apply — pairs with `scim.user.role_changed` `failure`
rows).

**ADR-2001 (SCIM↔OIDC identity linkage, CC6.8):**
`yuzu_scim_deprovision_role_refused_with_active_link_total` (D1 — a
deprovision was refused for a slug with an active linked federated identity
whose tokens were not auto-revoked; a human must terminate them manually),
`yuzu_scim_deprovision_unlinked_total` (D2 — a deprovision found a
login observation that should have matched the slug's `externalId` but no
link had formed, almost always a misconfigured `--oidc-scim-link-claim`),
`yuzu_auth_oidc_deprovisioned_denied_total` (§4/PR3 — the deny-at-login
backstop refused an OIDC re-login against a deprovisioned linked identity),
`yuzu_scim_saml_link_write_failures_total` (a SAML login's identity-link
write failed — see `docs/user-manual/scim-provisioning.md` "SCIM ↔ SAML
identity linkage"), and `yuzu_auth_saml_deprovisioned_denied_total`
(§4/PR4b — the SAML analogue of the OIDC deny-at-login backstop above,
refused a SAML re-login against a deprovisioned linked identity); see the
audit actions above and `docs/user-manual/metrics.md` "SSO login metrics".
Full description: `docs/auth-architecture.md` "SCIM v2 provisioning" §
Metrics and "SCIM ↔ OIDC identity linkage for deprovision" § New metrics.

**ADR-2001 #3072 (SAML D2 observability):**
`yuzu_scim_saml_link_unmatched_total` /
`yuzu_scim_saml_link_ambiguous_total` (login-time: a linkable-Format SAML
NameID matched zero / more than one active SCIM resource — pairs with
`auth.saml.link_unmatched` above), `yuzu_scim_saml_link_lookup_failures_total`
(login-time: the active-`externalId` lookup itself could not answer — pairs
with `auth.saml.link_lookup_failed` above), and
`yuzu_scim_deprovision_saml_unlinked_total` (deprovision-time: the SAML
analogue of `yuzu_scim_deprovision_unlinked_total` above — a deprovision
found a SAML login observation matching the slug's `externalId` but no
formed `saml_identity_links` row). See
`docs/auth-architecture.md` "SAML D2 observability (#3072)" for the honest
scope of what each half (login-time vs. deprovision-time) can and cannot
attribute, and `docs/user-manual/metrics.md` "SCIM deprovision-linkage
metrics" for the operator-facing description.

---

## Health

#### `GET /health` (alias: `GET /api/health`)

> **Note:** `/api/health` is an identical alias of `/health`, provided for monitoring integrations that prefix every REST call with `/api/`. Both paths are unauthenticated, exempt from rate limiting, and return the same JSON body. The canonical path is `/health`; use `/api/health` only when your tooling enforces the `/api/` prefix unconditionally. (Restored in v0.12.0 — see issue #620.)
>
> **Note:** `/health` and `/api/health` are intentionally NOT draining-aware (they continue returning 200 during graceful shutdown). For load-balancer health checks that should drain in-flight traffic before stopping, use `/readyz` instead — it returns 503 once the server begins draining.
>
> **Body shape varies by auth.** Unauthenticated callers (the standard monitoring case) get the cheap probe response: `status`, `uptime_seconds`, `agents.online`, `stores.*`, `version`. Authenticated callers additionally get `agents.pending`, `executions.*`, and `system.*` — those fields require SQLite scans and are gated behind a session so an unauthenticated probe flood cannot become a DoS amplification primitive.

Structured JSON health check endpoint. This endpoint is **unauthenticated** and intended for load balancers, monitoring systems, and orchestration tools.

**Permission:** None (unauthenticated). Authenticated callers receive an extended response (see body-shape note above).

**Response:**

```json
{
  "status": "healthy",
  "uptime_seconds": 86400,
  "agents": {
    "online": 42,
    "pending": 3
  },
  "stores": {
    "pg_pool": "ok",
    "pg_reachable": "ok",
    "responses": "ok",
    "audit": "ok",
    "instructions": "ok",
    "policies": "ok",
    "guaranteed_state": "ok",
    "offload_target": "ok",
    "ca": "ok"
  },
  "tls": {
    "default_certs_active": false,
    "ca_fingerprint": "",
    "ca_expires_at": 0
  },
  "executions": {
    "in_flight": 5,
    "completed_last_hour": 120,
    "failed_last_hour": 2
  },
  "version": "0.1.0"
}
```

| Field | Type | Description |
|---|---|---|
| `status` | string | `"healthy"` or `"degraded"` |
| `uptime_seconds` | integer | Server uptime in seconds |
| `agents.online` | integer | Number of currently connected agents |
| `agents.pending` | integer | Number of agents awaiting enrollment approval |
| `stores` | object | Health status of each data store (`"ok"` or `"error"`); the example shows a subset. Includes `ca` — the internal-CA store (`ca_store`, Postgres) — which is load-bearing whenever default certs are active; `status` is `"degraded"` if it is down. Includes `pg_reachable` (HA WS-8) — the only RUNTIME check here: whether this replica's dedicated probe currently reaches a writable Postgres primary. The other store entries report whether each store opened at startup. `/readyz` carries the same `pg_reachable` row plus a `pg` reason field when it fails; see `docs/user-manual/server-admin.md`, "What `/readyz` checks". |
| `tls.default_certs_active` | bool | `true` when running with built-in per-install default certs (replace before production — see security-hardening.md). Unauthenticated so monitoring can detect it. |
| `tls.ca_fingerprint` | string | SHA-256 fingerprint of the active default CA (empty when not on default certs). Public. |
| `tls.ca_expires_at` | integer | Unix timestamp of the default CA's expiry (`0` when not on default certs). |
| `executions.in_flight` | integer | Currently running instruction executions |
| `executions.completed_last_hour` | integer | Executions completed in the past 60 minutes |
| `executions.failed_last_hour` | integer | Executions that failed in the past 60 minutes |
| `version` | string | Server binary version |

The endpoint returns HTTP `200` when healthy and HTTP `503` when degraded.

**Authenticated response:**

When the request includes a valid session cookie, `Authorization: Bearer <token>`, or `X-Yuzu-Token` header, the response includes an additional `system` object with process health telemetry:

```json
{
  "system": {
    "cpu_percent": 12.5,
    "memory_rss_bytes": 134217728,
    "memory_vss_bytes": 536870912,
    "grpc_connections": 42,
    "command_queue_depth": 5
  }
}
```

| Field | Type | Description |
|---|---|---|
| `system.cpu_percent` | float | Server process CPU usage percentage |
| `system.memory_rss_bytes` | integer | Resident set size in bytes |
| `system.memory_vss_bytes` | integer | Virtual memory size in bytes |
| `system.grpc_connections` | integer | Number of connected agent gRPC streams |
| `system.command_queue_depth` | integer | Number of in-flight command executions |

This object is omitted for unauthenticated callers to avoid exposing process internals.

---

## Metrics

#### `GET /metrics`

Prometheus exposition format. Returns all server metrics.

**Example (curl):**

```bash
curl https://yuzu.example.com/metrics
```

**Example output (excerpt):**

```
# HELP yuzu_server_agents_connected Number of currently connected agents
# TYPE yuzu_server_agents_connected gauge
yuzu_server_agents_connected 42

# HELP yuzu_server_grpc_requests_total Total gRPC requests by method and status
# TYPE yuzu_server_grpc_requests_total counter
yuzu_server_grpc_requests_total{method="Register",status="ok"} 156
yuzu_server_grpc_requests_total{method="Heartbeat",status="ok"} 12483

# HELP yuzu_server_command_duration_seconds Command execution duration
# TYPE yuzu_server_command_duration_seconds histogram
yuzu_server_command_duration_seconds_bucket{plugin="hardware",le="0.1"} 89
yuzu_server_command_duration_seconds_bucket{plugin="hardware",le="1.0"} 95
yuzu_server_command_duration_seconds_bucket{plugin="hardware",le="+Inf"} 96
```

**Management group metrics:**

```
# HELP yuzu_server_management_groups_total Total number of management groups
# TYPE yuzu_server_management_groups_total gauge
yuzu_server_management_groups_total 5

# HELP yuzu_server_group_members_total Total members across all management groups
# TYPE yuzu_server_group_members_total gauge
yuzu_server_group_members_total 42
```

**Process health metrics:**

```
# HELP yuzu_server_cpu_usage_percent Server process CPU usage percentage
# TYPE yuzu_server_cpu_usage_percent gauge
yuzu_server_cpu_usage_percent 12.5

# HELP yuzu_server_memory_bytes Server process memory usage in bytes
# TYPE yuzu_server_memory_bytes gauge
yuzu_server_memory_bytes{type="rss"} 134217728
yuzu_server_memory_bytes{type="vss"} 536870912

# HELP yuzu_server_open_connections Number of connected gRPC agent streams
# TYPE yuzu_server_open_connections gauge
yuzu_server_open_connections 42

# HELP yuzu_server_command_queue_depth Number of in-flight command executions
# TYPE yuzu_server_command_queue_depth gauge
yuzu_server_command_queue_depth 5

# HELP yuzu_server_uptime_seconds Server process uptime in seconds
# TYPE yuzu_server_uptime_seconds gauge
yuzu_server_uptime_seconds 86400
```

> **Note:** Process health metrics (CPU, memory, connections, queue depth) are exposed on `/metrics` for all callers. When `--metrics-no-auth` is enabled, this data is accessible to unauthenticated remote clients.

All server metrics use the `yuzu_server_` prefix. Standard labels: `agent_id`, `plugin`, `method`, `status`, `os`, `arch`.
