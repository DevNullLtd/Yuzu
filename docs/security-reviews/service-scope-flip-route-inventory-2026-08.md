# Route inventory — service-scope default-deny flip (guardian-confinement-2298 PR 3, §3e)

**Date:** 2026-08-18
**Change:** the routes below reach agent/fleet/execution/result data via
`require_auth`/`auth_fn` alone (or, for the sweep findings, via a bypass of
`require_permission` in the SAME handler) — none of them are protected by
the §3a flip (`AuthRoutes::require_permission`'s service-scoped branch),
because none of them ever call it. This file is the closed inventory PR 3's
plan called for: every row is either fixed in this PR or has a recorded,
reviewed disposition to leave it as-is.
**Verification depth column:** `handler-read` = the route's handler body was
read line-by-line and the disposition follows directly from that read.
`sweep-heuristic` = found by a grep-driven agent sweep (`rest_api_v1.cpp` +
`mcp_server.cpp`, 74 + 3 `auth_fn` call sites) that classified a site from
its surrounding code shape, not a full line-by-line read of the whole
handler; treat `sweep-heuristic` rows as lower-confidence than
`handler-read` rows, per governance's completeness-probe expectation.

## Fixed in this PR

| # | Route | File | Disposition | Depth |
|---|---|---|---|---|
| 1 | `GET /fragments/health/summary` | `server.cpp` | Denied via `AuthRoutes::deny_service_scoped_session` | handler-read |
| 2 | `GET /events` (legacy SSE) | `server.cpp` | Denied before admission-control lease + `event_bus_.subscribe` | handler-read |
| 3 | `GET /fragments/instructions` | `server.cpp` | Denied (role check only ever gated the New/Edit buttons) | handler-read |
| 4 | `GET /fragments/result-sets/sidebar` | `server.cpp` | Denied | handler-read |
| 5 | `GET /fragments/result-sets/{id}/detail` | `server.cpp` | Denied | handler-read |
| 6 | `POST /fragments/result-sets/{id}/pin` | `server.cpp` | Denied | handler-read |
| 7 | `POST /fragments/result-sets/{id}/unpin` | `server.cpp` | Denied | handler-read |
| 8 | `POST /fragments/result-sets/{id}/delete` | `server.cpp` | Denied | handler-read |
| 9 | `POST /fragments/result-sets/create` | `server.cpp` | Denied | handler-read |
| 10 | `GET /fragments/compliance/summary` | `compliance_routes.cpp` | Denied via new `ComplianceRoutes::deny_service_scoped_` | handler-read |
| 11 | `GET /fragments/compliance/{policy_id}` | `compliance_routes.cpp` | Denied (same helper) | handler-read |
| 12 | `POST /api/scope/estimate` | `workflow_routes.cpp` | Denied via new local `deny_service_scoped_scope_estimate` | handler-read |
| 13 | `GET /api/v1/management-groups/{id}/roles` | `rest_api_v1.cpp` | Fleet-wide arm already flip-protected (`perm_fn`); the ITServiceOwner-of-group fallback now skips a service-scoped session | handler-read (sweep-found) |
| 14 | `POST /api/v1/management-groups/{id}/roles` | `rest_api_v1.cpp` | Was a raw `rbac_store->check_permission` call bypassing `require_permission` entirely — routed through `perm_fn`; fallback guarded same as GET | handler-read (sweep-found) |
| 15 | `DELETE /api/v1/management-groups/{id}/roles` | `rest_api_v1.cpp` | Same fix as POST | handler-read (sweep-found) |
| 16 | `POST /api/v1/tokens` (`scope_service` ITServiceOwner-of-"Service: X" check) | `rest_api_v1.cpp` | Same raw-`check_permission` bypass, same fix shape — **defense-in-depth only**: verified NOT reachable by a service-scoped token today, since the route's own top-of-handler `perm_fn(req,res,"ApiToken","Write")` already denies every service-scoped session (the §3a flip's ceiling check is pinned to the ITServiceOwner ROLE's own RBAC grants, and that role's seed list carries no `ApiToken` entry) | handler-read (sweep-found) |
| 17 | `GET /api/v1/result-sets` | `rest_api_v1.cpp` | Owner-scoped via `session->username` (the MINTER's identity, not the token's own scope) — denied via extended `deny_fleet_wide_service_scoped` | handler-read (sweep-found) |
| 18 | `POST /api/v1/result-sets` (direct create) | `rest_api_v1.cpp` | Same fix | handler-read (sweep-found) |
| 19 | `GET /api/v1/result-sets/{id}` | `rest_api_v1.cpp` | Same fix | handler-read (sweep-found) |
| 20 | `GET /api/v1/result-sets/{id}/members` | `rest_api_v1.cpp` | Same fix | handler-read (sweep-found) |
| 21 | `GET /api/v1/result-sets/{id}/lineage` | `rest_api_v1.cpp` | Same fix | handler-read (sweep-found) |
| 22 | `POST /api/v1/result-sets/{id}/pin` | `rest_api_v1.cpp` | Same fix | handler-read (sweep-found) |
| 23 | `POST /api/v1/result-sets/{id}/unpin` | `rest_api_v1.cpp` | Same fix | handler-read (sweep-found) |
| 24 | `DELETE /api/v1/result-sets/{id}` | `rest_api_v1.cpp` | Same fix | handler-read (sweep-found) |
| 25 | `POST /api/v1/result-sets/from-inventory-query` | `rest_api_v1.cpp` | **Distinct, more severe, NOT service-scope-specific**: had NO authorization check of any kind (CWE-862) — any authenticated session, service-scoped or not, could query up to 5000 fleet-wide inventory records with zero scoping. Its dispatch siblings (`from-tar-query`, `from-instruction-result`, `{id}/re-eval`) were already gated by an earlier fix (e7b47ca3/#2500); this synchronous-read producer was never in scope for that fix and was missed. Gated on `Inventory:Read` (matches `GET /api/v1/inventory/software`'s securable for the same data class) — closes both the CWE-862 gap and the service-scope gap in one call, since `perm_fn` routes through the §3a-flipped `require_permission` | handler-read (sweep-found) |

Rows 13–25 were not in the plan's original enumeration — found by the
residual sweep of `rest_api_v1.cpp` (all 74 `auth_fn` call sites) and
`mcp_server.cpp` (3 call sites) the plan itself flagged as outstanding.

**Correction (#4980, 2026-09-25):** row 25's claim was accurate WHEN
WRITTEN, not wrong from the start — but it did not survive a later,
unrelated change. On 2026-08-18 this route genuinely gated `Inventory:Read`
via `perm_fn` (`require_permission`), and the §3a flip's hard 403 closed
the service-scope gap at that point. Commit `606b9ec72` (2026-09-12, an
unrelated Batch B2 fix closing a real management-group confinement gap on
this same route) replaced that `perm_fn` gate with `fleet_read_fn` (the
ADR-0017 admit-then-filter chokepoint) — whose service-scope branch
admits-and-confines a service-scoped caller UNDER RBAC-ON rather than
denying it outright (it still hard-403s under RBAC-off, same as `perm_fn`)
— and in doing so silently reopened the service-scope axis this row's fix
had closed. The actual exposure window was 2026-09-12 through #4980's
merge (~13 days), RBAC-enabled deployments only, not the ~5 weeks since
this row's own date. #4980 closed it again with a dedicated
`deny_fleet_wide_service_scoped` call that no longer depends on which
underlying gate this route uses.

## MCP (`mcp_server.cpp`) — sweep result: 0 findings

All 3 `auth_fn`-resolving call sites are self-scoped (the JSON-RPC
dispatcher routing to C8-protected `tools/call` / flip-protected
`resources/read`, the SSE tail replaying the caller's own session stream,
and the session-terminate handler acting on the caller's own session).
Every `tools/call` tool now goes through the C8 `ServiceScopeClass`
default-deny (§3c); `resources/read` bypasses C8 structurally but calls
`perm_fn` directly, so it is covered by the §3a flip. — sweep-heuristic

## Document-only dispositions (no code change)

| Route | Reasoning | Depth |
|---|---|---|
| `GET /api/me` | Returns only the minter's own identity metadata — no fleet data | handler-read |
| `GET /metrics` | Separate auth plane, config-gated, not session-based | handler-read |
| `POST /api/scope/validate` | Pure syntax check (`yuzu::scope::validate`) — never touches `scope_fn`, a store, or any data | handler-read (re-verified this session) |
| `POST /api/v1/rbac/check` | Echoes only the caller's own resolved permission boolean, no fleet/agent data — belongs to the authz-topology-floor concern (`docs/security-reviews/authz-topology-floor-2026-08-05.md`), not this one | sweep-heuristic |
| 16 auth-only dashboard page shells | Static chrome; data reaches the page only via already-gated fragments | sweep-heuristic (per original plan enumeration) |
| Health probes, CA root/CRL, SCIM, upload-grant planes | Exempt by design (pre-auth or separate trust boundary) | sweep-heuristic (per original plan enumeration) |

## Sweep accounting (rest_api_v1.cpp, 74 `auth_fn` call sites)

- Already gated by a `perm_fn`/`require_scoped_permission`/existing
  `deny_fleet_wide_service_scoped`/`deny_service_scoped_*` call in the same
  handler: the large majority — safe, no action.
- Non-data routes (identity/config/syntax-check): a handful — safe by
  nature.
- Gate-less, agent/fleet-data-serving: **4 distinct sites** (rows 13–16
  above cover 3 call sites on one route pair + 1 on token-mint), plus the
  **8-route** result-set family (rows 17–24) and the **1** CWE-862 finding
  (row 25) — all fixed.
- Informational, no fix needed: `POST /api/v1/rbac/check` (routed to the
  topology-floor concern instead).

No routes were left in an unresolved/undecided state **within this sweep's
scope** — `rest_api_v1.cpp`'s 74 `auth_fn` call sites and `mcp_server.cpp`'s
3 (per the sweep note in the ADR). The nine other `*_routes.cpp` files
(guardian, dex, deployment, preflight, schedule, device, network, inventory,
tar_tree) were not re-swept here; they already carry `deny_service_scoped_*`/
`token_scope_service` handling from prior PRs in this saga (found by
compliance-officer, Gate 6) and are not re-verified by this document.
