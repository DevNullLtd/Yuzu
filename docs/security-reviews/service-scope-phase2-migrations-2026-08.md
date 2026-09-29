# Phase 2 migrations — real confinement (#3290)

**Date:** 2026-08-20
**Context:** guardian-confinement-2298 PR 3 ("the flip", #3278, ADR-1006) closed the
service-scope confinement gap with a blanket default-deny — any `require_permission`-gated
route not on the seeded-empty `kServiceScopeGlobalSafe` allow-list refuses a service-scoped
API token outright. That is defense, not function: the route is safe but *unusable* by a
service-scoped token. #3290 is the follow-through — migrate routes onto real per-request
confinement (`AuthRoutes::require_fleet_read`/`confine_agent_target`) so a correctly-confined
service-scoped token gets a real, filtered answer instead of a 403. This doc is the reusable
migration record: what changed, why this route first, and the backlog for what's next.

## Correction to the issue's own wording

Criterion 2 of #3290 implies migrating a route means adding an entry to
`kServiceScopeGlobalSafe`. That's backwards for the common case: `require_fleet_read` never
consults the allow-list at all — a migrated route **replaces** its `require_permission` call
with the gate (see `require_fleet_read`'s own doc comment for the BLOCKING falsifier on
pairing the two). The allow-list is only for the rare case of a fleet-wide aggregate with no
per-agent identity to confine by, re-admitted unconfined — a much higher bar, separately
security-guardian-signed-off, not exercised by this migration.

## Migration 1: `GET /api/v1/inventory/software` + MCP `query_installed_software`

### Why this route first (criterion 1 substitute — documented reasoning, not the metric)

`yuzu_auth_service_scope_default_denied_total` — the metric criterion 1 says to prioritize
by — has no real traffic to rank with: there is no production fleet yet. The substitute is
**documented reasoning**: rank read-only, high-value fleet reads an ITServiceOwner token
plausibly needs first (this route — per-service software/CVE triage is a canonical
service-token use case), defer mutations to their own later PRs (`confine_agent_target` +
`require_scoped_permission` pairing, a different primitive), and prefer a route whose REST
deny was already provably dead code (zero behavior change on that surface) with a live MCP
twin to prove the pattern on both transports in one PR.

### What changed

- `AuthRoutes::require_fleet_read` (Phase 0, PR #3216, zero callers) gained the
  elevated/engine/mcp_tier caller-class branches it was missing — mirroring
  `require_list_read`'s ladder, not `require_permission`'s (no belt-and-braces
  service-scope-allow-list check; `require_fleet_read` has no allow-list to guard). Without
  this, an engine principal under RBAC-off would have fallen through to
  `authorize_list_read`'s legacy-open `AdmitAll` — a real regression the moment a route
  migrated onto the bare Phase-0 primitive.
- `authz::FleetReadGate` — a plain, fakeable aggregate (`{bool admitted; VisibleSet scope;}`)
  is the new REST/MCP injected-callback seam, mirroring `ListReadGate`/`ListReadFn`'s existing
  pattern. `ListAuthority` itself stays move-only/`AuthRoutes`-friend-only — the right shape
  for a direct in-process caller, wrong for `std::function` injection or a test fixture that
  needs to fake an admit without a live Postgres `RbacStore`.
- Both routes: `perm_fn`/`deny_fleet_wide_service_scoped` (REST) and
  `tier_allows`/`deny_fleet_wide_service_scoped`/`perm_fn` (MCP) replaced by the gate as the
  **sole** authorization check. The REST deny was provably dead (fired after `perm_fn`); the
  MCP deny was live — its `ServiceScopeClass::confined` label was backed only by that blanket
  deny before this PR, which is the "confined label with no real mechanism" the routed-concern
  row's clause 3 forbids.
- `InventoryScopeFn` (the old per-row management-group predicate, already inert under the
  prior global gate) retired entirely on both surfaces — zero callers after migration.

### Behavior changes (all deliberate, documented at the route/tool doc comment + OpenAPI spec)

| Caller class | Before | After |
|---|---|---|
| Service-scoped token, RBAC on, correctly confined | 403 (the flip) | 200, filtered to `meet(management-group, service-scope)` — the point of this PR |
| Service-scoped token, RBAC genuinely disabled (store open, `is_rbac_enabled()` false) | 403 | 403 (unchanged) |
| Service-scoped token, RBAC store null/not-open | 403 (indistinguishable from the row above) | 503 Degraded — a DISTINCT sub-case from "RBAC disabled": the null-store check fires before the RBAC-off check, so this reads as a retryable infra gap, not the same permanent posture (consistency-auditor finding, governance run 2026-08-20) |
| Management-group-scoped-only operator (no global grant) | 403 (`check_permission` is global-only, never consulted `ManagementGroupStore`) | 200, filtered (`AdmitScoped`) — closes ADR-0017's "World A" gap for this route |
| Global-grant operator / RBAC-disabled non-service caller | 200 unfiltered | unchanged |
| RBAC store null/not-open, non-service caller | 200 unfiltered (legacy fallback) | 503 Degraded — fail-closed hardening, called out explicitly |
| Management-group store null/not-open, non-service caller with no global grant | 403 (indistinguishable from "no grant") | 503 Degraded — closed in this same governance round (unhappy-path finding UP-1); the mid-query-degrade half of this same store (store opens fine, a later read fails) is NOT closed and still renders 403, the same deliberate weakening `authorize_list_read`'s other callers (`plugin_config_routes.cpp`, the upload-grants resolver) already accept — tracked, not fixed here |
| JIT-elevated operator | 200 unfiltered | 200 unfiltered (new caller-class branch) |
| Engine principal, RBAC on + grant | 200 unfiltered | 200 unfiltered (new caller-class branch) |
| Engine principal, RBAC off | 403 | 403 (new caller-class branch — the regression this migration would otherwise have shipped) |
| Tag store null/degraded, service-scoped caller | 403 (never reached the tag store) | 503 Degraded (retryable) |
| MCP-tier token, tier disallows this Read | N/A — no production caller existed pre-migration for this branch to apply to | 403 (new caller-class branch, deny-or-fall-through ONLY per routed-concern clause 2 — never self-admits; a tier-allowed token falls through unaffected into the rest of the ladder). Added to this table per docs-writer's Gate 8 finding (governance run 2026-08-20): the migration checklist below names `mcp_tier` as a required row and this table did not have one, despite the branch being real and tested (`test_authz_gates.cpp`'s "mcp_tier='readonly' token, Read op" case) |

### ACCEPTED — `devices_omitted` as a bounded existence signal (UP-2, ruled at Gate 8)

A service-scoped token can now (correctly) see `devices_omitted > 0` when a `name`-filtered
query matches software outside its own scope. Repeated queries by name let a confined caller
determine WHETHER a title exists fleet-wide, without seeing WHERE. This is the same shape of
signal `authorize_list_read`'s other confined callers already expose (a drop count, never the
dropped identities) and is openly documented in the route/tool schema text — it is not a new
class of leak this migration introduces, but it IS the first time a **service-scoped** (as
opposed to management-group-scoped) caller gets it, since the caller class was previously
denied outright.

**Ruling: ACCEPT** (security-guardian, Gate 8 re-review, governance run 2026-08-20, not
self-adjudicated by the author). Derivation: TRIGGER — a service-scoped token repeating a
`name`-filtered query against this route. IMPACT — bounded information disclosure: existence
only, never identity or location (`target_id`/`audit_key` is computed purely from the query
params, unaffected by scope narrowing) — base MEDIUM. EXPOSURE — requires an already-
authenticated caller holding `Inventory:Read` (not `E0`), so no raise applies. EPISTEMIC —
confirmed from code, not speculative. Two independent reasons: (1) suppressing the field for
this caller class would recreate the exact false-negative this route's own design forbids
elsewhere — an empty/short result under a confined scope must read as *incomplete*, never
*absent*, and a suppressed `devices_omitted` on a genuine existence-elsewhere case would do
exactly that; (2) every probe is individually audited (`inventory.software.query`,
`target_id=name=<title>`), so a dictionary-enumeration pattern is detectable after the fact —
a real, load-bearing compensating control, not merely an assertion that one could exist.

### Tests

Unit-level (fake gate): `test_rest_inventory_software.cpp` (`InvHarness`), rewritten —
gate-deny/401/unwired-503 tests replace the old RBAC-deny/service-scoped-deny tests (the
route no longer has its own auth to fake); scope-filter tests drive `fleet_scope` directly.
`test_mcp_server.cpp` similarly — `fleet_read_fn_for_test` replaces
`inventory_scope_fn_for_test`; the old "service-scoped token denied" test is rewritten to
assert the blanket deny is *gone*. An MCP-side unwired-`fleet_read_fn_`-fails-closed test was
added in the Gate 8 fix round (quality-engineer flagged the prior asymmetry: REST had a
dedicated test for this branch, MCP's fixture default always admits, so nothing exercised
production's genuinely-empty `McpServer::fleet_read_fn_` state on that transport).

New `[pg]` end-to-end tests (`InvE2ERig`, real `AuthRoutes`, the same conversion lambda
production wires) prove the actual `meet()` composition against a real `RbacStore`/
`TagStore`/`ManagementGroupStore` — coverage that existed nowhere at the route level before:
service-scoped token → real filtered 200; management-group-confined operator → real filtered
200 (the `AdmitScoped` case, previously untestable at this route since it always 403'd);
unscoped operator → unchanged; tag-store degraded → 503; RBAC-off + service token → 403; a
genuine gate deny → exactly one `X-Correlation-Id` header and the correct
`auth.fleet_read_required`/empty-target audit shape (added in the Gate 8 fix round — the OLD
blanket-deny path audited under `inventory.software.query`/`target_id=fleet` with a cid
embedded in the detail string; `require_fleet_read`'s own deny branches use a DIFFERENT
taxonomy, so re-asserting the old shape would have pinned a property this gate does not
provide).

Primitive-level caller-class coverage (elevated/engine/mcp_tier branches, plus the new
null-management-group-store branch added in the Gate 8 fix round):
`test_authz_gates.cpp` and `test_engine_principal_integration.cpp` §6c.

### Migration checklist (for whoever picks up the next backlog item)

Distilled from Migration 1's own "What changed"/"Tests" sections above — follow this shape,
not the numbers:

1. Confirm the route's REST deny fires AFTER its existing `perm_fn`/`tier_allows` call (dead
   code, zero-behavior-change retirement) vs is genuinely LIVE (a real behavior change to
   document) — check both transports independently, they can differ (this migration's REST
   deny was dead, its MCP deny was live).
2. Replace the permission check with the gate as the SOLE authorization call — never stack the
   two (`require_fleet_read`'s own doc comment states the BLOCKING falsifier).
3. Retire the route's old per-row scope predicate (if any) once the gate's composed
   `VisibleSet` fully replaces it — check for dangling references in tests, not just
   production code.
4. Write the behavior-change table FIRST, one row per caller class from the shared preamble
   (elevated / engine / mcp_tier / service-RBAC-on-confined / service-RBAC-off /
   service-store-null / mgmt-scoped-only / global-grant / RBAC-store-null / mgmt-store-null /
   tag-store-degraded) — this migration shipped with two of these rows missing or conflated on
   the first pass and needed a governance round to catch it.
5. Add unit-level fake-gate tests for the route's OWN reaction to the gate's decision, plus
   `[pg]` end-to-end tests proving the real `meet()` composition against live stores — on BOTH
   transports if both exist; a fake-gate-only proof on one transport is a real, not merely
   theoretical, coverage gap (this migration shipped with exactly that MCP-side gap).
6. Grep the WHOLE repo for stale prose the migration falsifies — not just the file you're
   editing. `grep -rln "<tool_or_route_name>" docs/` once for a mechanical sweep, but expect it
   to still miss instances phrased with different terms (the audit verb name, an ADR's own
   tracking checklist, a customer-facing upgrade note) — this migration needed TWO governance
   rounds to find everything a single grep missed.
7. Update the routed-concern row's own illustrating examples if your migration retires the one
   it was citing — an example that goes stale silently is worse than no example, because it
   reads as still-current.

## Ranked backlog for subsequent migrations

1. **Bucket 1a — retire the provably-dead after-gate REST denies. DONE (2026-08-21).**
   Each one's deny fired after its route's own `perm_fn` already ran, so retirement was
   zero-behavior-change: `schedule_routes.cpp:67`, `server.cpp`'s three schedule routes
   (`schedule.list`/`.delete`/`.enable`), `mcp_server.cpp`'s `get_dex_group_app_perf`. No
   route migration needed — deleted the dead calls + updated the stale doc comments;
   `deny_service_scoped_schedule` (`schedule_routes.{hpp,cpp}`) had all four of its call
   sites removed and was retired entirely (declaration, definition, and its direct
   unit-test block). One real gap found while verifying the `schedule.enable` site's
   reachability, deliberately NOT fixed here (own PR only, per author's own scope
   decision): the route's `require_permission(Schedule,Write)` gate fires unconditionally
   before `enabled` is even parsed, so the documented "disable stays reachable as the kill
   switch for a service-scoped token" guarantee does not currently hold — filed as #3378.
   One test-fixture gap found and fixed: `test_mcp_server.cpp`'s `get_dex_group_app_perf`
   deny test relied on the now-retired interim deny for its assertions; `McpTestServer`'s
   fake `perm_fn` defaults to "always allow" (unlike production's real
   `require_permission`), so the test needed an explicit `perm_override_for_test` to keep
   proving the tool still denies a service-scoped token post-retirement — without it, the
   test would have silently started asserting nothing. Governance's own Gate 3
   quality-engineer pass surfaced a second, related gap this PR does not fix: only
   `POST /api/schedules` (create) has real route-level end-to-end test coverage — list,
   delete, and enable never did (their only prior "coverage" was the now-deleted direct
   unit test of the retired helper, which never went through the real routes at all).
   This is the exact shape that let #3378 go undetected — filed as #3390.
2. **Read-only fleet reads, by plausible ITServiceOwner value** (this migration's own
   reasoning, applied forward): device/network lists (`list_dex_perf_devices`,
   `list_network_devices` + REST twins) → `list_schedules` → DEX/Guardian reads.
3. **Mutations, last** — a different primitive pairing (`confine_agent_target` +
   `require_scoped_permission`, single-agent-shaped, not `require_fleet_read`).
4. **§3d — the `authorize_list_read` supersede→intersect migration** (ADR-1006's deferred
   item; two twin-pairs, `plugin_config_routes.cpp`/MCP `list_plugin_config` and the
   upload-grants resolver at `server.cpp:17722`/`:18307`). Separate stream — the
   plugin-config pair has no agent dimension, so it needs a `kServiceScopeGlobalSafe`-style
   policy decision rather than a `meet()`, unlike upload-grants' clean intersection.
5. **Bucket 3 — routes with no primary RBAC gate at all** (the `deny_service_scoped_session`
   family, the `/api/v1/result-sets` family, `/api/scope/estimate`, compliance fragments).
   **Explicitly out of scope for a `require_fleet_read` migration** — these need a gate added
   first (§3e class), a different and larger change than narrowing an existing one.

Known open items this migration surfaced but did not resolve:

- ~~`docs/auth-architecture.md:2458` vs `docs/mcp-server.md:22` disagree on whether a bare
  `perm_fn` ... qualifies an MCP tool's `confined` label~~ — **resolved in this migration's own
  Gate 8 fix round**: both now list `fleet_read_fn_`/`require_fleet_read`'s `meet()`
  composition as a qualifying real-confinement mechanism, since this migration made it one.
  Still open for the remaining 7 MCP denies: whether a bare `perm_fn`/`scoped_perm_fn` alone
  (no `fleet_read_fn_`-class mechanism) is enough, resolve when retiring those.
- `docs/auth-architecture.md:2464`'s "Dispatch's supersede→intersect migration" sentence
  conflates `authz::meet`'s dispatch-confinement use (ADR-0033, `compose_exec_visible` —
  genuinely supersede, zero `authorize_list_read` callers) with the actual §3d targets (4
  `authorize_list_read` callers, unrelated to dispatch). Not fixed here — out of this PR's
  diff scope; flag for whoever picks up §3d.
