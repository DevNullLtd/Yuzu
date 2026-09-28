---
status: accepted
date: 2026-06-28
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; issue #1714 (intent question)
scope: server — authorization shape for list/fan-out reads of per-agent data under management-group confinement
resolves: #1714
context-refs: #1634 (response-reader ruling), PR #1711 (per-row filter foundation), #1550 (query_responses scoping), #1713/#1676 (inventory)
---

# 0017 — Management-group confinement applies to list/fan-out reads: the admit-then-filter list gate

> **Update (2026-07-24) — #1715 resolved; PR-A foundation landed.** The global↔management-group
> deny-precedence lattice the "Combining algorithm" section below left *undecided* has been decided:
> **cross-boundary combining is additive/OR; deny-overrides applies only within a single group's
> assignments.** Concretely — **(a)** a global explicit-**deny** does **not** override a management-group
> **allow** (authority is additive — a row is readable *from* the group grant, per the #1634 ruling);
> **(b)** a global **allow** **does** override a group deny (→ `AdmitAll`). This ratifies the shipped
> `check_scoped_permission` behaviour, so PR-A's one-resolver refactor is behaviour-preserving for
> per-device authz and carries no migration. Frozen in `RbacStore::resolve_perm_groups` — the single
> INV-7 resolver behind `authorize_list_read`, `holds_permission_via_any_group`,
> `visible_agents_for_permission`, and `check_scoped_permission`. **PR-A** (the `authorize_list_read`
> chokepoint returning `DenyAll | AdmitAll | AdmitScoped(visible_set)` + the two primitives + the two
> batched `ManagementGroupStore` queries + the set-equivalence property test + the INV-7 cross-check)
> has landed; **no call site is switched yet** (PR-B…E do the per-surface wiring). The transport
> wrappers (`require_list_read` etc.) land with their first caller in PR-B rather than uncalled here.
> Ships alongside the decision-independent **#1717** fail-closed gate fix (`require_permission` /
> `require_scoped_permission` gate on `rbac_enforcement_in_effect`).
>
> **Update (2026-08-15) — `AuthRoutes::require_list_read` has a live first caller, outside the
> PR-B…E ladder.** `GET /api/v1/guaranteed-state/status` (#2298 item 6d / #3038) now gates via
> `require_list_read` as its sole authorization primitive — the transport wrapper this ADR names
> is no longer "uncalled." An earlier attempt (commit `9269b5636`) stacked a direct
> `authorize_list_read` call behind the pre-existing flat `require_permission` gate instead of
> replacing it, which does not compose (`require_permission`'s RBAC branch never consults
> `ManagementGroupStore`); the corrected wiring (`369643caf`) replaced both with the single
> `require_list_read` gate this ADR anticipated. This landed independently of the PR-B…E
> enumeration below (which still tracks `responses`/device-list/inventory/audit-log/DEX/TAR) —
> update that list's own status per-surface as each one actually switches, don't infer this
> route's completion applies to any of them.

## Context

Management groups confine an operator to a subset of the fleet. For **per-device** routes this
works today: the route's admission check *is* `scoped_perm_fn_(req, res, "<securable>", "<op>", id)`
(`device_routes.cpp:535`), which calls `RbacStore::check_scoped_permission`. That function admits a
caller who holds the permission either **globally** (step 1, the global `check_permission`,
`rbac_store.cpp:1115`) **or** via a management group containing `agent_id` (steps 3-5,
`rbac_store.cpp:1122-1180`, consulting `ManagementGroupStore::get_group_roles` / the
`management_group_roles` table). A single `agent_id` is available, so the scoped check can serve as
the gate.

For **list / fan-out** reads (responses, the device list, inventory, audit-log, DEX/TAR list
surfaces) there is no single `agent_id` to gate on. These routes instead gate on the **global**
`require_permission` / `perm_fn` (e.g. `dashboard_routes.cpp:203`, `rest_api_v1.cpp:3479`,
`mcp_server.cpp:1217`, `server.cpp:5307`) and then — where a filter exists at all — drop out-of-scope
rows per-row with `check_scoped_permission(user, sec, op, agent_id)`.

That shape is **inert**. UAT-proven (Windows, real server, `Operator@G1`-confined user `opA`,
agent-1 ∈ G1; full reproduction in #1634 / `streamB-maintainer-finding`), grilled with 5 disproof
attempts, all failed:

- **Global holder** (admin / global Operator): passes the global gate; `check_scoped_permission`
  step 1 returns true for **every** agent → the per-row filter is a no-op → sees the whole fleet.
  *(UAT: admin saw agent-1 + agent-2.)*
- **Confined operator** (`Operator@G1`): the global gate is `check_permission`, which consults only
  `principal_roles` (user) ∪ RBAC `group_members` (`collect_roles_locked`, `rbac_store.cpp:930-952`)
  — **never** the management-group `GroupRoleAssignment`s. So the confined operator is **403'd at the
  gate** and never reaches the filter. *(UAT: opA → 403 on `/api/responses/*`, `/api/agents`,
  `/fragments/devices/list`.)*

There is **no** RBAC configuration where an operator passes the global list gate *and* the filter
narrows. The per-row filters shipped for responses (#1634 / PR #1711) and `query_responses` (#1550)
are correct-but-unreachable. The same applies to `ManagementGroupStore::get_visible_agents`
(`management_group_store.cpp:628`): it narrows by **role-existence** (any role in the group,
`principal_type='user'` only, same-group join with **no hierarchy walk** — already inconsistent with
`check_scoped_permission`'s ancestor-aware admit) rather than by the *specific* permission, and is
itself unreachable for a confined operator / short-circuited for a global holder.

This issue (#1714) is the intent question that gates that whole class of work: **is list-view
management-group confinement actually intended?**

- **World A — yes (latent gap):** a confined operator who holds `Response:Read` (or
  `Infrastructure:Read`, `Execution:Execute`, `Inventory:Read`, `AuditLog:Read`) via a management
  group should see, in list/fan-out reads, only the agents inside those groups.
- **World B — no:** operators hold **global** read; management groups confine **only per-device
  routes** and organize the fleet. The per-row filters are unnecessary.

**Nothing is leaking today** — no management-group-confined operators exist in practice (they would
be 403'd everywhere), which is precisely why this sat undetected across multiple shipped features.
High-importance architecture debt, low operational urgency. Decide deliberately; do not hotfix.

## Decision

**World A.** List-view management-group confinement is intended. A confined operator who holds a
read permission via one or more management groups must, on list/fan-out reads, be **admitted** and
shown **only** the agents within those groups (ancestor-aware), exactly as the per-device routes
already behave for the single-`agent_id` case.

Three signals make World A the standing intent, not a new aspiration: the explicit #1634 ruling ("a
response is readable iff the caller holds `Response:Read` via a management group containing the
response's `agent_id`"); the scoped-grant machinery (`Operator@G1` delegation, `GroupRoleAssignment`,
`management_group_roles`) already exists and was built for confinement that cannot currently take
effect; and the per-device `scoped_perm_fn` precedent *is* World A for the single-id case.

### What is missing: mostly the gate shape — plus one undecided model question

`check_scoped_permission` (steps 3-5) **already expresses** per-agent management-group authorization
at the single-`agent_id` granularity. World A is therefore *largely* a gate-shape change, not an RBAC
rewrite. Two mechanical pieces are missing, and one semantic question is genuinely undecided:

1. **A list-admit primitive.** "Does this user hold `<securable>:<op>` via *any* management group?"
   — because a list gate has no single `agent_id` to pass to `check_scoped_permission`. New
   `RbacStore` computation, e.g. `holds_permission_via_any_group(user, securable, op, mgmt_store)`,
   mirroring steps 3-5 over the union of the user's reachable management groups.
2. **A permission-specific visible set.** The per-row filter / batched narrowing must key on the
   *specific* permission, not `get_visible_agents`' role-existence. **Direction is load-bearing:**
   `check_scoped_permission` admits an agent via its group **or any ancestor** (downward
   inheritance), so the inverted visible set must start from {groups where the user holds the
   perm-role} and walk **descendant-ward** to members. Collect direct members only → under-disclose
   vs the per-device gate; include ancestors' agents → over-disclose. PR-A must freeze the
   set-equivalence invariant:

   > `visible_agents_for_permission(u, s, o) == { a : check_scoped_permission(u, s, o, a) }`

   asserted by a property test over a fixture group tree (stronger than re-running the UAT).
3. **The combining algorithm across the global↔group boundary is UNDECIDED** (see next section). This
   *is* a model-level question, so the "only the gate shape" framing is qualified: the gate shape
   covers (1)+(2); the precedence lattice in (3) is a real model decision PR-A must freeze.

### Combining algorithm across the global↔group boundary (undecided — own issue)

Today a **global explicit-deny + a group allow ADMITS**: `check_permission` returns false on a global
deny (`rbac_store.cpp:1014-1017`); `check_scoped_permission` step 1 short-circuits only on an *allow*
(`:1115`), then falls through to steps 3-5, which read **only** `management_group_roles` — so the
global deny is not consulted. The proposed `holds_permission_via_any_group` OR-gate inherits this
exactly.

This is **not self-evidently a bug.** A global-deny-made-absolute forecloses the "deny globally,
re-grant per group" delegation idiom — a plausible *intended* use of `GroupRoleAssignment`, and the
#1634 ruling reads **additive** (readability comes *from* the group grant). So the cross-boundary
behavior may be a feature. The ADR does **not** prescribe deny-overrides; it records that the
precedence lattice (does a global deny override a group allow? does a global allow — an `is_global`
holder — override a group deny?) is **undecided and must be decided in its own issue**, then frozen
in **one** shared implementation used by `holds_permission_via_any_group`, the batched visible-set,
and `check_scoped_permission`, so list and per-device authz can never diverge. (Earlier drafts that
said "deny-overrides preserved" were wrong: deny-overrides holds only *within* a group's assignments,
not across the boundary.)

### The admit-then-filter list gate — one chokepoint, three transports

Rather than each route orchestrating two calls (admit + `is_global`) plus a filter — three things a
route can wire wrong, exactly the per-route drift this pattern exists to avoid — the decision is a
**single chokepoint returning a discriminated result**:

```
RbacStore::authorize_list_read(user, securable, op) -> DenyAll | AdmitAll | AdmitScoped(visible_set)
```

- **Placement is load-bearing.** The *computation* lives in `RbacStore` (it owns
  `check_permission` / `check_scoped_permission` / the new primitives) because list surfaces span
  **three transports** — REST (`AuthRoutes`), MCP (`mcp_server.cpp`), and dashboard fragments — and
  only an `RbacStore`-level chokepoint is shared by all three. Each transport wraps it with its own
  403 / audit envelope: `AuthRoutes::require_list_read` (REST, sibling to `require_scoped_permission`
  and to the `rest_audit.hpp` #1647 chokepoint precedent), the MCP equivalent, the dashboard
  equivalent.
- `DenyAll` → 403 (REST) / empty (dashboard). `AdmitAll` → unfiltered read (global holder).
  `AdmitScoped(set)` → the route reads **only** `set` (preferably pushed into SQL `WHERE agent_id IN
  (...)`).
- For **aggregates** (`aggregate_responses`) and **paginated** reads (#1550), the visible set MUST be
  applied **in SQL before** the aggregate / `LIMIT` (see invariants). Post-fetch per-row filtering is
  permitted **only** for bounded, unpaginated, unaggregated lists.
- Honest caveat: a single chokepoint *reduces* but does not *eliminate* "forgot to apply" — the route
  still applies the returned predicate to its own rows. The confined-operator UAT + the invariant
  tests below are the regression guard.

### Design invariants the implementation must satisfy

Folded from the Gate-4 unhappy-path register. CRITICAL invariants are confidentiality-load-bearing;
a wiring PR that violates one is a blocking defect.

- **INV-1 (CRITICAL) — fail-closed is total.** `authorize_list_read` returns `DenyAll` (not
  `AdmitAll`) on any `rbac.db` / mgmt-store error or `!is_open()`. The `AdmitAll` discriminant must
  never be the error default. Key on `rbac_enforcement_in_effect()` (`rbac_store.cpp:511`), which
  already fails closed on `!is_open()`.
- **INV-2 (CRITICAL) — empty visible set ⇒ empty result.** `AdmitScoped({})` returns zero rows. A
  query builder that omits the `WHERE agent_id IN ()` clause on an empty list (degrading to
  unfiltered) is the canonical fail-open; tests must cover it.
- **INV-3 (CRITICAL) — batched, before LIMIT/aggregate.** Any paginated or aggregated read applies
  the visible set as `WHERE agent_id IN (...)` **before** the aggregate or `LIMIT`. COUNT/SUM/AVG and
  GROUP BY values must be computed over the in-scope set only; LIMIT-before-filter (the #1550 known
  issue) yields short/empty pages and silently drops in-scope rows for confined operators.
- **INV-4 (CRITICAL) — descendant-ward expansion.** The batched visible set expands each
  perm-holding group **to its descendants** (mirror of `check_scoped_permission`'s ancestor-ward
  admit), so admit / batched / per-row agree. Pin the direction in code + test.
- **INV-5 (CRITICAL) — partial failure drops, never includes.** A per-row or batch resolution error
  (mgmt-store unavailable mid-read, ancestor lookup throws) drops the row or 503s the whole read —
  never includes the row. Recommended posture: whole-read 503 for confidentiality.
- **INV-6 (CRITICAL) — do not port the #1453 full-fleet fallback.** `get_visible_agents` returns
  `all_member_agents()` (the whole fleet) when the RBAC probe reports disabled
  (`management_group_store.cpp:638-639`). The new `visible_agents_for_permission` must NOT copy this;
  it keys on `rbac_enforcement_in_effect()` and fails closed. PR-C deletes the role-existence narrower
  and its full-fleet fallback rather than extending them.
- **INV-7 (CRITICAL) — one resolver.** Admit, batched-set, and per-row are one shared resolver (the
  discriminated chokepoint), guarded by a cross-check unit test (precedent: the H2/G9 schema↔handler
  cross-check) so a later edit can't make admit say yes while the filter shows nothing.
- **INV-8 (SHOULD) — cache invalidation tracks the graph.** Any visible-set / `is_global` cache
  (the many-groups case will demand one) MUST invalidate on `management_group_members` /
  `management_group_roles` / hierarchy mutations, not only RBAC writes (the existing `perm_cache_`
  hook). Stale visibility = over-disclosure after a regrouping.
- **INV-9 (SHOULD) — filter path is exercised and observable.** Most test principals are global, so
  the `AdmitScoped` path can ship broken behind green tests. Mandate the `opA`-confined UAT *plus* a
  unit assertion that `AdmitScoped` is returned for a confined caller, and emit a metric/log
  distinguishing filtered vs unfiltered list reads.
- **INV-10 (SHOULD) — batched, not N+1.** Resolve the visible set in one query, not a per-row
  ancestor walk; the many-groups × deep-hierarchy case is a latency/DoS surface otherwise. Cap and
  measure group count.
- **INV-11 (SHOULD) — hierarchy depth.** `get_ancestor_ids` is depth-capped (10). Prefer
  **cap-and-warn**: document the max-supported depth and surface a warning when hit (a deeper agent is
  denied in-scope rows — fail-closed but wrong). Removing the cap is the weaker option (it trades the
  bounded-recursion posture for an unbounded walk guarded only by the visited-set).
- **INV-12 (SHOULD) — the visible set constrains every per-agent source.** Apply the visible set to
  *every* per-agent data source feeding the response — secondary fetches, enrichment JOINs, and
  counts — not just the primary table. A read that filters the primary `WHERE agent_id IN (set)` but
  enriches via an unfiltered join or a secondary dispatch (cf. the process-tree dual-dispatch
  `network_diag` join) leaks out-of-scope data through the side channel.

### In scope (per-agent list/fan-out reads)

The surface list below is **indicative**, sourced from the #1634 / `streamB-maintainer-finding`
sweep — it is the decision's coverage map, not the authoritative wiring checklist. The test for
in-scope is **data-shape, not route-family**: *does a returned row carry `agent_id`?* Each wiring PR
**re-enumerates exhaustively** within its surface (grep every `perm_fn` / `require_permission`
list-read site, apply the `agent_id` test) so a missed route does not silently inherit the old global
gate.

- **Responses** — `query_responses` (#1550), `aggregate_responses` (filter-before-aggregate),
  REST `/executions/{id}/visualization`, `/api/responses/{id}` (GET list) + `/export`, dashboard
  `/fragments/results` + the scan fragment, workflow execution-detail.
  - **dashboard `/fragments/results` table + workflow execution-detail's responses section AND
    status grid/table: DONE (#1712, #3290 Phase 2 continuation)** — migrated onto
    `require_fleet_read`, replacing `perm_fn`/`perm_fn_` as the sole gate; confinement is now
    effective on all four (the status grid/table was a same-PR adversarial-review finding: the gate
    migration itself admits a confined caller class the old flat gate denied outright, so the grid
    needed the same filter as the responses section, not just the table). The scan fragment,
    `query_responses`, `aggregate_responses`, and the REST endpoints above remain on the older,
    still-largely-inert `response_scope_fn` mechanism (#1634) — not touched by this migration.
    **Update (#1634, closed):** `query_responses`, `aggregate_responses`, and the REST
    `/executions/{id}/visualization` + `/api/responses/{id}` (+`/aggregate`/`/export`) family all
    migrated onto `require_fleet_read` in a later PR, retiring `response_scope_fn` on these
    surfaces entirely. The scan fragment is unaffected by this update and remains as described.
    **NOT done, pre-existing (not introduced or worsened by #1712):** the SAME dashboard
    results workflow's sidecar routes — `/fragments/results/filter-bar` (reads
    `ResponseStore::facet_values`), `/fragments/create-group-form` (reads `facet_agent_count`), and
    `POST /api/dashboard/group-from-results` (reads `facet_agent_ids` then adds every returned id as
    a group member — a WRITE) — all still gate on flat `perm_fn_` and apply no scope predicate to
    the underlying `response_store.response_facets` query. `filter-bar` is gated on the same
    `Response:Read` securable as the now-migrated table, so a genuinely confined-only caller (the
    `#1715(a)` additive-grant class) cannot reach it at all — latent, not active. `create-group-form`
    /`group-from-results` gate on a *different* securable (`ManagementGroup:Write`), which has no
    logical tie to a caller's `Response:Read` confinement — a real persona holding both (global
    group-write + confined response-read) can use the unscoped facet query to discover and enroll
    out-of-scope agents. Tracked as a follow-up, not fixed by #1712 — see #3489
    (canonical; #3525 tracked the same finding and was closed as its duplicate).
- **Executions (legacy pre-v1 routes)** — `GET /api/executions` (list), `/{id}` (detail),
  `/{id}/summary`, `/{id}/agents`, `/{id}/children`, `POST /{id}/rerun`, `POST /{id}/cancel`
  (`execution_routes.cpp` as of #2542 PR-7, extracted from `server.cpp`) — absent from every prior version of this coverage map; found during #1634's own
  Gate 2 review and deliberately deferred to a dedicated issue rather than folded into that PR.
  **DONE (#3789, closed):** all seven migrated onto `require_fleet_read`/`authz::in_scope`, matching
  the `GET /api/v1/executions/{id}` shape documented in `docs/auth-architecture.md`'s "Fourth
  migration (#3789)". The LIST route's confinement predicate is pushed into SQL before `LIMIT`
  (INV-3) via a correlated `EXISTS` over `agent_exec_status` plus an owner disjunct — a real
  visible-agent intersection, not the own-dispatches-only shortcut MCP `list_executions` still uses
  (`docs/auth-architecture.md`'s Third migration paragraph). The two mutating routes keep `require_permission(Execution, Execute)` ahead of
  `require_fleet_read(..., "Read")` (the fleet gate is structurally Read-only, INV — see
  `authz_gates.cpp`) and apply a stricter complete-cohort-in-scope rule, not bare visibility, before
  allowing a rerun/cancel. Coverage: `tests/unit/server/test_legacy_executions_scope_authz.cpp`.
- **Device list** — `/api/agents` (`server.cpp:5312`), `/fragments/devices/list`, the dashboard
  `get_visible_agents` callers (`dashboard_routes.cpp:989/1159/1889`, `server.cpp:7892`),
  `get_visible_agents_json` (`server.cpp:3784/8543`).
- **Inventory** — `query_installed_software` (MCP) + `GET /api/v1/inventory/software` (REST):
  **DONE (#3290, 2026-08-20)** — migrated onto `require_fleet_read`, the admit-then-filter gate
  this ADR designed; confinement is now effective on both surfaces.
  - **`/inventory` dashboard FIND** (`InventoryRoutes`, `inventory_routes.cpp` find/results) shares
    the SAME per-row drop filter + omission audit as the REST/MCP siblings above — it converts the
    same way (swap its `Inventory:Read` gate to admit-then-filter; the per-row filter is already
    present).
  - **⚠ `SoftwareInventoryStore::software_catalog` / `software_versions`** (the `/inventory`
    Software-tab fleet aggregates) are a DIFFERENT shape: they read a **precomputed, fleet-wide
    rollup** (`catalog_rollup` / `version_rollup`, recomputed across ALL agents by the background
    `SoftwareCatalogRollup` thread). A shared global rollup **cannot** take a per-row
    admit-then-filter at read time — the counts are already aggregated across every group, and the
    rollup is one shared table, not a per-operator view. They are safe **only** while the
    `Inventory:Read` gate stays global (a confined operator is denied at the gate). When PR-D below
    flips Inventory to admit-then-filter, the catalogue **MUST stay pinned to a global-only
    permission** (per-operator rollups — one materialised table per management group — are the only
    alternative and are out of scope). It **MUST NOT** be left on the flipped gate, or it becomes an
    INV-3 cross-group count leak. The UI scope caveat is *not* the safeguard (it shows only to
    operators who already hold global read); this ADR entry is.
- **Audit-log** — `AuditLog:Read` reads (`server.cpp:5848`); audit rows carry `agent_id`, so a
  confined auditor must see only in-scope events. (Classified here per Gate-2/Gate-3 review; it is
  also a no-per-agent-filter reader, so it is in the fail-closed ship-now fix below.)
- **DEX / TAR list surfaces** — the DEX `VisibleSetFn` seam (`server.cpp:7888` def, `:8386` wiring,
  `dex_routes.hpp:311`) + remaining TAR/dashboard list fragments.
  - **Update (2026-09-28, WS-A4 PR-1 Gate 7 fix round, third revision — Fraser decision: revert to
    base gating):** `GET /api/v1/dex/signals/{obs_type}`, `GET /api/v1/dex/app`, and `GET
    /api/v1/dex/overview` (REST + MCP) stay pinned to a GLOBAL-only `GuaranteedState:Read` permission
    check — the same bare gate they had before this PR, never migrated onto `require_fleet_read`.
    Two intermediate designs were tried and reverted in review: pinning the three routes onto
    `require_fleet_read` (round 1), then adding a 403 refusal for an admitted-but-scoped caller
    (round 2). Every field they return (`subjects[]`/`by_os[]`/`devices[]`/`by_day[]`/
    `top_devices[]`/`top_apps[]`, etc.) is a query-time `GROUP BY` over agent-attributed rows —
    **not** a precomputed rollup like `software_catalog`/`version_rollup` above, so the rationale
    for pinning it global-only is different: it is simply **not yet confined per-caller** — an
    INV-3-respecting per-caller SQL slice (a `WHERE agent_id IN (...)` narrowing derived from the
    caller's visible set, applied INSIDE the aggregation, not a post-aggregate filter) has not been
    built for these three queries yet. Filing that as its own tracking issue is future work, not
    this fix round's scope. The `/fragments/dex/overview`, `/fragments/dex/app`, and
    `/fragments/dex/catalogue/signal` dashboard fragments are UNCHANGED by this fix round: they also
    gate on the SAME global `perm_fn` (a group-only operator is denied `403` there too, same as the
    REST/MCP surfaces) — the residual is the OPPOSITE of a confined-caller leak: among callers who
    DO hold the global grant, the fragments additionally narrow their device list by the
    permission-agnostic `Infrastructure:Read` `visible_set_fn` (a DIFFERENT securable from this
    row's `GuaranteedState:Read` gate) — tracked for the dashboard-rewire follow-up (PR-2), which
    also owns deciding whether that narrowing is correct or itself a bug.

### Out of scope (global by design)

Config / settings / CA / auth / discovery-write / offload / notification routes operate on
fleet-global or non-per-agent data and remain global-gated. This list is itself subject to the same
**data-shape re-enumeration**: a wiring PR must confirm each "out-of-scope" route really returns no
`agent_id`-bearing rows before leaving it global — the asymmetry (indicative-in-scope but
definitive-out-of-scope) is exactly how a per-agent reader hides forever (audit-log was such a case).

### Ship-now, decision-independent fixes (either world)

Two corrections are needed whether A or B is chosen and should ship independently of the gate work:

- **Doc honesty.** The docs/comments that *claim* effective list-view scoping today are false-as-
  shipped: `docs/user-manual/tar.md:302` ("scoped to your management-group visibility"), the
  inventory/MCP "out-of-scope devices omitted" strings (`mcp_server.cpp:255/1436`,
  `mcp_server.hpp:96`, `rest_api_v1.cpp:3235`, `rest_api_v1.hpp:116/129`, `docs/user-manual/inventory.md:106/141`,
  `docs/rest-api.md:2659`, `docs/mcp-server.md:45`). **Highest priority:**
  `docs/enterprise-readiness-soc2-first-customer.md:170` makes an affirmative **CC6.1 / CAIQ**
  tenant-isolation claim ("one operator cannot read another's device software… the affirmative answer
  to the CAIQ confidentiality question for this surface") — the most compliance-load-bearing instance,
  because it feeds a customer-facing CAIQ answer; revise to "designed for, not yet verified effective;
  confirmed via #1713/#1676 UAT before reliance." ADR-0016 (`:175/181`) makes the same claim and,
  being immutable, receives an **Update note pointing here** rather than an in-place edit. Until the
  gate lands, these read as "global read; per-device confinement only" (PR #1711 already corrected
  the response-reader strings). **Timing:** these corrections are customer-facing and ship as the
  ADR-0017 **companion PR** — before any customer is directed to those docs or a CAIQ is (re-)issued —
  not deferred to the gate ladder. If the CAIQ containing the line-170 claim has already gone to a
  prospect/customer, treat that as a BLOCKING retraction/caveat, not a routine doc fix.
- **Fail-closed list-read gate (HIGH).** The dashboard `/fragments/results` table
  (`dashboard_routes.cpp:1317`) and the workflow executions-drawer reader (`workflow_routes.cpp:548/550`)
  gate on flat `perm_fn` with **no per-agent filter at all**, and the gate **fails OPEN** on a
  corrupt/load-failed `rbac.db`: `require_permission` (call site `auth_routes.cpp:301`) keys on
  `is_rbac_enabled()` (def `rbac_store.cpp:493`), which returns `rbac_enabled_` — defaulted `false`
  (`rbac_store.hpp:118`),
  set true only on a *successful* config load (`rbac_store.cpp:485`). A failed open leaves it `false`
  → the legacy fallback returns **true for any `Read`** (`auth_routes.cpp:329`) → full-fleet response
  disclosure to any authenticated principal. The root cause is the **gate primitive**, not these two
  readers: `require_permission` keys on `is_rbac_enabled()` while the per-row filter keys on
  `rbac_enforcement_in_effect()` (fails closed). The fix is to make `require_permission` (and its
  scoped sibling) consult `rbac_enforcement_in_effect()` — closing the **entire** Read class at once,
  **behavior-neutral** for fresh installs (open db + enabled=false → `rbac_enforcement_in_effect` →
  false → legacy-allow preserved). This is independent of the gate-model decision and should ship at
  HIGH severity, tracked as a numbered risk-register entry with a mitigating control (the
  `rbac_enforcement_in_effect()` gate fix) and a target date. **Boundary:** the "nothing is leaking
  today" safe-harbour above covers ONLY the inert-confinement class (no confined operators exist to be
  under-restricted). It does **not** cover this fail-open, which discloses to *any* authenticated
  principal the moment `rbac.db` fails to load — independent of whether confined operators exist.

  **RESOLVED, both halves, in two separate PRs:** the fail-open half closed codebase-wide (not
  route-specific) via **#1717/#2472** — `require_permission`/`require_scoped_permission` now gate on
  `rbac_enforcement_in_effect()` exactly as this finding proposed. The no-per-agent-filter half closed
  for these two specific readers via **#1712/#3290 Phase 2 continuation** — both migrated onto
  `require_fleet_read` (the admit-then-filter gate this ADR designed), replacing `perm_fn`/`perm_fn_`
  outright rather than layering a filter under it: `dashboard_routes.cpp`'s `/fragments/results` and
  `workflow_routes.cpp`'s executions-drawer detail route (`/fragments/executions/{id}/detail`'s
  responses section AND its per-agent status grid/table, which reads a distinct store —
  `ExecutionTracker`, not `ResponseStore` — and needed the identical filter for the same reason: the
  gate migration itself admits a confined caller class the old flat gate denied outright, so leaving
  the grid unfiltered would have widened disclosure rather than closing it). The other three items
  under the "Responses" bullet below
  (`query_responses`, `aggregate_responses`, the REST `/executions/{id}/visualization` +
  `/api/responses` family, and the dashboard scan fragment) are **NOT** covered by either PR — they
  still use the older, still-largely-inert `response_scope_fn`/`response_agent_in_scope` mechanism
  (#1634), a distinct primitive from `require_fleet_read`; see `docs/user-manual/mcp.md`'s
  `query_responses` row for that mechanism's current status.
  **Update (#1634, closed):** `query_responses`, `aggregate_responses`, and the REST
  `/executions/{id}/visualization` + `/api/responses` family all migrated onto `require_fleet_read`
  in a later PR — `response_scope_fn`/`response_agent_in_scope` no longer computes scope on any
  of these surfaces. "Retired" describes the MECHANISM (nothing calls it to decide visibility
  anymore), not a completed code deletion: `ResponseScopeFn response_scope_fn` remains an unused
  parameter accepted and threaded through `rest_api_v1.cpp`'s constructor call chain (found in PR
  #3793's review, minor, not fixed) — dead plumbing, not a live second gate. The
  dashboard scan fragment is unaffected by this update and remains as described.

  **Also NOT covered by #1712, found during this PR's own governance re-review and previously
  absent from this coverage map entirely — the live streaming twin of the exact data this PR just
  confined on the request/response path:** the SSE channels `/sse/executions/{id}` (dashboard) and
  `/api/v1/events` (REST), both backed by `ExecutionEventBus`, publish `agent-transition` events
  (per-agent `agent_id`) and `execution-progress` events (unfiltered `agents_targeted`) for any
  `execution_id` to any caller holding a flat `Execution:Read` grant — including a caller this PR's
  own migration now narrows to `AdmitScoped` on the request/response drawer route. This is the
  same data-shape test this ADR's methodology names above (does a returned row carry `agent_id`?
  yes) reached via a route family the "grep every `perm_fn`/`require_permission` list-read site"
  sweep did not enumerate, since a streaming `Server::Get` handler is not a request/response
  list-read site in the shape the sweep was designed to find. Not introduced or worsened by #1712;
  tracked as a follow-up — see #3699.
  **Update (#1634, closed):** both SSE channels migrated onto `require_fleet_read` in a later PR,
  sharing one event projector (`execution_event_scope.hpp`) that filters `agent-transition` by
  `agent_id` and drops/sanitizes the execution-wide `execution-progress`/`execution-completed`
  events for a confined subscriber. #3699 is closed.

  **A WRITE-path sibling of the same shape, found during #1712's own governance re-review and
  undisclosed in this coverage map until then — now CLOSED (#3700):** `GET`/`PUT`/
  `DELETE /api/agents/:id/properties[/:key]` (`server.cpp`) read and wrote per-agent
  custom-properties data behind bare `require_permission("Infrastructure","Read"/"Write")` with no
  per-agent scope filter at all. Not introduced or worsened by #1712 — pre-existing, and absent from
  every prior enumeration of this ADR's surface list. Fixed by migrating all three routes to
  `require_scoped_permission("Infrastructure", "Read"/"Write", agent_id)`, the same per-target gate
  the Tag routes in `server.cpp` use — RBAC-off behavior is unchanged (`Infrastructure` is not in
  `kTopologyFloor`, so the legacy fallback branch is identical to `require_permission`'s). **Precision
  note (this fix's own PR review corrected an earlier draft of this bullet's framing):** the fix
  restores confinement for a management-group-**scoped-only** operator, previously denied outright
  on every agent (the flat gate never consulted management-group assignments) — not a narrowing of
  a global grant, which was and remains unconditional fleet-wide access by design, identical to
  every other `require_scoped_permission` caller. A THIRD caller class also changes: a
  service-scoped API token whose `ITServiceOwner` role holds `Infrastructure` permissions (the
  default seed) was previously blocked here by the flat gate's `kServiceScopeGlobalSafe`
  allow-list check (seeded empty — nothing clears it), and is now admitted on agents matching the
  token's own service tag via `require_scoped_permission`'s separate service-scoped branch, which
  checks `ITServiceOwner`'s role grant directly rather than that allow-list — Tag-route parity,
  working as intended. Coverage: `tests/unit/server/test_agent_properties_scope_authz.cpp`,
  including a source-text tripwire proving the route handlers still call the scoped gate (a
  primitive-level test alone cannot detect a handler reverted back to `require_permission`).

## Consequences

- A new, named authorization pattern (the admit-then-filter list gate, expressed as the
  `authorize_list_read` discriminated chokepoint) enters the codebase. Every future list/fan-out read
  of per-agent data must use it, not a bare global `require_permission`. This ADR is the contract
  those PRs build to, and the design invariants above are its acceptance criteria.
- The per-row filter foundation (PR #1711) and `query_responses` scoping (#1550) become **live**
  rather than inert once the chokepoint is wired in; #1550's gate must be swapped to the
  admit-then-filter shape (it has the filter, the wrong gate).
- One shared deny-precedence implementation (once the combining-algorithm issue is decided) backs
  list and per-device authz; a cross-check test pins admit/batched/per-row agreement (INV-7).
- Each surface re-runs the `opA`-confined UAT reproduction to *prove* narrowing (a confined operator
  is admitted and sees only in-scope rows; a global holder still sees all; both fail closed on a
  corrupt `rbac.db`), plus the INV-9 filtered-path assertion.
- Cross-operator authorization → every wiring PR runs the full governance pipeline with
  security-guardian + consistency-auditor + unhappy-path + chaos as load-bearing reviewers.

## Rejected alternative — World B

"Operators hold global read; management groups confine only per-device routes and organize the
fleet." Rejected because it contradicts the #1634 ruling, strands the `GroupRoleAssignment` /
`Operator@G1` delegation machinery (built specifically for confinement), and is inconsistent with the
per-device precedent. If World B were chosen the per-row filters would be deleted as dead weight and
the scoped-grant UI removed — a larger product reduction than building the gate. The doc corrections
and the fail-closed list-read gate above would still be required.

## Implementation ladder (separate governed PRs)

Sequenced; each its own governance round + `opA`-confined UAT re-run. (This ADR lands standalone,
ahead of PR-A.)

1. **PR-A — foundation.** The `authorize_list_read` chokepoint + `holds_permission_via_any_group`
   admit computation + the permission-specific `visible_agents_for_permission` (descendant-ward) +
   the transport wrappers (`require_list_read` etc.) + unit tests, including the **set-equivalence
   property test** and the **INV-7 cross-check**. Freezes the combining-algorithm decision (see the
   undecided-precedence issue) in one shared deny implementation. **No call site switched yet**, so
   it lands ahead of the wiring — but it is *not* semantically empty: it commits the precedence
   lattice and the visible-set semantics.
2. **PR-B — responses.** Builds on PR #1711's per-row filter; swaps the global gate for the
   chokepoint across the ~8 response readers; `aggregate_responses` filters **in SQL before**
   aggregating (INV-3); #1550's `query_responses` gate swapped.
3. **PR-C — device list.** `/api/agents`, `/fragments/devices/list`, the `get_visible_agents`
   callers, `get_visible_agents_json`; **delete** the role-existence narrower + its #1453 full-fleet
   fallback (INV-6), replace with the permission-specific set. Six callers across dashboard + server
   + json — consider splitting REST vs dashboard.
4. **PR-D — inventory.** `query_installed_software` + `GET /api/v1/inventory/software` —
   **DONE (#3290)**. `/inventory` dashboard FIND remains open (its own conversion, see above).
5. **PR-E — DEX / TAR / audit-log.** The DEX `VisibleSetFn` seam + remaining dashboard fragments +
   the `AuditLog:Read` surface.

Gate-independent, shippable now (not on this ladder): the doc corrections + the ADR-0016 Update note,
and the fail-closed list-read gate (HIGH). Tracked separately: the global↔group combining-algorithm
(deny-precedence) decision — a prerequisite for PR-A.

**Change-management traceability (Workstream F):** the spawned items are filed for closed-loop
evidence:

- **#1715** — the global↔group combining-algorithm (deny-precedence) decision — PR-A prerequisite;
- **#1716** — the doc-honesty companion PR (incl. `soc2-first-customer.md:170` / the CAIQ claim and
  the ADR-0016 Update note);
- **#1717** — the fail-closed list-read gate (HIGH) with its target date.

## Governance

Reviewed by the full Yuzu pipeline on commit `25a7f6d3` (Gate 2 security-guardian + docs-writer;
Gate 3 architect; Gate 4 consistency-auditor + unhappy-path), with a Gate 8 re-review on the hardening
round (`704fc77c`): security-guardian **PASS** (sec-H1/H2/M1 resolved, no Pattern-C regression),
compliance-officer **PASS** with tracked conditions (the CAIQ-claim reconciliation, doc-honesty
timing, the fail-open risk-register entry, and spawned-issue numbers above). No finding overturned
World A. The original "deny-overrides preserved" / "not the RBAC model" framing (Gate-2 BLOCKING) was
corrected; the single-chokepoint shape, descendant-ward set-equivalence, the design invariants
(INV-1..12), the audit-log classification, the data-shape out-of-scope caveat, and the reframed
fail-closed list-read gate were folded in.
