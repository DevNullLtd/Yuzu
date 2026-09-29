# Security review — Authorization topology floor (#2376)

**Date:** 2026-08-05
**Change:** `server/core/src/authz_topology_floor.hpp` (new) +
`AuthRoutes::require_permission`/`require_scoped_permission`
(`auth_routes.cpp`) + a new `EnginePrincipal` RBAC securable
(`rbac_store.cpp` `seed_defaults()`) + the engine-principal REST routes
(`rest_api_v1.cpp`) and MCP twins `list_engine_principals`,
`get_engine_principal`, `list_engine_roles` (`mcp_server.cpp`)
**Branch:** `feat/authz-topology-floor`
**Purpose of this record:** #2376 asks explicitly that this decision be
recorded "so it isn't re-litigated" — this file is that record, not a
design proposal.

## What shipped

- **The defect closed.** `RbacStore::rbac_enabled_` defaults `false` (a
  fresh install runs with RBAC off). With RBAC off,
  `AuthRoutes::require_permission`/`require_scoped_permission` fall through
  to a legacy branch that allows every `Read` to any authenticated
  non-engine session. On a default install that gave a plain `user` session
  fleet-wide read access to the authorization TOPOLOGY itself: the
  fleet-wide access-review export (SOC 2 CC6.2 evidence), `GET
  /api/v1/rbac/roles`, and the engine-principal grant graph.
- **A new `EnginePrincipal` securable** (`Read` only), cut away from the
  over-broad `Security:Read`, carrying REST `GET /api/v1/engine-principals`,
  `GET /api/v1/engine-principals/{id}`, `GET
  /api/v1/engine-principals/{id}/roles`, and the MCP twins
  `list_engine_principals`, `get_engine_principal`, `list_engine_roles`.
  Seeded to `Administrator` (full CRUD via the existing cross-type loop)
  and `Viewer` (`Read`) — the same two roles that reached these routes via
  `Security:Read` before the cut.
- **The topology floor**: `{AccessReview:Read, UserManagement:Read,
  EnginePrincipal:Read}` require the `admin` session role regardless of the
  RBAC on/off toggle (`authz_topology_floor.hpp`'s
  `topology_floor_applies()`), consulted only inside the legacy (RBAC-off)
  fallback of both `require_permission` and `require_scoped_permission`.
- **Audit + metric.** A floored denial is audited with a distinct reason
  (`"topology floor: ..."` on `auth.permission_required`/
  `auth.scoped_permission_required`, `result=denied`) and counted in
  `yuzu_auth_topology_floor_denied_total{permission}`.

## Decisions recorded

### 1. The floor holds regardless of the RBAC toggle, and is applied ONLY in the legacy branch — the ordering is load-bearing

The floor set is checked unconditionally against the toggle: it denies a
non-admin whenever the legacy (RBAC-off) branch is the branch in effect,
with no exception for "but I turned RBAC on and granted a role for this."
That property is what closes the defect — a toggle-conditional floor would
still leave the RBAC-off default wide open, which is the exact posture a
fresh install ships with.

The floor is applied **only** inside the legacy fallback, never ahead of,
or instead of, the live-RBAC branch (`rbac_enforcement_in_effect` at
`auth_routes.cpp:699`, which always `return`s — true or false — before the
legacy branch's code is reached in both `require_permission` and
`require_scoped_permission`). This is not a stylistic choice; it is what
makes the floor compatible with the pre-existing `AccessReview` design.
#2324 cut `AccessReview` as its own securable specifically so a non-admin
`Reviewer` role could be seeded `AccessReview:Read` and reach the
access-review export **without** being `admin` — that is the entire reason
`AccessReview` is a securable distinct from an admin-gated concept. Had the
floor run ahead of the live-RBAC branch (or replaced the branch order), a
`Reviewer` holding a live `AccessReview:Read` grant under RBAC-enabled
enforcement would be denied by the floor before their grant was ever
consulted — silently breaking the one legitimate non-admin path to this
data and destroying the reason the securable exists. Because the
legacy-branch-only application is structural (the live-RBAC branch always
returns first), this cannot silently regress by someone reordering
independent `if` blocks later without touching the control-flow shape
itself.

**Consequence, stated explicitly:** under RBAC-enabled enforcement, a
non-admin `Reviewer` continues to reach the access-review export exactly as
before this change. The floor changes behavior on RBAC-**off** installs
only.

### 2. Not configurable

There is no setting, environment variable, or config key that widens the
floor set or disables it. A toggle that can re-open a security floor is a
footgun, not a feature — it would give an operator (or an attacker who
gained config-write access) a one-line way to undo the fix. The floor set
is a `constexpr` array in `authz_topology_floor.hpp`; changing it requires
a code change and its own review, not an operational setting.

### 3. Securable-keyed, not route-keyed — and route-keying cannot see the MCP twins

The floor matches on `(securable_type, operation)`, the same pair
`require_permission`/`require_scoped_permission` already receive from every
caller — not on `req.path`. A route-keyed design (matching on the URL the
request arrived on) was considered and rejected for a concrete, checkable
reason: **it cannot distinguish the MCP tool twins from each other.** Every
MCP tool call — regardless of which tool — is a JSON-RPC POST to the single
`/mcp/v1/` endpoint; the tool name lives in the request body, not the URL.
`list_engine_roles` (floored, `EnginePrincipal:Read` after this change) and
`list_issued_certs` (deliberately not floored — see decision 4 below,
`Security:Read`) issue **identically-shaped** `perm_fn(req, res, <securable>,
<operation>)` calls on the same `req.path` (`/mcp/v1/`) — the only thing
that differs between them is the `(securable_type, operation)` pair passed
to `perm_fn`, precisely the values the securable-keyed floor matches on. A
floor keyed on `req.path` would either have to float over every MCP tool
alike (over-flooring `list_issued_certs` and everything else on that path)
or have no way at all to single out `list_engine_roles` on that transport.
Securable-keying is the only design that reaches both the REST route and
its MCP twin through one check with no special-casing per transport.

### 4. `Security:Read` considered and excluded — too coarse

`Security:Read` was the permission the engine-principal reads used before
this change (`{"list_engine_principals", {"Security", "Read"}}` etc. in
`mcp_server.cpp`'s tool-security table, and the equivalent `perm_fn(req,
res, "Security", "Read")` calls in `rest_api_v1.cpp`, both now moved to
`EnginePrincipal`). Flooring `Security:Read` directly — instead of cutting
a new securable — was considered and rejected because `Security:Read`
gates four collateral, purely operational surfaces that are not
authorization topology and should not require admin on an RBAC-off
install:

1. Quarantine visibility.
2. CA issued-certs (`GET /api/v1/ca/issued`, MCP `list_issued_certs`).
3. `/ca/root-csr`.
4. KEK status.

Flooring `Security:Read` wholesale would have swept all four of these into
the floor alongside the engine-principal reads, denying them to non-admins
on RBAC-off installs where they work today and are not the topology this
floor exists to protect. This is exactly why part 1 of the fix (the
`EnginePrincipal` cut) exists: a floor can only be as narrow as the
securable it is keyed on, so the engine-principal reads first had to move
to a securable that carries nothing else.

### 5. `ApiToken:Read` and `ManagementGroup:Read` considered and excluded

Both were considered against the same test applied to `Security:Read`:
does this permission gate authorization *topology* (who has what access),
or operational data? Neither does. `ApiToken:Read` gates API-token
lifecycle metadata; `ManagementGroup:Read` gates the device-grouping
hierarchy. Both are operational data an RBAC-off install is reasonably
expected to expose to any authenticated user under the existing legacy
posture — floor scope is capped at the three permissions that answer "who
holds what access", which the introductory defect describes.

### 6. Viewer keeps `EnginePrincipal:Read` — a deliberate scope boundary, not an oversight

`Viewer` is seeded `EnginePrincipal:Read` (`rbac_store.cpp`'s
`viewer_types[]`), matching the `Security:Read` grant it held on these same
routes before the cut. This means that under RBAC-**enabled** enforcement,
a `Viewer`-role principal can still list engine principals and their
role assignments — the same access `Viewer` had before this change,
unchanged.

This was a deliberate choice, not an oversight, and a distinct question
from the one this PR answers. **Narrowing the RBAC-on role model** — e.g.
deciding `Viewer` should no longer see the engine-principal grant graph at
all — is a separate decision with its own blast radius (it would change
behavior for every RBAC-enabled deployment that has ever relied on
`Viewer`'s read-only posture including this surface) and was **not** taken
here. This PR's job is closing the RBAC-**off** gap (the topology floor);
it deliberately preserves the RBAC-on status quo for every built-in role,
`Viewer` included, so the two changes cannot be conflated as one when
someone reviews the audit trail later. If tightening `Viewer`'s
RBAC-enabled scope is wanted, it is a follow-up with its own review, not a
side effect of this one.

### 7. No schema migration

`RbacStore::create_tables()`'s migration list was not extended for the new
`EnginePrincipal` securable. `seed_defaults()` runs **unconditionally** on
every `RbacStore` construction, and its seed loops (`types[]`,
`viewer_types[]`, the `Administrator` CRUD loop) are all `INSERT OR
IGNORE`. That combination means an **existing** deployment picks up the new
securable row and its Administrator/Viewer grants on the very next boot,
with zero migration machinery required — the row and its permission tuples
simply don't exist yet, `INSERT OR IGNORE` inserts them, and re-running the
same seed on every subsequent boot is a no-op. This is the same mechanism
that introduced `AccessReview` and `SoftwareLicensing`, both added as plain
entries in `seed_defaults()`'s type/grant arrays with no accompanying
migration.

A migration is needed only when a change **cannot** be expressed as an
idempotent additive re-seed. `rbac_store.cpp`'s v4 migration is the
counter-example that proves the rule: it `DELETE`s three specific
`(role_name, securable_type, operation)` tuples
(`('Administrator', 'AuditLog', 'Attest')`,
`('Reviewer', 'AuditLog', 'Read')`, `('Reviewer', 'AuditLog', 'Attest')`)
that predate the `AccessReview` securable and would otherwise linger
forever as stale grants — `INSERT OR IGNORE` has no way to *remove* a row,
so that class of change is exactly what needs a version-gated migration.
Adding a brand-new securable with brand-new grants has no equivalent
removal step, so it needed none here.

**The cost of this choice, recorded deliberately (governance UP-4).** The
property that makes no-migration work — `seed_defaults()` re-seeding
unconditionally on every boot — is the same property that means a grant an
operator **deliberately revokes** does not stay revoked. If an operator
removes `('Viewer', 'EnginePrincipal', 'Read')` while the `EnginePrincipal`
securable row remains, the next restart re-inserts it via `INSERT OR IGNORE`,
with no audit line distinguishing "re-seeded by boot" from "set by an
operator". An operator's least-privilege narrowing is silently undone.

This is **pre-existing and repo-wide**: it is true of every one of the 23
seeded securables and every built-in role grant, and was true before this
change. It is recorded here rather than left implicit because this change
does not merely inherit the behaviour — it *depends* on it, and a decision
doc that cites the upside of unconditional re-seeding while omitting its
downside would be selectively honest. Two consequences follow, and neither is
addressed here:

- the durable fix is a tombstone mechanism (an operator-revoked tuple that
  seeding must not resurrect), which is a change to seeding semantics across
  every securable — out of scope for this change, **tracked as #2809** (which
  also relates to #485, the inverse failure of the same mechanism: seeding
  leaving *stale* grants behind on upgraded deployments);
- until then, an operator narrowing a built-in role's grant must expect it to
  revert on restart, and should express the narrowing as a custom role or an
  explicit `deny` row instead.

`rbac_store.cpp`'s v4 migration is the only existing precedent for permanent
removal, and it is one-way and version-gated precisely because `INSERT OR
IGNORE` cannot express a deletion.

### 8. The floor is keyed on the securable — so the SET must be derived from the DATA, not from the routes we happened to know about

Added after the adversarial-review panel (Codex) returned BLOCK on a defect the
14-agent governance run passed.

`GET /api/v1/discover/permissions` and its MCP twin `discover_permissions` are
gated `Infrastructure:Read` — deliberately not floored, because
`Infrastructure:Read` gates ordinary operational reads — and returned
`build_permissions_catalog()`'s **complete role → permission grid**. On an
RBAC-off install the legacy fallback allows every `Read` to any authenticated
session, so a caller the floor had just refused at `/rbac/roles` could read
*strictly more* topology from the discovery route. The floor was advertised as a
control it did not have.

**The lesson, stated so the next person does not repeat it.** Keying the floor on
`(securable, operation)` is correct — it is what reaches the MCP twins (decision 3).
But the floor SET was derived by asking *"which securables gate the routes this
change touches?"* rather than *"which routes emit authorization topology?"*. Those
are different questions and they give different answers. The governance run
verified coverage of the floored securables exhaustively and correctly, and never
asked the second question.

**The fix: split the catalogue, do not floor `Infrastructure:Read`.** Flooring it
would repeat exactly the too-coarse mistake decision 4 rejected for
`Security:Read`. Instead the response has two halves with different permissions —
the taxonomy (`securable_types`, `operations`) at the route's own
`Infrastructure:Read`, the role grid behind `UserManagement:Read`, probed with a
throwaway response so a denial withholds the grid rather than 403-ing the route.
This is not a new pattern: `discover.plugins` in the same file already probes
`InstructionDefinition:Read` before enriching with `parameter_schema`.

**Omission is declared** (`roles_omitted` + `roles_omitted_reason`), never silent —
`roles` simply absent would read as "the fleet has no RBAC roles", the same
absent-vs-empty trap the upgrade note warns evidence collectors about.

**The audit that should have happened, now done.** Every caller of
`get_role_permissions`, `list_roles`, `list_all_principal_roles_checked` and
`get_principal_roles` was enumerated. The discovery pair was the only bypass; the
rest are already floored, are the caller's own self-read, or are the
engine-principal no-admin auditor (`AuditLog:Read`, which returns violations
only, not the grid). A new test also pins every floored pair against the store's
own `list_securable_types()`/`list_operations()`, so a floor entry naming a
securable that is never seeded fails loudly instead of protecting nothing.

### 9. Third instance, same shape — and the enumeration that should have been decision 1

Hermes (pre-submission security pass) found
`GET /api/v1/management-groups/{id}/roles` emitting the scoped principal→role
assignment graph (`{group_id, principal_type, principal_id, role_name}`) on
`ManagementGroup:Read`, which is deliberately **not** floored. Third instance of
the shape decision 8 names, found after a 14-agent governance run **and** a
two-model adversarial panel had both passed the change.

Fixed by requiring, in addition to the route's own `ManagementGroup:Read`,
**either** the floored `UserManagement:Read` **or** being an `ITServiceOwner` of
that group.

The second arm is not a weakening, and the first attempt at this fix omitted it —
Hermes pass 2 caught that as a regression. `ITServiceOwner` is the group-scoped
admin: it holds `ManagementGroup:Read` and no `UserManagement` grant at all, while
the POST and DELETE handlers on this same path already let it MUTATE assignments
through exactly this fallback. Requiring `UserManagement:Read` alone left a group
admin able to write role assignments it could not read — a broken workflow and an
incoherent posture. The arm is a DATA check against the group's own assignment
rows, so it holds with RBAC off, and it is scoped to the CALLER in that ONE group;
a test pins that a non-owner is still refused when someone else owns the group. Note this is a different remedy from decision
8's split, and deliberately so: `/discover/permissions` has a non-topology half
worth preserving, this route's body is topology end to end, so there is nothing
to withhold — the correct answer is a second required permission, not a
probe.

**The enumeration, now done and recorded so the next change does not re-derive
it.** Surfaces that emit authorization topology, and the securable each is gated
on today:

| Surface | Gate | Floored? |
|---|---|---|
| `GET /api/v1/access-reviews/export`, `/{id}`, list | `AccessReview:Read` | yes |
| `GET /api/v1/rbac/roles`, `/{role}/permissions` | `UserManagement:Read` | yes |
| `GET /api/v1/engine-principals`, `/{id}`, `/{id}/roles` + MCP twins | `EnginePrincipal:Read` | yes (cut by this change) |
| `GET /api/v1/discover/permissions` + MCP twin — role grid half | `Infrastructure:Read` **+ probed** `UserManagement:Read` | yes, for the grid |
| `GET /api/v1/management-groups/{id}/roles` | `ManagementGroup:Read` **+** `UserManagement:Read` | yes, via the second gate |
| `GET /api/v1/engine-principals/audit/no-admin` + MCP twin | `AuditLog:Read` | **no — deliberate** |

The last row is deliberate and should not be "fixed" without a decision: it is an
evidentiary auditor surface that returns **violations only** (principals holding
admin), not the grant graph, and it exists so an auditor without grant-graph
access can still prove the no-admin invariant.

Internal readers of the same data that do **not** emit it — `rest_api_v1.cpp`'s
three `get_group_roles` call sites that test whether the *caller* is an
`ITServiceOwner`, and the self-read of one's own roles — are correctly outside
this table.

### 10. The probe reuses the auditing gate, so the new counter is noisy — known, filed, not fixed here

`security-guardian`'s final pass on the fix diff caught this and correctly declined to gate on it.

The probe pattern decisions 8 and 9 introduce calls `require_permission` a second time with a
throwaway response. That function **audits and meters every denial**, so an ordinary non-admin
calling `/api/v1/discover/permissions` (or the mgmt-group roles route) now emits an
`auth.permission_required` `denied` row and increments
`yuzu_auth_topology_floor_denied_total{permission="UserManagement:Read"}` — the counter this very
change introduced as the signal for someone probing the authorization topology. Routine discovery
traffic is therefore indistinguishable from the attack the metric exists to surface.

**Not fixed here, deliberately.** A non-auditing probe mode changes an authorization chokepoint, which
warrants its own review rather than a late addition to a security PR — and the idiom is not new: the
pre-existing quarantine per-record admit probe does exactly the same thing. Tracked as **#2829**,
which must migrate all the probe call sites together.

**Documented rather than left implicit.** `docs/user-manual/rbac.md` now carries an explicit caveat
telling operators not to alert on this counter alone until #2829 lands. Shipping a metric as an
alertable security signal while knowing it is polluted would be harmful operator guidance, which is
the one category of finding this change has been most careful about.

## Hard-invariant check

- The floor set is a fixed, `constexpr` array (`kTopologyFloor`) — no
  runtime-mutable state, no config key reaches it. ✅
- `topology_floor_applies()` is a pure string-comparison predicate with no
  side effects; it cannot itself deny or allow anything — only the two
  legacy-branch call sites act on its result. ✅
- Both `require_permission` and `require_scoped_permission` gained the
  identical floor check — flooring only one of the two structurally
  identical legacy branches was explicitly avoided (see the comment at
  `auth_routes.cpp` in `require_scoped_permission`); no floored
  `(securable, operation)` pair reaches the scoped variant today, but the
  check is there so a **future** scoped topology read cannot silently skip
  the floor by landing in the branch nobody remembered to also floor. ✅
- The floor never runs ahead of, or replaces, the live-RBAC branch in
  either function — verified structurally: `rbac_enforcement_in_effect`'s
  `if` block always `return`s before the legacy branch's statements
  execute. ✅
- `EnginePrincipal`'s seed grants (`Administrator` full CRUD, `Viewer`
  `Read`) exactly reproduce the pre-cut `Security:Read` access those two
  roles held on these three routes — grepped `rbac_store.cpp`'s
  `types[]`/`viewer_types[]` diff: `EnginePrincipal` appended to both,
  nothing removed from either. ✅
- Both REST routes and all three MCP twins were moved to
  `EnginePrincipal:Read` together — grepped `mcp_server.cpp`'s
  `kToolSecurityRows[]` and the three `tier_allows(tier, "Security",
  "Read")`/`perm_fn(req, res, "Security", "Read")` call sites for
  `list_engine_principals`/`get_engine_principal`/`list_engine_roles`: none
  remain on `Security:Read`. ✅
- The four `Security:Read` collateral surfaces named in decision 4
  (quarantine visibility, CA issued-certs, `/ca/root-csr`, KEK status)
  remain on `Security:Read`, untouched by this change. ✅

## Tests

Owned by a sibling change on this branch:
`tests/unit/server/test_authz_topology_floor.cpp` (new) and the
corresponding `tests/meson.build` registration. Not verified in this
review pass — see that file for coverage of the floor predicate, the
audit-reason text, the metric emission, and the RBAC-on/`Reviewer`
non-interaction.

## Residual / follow-ups

- **The RBAC-on `Viewer` scope for `EnginePrincipal:Read` is unreviewed as
  a standalone question** (decision 6) — if a future review decides
  `Viewer` should not see the engine-principal grant graph, that is a
  separate, explicitly-scoped change.
- **`Security:Read`'s four collateral surfaces are unaffected by this PR**
  and remain reachable by any authenticated non-admin on an RBAC-off
  install, same as before. If any of those four is later judged to also be
  authorization topology (none is, per decision 4, as of this review),
  that is a separate securable-cut-and-floor decision, not an extension of
  this floor's scope by reinterpretation.
