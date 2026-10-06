# Role-Based Access Control (RBAC)

Yuzu implements granular role-based access control with deny-overrides-allow semantics, scoped permissions via management groups, and support for both built-in and custom roles.

## Enabling RBAC

RBAC is controlled by a global toggle. When disabled, all authenticated users have full access (with a legacy fallback: write/delete/execute/approve operations still require the `admin` session role) — **except** a small, fixed set of reads that the fallback still refuses to a non-admin; see "The authorization topology floor" below. When enabled, every API call and UI action gated on a real securable type is checked against the caller's assigned roles — but not every surface has one: result sets are ownership-scoped, not RBAC-gated, regardless of this toggle; see "Not RBAC-gated: per-operator result sets" below.

Toggle RBAC via `PUT /api/v1/rbac/enforcement` (or the `set_rbac_enforcement` MCP tool) — **not** a Settings-page control and **not** a `[rbac] enabled = true` config-file key. Neither exists: nothing in `server/core/src/main.cpp` or any `Config` header reads a `[rbac]` section — see [#388](https://github.com/Tr3kkR/Yuzu/issues/388).

```bash
curl -s -b cookies.txt -X PUT \
  http://localhost:8080/api/v1/rbac/enforcement \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

The toggle refuses unless the **calling operator** passes BOTH of the following: a `403` unless they hold authority under the regime that is durably true **right now** (the SOURCE regime — this closes a cross-replica cache-staleness gap in the outer admin gate itself, see below), and a `409` unless they would remain a durable administrator under the **destination** regime after the switch — it never gambles with a lockout.

- **Enabling** requires the caller's own fleet-wide `Administrator` grant (a `principal_roles` row, joined to an active `auth.users` account) as the destination check — the exact authority `is_rbac_administrator`'s RBAC-on branch will require of the caller on their very next request — **and**, as the source check (RBAC is currently off), the caller's own local account holding the `admin` role. Refused with a remediation naming the assignment call: `POST /api/v1/rbac/roles/Administrator/assignments` for yourself (or the `assign_rbac_role` MCP tool), then retry.
- **Disabling** requires the caller's own local account to hold the `admin` role (`auth.users.role='admin' AND is_active`) as the destination check — the only thing the RBAC-off predicate branch reads — **and**, as the source check (RBAC is currently on), the caller's own fleet-wide `Administrator` grant. Refused with a remediation pointing at `POST /api/settings/users/{username}/role`.

The source check exists because the outer admin gate that decides whether a caller may even attempt the toggle reads a replica-local cached view of the flag that can lag a real commit by up to a few seconds — and this route is the thing that flips the value that gate reads. Without it, a caller admitted under a momentarily-stale view could flip enforcement by satisfying only the destination check (concretely: disabling with nothing but a local `admin` role, while RBAC is durably on and that caller never held a real fleet-wide grant).

This is **caller-inclusive and deliberately stricter than a bare fleet-wide "at least one administrator survives" check**: it protects the specific operator making the change, not merely the fleet in the abstract. A fleet-wide survivor count is implied by it (and reported in the response and audit row as `post_transition_administrators`), never the other way round. One consequence worth knowing before you hit it: Alice (an RBAC `Administrator` grant, but a `user`-role local account) cannot disable enforcement while RBAC is on — the guard requires her own local account to hold the `admin` role, which hers does not, and while RBAC is on `is_rbac_administrator` itself already requires a fleet-wide `Administrator` grant before Alice's request ever reaches the disable-specific check, so a bare local `admin` role is never sufficient on its own either. The in-product handoff is for Alice to grant `Administrator` to a colleague who already holds the local `admin` role — that colleague then holds both authorities the guard requires and can perform the disable — or for an admin to promote Alice's own local role via `POST /api/settings/users/{username}/role` first. This is not "the fleet is at risk" — it is the guard protecting the specific caller's own standing, which is by design stricter than fleet survival.

Recommended order for a fresh install:

1. On a genuinely fresh install, the config-file admin already holds the fleet-wide
   `Administrator` grant from boot (`RbacStore::provision_first_admin`) — this step is a no-op for
   that account and only matters for an UPGRADED/pre-existing database whose current operators
   don't already hold it. `POST /api/v1/rbac/roles/Administrator/assignments` for yourself
   (`{"principal_type":"user","principal_id":"<your username>"}`) — see "Fleet-Wide Role
   Assignment" below.
2. Grant management-group roles to every operator who needs device visibility (see the callout immediately below) — RBAC-on applies role-scoped visibility immediately, and a user with no management-group role sees no agents.
3. `PUT /api/v1/rbac/enforcement {"enabled": true}`.

> **Before enabling RBAC in production:** ensure every operator who needs device
> visibility has at least one management-group role assignment. With RBAC
> **disabled**, all authenticated users see the full enrolled fleet. Turning RBAC
> **on** immediately applies role-scoped visibility — a user without a
> management-group role assignment will see **no agents** (including on the TAR
> fleet scan), and the role-grant endpoints themselves require an existing group
> role, which can be a chicken-and-egg lockout. The broadest grant is an
> `ITServiceOwner` role on the root "All Devices" group; see
> [`management-groups.md`](management-groups.md) for the delegation API.

> **SSO-only fleets:** only a LOCAL `auth.users` administrator can pass the
> enable guard above — an SSO session cannot pass the RBAC-off predicate
> branch at all, a property this toggle inherits from `is_rbac_administrator`
> rather than introduces. Under `--auth-mode=sso-only`, that means the
> break-glass local account, if it holds `role=admin` — see
> [#4966](https://github.com/Tr3kkR/Yuzu/issues/4966) for the underlying
> SSO-recognition gap. The guard fails safe in this direction: it refuses
> rather than strands.
>
> **sso-only prerequisites, made explicit:**
>
> 1. Break-glass is **optional** — it must be explicitly configured and armed
>    before an in-band enable path exists at all. A `sso-only` deployment that
>    never armed one has NO local account that can ever pass the enable
>    guard, in-band, full stop.
> 2. Its `role` is **not** validated as `admin` at boot the way its MFA
>    enrollment is checked — a break-glass account can exist, be armed, and
>    still not hold `role='admin'`. Verify before relying on it: `GET
>    /api/v1/me` while authenticated as it, or a direct query (see below).
> 3. If it is not `role=admin` today, the recovery is the **direct-SQL path**
>    — NOT a pointer to "the storage section", a concrete statement. Note
>    this touches a DIFFERENT store than the "Storage (ADR-0041)" callout
>    below: `auth.users` lives in AuthDB's own `auth` schema, not `rbac_store`
>    (which holds roles/grants/principal→role assignments instead):
>    ```sql
>    -- Promote the break-glass account's LOCAL role (AuthDB's auth schema):
>    UPDATE auth.users SET role = 'admin' WHERE username = '<break-glass username>';
>    ```
>    This is the `auth.users.role` column the RBAC-off predicate branch reads
>    directly (see "Disabling requires..." above) — it is separate from any
>    `rbac_store.principal_roles` grant, which the RBAC-off branch does not
>    consult at all.

> **Storage (ADR-0041).** RBAC configuration — roles, grants, principal→role
> assignments, groups + membership, and the global `rbac_enabled` flag — lives in
> the server's **PostgreSQL** substrate, schema `rbac_store` (it moved off the
> legacy SQLite `rbac.db` file). It is a single shared database across all server
> replicas, so administer it with one `psql`, not per-node.
>
> **RBAC store integrity (fail-closed / deny-on-degrade).** The `rbac_store`
> substrate fails **closed at boot** — an unreachable PostgreSQL (or an
> unreadable durable `rbac_enabled` flag) makes the server refuse to start,
> rather than serving RBAC-off on a fleet that enabled it. At runtime, an
> authorization read that cannot resolve (pool-acquire timeout, query error)
> **denies** rather than allowing (deny-on-degrade, ADR-0041 — this closes the
> prior "corrupt `rbac.db` fails open" behavior); watch the
> `yuzu_server_rbac_read_degrade_total` metric. In that degraded state, device
> visibility falls back to the role-scoped path for every caller, so agents stop
> appearing in the dashboard list, `/api/agents`, and TAR fleet scans rather than
> the whole fleet being exposed. **The same fail-closed posture covers MOST
> response/execution readers (#1634):** `query_responses`, `aggregate_responses`,
> `GET /api/v1/executions/{id}/visualization`, and the legacy `GET /api/responses/{id}`
> / `/aggregate` / `/export` surfaces return **zero rows** (the legacy aggregate
> returns `503`) on a corrupt store rather than reopening the cross-operator
> fleet-wide read.
>
> **The dashboard's facet/scope surfaces are covered too, on a narrower anchor
> (#1712, ADR-0017 —** `docs/adr/0017-management-group-confinement-list-reads.md`
> **):** `GET /fragments/results/filter-bar` (facet dropdown values + line
> counts) and `GET /fragments/create-group-form` (matching-agent count) scope
> their aggregate queries in SQL against the caller's `Response:Read`-visible
> agent set. `POST /api/dashboard/group-from-results` fetches its matching id
> list unscoped, then intersects it in C++ against that same visible set
> before materialising group membership, audits any ids the intersection
> drops, and — if every id is dropped — returns the same "no agents match"
> response as a genuine no-match (the caller cannot tell a filtered result
> from an empty one). All three resolve the visible set via
> `RbacStore::visible_agents_for_permission` (deny-aware, management-group
> hierarchy expanded, permission-specific to `Response:Read`).
>
> A degraded **management-group** store fails **closed** here too: an
> empty visible set makes the two GETs return success-empty without the
> query ever reaching the response store, and makes `group-from-results`
> report "no agents match." A degraded **RBAC** store behaves differently —
> it never reaches this scoping at all, because each route's own flat
> admission gate (below) denies with `403` first, the same as any other
> RBAC-store outage. A degraded **response** store keeps its own distinct
> existing rendering instead — a disabled "unavailable" dropdown on the
> filter bar, "agent count unavailable (store degraded)" on the
> create-group form, and `503` from `group-from-results` — since that
> failure is orthogonal to agent visibility.
>
> **Admission on these three routes is unchanged (#1712 follow-up, tracked for
> ADR-0017 PR-B).** Each route still gates on its own flat
> `require_permission`, which never consults management groups: the filter
> bar requires flat `Response:Read`; the two group routes require flat
> `ManagementGroup:Write`. A caller whose only grant of a route's own gate
> permission is management-group-scoped is denied at that route (`403`)
> before the scoping above ever runs. But the two gates are different
> permissions — a caller admitted to the group routes by a global
> `ManagementGroup:Write` grant, who holds `Response:Read` only through a
> management group, is admitted today and does observe the scoping (as does
> any JIT-elevated session admitted without a global `Response:Read`
> grant). Group-scoped-only admission becomes universal across all three
> routes once they migrate onto the ADR-0017 list-read gate.
>
> **Not yet covered (#1634 follow-up — these still fail OPEN on a
> corrupt store):** the dashboard `/fragments/results/…` table and the workflow
> executions-drawer reader have no per-agent filter and will expose the whole
> fleet's responses when the RBAC store is degraded. So a degraded store looks like "no
> agents in scope" / "no responses" **on the covered surfaces, but is a visibility
> leak via those two uncovered ones** — check the server startup log for `RbacStore`
> errors, the `/health` store status, and `yuzu_server_rbac_read_degrade_total`,
> then restore PostgreSQL (`rbac_store`) availability
> immediately. (If Grafana panels or scripted aggregate consumers show zero
> rows after an upgrade or restart, check for `RbacStore` open/migrate errors first.)
>
> **Note (#1634):** the per-agent filter on the covered response readers is, under
> *normal* RBAC operation, currently **inert** — a holder of global `Response:Read`
> sees all agents' responses; per-management-group scoping of these reads is not yet
> effective (the gate change is tracked in #1634). Today the filter's only active
> effect is the corrupt-store fail-closed described above. The three facet surfaces
> above are a partial exception: their scope filter is active for any caller
> who clears that route's own flat gate, not only during a corrupt-store
> degrade. It does not by itself make anyone admissible — a caller whose
> only grant of a route's own gate permission is management-group-scoped is
> still denied at the gate, unaffected by this filter.
> fleet-wide read. **Now also covered (#1712, #3290 Phase 2 continuation):** the
> dashboard `/fragments/results` table and the workflow executions-drawer reader
> (both its responses section and its per-agent status grid/table) migrated onto
> `require_fleet_read` — same fail-closed posture as everything else on this
> page: a degraded `rbac_store`/`mgmt_group_store` returns `503`, and a healthy
> store applies a real per-agent filter rather than exposing the whole fleet.
> **Still not covered, but NOT a fail-open-on-degrade risk** — these remaining
> readers gate on `perm_fn_`/`require_permission`, which has been deny-on-degrade
> since ADR-0041 regardless of confinement, so a corrupt store 403s them rather
> than exposing anything. Their gap is a *different* shape: a caller who holds
> the flat permission (globally, not confined) still gets an unscoped read/write
> with no per-agent filter. Dashboard `/fragments/results/filter-bar`,
> `/fragments/create-group-form`, and `POST /api/dashboard/group-from-results`
> (tracked #3489; #3525 tracked the same finding and was closed as its
> duplicate); REST `GET /api/v1/execution-statistics/agents` and the
> workflow executions LIST fragment `/fragments/executions` (tracked #3526). So
> a degraded store looks like "no agents in scope" / "no responses" / `503`
> across every reader on this page now — check the server startup log for
> `RbacStore` errors, the `/health` store status, and
> `yuzu_server_rbac_read_degrade_total`, then restore PostgreSQL (`rbac_store`)
> availability immediately. (If Grafana panels or scripted aggregate consumers
> show zero rows after an upgrade or restart, check for `RbacStore` open/migrate
> errors first.)
>
> **Service-scoped tokens and `ITServiceOwner` (the fleet-read authority ceiling; found while working #3526).**
> Every fleet-read route applies the `ITServiceOwner` authority ceiling to a service-scoped token, the check
> `require_permission` already made: the token is refused unless that role itself holds the pair, whatever its
> minter holds. Non-service callers are unaffected. Effects today:
>
> 1. **Breaking:** `ITServiceOwner` does not hold `Enrollment:Read`, so a service-scoped token is refused with
>    `403` on `GET /api/v1/enrollment/pending-agents` (it used to receive a view narrowed to its tagged agents).
>    Use an Administrator-minted non-service token for that route.
> 2. **Breaking:** `GET /api/v1/upload-grants` refuses a service-scoped token with `403` (no `permission`
>    field); it used to return the minter's `UploadGrant:Read` view. Same remedy: list with a non-service token.
> 3. The ceiling applies wherever a seeded `ITServiceOwner` permission is absent. No REST, MCP or CLI surface
>    removes one today (narrowing a seeded role's permission set is planned, see "Custom Roles" below), so
>    this is a safeguard for a future authoring surface, not something an operator can trigger now.
>
> A definitive deny is `403`; a FAILED permission read on the fleet-read gate is a
> retryable `503` (`retry_after_ms` 5000), while `require_permission` and
> `require_scoped_permission` keep answering `403` for the same failure. The ceiling read goes through the
> RBAC authz circuit breaker with a 250 ms acquire budget, so a degraded store answers quickly (an open
> breaker is counted under `pool_acquire_timeout`); a read that is already admitted and holds a connection can
> still wait up to the pool's `lock_timeout` (10 s default) or `statement_timeout` (30 s default). One
> deferred item remains: the `authorize_list_read` supersede-to-intersect migration for the remaining callers
> is tracked in `docs/security-reviews/service-scope-phase2-migrations-2026-08.md`, so "every fleet-read
> route" above does not mean every route that lists per-agent data.
>
> **Note (#1634):** the per-agent filter on `query_responses`/`aggregate_responses`/the
> REST visualization+responses endpoints is, under *normal* RBAC operation, currently
> **inert** — a holder of global `Response:Read` sees all agents' responses;
> per-management-group scoping of these specific reads is not yet effective (the
> gate change is tracked in #1634; this is a *different*, older primitive
> [`response_scope_fn`] than `require_fleet_read` below). Today that filter's only
> active effect is the corrupt-store fail-closed described above.
>
> **This does NOT apply to `/fragments/results` or the workflow executions-drawer**
> (#1712) — both migrated onto `require_fleet_read`, a *different* primitive whose
> per-agent filter is real and effective under normal RBAC operation, not inert:
> a management-group-confined or correctly service-scoped caller genuinely sees only
> their in-scope agents' data on those two readers today.
>
> **Update (#1634, closed):** the "inert" `response_scope_fn` filter described in
> both notes above is retired. `query_responses`, `aggregate_responses`, REST
> `/executions/{id}/visualization`, and the legacy `/api/responses/{id}`
> (`GET`/`/aggregate`/`/export`) are all now on `require_fleet_read`, the same
> real, effective primitive as `/fragments/results` and the workflow
> executions-drawer — a management-group-confined caller genuinely sees only
> their in-scope agents' data on every response reader on this page, not just
> the two named above. `GET /api/v1/executions/{id}`, `GET /api/v1/events`, and
> the dashboard `GET /sse/executions/{id}` migrated in the same round. See
> `docs/auth-architecture.md`'s "Third migration (#1634)" section for the full
> account, including the residuals it left open (a weaker own-dispatches-only
> confinement for MCP `list_executions`, since execution rows carry no single
> `agent_id` to filter by).

## The authorization topology floor (#2376)

Ten reads are treated as **authorization topology** rather than ordinary
operational data. Wherever the legacy RBAC-off fallback is the branch in
effect, they require the `admin` session role — the generic “any Read is
allowed” rule does not reach them. (With RBAC **enabled** they are ordinary
permission checks, so a seeded `Reviewer` holding `AccessReview:Read` is
admitted; the floor never overrides a live RBAC grant.)

| Securable:Operation | Surface |
|---|---|
| `AccessReview:Read` | The fleet-wide access-review grant export (SOC 2 CC6.2 evidence), `GET /api/v1/access-reviews*`, and the lighter-weight live grant-table listing `GET /api/v1/rbac/roles/assignments` (+ MCP `list_rbac_role_assignments`) — same securable, same sensitivity class, not a management-group-confined view |
| `UserManagement:Read` | `GET /api/v1/rbac/roles` and the rest of the RBAC role graph |
| `EnginePrincipal:Read` | The engine-principal inventory and grant graph, `GET /api/v1/engine-principals*` and the `list_engine_principals`/`get_engine_principal`/`list_engine_roles` MCP tools |
| `Enrollment:Read` (#4031) | Auto-approve enrollment rules and pending-agent visibility, `GET /api/v1/enrollment/auto-approve-rules` and `GET /api/v1/enrollment/pending-agents` (service-scoped tokens are refused with `403` on both: the `ITServiceOwner` ceiling does not hold this pair) |
| `OidcConfig:Read` (#4031) | OIDC SSO configuration status, `GET /api/v1/settings/oidc` |
| `TlsConfig:Read` (#4028) | TLS settings read-twins, `GET /api/v1/settings/tls` and `GET /api/v1/settings/https` |
| `PluginSigning:Read` (#4028) | Plugin trust-bundle distribution, `GET /api/v2/agent/plugin-policy` (#4144 — there is deliberately no `/api/v1/settings/plugin-signing` route; the v1 predecessor stayed on `require_admin`) |
| `ServerConfig:Read` (#4028) | Server runtime-configuration read-twins — `GET /api/v1/settings/server-config`, `/settings/gateway`, `/settings/mcp` and `/settings/data-retention` |
| `AnalyticsConfig:Read` (#4028) | Analytics/offload configuration status, `GET /api/v1/settings/analytics` |
| `Forensics:Read` | Windows forensic-artefact and per-device application-usage reads (Wave 7 PR7.2) |

**Why this exists.** With RBAC **disabled**, the legacy fallback described
above allows any authenticated non-engine session to perform every `Read` —
that includes these ten. On a default install (RBAC ships disabled) that
handed a plain `user` session read access to the authorization topology
itself: who holds what role, and the complete access-review grant
population that is supposed to *be* SOC 2 CC6.2 evidence of controlled
access. The floor closes that gap by denying these ten reads to a
non-admin whenever the legacy fallback is the branch in effect — never by
changing behavior under a live RBAC grant.

**This does not affect RBAC-enabled deployments beyond the one closed
gap.** The floor only ever engages inside the legacy (RBAC-off) fallback; a
live RBAC branch always answers first when RBAC is enabled and enforced. In
particular, a non-admin holding the seeded `Reviewer` role (`AccessReview:Read`
+ `AccessReview:Attest`) continues to reach the access-review export exactly
as before — the floor never overrides that grant.

**If you are relying on a non-admin reaching one of these ten reads on an
RBAC-disabled install,** that access is now denied. The supported remedy is
to enable RBAC and grant the appropriate role rather than to expect a
non-admin session to reach authorization topology while RBAC is off:

- For the access-review export: enable RBAC and assign the built-in
  `Reviewer` role (`AccessReview:Read` + `AccessReview:Attest`).
- For `/rbac/roles`: enable RBAC and grant `UserManagement:Read` (the
  built-in `Viewer` role holds it already).
- For the engine-principal inventory/roles reads: enable RBAC and grant
  `EnginePrincipal:Read` (the built-in `Viewer` role holds it already; a
  **custom** role that was granted `Security:Read` specifically to reach
  these routes must be re-granted `EnginePrincipal:Read` — see "Upgrade
  Notes" in [`server-admin.md`](server-admin.md)).
- For the enrollment auto-approve-rules/pending-agents reads: enable RBAC
  and grant `Enrollment:Read` — no built-in non-admin role holds it
  (`Administrator` only; unlike `EnginePrincipal`/`Directory`, `Viewer`
  deliberately does not, since these surfaces gate the fleet's enrollment
  admission policy). A service-scoped token is refused (`403`) on these
  routes whoever minted it, because `ITServiceOwner` does not hold the pair
  (the authority ceiling); use an Administrator-minted non-service token.
- For the OIDC SSO config status read: enable RBAC and grant
  `OidcConfig:Read` — `Administrator`-only for the same reason.

The floor is deliberately **not configurable** — there is no setting that
widens it back open. It is keyed on `(securable, operation)`, not on route
path, because an MCP tool and a REST route can share the same wire path
(every MCP tool call goes through the single `/mcp/v1/` JSON-RPC endpoint)
while gating different securables; a route-keyed floor could not
distinguish them. A denial from the floor is audited with a distinct reason
(`"topology floor: ..."` on the `auth.permission_required` /
`auth.scoped_permission_required` audit actions, `result=denied`) and
counted in `yuzu_auth_topology_floor_denied_total{permission}`, separate

> **Caveat — this counter is currently noisy (#2829).** Routes that PROBE a second
> permission to decide whether to include part of a response — `GET /api/v1/discover/permissions`,
> its MCP twin, and `GET /api/v1/management-groups/{id}/roles` — run that probe through the same
> auditing permission gate. An ordinary non-admin call therefore increments this counter and writes
> an `auth.permission_required` `denied` row for a permission the caller never asked for. Until
> #2829 lands, do **not** alert on this counter alone as evidence of someone probing the
> authorization topology — correlate with the route in the audit row first.
from an ordinary legacy-fallback denial, so a spike in floored denials is
visible without grepping audit-log text.

See `docs/auth-architecture.md` → "The authorization topology floor
(#2376)" for the full design rationale, and
`docs/security-reviews/authz-topology-floor-2026-08-05.md` for the recorded
decision (including what was deliberately excluded from the floor and why).

**The access-review export's `rbac_enforcement` stamp inherits this same
degrade-vs-outage ambiguity — read this if you're relying on it as
evidence.** `enabled`/`disabled`/`degraded` (full description:
`rest-api.md` → the `GET /api/v1/access-reviews/export` section) is derived
from the identical fail-closed machinery described above under "RBAC store
integrity (fail-closed / deny-on-degrade)" — a replica whose generation
refresh has failed reports `degraded`, same as a replica whose RBAC store is
unreachable. **Correlate against
`yuzu_server_rbac_read_degrade_total{reason=~"generation_refresh_failed.*"}`**
(and the narrower `stale_beyond_accepted_bound` reason) if you need to
distinguish "the store genuinely couldn't confirm state at pull time" from
"an administrator turned RBAC on/off" — the stamp alone cannot make that
distinction for you.

**The frozen campaign row is a strictly worse case than the live export.**
`GET .../export` recomputes `rbac_enforcement` fresh on every pull — a
transient degrade self-corrects the next time someone re-runs the export.
`POST /api/v1/access-reviews` (opening a review campaign) computes the
stamp **once**, at open time, and — per this feature's deliberate no-prune
retention policy — that campaign row persists **indefinitely**. A
`degraded` (or, on the cached-enabled short-circuit documented in
`rest-api.md`, an `enabled`) stamp recorded during a transient partition is
therefore **permanent evidence with no later self-correction**: re-reading
the same closed campaign always returns the value frozen at open, never a
retry. If a campaign was opened during a known RBAC-store incident, treat
its `rbac_enforcement` value as suspect and open a fresh campaign once the
store is confirmed healthy, rather than trusting the frozen one.

**This is an evidence-confidence gap, never a security-control failure.**
A stale or degraded `rbac_enforcement` reading never weakens actual
authorization — `check_permission`/`check_scoped_permission` independently
deny on the exact same degraded view (deny-on-degrade, ADR-0041, as
described throughout this section); nothing about the access-review stamp
being wrong changes what a real request is allowed to do. The risk is
purely that an auditor reading the export or a closed campaign draws the
wrong conclusion about what state RBAC was in — not that access control
itself misbehaves.

## Concepts

| Concept | Description |
|---|---|
| **Principal** | A user or group identity. Matches the authenticated username or an OIDC group claim. |
| **Role** | A named collection of permissions. Can be system-defined or custom. |
| **Securable type** | A category of resource that permissions apply to (e.g., `Infrastructure`, `Tag`). |
| **Operation** | An action on a securable type (`Read`, `Write`, `Delete`, `Execute`, `Approve`, `Push`, `Attest`, `Rotate`). |
| **Permission** | A single `(securable_type, operation, effect)` entry. Effect is `Allow` or `Deny`. |
| **Role assignment** | Binds a principal to a role, optionally scoped to a management group. |

## System Roles

Seven roles are created automatically and cannot be deleted:

| Role | Permissions | Use case |
|---|---|---|
| **Administrator** | All 5 CRUD operations on all 38 securable types, plus Push on GuaranteedState, Attest on AccessReview, and Rotate on ApiToken (P2 #11, SOC 2 CC6.3 — self-service human token rotation) (193 permissions) | Server admins, security team leads |
| **PlatformEngineer** | Full CRUD on InstructionDefinition and InstructionSet; Read on Execution, Schedule, Approval, Tag, AuditLog, Response, Inventory; Read/Write/Delete/Push on GuaranteedState | Authors and managers of YAML instruction definitions, sets, and Guardian rules |
| **Operator** | Read/Write/Execute/Delete on InstructionDefinition, InstructionSet, Execution, Schedule, Tag; Read and Approve on Approval; Read on AuditLog, Response, and Inventory; Read and Push on GuaranteedState | Day-to-day instruction execution, schedule management, tagging, and Guardian rule distribution |
| **ApiTokenManager** | Read, Write, Delete, Rotate on ApiToken (4 permissions) | Create, revoke, rotate, and manage API tokens for programmatic access |
| **ITServiceOwner** | All 5 CRUD operations on 18 securable types, plus Push on GuaranteedState, plus Workflow:Read, plus Decommission:Delete (93 permissions). Excludes 20 of the 38 securable types, including UserManagement, Security, ApiToken, AccessReview and EnginePrincipal | Service desk leads, team managers with delegated control over their IT services |
| **Viewer** | Read on 24 securable types (24 permissions) — an explicit allow-list in `rbac_store.cpp`'s seed, *not* “everything except” | Helpdesk staff, auditors, read-only dashboards |
| **Reviewer** | Read and Attest on AccessReview (2 permissions) | Periodic access reviews (SOC 2 CC6.2) — the non-admin role that can attest or flag a grant |

## Securable Types

| Securable type | Description |
|---|---|
| `Infrastructure` | Agent endpoints (query, command, patch) |
| `Tag` | Asset tags applied to devices |
| `InstructionDefinition` | YAML-defined instruction templates |
| `InstructionSet` | Grouped collections of instructions |
| `Execution` | Running or completed instruction instances |
| `Response` | Instruction response data |
| `Schedule` | Cron-style recurring instruction schedules |
| `Approval` | Approval workflow entries |
| `ManagementGroup` | Hierarchical device groups |
| `UserManagement` | User accounts and role assignments |
| `Security` | Security settings (TLS, enrollment, quarantine, CA and KEK reads, and privilege-posture reads such as the local_security_policy `sudoers` content) |
| `ApiToken` | API token lifecycle |
| `AuditLog` | Audit event records |
| `Policy` | Guaranteed State policy fragments and composed policies |
| `DeviceToken` | Agent device-token issuance and revocation |
| `SoftwareDeployment` | Software deployment campaigns |
| `License` | Enterprise license records |
| `FileRetrieval` | File upload and download operations |
| `GuaranteedState` | Guardian (Guaranteed State) policy rules, events, and status |
| `Inventory` | Installed-software inventory synced from endpoints (ADR-0016) |
| `EnginePrincipal` | Engine-principal inventory and fleet-wide grant-graph reads (list/get engine principals, list their assigned roles) — cut away from `Security` (#2376) so this narrower read is not gated by the same broad permission that also covers CA/quarantine/KEK operational reads. See "The authorization topology floor" below. |
| `Forensics` | Forensic-artefact reads (Windows execution artefacts — ShimCache/AmCache/Prefetch; per-device application-usage projection; per-app privacy-permission grants). Administrator-only by default (absent from the Viewer read-list; the stored results follow `Response:Read`); every catalogue row on it is single-target (exactly one agent id, no fleet/scope fan-out) and `AdminOrApproval`-gated. Wave 7 PR7.2/PR7.3. |
| `Decommission` | Device-level agent-erasure gate for `DELETE /api/v1/sle/agents/{id}` (ADR-0024 Decision 9, amended Wave 7 PR7.2). `Decommission:Delete` authorizes for the whole decommission cascade's blast radius (five per-agent stores spanning `Inventory`, `GuaranteedState`, and `SoftwareLicensing`; a companion package adds a sixth, `Forensics`-governed store) in one grant, replacing a hand-maintained per-store conjunction. |
| `SoftwareLicensing` | Discovered software-licence facts synced from endpoints (ADR-0024) |
| `AccessReview` | Periodic access-review campaigns and attestations (SOC 2 CC6.2). Seeded to Administrator and `Reviewer` only — deliberately NOT `AuditLog`, see "The authorization topology floor" above |
| `Workflow` | Multi-step workflow definitions and executions |
| `ProductPack` | Installed product packs |
| `PluginConfig` | Per-plugin configuration and kill switches |
| `PluginSecret` | Per-plugin secret material — never Operator-readable |
| `UploadGrant` | Upload-grant mint/revoke lifecycle |
| `PowerManagement` | `power_health.set_power_plan`, the plugin surface's only destructive power action |
| `Directory` | AD/Entra-synced user and group data |
| `TlsConfig` | TLS settings. Server-administration: denied to every MCP tier, and admin-floored when RBAC is off |
| `PluginSigning` | Plugin-signature enforcement settings. Server-administration, same posture as `TlsConfig` |
| `ServerConfig` | Server runtime configuration. Server-administration, same posture as `TlsConfig` |
| `AnalyticsConfig` | Analytics/offload configuration. Server-administration, same posture as `TlsConfig` |
| `Enrollment` | Auto-approve enrollment rules and pending-agent visibility |
| `OidcConfig` | OIDC SSO configuration |

### Not RBAC-gated: per-operator result sets

Result sets (scope-walking capability §30, `docs/scope-walking-design.md`) are **ownership-scoped, not RBAC-gated** — the RBAC toggle above has no effect on them, whether it is on or off. This is a deliberate phase-1 design (design §4.1), not an oversight, and it is unaffected by [#5047](https://github.com/Tr3kkR/Yuzu/issues/5047)'s fix below.

The 8 routes/tools in this family authorize purely on `owner_principal == session.username`:

| REST | MCP tool | Dashboard fragment |
|---|---|---|
| `GET /api/v1/result-sets` | `list_result_sets` | `GET /fragments/result-sets/sidebar` |
| `POST /api/v1/result-sets` | `create_result_set` | `POST /fragments/result-sets/create` |
| `GET /api/v1/result-sets/{id}` | `get_result_set` | `GET /fragments/result-sets/{id}/detail` |
| `GET /api/v1/result-sets/{id}/members` | `get_result_set_members` | *(no fragment equivalent — the detail fragment shows only a device COUNT, not the member list)* |
| `GET /api/v1/result-sets/{id}/lineage` | `get_result_set_lineage` | *(shown as the breadcrumb on the detail fragment)* |
| `POST /api/v1/result-sets/{id}/pin` | `pin_result_set` | `POST /fragments/result-sets/{id}/pin` |
| `POST /api/v1/result-sets/{id}/unpin` | `unpin_result_set` | `POST /fragments/result-sets/{id}/unpin` |
| `DELETE /api/v1/result-sets/{id}` | `delete_result_set` | `POST /fragments/result-sets/{id}/delete` |

`ResultSet` appearing as a `target_type` in audit rows, and the `Infrastructure:Write`/`Infrastructure:Delete` labels the 4 write tools (`create_result_set`/`pin_result_set`/`unpin_result_set`/`delete_result_set`) carry internally — the other 4 tools in the table above carry `Infrastructure:Read`, unaffected by any of this — are **not** a real RBAC securable or grant — they are borrowed labels used only to bucket the tools into the MCP tier/approval belt below (see "MCP tier/approval belt" below); naming them as a `.permission` an operator could self-remediate with would be a false claim, so the 403 body for a denial on this surface never does.

**No admin override.** `ResultSetStore::delete_set`/`pin`/`unpin` take only an id — there is no admin-bypass parameter, and every caller (REST's `load_owned`, MCP's `rs_load_owned`, the dashboard fragments' `rs_get_owned`) runs the ownership check before calling any of them. The one owner-blind path is `gc_sweep()`, the background TTL reaper — not an operator-triggered action, and it never deletes a pinned set.

**MCP tier/approval belt (added by #5047).** Ownership is the primary — and, for an untiered caller, only — gate on this surface. But the 4 write operations (create/pin/unpin/delete) also carry the same MCP tier/approval enforcement every RBAC-gated route gets (`AuthRoutes::require_tier_policy`, extracted from `require_permission`): a `readonly`-tier bearer cannot reach any of them, an `operator`-tier bearer cannot reach any of them (`Infrastructure:Write`/`:Delete` are not on `tier_allows()`'s operator allow-list), and a `supervised`-tier bearer's `delete` requires an approval ticket (`Infrastructure:Delete` is on `requires_approval()`'s list; create/pin/unpin are not). Before #5047 this belt applied on the MCP transport only — a tiered bearer could reach the identical REST/dashboard-fragment route and skip it entirely, since these routes have no `perm_fn`/RBAC gate to carry the belt. #5047 wires the belt into all 8 write sites (4 REST + 4 fragments) so a token cannot bypass its tier by switching endpoints (#520), matching MCP's own C8 chokepoint exactly. This belt is **not** RBAC — an empty-tier caller (a plain cookie session, or an API token minted with no `mcp_tier`) is untouched by it either way, which is the separate, already-tracked, open design question [#4309](https://github.com/Tr3kkR/Yuzu/issues/4309) tracks, not this fix.

**The producers ARE RBAC-gated.** The routes/tools that reach into fleet data to *mint* a result set are a different surface, with real securables: `create_result_set_from_tar_query`, `create_result_set_from_instruction_result`, and `reevaluate_result_set` all gate on `Execution:Execute` with the caller's confined dispatch-visible set (ADR-0033 §2); `create_result_set_from_inventory_query` gates on `Inventory:Read` via the ADR-0017 admit-and-confine fleet-read chokepoint (its MCP `kToolSecurity` row is labelled `Inventory:Write`, but that is tier-bucketing only — the actual RBAC check is `Inventory:Read`, matching its REST twin). None of these four is affected by the ownership-only posture above.

[#1207](https://github.com/Tr3kkR/Yuzu/issues/1207) tracks giving `ResultSet` a real RBAC securable for cross-operator sharing. When it lands, ownership must remain sufficient on its own — an operator's own result sets stay theirs whether or not they hold the new securable — and the grant must be **additive** (owner **OR** grant admits, never owner **AND** grant), so it only ever *widens* who can reach a set, never narrows an owner's own access. Sharing must be its own distinct, separately-gated operation, not a side effect of a broader grant. It must also cover the scope-expression resolver — the `from_result_set:<id>` evaluation path a shared set's grantee needs to actually *target* it (dispatch/policy/TAR scope evaluation, a code surface distinct from the CRUD routes: `scope_engine.cpp`, `scope_yaml.cpp`, `dispatch_scope_ladder.hpp`) — in addition to all three CRUD surfaces above (REST, MCP, and the 6 dashboard fragments); the CRUD surfaces alone let a grantee *see* a shared set without letting them *use* it in a scope.

## Operations

| Operation | Typical meaning |
|---|---|
| `Read` | View or list resources |
| `Write` | Create or modify a resource |
| `Delete` | Remove a resource |
| `Execute` | Run an instruction against devices |
| `Approve` | Approve a pending workflow item |
| `Push` | Distribute an existing rule set to scoped agents. Consumed **only** by `GuaranteedState` REST handlers and seeded **only** on `GuaranteedState` — separates deploy authority from authoring authority. Present in the operations catalogue so custom roles can adopt it, but the default seeds grant it on `GuaranteedState` alone. |
| `Attest` | Record a reviewer's attestation decision on a periodic access review (SOC 2 CC6.2). Consumed **only** by `AccessReview` REST handlers and seeded **only** on `AccessReview` — gated via the dedicated `AccessReview` securable, never `AuditLog` (see "The authorization topology floor" below). |
| `Rotate` (P2 #11, SOC 2 CC6.3) | Self-service overlap-pair rotation of a human-owned API token. Consumed **only** by `ApiToken` REST/MCP handlers and seeded **only** on `ApiToken`, to the same two roles that already hold `ApiToken:Write` (`Administrator`, `ApiTokenManager`) — deliberately a separate operation from `Write` so a narrower MCP-tier allowance can be granted for rotation without also widening token-mint access. |

## Permission Resolution

Yuzu evaluates permissions with **deny-overrides-allow**:

1. Collect all roles assigned to the principal (direct user assignments + group assignments).
2. Gather all permissions from those roles for the requested `(securable_type, operation)`.
3. If any permission has effect `Deny`, the request is **denied**.
4. If at least one permission has effect `Allow`, the request is **allowed**.
5. If no matching permission exists, the request is **denied** (implicit deny).

### Scoped Permissions

When a resource belongs to a management group (e.g., a device in "London Servers"), the permission check works in two passes:

1. **Global check** -- roles assigned without a group scope (via the `principal_roles` table) are evaluated first using standard deny-overrides-allow. If the user has a global allow, the request is permitted immediately.
2. **Scoped check** -- the system finds the agent's management group memberships, then collects all ancestor groups (child to root). For every group in this set, it looks up scoped role assignments (stored in the `ManagementGroupStore`) that match the user directly or via RBAC group membership. All matching permissions are evaluated with deny-overrides-allow: any deny returns false; otherwise, if at least one allow is found, the request is permitted.

This means a role scoped to a parent group automatically covers all child groups.

## API Reference

All REST API v1 responses are wrapped in a standard JSON envelope:

```json
{
  "data": ...,
  "meta": { "api_version": "v1" }
}
```

List endpoints add a `pagination` field:

```json
{
  "data": [...],
  "pagination": { "total": 6, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

### Check Permission

Verify whether the current user has a specific permission. Useful for UI feature gating or pre-flight checks in scripts.

**Note:** This endpoint uses `POST`, not `GET`, because it accepts a JSON request body.

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/rbac/check \
  -H "Content-Type: application/json" \
  -d '{
    "securable_type": "Infrastructure",
    "operation": "Execute"
  }'
```

```json
{
  "data": {
    "allowed": true
  },
  "meta": { "api_version": "v1" }
}
```

A denied response (the `allowed` field is `false`; no reason string is returned):

```json
{
  "data": {
    "allowed": false
  },
  "meta": { "api_version": "v1" }
}
```

### List Roles

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/rbac/roles
```

```json
{
  "data": [
    {
      "name": "Administrator",
      "description": "Full access to all operations",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "PlatformEngineer",
      "description": "Author and manage YAML instruction definitions, sets, and schemas",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Operator",
      "description": "Execute and manage instructions, schedules, and tags",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "ApiTokenManager",
      "description": "Create, revoke, and manage API tokens for programmatic access",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "ITServiceOwner",
      "description": "Admin control over devices tagged with the same IT Service",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Viewer",
      "description": "Read-only access to operational data",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Reviewer",
      "description": "Read audit evidence and attest/flag access-review grants (SOC 2 CC6.2)",
      "is_system": true,
      "created_at": 1710849600
    }
  ],
  "pagination": { "total": 7, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

### Get Role Permissions

```bash
curl -s -b cookies.txt \
  http://localhost:8080/api/v1/rbac/roles/ITServiceOwner/permissions
```

```json
{
  "data": [
    { "securable_type": "Approval", "operation": "Approve", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Delete", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Execute", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Read", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Write", "effect": "allow" },
    { "securable_type": "AuditLog", "operation": "Read", "effect": "allow" },
    { "securable_type": "Infrastructure", "operation": "Read", "effect": "allow" },
    { "securable_type": "Tag", "operation": "Read", "effect": "allow" }
  ],
  "meta": { "api_version": "v1" }
}
```

(Truncated for brevity. The full ITServiceOwner role contains 93 permissions across 18 securable types — the 90 CRUD grants plus three targeted ones: `GuaranteedState:Push`, `Workflow:Read` (#4030) and `Decommission:Delete` (Wave 7 PR7.2).)

### Custom Roles (Planned)

Custom roles can be created programmatically via `RbacStore::create_role()` and permissions assigned via `RbacStore::set_permission()`. REST API endpoints for role **creation** are planned but **not yet implemented** — there is no HTMX Settings UI fragment for this either (`settings_routes.cpp` has no RBAC role-CRUD registration). Currently, a genuinely NEW custom role can only be created directly against the shared PostgreSQL `rbac_store` schema (see the "Storage (ADR-0041)" callout above — one `psql` session, not a per-node file).

**Assigning one of the 6 fleet-wide-assignable built-in roles to a human user is implemented — see "Fleet-Wide Role Assignment" below** (`ITServiceOwner`, the 7th built-in role, is assignable only at management-group scope — see "Scoped Role Assignments"). Only AUTHORING a brand-new custom role (and narrowing/widening a seeded system role's own permission set) remains planned.

**Planned endpoints (not yet available):**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/rbac/roles` | Create a custom role |
| `PUT` | `/api/v1/rbac/roles/{name}` | Update a role |
| `DELETE` | `/api/v1/rbac/roles/{name}` | Delete a custom role |

### Fleet-Wide Role Assignment (Built-in Roles)

An Administrator can grant or revoke one of the 6 non-`ITServiceOwner` built-in roles (`Administrator`, `PlatformEngineer`, `Operator`, `ApiTokenManager`, `Viewer`, `Reviewer`) to a human (`principal_type="user"`) user, fleet-wide, through a dedicated pair of routes — **not** the general RBAC-securable `perm_fn`/`require_permission` gate every other route in this document uses. Granting (and especially revoking) standing Administrator authority is a stronger security decision than an ordinary permission check, so the caller must hold a **durable** Administrator role themselves, re-read fresh from the store rather than trusted from a cached session role or a JIT (`POST /api/v1/elevate`) elevation — an elevated session does **not** satisfy this gate.

```bash
# Grant the Operator role to a user, fleet-wide
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/rbac/roles/Operator/assignments \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane.doe"
  }'

# Revoke it again
curl -s -b cookies.txt -X DELETE \
  http://localhost:8080/api/v1/rbac/roles/Operator/assignments/jane.doe
```

Key constraints:

- **`principal_type` must be `"user"`.** Group-scoped fleet-wide assignment is not supported yet — `rbac_store.group_members` is written solely by IdP group-sync, so a group-held grant would make the IdP the admin-authority source, a decision not made by this surface.
- **`ITServiceOwner` is explicitly rejected**, not silently mis-assigned. Its 92-permission grant is designed around the holder being CONFINED to devices tagged with their IT Service — but that confinement is enforced entirely by `ManagementGroupStore::get_visible_agents`, which reads only the group-scoped `management_group_roles` table, never `principal_roles` (this surface's only write target). A fleet-wide `ITServiceOwner` grant would resolve unconfined/global on every type-level permission check while showing the holder zero visible devices on any per-device list read — wrong both ways. Assign `ITServiceOwner` via the management-group role route instead (see "Scoped Role Assignments" below).
- **Only the 6 named roles above are accepted** — enforced against a closed allow-list (`rbac_assignable_roles.hpp`), not "any role that happens to exist in the store". A pre-existing custom role (`is_system=false`, creatable only via direct SQL today — `RbacStore::create_role` has no route caller) is rejected exactly like an unknown role name. An unknown/custom role name and `ITServiceOwner` all return the identical client-facing rejection message — the specific reason is recorded in the audit log only, so a caller cannot enumerate the role catalog by diffing error text.
- **A caller may not revoke the fleet's last remaining `Administrator` grant through this surface.** The store-level guard runs inside the same transaction as the delete, so two concurrent revokes cannot both succeed and leave zero administrators. It counts only `principal_type='user'` rows that ALSO name a currently-active `auth.users` account — a grant naming a nonexistent, deactivated, or (soft-)deleted username is never treated as a survivor.
  - **A principal reactivated while an unassign is in flight is caught (Doomgoose external review, PR #4985).** The guard first locks the candidate Administrator grant rows (`FOR UPDATE OF pr`) and deliberately does not lock the candidate set of `auth.users` rows, because that would serialize unassigns against unrelated logins and role changes. A grant whose account was deactivated at that moment is therefore excluded from that snapshot and could be reactivated by an independent transaction (for example an account reactivation) before the delete runs. After the delete, in the same transaction, and only when the removed grant was not already among the counted rows, the guard re-reads the deleted principal's own `auth.users` row with `FOR UPDATE`: a reactivation that has already committed is seen, one still in flight makes the guard wait and re-read it, and one that starts later blocks until this transaction finishes. If the reactivated principal is the fleet's only real Administrator, the removal is refused. This is closed for an existing account only. Two cases remain outside the guard: a pre-provisioned grant whose `auth.users` row is created concurrently (there is no row to lock), and deactivation of a surviving Administrator between the guard's recount and its commit (`remove_user` has no last-Administrator guard). Both are tracked at #4966. A lock wait is bounded by the database pool's lock timeout (10 seconds by default; the pool does not inject it when the DSN sets its own `options` or `PGOPTIONS` is set, and the wait is then bounded only if that setting, or the server or role default, sets a `lock_timeout`); on timeout nothing is deleted, the REST route answers `503`, and the MCP twin answers an internal error with a retry hint.
  - **This guard covers only THIS route's own unassign path** — it does not, on its own, guarantee the fleet always has a *usable* administrator. Deactivating or deleting the account behind the fleet's last Administrator grant is a **separate, unguarded** path (account lifecycle management, not role-grant management) that can still leave zero authenticatable administrators. Tracked as a real gap in [#4966](https://github.com/Tr3kkR/Yuzu/issues/4966).
  - **An SSO (OIDC/SAML) Administrator cannot receive a `principal_roles` grant through THIS surface at all, which is a usability limitation for SSO fleets, not a security gap — and not because the row can't exist.** The real mechanism: this route's `principal_id` charset check (`is_valid_username` — alphanumeric plus `.`/`_`/`-`, 1–64 characters) rejects the stable SSO principal formats outright before an assignment is ever attempted — OIDC's `"oidc:" + iss + "#" + sub` and SAML's `"saml:" + entity_id + "#" + name_id` (`oidc_principal_id`/`saml_principal_id`) both contain `:` and `#`, neither of which the charset allows. So a `principal_roles` row naming an SSO principal can never be WRITTEN via this route in the first place — a stricter, earlier-stage gap than "the row doesn't exist". Whether an `auth.users` row separately exists for the principal differs by protocol and doesn't change this: **OIDC** *does* durably provision one — every successful OIDC login calls `AuthManager::provision_sso_identity` → `AuthDB::upsert_sso_identity`, an `INSERT ... ON CONFLICT (username) DO UPDATE` that creates (first login) or refreshes (every login after) a real, `is_active=TRUE`-by-default `auth.users` row keyed on the same stable principal — but that row is moot for this guard, since no `principal_roles` row can ever be assigned to that principal_id to begin with. **SAML**, by contrast, provisions no `auth.users` row at all today — `AuthManager::create_saml_session` only writes the session store, never `AuthDB` — so for SAML the original "no `auth.users` row" framing happens to still hold, just not for a reason that matters once the charset check is understood. Net effect: an SSO principal is entirely outside this guard's count — its `principal_id` format can never reach `principal_roles` via this route at all, so there is no "SSO grant this guard fails to recognize." Every grant the guard can ever count arrives through THIS route (the only writer of `principal_roles` Administrator rows for `principal_type="user"`), so in practice it only ever counts local-account grants (`AuthDB` usernames, not `oidc:`/`saml:`-prefixed ones) — the guard's own JOIN has no charset restriction and would count an `oidc:`/`saml:`-prefixed row too if one existed, but this route can never write one. Since the last-Administrator fix above (governance ledger `a2-p7-doomgoose-1`), a local grant that was never counted — a ghost (no matching `auth.users` row) or deactivated-account grant — no longer blocks its own removal; the guard only refuses when removing a grant that was itself counted (or whose account was reactivated while the unassign was in flight, see above) would take the count to zero. Also tracked in [#4966](https://github.com/Tr3kkR/Yuzu/issues/4966) (see that issue for a correction to its own originally-stated mechanism).
- **Assigning a role to a username with no existing account is allowed** (pre-provisioning) — RBAC's `principal_roles` and `AuthDB`'s `users` table are independent, unrelated by foreign key.
- **An MCP-tier bearer token of any tier — including `supervised` — is denied on this REST pair**, matching every other admin-only route ([#520](https://github.com/Tr3kkR/Yuzu/issues/520)): REST carries no maker-checker approval machinery, so an MCP-tiered credential reaching it directly would mint/revoke standing Administrator authority with neither REST's MFA step-up nor an approval ticket. MCP callers use the `assign_rbac_role`/`unassign_rbac_role` twins instead, which require the supervised tier plus an approval ticket.
- MCP twins: `assign_rbac_role` / `unassign_rbac_role` — see `docs/user-manual/mcp.md`.

> **The enforcement toggle (`PUT /api/v1/rbac/enforcement`, above) now refuses
> to enable unless the caller already holds this grant** — the chicken-and-egg
> lockout this callout used to warn about is a guarded refusal, not a live
> hazard, as of A1. Mint your own `Administrator` grant via this route FIRST
> (while RBAC is still off, using the disabled-mode durable-admin fallback —
> `auth_db`'s `role='admin'` re-read, the predicate's OTHER branch), THEN flip
> the toggle on. Minting the first grant directly against `rbac_store.
> principal_roles` (see the "Storage (ADR-0041)" callout above for the shared
> Postgres substrate) is now a **recovery-only** path — for a fleet already
> stranded by a direct-SQL enable with zero grants, not the normal onboarding
> flow.

### Scoped Role Assignments

Scoped role assignments bind a principal to a role within a specific management group. These are stored in the `ManagementGroupStore` (not in the RBAC principal_roles table) and are managed through the management group API:

```bash
# Assign a role scoped to a management group
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/management-groups/mg_london_office/roles \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane.doe",
    "role_name": "Operator"
  }'
```

## Examples

### Deny a Specific Operation

Prevent a role from deleting infrastructure resources, even if other roles would allow it. This requires creating a custom role with a Deny permission (via direct database access, since the role creation API is not yet available — no HTMX Settings UI fragment exists for this either):

```sql
-- Example: create a deny role directly against the shared rbac_store schema
-- (psql against the server's PostgreSQL instance — see the "Storage (ADR-0041)"
-- callout above; this is a single shared store, not a per-node SQLite file).
INSERT INTO rbac_store.roles (name, description, is_system, created_at)
  VALUES ('NoDeletion', 'Explicit deny on infrastructure deletion', false, extract(epoch from now())::bigint);
INSERT INTO rbac_store.role_permissions (role_name, securable_type, operation, effect)
  VALUES ('NoDeletion', 'Infrastructure', 'Delete', 'deny');
```

Assign this role alongside any other roles. Because deny overrides allow, the user will be unable to delete infrastructure resources regardless of their other role assignments.

## API Endpoint Summary

| Method | Endpoint | Description | Status |
|---|---|---|---|
| `POST` | `/api/v1/rbac/check` | Check if current user has a permission | Implemented |
| `GET` | `/api/v1/rbac/roles` | List all roles | Implemented |
| `GET` | `/api/v1/rbac/roles/{name}/permissions` | Get permissions for a role | Implemented |
| `POST` | `/api/v1/rbac/roles` | Create a custom role | Planned |
| `PUT` | `/api/v1/rbac/roles/{name}` | Update a role | Planned |
| `DELETE` | `/api/v1/rbac/roles/{name}` | Delete a custom role | Planned |
| `POST` | `/api/v1/rbac/roles/{name}/assignments` | Assign one of the 6 non-`ITServiceOwner` built-in roles to a human user, fleet-wide (A2) | Implemented |
| `DELETE` | `/api/v1/rbac/roles/{name}/assignments/{principal_id}` | Unassign a fleet-wide role from a human user (A2) | Implemented |
| `PUT` | `/api/v1/rbac/enforcement` | Enable or disable RBAC enforcement fleet-wide (A1) | Implemented |
| `GET` | `/api/v1/rbac/roles/assignments` | Fleet-wide "who currently holds which role" — the complete grant table, gated `AccessReview:Read` (see the securable table below) | Implemented |

## Planned Features

| Feature | Phase | Status |
|---|---|---|
| REST API for fleet-wide built-in role assignment | A2 | Implemented |
| REST API + MCP for enabling/disabling enforcement | A1 | Implemented |
| REST API for custom role creation | 3 (Priority B) | Planned |
| Group-scoped fleet-wide role assignment (`principal_type=group`) | 3 | Planned |
| OIDC group-to-role auto-mapping refinements | 3 | Stub |
| Role management via Settings UI matrix | 3 | Planned |
