# Role-Based Access Control (RBAC)

Yuzu implements granular role-based access control with deny-overrides-allow semantics, scoped permissions via management groups, and support for both built-in and custom roles.

## Enabling RBAC

RBAC is controlled by a global toggle. When disabled, all authenticated human users have full access (with a legacy fallback: write/delete/execute/approve operations still require the `admin` session role) — **except** a small, fixed set of reads that the fallback still refuses to a non-admin; see "The authorization topology floor" below. When enabled, every API call and UI action gated on a real securable type is checked against the caller's assigned roles — but not every surface has one: result sets are ownership-scoped, not RBAC-gated, regardless of this toggle; see "Not RBAC-gated: per-operator result sets" below.

Engine principals have no authority without RBAC: with RBAC disabled an engine credential is refused (or sees no agents) rather than treated as legacy-open, and with RBAC enabled it needs an explicit grant.

Toggle RBAC via `PUT /api/v1/rbac/enforcement` (the **Enforce roles** switch on the Users and roles page makes this call; or the `set_rbac_enforcement` MCP tool) — **not** a Settings-page control and **not** a `[rbac] enabled = true` config-file key. Neither exists: nothing in `server/core/src/main.cpp` or any `Config` header reads a `[rbac]` section — see [#388](https://github.com/Tr3kkR/Yuzu/issues/388).

```bash
curl -s -b cookies.txt -X PUT \
  http://localhost:8080/api/v1/rbac/enforcement \
  -H "Origin: http://localhost:8080" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

A call authorised by a session cookie must carry an `Origin` or `Referer` header naming this site (or an entry from `--csrf-trusted-origin`); without one, or with one naming another site, it is refused `403` `cross-site request refused` and audited as `csrf.denied`. API-token callers need no header. The same rule applies to the two role-assignment routes under "Fleet-Wide Role Assignment" below.

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
> [#5182](https://github.com/Tr3kkR/Yuzu/issues/5182) for the underlying
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
> and the legacy `GET /api/responses/{id}`
> / `/aggregate` / `/export` surfaces return **zero rows** (the legacy aggregate
> returns `503`), and `GET /api/v1/executions/{id}/visualization` answers `503`,
> on a corrupt store rather than reopening the cross-operator
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
> failure is orthogonal to agent visibility. Separately, when the server cannot determine
> whether the caller may read Forensics-tier rows (#4990), `group-from-results` creates nothing and
> answers `200`; the operator sees a constant error toast ("The permission check for this action
> could not be completed. Nothing was created. Retry shortly."), delivered in an `HX-Trigger`
> `showToast` header because the create-group form swaps no response body into the page (the response
> body carries the same text for every caller, but htmx does not display it for this form). The store-degraded case above answers `503`
> with its own error toast ("Agent count unavailable. The response store could not be read. Nothing
> was created. Retry shortly.") on the same channel, and also creates nothing.
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
> duplicate); `summarize_working_set` `kind=fleet`/`result_set` (an unscoped
> whole-registry agent count, tracked #4753). (REST
> `GET /api/v1/execution-statistics/agents` and the MCP
> `get_execution_statistics_by_agent` twin, formerly listed here under #3526, now gate on the
> fleet-read chokepoint and are confined, effective only with RBAC enforcement on (a
> management-group-scoped-only operator, refused before, is now admitted as a confined view;
> with RBAC off the rollup is unfiltered for every authenticated non-service, non-engine
> caller); the `/definitions` and fleet-summary
> statistics carry no agent identity and keep the plain `Execution:Read` gate.) So
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
>    Use an Administrator-minted non-service token for that route. This replaces a confined credential with an
>    Administrator-grade one, and there is no narrower option today: `Enrollment:Read` is Administrator-only by
>    default and custom-role authoring is not reachable through REST, MCP or the dashboard yet (see "Custom Roles"
>    below).
> 2. **Breaking:** `GET /api/v1/upload-grants` refuses a service-scoped token with `403` (no `permission`
>    field); it used to return the minter's `UploadGrant:Read` view. Same remedy: list with a non-service token.
> 3. The ceiling applies wherever a seeded `ITServiceOwner` permission is absent. No REST, MCP or CLI surface
>    removes a seeded `ITServiceOwner` permission today (narrowing a seeded role's permission set is planned,
>    see "Custom Roles" below). A direct database `DELETE` of the row is re-seeded at the next boot unless the
>    pair is recorded in `revoked_seed_defaults`, so a refusal on one of those pairs arises only for a pair
>    removed through `RbacStore::remove_permission` (which records it) or recorded there by hand; the rule is
>    the safeguard for that case and for a future authoring surface.
>
> A definitive deny is `403`; a FAILED read of the `ITServiceOwner` role's permissions is a
> retryable `503` (`retry_after_ms` 5000) on the fleet-read gate and on `require_scoped_permission`
> (an outage is not a missing grant, and the request is still refused). On a route behind the plain
> permission gate (`require_permission`) a service-scoped token is refused by the default-deny
> allow-list whatever the ceiling read returns, so a failed read there answers the same `403` as a
> healthy one, with no retry hint. The ceiling read goes through the
> RBAC authz circuit breaker with a 250 ms acquire budget, so a degraded store answers quickly and, once
> the breaker is open, without touching the pool (an open breaker is counted under `pool_acquire_timeout`). It is the same breaker operator permission checks use, so
> repeated ceiling-read failures can open it and an open breaker denies operators' cache-miss checks too
> (fail closed). The breaker counts consecutive failures and any successful authz read, a ceiling read
> included, resets the count, so a partial fault that lets the `role_permissions` read succeed while other
> authz reads fail can delay the breaker opening for operators' cache-miss checks. A read that is already admitted and holds a connection can still wait up to the pool's
> `lock_timeout` (10 s default) or `statement_timeout` (30 s default). On a dark network path (no reply at all)
> the wait is bounded instead by the pool's `tcp_user_timeout` (10 s), which is confirmed on Linux, unconfirmed
> on Windows and a no-op on macOS; and until two failures have returned, up to the pool size (16 by default,
> `--postgres-pool-size`) of these reads can each hold a connection for that long. One
> deferred item remains: the `authorize_list_read` supersede-to-intersect migration for the remaining callers
> is tracked in `docs/security-reviews/service-scope-phase2-migrations-2026-08.md`, so "every fleet-read
> route" above does not mean every route that lists per-agent data.
>
> **Executions panel and `summarize_working_set` (`kind=execution`).** The
> workflow executions LIST fragment `/fragments/executions` and MCP
> `summarize_working_set` `kind=execution` were on the "still not covered" list
> and are now on `require_fleet_read` too: on the dashboard fragment a
> group-scoped-only operator gets a confined view where it previously got `403`,
> while `summarize_working_set` keeps its plain `Infrastructure:Read` first gate
> (a group-scoped-only operator still gets `403` there; only a caller with a
> global `Infrastructure:Read` plus a group-scoped `Execution:Read` is newly
> admitted). An author-run reachability probe (not independently adjudicated)
> found no out-of-scope disclosure through the old gate, because the flat gate
> only ever admitted global-grant callers, who are unfiltered anyway. With RBAC
> off (the shipped default) both surfaces are unconfined for every authenticated
> non-service, non-engine caller whose tier allows it (an engine principal is refused with
> `403` with RBAC off), and a service-scoped token is refused (`403`; the dashboard fragment shows a "You do not have permission to view executions." note at HTTP `200`). A service-scoped
> token sees on the fragment only executions that touched an in-scope agent: the
> owner disjunct (a principal's own dispatches) is suppressed for it, because its
> session username is the account that minted it (the other execution read
> surfaces still show a minter's executions to a service-scoped token, #5557).
> **Exception to
> the degraded-store sentence above:** a degrade on the Executions panel is NOT a
> `503` the operator sees. The fragment's own failure notes (tracker or status
> read failure) and the gate's refusals (store not open becomes a
> `data-degraded="gate"` note, a permission refusal a `data-denied="true"` note)
> all render at HTTP `200`, because the dashboard drops `4xx`/`5xx` bodies; the
> gate's audit row is still written. An HTTP-status monitor of the fragment
> therefore no longer sees them, while `GET /api/v1/executions` keeps its real
> `403`/`503`. See `upgrading.md`. The `ITServiceOwner` ceiling for service-scoped
> tokens is applied by PR #5546 (the "Service-scoped tokens and `ITServiceOwner`"
> paragraph above), not by the executions-panel change.
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

Eleven reads are treated as **authorization topology or audit evidence**
rather than ordinary operational data. Wherever the legacy RBAC-off fallback is the branch in
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
| `Forensics:Read` | Windows forensic-artefact and per-device application-usage reads (Wave 7 PR7.2), per-app privacy-permission grants and per-account SSH access (`remote_access_audit`); also the stored responses of those Forensics-tier plugins on every response read path (REST, MCP, dashboard), which are served only to a caller holding it |
| `AuditLog:Read` (#5771) | The audit trail itself (SOC 2 CC6.1/CC7.2 evidence): `GET /api/audit`, `GET /api/v1/audit`, `GET /api/v1/audit/auth-sample`, `GET /api/v1/engine-principals/audit/no-admin`, the `query_audit_log` and `audit_engine_no_admin` MCP tools, and the `yuzu://audit/recent` MCP resource |

**Why this exists.** With RBAC **disabled**, the legacy fallback described
above allows any authenticated non-engine session to perform every `Read` —
that includes these eleven. On a default install (RBAC ships disabled) that
handed a plain `user` session read access to the authorization topology
itself: who holds what role, and the complete access-review grant
population that is supposed to *be* SOC 2 CC6.2 evidence of controlled
access — and, until #5771, the full audit trail (who did what, to which
target, with what outcome, plus the free-text detail and, on the legacy
`GET /api/audit` route, each actor's role and source IP). The floor closes
that gap by denying these eleven reads to a
non-admin whenever the legacy fallback is the branch in effect — never by
changing behavior under a live RBAC grant.

**This does not affect RBAC-enabled deployments beyond the one closed
gap.** The floor only ever engages inside the legacy (RBAC-off) fallback; a
live RBAC branch always answers first when RBAC is enabled and enforced. In
particular, a non-admin holding the seeded `Reviewer` role (`AccessReview:Read`
+ `AccessReview:Attest`) continues to reach the access-review export exactly
as before — the floor never overrides that grant.

**If you are relying on a non-admin reaching one of these eleven reads on an
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
- For the audit trail (#5771): enable RBAC and assign a role that holds
  `AuditLog:Read` — the built-in `Operator`, `PlatformEngineer`,
  `ITServiceOwner` and `Viewer` roles already hold it, or grant it to a
  custom role. The `Reviewer` role does not hold it. Under RBAC, `AuditLog:Read`
  is not confined to a management group: a holder reads every row.

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
> authorization topology — correlate with the route in the audit row first. The Access
> principals fragments (`/fragments/access/principals/*`) are a further source: they probe
> `EnginePrincipal:Read` on every page view, a floored refusal moves this counter, and for a
> browser session no audit row accompanies the increment.
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

## Managing accounts and roles from the dashboard

The **Users and roles** page (`/access/users`, in the **Access** section of the sidebar) lists
the accounts that can sign in to this server and shows one account's details beside the list.
An administrator can add, remove and change accounts from it; the page calls the same routes
Settings uses, so the two stay equivalent.

- **Who can see it.** Any signed-in user can open the page. The Users panels need the
  Administrator account role; for anyone else each panel says it is not available to their
  account. A refused browser session writes no audit row (the panels load automatically, so
  a row per page view would fill the log with denials); a refused API or MCP token that
  reaches the panel URL is recorded as an administrator-required denial.
  The Roles and Role permissions panels need the `UserManagement:Read` permission and record each
  refused load as a permission-required denial, so a person without it leaves one denial row per
  refused panel (the Role assignments panel is covered below).
- **Account role versus RBAC role.** The account role (`admin` or `user`) is the legacy role:
  it decides who can open Settings and what applies while RBAC enforcement is off. RBAC roles
  apply once enforcement is on.
- **Add user.** Asks for a username and a password. New accounts always start as `user`; set
  the account role afterwards. If the server refuses (name taken, password too short or too
  long, reserved prefix, or a username that still belongs to a removed account) the dialog
  stays open and shows the server's message. The username is kept; the password field is
  cleared on every refusal, so retype it.
- **Change role.** Switches a local account between `admin` and `user` and signs the person
  out of the dashboard.
- **Revoke sessions.** Ends the account's dashboard sessions at once. API tokens are not
  revoked. It works for single sign-on accounts too.
- **Remove user.** Revokes the account's sessions and API tokens, then removes the account.
  Local accounts only.
- **Confirmation and MFA.** Each of these asks to confirm in the page. Remove, Change role and
  Revoke sessions also need a recent second-factor check: when yours is stale the page asks for
  an authenticator or recovery code and then repeats the action once. A single sign-on session
  signed in through OpenID Connect is told to sign in again at its identity provider and to repeat
  the action afterwards; a SAML session sees the server's refusal.
- **What is never offered.** Your own row has no Remove or role change (the
  server refuses both) and no Revoke sessions (it would end the page you are using; use Sign out
  everywhere). A single sign-on or SCIM account has only Revoke sessions: the page hides the other
  controls as a hint (the server refuses single sign-on principal names outright, but a SCIM
  account has a plain name that the local account routes accept). The page never guesses whether an account is the last
  administrator: the server's refusal is shown as it came.
- **When the outcome is unknown.** After a server error or a dropped connection the page says the
  change may or may not have been applied and reloads both panels, so what is shown is what the
  store holds. Only Revoke sessions can report that the action succeeded but its audit record
  could not be written; Add, Change role and Remove cannot raise that banner.
- **Roles and what they allow.** The **Roles** panel lists every role in the catalogue with its
  description, and **View permissions** shows one role's permissions grouped by area (a deny row
  says so). Both need `UserManagement:Read` (the Administrator and Viewer roles; an administrator
  account while RBAC is off) and use the same read as `GET /api/v1/rbac/roles` and
  `GET /api/v1/rbac/roles/{role}/permissions`. A store that does not answer is a red message,
  never an empty list; a role the catalogue does not hold is "No such role", which is different
  from a role that holds no permissions.
- **Who holds which role.** The **Role assignments** panel lists every fleet-wide grant (type,
  principal, role). It needs `AccessReview:Read` (the Administrator and Reviewer roles; an
  administrator account while RBAC is off) and uses the same read as
  `GET /api/v1/rbac/roles/assignments`. Each view writes an `rbac.assignments.list` audit row
  with the number of grants on record (before the 2000-row display cap), exactly as the REST call
  does; if that row cannot be saved the panel is still drawn and the response carries
  `Sec-Audit-Failed`. A grant table that cannot be read is a red message, never an empty table.
- **Assign and remove a role.** On an administrator account the panel offers **Assign role** (a
  username and one of the seven fleet-wide roles; ITServiceOwner needs a management group and is not
  offered; the account does not have to exist yet) and **Remove** on a grant. These call
  `POST` and `DELETE /api/v1/rbac/roles/{name}/assignments`, which need a durable Administrator
  and a fresh MFA check; the page only shows or hides the controls from your account role, and the
  server's refusal (last administrator, your own Administrator grant, the enforcement-regime
  guard) is shown as it came. Only a plain local username can be removed here; a group, SSO or
  engine grant reads "Not removable here". After a server error the panel reloads, because the
  change may have taken effect. The change can take a moment to appear on other servers.
- **RBAC roles and Assigned counts.** The Users table's **RBAC roles** column and the Roles
  table's **Assigned** column are filled from the Role assignments panel. They read "Not shown"
  whenever that panel was not read in full (refused, unreadable, or over the 2000-row cap); a
  count of 0 appears only when the grant table was read and the role holds none.
- **Your account.** For the signed-in user: **Change password** (local accounts only, ends every
  session, same route as Settings) and **Sign out everywhere** (ends every session and revokes
  every API token you own). If the server reports that a token revoke or a session end did not
  persist, the page says so and waits for you to choose to continue instead of redirecting at once.
  "Sign out all other sessions" is shown as not available yet.
- **Turning enforcement on or off.** The **RBAC enforcement** panel shows the current setting to
  every signed-in user (the same value `GET /api/v1/me` reports) and gives an administrator
  account an **Enforce roles** switch. The switch always shows what the server holds: clicking it
  asks for confirmation, then (when your second-factor check is stale) for an MFA code, and then the panel is redrawn from the server, so a
  cancelled confirmation or a refusal leaves it where it was. The server's refusals (you would
  not remain an administrator, or the source regime does not recognise you) are shown with their
  remediation text. When the server cannot confirm the setting the panel says **Unconfirmed**
  instead of On or Off; it treats enforcement as on until it can. See "Enabling RBAC" for the
  lockout guards.
- **Checking your own permission.** **Check your own permission** asks the server whether your
  role grants an area and operation (for example `UserManagement` and `Read`). It checks role
  grants only; while enforcement is off access follows your account role, so Denied does not by
  itself block you. A role store that does not answer also reads as Denied on the server, so the
  page tells you to check again.
- **Temporary elevation.** **Your elevation** raises your own session to administrator for a
  limited time (reason required, recorded in the audit log, up to 1024 bytes; the duration is capped
  by the server). It needs elevation eligibility and an enrolled second factor and asks
  for an MFA code (an OpenID Connect session is sent to its identity provider instead); **Step down** ends it and is always safe. The page cannot show whether your
  session is currently elevated. Elevation does not satisfy the standing-Administrator rule: assigning
  roles and changing enforcement still need your own standing Administrator role, and
  changing an account role (Change role) needs your own account role to be admin: the server refuses it
  for a session that is only admin through an elevation.
- **Large directories.** The Users panel draws at most 500 accounts and the Role assignments panel at most 2000 grants, with a note saying how many exist. An account or grant beyond the cap is not reachable from this page (there is no search yet): use the Settings user table or the REST routes for it, and the derived "RBAC roles" and "Assigned" cells read "Not shown" when the grant table was capped.
- **What the audit trail shows.** Add user, Remove user and Change role write an `attempted` audit row first; if that write fails the server refuses the change with `503` and the `Sec-Audit-Failed` header, and nothing is created, removed or changed. The outcome row is written afterwards; if only that row is lost, the `attempted` row stands and reads as "started, outcome unknown". These three also refuse a cookie session whose request does not name this site in `Origin` or `Referer` (`403`, with a `csrf.denied` audit row), and Change role accepts only `application/json` (`415` otherwise); API-token callers are not subject to the same-site check. Opening or refreshing the Role assignments panel writes one `rbac.assignments.list` row per view, including the refresh that follows an elevation, step-down or enforcement change, so one session can write several rows with the same count.
- **SAML sessions.** A session that signed in through SAML cannot complete the second-factor step-up for Remove user, Change role or Revoke sessions; the page shows the server's refusal and its remediation text. Use a local administrator account or an administrator API token for those actions.
- **Unreadable store.** If the account store does not answer, the Users panel shows a red
  message with a Retry button. It never shows an empty list in that case, so a degraded store
  cannot be mistaken for "nobody is here".

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

Eight roles are created automatically and cannot be deleted:

| Role | Permissions | Use case |
|---|---|---|
| **Administrator** | All 5 CRUD operations on all 38 securable types, plus Push on GuaranteedState, Attest on AccessReview, and Rotate on ApiToken (P2 #11, SOC 2 CC6.3 — self-service human token rotation) (193 permissions) | Server admins, security team leads |
| **PlatformEngineer** | Full CRUD on InstructionDefinition and InstructionSet; Read on Execution, Schedule, Approval, Tag, AuditLog, Response, Inventory; Read/Write/Delete/Push on GuaranteedState | Authors and managers of YAML instruction definitions, sets, and Guardian rules |
| **Operator** | Read/Write/Execute/Delete on InstructionDefinition, InstructionSet, Execution, Schedule, Tag; Read and Approve on Approval; Read on AuditLog, Response, and Inventory; Read and Push on GuaranteedState | Day-to-day instruction execution, schedule management, tagging, and Guardian rule distribution |
| **ApiTokenManager** | Read, Write, Delete, Rotate on ApiToken (4 permissions) | Create, revoke, rotate, and manage API tokens for programmatic access |
| **ITServiceOwner** | All 5 CRUD operations on 18 securable types, plus Push on GuaranteedState, plus Workflow:Read, plus Decommission:Delete (93 permissions). Excludes 20 of the 38 securable types, including UserManagement, Security, ApiToken, AccessReview and EnginePrincipal | Service desk leads, team managers with delegated control over their IT services |
| **Viewer** | Read on 24 securable types (24 permissions) — an explicit allow-list in `rbac_store.cpp`'s seed, *not* “everything except” | Helpdesk staff, auditors, read-only dashboards |
| **Reviewer** | Read and Attest on AccessReview (2 permissions) | Periodic access reviews (SOC 2 CC6.2) — the non-admin role that can attest or flag a grant |
| **ForensicsAnalyst** | Read on Forensics, Response, Execution and Inventory (4 permissions). No Execute and no write of any kind | Read-only analysts of Forensics-tier response rows. Fleet-wide assignable only; cannot dispatch; not part of any other role |

### The ForensicsAnalyst role

`ForensicsAnalyst` is the delegable read tier for the stored rows of Forensics-tier plugins (`app_usage`, `browser_inventory`, `execution_artifacts`, `privacy_permissions`, `remote_access_audit`), which only a caller holding `Forensics:Read` is served (see the `Forensics` and `Response` rows under "Securable Types"). Without it, the only built-in holder of `Forensics:Read` is `Administrator`, so there would be no way to give an analyst these rows short of administrator rights or writing the grants by hand in PostgreSQL.

- **Read-only.** Exactly four permissions: `Forensics:Read`, `Response:Read`, `Execution:Read` and `Inventory:Read`. It holds no `Execute` and no write of any kind, so it cannot dispatch a command, and it is part of no other role.
- **Fleet-wide assignment only.** Assign it with `POST /api/v1/rbac/roles/ForensicsAnalyst/assignments`, the MCP `assign_rbac_role` tool or the **Assign role** control on the Users and roles page (see "Fleet-Wide Role Assignment" below). Assigning it at management-group scope is not offered: the scoped assignment routes accept only `Operator` and `Viewer`.
- **Not for engine principals.** It is a built-in (system) role, and the engine-principal assignment gate refuses a built-in role, so an engine principal cannot be given the seeded role. The one exception is a hand-made non-system role of the same name (see "Created at server start" below), which the gate does not recognize as built-in.
- **Inert while RBAC enforcement is off.** The legacy permission fallback is unchanged and `Forensics:Read` stays administrator-only until enforcement is on; a stored assignment is neither erased nor honored in that state, and takes effect again when enforcement is switched back on. See "Enabling RBAC".
- **Breadth: assign it as a high-sensitivity read role.** `Response:Read` is fleet-wide and covers the stored responses of every plugin, including the usage-class `device.live.*` results (process tree, active connections, logged-in users, DNS resolver cache), and `Inventory:Read` reaches the device configuration-item inventory (serial number, system UUID, MAC addresses) fleet-wide. These are the minimum the tier needs to interpret a forensic row, and the `Viewer` role already holds both (and `Execution:Read`), so over a `Viewer` the role adds only `Forensics:Read`; but an analyst can read all of it, so include the role in access reviews as such.
- **Collection stays approval-gated.** The role lets its holder read what was collected; it does not let them collect. A user holding `Operator` plus `ForensicsAnalyst` passes the permission step of a Forensics-plugin dispatch, but the dispatch is still `AdminOrApproval`: a caller who is not an effective administrator needs an approval ticket. A user holding only `ForensicsAnalyst` cannot dispatch at all: `POST /api/command` refuses with `403` at the `Execution:Execute` gate, and on the MCP `execute_instruction` tool at the supervised tier the approval step runs before the tool's own permission check, so an approval ticket can be spent by a call that is then refused for the same reason (an ordering that already applied to any caller lacking `Execution:Execute`).
- **API tokens.** A token carries its creator's authority. A plain API token and an MCP-tier token (a read is permitted at every tier) created by a global `Forensics:Read` holder carry that global read. A service-scoped token never carries it, even when its creator holds the role. There is no management-group scoped read tier: only a global `Forensics:Read` admits Forensics rows, whichever kind of caller asks, and a `Forensics:Read` grant scoped to a management group (which can only be written by hand in PostgreSQL, an unsupported route that does not pass through the server and so is not recorded in the in-product audit log or covered by the guards on the assignment routes) reads nothing from the stored-response surfaces. The one other consumer of such a grant is the per-device application-usage read (`GET /api/v1/forensics/agents/{id}/app-usage` and MCP `get_agent_app_usage`), a different data set with its own per-device scoped gate that still honors a group-scoped `Forensics:Read` for devices in the group. The scoped assignment routes accept only `Operator` and `Viewer`, and engine principals cannot hold a scoped assignment. No role that can be assigned at management-group scope, and not `ITServiceOwner`, holds `Forensics:Read` (a unit test pins this); adding a scoped tier would need a production authoring path, a fresh review and end-to-end tests. A token or MCP caller without a global `Forensics:Read` also leaves one `auth.permission_required` denied audit row per read of stored responses; an interactive browser sign-in does not.
- **Per plugin, not per kind of data.** The role unlocks the stored rows of the five Forensics-tier plugins only. Other plugins can return comparable information (file, registry, WMI or event-log reads, for example) under their own securables, and their stored rows stay under `Response:Read`.
- **Created at server start.** The role is created by the idempotent seed pass that runs at every server start, with no migration, and is assigned to nobody. If a role named `ForensicsAnalyst` that is not a built-in role already exists (it can only have been created by hand in PostgreSQL), it is kept as it is, the four grants are NOT added to it (so its existing holders gain no `Forensics:Read`), and the server logs one error naming the role at start-up; the built-in role is then unavailable until the hand-made role is removed and the server restarted. To find it, list the roles (`GET /api/v1/rbac/roles`) and look for `ForensicsAnalyst` with `is_system` false, and its holders with `GET /api/v1/rbac/roles/assignments`. While the collision exists, assigning `ForensicsAnalyst` through `POST /api/v1/rbac/roles/ForensicsAnalyst/assignments` or `assign_rbac_role` is refused as a name collision (409 on REST, an invalid-params error on MCP, audited). There is no product route to remove a role, so the remedy is direct SQL on the `rbac_store` schema, which is unsupported and not audited: create a replacement role under another name first if its holders need one, then `DELETE FROM rbac_store.roles WHERE name = 'ForensicsAnalyst' AND NOT is_system`, which also removes the role's grants and assignments (they reference the role by name with `ON DELETE CASCADE`, and a role with grants cannot be renamed); a hand `DELETE` does not bump the RBAC generation, so restart every serving replica afterwards. If the seed's role check cannot be completed at start-up, the four grants are withheld for that boot and added at the next one (an error is logged). Grants an earlier build already merged into such a role are not removed. Because that role is not a built-in role, the engine-principal bar above does not apply to it, so review its assignments and grants.

## Securable Types

| Securable type | Description |
|---|---|
| `Infrastructure` | Agent endpoints (query, command, patch) |
| `Tag` | Asset tags applied to devices |
| `InstructionDefinition` | YAML-defined instruction templates |
| `InstructionSet` | Grouped collections of instructions |
| `Execution` | Running or completed instruction instances |
| `Response` | Instruction response data (rows written by Forensics-tier plugins additionally need `Forensics:Read`) |
| `Schedule` | Cron-style recurring instruction schedules |
| `Approval` | Approval workflow entries |
| `ManagementGroup` | Hierarchical device groups |
| `UserManagement` | User accounts and role assignments |
| `Security` | Security settings (TLS, enrollment, quarantine, CA and KEK reads, and privilege-posture reads such as the local_security_policy `sudoers` content) |
| `ApiToken` | API token lifecycle |
| `AuditLog` | Audit event records. `AuditLog:Read` is in the topology floor (#5771): admin-only while RBAC is off. |
| `Policy` | Guaranteed State policy fragments and composed policies |
| `DeviceToken` | Agent device-token issuance and revocation |
| `SoftwareDeployment` | Software deployment campaigns |
| `License` | Enterprise license records |
| `FileRetrieval` | File upload and download operations |
| `GuaranteedState` | Guardian (Guaranteed State) policy rules, events, and status |
| `Inventory` | Installed-software inventory synced from endpoints (ADR-0016) |
| `EnginePrincipal` | Engine-principal inventory and fleet-wide grant-graph reads (list/get engine principals, list their assigned roles) — cut away from `Security` (#2376) so this narrower read is not gated by the same broad permission that also covers CA/quarantine/KEK operational reads. See "The authorization topology floor" below. |
| `Forensics` | Forensic-artefact reads (Windows execution artefacts — ShimCache/AmCache/Prefetch; per-device application-usage projection; per-app privacy-permission grants; per-account SSH authorized-key fingerprints and sshd settings). Held by default by Administrator and by the read-only `ForensicsAnalyst` role (absent from the Viewer read-list). The stored results of these plugins are served only to a caller who holds `Forensics:Read` in addition to `Response:Read`; to any other reader of the response APIs those rows are absent. With RBAC enforcement off, `Forensics:Read` is administrator-only, so a non-administrator session does not see them either. Only the `plugin` name is stored with a response row, so the filter is per plugin: a plugin that mixed Forensics and ordinary actions would have all of its rows treated as Forensics-tier until the action name is stored too (no such plugin exists today). Every catalogue row on it is single-target (exactly one agent id, no fleet/scope fan-out) and `AdminOrApproval`-gated. Wave 7 PR7.2/PR7.3. |
| `Decommission` | Device-level agent-erasure gate for `DELETE /api/v1/sle/agents/{id}` (ADR-0024 Decision 9, amended Wave 7 PR7.2). `Decommission:Delete` authorizes for the whole decommission cascade's blast radius (seven per-agent stores: five spanning `Inventory`, `GuaranteedState`, and `SoftwareLicensing`, a sixth `Forensics`-governed store, and the `endpoint_state` presence row read on `/hardware` and `/viz/fleet`) in one grant, replacing a hand-maintained per-store conjunction. |
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
| `GET /api/v1/result-sets/{id}/members` | `get_result_set_members` | `GET /fragments/result-sets/{id}/members` (same `Infrastructure:Read` scope, applied before the page limit) |
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
| `Approve` | Approve or reject a pending approval request. Holding `Approval:Approve` is necessary but not sufficient: the reviewer must also be on an interactive cookie session (local or OIDC) with a fresh MFA step-up, and must not be an API-token, MCP-token or engine session, nor a SAML session while step-up is on (see `instructions.md`, "Who can approve"). The step-up gate can only ask for a factor the account has, so it passes without a second factor in three cases: a local account with no enrolled MFA factor (the gate itself passes it in every `--mfa-enforcement` mode; `required`, and `admin-only` for admins, make login force enrolment, so in practice this is any account under `optional` and a non-admin under `admin-only`); an OIDC session whose identity provider asserted no `amr` proof, unless `--mfa-enforcement=required` (under `admin-only` it still passes for a non-admin role); and any session when `--mfa-step-up-window-secs=0`. `--mfa-enforcement=required` closes the OIDC case only if the identity provider asserts an MFA-method `amr` for approvers: an OIDC session without one gets `401` and loops through re-sign-in at every step-up endpoint, not only approval, so verify `amr` before enabling it (the way back is restarting in `optional` temporarily (it weakens MFA fleet-wide, so restore your intended enforcement afterwards), not just any non-`required` mode, because an `amr`-less OIDC admin is still gated under `admin-only`; see [MFA on SSO sessions](authentication.md#mfa-on-sso-sessions-pr-3) and the [recovery runbook](../ops-runbooks/auth-db-recovery.md#locked-out-by-mfa-enforcement-misconfiguration)). It also makes every local user enrol at login. Requiring an enrolled factor of the approver in every mode is tracked in #6079. |
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
  -H "Origin: http://localhost:8080" \
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

This reads the caller's role grants only. A denied answer is also what the server returns when the role store could not be read, so on **Access → Users and roles → Check your own permission** a "Denied" result asks you to check again if you expected access.

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
    },
    {
      "name": "ForensicsAnalyst",
      "description": "Read forensic-tier response rows (Forensics:Read) plus the ordinary response, execution and inventory reads needed to interpret them; read-only, cannot dispatch (#4990)",
      "is_system": true,
      "created_at": 1710849600
    }
  ],
  "pagination": { "total": 8, "start": 0, "page_size": 50 },
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

**Assigning one of the 7 fleet-wide-assignable built-in roles to a human user is implemented — see "Fleet-Wide Role Assignment" below** (`ITServiceOwner`, the 8th built-in role, is assignable only at management-group scope — see "Scoped Role Assignments"). Only AUTHORING a brand-new custom role (and narrowing/widening a seeded system role's own permission set) remains planned.

**Planned endpoints (not yet available):**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/rbac/roles` | Create a custom role |
| `PUT` | `/api/v1/rbac/roles/{name}` | Update a role |
| `DELETE` | `/api/v1/rbac/roles/{name}` | Delete a custom role |

### Fleet-Wide Role Assignment (Built-in Roles)

An Administrator can grant or revoke one of the 7 non-`ITServiceOwner` built-in roles (`Administrator`, `PlatformEngineer`, `Operator`, `ApiTokenManager`, `Viewer`, `Reviewer`, `ForensicsAnalyst`) to a human (`principal_type="user"`) user, fleet-wide, through a dedicated pair of routes — **not** the general RBAC-securable `perm_fn`/`require_permission` gate every other route in this document uses. Granting (and especially revoking) standing Administrator authority is a stronger security decision than an ordinary permission check, so the caller must hold a **durable** Administrator role themselves, re-read fresh from the store rather than trusted from a cached session role or a JIT (`POST /api/v1/elevate`) elevation — an elevated session does **not** satisfy this gate.

Changing the sign-in provider settings (`POST /api/settings/oidc`, and `PUT /api/config/{key}` for the `oidc_*` keys) needs the caller's own administrator role (the account's own legacy role must be `admin`; an RBAC Administrator grant alone does not count): a session that is administrator only through a temporary elevation is refused, because the provider decides who becomes an administrator at the next SSO login.

Likewise, `Infrastructure:Write` alone no longer suffices to write the administrator-only runtime-config keys through `PUT /api/config/{key}` (`plugin_signing_required`, `dex_alert_routing`, `dex_blast_min_devices`, `dex_blast_window_seconds`, `dex_blast_cooldown_seconds`, `dex_cohort_export_key` and `audit_retention_days`): the caller needs the administrator role (a temporary elevation counts), as on the Settings pages, and an MCP-tier token is refused. The role is the account's legacy role or a live temporary elevation, never an RBAC grant; an RBAC Administrator grant alone does not count. `audit_retention_days` has no Settings page; it is in this class by design because it is the stored audit-retention setting, not because a `PUT` changes the retention applied today: the value is stored only, and the enforced window is `--audit-retention-days` (or `YUZU_AUDIT_RETENTION_DAYS`) plus a restart. See [REST API](rest-api.md#put-apiconfigkey).

```bash
# Grant the Operator role to a user, fleet-wide
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/rbac/roles/Operator/assignments \
  -H "Origin: http://localhost:8080" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane.doe"
  }'

# Revoke it again
curl -s -b cookies.txt -X DELETE \
  -H "Origin: http://localhost:8080" \
  http://localhost:8080/api/v1/rbac/roles/Operator/assignments/jane.doe
```

These two examples send `Origin` because a session-cookie call without a same-site `Origin` or `Referer` is refused `403` `cross-site request refused` (audited as `csrf.denied`); an API-token call needs no header.

Key constraints:

- **`principal_type` must be `"user"`.** Group-scoped fleet-wide assignment is not supported yet — `rbac_store.group_members` is written solely by IdP group-sync, so a group-held grant would make the IdP the admin-authority source, a decision not made by this surface.
- **`ITServiceOwner` is explicitly rejected**, not silently mis-assigned. Its 92-permission grant is designed around the holder being CONFINED to the member devices of the management group they hold the role on (for a `Service: {name}` group, a snapshot of the devices tagged at the time the group was created) — but that confinement is enforced entirely by `ManagementGroupStore::get_visible_agents`, which reads only the group-scoped `management_group_roles` table, never `principal_roles` (this surface's only write target). A fleet-wide `ITServiceOwner` grant would resolve unconfined/global on every type-level permission check while showing the holder zero visible devices on any per-device list read — wrong both ways. Assign `ITServiceOwner` via the management-group role route instead (see "Scoped Role Assignments" below).
- **Only the 7 named roles above are accepted** — enforced against a closed allow-list (`rbac_assignable_roles.hpp`), not "any role that happens to exist in the store". A pre-existing custom role (`is_system=false`, creatable only via direct SQL today — `RbacStore::create_role` has no route caller) is rejected exactly like an unknown role name, except that a non-system role holding the name of a built-in role is refused with a distinct `409` (REST) or invalid params (MCP) naming the collision (see "Role name collision" in the upgrade guide). An unknown/custom role name and `ITServiceOwner` all return the identical client-facing rejection message — the specific reason is recorded in the audit log only, so a caller cannot enumerate the role catalog by diffing error text.
- **A caller may not revoke the fleet's last remaining `Administrator` grant through this surface.** The store-level guard runs inside the same transaction as the delete, so two concurrent revokes cannot both succeed and leave zero administrators. It counts only `principal_type='user'` rows that ALSO name a currently-active `auth.users` account — a grant naming a nonexistent, deactivated, or (soft-)deleted username is never treated as a survivor.
  - **A principal reactivated while an unassign is in flight is caught (Doomgoose external review, PR #4985).** The guard first locks the candidate Administrator grant rows (`FOR UPDATE OF pr`) and deliberately does not lock the candidate set of `auth.users` rows, because that would serialize unassigns against unrelated logins and role changes. A grant whose account was deactivated at that moment is therefore excluded from that snapshot and could be reactivated by an independent transaction (for example an account reactivation) before the delete runs. After the delete, in the same transaction, and only when the removed grant was not already among the counted rows, the guard re-reads the deleted principal's own `auth.users` row with `FOR UPDATE`: a reactivation that has already committed is seen, one still in flight makes the guard wait and re-read it, and one that starts later blocks until this transaction finishes. If the reactivated principal is the fleet's only real Administrator, the removal is refused. This is closed for an existing account only. One case remains outside the guard: a pre-provisioned grant whose `auth.users` row is created concurrently (there is no row to lock), tracked at #4966. Deactivating a surviving Administrator is guarded separately, takes the same grant-row locks in the same order, and is described under "Last-Administrator guard for account deactivation and demotion" below. A lock wait is bounded by the database pool's lock timeout (10 seconds by default; the pool does not inject it when the DSN sets its own `options` or `PGOPTIONS` is set, and the wait is then bounded only if that setting, or the server or role default, sets a `lock_timeout`); on timeout nothing is deleted, the REST route answers `503`, and the MCP twin answers an internal error with a retry hint.
  - **This guard covers only THIS route's own unassign path.** Deactivating or deleting an account, and demoting a local `admin` account, are guarded by a separate rule, described under "Last-Administrator guard for account deactivation and demotion" below. Neither rule proves that anyone can sign in.
  - **An SSO (OIDC/SAML) Administrator cannot receive a `principal_roles` grant through THIS surface at all, which is a usability limitation for SSO fleets, not a security gap - and not because the row can't exist.** The real mechanism: this route's `principal_id` charset check (`is_valid_username` - alphanumeric plus `.`/`_`/`-`, 1–64 characters) rejects the stable SSO principal formats outright before an assignment is ever attempted - OIDC's `"oidc:" + iss + "#" + sub` and SAML's `"saml:" + entity_id + "#" + name_id` (`oidc_principal_id`/`saml_principal_id`) both contain `:` and `#`, neither of which the charset allows. So a `principal_roles` row naming an SSO principal can never be WRITTEN via this route in the first place - a stricter, earlier-stage gap than "the row doesn't exist". Whether an `auth.users` row separately exists for the principal differs by protocol and doesn't change this: **OIDC** *does* durably provision one - every successful OIDC login calls `AuthManager::provision_sso_identity` → `AuthDB::upsert_sso_identity`, an `INSERT ... ON CONFLICT (username) DO UPDATE` that creates (first login) or refreshes (every login after) a real, `is_active=TRUE`-by-default `auth.users` row keyed on the same stable principal - but that row is moot for this guard, since no `principal_roles` row can ever be assigned to that principal_id to begin with. **SAML**, by contrast, provisions no `auth.users` row at all today - `AuthManager::create_saml_session` only writes the session store, never `AuthDB` - so for SAML the original "no `auth.users` row" framing happens to still hold, just not for a reason that matters once the charset check is understood. Net effect: an SSO principal is entirely outside this guard's count - its `principal_id` format can never reach `principal_roles` via this route at all, so there is no "SSO grant this guard fails to recognize." Every grant the guard can ever count arrives through THIS route (the only writer of `principal_roles` Administrator rows for `principal_type="user"`), so in practice it only ever counts local-account grants (`AuthDB` usernames, not `oidc:`/`saml:`-prefixed ones) - the guard's own JOIN has no charset restriction and would count an `oidc:`/`saml:`-prefixed row too if one existed, but this route can never write one. Since the last-Administrator fix above (governance ledger `a2-p7-doomgoose-1`), a local grant that was never counted - a ghost (no matching `auth.users` row) or deactivated-account grant - no longer blocks its own removal; the guard only refuses when removing a grant that was itself counted (or whose account was reactivated while the unassign was in flight, see above) would take the count to zero. Tracked in [#5182](https://github.com/Tr3kkR/Yuzu/issues/5182) (durable SSO Administrator recognition).
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

### Last-Administrator guard for account deactivation and demotion

Removing the last administrator from a fleet leaves nobody who can fix it from the dashboard. Account deactivation and demotion are guarded by one rule that is separate from the grant-removal guard above. It protects these operations:

- Deleting (deactivating) a local account: `DELETE /api/settings/users/{username}`, and a SCIM `active:false`, `PUT` or `DELETE` of a SCIM-provisioned account.
- Demoting a local `admin` account to `user`: `POST /api/settings/users/{username}/role`, and a SCIM group change that demotes a SCIM-provisioned admin.

The rule refuses an operation that would remove the last member of a protected population. There are two populations, and which applies depends on the RBAC regime:

| Population | What is counted | Applies when |
|---|---|---|
| Local admin accounts | active accounts whose `role` column is `admin` | RBAC enforcement on **and** off |
| Administrator grants | `Administrator` grants held by active local accounts | RBAC enforcement **on** only |

Each population is checked on its own, and a refusal from either one aborts the operation (the transaction rolls back, nothing changes). An operation is refused only if it removes a member of a population and leaves that population empty. A population that is already empty never blocks an unrelated deactivation, and an account that is not in a population is never refused on that population's account. Under enforcement off the grant population is not checked, because an admin account can grant itself the role and switch enforcement on in-band.

**What this is and is not.** It is a recovery rule that keeps at least one protected administrator account from disappearing. It is not a proof that anyone can sign in: account lockout, MFA, `sso-only` deployments and identity-provider state are all outside it. The Settings pages additionally require the caller to hold the admin role in their session, and the enforcement toggle requires the caller to be among the administrators.

- **Inactive accounts.** An inactive account is never counted as a survivor. Three rules apply to an inactive account at the store level, reached through `AuthManager::update_role_checked`: demoting an inactive admin is allowed (recovery), promoting an inactive account to `admin` is refused, and a request for the role the account already holds succeeds as a no-op. Nothing in the shipped routes reaches them for an inactive account today (they are dormant until [#5629](https://github.com/Tr3kkR/Yuzu/issues/5629)): the dashboard role route looks the account up first and answers `404` "User not found" (pinned by a route test), so its `409` "Cannot promote an inactive account" can fire only when the account is deactivated between that lookup and the write, and the SCIM group recompute treats an account with no active row as having nothing to retain (a quiet no-op). There is no dashboard view of inactive administrators yet ([#5629](https://github.com/Tr3kkR/Yuzu/issues/5629)).
- **Refusals.** The dashboard answers `409` with a toast, and a SCIM request answers `409` with `scimType` `mutability`; both are audited and counted (`yuzu_server_rbac_last_admin_guard_refused_total{transport}`). See the REST API reference and the audit log reference for the exact bodies and audit values.
- **Credentials are revoked first.** Deleting or deprovisioning an account revokes its linked credentials (API tokens and sessions, including those of linked SSO identities) before the account is deactivated, so that a completed deprovision never leaves live credentials behind (ADR-2001; an early refusal revokes nothing, so those credentials stay live). The server first runs a read-only, best-effort early check and, when it already shows that the account is the last member of a protected population, refuses before revoking anything. That check takes no lock and is not authoritative: two administrators can both pass it, a grant removal or a demotion can invalidate a pass, and the guard itself decides. When the guard refuses after the early check passed, the credentials **have** already been revoked and the account **remains active**; the `409` and its audit row say so. The account's holder has to sign in again and re-create any API tokens.
- **Availability and capacity.** Every guarded deactivation and role change takes the same row lock (the `rbac_enabled` row), so these operations are serialized with each other and with the enforcement toggle. Each waits at most 2000 ms for each of its locks (a transaction-local `lock_timeout` that the owner installs itself). A deactivation takes up to four locks in sequence (the `rbac_enabled` row, the counted Administrator grant set, the target's own grant row, the target's account row), so a stuck lock holder can keep one pooled PostgreSQL connection busy for up to four sequential lock waits of 2000 ms each (about 8 seconds typical bound; `lock_timeout` applies per lock acquisition, so several grant rows held by different transactions can exceed it), plus up to 2 seconds for the failure-path durable session wipe. The "about 8 seconds" figure bounds the lock waits only: the pool's 30 s `statement_timeout` still applies to each statement, and the 2000 ms lifecycle lock timeout is fixed and not configurable. A lifecycle guard transaction (a deactivation or a local role change, the two that install the bound) that sits idle between statements is also cut after 15 s (`idle_in_transaction_session_timeout`, set transaction-locally), so such a lock holder whose client vanished is released by the server instead of blocking every guarded write until the operating system's TCP keepalive reaps it; a lock wait is not idle time, so a waiting request is unaffected. The bound does not cover the transactions of a role unassignment, the enforcement toggle or the first-administrator provisioning, which keep only the pool defaults, and a transaction-local setting overrides a stricter operator-set `idle_in_transaction_session_timeout` upward to 15 s for the two lifecycle transactions. The default pool is 16 connections (`--postgres-pool-size`), and a request waiting for a lock holds its connection while it waits. Each guarded lifecycle request therefore pins one pool connection while it waits on the fleet-wide `rbac_enabled` row lock (up to 2 s per lock wait). With the shared 16-connection default pool, a stuck lock holder plus 16 or more concurrent guarded requests can exhaust the pool; permission checks that miss the cache then fail their pool acquire, which can open the authorization breaker (`yuzu_server_rbac_breaker_open`) and deny cache-miss permission checks until it recovers. This is reasoned from the code, not measured. Watch `yuzu_pg_pool_waiters` and `yuzu_pg_acquire_wait_seconds` (the acquire histogram shows the pool filling; the lock wait itself is not in it) and `yuzu_server_rbac_lifecycle_store_failure_total{op}` (a request that timed out or lost its store). A bulk SCIM deprovision that fires many deactivations at once queues on the row lock rather than running in parallel; the queue is bounded by time, not by size, so a burst larger than the guarded writes can finish inside one 2000 ms window sees the tail time out. A request that times out answers `503`: the dashboard `DELETE` with `Retry-After: 2` and `retry_after_ms`, SCIM with `Retry-After: 2` (no body member), and the dashboard role change with **no** retry hint (it cannot tell a timeout from a lost commit acknowledgement, and a repeat after a commit is a `200` "Role unchanged" that does not redo the session wipe, so its message tells the operator to check the user's role and revoke the user's sessions). After a lock timeout nothing was committed, and the SCIM retry then runs the deprovision again; that is the only case in which a retry finishes the job. It does **not** converge after a lost commit acknowledgement (the retry meets the `404` of the role guard on the now-deactivated account, [#5214](https://github.com/Tr3kkR/Yuzu/issues/5214)), nor after a failed session wipe, nor for a SCIM `POST` with `active:false` (the account stays active and mapped, and the retry answers the userName `409`). The 503 detail says the account state may be indeterminate. The account is unchanged by a timeout, although its linked credentials were already revoked (see above), and the target's sessions are cleared as a precaution (the in-memory sessions, and the durable wipe is attempted too) because a lost commit acknowledgement cannot be ruled out. On the dashboard `DELETE`, a repeat after a failed session wipe re-runs the guarded write and the session wipe, and the repeat that completes answers `404` (the account is already deactivated). No alert rule ships for these series yet; tracked in #5673.
- **Upgrades.** A replica running a build without this rule does not enforce it. During a rolling upgrade drain the old replicas before relying on the guard. A server with an authentication database but no RBAC store does not start, and at runtime the same condition fails closed (the operation is refused as a store failure rather than performed unguarded). Direct SQL against `auth.users` is break-glass and outside the guarantee.
- **Not closed.** A grant inserted for the target account after the guard has locked that account's grant rows is not seen by that transaction; it lands on an account that is inactive once the transaction commits, which the grant population does not count.

**SCIM specifics.** SCIM only manages accounts whose role is `user`, so a SCIM deprovision is refused by the guard only on the grant population under enforcement on (the account holds the fleet's sole `Administrator` grant); every other role case is already a `404` from the provenance and role guard. The column population is reached from SCIM through group-derived demotion: when a group change would demote the last active admin account, the group operation itself succeeds, the account keeps its role, and the refusal is audited as `scim.user.last_administrator_refused` (the recompute re-runs only via another group the user belongs to, or a revive; a re-send of the same Group change never names a member already removed). A `409` does not prove that an identity provider stops retrying the request, so a refusal can recur whenever the role is recomputed again; the audit row and counter are written for every attempt, and only the server log line is limited to one warning per account per minute. Each refused group-derived demotion also raises the critical analytics event `scim.user.last_administrator_refused` (an IdP-demoted person keeps admin, so an operator has to act).

**Group role recompute: what is recorded when it is incomplete.** A Group create, replace, patch or delete recomputes the role of every affected member after the membership write has committed. The members the request REMOVES are recomputed first (they are the demotion candidates; a rename that flips the admin-group match makes the kept members candidates too), then the rest. Every **demotion** is attempted, because skipping one would leave an identity-provider-removed administrator holding the role with a `2xx` and no evidence. After the first failed guarded write (a lock wait that expired, an unavailable store) the remaining **promotions** are skipped, because each would wait out the same lock timeout and promotion is the fail-safe direction. A member whose **read** fails (the SCIM resource, its provisioning source, its group memberships or its current role) is *undetermined*: its role is left untouched and it is recorded, because it is then unknown whether an administrator the identity provider removed keeps the role. An account that no longer exists, is not SCIM-owned, or has no active row is a legitimate no-op and is not recorded.

Nothing is dropped silently:

- A **refused** demotion (the last-Administrator guard) writes the `scim.user.last_administrator_refused` audit row and counter, and the critical analytics event.
- A **failed** demotion (a store failure, or a role that applied but whose durable session wipe failed) writes the `scim.user.role_changed` failure row, increments `yuzu_scim_role_change_failures_total`, raises the critical analytics event `scim.user.role_demotion_incomplete` and a critical log line naming the user as an IdP-removed admin that retains or may retain privilege: an operator has to demote the account and revoke its sessions. The event fields `role_applied` and `session_wipe_failed` are each `true`, `false` or the string `"unknown"` (the guarded write may have committed and its outcome is not known); the failure audit row then carries `role_applied=unknown`. A failed **promotion** also counts as failed (it has no critical event).
- When anything was refused, failed, undetermined or skipped, the request also writes ONE audit row `scim.group.recompute_incomplete` (`result=partial`, `target_type` `Group`) with the member count and, per class, `refused=<n>`, `failed=<n>`, `undetermined=<n>` or `skipped_promotions=<n>` each followed by its `..._users=` list (up to 20 names, then `,+N more`; an undetermined member whose username could not be read is named `scim_id:<id>`). `yuzu_scim_group_recompute_skipped_total{cause}` counts the skipped promotions (`promotion`) and the undetermined members (`undetermined`).
- The Group `created` / `updated` / `deleted` success audit row carries `recompute=complete` only when every member was recomputed as intended, otherwise `recompute=incomplete`. The HTTP status of the Group request does not change (its membership write already committed).

**Known limits of the Group role recompute.** These are real gaps, tracked in #5673. Until then they are documented here rather than engineered around.

1. **Serialization is per process.** Group mutations are serialized within one server process. When more than one server replica runs, send SCIM provisioning traffic to a single replica. `POST /Groups` does not take the per-process group lock (`PUT`, `PATCH` and `DELETE` do).
2. **There is no reconcile, and a re-send does not reach a member who has already left the group.** A failed or refused write IS reported: the group's success row says `recompute=incomplete` and a `scim.group.recompute_incomplete` summary row names the members. But re-sending the same `PUT` or `PATCH` recomputes only the old and the current members of the group at that moment, so it re-derives skipped promotions and undetermined members that are still in the group and can never re-derive a member who has left it. A retried `DELETE` never reaches the recompute (the group is gone: `404`, or an idempotent `204`), and an identity provider's next sync sends no change for a member who is already out. For a **refused**, **failed** or **undetermined** demotion of a member who has left the group, demote the member by hand with `POST /api/settings/users/{username}/role` and `{"role":"user"}` (the dashboard has no role button. Make the call while signed in as an administrator other than the member, because a self-target answers `403` `self_role_change_blocked`. It needs a cookie session (an account with MFA enrolled also needs a fresh step-up: a proof older than `--mfa-step-up-window-secs`, default 300 s, answers `401` with `meta.mfa_step_up_required`, and a fresh password plus TOTP login counts; an account with no MFA enrolled is not challenged under the default `--mfa-enforcement=optional`; a SAML session gets `403`) or an administrator API token (`Authorization: Bearer` or `X-Yuzu-Token`), which is never challenged for step-up. For a refused one, a second active local administrator account has to exist first; see "If the guard refuses an action you intend" below, which also gives the break-glass exit when no administrator session can pass step-up); a later change that names the user through another group they belong to also re-derives their role. A skipped **promotion** is the exception: a re-send of a `PUT` or `PATCH` retries it while the member is in the group, a `DELETE` never can. *Crash breadcrumb:* once a `PUT`, `PATCH` or `DELETE` has committed the membership change and either removed at least one member or renamed the group so that the admin-group match flips (the rename changes the role of every current member), the server writes ONE log line at WARN level before the first role change and flushes the log right after it: `SCIM: Group scim_id=<id> membership change committed; role recompute starting for <N> removed member(s): <ids>[,+M more]`; when the rename flips the match the line ends `; the group rename changes the admin-group match and <K> current member(s) will be recomputed`, and the removed-members part is absent if nobody was removed. WARN is written at the default log level and at `--log-level warn`, not at `error` or `off`. It names the first 20 removed members by SCIM ID (not by username: it performs no store read, so a degraded store cannot delay it) and `<N>` is the exact count; it is not written by `POST` or by a change that removed nobody and did not flip the match of a group that still has members (an add-only change writes none, and neither does a flipping rename of an empty group; a re-send recovers it), and it is also written on the idempotent already-gone path of a `DELETE`, which is reachable only through a cross-process race. Without `--log-file` the line goes to stdout (with `--log-file`, to stderr and the file); journald and container logs capture both, and only the null-logger fallback writes to stderr directly. The flush precedes the recompute, so the line survives a `SIGKILL` once written to the sink in use (a file sink may still hold a copy that was not yet written; the copy the console stream already took is not lost), but not power loss or a kernel panic (there is no fsync); a failure to write it never blocks the recompute. Crash signature, by where the process stopped: before the membership commit, nothing changed; after the commit and before the breadcrumb, no record of the removed members (these two cannot be told apart by signature: a commit whose acknowledgement was lost also leaves nothing); mid-recompute, the breadcrumb (only when members were removed or the rename flips the match; an add-only change writes none and a re-send recovers) and the per-member rows written so far, with no summary row, no `recompute=` marker and no Group success row; after the recompute and before the Group success row, the breadcrumb (when one applies), the per-member rows and any summary row, roles as the recompute left them (read the summary row), and no Group success row. A failed final read of the group after the recompute looks the same: a `PUT` then writes a failure row with an empty detail and answers `500`, and a `PATCH` writes no row. Per-member rows written before a crash persist. After any unclean restart, compare the identity provider's admin-group membership with the Yuzu roles and demote the difference. To replace the ONLY administrator, add the new administrator in one Group change and remove the old one in a second; one change that does both demotes the old administrator first, the guard refuses (no other administrator exists yet) and the old administrator has to be demoted by hand.
3. **A large or slow request holds locks.** A Group request recomputes every affected member and can be slow on a large group or a slow store; the HTTP request and the per-process group lock (taken by `PUT`, `PATCH` and `DELETE`, not by `POST`) are held meanwhile. There is no time bound on the loop.
4. **A failed Group `POST` leaves an empty group.** If a `POST` fails after the group row is created, the empty group remains and a retry answers `409`.
5. **A deactivate request can answer `404`.** Deactivation of an account whose role is not `user` is refused with `404` until the role is corrected.
6. **`POST /Users` re-provision ignores the recompute result.** The revive path recomputes the one user but does not report an incomplete outcome; an undetermined result there leaves only a log line, with no audit row and no counter. The other revive paths (`PATCH` and `PUT` with `active:true`) do not recompute the group role at all, so an inactive member added to the admin group stays `user` until the next Group change (this predates the last-Administrator guard).
7. **A deactivation whose SCIM mirror write failed is not retried to convergence.** The auth account is already deactivated, the request answers `500`, the SCIM resource still reads `active=true`, and the identity provider's retry answers `404` (the role guard finds no active account), so the mirror stays stale until it is reconciled ([#5214](https://github.com/Tr3kkR/Yuzu/issues/5214), and the follow-up tracked in #5673). Every identity provider retry also hits the role guard: it answers `404`, writes a `scim.user.provenance_denied` audit row and increments `yuzu_scim_provenance_denied_total`, which drives the shipped `YuzuScimProvenanceDenied` alert (`increase(...[1h]) > 0`, severity warning): it fires, and stays firing while the retries continue. There is no hand remedy today (no route and no SQL statement is documented for it) until #5214 and #5673 land.

SCIM provisioning refuses, before creating or reactivating anything, a username whose deactivated record still carries a role other than `user` (`404`, nothing reactivated) and a username that already holds an `Administrator` grant (`404`, nothing created), because a SCIM account must never become a counted administrator. The same two checks apply to a `PATCH`/`PUT` with `active:true` on a deactivated resource (behavior change: such a request used to reactivate the account), answering `404` and `scim.user.provenance_denied`; if the tombstone's role cannot be read the answer is `500`, and if the grant read is unavailable it is `503`. SCIM can therefore deactivate the holder of an `Administrator` grant but cannot reactivate it until the grant is removed. Every such attempt increments `yuzu_scim_provenance_denied_total`, whose alert description calls it a compromised-IdP signal: this benign case also fires it. **Operator remedy.** An elevated tombstone cannot be re-enabled through SCIM or through the dashboard (an inactive account answers `404` at the role route, and the group recompute reads active rows only) until its role is cleared. For a tombstone with `role='admin'`, clear it with SQL (an inactive row is outside both protected populations, so this cannot strand anyone): `UPDATE auth.users SET role = 'user' WHERE username = '<name>' AND NOT is_active;`. Record the manual change in your change record: it bypasses the Yuzu audit log. For a username that holds an `Administrator` grant, the in-band exit is `unassign_rbac_role` (MCP `unassign_rbac_role`, or `DELETE /api/v1/rbac/roles/{name}/assignments/{principal_id}`), then let the identity provider retry. The `404` is not an existence-free answer: it tells the holder of the SCIM bearer, with no side effect, that the name holds an Administrator grant or an elevated deactivated record. These checks read the RBAC store, so SCIM provisioning needs it even with RBAC enforcement off; when the grant read is unavailable the request answers `503` with `Retry-After: 2` and nothing is created.

If a later step of a create fails, the undo of the just-created account goes through the same guard. When the undo does not complete, the request answers `500`, a `scim.user.compensation_failed` audit row, a critical analytics event and `yuzu_scim_compensation_failed_total{outcome}` are recorded, and an operator has to check the account; an identity provider retry does not converge by itself. What state the account is in depends on the outcome: after `guard_refused_last_administrator` it is left **active**; after `deactivated_but_session_wipe_failed` it is deactivated but a session may survive; after `store_failure` its state is indeterminate (it may be active or deactivated). A `POST` with `active:false` that is refused by the guard leaves the new account active and mapped.

**A refused deprovision leaves the person live.** When the guard refuses a SCIM deactivation or delete, the identity provider has terminated the person but this server has not: the account stays active. After an early refusal nothing was revoked, so the person's API tokens and sessions are also still live. After a late refusal the tokens and sessions were revoked, but the account remains active in Yuzu, so any credential the identity provider still accepts for it works. Either way the refusal is audited as `scim.user.last_administrator_refused` (always written; the critical analytics event of the same name is a no-op under `--no-analytics`, so key any notification on the audit action) and an operator has to act: have another account hold the `Administrator` grant (`assign_rbac_role`, or `POST /api/v1/rbac/roles/Administrator/assignments`; SCIM only deprovisions `role=user` accounts, so this refusal is always on the grant population and an account whose `role` column is `admin` does not unlock it) and let the identity provider retry (or repeat the delete), or revoke the person's API tokens and sessions by hand. The audit row records what the refusal left in place (`live_api_tokens_slug=<n>`, which counts the username's own tokens and not those of linked SSO identities, with `linked_principals_not_walked=true` beside it so a `0` is not read as "nothing live"; and `sessions_not_revoked=true` on an early refusal).

**If the guard refuses an action you intend.** There is one in-band route: make another local account an administrator first and repeat the operation. (The role change itself needs the calling account's own `admin` role: a session that is administrator only through a temporary elevation is refused with `403`.) The second administrator has to be an ACTIVE LOCAL account whose `role` is `admin`: the column population is what a demotion or a deactivation of a local admin account is refused on, so a grant alone, or an administrator who signs in only through SSO, does not unlock it. Create the account in Settings > User Management > Add User (the create call ignores `role`), then set the role with `POST /api/settings/users/{username}/role` and `{"role":"admin"}`. Granting a second account `Administrator` under RBAC enforcement helps only when the refusal was on the grant population (a refusal on the column population is unaffected by it); a refused SCIM deactivation or delete is always on the grant population, so for it a second ACTIVE LOCAL account must hold `Administrator` instead of a local `role=admin` account. Grant it BEFORE the identity provider removes the member, while some account already holds the grant (`assign_rbac_role`, or `POST /api/v1/rbac/roles/Administrator/assignments`). The route needs a caller who holds an Administrator grant and is a counted account, so when the member being removed is the only counted holder nobody else can make the grant, and after the refusal the exit is direct SQL, which bypasses the audit log like the other break-glass SQL here: `INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) VALUES ('user', '<active local username>', 'Administrator');`, then retry. An inactive or unknown principal does not unlock the retry (granting one through the API is accepted but is not counted). An SSO-only principal cannot be granted through the API; an active SSO-provisioned `auth.users` row granted by SQL is counted. To demote the member afterwards, call the same route with `{"role":"user"}` while signed in as the newly created second administrator, not as the member: a self-target answers `403` `self_role_change_blocked`. On the dashboard the **Change role** button on the Users and roles page makes this call; the call needs a cookie session (an account with MFA enrolled also needs a fresh step-up: a proof older than `--mfa-step-up-window-secs`, default 300 s, answers `401` with `meta.mfa_step_up_required`, and a fresh password plus TOTP login counts; an account with no MFA enrolled is not challenged under the default `--mfa-enforcement=optional`; a SAML session gets `403` at step-up, an OIDC session instead needs a fresh IdP MFA assertion by signing in through SSO again, and Add User itself has no step-up, so a sole administrator who signs in only through SAML cannot start this chain) or an administrator API token (`Authorization: Bearer` or `X-Yuzu-Token`), which is never challenged for step-up (see [`server-admin.md`](server-admin.md#changing-a-users-role)). If no administrator session can pass step-up, promote the break-glass account with the SQL in the "SSO-only fleets" note under "Enabling RBAC", arm it (run `yuzu-server --break-glass-user <name> --break-glass-arm` on the server host; the account is armed for `--break-glass-window-secs`, default 24 h, and the command exits without starting the server; see [`server-admin.md`](server-admin.md)), sign in as it and continue. Afterwards revert the break-glass account to its previous role and record the change in your change record. Under `--auth-mode=sso-only` only the armed break-glass account can sign in locally (a newly created administrator's `/login` answers `401`), so make the calls as the break-glass account itself, with its cookie session or an administrator API token it mints, instead of as a new account. When `--break-glass-user` is set, the server refuses to start under `sso-only` unless that account exists, is active and has MFA enrolled, even before it is armed (with no break-glass user configured it starts and no local account can sign in). The Two-factor sign-in panel (Settings > Security and sign-in) is admin-only, so enroll the break-glass account while it is an administrator, before switching to `sso-only`. Under `--mfa-enforcement admin-only` or `required` a sole administrator who has not enrolled cannot sign in until they enroll (enrolling counts as a fresh proof, so the chain can continue at once); sessions and API tokens that already exist are not affected, only new logins. Afterwards demote or remove the temporary local administrator, so that it does not remain as a standing credential. It cannot demote or delete itself (`403`, audited as `self_role_change_blocked` for a demotion and `self_delete_blocked` for a delete), so a permanent administrator account has to do it once one exists. If the member's role is already `user` and only the session wipe failed, the role call answers "Role unchanged" and does nothing else: revoke the sessions separately (Settings > User Management > Revoke sessions, or `DELETE /api/v1/sessions?username=<name>`, which also needs a fresh MFA step-up for a cookie session; under RBAC enforcement it additionally needs `UserManagement:Write`, held through an Administrator grant, so a `role=admin` account with no grant answers `403` `permission denied: UserManagement:Write` so the revoke must come from an account that holds an Administrator grant, while the role call needs the `admin` role). Administrators who sign in only through SSO are not recognized as members of a population until [#5182](https://github.com/Tr3kkR/Yuzu/issues/5182) lands, so an `sso-only` fleet whose only administrators are SSO identities is protected by its local break-glass account alone. Direct SQL against `auth.users` is break-glass and outside the rule. A guarded operation that keeps answering `503` is usually waiting on a lock holder that never finished. Run this in the Yuzu database (it lists only sessions of the current database that block others and are not themselves blocked, i.e. the root of the queue). Confirm the holder is stuck first (for example `idle in transaction` for far longer than the 2000 ms bound, an old `xact_age`; the 15 s idle bound releases an orphaned deactivation or local role change on its own, but NOT an orphaned role unassignment or enforcement toggle, which need this step) and that it is not a backup or migration session you want to keep, then end that one backend (a lock held by a prepared transaction has no backend: it is listed in `pg_prepared_xacts` and is ended with `ROLLBACK PREPARED '<gid>'` once you have confirmed it is not a two-phase commit you want):

```sql
SELECT a.pid, a.state, now() - a.xact_start AS xact_age, left(a.query, 120) AS query
FROM pg_stat_activity a
WHERE a.datname = current_database()
  AND cardinality(pg_blocking_pids(a.pid)) = 0
  AND EXISTS (SELECT 1 FROM pg_stat_activity w
              WHERE w.datname = current_database() AND a.pid = ANY (pg_blocking_pids(w.pid)));
-- then, for a confirmed stuck pid:  SELECT pg_terminate_backend(<pid>);
```

**Refusal volume.** Each refused request writes one audit row (`scim.user.last_administrator_refused` or the dashboard's `user.delete` / `user.role_change`), is counted, and, for a SCIM deprovision or a refused group-derived demotion, raises one critical analytics event (it is a no-op under `--no-analytics`; the audit row and the counter are written every time). Only the server log line is limited. An identity provider that keeps retrying a `409` therefore produces audit rows and events at its own retry rate; the rate is bounded only by the identity provider.

**Related, not covered.** Deactivating an account is not the same as revoking API tokens held for that username: a token-backed session can fall back to the `user` role when the account lookup finds nothing ([#5627](https://github.com/Tr3kkR/Yuzu/issues/5627)). The deprovision paths revoke tokens first for this reason.

### Scoped Role Assignments

Scoped role assignments bind a principal to a role within a specific management group. These are stored in the `ManagementGroupStore` (not in the RBAC principal_roles table) and are managed through the management group API:

```bash
# Assign a role scoped to a management group
curl -s -b cookies.txt -X POST \
  -H "Origin: http://localhost:8080" \
  http://localhost:8080/api/v1/management-groups/mg_london_office/roles \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane.doe",
    "role_name": "Operator"
  }'
```

## Tokens and principals page

The `/access/tokens` page shows and changes API tokens and engine principals. Its token list uses `ApiToken:Read` and is scoped to the caller's own tokens unless the caller is an administrator on a cookie session; an administrator's API, MCP or service-scoped token gets its own tokens only. The principal list and detail use `EnginePrincipal:Read`, the same permission as `GET /api/v1/engine-principals` (administrators only while RBAC is disabled; an ordinary grant once it is enabled): with RBAC on, an account administrator without that grant is refused and a non-administrator who holds it is admitted. Engine and MCP-tier credentials are refused whatever they hold. A refused browser session writes no audit row, because the panels load automatically. A revoked principal's free-text revocation detail comes from the audit trail and is shown only to callers who also hold `AuditLog:Read`; others see it marked withheld. The no-administrator check above the list also needs `AuditLog:Read` and is skipped, with a note, without it.

Which controls appear follows what the server will allow. With RBAC off, creating and revoking tokens and every principal change need an Administrator browser session (an API, MCP or service-scoped token never qualifies); rotating or confirming a rotation of your own token is open to any signed-in owner (the one self-service action). With RBAC on, the page asks the gate once per permission when it draws a panel: `ApiToken:Write`, `ApiToken:Delete`, `ApiToken:Rotate`, `Security:Write`, and `UserManagement:Read` before it lists custom roles for an engine principal's Assign control. These checks are quiet for a browser session (no denied-access audit row); the server still decides every action. Assigning a role to an engine principal offers custom roles only; built-in roles are refused for engine principals.

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
| `POST` | `/api/v1/rbac/roles/{name}/assignments` | Assign one of the 7 non-`ITServiceOwner` built-in roles to a human user, fleet-wide (A2) | Implemented |
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
