# Reachability probe: executions-list fragment and summarize_working_set (#3526, #4753)

Evidence record committed for the governance ledger, recorded in this change's governance ledger fragment.
It is the author-run evidence recorded against two external-review claims (not an independent refutation) that
`GET /fragments/executions` and MCP `summarize_working_set` kind=execution were confinement escapes before the
executions-list migration.

## Provenance and limits (read before relying on it)

- Run on 2026-10-04 (written up 2026-10-05) against the base `5698aff3b` (origin/dev at branch creation) with real Postgres stores
  (`YUZU_TEST_POSTGRES_DSN`), the real `AuthRoutes::require_permission` and `require_fleet_read`, the real
  `WorkflowRoutes`, `McpServer::build_handler` and `register_response_routes`. No mocks on the authorisation path.
- It was run by a subagent of the session that authored the migration, so it is an author-run probe. The author
  concurs with its conclusions; that is author concurrence only, not an independent adjudication.
- The JIT-elevated case was checked by code reading only. It was not probed empirically (it needs an elevated
  cookie session).
- No independent party has re-run the probe. The probe test is temporary and is NOT part of the test suite. This
  record keeps its source and raw results so a reviewer can re-run it. The committed, durable evidence of the
  behaviour AFTER the migration is `tests/unit/server/test_workflow_executions_list_authz.cpp`; the claim that the
  old gate disclosed nothing beyond what the unconfined v1 twin serves rests on this probe alone.
- Not covered by the probe: the owner disjunct of a service-scoped session. A service-scoped token's session
  username is its minter, so on the execution read surfaces that evaluate `dispatched_by == username` the token is
  also shown executions its minter dispatched, outside the service scope. Tracked in #5557.

## Files

- `3526-confinement-reachability-probe-2026-10-05.patch`: `git apply`-able patch adding the temporary probe test
  (`tests/unit/server/test_zz_confinement_probe.cpp` + `tests/meson.build` entry) to base `5698aff3b`.
- `3526-confinement-reachability-probe-2026-10-05.results.txt`: raw output of the run.

Re-run: apply the patch on a checkout of `5698aff3b`, build `tests/yuzu_server_tests`, then
`YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:15432/yuzu_test ./build-linux/tests/yuzu_server_tests "[confprobe]"`.

## Method

Real RbacStore, ManagementGroupStore, ApiTokenStore, TagStore, AuditStore, ExecutionTracker and ResponseStore
(Postgres clones); real `AuthRoutes::require_auth` / `require_permission` / `require_fleet_read` wired as `server.cpp`
wires them. Principals: `gary` holds GLOBAL `Execution:Read`, `Response:Read` and `Infrastructure:Read`. `bob` holds
global `Infrastructure:Read` only; `Execution:Read` and `Response:Read` only through a ManagementGroupStore assignment
on group G (agent `a_in`). `a_out` is in group O. Execution X1 fans out to `a_in` and `a_out`; X2 only to `a_out`
(error text `SECRET-OUT-ERR-X2`, dispatched by a third principal). Surfaces driven: `WorkflowRoutes`
`/fragments/executions`, `McpServer::build_handler` `tools/call summarize_working_set` kind=execution,
`response::register_response_routes` legacy `GET /api/responses/{id}` and `/aggregate`, and `RestApiV1` v1 twins as the
comparison oracle.

## Matrix (RBAC on unless stated)

| Principal | plain require_permission(Execution:Read) | require_fleet_read | (1) fragment | (2) MCP summarize execution | v1 GET /api/v1/executions | out-of-scope data via (1)/(2) |
|---|---|---|---|---|---|---|
| global (gary) | ADMIT | ADMIT-ALL | 200, all rows | 200, counts+oracle | 200, all rows (identical) | yes, but unconfined by design (#1715(b)); v1 returns the same |
| scoped-only (bob) | DENY 403 | SCOPED{a_in} | 403 | 403 (Execution:Read gate; first gate Infra:Read passed) | 200, only G rows, a_out hidden | no (denied) |
| service token (bob/gary, svc=printers) | DENY 403 (allow-list empty) | SCOPED{a_in} (v1 admits narrowed) | 403 | -32003 blanket deny (ServiceScopeClass default `denied`, mcp_server.cpp:3960 at the base) | 200 narrowed | no |
| MCP readonly/operator/supervised (bob) | DENY 403 | SCOPED | 403 | 403 at every tier | 200 confined | no |
| MCP readonly (gary) | ADMIT | ADMIT-ALL | 200 | 200 | same as v1 | unconfined by design |
| MCP + service (bob) | DENY | SCOPED | 403 | -32003 | 200 narrowed | no |
| engine, no grant | DENY 403 | DENIED | 403 | 403 (Infra:Read) | 403 | no |
| engine, global Execution:Read | ADMIT | ADMIT-ALL | 200 | 200 | same | unconfined by design (engine grants are fleet-wide only) |
| JIT-elevated | ADMIT (auth_routes.cpp:660 at the base) | TOP (authz_gates.cpp:62 at the base) | admit | admit | unfiltered | equal by code reading, NOT probed empirically |
| RBAC OFF: gary/bob/mcp-readonly(bob) | ADMIT | ADMIT-ALL | 200 all | 200 | 200 all (identical) | yes, identical to v1: RBAC-off is legacy-open by design |
| RBAC OFF: service token | DENY 403 | DENIED 403 | 403 | -32003 | 403 | no |

## Findings

1. With RBAC on, a principal the plain gate admits is always admitted by `require_fleet_read` as ADMIT-ALL:
   `check_permission` reads only `principal_roles` and group membership, never ManagementGroupStore assignments
   (rbac_store.cpp:2605, and the `collect_roles` path at :2660, at the base), and a global grant is unfiltered under
   `authorize_list_read` (#1715(b), rbac_store.cpp:3027 at the base). With RBAC off both gates are legacy-open. So the
   set the plain gate admitted is a subset of the set `require_fleet_read` admits unfiltered, and no probed principal
   was served anything by the fragment or the MCP tool that the v1 twin does not serve the same principal.
2. `/fragments/executions` was therefore not a reachable confinement escape for the probed principals. It was a
   capability gap (a confined-only operator could not use it) and a latent trap: if #2665 (a group DENY overriding a
   global ALLOW) lands, the plain-admit set stops being a subset of ADMIT-ALL.
3. MCP `summarize_working_set` kind=execution: same result. The tool is also already `ServiceScopeClass::denied`
   (default row, mcp_server.cpp:3960 at the base), so the service-scoped half is closed by the C8 chokepoint before
   the handler runs.
4. Legacy `GET /api/responses/{id}` and `/aggregate` are confined: the scope is pushed into the store query and the
   scoped principal never received `SECRET-OUT-OUTPUT`. The defect is audit only. A scoped principal produces only a
   `response.read` / `denied` row (`scope_dropped=1`), where the v1 twin also writes `response.read` / `success`; a
   global principal produces no audit row at all on the legacy route, even for a whole-fleet read; and when audit
   persistence fails the legacy route stays `200` with the data (fail-open) while the v1 twin returns `503`. The
   probe did not drive `/api/responses/{id}/export`. Tracked in #5556.
