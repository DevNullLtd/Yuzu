# Reachability probe: executions-list fragment and summarize_working_set (#3526, #4753)

Evidence record committed for the governance ledger (`governance.d/3526-execution-surface-confinement.*.jsonl`).
It backs the `refuted` disposition of two external-review claims that `GET /fragments/executions` and MCP
`summarize_working_set` kind=execution were confinement escapes (CRITICAL I1/E2/E4) BEFORE this PR.

## Provenance and limits (read before relying on it)

- Run on 2026-10-04 against the base `5698aff3b` (origin/dev at branch creation) with real Postgres stores
  (`YUZU_TEST_POSTGRES_DSN`), the real `AuthRoutes::require_permission` and `require_fleet_read`, the real
  `WorkflowRoutes`, `McpServer::build_handler` and `register_response_routes`. No mocks on the authorisation path.
- It was run by a Sonnet subagent of the SAME session that authored this PR. It is therefore NOT independent
  of the author. Independent confirmation is limited to two reviewers who read the code (security-guardian
  Gate 2 and unhappy-path Gate 4, round 1); neither re-ran the probe.
- The probe test is temporary and is NOT part of the test suite. This record keeps its source and raw results
  so a reviewer can re-run it. The committed, durable evidence of the POST-change behaviour is
  `tests/unit/server/test_workflow_executions_list_authz.cpp`; the pre-change unreachability is carried by this
  probe only.
- The author (git author of this branch) concurs with the refutation (2026-10-05). That is author
  concurrence, NOT an adjudication: Gate 7 excludes the author as adjudicator, and `adjudicated_by` is left null.

## Files

- `3526-confinement-reachability-probe-2026-10-05.patch`: `git apply`-able patch adding the temporary probe test
  (`tests/unit/server/test_zz_confinement_probe.cpp` + `tests/meson.build` entry) to base `5698aff3b`.
- `3526-confinement-reachability-probe-2026-10-05.results.txt`: raw output of the run.

Re-run: apply the patch on a checkout of `5698aff3b`, build `tests/yuzu_server_tests`, then
`YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:15432/yuzu_test ./build-linux/tests/yuzu_server_tests "[confprobe]"`.

## Notes recorded by the probe run

# Step 0 reachability probe: execution-surface confinement (#3526 / #4644)

Worktree /home/dgr/yuzu-confinement (fix/3526-execution-surface-confinement @ 5698aff3b). Nothing committed; git status clean.
build-linux/ was configured in the worktree (git-ignored) and is reusable (`ninja -C build-linux -j 2 tests/yuzu_server_tests`).

## Artifacts
- confinement-probe.patch  (tests/meson.build hunk + new tests/unit/server/test_zz_confinement_probe.cpp). Re-apply with `git apply`.
- test_zz_confinement_probe.cpp (copy)
- probe-results-full.txt   (raw output of all 4 probe TEST_CASEs)
- Run: `YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:15432/yuzu_test ./build-linux/tests/yuzu_server_tests "[confprobe]"`

## Rig (real chokepoint, no mocks)
Real RbacStore + ManagementGroupStore + ApiTokenStore + TagStore + AuditStore + ExecutionTracker + ResponseStore (Postgres clones);
real AuthRoutes::require_auth / require_permission / require_fleet_read wired as server.cpp does (~14855 perm_fn, ~11757 fleet_read adapter).
Principals: gary = GLOBAL Execution:Read + Response:Read + Infrastructure:Read. bob = global Infrastructure:Read only; Execution:Read and
Response:Read ONLY via ManagementGroupStore assignment on group G (agent a_in). a_out is in group O. X1 fans out to a_in+a_out; X2 only a_out
(error text "SECRET-OUT-ERR-X2", dispatched_by carol). Surfaces driven: WorkflowRoutes /fragments/executions (TestRouteSink), McpServer.build_handler
tools/call summarize_working_set kind=execution, response::register_response_routes legacy routes, RestApiV1 v1 twins as the comparison oracle.

## Matrix (RBAC ON unless stated)
| Principal | plain require_permission(Execution:Read) | require_fleet_read | (1) fragment | (2) MCP summarize execution | v1 GET /api/v1/executions | out-of-scope data via (1)/(2) |
|---|---|---|---|---|---|---|
| global (gary) | ADMIT | ADMIT-ALL | 200, all rows | 200, counts+oracle | 200, all rows (identical) | yes, but unconfined by design (#1715(b)); v1 returns same |
| scoped-only (bob) | DENY 403 | SCOPED{a_in} | 403 | 403 (Execution:Read gate; first gate Infra:Read passed) | 200, only G rows, a_out hidden | no (denied) |
| service token (bob/gary, svc=printers) | DENY 403 (allow-list empty) | SCOPED{a_in} (v1 admits narrowed) | 403 | -32003 blanket deny (ServiceScopeClass default `denied`, mcp_server.cpp:3960) | 200 narrowed | no |
| MCP readonly/operator/supervised (bob) | DENY 403 | SCOPED | 403 | 403 at every tier | 200 confined | no |
| MCP readonly (gary) | ADMIT | ADMIT-ALL | 200 | 200 | same as v1 | unconfined by design |
| MCP + service (bob) | DENY | SCOPED | 403 | -32003 | 200 narrowed | no |
| engine, no grant | DENY 403 | DENIED | 403 | 403 (Infra:Read) | 403 | no |
| engine, global Execution:Read | ADMIT | ADMIT-ALL | 200 | 200 | same | unconfined by design (engine grants are fleet-wide only) |
| JIT-elevated | ADMIT (auth_routes.cpp:660) | TOP (authz_gates.cpp:62) | admit | admit | unfiltered | equal by code reading, NOT probed empirically (needs elevated cookie session) |
| RBAC OFF: gary/bob/mcp-readonly(bob) | ADMIT | ADMIT-ALL | 200 all | 200 | 200 all (identical) | yes, identical to v1: RBAC-off is legacy-open by design |
| RBAC OFF: service token | DENY 403 | DENIED 403 | 403 | -32003 | 403 | no |

Invariant proved: with RBAC on, plain-admit => check_permission true (rbac_store.cpp:2605; reads ONLY principal_roles + group_members, never
ManagementGroupStore assignments; rbac_store.cpp:2660 collect_roles) => authorize_list_read returns AdmitAll via #1715(b) (rbac_store.cpp:3027).
With RBAC off both are legacy-open AdmitAll. So {plain-admit} is a subset of {AdmitAll}: there is no principal for whom the plain gate admits
and the confined gate would have narrowed. The fragment/MCP return exactly what the v1 twin returns for the same principal.
test_response_execution_authz_pg_helper.hpp:42-52 already documents this ("require_permission ... never joins management-group assignments").

## Legacy responses (item 3), audit asymmetry (probe case 3)
Both legacy routes ARE already confined (gate.scope pushed into the store query; bob never receives SECRET-OUT-OUTPUT). The defect is audit only:
- bob (scoped): legacy writes ONLY `response.read/denied scope_dropped=1`; v1 writes denied + `response.read/success`.
- gary (global): legacy writes NO audit row at all, even for a whole-fleet read; v1 writes success.
- audit persistence failing: legacy stays 200 with the data (fail-open, (void) calls); v1 returns 503 with no body.
Same shape on /api/responses/{id}/export on this base (export fix lives only on the hardening branch).

## Verdicts
1. /fragments/executions: UNREACHABLE as a confinement escape today (probe: scoped-only principal 403; every admitted principal gets what v1 gives).
   It is a CAPABILITY gap (a confined-only operator cannot use it) plus a LATENT trap: if #2665 (global ALLOW overridden by group DENY) lands,
   plain-admit stops being a subset of AdmitAll and this becomes live. Derived band today: I9/INFO (defence in depth, status verified for the
   unreachability, likely for the latent trigger). Capability gap: I6/I8 (not a security finding).
2. MCP summarize_working_set kind=execution: same, UNREACHABLE today. Extra fact the kickoff misses: tool is already ServiceScopeClass::denied
   (default 2-element row, mcp_server.cpp:3960), so the service-scoped half is closed by the C8 chokepoint before the handler runs.
3. Legacy /api/responses/{id} + /aggregate success audit: REACHABLE (verified). TRIGGER any principal with Response:Read (global or group-scoped).
   IMPACT I1 (audit control does not hold: behavioural response output served with no durable success evidence, fail-open on audit failure,
   while v1 twins are fail-closed). EXPOSURE E3 (authenticated within own privilege; NOT E2: the actor never exceeds its privilege). Derived
   HIGH (BLOCKING) unless adjudicated that frozen legacy routes are exempt (the v1 openapi text calls the legacy route "frozen reference code").

## Smallest honest fixes
- Item 3: mirror the v1 twins in response_routes.cpp: emit_behavioral_audit success row AFTER the read, 503 + Sec-Audit-Failed + no body on
  failure, same verb/target (response.read / Execution / instruction_id), keep the existing denied row but make it fail-closed too.
  Mechanical; rebase conflict with the hardening branch is confined to the same three call sites.
- Items 1/2 (only if the architect wants the forward-compatible hardening): fragment: swap perm_fn for deps.fleet_read_fn, reuse
  execution_visible/confined_projection, redact last_error_detail, see rest_api_v1.cpp:8881-8973 (copy the pattern, do not fork a helper; the
  drawer detail route in the same file already does this). MCP: keep ServiceScopeClass denied; either keep the plain gate (unreachable) or move
  kind=execution onto fleet_read_fn_ with confined_projection counts and an identical not-found response for an invisible execution.
  NOTE: migrating ADMITS scoped-only principals that today get 403, so it is a capability widening that needs its own review, not a pure fix.

## Decisions only user/architect can make
1. Do items 1/2 ship at all? Evidence says no live gap; shipping them widens admission (scoped-only principals newly admitted) and is a product call.
   If #2665 deny-precedence is scheduled, they become mandatory at that point.
2. Item 3: are frozen legacy routes in scope for the fail-closed audit (derived HIGH) or exempt by ADR-1005 "frozen"? And fail-open vs fail-closed on the legacy denied row.
3. If item 2 is migrated: ServiceScopeClass stays `denied` (no new mechanism needed) vs `confined` (needs the real fleet_read mechanism, clause 3).
4. Whether to reword the "real, documented confinement gap" comments (rest_api_v1.cpp:8821-8830, openapi 1216) and the tracked-gap lists
   (auth-architecture.md ~2863/2875/2877, mcp-server.md ~55, rbac.md ~180-184) to "capability gap, latent trap" if items 1/2 are rejected.

## Kickoff file inaccuracies
- Line refs stale: fragment handler is workflow_routes.cpp:161-end (comment at 140); summarize_working_set is mcp_server.cpp:19477-19579 (19568-19640 is list_issued_certs).
- "Drive the REAL require_fleet_read as test_rest_executions_v1_twins.cpp does after 65cb5838c": on this base that file uses a FAKE fleet_read lambda
  (perm_grant / fleet_read_scope); 65cb5838c exists only on fix/4644-4703-response-routes-hardening. Real-chokepoint precedents here:
  tests/unit/server/test_legacy_executions_scope_authz.cpp + test_response_execution_authz_pg_helper.hpp (ResponseExecutionAuthzPgRig),
  and test_authz_gates.cpp GatesRig (what the probe copies).
- Omits that summarize_working_set is already service-scope `denied`.
- Legacy /export is also unfixed on this base; kickoff scope names only GET + aggregate (export fix is on the hardening branch).
- "Sol: CRITICAL I1/E2" is refuted by probe for (1)(2): E2 requires acting beyond starting privilege; no such actor exists.
