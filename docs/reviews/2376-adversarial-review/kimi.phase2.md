## Phase 2 cross-examination

### 1. Cross-examine `codex`’s findings

| PEER-ID | label | evidence I checked (file:line) | my severity |
|---|---|---|---|
| CDX-P1-001 | `disagrees` — builder fixed; `not-verified` at call sites | `build_permissions_catalog()` body in context: `if (include_roles)` block emits the grid, else sets `roles_omitted = true`. No REST handler or MCP handler code is shown, so I cannot see how `include_roles` is derived. | **HIGH** if the handlers still pass `include_roles=true` while only gating on `Infrastructure:Read`; **MEDIUM** as a verification gap on the claimed-fixed head. |

`codex` correctly identified the bypass in the pre-fix code. The function-level fix is real: the role grid is now behind an explicit `include_roles` flag and the no-roles path emits `roles_omitted` rather than silently returning an empty `roles` array. What `codex` did **not** verify in this bundle is whether **both call sites** actually derive `include_roles` from a live `UserManagement:Read` permission probe. That is the only remaining place the bypass can reappear.

### 2. Adopt or rebut `codex`’s coverage

- **Resource/concurrency/lifetime:** adopt. The changed builder only constructs local `json` objects and `std::move`s them; no new locks, handles, threads, or ownership edges.
- **Portability:** adopt. No platform-specific code changed.
- **Test-run evidence:** cannot adopt. I have no toolchain or test output; `codex`’s note that `[discovery][permissions]` passed before the fix actually confirmed the weak gate, not the fix.
- **Surface coverage:** partially rebut. `codex` audited the one builder but did not show a complete route/MCP inventory; other discovery surfaces remain unaudited in this context.

### 3. Defend / withdraw my own Phase-1 findings

- **F1** — **withdrawn.** Orchestrator refuted it: the comment attaches to the RBAC branch, and a dead store enters that branch and denies.
- **F3** — **withdrawn.** Orchestrator refuted it: `seed_defaults()` runs on existing databases and an upgrade test exists.
- **F5** — **withdrawn.** A new test now asserts every floored pair exists in the store’s own lists.
- **F2 / F6 / F7** — **withdrawn as #2376 blockers.** The `require_permission` / `require_scoped_permission` source is **not present** in the Phase 2 context, so I cannot re-verify them on head. They are pre-existing and not introduced by this diff; they should not block this change. If the engine-principal floor is the change’s security boundary, F2 is a serious follow-up, but not a #2376 merge blocker on the evidence shown.
- **F4** — **revised and retained** as a surface-audit gap: the context still only shows one builder, so other topology-emitting surfaces are unverified.

---

## Revised finding list

[F1] **WITHDRAWN** — refuted; comment attaches to the RBAC branch, and a dead store fails closed there.

[F2] **WITHDRAWN** — pre-existing elevation-ordering issue; `require_permission` source absent from Phase 2 context; not introduced by #2376.

[F3] **WITHDRAWN** — refuted; `seed_defaults()` runs on existing DBs and the upgrade path is tested.

[F4-rev]  LOW · CONFIDENCE(lo) · PROVENANCE(static-read)  
Other discovery surfaces that emit authorization topology remain unaudited  
- Location: REST route table / MCP tool table (not shown in context)  
- Claim: The provided context only proves `build_permissions_catalog()` was split; it does not show a complete inventory of discovery routes/MCP tools, so another surface could still return the role grid or engine-principal grant graph under a non-floored securable.  
- Evidence: Only `build_permissions_catalog()` and `seed_defaults()` are shown; no route/MCP handler call sites or OpenAPI/MCP schema are included.  
- Scenario: A caller holding only `Infrastructure:Read` or `Security:Read` invokes a different discovery tool that still emits `roles[].permissions[]`; the floor never fires.  
- Inference: The fix is local to one builder; a topology audit of all discovery surfaces is still needed.  
- Anchor: `docs/auth-architecture.md` — “The authorization topology floor”  
- Fix: Publish the complete REST/MCP discovery inventory and assert every topology-emitting surface uses a `kTopologyFloor` securable.  
- Falsifier: Complete list of all REST routes and MCP tools showing none emit authorization topology except under `AccessReview:Read`, `UserManagement:Read`, or `EnginePrincipal:Read`.

[F5] **WITHDRAWN** — addressed by new test asserting every floored pair exists in the store’s `list_securable_types()` / `list_operations()`.

[F6] **WITHDRAWN** — pre-existing duplication in `require_scoped_permission`; not introduced by #2376; source absent from Phase 2 context.

[F7] **WITHDRAWN** — pre-existing service-scoped token branch predicate; not introduced by #2376; source absent from Phase 2 context.

[KIM-P2-001]  HIGH · CONFIDENCE(lo) · PROVENANCE(static-read)  
`include_roles` call-site gating is the only thing preventing the bypass and is not shown  
- Location: `discover_routes.cpp` and `mcp_server.cpp` call sites of `build_permissions_catalog()` (not in Phase 2 context)  
- Claim: The builder now correctly omits the role grid when `include_roles==false`, but if either REST or MCP handler passes `true` while only requiring `Infrastructure:Read`, the exact bypass `codex` found returns.  
- Evidence: `build_permissions_catalog()` body: `if (include_roles) { ... roles grid ... } else { body["roles_omitted"] = true; ... }`. No handler code is provided.  
- Scenario: RBAC-off default install; ordinary `user` calls `/api/v1/discover/permissions` or MCP `discover_permissions`; handler gates on `Infrastructure:Read` and passes `include_roles=true`; response contains every built-in/custom role and permission/effect.  
- Inference: The function-level split is necessary but not sufficient; both callers must derive `include_roles` from a live `UserManagement:Read` permission check.  
- Anchor: `docs/auth-architecture.md` — “The authorization topology floor”; `.claude/routed-concerns.md` — authorization-topology-floor row; `docs/agentic-first-principle.md` A2  
- Fix: Show both call sites; ensure they pass `include_roles = check_permission(..., "UserManagement", "Read")` and add RBAC-off ordinary-user denial tests for both twins.  
- Falsifier: The actual call-site snippets showing `include_roles` is set only after a successful `UserManagement:Read` probe.

[KIM-P2-002]  MEDIUM · CONFIDENCE(lo) · PROVENANCE(static-read)  
REST/MCP parity of the `include_roles` split is unverified  
- Location: REST handler in `discover_routes.cpp` and MCP handler in `mcp_server.cpp` (not shown)  
- Claim: A1/A5 require REST/MCP parity. If one twin implements the split and the other does not, the bypass persists on the weaker surface.  
- Evidence: Only the shared builder is shown; no handler code.  
- Scenario: MCP `discover_permissions` passes `include_roles=true` unconditionally while REST correctly gates; an MCP caller reads the full grid.  
- Anchor: `docs/agentic-first-principle.md` A1/A5  
- Fix: Verify both handlers use identical permission probes and identical `include_roles` derivation.  
- Falsifier: Side-by-side handler snippets for REST and MCP showing identical gating.

[KIM-P2-003]  LOW · CONFIDENCE(med) · PROVENANCE(static-read)  
`seed_defaults()` silently ignores SQLite errors for the new `EnginePrincipal` securable  
- Location: `rbac_store.cpp` `seed_defaults()` securable-type loop  
- Claim: `sqlite3_prepare_v2`, `sqlite3_bind_text`, `sqlite3_step`, and `sqlite3_finalize` return codes are not checked. If the database is read-only or corrupt, the new `EnginePrincipal` securable is not inserted and no error is propagated, breaking RBAC-on engine-principal reads.  
- Evidence: Loop code: `sqlite3_prepare_v2(...); sqlite3_bind_text(...); sqlite3_step(s); sqlite3_finalize(s);` — no `SQLITE_DONE`/`SQLITE_ROW` checks.  
- Scenario: Upgrade on a read-only or corrupted `rbac.db`; `EnginePrincipal` type missing; admin denied `EnginePrincipal:Read`.  
- Inference: Pre-existing pattern for all securables, but the new securable is equally exposed. Not introduced by this diff.  
- Anchor: `docs/adr/0033-access-control-spine.md` (schema evolution consistency)  
- Fix: Check return codes or use the existing higher-level store API that does.  
- Falsifier: Show that `seed_defaults()` is wrapped in a transaction with error handling, or that the store open path already fails fast before seeding.

[KIM-P2-004]  LOW · CONFIDENCE(lo) · PROVENANCE(static-read)  
`roles_omitted` response shape is not shown to be documented in the discovery schema  
- Location: OpenAPI/MCP schema files (not shown)  
- Claim: The response now has two mutually exclusive shapes (`roles` array vs `roles_omitted` + reason). If the schema only documents `roles`, clients may misparse.  
- Evidence: Builder adds `roles_omitted` and `roles_omitted_reason`; no schema file shown.  
- Scenario: An agentic worker receives `roles_omitted:true` but its generated client expects `roles` array and crashes or reports the fleet has no RBAC roles.  
- Inference: Minor contract/documentation gap.  
- Anchor: `docs/agentic-first-principle.md` A2  
- Fix: Update the discovery schema/OpenAPI and MCP tool result schema to mark `roles` optional and document `roles_omitted`.  
- Falsifier: Schema files showing `roles` as optional and `roles_omitted` documented.

---

### Answers to the four attack questions

1. **Does any OTHER discovery route leak topology under a non-floored securable?** — Cannot tell; no route/MCP inventory is shown. Retained as F4-rev.  
2. **Can the probe itself mislead?** — No probe implementation is shown; not inspectable in this context.  
3. **Is `roles_omitted` honest?** — Yes at the builder level: when `include_roles==false`, no role name, description, `is_system`, or permission grid is emitted. The only inference is that the server has roles, which is already implied by the endpoint’s existence.  
4. **F2 / F6 — still block?** — No. Both are pre-existing and not introduced by #2376; the relevant source is absent from Phase 2 context, so I withdraw them as blockers for this change.

---

VERDICT:  BLOCK — the builder-level split is correct, but the `include_roles` call-site gating on both REST and MCP twins is security-critical and not shown in the Phase 2 context; the bypass reappears if either caller passes `true` under `Infrastructure:Read`.

COVERAGE:  
- security/privilege: deep — evaluated the builder split, call-site gating gap, REST/MCP parity, and seed idempotency.  
- correctness/logic: deep — builder conditional, `roles_omitted` honesty, SQLite error handling.  
- resource & concurrency safety: skimmed — no new threads/locks/handles in the shown code; local JSON moves only.  
- cross-platform/portability: skimmed — no platform-specific changes.  
- cross-component & schema/contract consistency: deep — A2 discovery schema, REST/MCP parity, floor contract.  
- test adequacy: unverifiable — no test files were included in the Phase 2 context.

FILES:  
- `rbac_store.cpp` `seed_defaults()` source  
- `discover_routes.cpp` / `mcp_server.cpp` `build_permissions_catalog()` body (call sites not shown)  
- Phase-1 reviews (own and codex)

DELTA-SINCE-PHASE-1:  
Withdrew F1, F3, and F5 after refutation/addressal; withdrew F2, F6, and F7 because the relevant `require_permission` source is absent from Phase 2 context and they are pre-existing. Retained F4 as a surface-audit gap and added KIM-P2-001/002 focused on the actual fix: unverified `include_roles` call-site gating and REST/MCP parity are the remaining risks.
