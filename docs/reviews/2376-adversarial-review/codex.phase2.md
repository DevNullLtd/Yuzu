# Codex Phase 2 — cross-examination and revised review

## Peer cross-examination

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| F1 | false-positive/unfair | `server/core/src/auth_routes.cpp:689-710` and `server/core/src/rbac_store.cpp`'s `rbac_enforcement_in_effect`: a non-open non-null store makes the predicate true, enters the live-RBAC branch, and calls `check_permission`; it does **not** enter the legacy fallback. The comment's “this branch” means the immediately following live-RBAC branch. | none |
| F2 | false-positive/unfair | `server/core/src/auth_routes.cpp:250-318,573-588`; token sessions, including engines, are synthesized per request with a default-empty `elevated_until`, whereas `AuthManager::elevate_session` (`auth.cpp:569-594`) mutates only a server-held cookie session identified by its session token. The elevation REST route also rejects token sessions at `auth_routes.cpp:3038`. | none |
| F3 | false-positive/unfair | `server/core/src/rbac_store.cpp:275-299,293-357` shows unconditional construction-time `seed_defaults()` with `INSERT OR IGNORE`; `tests/unit/server/test_authz_topology_floor.cpp:354-429` removes the new rows from an existing DB, reopens it, and proves they return. I reran `[authz][floor]`: 11 pass, 1 PG skip, 99 assertions pass. | none |
| F4 | false-positive/unfair | This is a hypothetical audit request, not a located falsifiable defect. I independently audited alternate surfaces in Phase 1 and found the discovery bypass; commit `1103e418` now splits the representation at `discover_routes.cpp:56-116,403-426` and `mcp_server.cpp:9336-9363`. Targeted REST/MCP tests pass. | none |
| F5 | confirmed-independently | `authz_topology_floor.hpp` uses string entries, so the drift concern is real but explicitly accepted. Head adds a store-backed correspondence test at `test_authz_topology_floor.cpp:157-181`, which materially mitigates it. | LOW (judgment; resolved adequately) |
| F6 | confirmed-independently | `auth_routes.cpp:713-747` and `:913-948` duplicate the audit/metric/A4 legacy-floor denial body around the shared predicate. This is maintainability debt only; both copies are intentionally required by the routed-concern contract and current behavior agrees. | LOW (judgment) |
| F7 | disagrees | `auth_routes.cpp:664-686,845-885` omits an explicit `is_open()` precheck, but a dead store cannot grant authority: `check_role_has_permission` prepares against `db_`, and its failure path returns false. The concrete claim of undefined behavior or incorrect allow is unsupported; only the 403-vs-503 failure classification is inconsistent with the engine branch. | LOW (judgment), not MEDIUM |

### Peer coverage adopted or rebutted

- Security/privilege and correctness: adopted the peer's elevation, dead-store, legacy-ordering, and topology-surface questions, but independently rebutted F1/F2/F3/F4 and downgraded F7 from the actual implementations and tests above.
- Cross-component/schema: adopted the upgrade-path concern and falsified it empirically; unconditional idempotent reseeding is both documented and tested.
- Maintainability: adopted F5/F6 as LOW judgment risks; F5 is now covered by a store-backed test, while F6 remains harmless duplication.
- Resource/concurrency and portability: the peer skimmed these, as did I after inspecting all changed TUs. The fix introduces no resource owner, raw handle, thread, synchronization, platform branch, or ABI/schema change. Linux compilation passed; no Windows/macOS environment was available.
- Test adequacy: the peer said it was unverifiable because it did not inspect tests. I inspected and ran the relevant suites. The new tests verify body omission/presence, but miss authorization-sensitive cache headers, which produced CDX-P2-002 below.

## Revised findings

[CDX-P1-001]  withdrawn · formerly HIGH · CONFIDENCE(hi) · PROVENANCE(test-run)
The A2 permission-discovery twins bypass the topology floor and disclose the complete RBAC role graph
- Location:  `server/core/src/discover_routes.cpp:56-116,403-426`; `server/core/src/mcp_server.cpp:9336-9363`
- Claim:     Withdrawn: commit `1103e418` probes `UserManagement:Read` on both twins, excludes `roles` when denied, and explicitly emits `roles_omitted` plus a reason while retaining the taxonomy under `Infrastructure:Read`.
- Evidence:  The builder only traverses `list_roles()`/`get_role_permissions()` inside `if (include_roles)` (`discover_routes.cpp:90-116`); both handlers derive that flag from a `UserManagement:Read` permission probe. `[discovery][permissions]` passed 88 assertions and `[mcp][integration][discovery]` passed 58 assertions, including denied and allowed representations.
- Scenario:  The Phase-1 RBAC-off ordinary-user sequence now receives taxonomy plus an explicit omission, not the protected role grid.
- Inference: The requested bypass is fixed at the application authorization layer with REST/MCP parity.
- Anchor:    `docs/auth-architecture.md` “The authorization topology floor (#2376)”; `docs/agentic-first-principle.md` A1–A2.
- Fix:       None for the original defect; see CDX-P2-002 for the cache-layer hole introduced by the conditional representation.
- Falsifier: N/A (withdrawn).

[CDX-P2-002]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run) · new-from-cross-exam
The permission-dependent REST catalog is publicly cacheable, allowing a privileged role grid to be replayed to an unprivileged caller
- Location:  `server/core/src/discover_routes.cpp:40-49` (shared `serve_doc`), affecting `/api/v1/discover/permissions` at `:403-426`; missing assertion in `tests/unit/server/test_discovery_routes.cpp:209-248`
- Claim:     The fixed REST endpoint emits two representations selected by `UserManagement:Read`, but marks both `Cache-Control: public, max-age=300` without a cache-key variance or private/no-store directive, so a conforming shared cache may serve the privileged role grid to a later unprivileged request for the same URL without reaching the permission probe.
- Evidence:  `serve_doc` unconditionally sets `Cache-Control` to `public, max-age=300` at line 44. `build_permissions_catalog(..., true)` includes `roles[].permissions[]` at lines 90-104, while `false` omits it at lines 105-115. The route URL and method are identical for both callers. The targeted test run passed, and inspection of the denied/present tests (`test_discovery_routes.cpp:209-248`) shows they assert only origin responses and never assert a private/no-store cache policy or simulate a shared cache.
- Scenario:  An Administrator or live-RBAC `UserManagement:Read` holder requests `GET /api/v1/discover/permissions` through a reverse proxy/CDN that honors `public, max-age=300` → the proxy stores the full role grid under that URL → an authenticated ordinary user requests the same URL within five minutes → the proxy returns the cached privileged body without contacting Yuzu, bypassing the new probe.
- Inference: HTTP shared caches normally key on method/URL plus declared `Vary` dimensions, not the server-side authorization decision; `ETag` does not partition an already-fresh public response. Whether a particular deployment currently installs such a cache does not make the response's explicit public-cache contract safe.
- Anchor:    CONTRACT — `docs/auth-architecture.md` “The authorization topology floor (#2376)” requires the RBAC role graph to require admin in the RBAC-off legacy posture; `.claude/routed-concerns.md` “Authorization-topology floor (#2376)” calls bypass of the floor catastrophic; the change's own `docs/security-reviews/authz-topology-floor-2026-08-05.md` defines the role/grant graph as protected topology.
- Fix:       Make `/api/v1/discover/permissions` authorization-dependent responses `Cache-Control: private, no-store` (simplest), or split taxonomy and role grid onto separately authorized URLs with safe cache contracts; add a regression assertion that the conditional response is never publicly cacheable. Do not rely on `Vary: Authorization` alone because cookie-authenticated sessions also select the representation.
- Falsifier: An enforced deployment invariant proving no shared cache can ever store or reuse this response, or an origin response on head showing the role-bearing representation has `private`/`no-store` (or an equivalent cache key that varies on every supported credential/session identity).

[KIMI-F6]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
Legacy floor denial plumbing is duplicated between global and scoped permission gates
- Location:  `server/core/src/auth_routes.cpp:713-747` and `:913-948`
- Claim:     The audit, metric, and A4 denial construction is duplicated, creating a future drift risk although current behavior is consistent.
- Evidence:  Both blocks independently construct the same `floored` reason, increment `yuzu_auth_topology_floor_denied_total`, and emit `admin role required`; only the audit action/agent id differ.
- Scenario:  A later observability or envelope change updates one branch but misses the other, making global and scoped topology denials inconsistent.
- Inference: This is maintainability debt, not a present authorization bypass; the shared `topology_floor_applies()` still preserves the single policy set.
- Anchor:    judgment.
- Fix:       Extract a small shared helper for legacy topology-floor denial emission while retaining calls in both legacy branches.
- Falsifier: N/A (non-blocking).

## Delta since Phase 1

- The original discovery bypass is verified fixed and CDX-P1-001 is withdrawn.
- Cross-examination rejects peer F1–F4, confirms F5/F6 as LOW judgment concerns, and downgrades F7 to a non-blocking response-classification inconsistency.
- The fix creates an authorization-varying REST representation but retains `Cache-Control: public`; this is a new HIGH cache-mediated bypass and keeps my verdict at BLOCK.
- Targeted compilation and all relevant non-PG tests pass; the missing cache-policy test is the remaining empirically identified coverage gap.

VERDICT:  BLOCK — commit `1103e418` fixes the origin-handler bypass, but its privileged and unprivileged REST representations remain publicly cacheable under one URL, allowing the protected role grid to cross authorization boundaries through a shared cache.
COVERAGE: Went deep on security/privilege, every peer finding, discovery fix semantics, HTTP cache behavior, RBAC branch ordering, engine/elevation lifecycle, upgrade reseeding, REST/MCP parity, schema/contract consistency, and targeted tests. Resource/concurrency and portability were inspected but necessarily shallow because the fix adds no owners, threads, handles, platform branches, schema, or ABI; Linux compiled, while Windows/macOS toolchains were unavailable. Test adequacy was deep for changed suites and exposed the cache-header omission. I did not rerun the broad server suite because Phase 1 already found unrelated/PG-environment failures and Phase 2's changed head was fully exercised by the targeted suites.
RAN:      `meson compile -C build-linux yuzu_server_tests` — PASS; `build-linux/tests/yuzu_server_tests '[authz][floor]' --reporter compact` — 11 passed, 1 PG-dependent skipped, 99 assertions passed; `[discovery][permissions]` — 5 passed, 88 assertions passed; `[mcp][integration][discovery]` — 6 passed, 58 assertions passed; `git diff --check c686f31a..HEAD` — PASS. CI status: UNKNOWN/no network query attempted in Phase 2; Phase 1's `gh pr checks 2376` could not reach GitHub. No linter/type checker applies separately to these C++ TUs beyond the warning-enabled Meson compile. No Windows/macOS toolchain was available.
FILES:    `/tmp/yuzu-advrev-2376-authz-floor/{codex,kimi}.phase1.md`; `.codex/skills/auth-and-authz/SKILL.md`; `docs/workstreams.md`; `CLAUDE.md`; `.claude/routed-concerns.md`; `docs/auth-architecture.md`; `docs/authz-model.md`; `docs/adr/0017-management-group-confinement-list-reads.md`; `docs/adr/0033-access-control-spine.md`; `docs/security-reviews/authz-topology-floor-2026-08-05.md`; `docs/agentic-first-principle.md`; all paths in `git diff --name-only c686f31a..HEAD`, with particular reinspection of `server/core/src/auth_routes.cpp`, `authz_topology_floor.hpp`, `rbac_store.{hpp,cpp}`, `discover_routes.{hpp,cpp}`, `mcp_server.cpp`, and `tests/unit/server/test_{authz_topology_floor,discovery_routes,mcp_server}.cpp`; `server/core/src/auth.cpp` and engine-token synthesis/lifecycle portions of `auth_routes.cpp` for peer F2.
