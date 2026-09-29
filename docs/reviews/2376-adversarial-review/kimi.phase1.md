[F1]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(static-read)
Legacy-fallback comment claims fail-closed behavior that the code does not implement
- Location:  `require_permission` legacy fallback comment + code block (post-change full snippet)
- Claim:     The comment says a corrupt/load-failed `rbac.db` “ENTERS this branch and fails CLOSED via `check_permission` on the dead handle,” but the legacy branch never calls `check_permission`; ordinary non-floored `Read`s pass through to `return true`.
- Evidence:  Comment: “A corrupt/load-failed rbac.db (`is_open()==false`) then ENTERS this branch and fails CLOSED via `check_permission` on the dead handle …” vs. code: `if ((operation != "Read" || floored) && auth::effective_role(*session) != auth::Role::admin) { ... } return true;` — no `check_permission` in the legacy path.
- Scenario:  A maintainer trusts the comment and believes non-floored Reads are denied when the RBAC store is dead; in reality any authenticated interactive session can still read non-floored data in that state.
- Inference: The comment appears stale; the actual legacy behavior is intentionally fail-open for Reads when RBAC is off/degraded.
- Anchor:    `docs/adr/0017-management-group-confinement-list-reads.md` (gate/filter consistency; #2225 global gate is deliberate)
- Fix:       Either remove/correct the comment to match the real fail-open-for-Reads behavior, or add an explicit dead-store denial for non-floored Reads when RBAC was supposed to be enabled.
- Falsifier: Show a `check_permission` call inside the legacy branch, or show that `rbac_enforcement_in_effect()` is false only when RBAC is explicitly disabled and never when the store is merely dead.

[F2]  MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read)
Elevation short-circuit precedes the engine-principal RBAC-only branch
- Location:  `require_permission` top of function, before the `session->principal_kind == "engine"` branch
- Claim:     `if (auth::is_elevated(*session)) return true;` runs before the engine-principal default-deny branch. If an engine session can ever carry an elevation flag, it bypasses the RBAC-only enforcement the change just added.
- Evidence:  Code ordering: `if (auth::is_elevated(*session)) return true;` then later `if (session->principal_kind == "engine") { ... RBAC-only ... }`.
- Scenario:  A bug or session-store compromise sets `elevated_until` on an engine-principal session; `require_permission` then returns `true` for any securable:operation.
- Inference: The comment says only interactive cookie sessions can be elevated, but the chokepoint itself does not enforce that invariant for engine principals.
- Anchor:    `docs/auth-architecture.md` — engine-principal lifecycle section / design §4.2 default-deny
- Fix:       Reorder the engine-principal check before the elevation short-circuit, or explicitly ignore/reset `is_elevated` for `principal_kind == "engine"`.
- Falsifier: Show that `auth::is_elevated()` returns `false` for every engine session, or that session creation/`elevate_session` rejects engine principals.

[F3]  MEDIUM · CONFIDENCE(lo) · PROVENANCE(static-read)
No evidence that `EnginePrincipal` securable is migrated into existing `rbac.db` deployments
- Location:  `authz_topology_floor.hpp` comment referencing `rbac_store.cpp` `seed_defaults()`; `rbac_store.cpp` is not in the context
- Claim:     The header says `EnginePrincipal` is “seeded in `rbac_store.cpp`’s `seed_defaults()`.” If that seeding only runs on an empty database, upgraded systems with an existing `rbac.db` will have no `EnginePrincipal:Read` grants, breaking engine-principal inventory reads under RBAC.
- Evidence:  Header: “`EnginePrincipal` is the securable cut in this same change … it is seeded in `rbac_store.cpp`’s `seed_defaults()`.” No migration/upgrade logic is shown.
- Scenario:  A production server with RBAC enabled is upgraded; an admin opens the engine-principal grant graph and is denied because no role (including admin) was granted `EnginePrincipal:Read`.
- Inference: The access-control spine needs either idempotent seeding or a migration for the new securable.
- Anchor:    `docs/authz-model.md` + `docs/adr/0033-access-control-spine.md` (schema evolution / spine consistency)
- Fix:       Add idempotent seeding or a versioned migration that adds `EnginePrincipal:Read` to the correct default roles on every startup/upgrade.
- Falsifier: Show `rbac_store.cpp` `seed_defaults()` runs on existing databases or a migration file adds the securable.

[F4]  MEDIUM · CONFIDENCE(lo) · PROVENANCE(static-read)
Context does not prove all surfaces exposing authorization-topology data use the floored securables
- Location:  `authz_topology_floor.hpp` + route/MCP handlers not shown in context
- Claim:     If any endpoint still returns access-review export data, the RBAC role graph, or the engine-principal grant graph under a securable outside the floor (e.g. `Security:Read`, `Infrastructure:Read`), the floor is bypassed.
- Evidence:  The floor deliberately excludes `Security:Read`, `ApiToken:Read`, and `ManagementGroup:Read`; the known `discover_permissions` bypass confirms such gaps can exist.
- Scenario:  A non-admin authenticated session calls an endpoint that returns the role graph but is gated by `Security:Read`; the floor never fires and the topology leaks.
- Inference: Need an audit of every REST route and MCP tool that emits authorization-topology data.
- Anchor:    `docs/auth-architecture.md` — “The authorization topology floor” section
- Fix:       Audit and retarget every topology-emitting surface to `AccessReview:Read`, `UserManagement:Read`, or `EnginePrincipal:Read`.
- Falsifier: A complete list of route handlers and MCP tools showing that only the three floored securables are used for topology data.

[F5]  LOW · CONFIDENCE(med) · PROVENANCE(static-read)
String-based floor set is decoupled from securable/operation constants
- Location:  `authz_topology_floor.hpp` — `kTopologyFloor`
- Claim:     The entries are raw string literals with no compile-time tie to the securable/operation constants used by routes or `seed_defaults()`. A future typo or case mismatch would silently disable the floor for that entry.
- Evidence:  `inline constexpr TopologyFloorEntry kTopologyFloor[] = { {"AccessReview", "Read"}, {"UserManagement", "Read"}, {"EnginePrincipal", "Read"}, };`
- Scenario:  A maintainer changes the canonical securable name elsewhere but mistypes one entry; legacy RBAC-off installs allow that topology read.
- Inference: The header explicitly accepts this tradeoff, but it is a maintainability/drift risk.
- Anchor:    judgment (the header’s own rationale)
- Fix:       Add a unit test or static check that verifies the seeded securable/operation constants match the floor set exactly.

[F6]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
Scoped variant duplicates the legacy floor enforcement block
- Location:  `require_scoped_permission` legacy tail
- Claim:     While both branches call the shared `topology_floor_applies()`, the surrounding audit log, metrics increment, and A4 denial code are duplicated; future edits to one may drift.
- Evidence:  Scoped tail mirrors the `require_permission` legacy block line-for-line, including the metric name and denial message.
- Scenario:  A future change updates the topology-floor metric label or denial reason in one function but not the other, producing inconsistent observability/UX.
- Inference: Low immediate security impact, but a classic “second copy” defect the repo’s chokepoints are meant to prevent.
- Anchor:    judgment
- Fix:       Extract a shared helper for the legacy floor denial path.

[F7]  MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read)
Service-scoped token branch does not verify the RBAC store is open
- Location:  `require_permission` service-scoped token branch
- Claim:     The branch checks `!rbac_store_->is_rbac_enabled()` but not `!rbac_store_->is_open()`. If the store is enabled but failed to open, `check_role_has_permission` may operate on a dead handle.
- Evidence:  `if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) { ... deny ... } if (!rbac_store_->check_role_has_permission("ITServiceOwner", ...))`
- Scenario:  A corrupt `rbac.db` leaves `is_rbac_enabled()` true but `is_open()` false; service-scoped tokens are either incorrectly denied or trigger undefined behavior, while engine principals get a clean 503.
- Inference: The engine branch explicitly checks `is_open()` and returns 503; the service branch should be consistent.
- Anchor:    `docs/adr/0017-management-group-confinement-list-reads.md`
- Fix:       Add `!rbac_store_->is_open()` to the service-scoped precondition and return 503 (or 403) consistently with the engine branch.

VERDICT:  PASS — the change correctly places the floor after live-RBAC enforcement and adds the engine-principal RBAC-only branch, but several MEDIUM verification/defense-in-depth gaps remain.

COVERAGE:
- security/privilege: deep — elevation ordering, engine/service/interactive store predicates, topology surface coverage, securable migration.
- correctness/logic: deep — floor ordering vs live RBAC, legacy fallback semantics, string matching.
- resource & concurrency safety: skimmed — no lifetime/ownership/handle issues visible in the shown code; metrics thread-safety not verifiable statically.
- cross-platform/portability: skimmed — constexpr `string_view` usage is portable.
- cross-component & schema/contract consistency: deep — migration, securable cut, ADR-0017 gate consistency.
- test adequacy: unverifiable — no test files were included in the context.

FILES:
- `authz_topology_floor.hpp` (full)
- `require_permission` post-change full implementation
- `require_scoped_permission` legacy tail
