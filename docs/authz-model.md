# The authz MODEL (ADR-0033 §2) and per-device dispatch visibility (#1788)

This document covers two related but separable pieces of PR1.4, plus a PR1.9a addition:

1. **The registry-independent authz MODEL** (`server/core/src/authz_model.hpp`) — the
   securable×operation×risk_tier×mcp_tier_class classification a future runtime
   capability-declaration registry (PR1.9) will consume when a Module registers a tool or REST
   route.
2. **The #1788 fix** — closing the `/api/command` per-device visibility gap across all four
   dispatch arms.
3. **PR1.9a: the command capability registry (pure headers) + three new securables** — the
   `plugin.action` classification core PR1.9's registration path will eventually consume, plus the
   live RBAC seed extensions (`PluginConfig`/`PluginSecret`/`UploadGrant`) it needs to not deny an
   Administrator on a fresh RBAC-enabled install (peer finding PLAN-001). See §3 below.

Both PR1.4 pieces live in `authz_model.hpp` because the second reuses the first's shared
`VisibleSet` primitive, but they are independent: the model does not enforce anything, and the
#1788 fix does not depend on the seed catalogue. §3 is a separate PR entirely and lives in its own
headers (`command_capability.hpp` etc.) plus an additive `authz_model.hpp` extension.

## Spine-version assumption

This PR is written against **ADR-0033 as accepted 2026-07-14** (`docs/adr/0033-access-control-spine.md`,
"design-only, binds prospectively"). Alex accepted the rework risk of building against that spine
before the runtime capability-declaration registry (ADR-0033 §2's own stated precondition) exists —
if the ADR is amended before PR1.9 lands, this schema may need a rework pass.

## 1. The authz MODEL

### Vocabulary

- **`securable`** — reuses an existing `RbacStore::list_securable_types()` entry (23 seeded types
  as of #2376's `EnginePrincipal` cut, `rbac_store.cpp:302-348`, read-only reference for this PR)
  wherever one accurately describes the protected resource. A Module minting a genuinely new
  securable is an ADR-0033 §2 escape hatch that
  is **not built yet** — its own stated precondition is the runtime capability-declaration registry,
  which is PR1.9's job, not this one's.
- **`operation`** — `yuzu::server::authz::Operation`. ADR-0033 §2 names "the existing six" as
  Read/Write/Execute/Delete/Approve/Push. `Attest` is a seventh, narrower operation
  (`rbac_store.cpp` seed comment: Periodic Access Reviews, SOC 2 CC6.2) and `Rotate` is an eighth
  (`rbac_store.cpp` seed comment: human API-token self-service rotation, P2 #11, SOC 2 CC6.3) —
  both deliberately excluded from every CRUD loop there, and included in this model's enum for the
  same reason: a capability can genuinely declare either. `Rotate` is additionally DISTINCT from
  `Write` on its own securable (`ApiToken`) — a round-3/4 security finding showed a shared op would
  let an MCP tier allowance for rotation also admit token creation; see `mcp_policy.hpp`'s
  `tier_allows()` operator-tier comment, the single narrative home for that finding.
- **`risk_tier`** — `yuzu::server::authz::RiskTier` (Low/Medium/High/Critical). The routing input
  ADR-0033 §5 (D5)'s future auto-approval policy layer will consume; the ADR does not fix concrete
  thresholds (D5 is explicitly future work), so this is a deliberately small, ordered scale captured
  from day one rather than a speculative rule language. `min_risk_tier_for(operation)` is the one
  rule this PR commits to: a **floor**, so a capability cannot under-declare the risk of an
  inherently sensitive operation class (Delete/Approve/Push floor at High; Write/Execute/Attest/
  Rotate at Medium; Read at Low). Declaring above the floor is always fine.
- **`mcp_tier_class`** — `yuzu::server::authz::McpTierClass` (read/write/execute). ADR-0033 §2: the
  routing input PR1.9 **will** feed into the shipped **tier-before-RBAC** ordering
  (`docs/mcp-server.md`, `mcp_policy.hpp::tier_allows`) so every built-in and declared tool routes
  through one chokepoint, extended, never a parallel one. **Not wired today** — `tier_allows` still
  takes a `std::string_view` and has no knowledge of this type. This is deliberately **not** derived purely from
  `operation` in general: ADR-0033 §1 is explicit that read-vs-effect ("the one typing that must not
  be self-certified") is core's *ratified* mutability class, decided when a Module's capability
  manifest is approved. `default_mcp_tier_class(operation)` is only a convenience for classifying
  this header's own seed catalogue below.

### The PR1.9-facing declaration schema

`CapabilityDeclaration` is the per-capability record PR1.9's registration path will populate. It
carries the securable×operation×risk_tier×mcp_tier_class quadruple this PR defines, plus the fields
ADR-1005/ADR-0032 require of **every** capability — the versioned REST twin, the MCP twin (or a
recorded ADR-1005 ledger exception), the `/api/v1/openapi.json` + MCP `tools/list` discovery entry,
the A4 error envelope, agentic-context annotations (track 2g), and `data_class` + `audit_verb`
(ADR-0032 Decision 11). This schema **references** those obligations as fields to populate at
registration — it does not redefine the platform mechanisms themselves, which stay governed by
ADR-1005/ADR-0032 and `rest_a4_envelope.hpp`.

`CapabilityDeclaration::is_valid()` **expresses** ADR-0033 §2's "undeclared means the capability
does not exist — never defaults to read": a missing `securable`/`discovery_entry`/`data_class`/
`audit_verb`, a `risk_tier` below its operation's floor, or **either** REST/MCP twin absent with no
recorded exception all fail validation. Once PR1.9 adds the registration path, a Module registration
that fails it must not register on **any** surface.

**It enforces nothing today.** `is_valid()` has zero production callers — the whole §2 half of
`authz_model.hpp` is reachable only from `test_authz_model.cpp`. That is the deliberate
shipped-incomplete state this section's own opening states ("the model does not enforce anything");
the future tense above is load-bearing, because a reader who takes this as a live control would
believe a capability registration is validated when nothing calls the validator.

There is deliberately **no `execute_roles` field** (or any role-shaped field) — which principals
hold `operation` on `securable` stays entirely in `RbacStore`'s `role_permissions` table. This model
classifies a capability; it never grants one.

### Seed catalogue

`kSeedCatalogue` is eight representative rows, not a full mirror of `RbacStore`'s 38 securables × 8
operations — it exists so PR1.9 has real rows to migrate and so this header's own tests exercise
`is_valid`, not to be the registry itself. It includes an ordinary CRUD read (`Response:Read`), a
`Tag:Write` (mirrors `mcp_policy.hpp`'s existing Tag special-case), `Execution:Execute` (the
combination the #1788 fix below narrows), the Guardian-only `Push` narrow op
(`GuaranteedState:Push`), — required by this PR's spec — `AccessReview:Attest`, deliberately
outside every CRUD loop, exactly as seeded in `rbac_store.cpp`, and three later additions:
`PluginConfig:Write`, `PluginSecret:Write` and `UploadGrant:Write`.

### Composition with the frozen #1715 lattice

This model **never re-decides** the frozen #1715 combining lattice or the single INV-7 resolver
`RbacStore` already ships (cross-boundary combining is additive/OR; a global allow overrides a group
deny; a global deny does not override a group allow; deny-overrides applies only within a single
group). It classifies securables/operations/risk-tiers and composes strictly on top, via
`RbacStore`'s existing public API (`check_permission`, `visible_agents_for_permission`,
`check_scoped_permission`, `authorize_list_read`) — never the private `resolve_perm_groups`/
`PermGroups`.

## 2. Closing #1788: per-device visibility on every operator dispatch arm

### The gap

`/api/command` (`command_routes.cpp` as of #2557, moved out of `server.cpp`; referenced at the handler's `#1788` comment) base-gates a single,
possibly-**global** `Execution:Execute` permission and then dispatches through one of four arms:

1. **Ids** — an explicit `agent_ids` list.
2. **Broadcast** — the published `__all__` ground scope.
3. **Group** — `group:<id>`, resolved via `ManagementGroupStore::get_members`.
4. **Scope** — a scope DSL expression, resolved via `AgentRegistry::evaluate_scope`.

None of the four narrowed the actual send set to the operator's own visibility. This has **one
live consequence and one forward-wired one**, which the fix below deliberately closes together:

- **Live (the exploit #1788 actually closes):** a **service-scoped token** reaches this route because
  `require_permission` admits it via the `ITServiceOwner` role's `Execution:Execute` grant —
  independent of the minting principal's own grants (`auth_routes.cpp`
  `check_role_has_permission("ITServiceOwner", …)`). So before this fix the token dispatched to the
  whole fleet through any arm, most directly by naming a foreign-service device in `agent_ids`,
  ignoring the very confinement `require_scoped_permission` enforces per-target on the non-generic
  paths. (Separately, because the minter *may* also hold a global `Execution:Execute` grant, the
  visibility composition below checks the service scope **first** — CDX-001 — so that grant cannot
  make the token unfiltered.)
- **Forward-wired (correct-but-currently-unreachable):** a purely **management-group-confined**
  operator holds *no* global `Execution:Execute` grant, so the base `require_permission` gate above
  **already denies them** before any arm runs (ADR-0017 records this as the World-A "correct-but-
  unreachable" gap). The per-agent narrowing below therefore changes nothing for that principal
  *today*; it composes correctly for when the ADR-0017 list-admit gate (#1714/#1715) makes such a
  caller reachable. The changelog should not be read as evidence a live management-group exploit was
  closed — it was not; the service-token arm is the live fix.

### The fix

`server.cpp` derives **one** permission-specific visible set — `yuzu::server::authz::VisibleSet`,
`std::nullopt` meaning "unfiltered" — right after the existing destructive-action block and before
any dispatch arm runs:

- A **service-scoped token** (`Session::token_scope_service` non-empty) is resolved **first** and is
  **never unfiltered**: it attenuates to exactly its own service's agents
  (`TagStore::agents_with_tag("service", …)`), and that confinement takes precedence over any global
  `Execution:Execute` grant the minting username holds (an administrator minting a service-A token
  must still be confined to service A, not reach the whole fleet — CDX-001). The tag store being
  unavailable fails closed to the empty set.
- Otherwise, if the operator holds `Execution:Execute` **globally** (`RbacStore::check_permission`),
  or reaches the route via JIT admin elevation (`auth::is_elevated`) — both of which
  `require_permission` above already treats as full access without a matching `principal_roles` row —
  the set is unfiltered. This mirrors `RbacStore::check_scoped_permission`'s own internal order
  (global first) so a global ALLOW keeps overriding a group deny (#1715(b)), rather than this fix
  inventing a second, divergent order.
- Otherwise, the set is `RbacStore::visible_agents_for_permission(user, "Execution", "Execute",
  mgmt_store)` — the ADR-0017 per-agent visible set. Any store error narrows to "nothing visible",
  never "everything" (fail-closed).

Every dispatch arm then intersects its own already-resolved target list against this set via the
shared, pure `yuzu::server::authz::in_scope` / `filter_to_scope` primitives before calling
`send_to`:

- **Ids** — `agent_ids` is filtered directly.
- **Group** — each resolved member is checked before `send_to`.
- **Scope** — `evaluate_scope`'s matched ids are filtered directly.
- **Broadcast** (both the named `__all__` arm and the untargeted-omission fallthrough, #2500) — a
  shared `dispatch_broadcast` closure sends to `AgentRegistry::send_to_all` only when unfiltered;
  otherwise it walks the currently-known agent ids (`AgentRegistry::to_json_obj`) and sends only to
  those in scope.

A hidden id is **silently dropped**, the same posture the Scope/Group arms already had for an id
that resolves to nothing (a 503 "failed to send command to any agent" only if the visibility filter
empties the *entire* resolved set) — this fix narrows the send set, it does not add a new error
shape.

### Where the decision lives, and which surfaces route through it

Two functions, each with exactly one implementation:

| | Function | Decides |
|---|---|---|
| Which arm | `classify_dispatch_arm` (`dispatch_target_shape.hpp`) | Group / Scope / Ids / Broadcast / None |
| Who is reached | `dispatch_confined_arms` (`dispatch_confined_arms.hpp`) | the per-arm `VisibleSet` intersection |

Every OPERATOR dispatch surface reaches the second through one of two callers —
`ServerImpl::dispatch_confined` (the shared closure behind MCP `execute_instruction` /
`execute_bundle`, the dashboard execute and TAR `purge_source` routes, the per-device DEX live
query, the three async result-set producers (`POST /api/v1/result-sets/from-tar-query`,
`/from-instruction-result`, `/{id}/re-eval`), and `POST /api/instructions|workflows/{id}/execute`)
or `command_routes.cpp`'s `/api/command` handler (moved out of server.cpp by #2557). Those two
callers legitimately differ in how they RESOLVE targets (management-group store, scope engine,
principal from a live session versus an execution row) and in how they report failure
(`/api/command` answers 400/503; the shared closure has no response object — background runners call
it). They do not differ in who gets reached, and that is the part now held in one place.

The REST layer reaches the shared closure through `RestApiV1::CommandDispatchFn`, whose signature
**requires** the caller's `VisibleSet`. That is deliberate and load-bearing: the class was formerly
handed the 6-argument SYSTEM closure (`exec_visible` hardcoded `nullopt` — correct for background
engines, never for an operator surface), and the async result-set producers dispatched through it,
so a service-scoped token admitted by their bare global `Execution:Execute` gate reached the whole
fleet. Making the parameter mandatory means the unconfined closure is no longer type-compatible with
the REST registration: a future dispatch caller in that file cannot pick the wrong one. Callers must
not pre-intersect their own target list — for the Scope and Broadcast arms they could not anyway,
since the candidate set lives in the `AgentRegistry`, not the route.

Each surface supplies the caller's set via an `ExecVisibleFn`, derived per request by
`derive_exec_visible`. **An unwired `ExecVisibleFn` substitutes a PRESENT-EMPTY set, never
`nullopt`** — deny-all rather than unfiltered. That asymmetry is the whole fail-closed contract: the
two states are not interchangeable, and treating a missing derivation as "no filter" is precisely
the failure mode being guarded. A harness that wants genuinely unfiltered dispatch wires a callback
**returning** `nullopt`; leaving the callback empty is a missing gate, not a synonym for it.

One refinement on top of that floor, by route class. Where the derivation is defense-in-depth behind
a per-target `scoped_perm_fn` gate (REST bundles, TAR purge, the DEX live query), present-empty is
the whole answer — the primary gate already reports its own absence with a `500`. Where it is the
**only** per-device authorization — the three async result-set producers, which admit on a bare
global gate and then dispatch by scope or `__all__` — an unwired derivation answers an **audited
`500`** instead. Both fail closed; the difference is only whether a misconfigured server can be
distinguished from an empty fleet, and on a route with no other gate it must be.

`broadcast_on_none` is the one thing a caller parameterises: it says what an UNNAMED target means.
The shared closure passes `false` — no target named reaches NOBODY (#2500). Callers whose UI or tool
has already normalised a deliberate whole-fleet selection into empty+empty pass `true`. A new
dispatch caller passes `false` and names `__all__` explicitly.

One deliberate exclusion: the BACKGROUND engines (scheduler, Guardian push, policy evaluator)
dispatch as system with `nullopt`, deferred to the #1714/#1715 core chokepoint.

`quarantine_device` is NOT an unfiltered exclusion — both the MCP tool and the REST twin
(`POST`/`DELETE /api/v1/quarantine`) gate on the SOLE per-target `scoped_perm_fn("Security","Execute",
agent_id)` (CDX-P1-02 brought REST to parity with MCP, which already threads a `{agent_id}` confined
`VisibleSet`), and both fail CLOSED — a 500/`kInternalError` — when the scope gate is unwired, never
widening to a global grant. `GET /api/v1/quarantine` is scoped the same way (gov-fix, admit-then-filter
per record via the same `scoped_perm_fn`): a device outside the caller's visible set is dropped from
the list entirely, not merely blocked from write access — closing the asymmetry where a confined
operator could act on a device via POST/DELETE but not see it via GET, and a global `Security:Read`
holder could enumerate devices outside every caller's actionable scope.

### What this fix deliberately preserves

- Every `dispatch_target_shape.hpp` invariant: `__all__` is still the one published spelling of
  broadcast and is **never inferred** from an omitted target; a targeting argument that was
  **supplied** but resolves to nothing is still refused as a 400 before any arm runs (unchanged —
  this fix only touches what happens *after* a target set is already resolved).
- The frozen #1715/INV-7 precedence — this fix calls `RbacStore`'s public resolver-backed API and
  composes on top; it does not touch `rbac_store.{hpp,cpp}` and never reaches the private
  `resolve_perm_groups`.
- The existing destructive-action securable-elevation block (`kDestructiveActionSecurable`), which
  is untouched; its own `ManagementGroupStore`-based `agent_ids` filtering for the destructive-action
  list runs first, and this fix's visibility filter composes on top of whatever `agent_ids` block
  leaves behind (intersecting twice is idempotent).

## 3. PR1.9a: the command capability registry (pure headers) + three new securables

### The classification core

Three new header-only files under `server/core/src/`, zero `server.cpp` involvement:

- **`command_capability.hpp`** — `DispatchClass` (ReadOnly/Mutating/Destructive) and `Mutability`
  (None/Reversible/Irreversible), deliberately independent axes set explicitly per row rather than
  inferred from each other or from `authz::Operation` (same ADR-0033 §1 "not self-certified"
  reasoning as `McpTierClass` in §1 above). `CommandCapability` is a view/enum-only struct — no
  `std::string`, no heap on the lookup path. `CommandCapabilityRegistry` composes SEVERAL
  independently-authored fragments (injected as `std::span`s via its constructor's
  `initializer_list`, stored in a small fixed array — never a file-scope singleton) and exposes
  `classify(plugin, action)`, case-insensitive on both components (matching the lowercase
  normalisation `server.cpp:6360-6368` applies to the action before dispatch, extended here to the
  plugin half too). A miss is `ClassificationError::Unclassified`, **never** a permissive default;
  the same `plugin.action` declared by two fragments is `ClassificationError::Ambiguous`, never
  first-wins.
- **`command_capability_parsers.hpp`** — `normalize_action_key`, `compute_plan_hash` (a
  parameter-insertion-order-invariant plan identity, since it iterates a `std::map` in its natural
  key order), and `encode_dispatch_tag`/`decode_dispatch_tag` for the **frozen** wire grammar
  `v1|<class>|<mutability>|<plan_hash_hex>` (class ∈ {ro,mut,dest}, mutability ∈
  {none,rev,irrev}) — later PRs mirror this exact grammar into the proto comment and put it on the
  wire; this header is the one place that gets to change the spelling.
- **`capability_decls/core_dispatch_capabilities.hpp`** — this package's own fragment: the three
  dispatches the **server issues to itself** (`tar.fleet_snapshot`, `__guard__.push_rules`,
  `asset_tags.sync`), each `system_reserved = true`. Every other plugin's rows live in separate
  per-group fragment headers owned by other packages; none of them are aggregated here.

**Wired to the live dispatch path.** This paragraph previously recorded the registry as
shipped-incomplete and reachable only from `test_command_capability.cpp`; PR1.9c ended that.
`ServerImpl::build_classified_command` (`server.cpp`) constructs a `CommandCapabilityRegistry` over
all six spans — `core_dispatch_capabilities()` plus the five per-group fragment headers — and every
`CommandRequest` the server builds is classified and authorized through it. An unclassified or
ambiguous `plugin.action` is refused there, so the registry is now load-bearing rather than
declarative.

### Three new securables

The declaration model above is not the same thing as the live RBAC seed — `RbacStore::seed_defaults()`
(`rbac_store.cpp:283-375`) independently seeds its own `types[]`/`ops[]` arrays, and a securable
absent from `types[]` cannot receive a default grant (including Administrator's). This PR appends
three securables to both `authz_model.hpp`'s `kSeedCatalogue` (representative `CapabilitySeed` rows)
and `rbac_store.cpp`'s `types[]` (the live seed):

| Securable | Purpose | Example operation |
|---|---|---|
| `PluginConfig` | A plugin's configuration, including its kill-switch flip | `PluginConfig:Write` |
| `PluginSecret` | Plugin secret material (credentials, tokens a plugin holds) | `PluginSecret:Write` |
| `UploadGrant` | The mint/revoke lifecycle of an upload grant (not the file transfer itself — that stays under the existing `FileRetrieval` securable) | `UploadGrant:Write` (mint), `UploadGrant:Delete` (revoke) |

No new `Operation` enumerator — every one of the three maps onto the existing
Read/Write/Execute/Delete/Approve vocabulary, keeping the `rbac_store.cpp` change to three appended
`types[]` strings plus role grants, with `ops[]` untouched byte-for-byte.

Role grants (`rbac_store.cpp` `seed_defaults()`):

| Role | PluginConfig | PluginSecret | UploadGrant |
|---|---|---|---|
| Administrator | Read/Write/Execute/Delete/Approve (existing CRUD loop over `types[]`) | Read/Write/Execute/Delete/Approve | Read/Write/Execute/Delete/Approve |
| PlatformEngineer | Read/Write/Delete | Read/Write/Delete | Read/Write/Delete |
| Operator | Read | **none** | Read |

Operator deliberately never sees `PluginSecret` — secret material stays PlatformEngineer/
Administrator-only, unlike `PluginConfig`/`UploadGrant` where Operator gets read visibility for
day-to-day triage. No other role (Viewer, ITServiceOwner, ApiTokenManager, Reviewer) is touched by
this PR.

## 4. Wave 7 PR7.2: `Forensics` and `Decommission` (37th/38th securables)

Two more securables appended to `rbac_store.cpp`'s `types[]` (36→38) and its `mcp_server.cpp`
mirror (`kRbacSecurables`):

| Securable | Purpose | Consumed operations | Roles |
|---|---|---|---|
| `Forensics` | Read-only forensic artefact reads (ShimCache/AmCache/Prefetch, application usage). Every catalogue row on it is `ExecuteGate::AdminOrApproval` AND single-target (below) — Administrator only. | `Read`, plus the unused CRUD-loop ops (harmless, keeps the loop uniform) | Administrator (CRUD via the loop); deliberately ABSENT from the Viewer read-list — a forensic read is never a Viewer-tier operation |
| `Decommission` | The whole-device erasure cascade (`DELETE /api/v1/sle/agents/{id}`). Replaces the three-way `SoftwareLicensing`∧`Inventory`∧`GuaranteedState:Delete` conjunction ADR-0024 Decision 9 originally rejected promoting a dedicated securable for. | `Delete` is the ONLY consumed operation — `Read`/`Write`/`Execute`/`Approve` are meaningless on this securable and are never widened onto it | Administrator (CRUD via the loop, PowerManagement/PluginConfig precedent); ITServiceOwner gets a TARGETED `Decommission:Delete` grant only (preserves the population that could decommission under the old conjunction — ITServiceOwner held CRUD on all three of its members) |

`Decommission` has **no MCP consumer by design** — the erasure verb is REST-only (ADR-1005
twin-existence exception #2102). It is still listed in `kRbacSecurables` purely so the
seeded-catalogues binding test (`test_rbac_store.cpp`, "seeded catalogues match the MCP C8
validator mirrors") keeps the two mirrors equal; no MCP tool or dispatch path ever checks it.

**Forensics is SINGLE-TARGET, not Destructive-classified.** `dispatch_destructive_gate.hpp`'s
`requires_explicit_targets` extends the existing Destructive-class targeting rule to any row on
the `Forensics` securable: exactly one explicit, in-scope `agent_id`, no `scope` key (including
`"__all__"`) — a fan-out (zero ids, more than one id, or any scope) is refused with a distinct
message (`kForensicUntargetedMessage`) from the Destructive refusal
(`kDestructiveUntargetedMessage`, unchanged byte-for-byte). A Forensics row that passes
(`Targeted`) is still run through `confine_destructive_targets`: **mgmt-group confinement APPLIES
to the read** — a forensic read never reaches an agent outside the operator's visible set, and the
existing 404 `no reachable in-scope agent` answers an out-of-group id, same as a Destructive row.

**The single exception to the rule just stated, and it is narrow and explicit:**
`ScheduleRunner`'s approval-gated fan-out (D3 in `dispatch_destructive_gate.hpp`) runs a
DIFFERENT dispatch path from the three route handlers `requires_explicit_targets` gates — a
scheduled fire never reaches `evaluate_destructive_targeting` at all, so this rule neither narrows
that path nor widens what any of those three route handlers themselves accept. An approved
scheduled forensics read remains permitted by the schedule-approval posture alone (four-eyes at
schedule-creation time), never by a broadcast exemption carved into this targeting gate. No other
surface may cite this exception; every other caller of a Forensics-classified row stays
single-target, no exceptions.

**`execution_artifacts` — planned, not yet built.** This PR ships the `Forensics` securable and
its single-target dispatch rule with zero registered consumers: no plugin, no
`capability_decls/*.hpp` row classifies anything `Forensics` yet. `execution_artifacts` (a future
companion package, referenced elsewhere in this codebase only as a forward-looking name and as a
synthetic fixture string in `test_dispatch_destructive_gate.cpp`) is planned to be the first
Forensics-class plugin, but its default-off posture, its kill-switch mechanism, and its enable
endpoint are planned, not yet designed in detail — there is no `seed_kill_switch_default_off` (or
equivalent) anywhere in this tree today. Until it lands, `Forensics` exists as authorization
infrastructure only.

**Wave 7 PR7b: application usage is the first live `Forensics` consumer, not `execution_artifacts`.**
The `app_usage` plugin's dedicated read surface (single-target, `Forensics:Read`) is the first row
to actually classify anything `Forensics` — application usage history (TAR's `usage_live`/
`usage_daily`/`usage_daily_user` tables, retained on a 31-day rolling window) is designed to be
reachable only through that surface (see the residual read-path caveat below). It is deliberately
unreachable through the generic `tar.sql` endpoint (`Infrastructure:Read`,
`plugin_action_catalogue_a.hpp`): the three usage tables are excluded from `is_queryable_table()`'s
allowlist in `tar_schema_registry.cpp`, so the read-only connection's SQLite authorizer denies every
access path to them — direct name, `$Usage_*` placeholder, alias, JOIN, or subquery — with the same
no-existence-oracle posture `tar_events` already gets (#760 UP-8). #4260 tracked this gap; closed by
this exclusion. #2744 (the app_usage measurand ADR) is superseded by the machine-scope decision
above and closes without a code change.

**Residual read path, accepted not closed:** `app_usage` is also a typed daily-sync source
(`typed_inventory_sources.hpp`) excluded from the generic `InventoryStore` only on the gateway's
*write* path, with a boot-time purge cleaning up any stray row from a mixed-version deployment
window (an older gateway writing before an upgraded server's boot purge runs). The generic *read*
path (`InventoryStore::get`/`query`/`list_tables`) carries no typed-source filter, so a stray row
from that window — or a failed purge — stays readable via the far lower-privileged
`Infrastructure:Read`/`Inventory:Read` securable until the next boot purge. This is the same
architectural gap `device_ci` already carries (per `typed_inventory_sources.hpp`'s own header
comment) and is not being retrofitted here either; it was accepted at this feature's planning gate
in favor of purge-on-upgrade over a read-time filter.

## Testing

`tests/unit/server/test_authz_model.cpp` covers:

- `CapabilityDeclaration::is_valid()` against the seed catalogue and deliberately-invalid rows.
- Composition semantics (`visible_agents_for_permission` / `check_scoped_permission` /
  `authorize_list_read`) for `Execution:Execute` specifically, mirroring
  `test_list_read_confinement.cpp`'s fixture pattern, including the global-allow-overrides-group-deny
  and global-deny-does-not-override-group-allow #1715 cases.
- `in_scope`/`filter_to_scope` directly, exercising each of the four dispatch arms' characteristic
  target-set shape (an explicit id list, resolved group members, scope-matched ids, and the full
  known-agent-id list for broadcast) against a scoped visible set, and against `std::nullopt`
  (unfiltered).

The arms themselves are covered separately, and both layers are needed. The tests above cover the
shared `in_scope`/`filter_to_scope` PRIMITIVE; `tests/unit/server/test_dispatch_confined_arms.cpp`
covers the per-arm SEAM (`server/core/src/dispatch_confined_arms.hpp`) by running it against a
recording sink and asserting the exact set of agents reached, for every arm against each of the
three `VisibleSet` states.

Proving the primitive correct says nothing about whether every arm actually calls it — that gap is
what previously let route mocks pass while the intersection was deleted from production. The seam
tests are mutation-checked against exactly that: removing any single `in_scope`/`filter_to_scope`
call fails them.

Route-level tests additionally prove the HANDOFF — that each handler derives the caller's visible
set and threads it in — for the MCP, REST-bundle, dashboard, instruction-execute and
workflow-execute surfaces. Handoff plus intersection together is the full path; either alone is not.

`tests/unit/server/test_command_capability.cpp` covers §3's classification core:
`CommandCapabilityRegistry::classify` (unknown → `Unclassified`, cross-fragment collision →
`Ambiguous`, case-insensitivity on both `plugin` and `action`), `core_dispatch_capabilities()`'s
three rows, and the `command_capability_parsers.hpp` helpers (`compute_plan_hash`'s
insertion-order invariance and per-component sensitivity, and `encode_dispatch_tag`/
`decode_dispatch_tag` round-tripping every `DispatchClass`×`Mutability` pair and rejecting a
malformed tag). `tests/unit/server/test_rbac_store.cpp` adds the PLAN-001 fresh-seed coverage:
securable-type presence, and the Administrator/PlatformEngineer/Operator grant tables above,
including the explicit "Operator holds nothing on `PluginSecret`" negative assertion.
