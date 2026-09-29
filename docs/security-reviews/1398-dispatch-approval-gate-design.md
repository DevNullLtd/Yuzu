# Design: definition-declared approval governance on raw dispatch (#1398)

**Status: APPROVED WITH CHANGES by security-guardian + architect (2026-08-28).**
All required changes below are folded into this revision — ready for rung 1.
Baseline: `origin/dev@06da83a12`.

## Problem

An `InstructionDefinition`'s `approval.mode` (and the dead `permissions.executeRoles`
field) is enforced only on the governed path `POST /api/instructions/:id/execute`.
Raw dispatch (`POST /api/command`, MCP `execute_instruction`) authorizes on the
classified `(securable, operation)` pair alone via the existing dispatch chokepoint
(`ServerImpl::build_classified_command` / `classify_and_authorize_dispatch`,
`agent_registry.hpp`) and never resolves a governing definition, so a `role-gated`
action's approval requirement does not apply there.

Two things changed the shape of the fix since the issue was filed: (1) the
`CommandCapabilityRegistry` (PR1.9b/c) already classifies every dispatchable
`(plugin, action)` pair and enforces `securable`/`operation` RBAC on **every**
dispatch surface through one chokepoint; (2) `executeRoles` was never wired
server-side at all (dropped at build time by `embed_content.py`) and its content
labels (`endpoint-admin`, `security-admin`, ...) match no seeded RBAC role.

Both reviewers independently verified every factual claim in this doc against
`origin/dev@06da83a12` (chokepoint singularity via `ClassifiedCommand`'s private
constructor, the 184-row/six-fragment catalogue, the N:1 `tar.sql` mapping, the
`authz_model.hpp:174` doctrine, the `embed_content.py` extraction behavior, the
`script_exec.*` bonus-closure claim, the `firewall`/`bitlocker` audit spot-check,
and the empty-shipped-`AlwaysApproval`-set claim) and found no factual error in
the design's premises. The changes below are precedence/mechanism/wording fixes
found during review, not corrections to the underlying analysis.

## Decision 1 — governance unit is the (plugin, action) pair, not the definition

`(plugin, action) -> InstructionDefinition` is N:1 (`tar.sql` has 15 shipped
definitions). Threading definition identity through every dispatch surface would
require a new reverse index and a runtime YAML re-parse (`executeRoles` survives
only inside the opaque `yaml_source` blob) for a control the platform doctrine
(`authz_model.hpp:174`: "this schema classifies a capability, it never grants
one") already says shouldn't be role-shaped. Per-definition granularity is not
lost: the governed path keeps enforcing each definition's own `approval_mode`
(`workflow_routes.cpp:1735-1746`) as an ADDITIONAL, earlier check — an
`always`-mode definition's caller sees a pending-approval ticket before dispatch
is ever attempted, for instance.

**Correction (governance Gate 4 consistency-auditor finding, folded in
2026-08-28):** the sentence this replaced claimed the pair gate is "a floor
under raw dispatch, not a replacement for the governed path's finer check" —
true of the approval-mode pre-check, but misleading about what actually happens
at dispatch. The governed path's own dispatch call (`workflow_routes.cpp:1843`,
`cmd_dispatch` -> the shared chokepoint) reaches the IDENTICAL
`classify_and_authorize_dispatch` raw dispatch uses. So the pair-derived
`ExecuteGate` is not scoped to raw dispatch at all — it is the floor under
EVERY dispatch, governed path included. The practical consequence: an
`auto`-mode definition whose pair is `AdminOrApproval`/`AlwaysApproval` because
a SIBLING definition on that pair is `role-gated`/`always` will still be denied
`ApprovalRequired` for a non-admin, non-ticketed caller at governed-path
dispatch, even though that definition's own mode says no approval is needed.
This is deliberate defense-in-depth (no individual definition can locally
override a pair the catalogue classifies as sensitive) but was not what the
original wording described, and is a real operator-visible surprise worth
knowing about — filed as a design gap in this ladder's follow-up list (item 10
below), since shipped content today has zero such conflicts (verified by the
rung-2 cross-check) but a future runtime import is not yet protected against
creating one.

Instead: add an approval-gate dimension to `CommandCapability` itself — the
struct that already carries `securable`/`operation`/`risk_tier` per pair and is
authored explicitly (never inferred) in the six `capability_decls/*.hpp`
fragments, same pattern as the existing `dispatch_class` field.

**Forward compatibility note (architect):** ADR-0033 §4 already states a future
capability declaration "may carry `requires_approval`". `ExecuteGate` is a
compatible pre-echo of that field on `CommandCapability` specifically (not on
`authz_model.hpp`'s still-inert `CapabilityDeclaration`, which carries no such
field today and stays doctrine-compliant). When the ADR-0033 capability
registry materializes, `ExecuteGate` folds into its `requires_approval` — one
dimension, never two in parallel.

### F1 fix — the enum must be GENUINELY compile-enforced, not just intended to be

Original design claimed "no default member initializer... compile-enforced."
Both reviewers independently found this **false as stated**: `CommandCapability`
rows use designated initializers, and C++ value-initializes any omitted
designated member — an omitted `.execute_gate` silently becomes enumerator `0`
with no compiler error. Fail-open is the worst possible failure mode for an
authorization gate; corrected mechanism, all four parts required:

```cpp
enum class ExecuteGate : uint8_t { Unspecified, None, AdminOrApproval, AlwaysApproval };
```

1. `Unspecified = 0` is the value-initialized default — deliberately NOT `None`,
   so an omission cannot be silently mistaken for an authored "no gate" decision.
2. Each of the six `capability_decls/*.hpp` fragments gets a `consteval`
   sweep + `static_assert` immediately after its `constexpr` array, e.g.:
   ```cpp
   namespace detail {
   consteval bool all_gates_specified(std::span<const CommandCapability> rows) {
       for (const auto& r : rows)
           if (r.execute_gate == ExecuteGate::Unspecified) return false;
       return true;
   }
   } // namespace detail
   static_assert(detail::all_gates_specified(kPluginActionCatalogueA),
                 "every row must author .execute_gate");
   ```
   This is genuinely compile-enforced: a build with an omitted field fails to
   compile, in the same translation unit, at the point of omission.
3. `classify_and_authorize_dispatch` treats `Unspecified` as a classify-miss
   (deny, same as `Unclassified`/`Ambiguous`) — defense in depth in case a
   future seventh fragment source is composed into the registry without
   carrying its own static_assert sweep.
4. Rung 2's CI cross-check independently asserts, over the **live composed
   registry** (not per-fragment source text), that no row's `execute_gate` is
   `Unspecified` — a second, fragment-source-independent layer that also
   catches a hypothetical future fragment omitting its own sweep.

Value derived **strictest-wins** from every shipped definition targeting that
pair: `auto -> None`, `role-gated -> AdminOrApproval`, `always -> AlwaysApproval`.
Content-declared pairs with **no catalogue row at all** (all 42 are
`server`/`server_internal`/`_server`-prefixed — server-side handlers, never
agent-dispatched) are deliberately excluded from this derivation, not silently
skipped: they can never reach `CommandCapabilityRegistry::classify` because
nothing dispatches them to an agent, so `ExecuteGate` is meaningless for them.
Rung 2's cross-check states this rule explicitly so a future `server`-prefixed
catalogue row (should one ever be added) doesn't silently inherit an unstated
exemption.

## Decision 2 — enforcement point

`classify_and_authorize_dispatch` (`agent_registry.hpp:151`), immediately AFTER
the existing `has_permission` check (RBAC `Forbidden` always takes precedence —
approval never substitutes for a missing grant):

```
if (cap.execute_gate == ExecuteGate::AlwaysApproval && caller.approval_provenance == ApprovalProvenance::None)
    -> DispatchDenialReason::ApprovalRequired
if (cap.execute_gate == ExecuteGate::AdminOrApproval
    && caller.approval_provenance == ApprovalProvenance::None && !caller.principal_is_admin)
    -> DispatchDenialReason::ApprovalRequired
if (cap.execute_gate == ExecuteGate::Unspecified)
    -> DispatchDenialReason::Unclassified   // F1 defense-in-depth, see Decision 1
```

The `caller.system == true` arm returns before this (background/system dispatch
stays exempt, as it is for RBAC today). This is the ONE chokepoint every surface
already funnels through (verified: `classify_and_authorize_dispatch` has exactly
one production call site, `server.cpp:10204`), so no second copy of this logic
is written anywhere.

**F3 fix (security) — the new denial reason must be audit-discriminable, not
just metric-discriminable.** `/api/command`'s current denial audit detail is a
flat `reason=dispatch_denied` (`server.cpp:14311-14315`) — the codebase's own
stated rationale for splitting `KillSwitched` from `Forbidden`
(`agent_registry.hpp:87-93`: "an incident review needs to tell the two apart")
applies identically to `ApprovalRequired` vs. `Forbidden`. Rung 3 must carry the
specific denial reason into the audit row on every surface (REST and MCP), not
only into the `yuzu_server_dispatch_denied_total{reason=...}` metric label —
a metric alone is not incident-review evidence.

## Decision 3 — two new DispatchCaller fields, not a role list

```cpp
bool principal_is_admin{false};   // auth::effective_role(session) == admin (JIT-aware)
enum class ApprovalProvenance : uint8_t { None, Ticket, GovernedPipeline };
ApprovalProvenance approval_provenance{ApprovalProvenance::None};
```

Neither is role-shaped; `principal_is_admin` mirrors the same binary check the
governed path already uses (`auth::effective_role`). `principal_role` (string)
is left untouched — it feeds the scope-ladder audit callbacks and changing its
meaning would corrupt audit rows.

**F-fix (security, Decision 5 requirement 1) — provenance is typed, not a bare
bool.** The original `bool approval_satisfied` would read, on a deployment
dispatch, as "this dispatch is provably covered by an existing approval
decision" — false on every deployment stamp, since no `ApprovalManager` ticket
exists for it. `ApprovalProvenance::Ticket` (a real consumed ticket) and
`ApprovalProvenance::GovernedPipeline` (Decision 5's exemption) are distinct
values so an audit reader or future maintainer cannot infer a ticket existed
when it did not.

**`principal_is_admin` stamped at:** `derive_dispatch_caller` (server.cpp,
feeds `/api/command`, `forward_legacy_command`, workflow/dashboard/tar-tree
caller_fn, MCP deriver), `derive_dispatch_caller_for_username` (schedule, new
bool param — **resolved from the auth store at fire time**, matching the
existing fire-time principal re-resolution posture; `false` on any resolution
failure, fail-closed), `deployment_routes.cpp` `caller_from_session`,
`rest_api_v1.cpp` `resolve_secondary_caller`, MCP `quarantine_device` inline
mint.

**`approval_provenance` stamped at exactly three production sites** (deliberately
not at the workflow/governed-execute layer — see Decision 4). **This is a
stated, closed contract**: `DispatchCaller`'s declaration comment must
enumerate all three by name (mirroring how `DispatchCaller::system`'s comment
states its own closed call-site set) so a fourth stamping site is a visible
diff against a documented list, not a silent addition:
1. `ScheduleRunner::dispatch_tracked` — `= Ticket` when firing on an approved
   ticket, `= None` on a direct `auto` fire (the only non-MCP ticket-redemption
   loop).
2. MCP supervised-tier `execute_instruction` / `quarantine_device` callers —
   `= Ticket`, set only post-`consume_ticket`.
3. `DeploymentEngine` / `DeploymentRoutes` content_dist dispatches — `=
   GovernedPipeline` (Decision 5).

**F4 note (security) — the JIT-elevation asymmetry is intentional, stated
here explicitly rather than left implicit.** `principal_is_admin` is JIT-aware
(via `effective_role`); the chokepoint's separate RBAC binder deliberately
resolves only a principal's *base* grants, never JIT elevation
(`agent_registry.hpp:127-139`, a documented pre-existing gap with no citing
issue found in a 2026-08-28 search — filed as follow-up #6 below). This design
makes a decision for the **approval** dimension only (JIT elevation counts) and
leaves the **RBAC** dimension's gap untouched — consistent with the governed
path's own use of `effective_role`, and fail-closed either way. Stated
explicitly so a future reader does not read the asymmetry as an oversight.

## Decision 4 — why NOT per-execution provenance at the workflow layer

The governed path (`workflow_routes.cpp`) and workflow-step pre-gate only ever
dispatch a non-`auto` definition when the caller is effective-admin (both check
`auth::effective_role(*session) == admin` before proceeding) — that's covered
by `principal_is_admin` at the chokepoint with no extra plumbing. Setting
`approval_provenance` per-execution at that layer instead would let a
runtime-authored `auto` definition on an already-gated pair ride through
without ever proving the pair-level control was satisfied — exactly the kind of
hole this gate exists to close. (Verified: the approve route,
`server.cpp:16871-16922`, marks a ticket approved and does NOT itself dispatch
— there is no hidden redemption-dispatch path bypassing the three stamping
sites above.)

## Decision 5 — `/auto` Deploy is a governed surface, not a raw-dispatch bypass

`content_dist.{stage, execute_staged, cleanup, upload_file}` are genuinely
`role-gated` in shipped content (`upload_file`'s definition lives in
`t2_capabilities.yaml`, not `content_dist.yaml` — confirmed by direct parse of
every content file, not just the plugin's own file; `list_staged` is the only
`auto` content_dist action and stays ungated), so their derived gate is
`AdminOrApproval`. `DeploymentEngine` and `DeploymentRoutes` dispatch these
under the real caller's identity (deliberately not `system`, per prior
governance findings on that surface), so a literal reading would block
non-admin `/auto` Deploy advance entirely, with no approval path on that
surface. Security-guardian additionally confirmed the literal alternative is
worse than a policy disagreement: `DeploymentEngine` dispatches after
`claim_for_exec` (execute-once CAS), so a non-admin advance blocked at the gate
would claim the device step and then die there — a state-machine hazard (a
claimed-never-executed run) on top of the product regression.

Decision: the `/auto` Deploy pipeline (`PreflightRunStore` go-cohort computed
under the creator's authority, `DeploymentRunStore`'s guarded one-way
transitions + execute-once CAS, per-tick re-authorization against the viewer's
current scope) **is itself the governance** the gate exists to require — a
mutating, re-authorized, auditable, operator-gated pipeline is not the "any
`Execution:Execute` holder, no oversight" shape #1398 is about. So
`DeploymentEngine`/`DeploymentRoutes` stamp `approval_provenance =
GovernedPipeline` on their content_dist dispatches.

**Three required changes (security-guardian), all now folded in:**
1. Provenance is typed (`GovernedPipeline`, not a bare "satisfied" bool) so it
   cannot be misread as a consumed ticket — see Decision 3.
2. The deployment-stamped dispatch must carry the deployment-run id into the
   audit trail as its justification, so the exemption is per-dispatch
   attributable in an incident review, not a blanket unexplained pass.
3. A follow-up issue is filed for real approval integration on `/auto` Deploy
   (or, alternatively, this substitution is recorded explicitly against
   ADR-1005's "one core-owned approval primitive" ledger as a stated exception)
   — the substitution itself is accepted for this ladder; undocumented
   permanence of it is not. See follow-up list, item 7.

## Decision 6 — legacy-open (RBAC disabled, the shipped default)

The gate still runs. The chokepoint's RBAC callback short-circuits to `true`
under legacy-open (`rbac_enforcement_in_effect` false), but the gate check runs
independently, after it. Under legacy-open the surface-level `require_permission`
floor already requires effective-admin for any non-`Read` operation
(`auth_routes.cpp` legacy fallback), so `AdminOrApproval` is a near-no-op there
(effective-admin was already required to reach the dispatch at all) and
`AlwaysApproval` newly binds admins on raw dispatch — matching the governed
path's existing behavior for `always`-mode definitions. Both reviewers
confirmed this against `auth_routes.cpp:870/1145` with no objection.

## Decision 7 — deny UX: 403 + redirect, no new ticket-mint surface

REST (`/api/command`, `forward_legacy_command`): 403, A4-envelope-shaped JSON
body naming the gate and pointing at `POST /api/instructions/{id}/execute` as
the governed alternative, with the specific denial reason in the audit detail
(Decision 2's F3 fix).

**F fix (security, supersedes original Decision 7 text) — MCP's pre-check must
call the FULL decision function, not a gate-arms-only slice.** The original
design proposed a narrow closure re-implementing "classification + gate arms
only, no RBAC" for envelope shaping. Security-guardian found this would
misreport: a caller who passes MCP's own C7 `Execution:Execute` tier check but
lacks the row's classified securable (e.g. `Infrastructure:Write`) would be
told `ApprovalRequired` by the narrow pre-check when the chokepoint's real
verdict is `Forbidden` — contradicting this design's own stated RBAC-first
precedence at the one surface where it's user-visible. Architect separately
required the closure structurally "call one named function, never
re-implement the two ifs" (the #2500 second-copy pattern this repo has already
been burned by once). Both requirements are satisfied by the same fix:

MCP's pre-dispatch closure calls `classify_and_authorize_dispatch` itself (the
exact function, the exact injected RBAC binder — a pure, side-effect-free,
`noexcept` call) as a dry run before `dispatch_fn`:
- **Deny** → the closure itself emits the audit row (with the real denial
  reason: `Forbidden`, `ApprovalRequired`, etc. — never collapsed to one
  generic label) and the `yuzu_server_dispatch_denied_total{reason=...}`
  metric increment, matching exactly what the chokepoint would have emitted,
  then returns a JSON-RPC error naming that reason. `dispatch_fn` is never
  called, so the chokepoint's own denial path never fires a duplicate.
- **Allow** → proceeds to call `dispatch_fn` as today, which internally
  re-runs the same pure, deterministic function a second time (cheap — no
  I/O beyond the same RBAC read the first call already made) and dispatches.

This keeps the chokepoint as the sole enforcement point (the pre-check cannot
drift from it because it *is* it) while giving MCP a discriminable error
without widening `DispatchFn`'s return type (explicitly out of scope — see
follow-up list, item 3).

No new approval-ticket mint path is added on raw surfaces in this ladder.

## Decision 8 — `executeRoles` is retired, not implemented

It has zero server-side representation today (dropped at build time), its
labels match no seeded RBAC role, and 66 shipped files disagree with each other
per pair. Making it real would mean a new struct field + column, a
label-to-RBAC-role mapping table, and a new "does this principal hold role R"
API atop `RbacStore` (`collect_roles` is private) — while contradicting the
standing doctrine that `CapabilityDeclaration`/`CommandCapability` never carry
role-shaped fields. Both reviewers confirmed this reading of the doctrine and
approved retirement outright, with no required changes. Docs (rung 5) are
corrected to describe it as advisory content metadata; the YAML keys themselves
are left in place (verified inert — `embed_content.py` extracts named fields
only, no unknown-key rejection anywhere) since stripping them from 66 files is
unnecessary churn for this fix.

**ADR-1005 "one core-owned approval primitive" check (architect, confirmed):**
this gate mints no new tickets, redeems only via the existing `ApprovalManager`
flows (`fire_with_approval`, `consume_ticket`), leaves `ApprovalManager` itself
untouched, and extends the single existing dispatch chokepoint rather than
adding a parallel one — the same "extend the one chokepoint, never fork it"
shape ADR-0033 cites as the correct precedent (`dangerous_enforce_in_spec`).
Decision 5's `/auto` Deploy stamp is an exemption assertion on top of that
chokepoint, not a second approval mechanism.

## Verified pair -> gate table

Every claim above was checked against a full parse of all 69
`content/definitions/*.yaml` files (232 definitions, all `plugin.action` +
`approval.mode` pairs — the files are multi-document YAML streams, one
definition per `---`-separated document). The complete post-remap table (214
pairs) is committed at `tests/fixtures/1398_pair_gate_table.json`; rung 2's
`ExecuteGate` authoring (the 184 `.execute_gate = ...` values across the six
`capability_decls/*.hpp` fragments) was derived from this table mechanically.

**Correction (governance Gate 4 consistency-auditor finding, folded in
2026-08-28):** the sentence this replaced additionally claimed the CI
cross-check (`tests/test_capability_gate_consistency.py`) "derive[s] from this
same table" — false as shipped. The script never reads the fixture
(`grep -rn "1398_pair_gate_table" tests/test_capability_gate_consistency.py`
returns nothing); it independently re-parses `content/definitions/*.yaml` and
the six fragments fresh on every run, which is actually the STRONGER
guarantee (a fixture can go stale; a live parse cannot) but is a different
mechanism than authoring claimed, and means the fixture today has no
consumer except a human re-deriving it by hand. Either wire the fixture in as
a golden-file comparison or accept it as authoring-time scaffolding only —
undecided, not blocking. Rung 2 must also replicate
`embed_content.py`'s exact mode-defaulting semantics (`approval.get("mode") or
"auto"`, `embed_content.py:69,89`) so a definition with no `approval:` block
derives `auto` identically in both places (architect requirement). Headline
counts, restricted to pairs with a real agent-dispatch surface (the 42
`server`/`server_internal`/`_server`-prefixed pairs are server-side only,
excluded by construction per Decision 1):

- `AdminOrApproval`: **42 pairs** (verified — matches the design's earlier
  estimate exactly): `certificates.delete`, `chargen.chargen_start`,
  `content_dist.{stage,execute_staged,cleanup,upload_file}`,
  `discovery.scan_subnet`, `filesystem.{append,create_temp,create_temp_dir,
  delete_lines,find_by_hash,replace,write_content}`, `http_client.download`,
  `installed_apps.list_per_user`, `interaction.{input,message_box,notify,
  set_dnd,survey}`, `network_actions.{flush_dns,ping}`,
  `quarantine.{quarantine,unquarantine,whitelist}`, `rdp_control.set_state`,
  `registry.{delete_key,delete_value,get_user_value,set_value}`,
  `script_exec.{bash,exec,powershell}`, `services.set_start_mode`,
  `storage.{clear,delete,set}`, `tags.clear`, `tar.configure`,
  `wol.{wake,check}`.
- `AlwaysApproval`: **0 agent-dispatched pairs** — all 11 genuinely-`always`
  pairs (`policy.delete`, `policy.invalidate_all`, `product_pack.uninstall`,
  `workflow.delete`, the two `webhooks.*`, both `directory_sync.*`, both
  `patches_*`, `create_deployment_job`) are `server`/`server_internal`/
  `_server`. Confirms the "shipped AlwaysApproval set is empty" claim,
  independently re-verified by security-guardian (grepped for any non-YAML
  executor of `list_deployment_jobs`/`create_deployment_job`: zero hits) — the
  enum arm is implemented for future content, exercised only in unit tests
  until a plugin-dispatched definition uses it.
- No pair has conflicting modes across its definitions (0 of 214).
- Row count (184 across 45+55+34+42+5+3 in the six fragments) and the
  20-invalid-definition count (18 `manual` + 2 `none`) both independently
  reproduced by architect's own audit — exact match.

## Content remap (rung 1, 20 definitions currently outside the valid
`{auto, role-gated, always}` vocabulary)

Both previously-pending rows are now **approved by both reviewers** (security:
verified `list_jobs` inert — no catalogue row, no executor anywhere; verified
`set_dnd`'s `none` invalid and sibling-consistent with the other 4 interaction
actions).

| pair(s) | current (invalid) | -> new | effect |
|---|---|---|---|
| `interaction.{notify,message_box,input,survey,set_dnd}` | manual / none | role-gated | raw dispatch: admins keep it, non-admins gated. **Governed path (security F-finding): today `manual`/`none` are unknown modes and the governed-path pre-gate fails closed for EVERYONE including admins (`workflow_routes.cpp:1743-1748` binds only the `role-gated` branch's admin bypass, not the unknown-mode branch) — these 5 defs are currently unexecutable via `/api/instructions/:id/execute` at all. The remap makes them executable there again, for admins.** |
| `network_actions.{flush_dns,ping}` | manual | role-gated | same dual effect as above |
| `wol.{wake,check}` | manual | role-gated | same dual effect as above |
| `discovery.scan_subnet` | manual | role-gated | same dual effect as above |
| `chargen.chargen_start` (testing plugin) | manual | role-gated | same dual effect; keeps `/api/chargen/start` usable by admins |
| `tar.configure` | manual | role-gated | same dual effect; keeps tar-tree capture-source config usable by admins |
| 7 `server`/`server_internal` defs (webhooks x2, deployment create_job, directory_sync x2, patch_management x2) | manual | always | no dispatch surface (server-side only) — zero behavior delta on raw dispatch; same governed-path fail-closed-for-everyone status is UNCHANGED (`always` still requires approval for all, matching intent) |
| `server.deployment.list_jobs` | none | auto | read-only listing, server-side only, verified inert |

**Framing correction (security F-finding):** every `manual`/`none` -> `role-gated`
row above is simultaneously a raw-dispatch **tightening** (non-admins newly
gated, closing #1398's shape) and a governed-path **widening** for admins
(parked-forever-pending -> direct execute). It converts a broken state rather
than removing a working control, but both effects are named here explicitly
for the rung-1 sign-off record, not just the raw-dispatch half.

## Bonus closure worth naming to reviewers

`script_exec.{exec,powershell,bash}` classify as bare `Execution:Execute` — the
existing `/api/command` "Destructive" elevation block (a parallel, narrower
mechanism, out of scope for this ladder) re-checks a permission the base gate
already granted, so today an `Execution:Execute`-only, non-admin principal can
already raw-dispatch arbitrary script execution with no additional control.
Because these three pairs are genuinely `role-gated` in shipped content, this
ladder's `AdminOrApproval` gate closes that hole as a side effect for non-admin
callers, on top of closing the definition-approval bypass the issue is about.
Independently re-verified by security-guardian against
`plugin_action_catalogue_d.hpp:286-312` and `content/definitions/script_exec.yaml`.

## `executeRoles` audit — does retiring it silently drop any live control?

Spot-checked the two `auto`-mode-but-`executeRoles`-declaring plugins raised
during review: `firewall.{state,rules}` and `bitlocker.state` are all
classified `Security:Read`, Low/Medium risk, `ReadOnly` dispatch class — no
mutation capability exists for either plugin today (`firewall`'s `actions()` is
exactly `{state, rules}`; `bitlocker` has one action, a status query). Retiring
`executeRoles` drops no live restriction for these two — independently
re-confirmed by security-guardian. Rung 2's CI cross-check script additionally
emits the full table of every `auto`-mode pair with a content `executeRoles`
declaration, so the complete picture is available before merge, not just this
spot check.

## What this ladder does NOT do (filed as separate follow-up issues)

1. Fix the `/api/command` Destructive-class elevation block (fail-open on a
   classify miss, no-op elevation for `Execution:Execute` rows, no MCP
   targeting-confinement parity, untested — relates to #2557). Filed as
   **#3685**.
2. Close the chokepoint's JIT-elevation gap (`agent_registry.hpp:127-139`
   binder resolves only base grants; its own comment says "Tracked" but named
   no issue — a search on 2026-08-28 found no existing tracking issue). Filed
   as **#3684**.
3. Widen MCP's `DispatchFn` return type for richer programmatic denial
   discrimination beyond what Decision 7's pre-check closure already provides
   (an in-code follow-up note already flags the underlying limitation). Filed
   as **#3687**.
   **2026-09-02 follow-up:** #3687 shipped a NARROWER fix than this item's
   own title describes — a pre-dispatch dry-run closure (the same shape as
   Decision 7's own `execute_instruction` pre-check, generalized via a shared
   `dispatch_pairs_for(tool_name, args)` registration point to
   `execute_bundle` and `quarantine_device` too, PR #3893), not a literal
   `DispatchFn` signature widening. This is a deliberate choice, not a
   shortfall — it matches Decision 7's own "do NOT widen `DispatchFn`"
   constraint and covers every dispatch-capable MCP tool's denial
   discrimination without the larger refactor a signature change would need.
   No separate literal-widening issue is filed as a successor; #3687's own
   acceptance criteria are satisfied by the narrower approach, and nothing
   currently blocked on the wider signature.
4. **RETRACTED — this item was itself wrong, twice.** The original ladder text
   ("thread a full `DispatchCaller` through `BundleOrchestrator`") was
   corrected during Rung 0 review to claim no follow-up was needed, on the
   grounds that `BundleOrchestrator::DispatchFn` already carries the full
   `DispatchCaller`. That correction conflated the TYPEDEF (genuinely already
   widened, PR1.9c) with `BundleOrchestrator::dispatch()`'s own METHOD BODY,
   which reconstructed a per-step `DispatchCaller{.principal, .exec_visible}`
   carrying neither `principal_is_admin` nor `approval_provenance` — so an
   admin's (or a ticket-holding supervised MCP caller's) bundle step on any
   `AdminOrApproval`/`AlwaysApproval` pair was refused `ApprovalRequired`
   unconditionally, with no way to satisfy the gate via this surface at all.
   **Found independently by both adversarial-review external reviewers
   (Kimi + Codex, 2026-08-28), confirmed against the code, and fixed** —
   `dispatch()` now accepts and threads both fields (`bundle_orchestrator.hpp`/
   `.cpp`), both REST (`rest_api_v1.cpp`) and MCP (`mcp_server.cpp`)
   `execute_bundle` handlers pass their already-derived caller values through,
   and the stale `server.cpp` comment this same review round flagged is
   corrected alongside. New coverage: `tests/unit/server/test_bundle_orchestrator.cpp`
   and the REST/MCP `execute_bundle` test suites assert an admin's/
   ticket-holder's gated-pair step now dispatches. This is the second
   design-doc claim in this file shown false by the same review round (see
   the sign-off table's corrected Decision 7 row) — both were claims about
   implementation state made during the Rung 0 revision pass that outran what
   was actually verified at the time.
5. Any new ticket-mint surface on raw dispatch (deny+redirect only, per
   Decision 7).
6. Interactive-REST ticket redemption (approve -> subsequently execute) for an
   `always`-mode definition — pre-existing gap, made slightly more visible now
   that the pair-gate exists; the shipped `AlwaysApproval` set is empty after
   this remap, so it stays latent.
7. **NEW (security-guardian, Decision 5 requirement 3):** real per-dispatch
   approval integration for `/auto` Deploy's content_dist actions — this
   ladder accepts the existing Deploy pipeline as a substitute governance
   surface (Decision 5); a follow-up issue tracks whether/when that
   substitution should be upgraded to an explicit ticket, or formally recorded
   as a permanent ADR-1005 ledger exception instead. Filed as **#3686**.
8. **NEW (both reviewers, F2):** a runtime-authored `role-gated`/`always`
   definition targeting a pair whose *compiled* gate is `None` is enforced on
   the governed path but stays unenforced on raw dispatch until rung 4's
   import-refusal check ships (rung 4 refuses importing/creating a definition
   stricter than its pair's compiled gate — once live, this residue closes for
   any catalogue-backed pair). Between rung 3 landing and rung 4 landing, this
   is a real but narrow window, identical in shape to #1398 itself but scoped
   to newly-authored content rather than the 232 shipped definitions this
   ladder covers. Named explicitly rather than left implicit; rung 4 should
   ship promptly after rung 3, not be deferred indefinitely.
9. **NEW (security-guardian, F10):** user-facing docs correction beyond rung
   5's `executeRoles` retirement — `docs/mcp-server.md`'s operator-tier
   description ("auto-approved executions") becomes inaccurate for the 42
   gated pairs; a non-admin operator-tier MCP token loses those pairs on
   `execute_instruction` unless the definition is dispatched via a
   supervised-tier ticket instead. Fold into rung 5.
10. **NEW (governance Gate 4 consistency-auditor, 2026-08-28 hardening
    round):** the inverse of item 8 — an `auto`-mode definition targeting a
    pair whose compiled gate is `AdminOrApproval`/`AlwaysApproval` *because a
    sibling definition on that pair is stricter* is denied `ApprovalRequired`
    at governed-path dispatch too, even though its own `approval_mode` says
    no approval is needed (see Decision 1's correction above — the pair floor
    is not scoped to raw dispatch). Zero shipped definitions hit this today
    (verified by the rung-2 cross-check: no pair has both an `auto` and a
    stricter sibling), so it is latent, not live — but nothing prevents a
    future runtime import from creating one, and rung 4's planned
    import-refusal check (item 8) only catches a definition *stricter* than
    its pair, not one *looser* than a stricter sibling. A complete fix needs
    a second import-time check: refuse importing/creating an `auto`-mode
    definition on a pair whose compiled gate is already
    `AdminOrApproval`/`AlwaysApproval`, or accept the surprise and document it
    as intentional defense-in-depth. Undecided; not blocking this ladder.

## Sign-off record

Both reviews complete, both **APPROVE WITH CHANGES** (2026-08-28); no OBJECT
on any item. All required changes are folded into this revision:

| Item | Reviewer | Verdict | Status |
|---|---|---|---|
| Decision 1 mechanism (pair-gate home) | architect | APPROVE | — |
| F1 — genuine compile enforcement | architect + security | required change | folded in (Decision 1) |
| Decision 2 enforcement point / precedence | architect + security | APPROVE | — |
| F3 — audit-discriminable denial reason | security | required change | folded in (Decision 2, 7) |
| Decision 3 (two caller fields, no workflow-layer provenance) | architect + security | APPROVE | — |
| F4/F5 — JIT asymmetry stated, fire-time admin-bit resolution | security | required change | folded in (Decision 3) |
| stamping-site closed-contract comment | architect | required change | folded in (Decision 3) |
| Decision 5 (`/auto` Deploy provenance) | security | APPROVE WITH CHANGES | folded in (typed provenance, run-id audit, follow-up #7) |
| Two content remaps (`set_dnd`, `list_jobs`) | architect + security | APPROVE | table updated, no longer "pending" |
| manual->role-gated dual-effect framing | security | required change | folded in (remap table) |
| Decision 6 (legacy-open) | architect + security | APPROVE | — |
| Decision 7 (deny UX) | architect + security | required change | REST half folded in (Decision 2's F3 fix — the specific `ApprovalRequired` message + audit reason on `/api/command`). **Correction (2026-08-28, adversarial review):** the MCP pre-dispatch closure this row originally claimed was "folded in" was NOT implemented — `mcp_server.cpp` has no `classify_and_authorize_dispatch`/`build_classified_command` call. The chokepoint still enforces correctly via the existing `dispatch_fn` path (not a security gap), but a denied MCP caller today gets a misleading success-shaped `no_agents_reached` response and a phantom cancelled execution row instead of a discriminated error. This is genuinely Rung 4 work — see "What this ladder does NOT do" below — the doc was simply wrong to mark it done here. **Follow-up (2026-09-02, #3687):** the MCP pre-dispatch closure this row's correction found missing has now shipped — `mcp_server.cpp`'s `execute_instruction` handler calls a pre-dispatch `AuthorizeDispatchFn` (composing `classify_and_authorize_dispatch` + the kill-switch check) before `dispatch_fn`, and a denied caller gets a discriminated JSON-RPC error, not `no_agents_reached`, with no execution row created. This closes the gap the 2026-08-28 correction above describes; that correction is left as-written as the historical record of what was found. |
| Decision 8 (`executeRoles` retirement) | architect + security | APPROVE | — |
| Rung-2 CI cross-check structure | architect | required change | folded in (parse-integrity assertion, embed_content.py semantics match) |
| Follow-up #4 (BundleOrchestrator) | architect + security | doc correction | folded in — claim was stale, corrected |

**Cleared to proceed to rung 1.**
