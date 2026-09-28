---
status: proposed
date: 2026-09-02
owner: Dave Rae
deciders: Dave Rae (pending -- numbered ADR-1008, committed for /governance review, not yet
  through it; see Binding status below)
scope: server -- target access-control architecture for RBAC + Management Groups
depends-on: ADR-0017, ADR-0033, ADR-1006 (this document's decisions must compose with, not
  re-decide, the frozen contracts in these three)
context-refs: ADR-0006, ADR-0031 (presentation-core-engine-decomposition), ADR-0032, ADR-0041,
  ADR-0042, ADR-1005, docs/auth-engine-principals-design.md,
  docs/enterprise-readiness-soc2-first-customer.md (Workstream B), #388, #480, #1362, #1453,
  #1496, #1715, #1836, #1842, #2485, #2665, #2670, #2677, #2721, #2809, #3290, #3489
supersedes: nothing (net-new target-architecture record; ADR-0017/0033/1006 remain the accepted
  contracts this one builds forward from)
---

# ADR-1008 -- RBAC and Management Groups: target access-control architecture

## Binding status

**Proposed, not accepted.** Numbered ADR-1008; committed to the repo for `/governance` review;
not yet through it. Written in the repo's ADR shape to be evaluated as one before any decision
to accept it. If accepted, it binds **prospectively**: the "not yet built" and "non-conformance"
items below become the acceptance bar for calling this subsystem complete, not a retroactive
claim that today's code already violates a rule that didn't exist yet.

All eleven decisions (D1-D11) are decided by Dave. D6's Guardian extension is the sharpest
instance of this document exercising its own judgment rather than reading an existing ADR
directly (applying ADR-0032 Decision 7's credential-recheck mechanism to Guardian, which no
accepted ADR names -- see D6's own opening for the reasoning), but it is not the only one: D5
reasons by the same kind of analogy when extending ADR-1006 Decision 2's rationale to a third
confinement mechanism, and this document names that explicitly in Rejected Alternatives rather
than pretending D6 is unique in needing this. Five independent read-only reviews were run against successive
drafts before reaching this text (Codex/Sol twice, two independent Fable passes, and a two-model
adversarial review with cross-examination); the full history, including several corrections to
earlier framings of D6, is preserved under Governance below for anyone who wants to see how this
text was arrived at. It is not restated in the decision text itself.

What remains before this can be proposed as a real, numbered ADR and pushed: the standard
`/governance` pipeline this codebase requires of every change, and -- separately -- the fact that
D6 describes a mechanism that does not exist in code at all yet (D1-D5 and D7-D11 are, by
contrast, mostly gaps in an otherwise-working system). Neither of those is a design question;
both are the ordinary next steps for any accepted architecture decision.

## Context

Yuzu's RBAC (`RbacStore`) and Management Groups (`ManagementGroupStore`) subsystems have grown
two very different depths. The **enforcement plane** -- the chokepoints that decide whether a
request is admitted and what it can see -- is mature: a Postgres-backed store with fail-closed
boot and deny-on-degrade semantics (ADR-0041/0042), a frozen cross-boundary precedence lattice
(#1715), an admit-then-filter list-read chokepoint with twelve pinned invariants (ADR-0017), a
default-deny posture for service-scoped credentials (ADR-1006), and a shipped non-human
principal class (engine principals, ADR-1005 §5). Several hundred `TEST_CASE`s exist across the
auth/rbac/scope/authz test files (`rg --files tests/unit | rg '(auth|rbac|scope|authz)' | xargs
rg -n "TEST_CASE" | wc -l` -- re-run this rather than trust a hardcoded number here, which two
prior drafts already got wrong in different directions), including a property test for
visible-set/scoped-check
equivalence.

The **administration plane** -- how an operator actually configures any of this -- is
essentially unbuilt. `RbacStore::set_rbac_enabled`, `create_role`, `set_permission`, and
`remove_permission` have zero production callers on `origin/dev`; no REST route, MCP tool, or
Settings UI fragment can enable RBAC, create a custom role, or grant a human principal anything
beyond `Operator`/`Viewer` at a management-group scope. `POST /api/v1/rbac/check` calls the raw
global permission check and diverges from every real gate's actual decision -- notably it never
consults `auth::is_elevated`, so a JIT-elevated caller currently gets a *false negative* from
`check`. The product manual documents an enable toggle and a Settings matrix that do not exist
(`docs/user-manual/rbac.md`).

A third, more fundamental gap sits underneath both: the RBAC securable-type catalogue
(`rbac_store.cpp` `types[]`, 26 entries) does not contain `Directory`, `Patch`, `Workflow`,
`ProductPack`, or `Server` -- five securables that live route handlers already gate on
(`discovery_routes.cpp`, `workflow_routes.cpp`, `mcp_server.cpp:3468`). Because
`role_permissions.securable_type` carries a foreign key into `securable_types(name)`, no
permission on an unseeded type can ever exist, so **enabling RBAC today would 403 every
non-elevated principal on every route gated by one of those five securables** -- an
elevated/admin session survives via the `is_elevated` short-circuit, but no ordinary grant ever
could. This was found while reviewing an earlier draft of this document and independently
verified twice (Codex/Sol, then Fable) against `origin/dev`.

Management Groups share the same enforcement-ahead-of-operability shape: the hierarchy,
service-tag-derived dynamic groups, and the descendant-ward visible-set expansion are built and
tested, but the legacy role-existence visibility resolver (`get_visible_agents`) still coexists
with the ADR-0017 permission-specific resolver at 7 call sites, dynamic membership only
evaluates at group creation and never on a later write to an already-existing group (tracked
in-code as governance finding UP-5, and the code's own comment at that call site currently
*misdescribes* its own behavior -- a documentation-truth defect independent of the functional
gap), and group reparenting has a non-atomic check-then-write window (#1362).

This document is not a bug list. It states, as decisions, what "done" looks like for this
subsystem, splitting two distinct kinds of gap that the codebase's own severity model
(CLAUDE.md's derived-severity discipline) already treats differently:

- a **defect** -- a rule this document states that the current code actively violates or that
  makes the system incorrect once a precondition is met (D1, D2's escalation hole, D8's
  divergence from the real gate); and
- **not yet built** -- a capability this document requires that simply does not exist yet and
  is not claimed to (D10, D11, most of D3-D9's forward-looking clauses).

Both matter equally for calling this subsystem gold-standard; only the first should be read as
"this is already wrong."

## Decision

Eleven architectural decisions, D1-D11. An earlier draft separately numbered a twelfth,
explainability; its content is folded into D9 (cross-referenced there) rather than kept as its
own heading, since D7 (which does keep its own heading) names a distinct non-human-attenuation
requirement but the former D12 does not -- it is entirely implemented via D8/D9's primitives. See
the Governance log for this and an earlier, now-fixed decision-count arithmetic error.

### D1 -- The securable catalogue is one source of truth, enforced at every gate, not just tool registration

Every securable string reaching `require_permission` / `require_scoped_permission` /
`authorize_list_read` / `require_fleet_read` / a REST `perm_fn` / an MCP `resources/read` call /
a declared MCP tool's permission MUST be a member of `RbacStore::list_securable_types()`, with
no second, hand-maintained mirror of that list anywhere in the codebase.

Partial coverage already exists and this decision extends it rather than starting from zero:
`McpServer`'s constructor validates every `kToolSecurity` row against a catalogue at boot
(`validate_tool_security_registration`), and a binding test pins that catalogue against
`RbacStore`'s. **That existing catalogue (`kRbacSecurables` in `mcp_server.cpp`) is itself a
second, hand-maintained mirror of `types[]` and is a non-conformance with this decision as
stated -- it must collapse into a single source, not be joined by a third.** The coverage gap
this decision actually closes is everything the tool-registration validator does not reach: the
direct `perm_fn`/`require_permission`/`scoped_perm_fn` call sites in REST and dashboard routes,
and MCP's `resources/read` path (which is exactly where the live, unseeded `"Server"` securable
was found). Add a contract test enumerating every such call site's literal securable string and
asserting catalogue membership; fail the build otherwise.

This decision is a bridge to ADR-0033 §2's already-accepted direction: securables become
runtime-registrable data via a capability-declaration registry, with "undeclared means the
capability does not register on any surface" as the terminal rule. Until that registry exists,
D1's contract test is the enforcement mechanism; once it exists, the registry subsumes it.

*Non-conformance (defect) today:* `Directory`, `Patch`, `Workflow`, `ProductPack`, `Server` are
gated live and are not seeded, so no ordinary (non-elevated) grant can ever cover them. The
`kRbacSecurables` mirror exists and has not been collapsed. REST/dashboard call sites and MCP
`resources/read` have no catalogue-membership check.

### D2 -- Enabling and disabling RBAC is atomic, escalation-safe, and cannot produce zero active Administrators

Enabling RBAC verifies, in the same transaction, that at least one active, authenticatable human
principal holds `Administrator` globally, before the toggle commits. Where none exists, the
system may create that grant for the enabling operator -- but **only when the enabling
operator's current session already holds the legacy `admin` session role** (via
`auth::effective_role`), and that self-grant is itself an audited, named bootstrap event
distinct from an ordinary assignment. Without that condition, the enable endpoint is a
privilege-escalation path for anyone holding only `UserManagement:Write`: they could enable
RBAC and be self-granted `Administrator` regardless of their actual standing authority.
Disabling RBAC is symmetric: audited, MFA-stepped-up, reversible. A failed transaction is
reported to the caller (`set_rbac_enabled`'s current `void` return must change to support this).

**"Cannot produce zero active Administrators" must hold on an ongoing basis, not only at enable
time (PR review finding, @fjarvis).** As first written, this decision's mechanism only guarded
the moment RBAC is switched on; nothing guarded a later revocation, once RBAC is already enabled,
that drops the last active Administrator to zero -- the heading's claim was broader than the
mechanism delivered. This decision closes that the same way it closes every other escalation-
safety gap: through the existing chokepoint, not a second bespoke check. `validate_assignment`
(D3) must refuse a revocation or role edit that would leave zero active, authenticatable human
principals holding `Administrator` globally, the same class of check D2 already requires at
enable time, now required at every subsequent write through the same chokepoint rather than
only at the one moment this decision originally named.

**The self-grant branch's own precondition needs the same discipline as the Administrator check,
not a different one (Gate-5 governance finding).** The row-lock/`SERIALIZABLE` requirement added
below closes the race on the Administrator-existence check, but the self-grant branch gates on a
DIFFERENT fact -- "the enabling operator's current session already holds the legacy `admin`
session role" -- read via `auth::effective_role(session)`, which resolves against an in-memory
session cache bounded by `kSessionGenStaleServeBoundMs` (30s), not a transactional read of the
durable store. A concurrent revocation of the enabling operator's `admin` role landing inside
that staleness window is invisible to a Postgres row lock or `SERIALIZABLE` isolation level on a
different table entirely -- those primitives cannot reach a stale in-memory session. This
decision therefore requires the self-grant branch to re-verify the operator's admin standing
against the DURABLE store (not the session cache) inside the same locked/serializable transaction
as the Administrator-existence check and the toggle write, before creating the bootstrap grant.

**"Same transaction," named (Gate-2 governance finding):** the Administrator-existence check
spans two currently separate stores -- the grant lives in `RbacStore`, the human's active-account
status lives in `AuthDB` -- and neither exposes a joint transaction primitive to the other today,
even though both are constructed over the same underlying Postgres pool. This decision requires
building one (e.g. the enable transaction takes its connection from whichever store owns the
other, rather than two sequential, non-transactional reads); it is not a detail D2 can leave
implicit, because a non-transactional version of this check reopens exactly the zero-active-
Administrators race this decision exists to close. **"Same transaction" alone is not sufficient
under ordinary `READ COMMITTED` isolation (Gate-4 governance finding):** a concurrent,
independently-ordinary deactivation of the checked Administrator can still commit between the
read and the toggle-write unless the read takes a row lock on the checked account (or the
transaction runs `SERIALIZABLE` with retry-on-conflict) -- this decision requires one of those
two, not merely a shared transaction boundary with unspecified isolation.

*Non-conformance (defect) today:* no code path can enable RBAC at all (#388); `set_rbac_enabled`
cannot report failure to a caller. *Not yet built:* the bootstrap-grant conditioning, the
cross-store transactional check, and the audit event described above have no code to violate
them yet, precisely because no enable path exists -- they are binding on whatever implements D2,
not a claim about current behavior.

**Delivery note (A1, 2026-09).** The `#388` non-conformance above is now CLOSED for the enable
path: `PUT /api/v1/rbac/enforcement` + the `set_rbac_enforcement` MCP tool ship an atomic,
same-transaction, row-locked enable/disable toggle (`RbacStore::set_rbac_enforcement`), and
`set_rbac_enabled` now returns `std::expected<void, std::string>` (kept as a deliberately
UNGUARDED seed/test primitive for the ~70 existing test call sites that need it, never called
from a route or MCP handler). The cross-store transactional check this decision calls for is
built: the guard runs inside `RbacStore`'s own transaction, over the SAME row-locked
`principal_roles JOIN auth.users` set (`FOR UPDATE OF pr`) `unassign_role`'s (D3's) own
last-Administrator guard takes -- one shared fragment, not two copies -- closing exactly the
race this section's Gate-4 finding describes for the checked-Administrator-account case. Three
narrow, deliberate deviations from the literal decision text above, each with its own tracked
follow-up rather than silently left unstated:

1. **No self-grant bootstrap.** The shipped guard is *caller-inclusive* (the transition is
   refused unless the CALLER would remain a durable administrator under the destination regime)
   rather than *self-granting* (minting a fresh Administrator grant for an `admin`-session
   caller who lacks one). A caller who fails the guard is refused with a remediation naming the
   exact assignment call (`assign_rbac_role` / `POST .../roles/Administrator/assignments`) rather
   than having standing authority minted on their behalf. This is a stricter posture than D2's
   self-grant branch, not a weaker one -- it never mints authority nobody asked for -- but it is
   a genuine deviation from the literal text above; the self-grant branch (and the fresh
   staleness/precondition hazards Gate-5 raised against it) is not built.
2. **No `auth.users` row lock under the toggle's own transaction.** D2's "same transaction, same
   isolation" requirement is satisfied for the `principal_roles` side (the `FOR UPDATE OF pr`
   lock above); the disable direction's `auth.users.role='admin'` read is a single, lock-free
   snapshot, matching `unassign_role`'s own no-lock parity with `auth.users` (locking it would
   serialize unrelated logins/role-changes). The residual -- a concurrent deactivation/demotion
   of the checked account landing between the read and the toggle's commit -- is the SAME ongoing
   case D2's own "cannot produce zero active Administrators... not only at enable time" clause
   flags, tracked as [#4966](https://github.com/Tr3kkR/Yuzu/issues/4966) and Priority C item 4.1
   (a joint-transaction primitive), not closed by this delivery.
3. **MFA step-up is the existing `require_mfa_step_up` policy, not a fresh, uniform proof.** The
   REST route calls `step_up_fn` exactly where A2's role-assignment route does; the MCP tool
   carries no step-up call at all (supervised-tier approval instead). Because `api_token`/
   `mcp_token` sessions are exempt from `require_mfa_step_up` (token issuance is treated as the
   step-up moment) and approval is an authorization control, not an MFA proof, the toggle is not
   uniformly MFA-gated across every principal class today -- tracked as Priority C item 4.1 ("MFA
   step-up design for admin actions"), not a defect introduced by this delivery.

**Delivery note (fresh-install bootstrap, 2026-09-28).** A second, narrower gap closes alongside
A1's, and is a NEW DECISION, not a deviation from A1's delivery note above -- it supersedes
nothing there. A1's delivery closed the enable-path escalation guard for an OPERATOR who is
already authenticated and holds a session. It did not, and could not, address a genuinely FRESH
install: `rbac_enabled` seeds `'false'` today, and before this delivery there was no way for a
fresh install's first operator to end up with a durable RBAC Administrator grant, so flipping the
seeded default to `'true'` would have locked out the first admin entirely -- every RBAC-gated
route, including the assignment routes A1 ships, requires a durable grant that nothing existed to
create at that point.

This delivery closes that. `RbacAdminAuthorityOwner::provision_first_admin`
(`rbac_admin_authority_owner.hpp:130-163`, `.cpp:596-671` -- the THIRD `RbacAdminAuthorityOwner`
consumer, same delegation shape as `unassign_role`/`set_enforcement` above) inserts the
configured admin's `auth.users` row -- the exact `WHERE NOT EXISTS (SELECT 1 FROM auth.users)`
shape `AuthDB::seed_admin_if_empty` uses, under the SAME `kSeedAdminLockSql` advisory lock
(auth_db.cpp:154) -- and grants that account `Administrator`, atomically in one transaction, ONLY
when `auth.users` is genuinely empty; `RbacStore::provision_first_admin`
(`rbac_store.hpp:472-489`, `.cpp:2156-2179`) is the thin public wrapper, mirroring
`unassign_role`'s/`set_rbac_enforcement`'s own delegation pattern exactly. `main.cpp`'s
fresh-start seed block (`main.cpp:1449-1547`) calls this BEFORE `AuthDB::seed_admin_if_empty`
-- not merely "also", and not after -- because the ordering is forced, not a style choice:
whichever of the two INSERTs runs second can never see auth.users empty (the first one already
committed a row), so the account+grant must be created by `provision_first_admin`'s own INSERT,
in ONE transaction, so a crash between account-creation and grant-creation can never strand an
account with no grant and no later boot able to fix it (the table would no longer be empty).
`seed_admin_if_empty` stays in `main.cpp` for its unrelated role there (the break-glass paths
further down reference `auth_db` directly) but is now a guaranteed no-op in production.

**The seeded-default flip itself is DEFERRED, not shipped in this delivery.** The bootstrap above
makes flipping `rbac_store.cpp`'s seeded-default literal from `'false'` to `'true'`
MECHANICALLY safe on its own (`ON CONFLICT (key) DO NOTHING`, `rbac_store.cpp` ~532-548, means it
would only ever take effect on a database that has never run this code before -- an
existing/upgrading install's row is already written and untouched by this INSERT, structurally
unaffected either way). Attempting the flip surfaced that a large, separately-scoped swath of the
EXISTING test suite implicitly depends on a freshly constructed `RbacStore` seeding `'false'`,
rather than setting the flag explicitly where a test actually needs it off -- 64 of 331 test
cases (115 of 6260 assertions) failed across `test_rbac_role_assignment.cpp`,
`test_rbac_store.cpp`, `test_rbac_enforcement_toggle.cpp`, `test_engine_principal_integration.cpp`
and `test_list_read_confinement.cpp` with the flip applied, in at least two distinct shapes: (1) a
harness gap -- `RbacRoleHarness::make_caller_admin(bool rbac_on)`
(`tests/unit/server/test_rbac_admin_surface_harness.hpp:366-389`) sets `rbac_enabled` explicitly
only on its `rbac_on=true` branch, silently relying on the (now-wrong) seeded default for
`rbac_on=false`; and (2) at least one test whose entire premise IS the invariant this delivery
changes -- `tests/unit/server/test_rbac_store.cpp:524-527`, literally named
`"RbacStore: RBAC disabled by default"`. Bringing that suite up to date -- and deciding, test by
test, which of those two shapes (or another) each failure is -- is its own scoped, reviewed
change, deliberately not absorbed into this delivery; `rbac_store.cpp`'s seeded-default literal
stays `'false'` until that follow-up lands.

D2's own original text already anticipated exactly this shape -- "that self-grant is itself an
audited, named bootstrap event distinct from an ordinary assignment" (paragraph above) -- but the
two are materially different mechanisms, not two readings of the same one, and this delivery does
not reopen A1's own deviation 1 ("No self-grant bootstrap"). A1's self-grant, had it been built,
would be a RUNTIME grant tied to an already-authenticated operator's OWN session and their own
toggle action, carrying that path's session-cache-staleness hazards -- the exact ones Gate-5
raised against it (paragraphs above, "The self-grant branch's own precondition needs the same
discipline..."). This delivery is a BOOT-TIME, SESSION-LESS, single-transaction mechanism that
runs before the server ever accepts a request -- no session, no cache, no caller to stale-read,
and no toggle action at all (RBAC is never switched on by an operator here; the seeded-default
flip, when it lands -- deferred in this delivery, see above -- will ship a fresh database already
on with no operator toggle involved). A1's three deviations above (no self-grant bootstrap; no `auth.users` row
lock under the toggle's own transaction; MFA step-up posture) all stand exactly as A1 left them,
unaffected by this delivery.

Observability: a fresh-install provision is logged once, at `spdlog::warn` level (folded into the
existing "AUTH DATA RESET ON POSTGRES CUTOVER" line rather than a second, separate warning for
what is now one event -- `main.cpp:1517-1525`); `Config::auth_fresh_start_seeded` (and the
`yuzu_auth_fresh_start_reset_total` counter it drives, `server.cpp:3130-3163`) is now sourced from
`provision_first_admin`'s outcome rather than `seed_admin_if_empty`'s, since the former is the
operation that actually performs the fresh-start INSERT in production now -- the counter's own
documented contract ("1 iff this boot seeded the sole admin user into an empty auth.users table")
is unchanged, only which call detects the event. No real `audit_store` row is written for this
event: `main.cpp` has no `AuditFn` audit callback available this early in boot (confirmed against
`AuditStore::log()`, which always self-acquires its own pool lease with no connection/transaction
-scoped write API to fold into `provision_first_admin`'s transaction) -- a deliberate, reviewed
scope boundary for this delivery, not an oversight; a durable audit record for this specific event
is not built.

Also fixed in passing, in the same code path this note describes: `main.cpp`'s config-loaded
identity-selection loop previously fell back to `cfg_users.front()` (silently promoting whatever
the FIRST config entry was to Administrator) when no `Role::admin`-tagged entry was found in a
hand-edited config file. That fallback is now a fatal boot refusal instead (`main.cpp:1476-1488`)
-- the interactive `first_run_setup` flow (`auth.cpp`) always creates the admin account with
`Role::admin` explicitly, so the fallback was reachable only via a hand-edited config, but it must
still fail loudly rather than silently provision the wrong identity as the fleet's first
Administrator.

Explicitly out of scope for this delivery (Phase 1): the seeded-default flip itself (deferred, see
above -- `rbac_enabled` still seeds `'false'`); `docs/user-manual/rbac.md` and any dashboard-facing
documentation of a new default, which has no meaning to document until the flip actually ships;
the dashboard itself; any new REST/MCP route (this is boot-time-only, with no API surface of its
own).

### D3 -- One assignment chokepoint for every principal type and scope; deny at assignment level is a decided, not silent, extension of the frozen lattice

**The decision is one write CHOKEPOINT, not one table.** Every role assignment or revocation --
principal (user | group | engine), role, scope (global | management-group) -- is validated by
exactly one function (`validate_assignment`, extended, never forked) regardless of which
underlying table it lands in. `validate_assignment` already serves both `RbacStore` and
`ManagementGroupStore` today (the latter calls into the former), so this decision is narrower
than an earlier draft claimed: the chokepoint already exists and is shared; what is missing is
(a) deriving the grantable-role set from the grantor's actual authority (D4) instead of a
hardcoded allow-list, and (b) a shared assignment record shape (principal, role, scope, granted_by,
justification, audit correlation id -- the same correlation id D9's `assignment-authority` axis
consumes, so a D4 or D11 denial at this chokepoint is D9-covered by construction, not a second
evidence mechanism) so the two tables present one API contract even if they
remain two tables.

**A per-assignment `effect` (allow/deny) is a new model element, not a formatting choice, and
this decision does not add one without saying how it composes.** The codebase has already
frozen the #1715 cross-boundary lattice: a global allow overrides a group deny; a global deny
does not override a group allow. An assignment-level deny is a third kind of fact competing in
that same lattice. **This decision does not introduce assignment-level deny.** If a future
change wants one, it must be its own decision that extends `resolve_perm_groups` (the single
INV-7 resolver) with an explicit rule for where an assignment-deny sits in the existing
precedence, reviewed with the same rigor as #1715 was. Until then, an assignment record's
`effect` field, if built, is `allow`-only.

**The chokepoint also covers group-membership writes, not only role assignment (Gate-4 governance
finding).** Adding a member to a group that already holds a role grant is, in effect, granting
that member the group's roles -- the ordinary onboarding action, not an edge case -- and
`RbacStore::add_group_member` today writes directly (`INSERT INTO group_members` + a generation
bump) with no call into `validate_assignment` or any equivalent check. Left as is, this is a
grant-authority bypass in plain sight: whoever can add a group member can hand that member
every permission the group holds, regardless of whether they themselves could pass D4's check
for any of those permissions. This decision therefore extends its own chokepoint scope to
group-membership writes against any role-bearing group -- a membership add must pass the D4
check for the group's own currently-held role grants -- not only to the role-assignment writes
named above.

**The chokepoint also covers role-DEFINITION edits, not only who holds a role (PR review finding,
@fjarvis).** `RbacStore::create_role`/`set_permission`/`remove_permission` change what a role
GRANTS, and today none of them route through `validate_assignment` or any equivalent
grant-authority check -- confirmed against the store's actual signatures
(`rbac_store.hpp:202,226,246`). This is the same escalation shape as the group-membership bypass
above, one level up: whoever can edit a role's permission set can add a permission to that role
they do not themselves hold, silently escalating themselves (if they hold the role) and every
other current holder of it, with no D4 check ever running on the editor. D4's own latent-widening
trigger #3 (a later edit to a role's permissions) already treats this as something to *detect*
on existing grantees after the fact -- but detection-only leaves the editor's own escalation
ungated at the moment they make the edit. This decision extends its chokepoint scope a second
time: adding a permission to a role's definition must pass the same D4 check as granting that
permission directly -- the editor must currently hold what they add to the role -- while removing
a permission from a role needs no such check (removal never grants standing authority to anyone).

**The chokepoint also covers assigning a role TO an already member-bearing group, not only
adding a member to an already role-bearing group (PR review finding, @fjarvis).** The
group-membership fix above closes one direction: adding member M to group G, where G already
holds role B. Its mirror is open: create group G with no role, add members to it freely (D3
exempts a non-role-bearing group from this chokepoint, since it grants nothing yet), then assign
role B to G. `validate_assignment` already runs on that role-assignment write per this decision's
opening paragraph, so D4's grant-authority check (does the grantor hold B) already applies
correctly regardless of whether the target principal is a user or a group -- but D11's SoD check
(below) resolves the *write principal's* effective set, and the write principal here is the
group, whose own set does not include each existing member's other roles. A member who already
holds role A, now inheriting B through the group, can assemble a declared A+B SoD-forbidden pair
with neither half of the check ever seeing both roles together. D11 must resolve every CURRENT
member's resulting combined role set against the SoD table at the moment a role is assigned to a
member-bearing group, symmetric to the group-inclusive check it already requires on new-member
adds.

*Non-conformance (defect) today:* the scoped-assignment route hardcodes its allowed-roles list
(`role_name != "Operator" && role_name != "Viewer"`) instead of deriving it from D4; there is no
production write path for a global human assignment at all; `add_group_member` bypasses the
chokepoint entirely (see above); `create_role`/`set_permission`/`remove_permission` bypass it
entirely too (see above). *Not yet built:* the shared assignment record shape; a decided, tested
lattice rule for assignment-level deny (deliberately out of this decision's scope, see above);
both group-membership checks just added to this decision's scope (member-add to a role-bearing
group, and role-assign to a member-bearing group); the role-definition-edit check.

### D4 -- Grant authority is an explicit administrative model: the grantor must currently hold what they grant, computed as an effective-authority delta

A grantor may only grant authority they themselves currently hold at the target scope, evaluated
as the delta between the grantee's effective permission set before and after the proposed grant
-- across the frozen additive lattice (#1715), including deny interactions and descendant-scope
expansion -- not a per-`(securable, operation)` row lookup. A grantor who holds a permission only
via a group that does not cover the target scope must not be able to grant it there.
`visible_agents_for_permission` is the right resolver *primitive* for computing each side of that
delta, but it operates on currently-persisted state -- it is not a transactional
before/after simulator, and this decision does not claim the check is free to build; it requires
either evaluating the delta inside the same transaction as the write (persisted-before vs.
persisted-after, with rollback on violation) or an equivalent hypothetical-state evaluation this
document does not further specify. **Whichever mechanism is chosen, a failure to complete the
delta computation -- a degraded resolver, a timed-out read, an incomplete hypothetical-state
evaluation -- must deny the grant, never default-allow it (Gate-4 governance finding): this
decision's whole purpose is closing an escalation path, and an unspecified failure mode on either
mechanism would silently reopen it.**

**The delta is evaluated against the grantor's full ADR-0033 §1 effective authority, not only
their RBAC/management-group lattice standing (Gate-4 governance finding).** An earlier draft's
"effective permission set" language reused ADR-0033 §1's own defined term while silently scoping
it to `visible_agents_for_permission`'s RBAC-lattice-only view -- §1 defines effective authority
as the full intersection (authenticated-actor grants ∩ represented-operator grants ∩
attenuated-credential grants, when a credential is presented, ∩ ...), and states plainly that "no
applicable filter may be skipped because another one passed." A grant request arriving on an
attenuated credential (ADR-0033 §3) must have its credential's own minted envelope checked
alongside the underlying principal's RBAC holdings -- otherwise a token deliberately minted with
narrower authority than its owner could pass this check by riding the owner's broader standing
grants, exactly the escalation-by-token-laundering shape ADR-0032 Decision 7 and this document's
own D6 already guard dispatch authority against. This decision does not reuse `visible_agents_for_
permission` alone as sufficient; it requires the same credential-attenuation filter §1 already
mandates whenever a credential is presented.

**A point-in-time check at assignment is necessary but not sufficient (second Sol review): it
does not prevent authority that widens *after* the grant with no new assignment event.** Four
distinct triggers can do this, none of them a new assignment event: (1) a grant that adds no
authority today because a deny currently masks it can become effective the moment that deny is
later removed by someone else; (2) a management-group hierarchy change can widen the descendant
set a scoped grant reaches; (3) a later edit to the granted role's own permissions can give the
grantee more than the grantor verified at grant time; (4) **adding a member to a group that
already holds a role (D3's chokepoint extension above covers the write itself; this is the same
widening problem viewed from D4's side)**; (5) **a D10 time-bound grant's `valid_from` arriving --
a grant with zero delta at creation time can activate later with no new assignment event, the
same shape as (1)-(4) just clock-driven instead of mutation-driven (Gate-4 governance finding;
D10's corrected text already requires its OWN read-time expiry check for `valid_until` -- an
implementation must not treat `valid_from` activation as somehow already covered by that same
fix without separately checking it); (6) **assigning a role to a group that already has members
(D3's second chokepoint extension covers the write itself; the same widening problem as (4),
mirrored).** This decision therefore requires one of: (a) a durable ceiling recorded on the
assignment (the grantor's authority snapshot at grant time, re-verified whenever the assignment's
authority is *read*, not only when it is written), or (b) revalidation triggered by every
mutation that can grow an existing assignment's effective reach (deny removal, hierarchy
reparenting, role-permission edits, group-membership growth in either direction). Which of these
-- or another mechanism -- is chosen is left open; this decision fixes the requirement (latent
widening must be caught, not only grant-time escalation), not the mechanism.

**Mechanism (a)'s snapshot re-verifies its own integrity, not that the grantor still holds it
today (PR review finding, @fjarvis; this decision takes a position rather than leaving it
implicit).** "Re-verified whenever read" as written checks that the recorded ceiling has not been
tampered with -- it does not re-check whether the grantor who set that ceiling has since been
demoted or lost the authority the snapshot recorded. A grant can therefore outlive its own
grantor's standing under mechanism (a), which is in tension with this decision's own framing
("the grantor must CURRENTLY hold what they grant"). This decision's position: that tension is
accepted for mechanism (a), not silently permitted -- a snapshot is a point-in-time ceiling by
design, and continuously re-validating it against the grantor's live standing would collapse
mechanism (a) into mechanism (b) in every case that matters. An implementation that wants the
grantor's ongoing standing enforced, not merely their standing at grant time, should choose
mechanism (b) instead; mechanism (a) is for callers who explicitly want a frozen ceiling.

**This decision deliberately rejects the alternative administrative model -- a dedicated
`Approve`/administer-without-holding permission -- that ADR-0033 §8 already adopted for
approvals** ("approvers need `Approve` on the securable and never the underlying permission, so
a low-privilege reviewer stays possible"). The two are not in conflict because they answer
different questions: §8's model lets someone *gate* an action they cannot themselves perform;
D4's model governs *creating standing authority* for someone else, where "I can let you do X
without being able to do X myself" is the escalation this decision exists to prevent. A future
`Grant` operation modeled on §8's shape (a dedicated `UserManagement:Grant` permission,
independent of the granted role's own permissions) is a genuine, different, and rejected
alternative -- see Rejected Alternatives.

**This decision's denial routes through D9's `assignment-authority` axis with its own reason
code, not a bare `deny` (Gate-8 governance finding, committed here rather than asserted only from
D9's side).** A grant-authority-delta denial and an ordinary permission denial are different
facts a SOC 2 reviewer needs to tell apart; this decision is bound to surface that distinction at
`validate_assignment`, the same obligation D9 states it expects of D4.

*Non-conformance:* not applicable as a defect -- no production grant-authority check exists at
all outside the hardcoded Operator/Viewer list, so there is nothing yet to violate D4. Any
implementation of D3 that ships a per-row check instead of the effective-authority delta
described here, or that omits the latent-widening handling above, would be a D4 non-conformance
from the day it ships.

### D5 -- Per-agent data is confined by one of three named mechanisms on every transport, and coverage is proven, not asserted

Yuzu already has three legitimate confinement mechanisms for different shapes of operation, and
this decision does not merge them (ADR-1006 Decision 2 already rejected merging
`require_list_read` and `require_fleet_read` for the same reason: they answer different
questions and merging weakens one or complicates the other):

1. **Single-target writes** -- `require_scoped_permission(..., agent_id)`, the existing
   per-device pattern.
2. **Fan-out dispatch** -- `dispatch_confined_arms` / `derive_exec_visible` / `authz::meet`, the
   existing per-dispatch-arm intersection (the `∩` narrowing formula ADR-0033 §1 states, applied
   at the dispatch-targeting seam `docs/mcp-server.md`'s routed concern names -- not §2, which is
   the capability-declaration registry D1 already cites correctly; a Gate-3 governance review
   caught this mis-citation).
3. **List/fan-out reads and bulk mutation targets** -- the ADR-0017 admit-then-filter triad
   (`authorize_list_read` / `require_fleet_read` / `require_list_read`) plus the built-but-unwired
   `confine_agent_target` for the write-target case ADR-0017 did not cover.

Every per-agent read or write on every transport (REST, MCP, dashboard fragment, SSE stream)
must reach at least the applicable one(s) of these three for its shape -- **"at least," not
"exactly one"** (second Sol review's correction: a bulk operation can legitimately need route
admission via one mechanism, target confinement via a second, and downstream dispatch-arm
authorization via a third; layered coverage across applicable stages is the goal, not forcing
every route into a single mechanism) -- or be on a documented, reviewed exception list of
genuinely fleet-global surfaces (the existing ADR-0017 precedent for the software-catalogue
rollup). What this decision forbids is a *fourth*, ad hoc mechanism, or a route that reaches
*none* of the three where one applies. **The new requirement this decision adds is a provable
coverage check**: a static/CI pass enumerating every registered route and MCP tool, classifying
each into the applicable mechanism(s) or the exception list, and failing if any per-agent-data
route reaches none of them.
"We believe every route is gated" is not sufficient; a governance-blocking test is.

Retiring `ManagementGroupStore::get_visible_agents` in favor of `visible_agents_for_permission`
is **not a new decision this ADR makes** -- ADR-0017 INV-6 already states PR-C "deletes the
role-existence narrower and its full-fleet fallback... rather than extending them." This document
reaffirms that conformance
with INV-6 is required for a gold-standard claim; it does not re-decide it.

*Non-conformance (defect) today:* `get_visible_agents` still has 7 production call sites (a
standing INV-6 non-conformance); `confine_agent_target` has zero callers; `/api/scope/estimate`
has no permission gate of any kind (worse than bare-gated). **Correction (adversarial review,
2026-09-02): "nine specific bare-gated routes" is not reproducible and was overcounted.** A fresh
sweep by both external reviewers independently found at least 7 flat, `perm_fn`-only per-agent
routes with no confinement mechanism at all across `dex_`, `compliance_`, `discovery_`, and
`inventory_routes` -- not 9, and the exact set the two reviewers found differed slightly, which
is itself evidence that a hand count in prose is the wrong way to state this. More importantly,
the original "six route modules... have not migrated" framing conflated two different states:
`device_routes.cpp` and `tar_tree_routes.cpp` (and part of `inventory_routes.cpp`) already route
their list surfaces through a legacy `get_visible_agents`-backed scoped provider
(`devices_fn_`) -- not on ADR-0017's mechanism 3, and therefore still a standing non-conformance
with INV-6, but not bare-gated or unconfined the way the other four modules' flat routes are.
This document does not restate a corrected exact count, because the count is exactly what D5's
own coverage-proving contract test exists to make authoritative rather than asserted in prose --
that test, once built, replaces this paragraph's inventory. *Not yet built:* the coverage-proving
contract test.

### D6 -- Every durable or background dispatch resolves to a currently-valid human authority and credential

**The requirement is not in question; this document decides, on its own authority, to apply it to
BOTH dispatchers below -- corrected here to match sub-clause 4's own text (PR review finding,
@fjarvis; this exact contradiction was flagged twice: once by this session's own Gate 8, which
fixed sub-clause 4 but missed this earlier restatement of the same claim; once by an external
reviewer's panel, which caught what the self-check missed).** ADR-0033's narrowing law (§1) is
platform-wide: authority is never created out of nowhere, and an effect crosses the system only
through filters that confirm a real, current grant behind it. ADR-0032 Decision 7 is the
validated design whose mechanics satisfy this shape of problem: record the credential that armed
the dispatch, not only the human; recheck it at execution; distinguish routine rotation (rebind,
keeps running) from revocation/expiry/deletion (stop); make a stopped dispatch loud, not a silent
failure. **Decision 7's own text governs a Use-Case run under the not-yet-built UCE admission
protocol, not the shipped `ScheduleRunner`/`InstructionSet` dispatch this document actually
applies its mechanics to** -- so for Schedules, exactly as much as for Guardian, this document
extends Decision 7's principle on its own authority; it is not compliance with an ADR that
already covers the shipped feature. See sub-clause 4 below for the full citation-accuracy
argument. **For Guardian, no accepted ADR names this dispatcher either, and this document
decides, on its own authority as a proposed ADR-0033 extension, to apply the identical
mechanism** -- not because an existing text already reaches that far, but because Guardian's rule
distribution is the same shape of problem (a person's decision keeps taking effect long after
they made it, with nobody
re-checking whether they still could) and reusing a mechanism this codebase has already designed,
reasoned through, and will build once for Schedules is better engineering than inventing a second
one. Dave decided this directly (2026-09-02) rather than leaving it contingent on a maintainer's
reading of ADR-0032's text, which is the right place for this decision to sit: whether Guardian
needs this protection is a product/security judgment, not a question of what a sentence in
another document happens to say.

The prior drafting history on this exact point -- three rounds of asserting an accepted ADR
already settled it, having that retracted, and two independent external reviewers splitting on
the question when asked to check -- is preserved in Governance below, because it is the reason
this decision is now stated as an owned choice rather than argued as a forced reading. It is not
restated here; a decision does not need to relitigate its own history to be binding.

**What is this document's own content, decided here, independent of any existing ADR:** how the
credential-recheck mechanism's *mechanics* apply to a dispatcher that distributes rules built
from *multiple* Baselines with independently-changing roots and credentials at once -- Decision 7
was written for a single-armer Schedule and does not by itself resolve what happens when a
distributed rule set has several roots simultaneously. That multi-root mechanics question, and
the parallel question of how the same model extends to policy remediation and other background
dispatchers, is what sub-clauses 1-3 and 5-6 below resolve. It is not implementable as a single
sentence.

1. **What counts as an "effect" here is each distribution event, not a periodic "push cycle" --
   Guardian has no timer.** Distribution is event-driven via two paths: an explicit push fired on
   Baseline deploy/undeploy or a manual REST push, and a separate, rate-limited per-agent
   heartbeat reconcile that fires only when that agent's generation is behind the current policy
   generation. The "effect" this decision binds is **each such distribution event** -- the
   server-side act of handing an agent a rule set it will thereafter evaluate and act on
   autonomously -- not each individual moment an already-received rule later fires locally on a
   device. This follows from how Guardian works: agents keep enforcing already-received rules
   while disconnected from the server, so there is no live round-trip at local-enforcement time
   to check anyone's current authority against; a distribution event is the only point where a
   live authorization decision is architecturally possible at all. **Both paths must apply the
   same per-Baseline root resolution identically** -- an agent reached by the event-driven push
   and one reached only by the later heartbeat reconcile must not diverge on which Baselines'
   rules they are currently enforcing. Read-only evaluation (the policy evaluator's compliance
   tick) is excluded on separate grounds -- it produces no effect at all.
2. **The authority root per dispatch class, plus a default rule for everything not yet
   inventoried.** Four classes are settled: direct human action (already rooted, unaffected);
   scheduled dispatch (the armer, `Schedule.created_by`, re-checked at fire per #3133, adoption
   gap closed by sub-clause 5); Guardian's distribution events (per-Baseline deployer/adopter,
   resolved at each event per sub-clauses 1 and 3); and policy remediation (the live requesting
   operator, per sub-clause 5, with no stored root at all). Not every `system_reserved`
   capability has been individually inventoried against this table, but neither of the two named
   in an earlier draft turns out to need it: `tar.fleet_snapshot` declares itself read-only in
   `core_dispatch_capabilities.hpp`, so D6's own read-only exclusion already covers it the same
   way policy evaluation is covered; and `asset_tags.sync` fires from a tag-write route gated by
   `scoped_perm_fn(req, res, "Tag", "Write", agent_id)` against a live session before dispatching
   system-rooted, so it already has a findable, live root and is not an "unexamined" case at
   all -- both corrections from an earlier draft that flagged them as unexamined without checking.
   **The capture-source push is not in this set**: `POST /fragments/tar/capture-sources/push` is
   session-authenticated, gated by `scoped_perm_fn_("Infrastructure", "Read", device)`, and
   derives a real, non-system caller that `build_classified_command` enforces
   `Infrastructure:Write` against -- it is already a correctly-rooted direct human dispatch, not
   one of the three actual `system_reserved` rows in `core_dispatch_capabilities.hpp`.
   **The default rule for any dispatcher not in the four settled classes above**: it must
   resolve to whoever's action created the record or state it is now acting on, re-checked at
   the moment of dispatch, unless and until it is reviewed and found to genuinely have no such
   record to root against -- in which case sub-clause 6 governs, and the burden of showing no
   arm-event root is achievable sits with that dispatcher, never a default assumption that it is
   exempt. Applying this default: preflight's checks are already read-only by design
   (`docs/user-manual/preflight.md`'s load-bearing invariant that every check is
   read-only/idempotent), so preflight is excluded the same way policy evaluation is -- it
   produces no effect. **Quarantine reconciliation does NOT conform**: `QuarantineContainment
   Reconciler` dispatches through `command_dispatch_fn`, the same unfiltered `system=true`
   closure policy remediation uses (a distinct path from Guardian's own `send_system_reserved`,
   though both are equally system-rooted with no per-human authority, which is the point that
   matters here). **Correction:** an earlier draft claimed the reconciler's dispatch function
   type is caller-typed in signature but simply doesn't supply a real caller at its call site --
   this overstated how close it is to conforming. `QuarantineContainmentReconciler`'s
   `CommandDispatchFn` is a plain, no-caller shape at its declaration
   (`quarantine_containment_reconciler.hpp`), the same as `command_dispatch_fn` itself; there is
   no caller-typed signature to fail to use. The conclusion is unaffected: quarantine
   reconciliation is squarely inside this sub-clause's default rule, and building the caller-typed
   path is new work, not a matter of wiring an existing hook. Whatever record establishes
   a device's quarantine is the candidate root, re-checked at reconciliation time, and building
   that is in scope for whoever implements D6.
3. **The Guardian multi-root problem: orphaning pauses enforcement, loudly.** Every distribution
   event (sub-clause 1) constructs its rule set from `deployed_member_rule_ids()` filtered across
   *every currently-deployed Baseline*, which may represent several different deployers with
   different, independently-changing current authority. "Resolve to the deploying operator" has
   no single answer once more than one Baseline is live simultaneously. Three other candidate
   answers are rejected: failing the whole distribution over one deployer's status change makes
   an unrelated HR/RBAC event a fleet-wide enforcement outage; indefinitely retaining
   last-known-enforced state with no path back to a rooted authority just defers the "unrooted
   effect" problem this decision exists to close; and **"keep an orphaned Baseline's rules
   enforced unchanged while pending adoption" is not achievable through the two paths this
   decision's own re-evaluation mechanism uses, though the push endpoint itself has a broader
   partial-update mode -- a correction from an earlier draft, which claimed no such mode exists
   anywhere.** `POST /guaranteed-state/push` accepts a `full_sync` flag defaulting to `false`,
   and an incremental (`full_sync=false`) push upserts only the delivered rules, leaving
   everything else on the agent untouched -- so "every distribution event is a full sync" is
   false as a blanket statement about the push endpoint. What is true, and what this decision's
   mechanism actually relies on: Baseline deploy/undeploy and the heartbeat reconcile -- the two
   paths sub-clause 1 names as the ones this decision governs -- are both hardcoded
   `full_sync=true` in current code, with no operator-facing way to make them incremental. On
   those two paths specifically, the agent clears its prior rule set and reapplies whatever the
   event delivers, so exclusion from the delivered set **is** disarming that Baseline's rules.
   This has two consequences the earlier, overstated version of this paragraph did not name: the
   periodic re-evaluation sweep (below) must itself trigger a `full_sync=true` distribution when
   it finds an orphan transition, or the pause it is supposed to enforce simply will not happen;
   and an operator-initiated incremental push made while a Baseline is orphaned does not enforce
   the pause either -- it leaves already-armed rules exactly as they were, which is a residual
   gap this decision accepts rather than closes (closing it would mean either forcing every push
   to be full-sync, which has its own fleet-convergence cost, or teaching the incremental path to
   also respect orphan state, which is additional mechanism this document does not specify).

   **The decision:** when a deployed Baseline's original deployer no longer holds the
   authority under which it was deployed, or the credential they deployed it with is no longer
   valid (sub-clause 4), the Baseline enters an **orphaned, pending-adoption** state, and its
   rules are **paused** -- excluded from the rule set at the next distribution event that reaches
   each affected agent, on both paths (sub-clause 1). This is accepted as the correct trade-off,
   not a euphemism for it: a paused control that is loud, audited, and immediately adoptable is
   safer than one of the two alternatives above (silent fleet-wide outage) and more honest than
   the third (a decision that claims continuity the mechanism cannot deliver). The orphaned state
   is **loud**: an audit event on transition into it, a Prometheus gauge counting Baselines
   currently pending adoption, and a surfaced operator-facing signal (dashboard +
   `list_baselines`/equivalent MCP output) so a paused Baseline cannot go unnoticed. **Resolution
   is an explicit `adopt_baseline` action**, audited, callable only by an operator whose current
   effective authority (per D4) covers the Baseline's scope at least as fully as the original
   deployment required -- adoption cannot itself be an escalation path. Adoption re-roots the
   Baseline to the adopting operator and clears the pending-adoption state; re-enforcement
   resumes at the next distribution event that reaches each agent, not instantly on adoption.
   **The orphaned-to-adopted transition is a guarded, atomic state change, not an unconditional
   overwrite (Gate-4 governance finding):** this document's own Context section already names the
   identical failure family elsewhere (#1362, management-group reparenting's non-atomic
   check-then-write), and this codebase already has the correct pattern for a stateful, mutating,
   execute-once transition on exactly this shape of record (the Deployment/Preflight guarded-
   transition + CAS pattern this codebase's routed concerns document as catastrophic if violated).
   `adopt_baseline` must use the same shape -- a CAS on the orphan/adoption state, not a bare
   read-then-write -- so two racing adoptions cannot both succeed or leave the Baseline in an
   inconsistent root state. **A CAS on the Baseline's own row does not, by itself, close the
   second race named above (Gate-5 governance finding): the adopting operator's authority lives
   in a different table entirely (RBAC/management-group grants), which a single-row CAS on the
   Baseline cannot observe.** The D4 authority check ("current effective authority... covers the
   Baseline's scope") must therefore be re-verified *inside* the same transaction that commits
   the CAS, under the same locking/`SERIALIZABLE` discipline D2 requires for its structurally
   identical problem -- a check performed before the CAS, in a separate read, leaves the window
   D2's fix was written specifically to close, reopened here. **This decision independently
   requires `adopt_baseline`/`adopt_schedule` to be audited (Gate-8 governance finding, naming
   the coverage precisely): that audit obligation is D6's own, not borrowed from D9, and does not
   by itself require D9's specific structured schema (correlation id, closed-taxonomy reason,
   Prometheus counter) -- an ordinary audit-log row satisfies this sub-clause's own text. Routing
   it through D9's schema as well is worth doing for the same evidentiary reasons D3/D4/D11 do,
   but this sub-clause does not currently commit to it; treat it as an open follow-on, not an
   already-closed gap.

   **Shared-Guard rule:** a Guard reached by more than
   one Baseline is armed once on the agent, and `deployed_member_rule_ids()` returns a flat,
   Baseline-attribution-free set of rule ids -- so a Guard contributed by both a rooted Baseline A
   and an orphaned Baseline B must not be paused, because A still legitimately roots it. Exclusion
   applies at the rule level, computed as: a rule is included if **at least one** currently-rooted
   (non-orphaned) Baseline contributes it, and excluded only if **every** Baseline contributing it
   is currently orphaned. Implementing this decision therefore requires adding per-rule
   Baseline-contribution attribution to the deployed-rule resolution path, which does not exist
   today -- `deployed_member_rule_ids()`'s flat-set shape is itself *not yet built* against this
   decision, not merely the `adopt_baseline` action layered on top of it.

   **Re-evaluation trigger:** an orphan transition
   (an authority or credential loss detected between distribution events) does not, by itself,
   cause any distribution event to happen -- distribution is event-driven (sub-clause 1) and
   nothing today ties an RBAC mutation or a credential revocation to a Guardian push or to
   bumping the policy generation the heartbeat reconcile keys on (`bump_policy_generation`'s only
   callers today are Baseline deploy/undeploy). Without a fix, "paused, loudly" could mean
   "paused whenever the next unrelated Guardian change happens to trigger distribution," which
   could be an arbitrarily long time -- not the bounded, prompt pause the decision intends. This
   decision therefore requires a periodic sweep (the same shape as `PolicyEvaluator`'s existing
   tick, not a new architectural pattern) that re-validates every deployed Baseline's current
   root and credential, and triggers a **`full_sync=true`** distribution on any transition it
   finds (orphan or adoption) rather than waiting for an unrelated change to surface it --
   per the correction above, a `full_sync=false` push would not actually enforce anything the
   sweep just decided. The sweep must carry the same kind of explicit bound `PolicyEvaluator`
   already does (a tick, a grace period, and a floor -- `docs/user-manual/policy-engine.md`'s
   10s/15s/60s-floor shape is the cited precedent, not the exact numbers); an unbounded or
   implementation-defined-with-no-floor interval would satisfy this sub-clause's letter while
   defeating "bounded, prompt pause" in substance (a Gate-2 governance finding). The exact
   values are implementation, but the requirement that a floor and default be stated up front,
   the same standard D9 already holds itself to for its own operational-cost parameters, is not.
   **The sweep must also emit its own liveness signal (Gate-4 governance finding):** sub-clause
   3's central guarantee is that orphaning "pauses enforcement, loudly" -- but that guarantee is
   only as strong as the sweep that detects orphaning, and nothing above says what happens if the
   sweep itself crashes, hangs, or cannot reach the store mid-cycle. A dead sweep degrades
   silently to the opposite of the guarantee: stale rules keep enforcing fleet-wide with no
   operator-visible sign anything stopped working. This decision requires a "last successful
   sweep completed" timestamp or gauge, alerted on after N missed cycles, the same way any other
   safety-critical background process in this codebase is expected to prove it is still running,
   not merely that it is scheduled to run. **A completion timestamp proves the last pass
   finished, not that passes are keeping pace with fleet growth (Gate-6 governance finding):**
   this decision's own tick/grace/floor bound (above) constrains cadence, not the cost of a
   single pass, which scales with the count of currently-deployed Baselines and Schedules. This
   decision requires a duration histogram for the sweep's own pass time, the metric shape this
   codebase's observability conventions already use to detect exactly this kind of degradation,
   not only a liveness gauge. **On more than one server replica, the sweep also needs a
   single-writer discipline (Gate-6 governance finding), the same pattern this codebase already
   uses for background processes with an identical shape** -- the session-store reap and the
   #2964 rotation sweep are both single-writer-by-construction via a store-wide advisory lock,
   specifically because an unelected sweep's effect (here, a fleet-wide `full_sync=true` push) is
   wrong to fire from every replica independently. This decision does not specify the lock itself
   -- that is implementation -- but requires that one exists before this mechanism runs on more
   than one replica.
4. **Credential recheck.** **Corrected (Gate-8 governance finding): ADR-0032 Decision 7 does
   NOT already decide this for the shipped `Schedule`/`ScheduleRunner` feature, and "compliance,
   not invention" was wrong.** Decision 7's own scope is a *Use-Case run* under the not-yet-built
   UCE admission protocol -- ADR-0032's frontmatter names its scope as exactly that, and
   `ADR-0032`/`ADR-1005`/`ADR-0031`/`ADR-0033` collectively contain zero references to
   `schedule_engine`/`ScheduleRunner`/`InstructionSchedule`, while `schedule_runner.{hpp,cpp}`
   contains zero references to ADR-0032, ADR-1005, UCE, or a use-case run, verified by direct
   grep in both directions. The shipped feature this document is actually applying Decision 7's
   mechanics to (`ScheduleEngine`/`ScheduleRunner`, ADR-0009/0065) dispatches `InstructionSet`
   executions directly to agents; it never enters a UCE admission path. "A schedule" in Decision
   7's text names a real thing, but a different, not-yet-built one -- the same word, not the same
   referent. Six review rounds each confirmed the word "schedule" appears in Decision 7 without
   checking whether it names the object this document applies it to; that check is what this
   correction adds. **What this document actually does, correctly stated:** the same way it
   extends the credential-recheck mechanism to Guardian on its own authority (below), it now also
   extends Decision 7's *principle* -- record the arming credential, distinguish rotation from
   revocation, stop on either -- to the shipped Schedule feature, as this document's own decision
   by analogy, not as compliance with an ADR that already covers it. The requirements below this
   correction (recording the arming credential, the rotation-vs-compromise split, `adopt_schedule`)
   are unchanged; only their source of authority is corrected. For Guardian, Decision 7's own
   scope statement ("this governs operator-facing runs... it does NOT re-home the autonomous-sync
   identity") names neither Guardian's case nor excludes it, so this document decides, on its own
   authority as an ADR-0033 extension, to apply the same mechanism -- see the decision's opening
   above for why. (ADR-0033 §7's own general text, separately from its four-eyes table, names "a
   scheduled or background run" without Decision 7's operator-facing qualifier; whether that
   sentence already reaches Guardian on its own is left unargued here, because D6's mechanism is
   at least as strict as any such reading would require -- the question has no normative effect
   on what this document actually does. Correction (Gate-3 governance review): the phrase "a
   scheduled or background run" sits as a row INSIDE §7's four-eyes comparison table, not
   separately from it, and §7 opens with an explicit caution against reusing that resolution as
   a general identity-collapsing rule outside four-eyes -- this document's independent D6
   authority is the operative basis for Guardian, not an unqualified reading of that phrase.)

   **Unified in shape across live and durable dispatch:**

   - **Live dispatch (manual policy remediation, any future "act now" flow)** already has a
     real, current credential presented with the request, and needs no new mechanism -- this is
     exactly what sub-clause 5's fix for remediation already does by threading the live
     requester's session/token through to dispatch instead of falling through to the shared
     system-rooted closure.
   - **Durable dispatch splits by whether a durable credential exists to record -- a correction
     to an earlier draft, which proposed recording "the session or API token id" as if the two
     were interchangeable.** They are not: a `Session` has no addressable credential identity
     exposed beyond the stable `username`, and every session expires at an absolute 8-hour
     `kSessionDuration` regardless of activity. Applying expiry-triggers-orphan to a session
     literally, as the earlier draft did, would auto-orphan every dashboard-deployed Baseline (or
     dashboard-armed Schedule) within a single workday -- an absurd operational outcome for a
     mechanism meant to catch genuine authority loss, and it holds for Schedules exactly as much
     as for Guardian, since ADR-0032 Decision 7's text does not itself distinguish session-armed
     from token-armed runs. This document resolves the gap Decision 7 leaves open, consistent
     with its intent rather than in tension with it:
     - **Armed with an API token**: record that token's id at deploy/arm time (not only the
       principal's username, as today's `Baseline.deployed_by` / `Schedule.created_by` do). At
       every distribution event or fire, the recorded token's current validity is rechecked in
       addition to the principal's current RBAC authority (sub-clauses 2/3/5) -- a revoked,
       expired, or deleted token triggers the same orphaned/pending-adoption state sub-clause 3
       defines for authority loss, not a separate failure mode. **Routine credential rotation is
       not treated as revocation, keyed on the same distinction Decision 7 requires (a recorded
       successor vs. a compromise revocation with none)**: re-arming with a freshly issued token
       for the *same* still-authorized principal, recorded as a rotation successor rather than a
       compromise, is an explicit, audited **rebind** action -- this document's name for what
       Decision 7 calls re-arming, not a separate mechanism -- lighter-weight than
       `adopt_baseline`/`adopt_schedule`, since it does not change who roots the Baseline or
       Schedule, only refreshes the credential recorded against the existing root. This mirrors
       the existing `Rotate` operation this codebase already has for API tokens
       (`ApiToken:Rotate`) rather than inventing a new verb from nothing.
     - **Armed with an interactive session**: there is no durable credential to record or expire
       -- a session was never designed to represent a standing authorization that should outlive
       the login, only that a particular browser tab was recently authenticated. For this case,
       the recheck is the principal's current RBAC authority plus account liveness (below), with
       no separate credential-EXPIRY component; the 8-hour session lifetime has no bearing on how
       long the Baseline or Schedule stays rooted. **Explicit session revocation is a different
       signal from expiry and is not excluded by the sentence above (PR review finding,
       @fjarvis): this codebase's `AuthManager::invalidate_session` is a real, distinct,
       operator-triggered event -- a forced logout or a detected-theft response -- not a passive
       clock. Excluding time-based expiry (correct, argued above) is not the same claim as
       excluding an explicit invalidation, and ADR-0032 Decision 7's revocation-stops-the-run
       principle does not carve out session-armed dispatch from that distinction.** This decision
       requires the recheck to also observe an explicit `invalidate_session` on the arming
       session, treating it the same way sub-clause 3 treats authority loss -- orphaned, loudly
       -- distinct from the ordinary 8-hour expiry this sentence correctly excludes. An operator
       who wants a dispatch immune from needing periodic rebinds should arm it with a token,
       which is exactly what the token path
       above is for.
   - **Account liveness is an explicit, separate check, required in both cases above (and
     necessary on the token path specifically, not merely a fallback for the session path).**
     `ApiTokenStore::validate_token` checks only a token's own `revoked`/`expires_at` columns,
     with no join against the owning account's active status -- deactivating a human account
     does not, by itself, revoke that account's outstanding API tokens. Treating token validity
     as sufficient would let a durable controller keep enforcing under a deactivated principal
     whose token simply hasn't expired yet, which is exactly the unrooted-effect gap this whole
     decision exists to close. **The rule: durable-controller recheck always includes the root
     principal's account being active** (`AuthDB::get_user`'s existing active-only predicate, the
     same one `ScheduleRunner::resolve_caller` already uses), and additionally the recorded
     token's validity when the dispatch was token-armed -- either check failing triggers the
     orphaned/pending-adoption state. `locked_until` is explicitly **excluded** from the
     account-active predicate used here, per its own separate, deliberate trade-off: lockout is a
     temporary, auto-expiring throttle against brute-forced login attempts, triggered by
     wrong-password attempts against a known username -- not a fact about whether the account or
     its existing credentials are still valid. Folding it in would let anyone who learns a
     Baseline deployer's or Schedule armer's username deliberately trigger their lockout to pause
     that Baseline's enforcement or that Schedule's fires, turning a login rate-limit into a
     remote disarm switch.

   Both halves are now variations of one rule -- recheck the credential that authorized this
   effect, at the moment the effect fires or distributes, where "the credential" is whatever
   durable authorization fact actually exists for that arm event -- rather than two different
   rules for two situations. The only thing that differs is what the credential is and how
   "current" is established: a live session/token for live dispatch, a recorded, rotatable
   token id (plus account liveness, always) for
   durable dispatch.

5. **The safe state on reauthorization failure for scheduled dispatch and policy remediation --
   the two resolve differently because their data models differ, not because the underlying
   principle changes.** The adoption shape from (3) --
   orphan-then-loud-surfacing-then-explicit-authorized-hand-off, never silent drop and never
   silent indefinite continuation -- extends to whichever of these two actually has a stored,
   aging root to orphan. Only one does.

   **Scheduled dispatch: adoption applies, and part of the machinery already exists.** A
   `Schedule` already stores its arming principal (`created_by`) and the runner already
   re-resolves that principal at every fire via `resolve_caller`, which itself calls
   `AuthDB::get_user` -- filtered to active accounts only, with the code's own comment reading
   "EXISTENCE IS THE GATE." The account-deprovisioning half of a liveness check is already built
   for schedules; Guardian has no equivalent check at all. What genuinely is missing: `Schedule` records only
   `created_by` (a username), not the credential the armer used, so there is nothing yet for a
   revoked/expired/rotated credential to be checked against, and the RBAC-authority denial
   `resolve_caller` triggers (a distinct path from `arming_check`'s own
   `yuzu_schedule_arming_denied_total` -- `resolve_caller`'s account-non-existence case flows
   through the `AnonymousOperator` refusal into `yuzu_server_dispatch_denied_total{reason=...}`;
   this is a second Gate-2 correction to the same attribution, having survived one prior fix
   elsewhere in this document -- see the Governance log) is silent per-schedule, visible only in
   an aggregate counter, not a per-schedule surfaced state.
   Closing this means: recording
   the arming credential at arm time (sub-clause 4); on the first denied fire from either RBAC-
   authority loss or credential invalidity, transitioning the schedule to an audited, surfaced
   **orphaned** state (visible in the schedule list/API, not just the aggregate metric) rather
   than silently skipping it release after release; continuing to skip it, not force-firing,
   while orphaned; and an explicit `adopt_schedule` action (re-rooting, per sub-clause 3's shape)
   or a lighter **rebind** action (same root, fresh credential, per sub-clause 4) to resume
   firing from the next occurrence. The same re-evaluation-trigger gap sub-clause 3 names for
   Guardian applies here too: nothing today ties an authority or credential change to an
   out-of-band schedule re-check between fires, so the periodic sweep sub-clause 3 requires
   should cover schedules as well, not only Baselines.

   **Policy remediation: adoption does not apply, because there is no stored root to orphan.**
   `Policy` (`policy_store.hpp`) has no author/creator field at all, and per this codebase's own
   standing design, remediation is **operator-gated only** -- there is no automatic,
   background-triggered remediation effect for a root to go stale on; the background evaluator
   only computes compliance status (a read, explicitly out of D6's effect-producing scope
   already). Every remediation is a live operator clicking "remediate now" in their own current
   session. There is nothing to adopt, because there is no aging root in the first place --
   the correct fix for this case is the same one sub-clause 4 already requires and #3133 already
   modeled for schedules: thread the requesting operator's real identity through to the
   remediation dispatch and recheck their current authority and credential at that exact moment,
   rather than letting it fall through to the shared system-rooted closure. If a future change
   ever introduces automatic/background-triggered remediation, that change re-opens this
   sub-decision and should apply the Baseline/Schedule adoption shape at that time, not before.
6. **Whether a narrow, explicitly bounded institutional-controller exception is warranted: none
   is granted to any dispatcher examined in this document, and none is needed.** Every dispatch
   class this decision actually resolved -- Guardian push,
   scheduled dispatch, and policy remediation -- now has a real human root (adoption or live
   recheck), so none of them required falling back to an unaccountable institutional exception in
   the first place; sub-clause 2's default rule closes the remaining classes the same way. This
   decision does not foreclose one being proposed later for some dispatcher this document did not
   examine, but it sets the bar rather than leaving it undefined: this codebase already has a
   working precedent for exactly this shape of problem -- the auth subsystem's break-glass
   account and ADR-0031 (presentation-core-engine-decomposition)'s break-glass Core recovery
   ingress, both built on the explicit principle
   that "no filter and no gate is skipped because the surface is called break-glass." Any future
   institutional-controller exception must be built the same way: narrow, named, individually
   reviewed as its own ADR-0033 amendment (not silently absorbed into whatever PR implements this
   ADR), mandatorily audited on every use, and gated by the same fail-closed discipline as every
   other privileged path in this codebase -- never a bare `system=true` flag doing duty as one by
   default. A dispatcher proposing such an exception carries the burden of showing that no
   arm-event root (sub-clause 2's default) is achievable for it at all, not merely that one is
   inconvenient to build.

A blanket `system=true` flag with no stated root is not a declared exception under this
decision; it is the absence of a decision, which is the current state. This decision does not
close that absence -- it names exactly what closing it requires.

*Current state:*

For **Guardian**: the "effect" is each distribution event, not a periodic push (sub-clause 1);
Baseline root authority resolves via `adopt_baseline` and pauses when orphaned (sub-clause 3);
credential recheck applies Decision 7's mechanism by this document's own extension (sub-clause
4). *Not yet built, essentially all of it:* there is no `adopt_baseline`/rebind action, no
orphaned-Baseline state, no per-baseline (let alone per-rule, per the shared-Guard fix) root or
credential resolution at any distribution event, no orphaned-Baseline audit/metric/dashboard
surface, no recorded arming credential on `Baseline` at all (only `deployed_by`, a username), and
no periodic root/credential-validity sweep to trigger timely re-evaluation. Guardian distribution
currently dispatches as `system_reserved`/`system = true` with no per-baseline root, no
credential check, and no re-checked ceiling of any kind -- this decision's mechanism replaces
this, essentially from zero.

For **schedules**: the runner already re-resolves the arming principal and denies on
current-RBAC-authority loss or account deprovisioning at fire time (`created_by` +
`resolve_caller` + `AuthDB::get_user`'s active-only filter, the #3133 fix) -- more of the
mechanism is shipped here than for Guardian. *Not yet built:* recording the arming credential
(today only `created_by`, a username, is stored), rechecking that credential's validity per
sub-clause 4, the surfaced per-schedule orphaned state (today's denial is visible only in the
aggregate `yuzu_schedule_arming_denied_total` counter), the `adopt_schedule`/rebind actions, and
schedules' share of the periodic re-evaluation sweep.

For **policy remediation**: adoption does not apply (no stored root exists to orphan,
remediation is operator-gated only, sub-clause 5); sub-clause 4 for this class is simply the live
credential on the live request, threaded through to the remediation dispatch instead of falling
through to the shared system-rooted closure -- *not yet built*.

Per sub-clause 2's default rule: preflight needs no root (read-only by existing design, never in
scope); **quarantine reconciliation does NOT conform** -- it dispatches through the same
unfiltered `system=true` closure as remediation (`command_dispatch_fn`), not a caller-typed path,
and does not share Guardian's own separate `send_system_reserved` path -- so it is squarely
inside this default rule's scope, not a plausible pre-existing exception; `tar.fleet_snapshot`
and `asset_tags.sync` remain unexamined against the default rule. The capture-source push is not
in this list: it is already a settled, correctly-rooted direct-human dispatch and was never a
default-rule case.

Per sub-clause 6, no institutional-controller exception exists or is proposed for any of these.

**No sub-clause remains open, but the mechanism this decision requires is essentially unbuilt
from zero** -- the shared-Guard rule attribution, the periodic re-evaluation sweep, recorded
arming credentials, and rebind as distinct from adoption are all new construction, not small
patches to something mostly working.

### D7 -- Non-human principal authority composes through the same primitives as D3/D5, never a parallel mechanism

An engine principal's effective authority for any delegated or represented action is the
intersection of its own grants and the represented operator's current grants -- computed via the
same `authz::meet` composition D5 already uses for dispatch confinement, and assigned through
the same D3 chokepoint -- never a union, and never a standing global grant substituting for
per-run scoping. This is ADR-1005 §5 and ADR-0033 §3's attenuation model, applied without a
second implementation when management-group-scoped engine assignments are built.

*Non-conformance today:* engine principals (shipped through PR 4.5) can currently only hold
global grants. The existing dangerous-role guard rejects assignment by both a hardcoded name
list (`"admin"`, `"Administrator"`) and an `is_system` check on the target role -- but neither
catches a *custom* role that happens to carry fleet-wide destructive permissions (#2485), which
is the actual gap D4's effective-authority model, applied to engine grants, would close.
Delegation/attenuation per ADR-1005 §5 remains design-only.

### D8 -- `can-i` and every real gate share one Request-free decision core; there is no second implementation to keep in sync

The resolution logic behind `require_permission`'s ladder (elevated -> engine ->
mcp_tier -> service -> RBAC-enforced -> legacy, per ADR-1006) is extracted into a form callable
without an `httplib::Request` -- a decision core -- and both the real gate wrappers and any
"can I do X" endpoint (REST, MCP, or internal) call that same core. This is stronger than "call
the real ladder": today's `rbac/check` shortcut exists specifically because the ladder is
presently coupled to `AuthRoutes`' request/response types, so simply asking implementers to
"use the real ladder" without extracting a shared core invites exactly the second,
divergent implementation this decision forbids.

**"One decision core" means one core PER GATE FAMILY, not one ladder for every gate (Gate-4
governance finding).** `require_permission`'s ladder is not the only one this decision must
cover: ADR-1006 Decision 2 already froze `require_list_read`/`require_fleet_read` as a
deliberately DIFFERENT ladder from `require_permission`'s -- "two gates, two route classes, kept
deliberately separate" -- and #3290 built `require_fleet_read`'s caller-class branches to
mirror `require_list_read`'s ordering, explicitly NOT `require_permission`'s (no
service-scope belt-and-braces check `require_fleet_read` structurally cannot need). A single
core extracted only from `require_permission`'s ladder and asked to answer for a
list/fan-out-read-gated operation would reproduce this decision's own named defect (`rbac/check`
diverging from the real gate) for that entire route class. This decision therefore requires
either a family-parameterized core (one shape for `require_permission`, a second for
`require_list_read`/`require_fleet_read`) or an explicit, reliable way for a `can-i` caller to
resolve which family a given operation belongs to before consulting the core -- "extract the
ladder" is underspecified until one of those two is chosen.

*Non-conformance (defect) today:* `POST /api/v1/rbac/check` calls raw `check_permission`
directly, reproducing none of the toggle-off legacy fallback, JIT elevation (it currently
returns a false negative for an elevated caller the real gate would admit), engine-principal
branch, management-group scoping, service-token scoping, or MCP tier ordering. No Request-free
decision core exists to extract from yet, for either gate family.

### D9 -- Every authorization decision emits one structured, queryable record, and a record that cannot be written fails the request closed

Every admit/deny/degrade decision made by (a) any of D5's three named confinement mechanisms in
full -- single-target writes (`require_scoped_permission`), fan-out dispatch
(`dispatch_confined_arms` / `derive_exec_visible` / `authz::meet`), and list/fan-out reads (the
ADR-0017 triad `authorize_list_read` / `require_fleet_read` / `require_list_read`, plus
`confine_agent_target`) -- (b) `require_permission` (including its service-scope and MCP-tier
branches), and (c) `validate_assignment` (D3's write chokepoint) emits one shared decision shape:
axis (management-group / service-scope / RBAC-legacy / engine / **assignment-authority**),
outcome (admit-all / admit-scoped / deny / degrade), and a reason drawn from a closed taxonomy,
to both the audit log (with correlation id) and a Prometheus counter. Per-gate bespoke logging
that cannot be aggregated is non-conforming. Consistent with the codebase's existing
audit-failure posture (ADR-0033 §9, mutations fail closed on audit-write failure): **a mutating
authorization decision whose record cannot be durably written is itself denied, not admitted
with a missing record.**

**"Every authorization decision" is defined by reference to D5's own canonical, CI-proven
mechanism set, not by a second, independently-maintained enumeration (Gate-8 governance
finding).** Two earlier drafts of this clause each enumerated gates by hand and each omitted a
real one: the first omitted `validate_assignment` entirely (D3/D4/D11's escalation-safety and
SoD checks would have had no structured evidence); fixing that omission still left out
`require_list_read`, `confine_agent_target`, and the fan-out dispatch mechanism -- verified
directly against `require_list_read`'s own implementation, whose caller-class rejections
(non-Read, MCP-tier, service-scoped-token) each call a generic `audit_log()` today, precisely
the "per-gate bespoke logging that cannot be aggregated" this decision forbids, with no route
into any of the enumerated gates above them. A hand-maintained list drifted wrong twice in two
consecutive fix rounds because nothing forces it to track D5's own mechanism set as that set
gets corrected. This decision now points at D5's three mechanisms **as a set**, not by naming
each function separately, specifically so that D5's own coverage-proving CI check (which must
already enumerate every route/tool against those three mechanisms) is the single source of
truth both decisions read from -- a route D5's CI check classifies is a route D9 already knows
to instrument, with no second list to fall out of sync. `confine_agent_target` and the fan-out
mechanism's per-arm decisions (including D7's non-human-principal delegation decisions, which
compose through the same `authz::meet`) are named by this reference, not as separately-listed
additions. **"Covered by construction" is D5's own claim about route-to-mechanism reachability;
it is not, by itself, a claim about mechanism-internal completeness (PR review finding,
@fjarvis) -- softened from an earlier overclaim.** D5's coverage-proving CI check proves a route
REACHES the applicable mechanism; it cannot prove every internal admit/deny/degrade branch
inside that mechanism (a service-scope sub-check, a degrade path, a per-arm decision) actually
emits D9's record once it is written -- a later-added internal branch that returns without
calling the D9 writer would still pass D5's route-level coverage check while silently opening a
gap in D9's completeness. This decision therefore requires a separate, per-branch D9 contract
test for each of D5's three mechanisms, not only the route-level CI check D5 already has.

The new `assignment-authority` axis, and closed-taxonomy reason codes that distinguish a D4
delta-denial from a D11 SoD-denial from an ordinary permission denial, cover `validate_assignment`
specifically. **D3, D4, and D11 must each state that they route through this axis, not only D9
and D3 asserting it from one side (Gate-8 governance finding):** D4 and D11's own text did not,
as of the previous round, commit to anything -- an implementer reading only D4 or only D11 would
not know a discriminable reason code is expected from them. D4's grant-authority delta denial and
D11's SoD denial must each surface via `validate_assignment`'s D9 record using a reason code
specific to that decision, not a bare `deny`; this is binding on D4 and D11 as much as it is on
D9, not a one-sided obligation this decision imposes on itself alone.

**A fail-closed mutation denial must be distinguishable from an ordinary permission denial
(Gate-4 governance finding).** `rest_audit.hpp` already gives REST behavioural-PII reads a
distinguishing signal for exactly this situation (`Sec-Audit-Failed`, per the correction below);
this decision's mutation-side fail-closed clause does not yet have an equivalent. Under
sustained audit-store unavailability, every mutating gate this decision covers would deny
indistinguishably from a genuine 403 -- an operator or on-call responder chasing the outage would
see what looks like a permissions problem, not an infra one, across the entire mutating surface
of the product for the duration of the outage. This decision requires an equivalent
operator-visible signal on an audit-driven mutation denial, not only the denial itself.

**Correction (adversarial review, 2026-09-02): the read-only half of this decision, as originally
written, overrode an accepted ADR's existing per-surface posture rather than preserving it.**
ADR-0033 §9 does not say all reads degrade to observability-only on audit-write failure -- its
table entry for reads is "keep the surface's existing posture (`rest_audit.hpp`): REST
behavioural-PII fails closed with `Sec-Audit-Failed`; dashboard HTML and MCP set-and-proceed."
`rest_audit.hpp` implements exactly that split today: HTML fragments proceed (a transient audit
hiccup must not blank an operator's dashboard), REST JSON integrations reading behavioural-PII
data fail closed with a 503, specifically so a downstream CMDB integration never records
evidence-less PII as audited. A uniform "read failure degrades observability, not the decision"
rule, applied literally, would make a REST JSON behavioural-PII read proceed on an audit-write
failure -- the exact regression `rest_audit.hpp`'s existing design exists to prevent. **D9's
read-only clause is corrected to: a read-only authorization *decision* record (the new schema
this decision defines) failing to write degrades observability and is itself counted, but this
does NOT touch or override the existing, accepted per-surface posture for behavioural-data audit
records** -- REST behavioural-PII reads keep failing closed via `rest_audit.hpp`'s established
mechanism regardless of what this decision's own authorization-decision telemetry does. The two
audit concerns (a gate's admit/deny/degrade decision record, and a behavioural-data access
record) are related but distinct, and this decision governs only the former.

**This decision needs an explicit operational-cost design, not just a schema (second Sol
review).** Durably recording every admitted read authorization decision, not only denials, can
be substantial write volume on a busy fleet. Whatever implements D9 must specify batching,
bounded queues, and low-cardinality Prometheus label sets up front, and decide explicitly
whether admitted reads are sampled rather than recorded at 100% -- silently discovering this
under load in production is not an acceptable way to make that call. **That sampling rate is
also bounded by `audit_store`'s own capped retention pass (Gate-6 governance finding, if these
records land in that store, the natural reading): a sampling rate chosen without reference to
the reaper's own per-pass cap can grow the store faster than the reaper's steady-state throughput
even while the reaper runs healthily every cycle.** This decision does not specify a retention
posture for its own records either, and should: whether they inherit `audit_store`'s existing
clock-guarded default or need a longer window is a real question given a SOC 2 Type II audit
period runs roughly 12 months with fieldwork after the period closes -- a shorter default window
can prune period-start evidence (D2's own enable/disable event is the sharpest instance) before
an auditor ever examines it. This decision requires that whoever implements it states the chosen
posture explicitly, not that it picks one here.

**The existing `AuditEvent` envelope this decision would write into does not yet have the fields
this decision's schema needs (Gate-6 governance finding).** `AuditEvent` has no correlation-id
column today (only a free-text `detail` field, and `docs/observability-conventions.md` already
forbids adding `detail` to any queryable filter) and no `degrade` value in its `result` field --
so "queryable... with correlation id" and the `degrade` outcome this decision names both require
a schema addition to the existing envelope, not a mapping onto its current columns. This is
implementation, properly left to the store playbook per D3's own precedent, but it is not free:
whoever builds D9 needs a migration, not just a new write path.

**A fail-closed mutation-write's durability confirmation needs a stated mechanism, distinct from
the read-path's own batching design above (Gate-6 governance finding).** The read-path
operational-cost design (batching, bounded queues, sampling) trades latency-to-durability for
throughput -- correct for reads, unsafe for the mutation path, where a fail-closed gate must
confirm durability *before* admitting the mutation. This decision does not say whether that
confirmation is a synchronous per-request round-trip or a group-committed batch with a bounded
flush SLA, and therefore does not bound the latency this adds to every RBAC-gated write in the
product. Whoever implements the mutation-side fail-closed clause must choose and state one.

A decision engine built to D8 is expected to expose its winning grant/deny and reason as a
normal return value; an "explain this decision" surface (effective-permissions view, a
dry-run simulator) is a direct consumer of D8 plus this decision's closed reason taxonomy, not a
separate mechanism requiring its own architectural decision. **This covers a LIVE query only
(Gate-4 governance finding):** the persisted record's closed, low-cardinality reason taxonomy is
deliberately too coarse to name which specific grant/role/group admitted a *past* decision once
live state has since changed -- D8's return value can explain a decision made right now, but
this decision does not, as specified, let an operator forensically reconstruct why an audit-log
entry from last month was admitted. If that forensic capability is wanted, it needs its own,
necessarily higher-cardinality, audit-log-only field -- never Prometheus-labeled -- which this
decision does not currently add.

*Non-conformance today:* audit logging exists per-gate but is not uniform, and most gate callers
already ignore the audit helper's own success/failure return today -- **correction (second Sol
review): the fail-closed-on-audit-failure requirement is not merely prospective with nothing yet
to violate.** Fire-and-forget audit writes already happen on every existing gate; a store
outage today already produces exactly the silently-non-durable-record failure mode D9 forbids,
even though the unified decision-record schema itself doesn't exist yet. A management-group
confinement axis counter does not exist (ADR-0017's own INV-9 already calls for this and it has
not shipped, only the service-scope and RBAC-degrade axes have one today); a known audit
argument-order bug exists (#3219); denied and degraded outcomes are not always distinguishable
in the audit record -- confirmed concretely: `authz_gates.cpp`'s store-unavailable path returns
a 503-degraded gate result while auditing it as `"denied"` (#3739/#3256 track this class).
*Not yet built:* the unified record schema, the missing counter axis, and the effective-
permissions view and simulator this decision's engine would enable.

### D10 -- Time-bound, scoped grants are a distinct RBAC primitive from session elevation

A grant may carry a validity window (`valid_from`/`valid_until`), independent of the existing JIT
session-elevation mechanism. JIT elevation promotes a session to full admin temporarily; it is
neither role-specific nor scope-specific and must not be credited as satisfying this decision.

**Enforcement seam, corrected (Gate-2 governance finding):** an earlier draft named "the D3
chokepoint... on every read of that grant" as where expiry is enforced. That is wrong on its
face -- D3 is explicitly, in its own heading, a **write** chokepoint (`validate_assignment`,
scoped to assignment and revocation). The seam that actually reads a grant to answer a
permission question is `check_permission` / `visible_agents_for_permission` today, and D8's
Request-free decision core once that exists. Expiry must be checked there, not at D3; D3's role
is limited to rejecting an already-expired window at assignment time, which is necessary but not
what makes an in-flight grant stop being honored once its window closes.

**Cache correctness, corrected (Gate-2 governance finding):** this decision's first draft claimed
a validity window is already covered by "the existing invalidation rule this codebase has
already stated twice (ADR-0033 §3; ADR-0017 INV-8): no such cache may key on an input unless
every path that shrinks that input invalidates it. This decision does not introduce a new
invalidation mechanism; it inherits the existing one." That claim is false assurance, not
compliance: the codebase's actual invalidation rule (`RbacStore::perm_cache_`, keyed off a
durable `write_generation` counter bumped only *inside a mutation transaction*) invalidates on
writes. A validity window's expiry is not a write -- nothing bumps the generation when
`valid_until` merely elapses, so a decision cached before expiry can keep answering "allow"
after expiry until some unrelated mutation happens to invalidate the cache, which could be an
arbitrarily long time. The ADR-0033 §3 / ADR-0017 INV-8 rule is real and still applies to every
input it already covers (mutations); it simply does not, on its own, cover a purely time-driven
shrink, and this document was wrong to imply otherwise. This decision therefore DOES introduce
one new requirement beyond the inherited rule: any cache serving a validity-window-bearing
decision must either bound its entry's lifetime to `valid_until` (never cache past the window's
own expiry) or re-read `now()` against the stored window on every hit rather than trusting a
cached "allow" unconditionally. Whichever of the two an implementation picks, it is new
construction this decision adds, not something the existing mutation-triggered rule already
provides for free.

**The two options are safety-equivalent only if "bound lifetime" means enforced at read time, not
merely eventual reaping (Gate-4 governance finding).** A passive-eviction reading of "bound
lifetime" -- expired entries reaped by a background timer or on the next unrelated write, rather
than checked synchronously on every hit -- reopens the exact staleness gap this fix just closed:
a hit landing in the window between `valid_until` elapsing and the next reap cycle still returns
the cached "allow." Both options therefore require the same structural change regardless of which
is chosen: `perm_cache_`'s current value type (a bare `bool`, with no field for a deadline or the
window itself) must gain a per-entry expiry the read path checks on every hit. "Bound lifetime to
`valid_until`" and "re-check `now()` on every hit" are two names for the same read-time
enforcement, not two independently-safe alternatives -- an implementer must not pick a
timer-based reap believing it satisfies the lighter-sounding of the two options.

**The same fix must also reactivate a cached DENY when `valid_from` arrives, not only expire a
cached ALLOW at `valid_until` (PR review finding, @fjarvis).** Everything above addresses one
direction of the staleness problem D4 trigger #5 names: a future grant is fully specified at
creation but has zero effective delta until its window opens, so a decision cached as "deny"
before `valid_from` can keep answering "deny" after the window opens, for exactly the same
reason a cached "allow" can outlive `valid_until` -- nothing bumps the generation when a clock
boundary passes with no write. This is fail-closed (a functional defect -- a grant that never
activates on schedule -- not an escalation), but it is the same mechanism this decision already
requires, applied to the other edge of the same window: the per-entry expiry check the read path
performs on every hit must compare `now()` against BOTH `valid_from` and `valid_until`, not
`valid_until` alone.

*Not yet built* (not a defect -- this capability has never existed): only JIT-to-admin exists;
no assignment record carries a validity window. Access-review's `flagged_revoke` intentionally
records evidence only and does not itself revoke -- that is existing, correct policy and is
unaffected by this decision.

### D11 -- Static separation-of-duty is declarative data checked at the D3/D4 chokepoint; dynamic SoD is a separate, unaddressed decision

Mutually-exclusive role pairs (an INCITS 359-style static SoD constraint) are declared as data
and checked at assignment time by the D3/D4 chokepoint, not a separate validator that can drift
from the authority model it protects. Dynamic SoD (constraints on simultaneous session
activation) is a distinct, currently unaddressed decision, explicitly out of scope here.

**The checked set is the principal's full, group-inclusive effective role set, not only the write
being processed (Gate-5 governance finding).** D3's chokepoint now covers two distinct write
shapes: a direct role assignment, and (per D3's own Gate-4 extension) a group-membership add
against a role-bearing group. Declaring a SoD pair and checking it only against whichever single
write is in flight does not catch a pair assembled across both shapes -- role A assigned directly
to a principal today, then that same principal added to a group holding role B tomorrow, with
neither write individually seeing the other half of a declared A+B SoD violation. The chokepoint
must resolve the principal's complete effective role set (direct grants union every role-bearing
group they belong to, following the same membership resolution D5/D7 already use) before
consulting the SoD table on either write shape, not just the roles the current write touches.

**The mirrored write shape needs the mirrored check: assigning a role TO a member-bearing group,
not only adding a member TO a role-bearing group (PR review finding, @fjarvis, per D3's own
second chokepoint extension).** A direct role assignment and a member-add against a role-bearing
group are one pair of write shapes; assigning a role to a group that already has members is a
second, symmetric shape D3 now also routes through the chokepoint. When that write lands, the
principal the chokepoint sees is the GROUP, whose own effective-role-set resolution (above)
doesn't surface any individual member's OTHER roles -- so this decision's check must, on this
specific write shape, additionally resolve every CURRENT member's resulting combined role set
(their own direct/group roles union the group's newly-assigned role) and reject the write if any
member would land in a declared SoD-forbidden pair, not only check the group's own set against
the table.

**A blocked SoD pair routes through D9's `assignment-authority` axis with its own reason code
(Gate-8 governance finding, committed here rather than asserted only from D9's side).** A SoD
denial and an ordinary permission denial are different facts a SOC 2 reviewer needs to tell
apart, and D9 already names this as an expected discriminator; this decision is bound to produce
it, not merely benefit from it if built.

*Not yet built* (not a defect): no SoD mechanism of either kind exists today.

## Consequences

- **D1 is a correctness and availability defect, independent of everything else here.** It is a
  class of route that cannot be granted to an ordinary (non-elevated) principal once RBAC is on
  -- a fail-closed availability gap, not a disclosure. An earlier draft asserted this was
  unconditionally governance-CRITICAL; the second Sol review correctly pushed back that
  severity here should be derived through this codebase's own trigger+impact+exposure model
  when D1 is actually scoped as work, not asserted in the ADR itself.
- **D1 also retires a second catalogue** (`kRbacSecurables` in `mcp_server.cpp`), not only fixes
  five missing entries -- collapsing that mirror is part of D1, not a follow-up.
- **D5's coverage-proof clause changes what "PR-C/PR-E are done" means.** ADR-0017's existing
  ladder is not re-decided, but conformance with this document requires the CI coverage check in
  D5, not just "the callers were migrated."
- **D3 does not mandate merging `principal_roles` and `management_group_roles` into one table.**
  It mandates one validation chokepoint and one API-facing record shape. Table layout is
  implementation, not architecture, and is left to the store playbook.
- **D3 explicitly declines to add assignment-level deny.** A future decision that wants one must
  extend `resolve_perm_groups` (the single INV-7 resolver implementing the #1715-frozen lattice)
  with its own precedence rule -- this document does not do that implicitly via an unexamined
  `effect` field.
- **D6 extends ADR-0032 Decision 7's credential-recheck principle to BOTH the shipped Schedule
  feature AND Guardian, on this document's own authority, not as compliance with an ADR that
  already covers either (Gate-8 correction to an earlier framing that treated Schedules as
  already-decided).** Decision 7's own text governs a *Use-Case run* under the not-yet-built UCE
  admission protocol -- a different, real thing from the shipped `ScheduleRunner`/`InstructionSet`
  dispatch this document applies its principle to. Anyone implementing D6 should still check the
  credential-recheck mechanics against Decision 7's actual text, not just this document's summary
  of it -- not because the decision is in question, but because it is genuinely new construction
  for both dispatch classes, and the usual review a new mechanism gets before it ships.
- **D4 defaults to "grantor must currently hold what they grant," computed as a delta that must
  also catch authority that widens after the grant with no new assignment event** -- not just
  escalation visible at grant time. A `Grant` administrative-permission model is not adopted as
  the default but is left open as a future, separately-bounded primitive -- see Rejected
  Alternatives.
- **D7 is not a standalone mechanism.** Anyone implementing management-group-scoped engine
  assignments is implementing D3 and D5 for a third principal type, not a fourth mechanism.
- **D9's fail-closed clause means a mutating gate now has a new failure mode** (audit-write
  failure denies the mutation) that must be load-tested and alerted on, the same way any other
  fail-closed audit path in this codebase already is.
- **The open model decisions (#2665 additive-vs-deny-precedence for admitted runs; #2670/#2677
  derived-state confinement) are not resolved by this document** and are referenced, not
  restated. **Neither is #1836** (Gate-6 governance finding): a live session/token can retain a
  stale IdP-derived role until its next SSO login, since nothing invalidates a cached role on
  IdP-side group removal -- the mirror case of the latent-widening problem D4/D10 both address
  (there, a cached fact fails to *shrink*; here, a session fails to *shrink* to match an already-
  shrunk IdP fact). This document does not absorb #1836 as new scope; it is named here for the
  same reason #2665/#2670/#2677 are.
- **This document is silent on point-in-time-restore interaction with the durable state D2, D6,
  and D10 introduce (Gate-6 governance finding), and that silence is itself worth naming even
  without solving it** -- unlike D3's table-layout deferral, which states its reason, this gap
  was simply absent from every draft until Gate 6. A restore predating a Guardian orphan
  transition resurrects a Baseline as rooted under authority already revoked in the lost window;
  a restore predating a legitimate `adopt_baseline` re-pauses a correctly-adopted one; a restore
  predating a D10 grant's `valid_until` expiry resurrects an already-expired enforcement window.
  This document defers the mechanism to the store playbook, the same way it defers D3's table
  layout, but flags the topic rather than leaving it wholly unaddressed.
- **D2's atomic enable/disable has no stated rollout lever for a change of this blast radius**
  (Gate-6 governance finding) -- no shadow/audit-only third state, no staged or canary
  enablement across a fleet, despite this document's own Context section proving the blast
  radius is severe (every non-elevated principal 403s on five unseeded securable types today).
  D8's decision core and D9's decision record are exactly the primitives that would make a
  "log what would be denied, without denying" shadow state cheap to build on top of D2's binary
  toggle; this document does not add one, nor does it explicitly defer the question to a named
  follow-on decision the way D3 defers table layout. Flagged here as a gap in this document,
  not resolved by it.
- **D10's export/attestation composition is not automatic (Gate-6 governance finding): the
  already-shipped `AccessReviewStore` export schema has no field for a validity window today.**
  A completed access-review campaign would list a 3-day temporary grant identically to a
  standing one once D10 ships, with no field for a reviewer to tell them apart, unless the
  export schema gains one. Generalizing: any new assignment-record dimension D1-D11 introduces
  (D10's window here; D4's rejected-but-noted durable-ceiling option would be another) needs the
  same schema addition before that dimension is complete, not only a store-side implementation.
- **The already-shipped Periodic Access Review feature's export is evidentially void under
  today's shipped default, and this document is the right place to name that (Gate-6 governance
  finding, BLOCKING).** `RbacStore` seeds `rbac_enabled` to `false` by default, and per this
  document's own Context, no code path can flip it (#388) -- so on every install today, the
  grant table that feature's export reads has no bearing on actual access, which the legacy
  session-role model governs instead. The export artifact itself carries no caveat to that
  effect, and a completed attestation campaign is durable, no-prune evidence by design (per that
  feature's own routed concern) -- meaning a campaign closed today would certify a grant
  population with no relationship to real enforcement, with nothing on the artifact saying so.
  This is not new scope for D1-D11 to absorb: it is an additional, customer-facing reason (beyond
  the ones already given for sequencing D1/D2 first) that this feature's compliance claim is not
  meaningful until RBAC can actually be enabled, and it belongs in this document because nowhere
  else currently states it.

## Rejected alternatives

- **A `Grant` administrative permission (ADR-0033 §8's approve-without-holding model, applied to
  role assignment), as the DEFAULT for D3/D4.** Rejected as the default, with a correction from
  the second Sol review: an earlier draft called this shape "inherently a direct escalation
  path," which is too categorical -- a bounded grant-administrator role (constrained by an
  explicit, closed list of grantable roles/scopes, with its own ceiling, possibly requiring
  four-eyes) is a legitimate delegated-administration model in principle, the same way `Approve`
  is legitimate for approvals. The rejection is narrower: it is not the *correct default* for
  ordinary assignment, because an approval gates one already-scoped action while a grant creates
  open-ended standing authority for someone else, and defaulting to "administer without holding"
  for the latter is a materially larger blast radius than for the former. `Grant` remains
  available as a future, separately-decided, explicitly-bounded primitive layered on top of the
  D4 default -- not adopted as the default itself.
- **Merging the three confinement mechanisms in D5 into one, or requiring every route to reach
  only one of them.** Rejected on two grounds, one directly decided and one by analogy (kept
  distinct per the second Sol review): ADR-1006 Decision 2 directly and explicitly rejected
  merging `require_list_read` and `require_fleet_read`, because they answer different questions.
  Extending that reasoning to the third, dispatch-fan-out mechanism, and to the "at least the
  applicable ones, not exactly one" framing D5 uses, is this document's own architectural
  judgment by analogy, not something ADR-1006 itself decided -- stated as such rather than
  implied to carry ADR-1006's own authority. Three named, coverage-proven mechanisms, applied in
  whatever combination a given route's shape genuinely needs, are the target; a fourth, unifying
  abstraction is not.
- **Claiming ADR-0032 Decision 7 already covers Guardian by its own text.** Rejected: Decision 7
  names Schedules and excludes only the autonomous-sync-identity case; Guardian's continuous rule
  distribution is neither, so the text does not reach that far on its own. Asserting otherwise
  would have made an unfalsifiable claim about what an accepted ADR requires, rather than the
  honest one -- that applying the same mechanism to Guardian is a good idea this document adopts
  on its own authority.
- **Leaving the Guardian question open pending a future maintainer decision.** Rejected: the
  underlying facts (what mechanism to reuse, why it fits Guardian's problem shape) do not change
  by waiting, and this document's own frontmatter already grants Dave the authority to decide it.
  A maintainer or architect reviewing this document later is still free to push back on the
  reasoning -- that is what review is for -- but the document does not withhold a position in the
  meantime.
- **Row-wise "grantor holds this exact permission" as the no-escalation check.** Rejected in
  favor of D4's effective-authority-delta comparison, because the codebase has already frozen an
  additive (not deny-precedence) cross-boundary lattice (#1715); a row check cannot correctly
  reason about what a grant actually changes under that lattice.
- **Treating JIT session elevation as satisfying D10.** Rejected: JIT elevation is a temporary
  full-admin promotion, neither role- nor scope-specific; conflating the two would let the
  codebase claim a capability it does not have.
- **Building ABAC conditions, a policy simulator, or least-privilege recommendations now.**
  Rejected as premature -- each depends on D1-D9 holding first. Revisit under ADR-0033 §5's own
  stated trigger pattern for when its future auto-approval policy layer is built, not before.
- **Sequencing all of D2/D3/D4 (administration) to completion before any of D5/D6 (confinement),
  or the reverse.** Rejected on both sides, with a correction to an earlier draft's reasoning:
  the claim that an operable-but-underconfined RBAC is unconditionally "a worse state" than an
  inoperable one is **overstated**. ADR-0017's admit-then-filter design means a confined operator
  hitting an unmigrated route is denied (403), not over-disclosed -- the residual risk from
  under-migration is a bounded, enumerable class of genuine over-disclosure (the #3489 pattern:
  a caller with a *different* global grant plus a confined `Response:Read` reaching out-of-scope
  agents through an unscoped facet or count-oracle query such as `/api/scope/estimate`), not a
  blanket "anything unmigrated leaks." The stronger argument for running D1/D2 early rather than
  after D5 completes is that ADR-0017's own INV-9 ("the filter path is exercised and observable")
  cannot be verified in production without a confined operator existing at all, and only D2/D3
  create one. **D1 is not parallel to anything -- it is a precondition for a working enable path
  and should land as its own blocking change ahead of D2.** D2-D5 and D7-D11 otherwise proceed as
  independently governed workstreams (D6 held out separately -- see below), gated jointly by
  concrete, testable criteria before RBAC is described as production-supported: the D1 catalogue
  contract test passing, the D5 coverage proof passing, the enumerated #3489-class routes closed,
  and the ADR-0017 confined-operator (`opA`) UAT passing. "Both tracks feel done" is not a
  criterion; those four checks are. **D6 is excluded from this list on purpose** -- it is decided
  but, unlike the other decisions in this joint gate, describes a mechanism that does not exist
  in code at all yet (per D6's own "Current state"), so it has no work-in-progress to gate on
  today. It is not gate-independent forever, though: `adopt_baseline`'s authorization check is
  explicitly "per D4" (D6 sub-clause 3), so D6's own implementation cannot ship correctly ahead
  of D4's effective-authority-delta mechanism landing -- a real dependency, not a coincidence of
  timing, and D6's implementers should treat D4 as a prerequisite even though D6 sits outside
  this joint gate.

## Governance

**Current status: see the LAST numbered entry below, not this paragraph (Gate-8 governance
finding, third occurrence).** A specific gate/entry count stated here has gone stale three
separate times as entries were added -- caught and fixed at Gate 4 (this exact sentence), fixed
again in the closing paragraph at Gate 8's first pass, and found stale here a third time on the
next check. A snapshot restated at the top of a growing log is structurally guaranteed to drift;
the fix is to stop maintaining one here, not to write a fourth snapshot that will drift again.
Review history so far:

1. **Codex (Sol, `gpt-5.6-sol`), read-only opine, 2026-09-02.** Reviewed an earlier
   delivery-plan-shaped draft. Corrected several overclaims (call-site counts, a claim that the
   scheduler was still unconfined when #3133 had already fixed it, a stale issue reference to
   #2809 which was already fixed under #2703) and surfaced the D1 catalogue defect, independently
   verified. Recommended parallel administration/confinement tracks over strict sequencing.
2. **Fable (Claude, architect-agent review), read-only, 2026-09-02.** Reviewed this ADR-shaped
   draft independently, without seeing Sol's review. Corrected further overclaims (D1's "no
   contract test exists" -- three partial ones do, plus an unremarked second catalogue mirror;
   D5's restatement of an already-decided ADR-0017 invariant as if new; D6's "unfiltered by
   default" mischaracterization of an already-declared-but-unrooted dispatch). More
   significantly, found that **D6 as originally written directly conflicted with ADR-0033 §7 and
   ADR-0032's already-accepted "no unrooted system principal" rule**, and that **D4 silently
   picked an administrative model in tension with ADR-0033 §8's approval model** without
   reconciling the two. Both are folded into the current text. Verdict: not ready to propose
   until (a) D6's reconciliation is itself reviewed as a potential ADR-0033 amendment rather than
   asserted here, and (b) a maintainer/architect signs off on D3's explicit no-new-lattice-rule
   stance and D4's rejection of the `Grant` alternative.

3. **Codex (Sol, `gpt-5.6-sol`), read-only opine, round 2, 2026-09-02.** Given the specific task
   of adversarially cross-checking round 2's Fable-driven rewrite, not just the document.
   Independently re-read ADR-0033 §7/§8 and ADR-0032's actual text and found the round-2
   rewrite of D6 had overextended it: §7's human-root resolution is textually scoped to
   four-eyes ("must never be reused as a general identity-collapsing rule") and ADR-0032 governs
   UCE runs specifically, neither of which cleanly covers Guardian's rule push. Traced Guardian
   push's actual code path and found it aggregates rules from every currently-deployed Baseline
   before dispatch (`filter_deployed_members` over `deployed_member_rule_ids()`), meaning a
   single push can represent multiple deployers with independently-changing authority -- a
   problem round 2's "resolve to the deploying operator" framing had no answer for. Also caught
   a real arithmetic error (the document claimed nine decisions while containing D1-D11, and its
   sequencing criteria silently dropped D10/D11), an overclaimed unconditional CRITICAL severity
   on D1, an overclaimed "inherently an escalation path" characterization of the rejected
   `Grant` alternative, a gap in D4 around authority that widens *after* grant time with no new
   assignment event, and a missing operational-cost/audit-write-volume requirement in D9. All
   folded into the current text; D6 is now framed as an explicit, only-partially-decided
   extension to ADR-0033 with named open sub-decisions, not as an implementation of an
   already-settled rule.

The pattern across all three rounds is worth naming: each successive review found the *previous*
review's correction had itself gone slightly too far in one direction (round 1 found overclaims
in the original draft; round 2 found round 1 had under-corrected in places and over-corrected
in others; round 3 found round 2's own correction had overextended its source citations). This
is not evidence the process is unstable -- it is evidence that a single-pass review, however
good, should not be the last word on a document this dense with cross-ADR claims. At this point
in the document's history (three rounds in), this was read as grounds for treating D6 as needing
a heightened, D6-specific maintainer decision before proceeding; entries 8 and 10 below found
concrete, code-level defects three more rounds later, which is the actual reason repeated review
mattered here, not a standing rule that D6 carries a higher bar than any other decision in this
document -- see the closing paragraph below, which states the ordinary bar once the mechanism has
substantive content to review, and Governance entry 11 for what changed since this framing.

4. **Dave, 2026-09-02.** Decided D6 sub-clause 3 (Guardian's multi-baseline authority problem):
   an orphaned Baseline is surfaced loudly and resolved by an explicit, audited
   `adopt_baseline` hand-off to a currently-authorized operator -- never a silent drop, a
   fleet-wide push failure, or indefinite unrooted enforcement. Folded into D6 above, including
   the consequence that push construction must resolve each Baseline's root individually rather
   than continuing to union all deployed rules into one undifferentiated `system=true` dispatch.
5. **Dave, 2026-09-02.** Decided D6 sub-clause 5 (extending the same shape to scheduled dispatch
   and policy remediation) as an explicit non-uniform extension: schedules get the same
   orphan/surface/`adopt_schedule` shape as Baselines, since `Schedule.created_by` is already a
   stored, aging root the runner already partially re-checks (#3133); policy remediation does
   not, because remediation is operator-gated only and `Policy` carries no author field to orphan
   in the first place -- its fix is threading the live requesting operator's identity and
   credential through to dispatch, per sub-clause 4, not an adoption mechanism. Folded into D6.
6. **Dave, 2026-09-02.** Decided D6 sub-clauses 1, 2, and 6 in one round: (1) the "effect" D6
   binds for an always-on, disconnection-tolerant dispatcher is the point of distribution (the
   push), not each later moment of on-device enforcement, because push time is the only point a
   live authorization decision is architecturally possible; (2) the per-dispatch-class root
   table is settled for the four classes already decided, plus a default rule for every other
   `system_reserved` capability (root to whoever created the record being acted on, re-checked
   at dispatch, unless formally found to have none) -- applying that default, preflight needs no
   root at all (already read-only by design) and quarantine reconciliation's conformance is
   flagged unverified, not asserted; (6) no institutional-controller exception is granted to
   anything examined in this document, and any future one must meet the existing break-glass
   precedent's bar (narrow, individually reviewed, mandatorily audited, no gate skipped for
   being called an exception) rather than defaulting to a bare `system=true` flag. Folded into
   D6. **This left D6 with exactly one open item: sub-clause 4, credential recheck.**
7. **Dave, 2026-09-02.** Decided D6 sub-clause 4, the last one: "credential recheck" splits into
   two non-interchangeable mechanisms rather than one rule applied uniformly, because a live
   credential to recheck only exists for some dispatch classes. For live, human-present dispatch
   (policy remediation, any future "act now" flow), it means exactly ADR-0033 §8's model: the
   live session/token on the current request is checked, which sub-clause 5's fix for
   remediation already threads through. For durable dispatch with no live credential by design
   (Guardian push, Schedule fire, potentially months after the arming/deploying session ended),
   applying §8 literally would be a category error -- instead it means checking that the root
   principal's *account* is currently live and authenticatable (not deprovisioned, not
   deleted, not locked out), verifiable today via `AuthDB::user_exists`'s existing "active only"
   contract and `locked_until`, as a check independent of and additional to the current-RBAC-
   authority check sub-clauses 2/3/5 already require -- a principal can hold a fully valid role
   grant while their account is disabled, and D6 must not treat the grant lookup alone as proof
   the account behind it still exists. **All six of D6's sub-clauses are now decided. D6 is
   complete in substance; what remains is implementation and the sign-off below.**

8. **Fable (Claude, architect-agent review), read-only, final pass, 2026-09-02.** A different
   Fable instance than round 2, with no memory of it, reviewing fresh against a clean worktree
   checked out at the then-current `origin/dev` tip (code had moved since round 2/3 -- new
   commits touched `schedule_runner.cpp` and `server.cpp`, verified not to affect any cited
   mechanism). Explicitly instructed not to assume five prior rounds of correction made the
   document safe by construction. Confirmed D1-D5 and D7-D11 hold up completely on fresh
   verification -- every load-bearing code citation checked out. Found D6 had three real
   problems surviving all four prior rounds: (1) sub-clause 3 was **self-contradictory** --
   "continues to be pushed and enforced unchanged" and "excluded from that push cycle's rule
   set" cannot both be true once checked against Guardian's actual full-sync mechanism, where
   exclusion from a distributed rule set **is** disarming it on the agent; (2) Guardian
   distribution is event-driven, not a periodic "push cycle" as sub-clauses 1 and 3 assumed --
   a factual error, not a framing quibble; (3) most seriously, sub-clause 4's account-liveness
   answer to credential recheck **conflicts with ADR-0032 Decision 7 as imported by ADR-0033's
   general (not merely four-eyes-scoped) text** -- an accepted ADR this document's own
   frontmatter says it must compose with, not re-decide, and round 2/3's UCE-scoping objection
   answered a narrower question than the one it was used to settle. Also found: `Schedule`
   already has an account-existence check the document had credited as unbuilt (W2); quarantine
   reconciliation does NOT conform, reversing an earlier round's opposite-direction hedge (W3);
   a shared-Guard-rule gap (a Guard armed by multiple Baselines has no stated outcome when only
   some are orphaned); a re-evaluation-trigger gap (nothing ties an authority/credential change
   to a Guardian distribution event, so "paused" could mean "paused whenever something unrelated
   happens to trigger distribution"); and a live security critique -- using account lockout as a
   liveness signal is a spray-to-disarm vector, since lockout is an attacker-triggerable,
   temporary throttle against a known username, not an account-validity fact. Verdict: not ready
   for maintainer sign-off, another round scoped to D6 specifically.
9. **Dave, 2026-09-02.** Decided all three open questions from the final Fable review in one
   round, each reversing or substantially revising a prior decision: (a) sub-clause 4 now
   follows ADR-0032 Decision 7 -- record the arming credential (not just the human) on Baseline
   deploy and Schedule arm, stop enforcement on that credential's revocation/expiry/deletion,
   and handle routine token rotation via an explicit, lighter-weight **rebind** action distinct
   from full adoption; (b) sub-clause 3's orphan mechanics now honestly state that orphaning
   **pauses** enforcement (loudly, audited, immediately adoptable) rather than the
   self-contradictory "continues unchanged" claim, accepting that a paused-and-alarmed control
   is the correct trade-off given the mechanism Guardian actually has; (c) account-liveness
   checks, where they still apply, explicitly **exclude** `locked_until` -- lockout is a
   temporary, attacker-triggerable throttle, not a liveness fact, and folding it in would let
   anyone who learns a deployer's or armer's username deliberately disarm their Baselines or
   Schedules by spraying wrong passwords at their account. All three folded into D6 above,
   along with the shared-Guard-rule and periodic-re-evaluation-sweep additions the corrected
   mechanics required, and the quarantine-reconciliation and schedule-liveness factual
   corrections.

D6 was decided in substance across all six sub-clauses at this point, corrected twice by
external review after Dave's own decisions (rounds 4-7) were themselves found to need revision
by round 8 -- a pattern this document took as evidence that no single round of review, including
its own most recent one, should be treated as the last word. Two more rounds followed this one
(10, 11) and found further, code-level corrections -- see those entries and the closing paragraph
below for the actual current state, which does not carry a special "D6 needs more than the
ordinary review" rule going forward.

10. **Adversarial review (Kimi K2.7 + Codex GPT-5.5, two-phase independent review +
    cross-examination + synthesis), read-only, static, 2026-09-02.** Run against a fresh
    `origin/dev` checkout (`bd387afecf8e175f4234fa7e6f3412ac1f8a6b4a`) with the full document as
    the review target -- no diff exists, so this graded the document against the codebase and
    against its cited ADRs directly, not a code change. Both reviewers independently reached
    BLOCK in Phase 1 and held BLOCK through Phase 2 cross-examination, on largely overlapping
    grounds. Confirmed findings, adjudicated by the synthesizer against the actual code/ADR text
    (not just accepted from either reviewer): **(a)** D9's read-only audit-failure clause, as
    written, overrode ADR-0033 §9's accepted per-surface posture (REST behavioural-PII reads
    fail closed via `rest_audit.hpp`, not merely "degrade observability") -- fixed to scope D9's
    rule to the new authorization-decision record only, explicitly preserving the existing
    behavioural-audit posture untouched. **(b)** D6 wrongly listed "the capture-source push" as
    an unexamined `system_reserved`-class dispatcher, in three places, contradicting D6's own
    "direct human action is already rooted" text -- the route is in fact already a settled,
    correctly-rooted direct-human dispatch; removed from all three. **(c)** D5's "nine bare-gated
    routes" count was not reproducible by either reviewer (both independently found 7, with
    slightly different specific routes, and found that two of the "six unmigrated modules" use a
    legacy scoped provider rather than being bare-gated) -- corrected to not assert a hand-counted
    number the document's own coverage-proving test exists to make authoritative instead. **(d)**
    D6 misnamed Guardian's dispatch closure as the same one policy remediation and quarantine
    reconciliation use (`command_dispatch_fn`) -- Guardian actually uses a distinct path
    (`send_system_reserved`); corrected while preserving the underlying true claim that all three
    are equally system-rooted. **(e)** D6 sub-clause 4's account-liveness clause claimed
    credential validity "subsumes" account deprovisioning -- `ApiTokenStore::validate_token`
    checks only token revocation/expiry with no join to account-active status, so this was an
    unverified assumption, not a fact; corrected to require both checks independently. **(f)**
    the ADR-0032 Decision 7 framing was adjudicated directly against Decision 7's own text
    (synthesizer read it fresh rather than trusting either reviewer): Decision 7 unambiguously
    covers Schedules by name; it does not, on its own text, cover Guardian, which is neither an
    "operator-facing run" nor the excluded "autonomous-sync identity" case -- corrected to state
    this as this document's own extension-by-analogy for Guardian specifically, not a directly
    dictated consequence of existing text, matching what the disagreement between the two
    reviewers on this exact point (one held it, one withdrew it) already signaled was genuinely
    unsettled rather than a plain misreading either could resolve alone. **(g)** the quoted
    `TEST_CASE` count was stale (663 claimed, 571 reproduced) -- replaced with the reproducible
    command instead of a number that will drift again. All findings were text/citation
    corrections; none required a new architectural decision beyond what rounds 4-9 already made.
    D1-D4, D7, D8, D10, D11 were reverified and confirmed accurate with no changes needed.

11. **Dave, 2026-09-02.** Reworked D6's own text to drop the round-by-round "was this already
    decided by an existing ADR" narrative from the normative decision (preserved above in this
    Governance section instead, entries 1-10) and to state the Guardian credential-recheck
    extension as an owned decision on this document's own authority, not as a claim about what
    ADR-0032/0033's text already requires. Directed this rework and confirmed the document ships
    as one document, not split into a settled half (D1-D5, D7-D11) and a held-back half (D6).

12. **Fable (Claude, architect-agent review), read-only, sixth review, 2026-09-02.** A third
    Fable instance, no memory of rounds 2 or 8, reviewing the reworked D6 fresh against another
    clean worktree at the then-current `origin/dev` tip. Explicitly asked whether the rework's
    confident "owned decision" framing actually resolved the underlying instability or just
    relocated it. Verdict on the reframing itself: it works -- D6's mechanism is at least as
    strict as any reading of ADR-0033 §1/§7 could require, so "compliance vs. extension" has no
    normative consequence either way, and stating it as an owned decision is the honest position.
    But the review found the rework had moved D6's confidence off the ADR-text argument and onto
    two new, unverified mechanical premises, both of which turned out to be wrong on this
    worktree -- the most consequential findings across all six review rounds: **(a)** sub-clause
    3's claim that "every distribution event is a full sync" is false -- Guardian's push endpoint
    has an incremental (`full_sync=false`, the default) mode that does not wipe prior rules; only
    Baseline deploy/undeploy and the heartbeat reconcile are hardcoded full-sync, and the periodic
    re-evaluation sweep sub-clause 3 requires must itself trigger a full-sync distribution or it
    enforces nothing. **(b)** sub-clause 4's "record the session or API token id" would have
    auto-orphaned every dashboard-deployed Baseline within a single 8-hour session lifetime,
    since a `Session` carries no durable credential identity and `kSessionDuration` is an absolute
    cap -- a design gap serious enough that, taken literally, it would have made the mechanism
    nearly unusable for the common case of an operator deploying via the dashboard rather than an
    API token. Also found and independently verified: the quarantine reconciler's dispatch
    function is a plain no-caller shape, not "caller-typed in signature" as an earlier draft
    claimed; the "vacuous... under-specified" quote belongs to ADR-0032 Decision 0's corollary,
    not Decision 7's own text; `yuzu_schedule_arming_denied_total` is emitted by `arming_check`,
    not `resolve_caller`; `tar.fleet_snapshot` and `asset_tags.sync` were wrongly flagged as
    having no findable root (the first is already excluded as read-only, the second already has a
    live-session root); `adopt_baseline`'s authorization depends on D4, which the sequencing
    section's "D6 has no work-in-progress to gate on" did not acknowledge; and two places where
    the document's own history read as claiming D6 needs a permanently heightened review bar,
    which the rest of the document does not actually assert. Every finding was verified directly
    against this session's own reads of the code and of ADR-0032 Decision 7's and ADR-0033's text
    before being accepted, not taken on the reviewer's word. All folded into D6 and this
    Governance section above. D1-D5, D7-D11 held with no changes needed. Verdict: not ready
    without this round's fixes; ready once they land, which they now have.

13. **Fold `/governance` Gates 2-3 (2026-09-02).** Committed as `ADR-1008` (Dave's `1xxx` block
    per `docs/adr/README.md`; the number reserved above, "0066," was itself wrong -- 0xxx is the
    platform block, not Dave's -- caught before this round's agents ran) and run through the real
    pipeline for the first time: `security-guardian` + `docs-writer` (Gate 2), `architect`
    (Gate 3, triggered as normative cross-cutting architecture text extending the ADR-0031/32/33
    decomposition). One BLOCKING finding, from `security-guardian`: **D10's original text claimed
    a validity-window cache was already covered by the existing mutation-triggered invalidation
    rule (ADR-0033 §3 / ADR-0017 INV-8) and cited "the D3 chokepoint" as the enforcement seam --
    both wrong.** D3 is a write-only chokepoint by its own heading; the actual read seam is
    `check_permission`/`visible_agents_for_permission` (D8's future decision core). And the
    inherited rule invalidates on mutations, not on a validity window's wall-clock expiry --
    nothing bumps `RbacStore`'s durable generation when `valid_until` merely elapses, so a cached
    "allow" could survive expiry until an unrelated mutation happened to invalidate it. This was
    false assurance in the ADR text (a future implementer following D10 literally would ship a
    cache that never actually expires a grant), not a defect in shipped code -- D10 is fixed
    to name the correct seam and to require the cache either bound its lifetime to `valid_until`
    or re-check `now()` on every hit, as a new requirement this decision adds rather than one it
    could claim to inherit for free. Verified directly against `rbac_store.hpp`/`.cpp`'s actual
    `perm_cache_`/`write_generation` mechanism before accepting the finding. Two MEDIUM findings,
    both fixed: D2's "same transaction" spans two stores (`RbacStore`, `AuthDB`) with no existing
    joint-transaction primitive between them, now named explicitly as something D2 must build,
    not assume; D6 sub-clause 3's periodic re-evaluation sweep had no stated bound, now required
    to state an explicit tick/grace/floor the way `PolicyEvaluator` already does. Remaining
    findings were citation-location errors, all fixed: D5 miscited ADR-0033 §2 (capability
    declarations) for its fan-out-dispatch intersection when the actual anchor is §1's narrowing
    law; D6 sub-clause 4 misdescribed where ADR-0033 §7's "scheduled or background run" phrase
    sits (inside its four-eyes table, not separately from it) and missed that §7 opens with a
    caution against reusing it outside four-eyes; D6 sub-clause 5 repeated a resolve_caller/
    arming_check counter conflation this document had already once corrected elsewhere (Governance
    entry 10) -- a second instance of the same attribution error surviving a first fix, worth
    naming plainly rather than smoothing over. `docs-writer` found the frontmatter `status:` field
    carrying explanatory prose that belongs in `deciders:`/the body (fixed), a false claim that a
    since-removed "D12" heading still exists (fixed), and an opening paragraph under "## Decision"
    that led with draft-history trivia before D1 (trimmed). Both `docs-writer` and `architect`
    independently flagged the same pre-existing repo-wide `ADR-0031` number collision (two
    accepted ADRs share it); this document's own bare citations are now disambiguated, though the
    collision itself is out of this document's scope to fix. `architect` separately noted that the
    prior round's "D1-D5, D7-D11 held with no changes needed" claim (entry 12, immediately above)
    was itself not quite true -- the D5 miscitation this round fixed had already survived that
    claim once -- recorded here rather than edited into the historical entry, since the entry
    accurately reports what that round believed at the time. `compliance-officer`/`sre`/
    `enterprise-readiness` (Gate 6) and the happy-path/unhappy-path/consistency-auditor triad
    (Gate 4) are outstanding as of this entry. Verdict: not ready without this round's fixes;
    re-verify once the remaining gates complete.

14. **Fold `/governance` Gate 4 (2026-09-02).** `happy-path`, `unhappy-path`, and
    `consistency-auditor` ran independently against the post-entry-13 text. All three found real,
    non-overlapping gaps Gate 2/3 did not: `happy-path` found D3/D4's escalation chain never named
    RBAC group-membership growth as a widening trigger (`add_group_member` writes directly, with
    no call into `validate_assignment` -- verified against the actual function), and that D8's
    single-decision-core claim didn't account for ADR-1006 Decision 2's frozen, deliberately
    different `require_list_read`/`require_fleet_read` ladder (verified against that accepted
    ADR's own text). `unhappy-path` found four decisions that specify WHAT a mechanism must
    accomplish but leave fail-open-vs-fail-closed behavior under partial failure or concurrency
    unaddressed: D2's cross-store Administrator check names "same transaction" without a locking
    discipline, leaving a concurrent-deactivation race under ordinary `READ COMMITTED` isolation;
    D6's periodic sweep had no liveness signal, so the sweep itself dying silently defeats
    sub-clause 3's own "pauses enforcement, loudly" guarantee; D9's fail-closed mutation denial
    has no operator-visible signal distinguishing it from an ordinary 403, unlike the
    `Sec-Audit-Failed` precedent this codebase already has for reads; and D4's second,
    unspecified delta-computation mechanism never states that a failed computation must deny
    rather than default-allow. It also found D6's `adopt_baseline`/`adopt_schedule` transition has
    no concurrency control, against this codebase's own routed, catastrophic-if-violated
    guarded-transition precedent for the structurally identical Deployment/Preflight mutations.
    `consistency-auditor` independently found the most consequential gap of the round: D4's
    "effective authority" language silently narrows ADR-0033 §1's own accepted definition of that
    exact term (the full authenticated-actor ∩ represented-operator ∩ attenuated-credential ∩ ...
    intersection, which §1 states no applicable filter may skip) down to only the RBAC/
    management-group lattice via `visible_agents_for_permission` -- a grant request arriving on an
    attenuated credential could pass D4's check by riding its owner's broader RBAC standing,
    exactly the token-laundering escalation D6 and ADR-0032 Decision 7 already guard dispatch
    authority against, now found unguarded on the higher-stakes standing-authority-grant seam.
    This is the same false-assurance shape Gate 2 already blocked once in this document (D10);
    finding a second, independent instance of it in D4 is why Gate 4 exists as a distinct pass
    from Gate 2/3, not a formality. `consistency-auditor` also found D4 never cross-referenced
    D10's `valid_from` activation as a fifth latent-widening trigger, and that this Governance
    section's own opening line still read "Not run through `/governance`" after entry 13 had
    already run two of its gates -- both fixed. Every finding in this entry was independently
    verified against the cited code or accepted-ADR text before being accepted, distinguishing
    real false-assurance/omission defects (fixed into D2/D3/D4/D6/D8/D9/D10 above) from
    ordinary, already-flagged "not yet built" incompleteness (not re-litigated). Two findings
    (D2's connection-hold duration, D5's CI-test false-negative risk) were speculative and
    non-blocking per their own reviewer's assessment; noted here, not fixed, since fixing an
    unverified speculative concern risks adding false precision instead of real coverage. Gate 5
    (chaos-injector) and Gate 6 (compliance-officer/sre/enterprise-readiness) remain. Verdict: not
    ready without this round's fixes; ready once they land, which they now have.

15. **Fold `/governance` Gate 5 (2026-09-02).** `chaos-injector`, run because Gate 4 found
    substantive issues, stress-tested the Gate-4 fixes against each other rather than against the
    original text -- and found a real, nameable pattern: **two of Gate 4's own fixes (D2's
    Administrator-check locking, D6's `adopt_baseline` CAS) named a single-row/single-store
    concurrency primitive and claimed it closed a race that actually spans a DIFFERENT row or
    store.** For D2, the row-lock/`SERIALIZABLE` requirement covers the Administrator-existence
    check but not the self-grant branch's own precondition (the enabling operator's session-role
    standing), which resolves through an entirely different, session-cache-based consistency
    mechanism bounded by `kSessionGenStaleServeBoundMs` (30s) -- verified directly against
    `auth::effective_role`/`AuthManager`'s session-generation refresh code, not asserted from the
    ADR text alone. A Postgres row lock cannot reach a stale in-memory session, so a concurrent
    revocation of the enabling operator's admin role inside that window could still let the
    self-grant through; fixed by requiring the self-grant branch to re-verify against the durable
    store, not the session cache, inside the same locked transaction. For D6, the CAS on a
    Baseline's own orphan/adoption-state column closes the two-operators-racing-the-same-Baseline
    case but cannot observe the adopting operator's own RBAC/management-group grant rows, so an
    authority revocation landing between the D4 check and the CAS commit could still complete the
    adoption; fixed by requiring the D4 check inside the same transaction as the CAS, under the
    same discipline D2 now names. `chaos-injector` also found a genuinely new class of gap,
    distinct from the concurrency-primitive-scope pattern above: D11's static SoD check is
    declared as running "at assignment time," but D3's own Gate-4 extension widened that
    chokepoint to also cover group-membership writes, and D11 was never revisited to state that
    the checked role set must be the principal's full direct-plus-group-inherited set -- a
    declared SoD-forbidden pair could otherwise be assembled across a direct assignment and a
    separate group-membership add, with neither write's SoD check seeing the other half; fixed.
    Two prompted questions were checked and cleared with no defect: the Shared-Guard rule's
    interaction with concurrent adoption of different orphaned Baselines (the per-Baseline CAS
    scoping is correct here), and D9's audit-sampling clause vs. its new mutation-denial signal
    (the text already keeps these disjoint by construction; the reviewer's own note that a
    conflation is reachable only against the grain of the text is why this stayed non-blocking).
    The reviewer's own convergence assessment, worth recording verbatim in substance: the
    concurrency-primitive-scope pattern (Findings 1 and 3) is "narrowing in kind" -- the same
    nameable class recurring rather than new unrelated classes -- while the D11 finding shows a
    fix round can still open a genuinely new cross-reference gap when it widens one decision's
    scope (D3) without revisiting a decision that reads from it (D11). Gate 6 (compliance-officer/
    sre/enterprise-readiness) remains. Verdict: not ready without this round's fixes; ready once
    they land, which they now have.

16. **Fold `/governance` Gate 6 (2026-09-02) -- the last mandatory review gate.** `sre` returned
    PASS with 7 MEDIUM findings, no BLOCKING -- the first Gate 6 sub-reviewer in this run to clear
    without a block: D9's proposed schema doesn't map onto the real `AuditEvent` envelope's actual
    columns (no correlation-id field, no `degrade` result value); D6's sweep bounds cadence but
    not per-tick cost as fleet size grows, and has no multi-replica single-writer discipline
    despite this codebase's own precedent for the identical process shape; D9's admitted-read
    sampling decision doesn't reference the existing `audit_store` retention cap it would share
    load with; D9's fail-closed mutation-write names no durability-confirmation mechanism or
    latency bound, a materially different problem from the read-path's own batching design; D2,
    D6, and D10 are silent on point-in-time-restore interaction with the durable, time-sensitive
    state they introduce; D2's atomic enable has no shadow/staged/canary rollout lever for a
    change of this blast radius. All seven fixed. `compliance-officer` found one BLOCKING issue,
    verified directly against the text: D9's own heading claims "**every** authorization
    decision," but its enumerated gate list never included `validate_assignment` -- D3's own
    named write chokepoint, where D4's escalation-delta check and D11's SoD check actually run --
    so a blocked privilege-escalation attempt or SoD violation would have produced no structured
    evidence at all, the exact false-assurance shape this governance run has now found and fixed
    five separate times across five different decisions (D10 twice, D4, D6 twice, now D9). Fixed
    by adding `validate_assignment` and a new `assignment-authority` axis with dedicated reason
    codes, cross-referenced from D3. Also found and fixed: no stated retention posture for D9's
    records against a SOC 2 Type II audit period; D10's `valid_from`/`valid_until` not reflected
    in the shipped `AccessReviewStore` export schema; #1836 (IdP-deprovisioning staleness) never
    added to the Consequences "referenced, not restated" list alongside #2665/#2670/#2677; and
    that this document's own Governance-log narrative, while unusually rich change-traceability
    evidence with real preserved dissent (entry 3), uses entry numbers as its only identifiers --
    stable in this file, but not the `finding_id`/`governance.d/` ledger-fragment shape this
    codebase's own code-change governance runs produce, and not mintable yet since this document
    has no PR number; flagged for Dave to action at the point this is actually proposed as a PR,
    not fixed in this text. `enterprise-readiness` found one BLOCKING issue, also verified
    directly: the already-shipped Periodic Access Review feature's export is evidentially void
    under `RbacStore`'s own shipped default (`rbac_enabled=false`) plus #388 (no path to change
    it) -- a completed, durable-by-design attestation campaign would certify a grant population
    with no bearing on actual access, with nothing on the export artifact itself saying so. Fixed
    as a Consequences bullet naming this as an additional, customer-facing reason for the
    sequencing this document already argues, not new scope for D1-D11 to absorb. Three companion
    findings (stale RBAC rows in `docs/enterprise-parity-plan.md`/`docs/capability-map.md`;
    `docs/user-manual/rbac.md`'s fictional `[rbac]`-config/Settings-page claims, already tracked
    as #388; an `rbac_enforcement_active` field for the access-review export itself) are real but
    out of this document's scope -- filed here for whoever picks them up, not fixed in this text.
    Verdict: not ready without this round's fixes; those fixes are in this text, but **Gate 8
    (re-review of every gate whose domain the fix diff touched, plus the ledger and final
    decision) had not yet run when this entry was first written -- that sentence was itself a
    premature completeness claim, corrected here rather than silently edited away.** This fix
    round touched 8 of 11 decisions (D2, D3, D4, D6, D8, D9, D10, D11); assuming the largest fix
    commit of the whole run needed no further check would have repeated, in the governance record
    itself, the exact false-assurance pattern this run found and fixed five separate times in the
    decisions above.

17. **Fold `/governance` Gate 8, first pass (2026-09-02).** `security-guardian`, `architect`,
    `consistency-auditor` ran a fresh top-to-bottom read of the whole document (not just the Gate
    6 diff), plus a targeted self-check by `sre` of its own seven Gate 6 fixes. The self-check
    held up on all seven, with two trivial LOW findings folded in below. The three fresh reads
    found real, independently-verified problems -- proving the concern that motivated running
    Gate 8 at all (this document declared itself complete once before, at the end of entry 16,
    before Gate 8 had actually run; that premature claim was caught and corrected in a separate
    commit before this pass launched). `consistency-auditor` and `security-guardian` independently
    found the SAME defect from different angles: D9's Gate-6-fixed gate list, even after adding
    `validate_assignment`, still omitted `require_list_read`, `confine_agent_target`, and the
    fan-out dispatch mechanism (`dispatch_confined_arms`/`derive_exec_visible`/`authz::meet`) --
    `consistency-auditor` verified this by reading `require_list_read`'s actual implementation
    line by line and confirming its caller-class rejections use generic `audit_log()` calls, not
    D9's structured shape; `security-guardian` independently found the same gap by cross-checking
    D9's list against D5's and D7's own named mechanism inventories. This is the SAME recurring
    false-assurance shape found and fixed six times before in this document (D10 x2, D4, D6 x2,
    D9 once already) -- now found a second time inside D9 specifically, surviving its own Gate 6
    fix. Fixed structurally rather than by hand-enumerating a fourth time: D9 now defines its
    coverage by reference to D5's own canonical, CI-proven mechanism set, so a route D5's coverage
    check classifies is a route D9 already knows to instrument, with no second list to drift out
    of sync. `architect` independently found a different, previously-undetected instance of the
    same defect class in D6 sub-clause 4: the claim "ADR-0032 Decision 7 already decides this...
    compliance, not invention" for the shipped Schedule feature is wrong -- verified directly
    against ADR-0032's own frontmatter (scope: "the protocol by which a Use-Case run is
    admitted... "), Decision 7's actual text (governing scheduled *Use-Case runs* under the
    not-yet-built UCE admission protocol), and cross-grepping in both directions (zero references
    between ADR-0031/0032/0033/1005 and `schedule_engine`/`ScheduleRunner`, zero references
    between the shipped scheduler's code and ADR-0032/UCE/use-case). Six prior review rounds each
    confirmed the word "schedule" appears in Decision 7's text without checking it names the same
    real-world object D6 applies it to -- a referent-identity error, not a plain misreading.
    Fixed by reframing Schedules the same way Guardian was already framed: this document's own
    extension of Decision 7's principle by analogy, decided on its own authority, not compliance
    with an ADR that already covers the shipped feature. `consistency-auditor` also found D4's
    and D11's commitment to route through D9's new axis was asserted only from D9's/D3's side,
    with nothing in D4 or D11's own text committing to it -- fixed by adding the commitment to
    both. `security-guardian` separately, more leniently, flagged that `adopt_baseline`/
    `adopt_schedule`'s D4 check isn't named in D9's list either, but correctly judged this
    non-blocking since D6 already independently requires it audited on its own terms -- fixed by
    naming this as an open follow-on, not an already-closed gap. `sre`'s self-check found its own
    seven fixes accurate and appropriately scoped, plus two small governance-record slips: an
    entry-16 count mismatch ("7 MEDIUM findings" against "All six fixed" a few sentences later --
    fixed to "All seven") and a stale opening-line status snapshot that had now drifted three
    times (caught at Gate 4, fixed again at this Gate 8 pass's start, found stale a third time by
    this same pass) -- fixed by no longer maintaining a restated snapshot at all, pointing instead
    at the last entry in this log, which cannot go stale the way a duplicated count can.
    **Convergence decision:** per the explicit stop condition set before this pass launched (fix,
    one targeted recheck, then stop regardless of outcome rather than an open-ended Gate 9/10/11),
    this fix round is self-verified against the same code and ADR text the findings cited, not
    re-submitted to a third full four-agent Gate 8 pass. The pattern across the whole run is now:
    eleven total false-assurance-shaped findings, in D4 (x1), D6 (x3: sub-clause 3's sweep claim,
    sub-clause 4's Decision-7 citation twice), D9 (x2: `validate_assignment` then the wider
    mechanism list), D10 (x2). Two consecutive independent Gate 8 passes would be needed to have
    empirical confidence the pattern has actually stopped rather than merely narrowed; this
    document has had one. That is the honest state to hand to Dave, not "verified clean."

18. **PR #3891 review, @fjarvis (2026-09-02).** Requested changes on commit `2d6587ff1`, running
    four more independent reads (Codex+Kimi adversarial, a Hermes deep-cyber pass, a Fable
    enterprise-architecture adjudication) and personally verifying their findings against real
    code and the accepted ADRs before reporting -- exactly the practice this governance run has
    used throughout, now applied externally. Confirms the document's own entry 17 assessment: one
    Gate 8 pass narrows the pattern, it does not stop it. Two real, previously-undetected
    escalation-coverage gaps found from opposite angles, both now fixed: (1) role-DEFINITION
    edits (`create_role`/`set_permission`/`remove_permission`) were entirely ungated -- D4's own
    trigger #3 only detects a role-permission edit's effect on existing grantees after the fact,
    never gating the EDITOR's own escalation at the moment they add a permission they don't hold
    (Fable, verified against `rbac_store.hpp:202,226,246`'s actual signatures); (2) the mirror of
    D3's own group-membership fix was missing -- assigning a role TO an already member-bearing
    group bypasses per-member SoD checking the same way adding a member TO a role-bearing group
    used to bypass D4 (Hermes, verified against D3/D11's actual text). Both fixed by extending
    D3's chokepoint scope a further time and D11's checked-set requirement, the same shape as
    every prior fix in this family. Separately: D6's OPENING paragraph -- not sub-clause 4, which
    this run's own Gate 8 already fixed -- still asserted "For Schedules, this document is simply
    compliance," the identical false-assurance claim, missed because Gate 8's self-check grepped
    the specific sentence it had already found, not every restatement of the same claim elsewhere
    in the document (Codex+Kimi, independently; this is the twelfth instance of the recurring
    class, and the second time in this document specifically this exact D6/Schedule claim needed
    fixing). D2's own heading ("cannot produce zero active Administrators") was broader than its
    mechanism (enable-time only, nothing guarded a later revocation) -- fixed by routing a
    would-be-zero-admin revocation through the same D3 chokepoint, rather than leaving it as a
    named-but-unclosed gap. Session-armed durable dispatch conflated explicit `invalidate_session`
    revocation with ordinary 8-hour expiry under one exclusion, when this codebase has a real,
    distinct revocation event Decision 7's stop-on-revocation principle should reach (Codex,
    verified against `auth.cpp:1391`). D9's "covered by construction" over-claimed that D5's
    route-level coverage proof also proves mechanism-INTERNAL branch completeness -- softened,
    with a new per-branch D9 contract test required. D10's cache fix addressed `valid_until`
    expiry but not the mirrored `valid_from` activation of a cached deny -- fixed, correctly
    characterized as fail-closed (a functional defect, not an escalation). D4's durable-ceiling
    mechanism was silent on whether a snapshot re-validates against the grantor's CURRENT
    standing or only its own integrity -- this decision now takes an explicit position (it does
    not; that is what distinguishes mechanism (a) from (b)) rather than leaving the tension
    implicit. Two Hermes findings did NOT survive @fjarvis's own verification (quarantine
    reconciliation already disclosed non-conforming in D6 sub-clause 2; D9 already requires
    pre-admission durability confirmation) -- correctly not counted against the document, and not
    re-litigated here. @fjarvis's own recommendation, worth recording: D6 carries enough
    finding-density across its own review history that it may warrant a separate acceptance
    track from D1-D5/D7-D11, since it cannot ship ahead of D4 regardless. Not decided here --
    Dave's call.

Gates 2 through 6, plus one Gate 8 pass and one external PR review round, have run against this
document as ADR-1008, per entries 13-18 above. D6's implementers
should still read ADR-0032 Decision 7's text directly before building the Guardian mechanism, the
same way any implementer reads the ADR they are building a novel extension of, but that is
ordinary diligence, not a precondition on the decision itself. Given how much of D6's mechanics
were still wrong through six rounds of review plus this governance round, whoever picks up its
implementation should re-verify sub-clauses 3 and 4 against the code one more time before writing
to them, rather than trusting this document's citations as a substitute for that read.
