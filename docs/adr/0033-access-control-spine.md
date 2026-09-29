---
status: accepted
date: 2026-07-14
owner: "@dgr (Dave Rae)"
deciders: >-
  Ratified 2026-07-14 by @dgr and the engineering colleagues, via the access-control ballot
  (A1–A5, D1–D12, pins P1–P11, open questions G1–G10). Independent review of record (SOC 2
  Workstream F change-management evidence): a two-reviewer adversarial review (findings S1–S11,
  three blockers, all closed by this ADR set), a convergence pass over the finished set, and an
  overclaim sweep. Open questions G1 (cross-process event transport), G6/G7 (MCP session and
  replay-ring placement) and G10 (the Drogon build canary) remain open by design and are named
  as prerequisites, not resolved by this acceptance.
scope: platform — capability declarations, RBAC unit, token attenuation, approvals, execution authorisation, audit posture
depends-on: >-
  1005-headless-platform-use-case-engines (every capability is reachable by an external principal;
  this ADR is what "RBAC + audit enforced at the API" concretely means once capabilities can be
  declared by a Module rather than compiled into core).
  0017-management-group-confinement-list-reads (scope confinement is one of the narrowing
  filters below; this ADR does not restate it).
related: >-
  0031-presentation-core-engine-decomposition (the process boundary that makes "enforced once, in
  core" structural rather than reviewed — topology, TCB and the credential-pipe invariant live
  there, not here).
  0032-use-case-admission-protocol (the run/grant lifecycle, the release log, manifest ratification
  and version-locking, and the declared-mutability rules that classify a dispatch as fact or
  effect — this ADR consumes those and never restates them).
  `docs/auth-engine-principals-design.md` (2b — engine principals, delegation artifacts),
  `docs/auth-architecture.md` (roles, securables, operations, MFA step-up, JIT elevation),
  `docs/mcp-server.md` (the tier-before-RBAC ordering this ADR extends to declared tools).
---

# ADR-0033 — The access-control spine

## Binding status

Nothing here binds reviews or blocks PRs until this ADR's status is **accepted**. On acceptance the
Decisions bind **prospectively** — including §4's prohibition on new approval gates outside the core
primitive, which is a rule about the *next* gate, not a demand that the four existing ones be
rewritten (they migrate opportunistically, §4).

Tag families used throughout (ballot **A**/**D** rows, **P** pins, **G** open questions, **S**
adversarial-review findings) are indexed in **ADR-0031**.

## Context

RBAC, attribution, approvals and audit are usually treated as four features. They are not. They are
one **ordered pipeline** that every request transits at core's API:

```
authenticate → attribute → authorize (RBAC ∩ scope) → approval gate → audit → execute
```

The pipeline's *shape* exists today - fused into one binary, so every subsystem that needed a stage
grew its own partial copy of it. The unifying mechanisms this ADR adds - declared attenuation (§3),
the capability registry (§2), the single approval primitive (§4) and Execution Plans (§10) - do not
exist yet. There are already **four hand-built approval gates** (instruction approval
workflows, the agent enrollment queue, Guardian's dangerous-enforce gate, deploy's operator gate),
two independent re-authorisation idioms, and a hand-maintained list of MFA step-up surfaces. Each
was a reasonable local decision. Together they are a spine that was never named, and therefore never
enforced in one place.

Two things now make naming it urgent.

**Capabilities stop being compiled in.** Under ADR-1005 a use-case Module registers its tools with
core's capability registry at activation. A tool that arrives as *data* cannot be covered by a
permission model that only knows about securables someone typed into C++ last release. Unclassified
means unenforced, and "unclassified" is a hole shaped exactly like an engine.

**The actors we trust least authenticate with the credentials we attenuate least.** An API token
inherits its owner's entire role. An agentic worker doing read-only CVE triage today carries its
owner's patch-dispatch authority. That is the opposite of least privilege for precisely the class of
operator this platform exists to serve.

This ADR is **platform-wide, not UCE-specific**. Every rule below binds the dashboard, REST, MCP,
built-in capabilities and Module-declared capabilities alike. Where a rule needs the run/grant
machinery, it cites ADR-0032; where it needs the process boundary, it cites ADR-0031.

## Decision

### 1. The narrowing law: core is the only layer that may create authority

Every other layer — a credential, a Module, an approval — may only *reduce* it.

```
effective authority =
    authenticated-actor grants
  ∩ represented-operator grants      (when an operator is represented)
  ∩ attenuated-credential grants     (when a credential is presented)
  ∩ Module envelope                  (when a Module capability is invoked)
  ∩ execution authorisation          (when the operation is a protected effect)
```

A requested action (tool + parameters + scope) passes through the filters **that apply to its
operation class**, and **core denies the action if any applicable filter does not allow it**:

| Filter | Asks | Applies |
|---|---|---|
| **Authenticated actor** — the calling principal's own RBAC + scope | Can *this actor* (human, engine principal, service identity) perform this operation here? | always |
| **Represented operator** — the admitting operator's CURRENT RBAC + management scope | When the actor acts *for* an operator (a run, a delegated call), does that operator still permit it? | when an operator is represented |
| **Credential** — explicit attenuated grants (§3) | Was the presenting credential deliberately minted for this power? | when a credential is presented |
| **Module** — declared maximum envelope (§2) | Was this capability reviewed for this Module version? | when a Module capability is invoked |
| **Execution authorisation** — exact plan or bounded envelope (§4–§8) | When risk requires it, did a qualified supervisor approve? | when the operation is a protected effect |

The **Module envelope** is not the manifest. It is **core's ratified copy** of the module's
declarations, taken at manifest approval and version-locked at admission — the same object ADR-0032
Decision 13 names "core's ratified mapping". One object, and it is core's, or the filter is
self-certified by the thing it filters.

The same law, stated from the identity axis (it is one law, not two):

```
effective authority = IdP-mapped Yuzu grants ∩ current owner grants ∩ token grant subset ∩ Yuzu scope
```

An upstream OIDC group or OAuth scope may **narrow or select** a local mapping. It never directly
means "may perform operation X on these devices" until core resolves it against Yuzu's own
authorization store. The IdP answers *who*; Yuzu answers *may they*.

Filters are **intersections, and intersection is fail-closed**: an unresolvable, missing or
unparseable input for a filter that **applies** denies. No applicable filter may be skipped because
another one passed.

**Applicability is core-determined and typed, never a missing input.** A filter leaves the conjunction
for an operation *only* when core marks it not-applicable from the operation's declared class - there
is no represented operator on a direct expert call; no Module envelope when core *approves* a manifest
(the approval is what mints the envelope); no execution authorisation on a read. That is the only way a
factor drops out. Non-applicability is **never** inferred from a value a caller could have omitted, and
a missing input for an *applicable* filter denies. This is what lets the create-authority seams exist
without paradox: approving a manifest, or granting an approval, runs every filter that applies to
*that* seam and does not self-referentially require the authority it is about to create.

**The one typing that must not be self-certified is read-vs-effect**, because it decides whether the
execution-authorisation filter applies at all. It is **not** a free manifest field: it is core's
ratified mutability class (ADR-0032 Decision 8 / Decision 13), and on the dispatch path it is enforced
where the module cannot reach - the agent-side read-only envelope refuses a non-read-only action and
core quarantines on mismatch (ADR-0032 interlock (f)). A manifest that mis-declares an effect as a read
is caught there and at four-eyes manifest vetting (§2), never trusted because it typed itself.

### 2. The capability declaration is the RBAC unit (D1-C · G3 · G9)

Each registered tool or capability declares, at registration, a triple plus a tier:

- **`securable`** — reusing an existing securable wherever one accurately describes the protected
  resource; a Module mints a new securable only when nothing fits.
- **`operation`** — one of the existing six (Read / Write / Execute / Delete / Approve / Push).
- **`risk_tier`** — the routing input D5's future policy layer consumes, captured from day one.
- **`mcp_tier_class`** (read / write / execute) — so the shipped **tier-before-RBAC** ordering
  (`docs/mcp-server.md`) evaluates built-in and declared tools through **one chokepoint**. A new
  gate for declared tools is prohibited: extend the existing chokepoint, never parallel it.

A declaration also carries what ADR-1005 requires of **every** capability, because a module-declared
capability is not exempt from the platform's own rules: the **versioned REST twin and the MCP twin**
(both, or a recorded exception in ADR-1005's ledger), its **discovery entry** (it must enumerate in
`/api/v1/openapi.json` and MCP `tools/list` — ADR-0032's interlock (j) is what makes that possible),
the **A4 error envelope**, its **agentic-context annotations** (track 2g), and its **`data_class` +
`audit_verb`** so a device-attributable read is countable by construction (ADR-0032 Decision 11 emits
it with the release-log write). Without these, a module could declare a capability that passes all
the applicable §1 filters and still ships MCP-only, undiscoverable, or silently uncounted — a second-class
capability surface built by the same door we closed on ourselves.

Role administration therefore stays at securable granularity — the role UX does not become a wall of
per-tool checkboxes — while individual tools still carry an operation and a risk tier. The goal is
that **a new engine's permissions are data, not C++**.

**They are not, today, and that gap is this section's precondition.** Securable types are a
hard-coded C++ array seeded `is_system` into the RBAC store (`rbac_store.cpp:217-244`, 21 entries —
`SoftwareLicensing` was added to it by a code change, which is exactly the point);
`RbacStore` offers `list_securable_types()` and **no runtime create path**. So §2's own escape hatch
— "a Module mints a new securable only when nothing fits" — is a C++ edit, a recompile and a
release. **Building the runtime capability-declaration registry is core work, it is the precondition
for every rule in this section, and it lands on a store ADR-0006 also requires be migrated to
Postgres.** Until it exists, an engine ships with a core release.

**The declaration is the security boundary, so the declaration is vetted (G3):**

- **Namespace-bound.** `engine:vuln` may declare against `Vulnerability:*` and nothing else. A
  declaration outside the principal's namespace is rejected at registration, not audited after.
- **Approved, then diffed.** First registration and *every later change* park as a pending capability
  manifest for admin approval — the enrollment-queue pattern, reused. The diff is what an approver
  reads. A **permission expansion is a visible security change; it cannot arrive as an incidental
  Module upgrade.**
- **Manifest approval takes §4's full posture, four-eyes included.** This gate is where permissions
  become data, so it is the highest-leverage approval in the platform — and an approval gate without
  four-eyes is where a publisher approves their own privilege escalation. Approving a manifest
  therefore requires `Approve` on the registry securable, an **MFA step-up**, and an approver whose
  **human root differs from the module publisher's and owner's** (§7). Both principals are audited.
  **No eligible approver ⇒ fail closed** — never auto-approve, and never fall back to the publisher.
  §7 closes the *run-scoped* self-approval bypass; leaving this one open would close the small door
  and leave the large one ajar.
- **Undeclared means the capability does not register on ANY surface** — not "invisible to MCP but
  callable over REST", which would be the very UI-only/one-surface split ADR-1005 forbids. A missing
  or unparseable `mcp_tier_class`, securable or operation means the capability **does not exist**.
  Never "defaults to read".
- **Mind the chokepoint's existing default, because it is the opposite of this rule.** §2 says extend
  the shipped tier-before-RBAC chokepoint rather than parallel it — and that chokepoint currently
  reads: if the token carries no MCP tier, **allow** (it is not an MCP token, so tier policy does not
  apply). That default is correct *for token tiers* and catastrophic *for tool classes*: the naive
  extension — a second argument threaded through the same early return — inherits ALLOW for an
  undeclared tool. The deny-on-absent guard for the **tool's** declared class must sit **before** that
  early return, and a contract test must show an undeclared *tool class* denied while an absent
  *token tier* still defers to RBAC. Two defaults, one function, opposite directions.

How core's approved copy of the mapping becomes the *binding runtime input* — version-locked at
admission, with the Module's manifest reduced to a request — is ADR-0032 (S4); how a capability's
mutability is attested is ADR-0032 (P5/P9). This ADR fixes **what is declared and who vets it**.

### 3. Tokens carry their own, narrower grants (D2 · G8 · S9)

A token may be minted with a **subset** of its owner's authority:

```
effective = (token roles ∩ owner roles)  within  (token scope ∩ owner scope)
```

- The scope cap is expressed **in the existing scope language** — the single-scope-engine rule holds;
  no new dialect. "Read-only vuln triage, canary ring only" must be expressible at mint time.
- Narrowing only: the owner's **current** grants are one side of every intersection, so a token does
  not outlive a demotion. **This is enforced by code, not by construction** — the formula's *shape*
  guarantees nothing on its own, and it is real only once M5.3's contract test exists. (Saying
  "impossible by construction" here would contradict the migration rule below, which is written on
  the premise that the intersection is decorative storage until a test proves otherwise.)
- **A standing constraint on caching, stated forward rather than against today's code.** Authority
  decisions get cached — `RbacStore` already memoises permission decisions in `perm_cache_`, keyed
  `user:type:op` and invalidated by a generation bump on role/permission mutation. That cache holds
  no scope, so it has no stale-scope bug today. The rule that keeps it that way: **no authority cache
  may key on anything the intersection reads unless every path that shrinks that input invalidates
  it.** The moment a cache memoises a *scope-aware* decision, management-group and scope changes
  become invalidation paths — and if that is missed, a token outlives its demotion silently. Write
  the invalidation with the cache, not after the incident.
- Same intersection machinery as delegation (2b) and as the invocation grant (ADR-0032). One
  narrowing model everywhere, not three.

**Migration rule (M5 — the enforcement contract, not just the schema):**

1. Existing owner-inherited tokens are migrated with an **explicit** `attenuation = owner_inherited`
   marker. Legacy behaviour becomes a *declared* state; it is never an absence. No live token changes
   authority on migration day. **One statement, no window:**
   `ADD COLUMN attenuation TEXT NOT NULL DEFAULT 'owner_inherited'` — every existing row is
   attenuation-declared the instant the column exists. Drop the default afterwards so new tokens must
   declare. Add-then-backfill would leave a NULL window during which the reader must guess, and
   "guess" is how fail-open happens.
2. The column is a **closed enum with an explicit `default: deny`**: a token whose attenuation value
   is missing, unreadable or **unrecognised** is denied. `owner_inherited` is a *value*, not an
   absence — which matters, because a reader is one `if (value.empty())` away from treating absence as
   "no constraint". Contract test: a NULL and an unknown value both deny.
3. **Contract test, not a comment:** an attenuated token is *denied* an operation its owner is
   *allowed*. Without that test the intersection is decorative storage.

Per-task sub-principals (a managed identity per worker run) remain a plausible later layer **on top
of** attenuation, not an alternative to it.

### 4. One core-owned approval primitive (D4)

A capability declaration may carry `requires_approval`. When it does, invocation **parks** as a
durable pending-approval object in core rather than executing:

- Approving requires the **`Approve` operation on that securable**, an **MFA step-up**, and
  **requester ≠ approver** — meaning distinct **human roots** (§7), never merely distinct
  principals.
- Execution audits **both** principals — requester and approver.
- Over MCP the call returns a **pending** state and resolution rides the **existing** SSE/progress
  spine the executions ladder already uses (`docs/executions-history-ladder.md`). No parallel
  notification path is created for approvals. **Once presentation is a separate binary, that spine
  needs a cross-process transport it does not have today (G1) — a prerequisite, per ADR-0032
  Decision 9, not an assumption.**
- **Pending-approval hygiene:** approvals expire (7 days), and an approved-but-stale request
  **re-resolves its scope at execution** (§8) — approving yesterday does not authorize against
  today's larger cohort.

The four existing gates migrate **opportunistically**, not big-bang. The binding rule is
directional: **no new approval gate may be built outside this primitive.** Guardian's
`dangerous_enforce_in_spec` is the standing precedent for how this goes right — one chokepoint,
extended, never parallelled.

### 5. Approvals are manual in v1 (D5)

Policy auto-approval ("auto-approve if risk tier is low *and* blast radius < N devices *and* the
requester is a human with a standing role; park everything else") is clearly where this ends up. It
does not ship in v1 — but the **risk tiers it consumes are captured from day one** (§2), so the
policy layer arrives with real inputs rather than a speculative rule language.

**One explicit trigger is recorded now:** when approval volume produces rubber-stamping, that is the
signal to build the policy layer. *Approval fatigue is worse than no gate at all* — an approver
trained to click yes without reading is a control that reports success while providing none.

### 6. Approvers are humans in v1 (D8)

v1 approvals are **humans-only outright**. The schema stays policy-actor-ready — it can *represent* a
non-human approver — but **enabling** one requires a later ADR plus explicit administration. A safer
initial posture without a data-model dead end.

### 7. Four-eyes compares human roots, and a run's requester root is the admitting operator (D9 · P11)

Requester and approver must resolve to **distinct human roots**. Distinct *principals* alone never
satisfies four-eyes:

**One caution before the table: this resolution is for FOUR-EYES ONLY.** It answers "which human is
behind this actor", and it must never be reused as a general identity-collapsing rule. ADR-0032's
admission idempotency namespace, for instance, keys on the **credential** (token id / session id), not
on the owner — because collapsing an attenuated token onto its owner there would let the token inherit
the owner's unattenuated authority, defeating §3 at the seam §3 exists for. Same human, different
question.

| Principal | Resolves to (for four-eyes) |
|---|---|
| API token | its owner |
| engine principal | its named human owner |
| delegated call | the delegating operator |
| **any run-scoped effect** | **the admitting operator (P11)** |
| **a scheduled or background run** | **the humans who authored its effect-bearing definition** (the *armer* is the run's admitting operator, whose live authority confines it — ADR-0032 Decision 7 — but the armer is a four-eyes root only if they also authored the effect) |

Alice's worker can never approve Alice's other worker.

**A scheduled run has no interactive operator, and that is exactly where a root goes missing.**
P11 says the requester root is the admitting operator — but a 03:00 cron-style run admits itself.
Two distinct roles are **bound at arming time** (ADR-0032 Decision 7, which keeps them apart): the
schedule's **admitting operator** - the *armer*, whose CURRENT authority confines every run it
produces - and the **four-eyes requester root**, which is the set of humans who authored the effect
(below) and includes the armer only if they authored it. The armer's authority is **re-checked at
every execution** (§8), so a departed or demoted scheduler does not keep dispatching effects from
beyond the grave: a schedule whose armer can no longer perform the action **stops**, does not fall back
to the engine's owner, and does not run as a system principal. **There is no unrooted effect** - and,
because the four-eyes root is the author-set and not the armer, neither the armer nor an author can
approve the schedule's effect.

**"Last modified" must never launder the root.** The naive rule — *the human who created or last
modified the schedule* — is a four-eyes bypass with a one-character edit: Alice authors an
effect-bearing schedule (root = Alice, so she cannot approve it), Bob renames it, the root becomes
Bob, and **Alice now approves the effect she designed**. So the root is the **set of humans who
authored the schedule's current effect-bearing definition** — its targets, scope, capability and
parameters — and the approver must be outside that set. An **effect-bearing edit re-arms the
schedule and re-requires approval**; a cosmetic edit (a rename, a description) changes no root and
requires nothing. The question four-eyes asks is *who designed this effect*, not *who touched this
row last*.

**P11 closes a real bypass**, not a hypothetical one: a plan raised by `engine:vuln` (owned by Alice)
*inside Bob's run* would otherwise resolve its human root to Alice — letting **Bob approve his own
run's plan**. For any run-scoped effect the requester root is the **admitting operator**; the engine's
named owner is recorded, and is never the root. (What a run is, and who admits it: ADR-0032.)

### 8. Approval is a gate, not a grant (D10)

An approved action executes under the **requester's** authority **and the requesting credential's**,
both **re-checked at execution time**. This is authority seam 5 (ADR-0032 Decision 0), and it is the
only seam that touches endpoints:

- Requester revoked → the approval is **void**, not merely stale.
- **Requesting credential revoked, deleted or expired → the plan is VOID**, exactly as requester
  revocation voids it. Without this, an approved plan is a frozen authorisation that credential
  revocation cannot reach: an attenuated worker token leaks, drives a run that submits a plan, a human
  approves it, you revoke the token — **and the effect fires on the fleet anyway**. The plan therefore
  records the **requesting credential**, and execution re-reads its current grants.
- **A voided plan is LOUD, and it is re-authorisable.** A control that stops without saying so is the
  defect ADR-0032 Decision 7 fixes for schedules, and it would be the same defect here — worse, because
  a plan can void **mid-rollout**, leaving the fleet partially changed (that partial state is visible
  only through §10's coverage envelope, which is why it is interlock item (i) and not an optional
  field). So: `yuzu_execution_plan_voided_total{reason=requester_revoked|credential_revoked|credential_expired}`
  is a counter with an alert, and the operator is offered a **re-authorisation** path rather than a
  dead end.
- **Rotation is not a governance event, here as well as there.** ADR-0032 Decision 7 rules that
  re-arming a schedule after a credential rotation is an audited authority change and *not* an
  effect-bearing edit. §8 needs the twin rule or the asymmetry becomes approval fatigue: a routine
  90-day token rotation would void every approved plan and demand **fresh four-eyes on an unchanged
  effect**, which §5 calls worse than no gate at all. So the rebind rule is **narrow, and keyed on an
  explicit classification, never on "same owner"**: re-binding a plan to a **routine-rotation
  successor** - a credential the auth store records as succeeding the approved one under a
  **credential-level predecessor/successor relation with a terminal-reason classification**
  (`rotation_superseded` vs `compromise`). That relation is a **new required mechanism** (interlock
  item (n)), **not** the existing 2b §3.1 `superseded_by` (defined on `EnginePrincipalStore`), which links *engine-principal* successors
  after *terminal* revocation (compromise recovery included) and would wrongly treat a post-compromise
  replacement as the approval-preserving successor. Rebind additionally requires **equal-or-narrower
  attenuation**, an **unchanged plan hash**, and a **fresh MFA step-up** - then it is an audited
  authority change, not a new approval. Everything else is not a
  rebind: a credential recorded as **`compromise`-revoked** (not `rotation_superseded`) has no valid
  successor for this purpose and **cannot preserve an approval** - a compromise discovered during an
  overlap window disqualifies the pair **and revokes both credentials** (2b's terminal
  revoke-both behavior), so the plan is voided and is **re-authorisable through fresh
  four-eyes** (it is not permanently dead), never rebound silently; and a **different requester**, a
  **broader** attenuation, or **any change to the plan hash** is a new plan needing new four-eyes. The
  classification is core's - the auth store distinguishes `rotation_superseded` from `compromise` at
  revocation time - and only the former is an input to this rule.
- **Setting the classification is itself an authority act, and it is not frozen.** `rotation_superseded`
  vs `compromise` is recorded by core under an **authorized, audited** action - **never self-set by the
  credential's holder** (who, if the credential is compromised, is exactly whom the classification
  defends against). And reclassifying a credential to `compromise` *after* a rebind - a rotation later
  discovered to have been a compromise - **voids every plan and schedule rebound to its successor, and
  to any transitive successor in the rotation chain**,
  retroactively, exactly as a first-instance compromise would. A classification an attacker could set,
  or that could not be corrected once wrong, would be no control at all.
- Requester's scope shrank → the run gets **smaller**, never grandfathered.
- Approvers need `Approve` on the securable and **never the underlying permission** — low-privilege
  reviewers stay possible, which is what makes four-eyes deployable at all.

**An approved plan outlives its run, and executes on the requester's authority — not the run's.**
The ambiguity here is worth naming because both of its branches are bad. Runs are TTL'd and reaped
(ADR-0032 Decision 5); approvals are durable for 7 days. If plan execution required a *live run*, a
human's approval would become **silently unexecutable** the moment the reaper fired — an approval
that visibly succeeded and did nothing. If it ignored the run entirely, an effect could execute with
no live authority context at all. Neither is acceptable, so: **an Execution Plan is authorised in its
own right.** Once core has accepted it, the plan carries its own frozen targets, its own plan hash and
its own requester root; the run that *produced* it may reach a terminal state without voiding it. What
is re-checked at execution is the **requester's current authority** (above), never the run's liveness.
The run id remains on the plan as evidence — it is how the plan joins the chain — but it is not the
plan's licence to execute.

Deploy's re-authorize-every-tick behaviour is the shipped precedent for this rule; it becomes the
platform's, rather than one feature's.

### 9. Audit-failure posture: mutations fail closed (D6)

When the audit write fails mid-request:

| Class | Posture |
|---|---|
| Mutating capability, or **any** approval-gated action | **Fail closed.** No audit row → no mutation. |
| Reads | Keep the surface's existing posture (`server/core/src/rest_audit.hpp`): REST behavioural-PII fails closed with `Sec-Audit-Failed`; dashboard HTML and MCP set-and-proceed. |

An **unattributable mutation** is the one thing a fleet-control product may not produce. An
unattributable page-view during an audit-store outage is survivable, and it is flagged. Making
*everything* fail closed instead would turn the audit store into an availability single point of
failure for read traffic; making everything proceed would be disqualifying in any enterprise
security review.

The read half of this rule is tightened for engine tools returning device-attributable data — that
extension is ADR-0032 (S6), not restated here.

### 10. Effects cross core as immutable Execution Plans (D11)

A **fact** is acquired under the caller's authority. An **effect** crosses a plan boundary. (Which
dispatches are which — the declared-mutability classification and its mutating-by-default posture —
is ADR-0032.)

**Execution Plan.** An immutable, resolved plan with exact versions, parameters, targets, fact
references and a **plan hash**. Prepared by a Module or by core; **authorised and executed by core**.

- **Approval binds to the plan hash**, and to nothing looser. A material plan change invalidates the
  authorisation — it does not silently inherit it.
- **Targets are frozen in the plan; execution may only narrow them.** These two rules look like they
  fight, and an implementer must be told they do not: §4 says a stale approval "re-resolves its scope
  at execution", and re-resolving could *add* a device, which would change the targets, change the
  hash, and invalidate the approval that was just given. So: the plan's target set is **frozen at
  authoring**, the hash covers it, and at execution core intersects that frozen set with the
  requester's **current** authority — devices may **drop out, never in**. The hash never changes; the
  run only ever gets smaller. This is exactly what the shipped `/auto` deploy path already does
  (freeze the cohort, re-authorise every tick), and it is the reason "approve at 17:00, execute at
  09:00" has one answer instead of two.
- **Authority-monotone is not the same as operationally safe.** Narrowing the cohort can never make a
  plan over-authorised, but it can make it *invalid*: a phased rollout, a quorum change, or a
  coordinated client/service update can be more dangerous done to half a cohort than not at all. So a
  plan **declares its cohort-integrity condition** (all-or-nothing, minimum quorum, ordered waves, or
  none), and at execution core checks the narrowed set against it. A narrowed cohort that fails the
  condition **parks or denies** - it is never executed as an unsafe subset merely because the subset
  is authority-monotone. §10's coverage envelope reports a partial execution *after* the fact; the
  integrity condition is what prevents an unsafe partial execution *before* dispatch.
- Execution authorisation is **time-limited** and one-use where appropriate.
- The approving human may **approve, veto, narrow or escalate**. A supervising model may *recommend*
  those actions; it can never widen or authorise. (**Narrow** mints a *derived* plan with its own hash
  and its own approval - the immutable plan is never edited in place; **escalate** routes to a
  different approver, and never widens authority.)
- An enterprise messaging service may notify a supervisor and carry a deep link. **Approval occurs
  only on the trusted Yuzu presentation surface** — never in the notification channel.
- **Reuse before invention:** a Use Case composes existing **Instructions and Workflows** wherever it
  can. Specialist Module code is reserved for domain interpretation, derived state and external data
  — a Module does not get to build a second execution engine.

**Execution is claim-once, and the claim linearises against revocation.** "One-use where appropriate"
is not enough for the object that touches endpoints, so the concurrency contract is normative:
execution acquires a **guarded claim (CAS)** on the plan's execution record - the same
one-way-transition pattern as ADR-0032's run state machine and the shipped `/auto` deploy
`claim_for_exec` - so two ticks, two replicas or a retry commit **exactly one** execution record per
plan-execution identity, and agent-side idempotency (ADR-0031 B7) makes that at most one endpoint
effect. The authority re-check (requester + requesting credential, above), the claim,
and the audit write **commit together**; only a committed claim may publish the command to the gateway
(a durable outbox / at-least-once hand-off, deduplicated by the agent, ADR-0031 B7). There is **no
check-then-dispatch window**: a revocation landing between the check and the dispatch loses to the
claim's transaction boundary - it either voids the plan before the claim commits, or the command was
already durably enqueued at the linearisation point and any repeat delivery is idempotency-suppressed
downstream. The detailed schema is deferred; this
linearisation point is not.

**Coverage envelope — part of every distributed answer.** A distributed query cannot honestly return
only rows; it must state how much of the intended fleet answered:

| Field | Meaning |
|---|---|
| `intended` | endpoints in the authorised resolved scope |
| `contacted` | endpoints to which core attempted delivery |
| `responded` | endpoints returning a valid result before the deadline |
| `failed` | endpoints returning a terminal error |
| `timed_out` / `offline` | known non-responses, kept **distinct** from an empty or negative result |
| `scope_basis` | `global` or `authority_scoped`, computed by core from the caller's confinement **status**, never from the data (ADR-0032 Decision 11), **conservatively across the run** (`authority_scoped` if any read's confinement ceiling was below the intended scope - a status, not a row count) - **independent of `completeness`**. A **fleet-wide claim** requires the intended scope to be the whole fleet, `completeness = complete`, AND `scope_basis = global`; `scope_basis = global` alone never licenses a fleet claim (a fleet-authorised caller may intentionally scope narrow). This is **not** a count of withheld rows: a per-query withheld figure is a one-bit existence oracle over forbidden data (ADR-0017 INV-3), so the numeric matched/withheld figures stay core-internal and reach only a caller whose full applicable effective authority resolves to global read. |
| `completeness` | `complete` · `partial` · `insufficient` · `unknown`, **relative to the requested/intended scope** (did everything asked-for answer). A fleet-wide claim requires intended-scope = fleet AND `complete` AND `scope_basis = global`; a `complete` result over a narrower intended scope (by choice, or by `authority_scoped` confinement) is complete only within that scope |
| `policy` | the declared threshold, and whether incomplete evidence blocks the next step — **subject to a core-owned ceiling** (below) |

**Missing evidence is never a negative finding.** "No vulnerable devices found" and "62 devices never
answered" are different sentences, and the platform must not be able to say the first when it means
the second.

**The completeness policy is declared by the module and CEILINGED by core.** ADR-0032 gives the
module-declared run TTL a core ceiling for the same reason this one needs it: a module that may
declare its own honesty threshold can declare `complete` at 1% coverage, and the platform would then
render a lie *truthfully*. Core's ratified mapping (ADR-0032 Decision 13) carries a minimum
completeness bar per risk tier; a manifest declaring a laxer one is **refused at activation**, not
honoured at runtime. And coverage itself is **core-verified, never engine-asserted** (ADR-0032
Decision 11) — core performed the dispatch, so core knows who answered.

**Compensating recovery — never fictional rollback.** Endpoint effects cannot be rolled back
atomically, and the product will not pretend otherwise. Each state-changing capability **declares its
reversibility class**: *naturally reversible*, *compensatable*, *retry-safe*, *verification-only* or
*irreversible*. A recovery plan that creates new effects is **separately authorised** — it is a plan,
subject to every rule in this section, and it is linked to the effects it compensates.

**A broken fleet must not be un-fixable because the person who broke it left.** Recovery is a plan,
so it needs a requester root (§7) — and the obvious root, the operator who authored the original
effect, may be exactly the person who has been offboarded or demoted, which under §8 **voids the
approval** and strands the fleet mid-change. So: an **Administrator holding `Approve` may adopt the
root of an orphaned recovery plan**, audited as an explicit adoption (both the original and the
adopting root are recorded), with four-eyes then applying against the *adopter*. Without this rule,
§7's "there is no unrooted effect" would be true and would mean "there is no recovery".

### 11. Module presentation contributions are declarative-only (D7)

Capability views are **generic and schema-derived first** — a Module is usable by humans on day one
with zero presentation change. A Module may contribute **reviewed, declarative** metadata, forms and
result-rendering hints. **Arbitrary executable routes or templates never load into presentation**;
bespoke views ship through the normal release process, and analytical dashboards ride the existing
Prometheus-native metrics surface rather than a Module-supplied renderer.

This is an access-control rule, not a UI preference: presentation terminates operator credentials
(ADR-0031), so a Module that could inject executable code into it would be inside the credential TCB
by the side door — an authority-widening path that no filter in §1 evaluates.

## Consequences

- **The four existing gates become migration targets, and the fifth is prohibited.** Instruction
  approval, the enrollment queue, Guardian's dangerous-enforce gate and deploy's operator gate keep
  working; new approval-shaped behaviour lands in §4's primitive. Without this rule the fifth gate
  gets built by a Module team, outside core, and it is the one that is subtly wrong.
- **Schema deliverables, all born-on-PG** (ADR-0012; queued in `docs/postgres-migration-ladder.md`):
  attenuation columns on `ApiToken`; the pending-approval object; the Execution Plan record + plan
  hash; capability-declaration tables (core's approved copy); the coverage envelope on distributed
  results. The audit-envelope columns (D12) ride the audit-store migration and are specified in
  ADR-0032.
- **Deciding attenuation now is cheaper than deciding it later.** It is a schema change on
  `ApiToken`; after the auth store's Postgres migration it is a schema change *plus* a data
  migration under load.
- **Works-council counters become possible and cheap — not free.** §2's declarations give every
  capability a place to hang its own audit verb (the shipped `device.live.*` /
  `emit_behavioral_audit` pattern), but the verb is still declared per capability and routed through
  the `rest_audit.hpp` chokepoint by hand, and the counting/reporting surface does not exist. What
  §2 actually buys is that **no capability can arrive unclassified — so none can arrive
  uncountable.**
- **Every capability declaration becomes a security-review artifact.** That is the cost of Modules
  being data: the manifest diff is now something a human must actually read, and it is the last human
  check before core's registry copy becomes binding.
- **This spine is a prerequisite, not a companion, for the split-plane code paths.** The sequencing
  interlock that says which of these must land before any ADR-0032 code path ships lives in
  ADR-0032; it is not duplicated here, so that there is exactly one place to look for it.
- **Latency and UX are unaffected in the common case.** Browsing, asking questions, exploring options
  and *producing* a plan use the operator's normal authority. A new execution authorisation is
  required only when a plan crosses a protected-effect boundary, or when risk tier, scope, novelty or
  confidence says supervision is warranted.

## Alternatives considered

- **Keep building per-feature gates** (D4-A). Fastest per feature; N approval UIs, N audit shapes, N
  four-eyes implementations of varying quality. Rejected: it is exactly how four gates already
  happened, and it fails silently — a wrong gate looks like a working one.
- **One securable per Module** (D1-A). A read-granted agentic worker could invoke everything the
  Module offers, including an expensive recorrelation. Rejected: ad-hoc per-tool checks get bolted on
  afterwards, and that is how parallel gates are born.
- **One securable per tool** (D1-B). Maximally precise; every new tool mints an RBAC row and role
  administration becomes a wall of checkboxes nobody audits. Rejected.
- **Owner-inherited tokens forever** (D2-A). "Create a dedicated low-privilege account per worker"
  works today, proliferates service accounts, and nobody actually does it. Rejected: it leaves every
  agentic worker over-privileged in practice, and the first prompt-injected worker holding patch
  authority is a headline, not a bug ticket.
- **Policy auto-approval in v1** (D5-B). Designing a rule language before knowing which rules anyone
  wants. Rejected — deferred behind §5's explicit trigger.
- **Non-human approvers designatable per securable** (the pre-synthesis D8). Rejected for v1: the
  schema stays ready, the capability does not ship without its own ADR.
- **Everything fails closed on audit failure** (D6-B) — maximal integrity; an audit-store outage
  becomes a full platform outage including browsing. **Everything proceeds with a flag** (D6-C) — a
  fleet mutation with no audit row. Both rejected; §9 splits by mutability instead.
- **Atomic fleet rollback.** Rejected as undeliverable: endpoint effects are not transactional.
  Promising it would make the recovery story a lie at exactly the moment an operator depends on it.
