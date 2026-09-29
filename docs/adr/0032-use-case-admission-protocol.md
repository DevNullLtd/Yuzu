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
scope: >-
  platform — the protocol by which a Use-Case run is admitted, authorised mid-flight, evidenced,
  finalised and reaped. Pins ballot A5's protocol semantics (pins P1–P10; pin P11 is owned by
  ADR-0033 §7) and closes the adversarial review's S2/S3/S4/S6/S7/S8 findings. Tag families
  (ballot A/D · pins P · open questions G · review findings S) are indexed in ADR-0031.
depends-on: >-
  0031-presentation-core-engine-decomposition (the topology this protocol runs on: core admits and
  mints the grant; presentation calls the engine directly; the engine reaches facts and effects only
  through core). 1005-headless-platform-use-case-engines (engine principals; no UI-only
  capabilities; one public surface).
related: >-
  0033-access-control-spine (registry-declared RBAC and manifest vetting, token attenuation, the
  approval primitive, Execution Plans, the coverage envelope, four-eyes and P11 — this ADR
  cross-references them and never restates them). 0017-management-group-confinement-list-reads (the
  admit-then-filter chokepoint this protocol confines against, ADR-0017 PR-A; #1715 prerequisite). 0012-server-postgres-store-contract
  (every new core store named here is born on Postgres). docs/auth-engine-principals-design.md (2b —
  the delegation artifact the invocation grant IS). docs/adr-1005-execution-plan.md (Phase 4 engine
  principals; the M3 gate whose style the sequencing interlock below copies).
---

# ADR-0032 — The Use-Case admission protocol

## Binding status

Nothing here binds reviews or blocks PRs until this ADR's status is **accepted**. On acceptance,
the Decisions bind prospectively and the **sequencing interlock binds immediately** — it is a
precondition on shipping code, and a precondition can only be honoured before the code exists.

## Context

ADR-0031 fixes the *shape*: core is the admission-and-authority chokepoint, not the byte path.
Core admits the run and mints an audience-bound grant; presentation then calls the use-case engine
(UCE) directly with it; the UCE reaches facts and effects only through core. That shape buys the
audit chokepoint without making core parse, proxy and re-aggregate every domain payload.

It also leaves a protocol undefined — and an undefined admission protocol is precisely where the
audit gap lives. If "the run is authorised in core" is a sentence rather than a state machine, the
first module ships with an invocation nobody can prove was admitted, a cached result nobody
re-confined, and a disclosure record that lives in a database core cannot read.

The 13 July grill pinned six protocol semantics (P1–P6); the round-4 auth/provability review pinned
five more (P7–P11) and promoted the evidence envelope to a named deliverable (D12). A Kimi+Codex
adversarial review then returned BLOCK on the ballot with three findings, two of which are this
ADR's job:

- **S2** — A5's sequencing named Phase-4 engine principals and the ADR-0017 gate, but *not* the
  D12 audit schema or the P7 release log, which its own confinement and DSAR stories consume. An
  implementation could ship admitted runs whose disclosure cannot be proven from core-owned
  evidence.
- **S3** — P8 stated the cached-result subset rule but named no component that runs it before result
  bytes move. Scenario: Alice's scope shrinks from A+B to A; the UCE serves the cached A+B aggregate
  on run id alone.

Both are fixed by writing the protocol down normatively. That is this ADR.

**What this ADR does not own.** Registry-declared RBAC and manifest *vetting* (D1-C/G3/G9), token
attenuation (D2/G8), the approval primitive (D4/D5), four-eyes and the run-scoped requester root
(D9/P11), execution under the requester's authority (D10), Execution Plans, the coverage envelope
and compensating recovery (D11) — all **ADR-0033**. The binary decomposition, the credential-pipe
invariant (ballot D3, named there as **INV-31-1**), the presentation TCB statement and the
failure-posture table — **ADR-0031**. This ADR cross-references those by number and never restates
them.

## Terminology

- **Use-Case run** (the *run*) — one admitted episode of one use case, identified by a
  core-minted `use_case_run_id`.
- **Admission** — the core-side act of authenticating, authorising, scoping, risk-tiering and
  auditing a run *before* any UCE work begins.
- **Invocation grant** (the *grant*) — the short-lived, audience-bound artifact core mints at
  admission. It **is** the 2b delegation artifact (RFC 8693 token-exchange family), not a parallel
  mechanism.
- **Result-scoped grant** — the grant minted by a cached-result re-admission (Decision 10). It
  authorises the release of *one* stored result and nothing else. It is **one logical serve
  authorization**, idempotent on replay by the same caller and serve-run (Decision 10 step 5), not a
  count of network deliveries - core authorizes the serve and cannot observe delivery.
- **Release log** — core's own record of which device data it released to which run. The primary
  disclosure evidence (Decision 11).
- **Finalisation receipt** — core's record that a run completed, with the canonical result hash,
  result schema, coverage and a link to the UCE's journal entry. **Integrity, not authority.**
- **Fast lane** — a cheaper admission path for low-risk read-only use cases and cached-result
  serves. A cheaper admission, **never a skipped one**.
- **Core's ratified mapping** — core's own copy of an activated module's declarations, taken at
  manifest approval. The binding runtime input (Decision 13). The manifest itself is a *request*.

## Decision

### 0. Authority is evaluated at every seam in this inventory; each seam runs every filter that applies to it

This decision exists because the drafting of this ADR kept getting it wrong in the same way, and the
mistake is invisible one seam at a time.

**This is a seam INVENTORY, not a count.** An earlier draft of this decision said "exactly four" and
was short by one — which is this decision's own defect, committed one level up, in the enumeration
itself. So the rule is written to survive being incomplete: **any place the platform decides whether
an actor may do a thing is an authority seam, and it runs every filter of §1 that applies to it
(applicability is core-typed, never a missing input; ADR-0033 §1). Finding a new one
extends this list; it never creates an exemption.**

| # | Seam | Owner |
|---|---|---|
| 1 | **Admission** of a run | Decision 1 |
| 2 | **Every mid-run core call** (fact reads, capability requests) | Decision 4 |
| 3 | **Mint** of a cached-result grant | Decision 10 |
| 4 | **Redemption** of that grant — the seam that hands over bytes | Decision 10 |
| 4b | **Release of a freshly composed result** to presentation (finalisation) | Decision 12 |
| 5 | **Authorisation and execution of an Execution Plan** — the seam that touches endpoints | ADR-0033 §8 |
| 6 | **Granting an approval** (who may approve a plan) | ADR-0033 §4, §7 |
| 7 | **Approving a capability manifest** — where permissions become data | ADR-0033 §2 |
| 8 | **Authorising an event/progress subscription** | Decision 9 — **open**, owned by G1: until the cross-process transport is designed, presentation's routing table would be the confidentiality boundary between operators, which INV-31-1 says presentation never holds |

Each of them evaluates **every filter of ADR-0033 §1 that APPLIES to it** —

```
authenticated-actor grants
  ∩ represented-operator grants      (when an operator is represented)
  ∩ attenuated-credential grants     (when a credential is presented)
  ∩ Module envelope                  (when a Module capability is invoked)
  ∩ execution authorisation          (when the operation is a protected effect)
```

— and **a seam that omits an APPLICABLE filter is a bug, not an optimisation.** Applicability is
**core-determined from the operation's class**, never inferred from a missing input a caller could
omit; the create-authority seams (approving a manifest mints the Module envelope; granting an approval
mints the execution authorisation) run every filter that applies to *them* and do not
self-referentially require the authority they are about to create. Successive drafts dropped the
**credential** term at three of the four seams it then enumerated; each omission independently let a deliberately
attenuated token act with its owner's full authority, which is worse than having no attenuation at
all, because the operator believes the worker is confined.

Corollaries, all normative:

- **Every filter reads LIVE, except the ceiling.** A frozen snapshot may only ever *narrow*: it is the
  ceiling the run may not exceed. Anything that can be *revoked* — the operator's authority, the
  engine's grants, the module's liveness, **and the credential** — is re-read at every seam. A frozen
  input is an input revocation cannot reach, and revocation that cannot reach a live run is not
  revocation.
- **Whatever admits a run supplies a credential.** If a seam has no credential to filter on, the
  answer is never "then that filter is vacuous" — it is that the seam is under-specified. Scheduled
  runs (Decision 7) therefore record an **arming credential**, and it is the admitting credential of
  every run they produce.
- **Seam 5 bites hardest, and it was the last one found.** An Execution Plan is authorised in its own
  right and outlives the run that produced it (Decision 5) — so if its execution check reads only the
  *human* requester's authority, the plan is **a frozen authorisation that credential revocation
  cannot reach**, on the only path that touches endpoints. The attack is short: an attenuated worker
  token leaks; within its own envelope it drives a run that submits a plan; a human approves it; the
  leak is detected and **the token is revoked** — and the effect fires on the fleet anyway. ADR-0033
  §8 therefore re-checks the **requesting credential's current grants** alongside the requester's
  authority, and a revoked, deleted or expired requesting credential **voids the plan**.

**The inventory is enforced by a contract test, not a promise.** Decision 0's "finding a new one
extends this list" is only safe if a drift is caught: **every authorization decision point in the code
- every place core answers "may this actor do this" - must resolve to a registered seam that runs the
applicable conjunction, and a build/contract test must fail on an authorization site outside this
inventory.** Seam 4b's own late discovery is why this is a test rather than a habit - the inventory
drifts, so the build must catch it (the same posture as INV-31-4's route-enumeration test, ADR-0031).

### 1. A run is one declared episode (P1)

One admission, one input hash, one scope ceiling, one finalisation. Multi-step work happens
*inside* the UCE, under the one run — not by re-entering core with a chain of related invocations.
Iterative agentic triage is therefore **many small runs**, which makes the cost of admitting a run
a first-class design constraint: the admit path is a **single round trip and one audit row**.

A **fast lane**, declared per use case in the manifest (and projected into the agentic-context
capability annotations of track 2g — *not* to be confused with ballot row A5, this ADR's topology),
applies to low-risk read-only use cases: no approval routing, no plan, no
mutation path. It is a cheaper admission, not a skipped one — it still authenticates, still
authorises, still writes `use_case.run.admitted`, still mints a grant.

The admission request carries: `use_case_id@version · module_id@version · raw inputs ·
requested scope · correlation_id · idempotency_key`. Core authenticates the stable principal,
resolves RBAC and management-group scope, applies token attenuation, evaluates the risk tier from
**its own ratified mapping** (Decision 13), and writes `use_case.run.admitted` or a denial. There is
no admission that produces no audit row.

**Admission is idempotent, and it must be.** The split introduces a localhost hop between
presentation and core, so the ordinary retry — a lost response, a double-clicked button — now
happens on the admission path. Without an idempotency key, one operator intent becomes two runs, two
grants, two engine executions, **two release-log entries recording one disclosure twice** (a DSAR
that over-reports), and for a mutating use case, **two Execution Plans**. So: core dedupes on
`idempotency_key`, and a repeat admission within the run's lifetime **returns the existing run and
its grant** rather than minting a second.

**The dedupe namespace is `(admitting CREDENTIAL, idempotency_key)` — never the key alone, and never
the human root.** This is not a detail; without it the idempotency key becomes the same
attacker-chosen selector that filter (0) exists to kill, moved one seam earlier. **Credential-level,
not owner-level, is the load-bearing word.** ADR-0033 §7 resolves an API token to *its owner* for
four-eyes purposes, and an implementer who reuses that resolution here would key the namespace on the
human — at which point Alice's broad browser session admits run R under key K, and Alice's
**deliberately attenuated, read-only agentic-worker token** (precisely the credential ADR-0033 §3
exists to distrust) replays K, **hits**, and is handed R's id and R's grant, admitted under her
*unattenuated* authority. Attenuation would be defeated at the exact seam it was invented for. So:
**two credentials of the same owner never collide.** The namespace is the token id or session id. A caller-supplied key with a global namespace lets
operator B replay operator A's key, receive **A's run id and A's grant**, and read under A's authority
— filter (0) binds the run to its *engine* caller, not to the operator, so nothing downstream would
catch it, and the release log would attribute the disclosure to A. Therefore: **a key collision across
principals is a MISS, never a hit**, and **no admission ever returns a run or a grant admitted by a
different principal.** The natural key (`principal + use_case_id@version + module_id@version +
input_hash + resolved scope`) is used when the caller supplies none; an explicit key is preferred,
because "same inputs" and "same intent" are not the same thing and only the caller knows which it
meant.

**Admission is one transaction.** The run row, the audit row and the grant are written together or
not at all. Three transactions would permit a partial admit — a live run with no audit row — which
is precisely the state this ADR exists to make impossible.

### 2. Core computes the input hash; the UCE rejects inputs that do not match it (P1)

**Presentation sends raw inputs; core canonicalises and hashes them.** Canonicalisation living in
one place is what stops it drifting between the hasher and the verifier. Core returns the canonical
input document alongside the run id and the grant; presentation forwards that document to the UCE
**verbatim**.

The UCE **recomputes the hash over the inputs it actually received and rejects any request whose
inputs do not match the grant's `input_hash`** — the "mismatched grant" rejection, made explicit.
Without it, presentation could declare one input set to core and hand a different one to the UCE,
and the run's evidence would describe work that never happened.

### 3. The grant is the 2b delegation artifact, and it gates run START only

Core mints, on admission, a short-lived, audience-bound grant binding: the admitting **principal**;
`use_case_id@version` and `module_id@version`; the `input_hash`; the **scope ceiling** (the resolved
device scope, frozen); the **risk tier**; the **intended caller** (Decision 7); and an **expiry**.
It is server-issued and never self-authored by presentation.

Two properties are load-bearing:

- **It is the same artifact family as 2b delegation** (RFC 8693 token exchange, audience-bound,
  short-TTL, server-issued). A5 deliberately pulls a bounded slice of Phase-5 delegation forward;
  it does not invent a second credential type. The **invocation** grant's format follows 2b §5 -
  **opaque, server-side, keyed by `jti`, not a self-contained JWT** - the same as every artifact in
  the family; this ADR does not re-open it. What this ADR adds is only that its *one-use* property
  comes from the run state machine (`admitted → executing`), not from the token, so no signing scheme
  is needed to enforce single use. The **result-scoped** grant's format is *not* deferred — see below.
- **The invocation grant gates starting the run, nothing else.** Its TTL is not the run's authority.
  Every subsequent core call is authorised by Decision 4's server-side lookup, so a long-lived run
  does not need a long-lived credential, and a **stolen invocation grant expires without carrying
  the run with it**.

**The invocation grant is one-use too, via the guarded-transition pattern you already have.** The engine's first
core call on a run performs the guarded `admitted → executing` transition (Decision 5); a call
presenting a grant for a run **not** in `admitted` is refused. Without that, presentation could
replay one grant inside its TTL and open N concurrent executions on one run id — N sets of fact
reads, an ambiguous finalisation, and the collapse of Decision 1's "one admission, one finalisation".

**No grant in this protocol is a bearer capability over data.** That is a deliberate design
constraint, and it is the reason Decision 10 makes the **result-scoped grant** redeemable **only at
core**, with a guarded CAS and a re-run of the subset check at redemption. An earlier draft of this
ADR let the engine serve cached bytes on the result-scoped grant alone; that would have made it a
one-use ticket whose one-use property was enforced by the engine — the component the grant exists to
constrain — and whose theft, inside its TTL, yielded rows. It is now **a ticket core adjudicates**,
not a token that authorises. No grant, of either kind, entitles anyone to bytes without a core call.

**The RESULT-SCOPED grant's format follows from that, and Decision 10 settles it:** a stateless
*signed* grant cannot be one-use, because nothing consumes it. The result-scoped grant is therefore
**opaque and server-side**, with core holding the record it CASes. Leaving *that* format deferred
would let an implementer pick signed, silently downgrading one-use to advisory and re-opening S3.
(The invocation grant is unaffected: its one-use comes from the state transition, and its format is
already fixed opaque/server-side by 2b §5 - see Decision 3 above.)

The UCE rejects a grant that is missing, expired, wrong-audience, or mismatched against the request
it accompanies — and, for a result-scoped grant, one that core refuses to redeem.

### 4. Mid-run authority = engine principal ∧ server-side run lookup (P2)

The UCE authenticates **every** core call as its own 2b engine principal — never as the operator,
never on a caller-asserted identity (ADR-1005's on-behalf-of ban is unamended by this protocol).
Core authorises each such call by looking the run up **server-side** and requiring, conjunctively:

0. **the calling engine principal, and the `module_id@version` it presents, are exactly the ones
   bound into the run row at admission** — the run is *the caller's own* run;
1. the run is **live and unexpired** - core evaluates `now < expires_at` inline on every core call,
   against core's own clock, so authority expiry never depends on the reaper (Decision 5's state
   machine flips the terminal state; the clock check, not that flip, is the authority boundary);
2. the request falls inside the run's **frozen scope ceiling**;
3. the engine principal's **own grants** permit the capability;
4. the **admitting operator's CURRENT authority** still permits it — re-evaluated per call, not
   frozen at admission;
5. the module version and capability are still **live** (Decision 6);
6. the **admitting credential's attenuated grants** still permit it — **the snapshot frozen into the
   run row at admission ∩ that credential's CURRENT grants**. The snapshot is the ceiling (the run can
   never widen beyond what the credential could do when it admitted); the live read is what makes
   revocation work. A credential that has been **revoked, deleted or narrowed to empty ABORTS the run**
   (terminal `aborted`, reason `credential_revoked`) — symmetric with filter (4)'s operator revocation
   and Decision 6's module revocation. Freezing alone would make the credential the one input in this
   conjunction that revocation cannot reach: kill a leaked worker token and its in-flight runs would
   keep acquiring facts and driving effects for the whole TTL.

**Filter (6) exists because the narrowing law's applicable factors (ADR-0033 §1) include the
credential, and this conjunction was quietly dropping it.** §1: `authenticated-actor ∩
represented-operator ∩ attenuated-credential ∩ Module envelope ∩ execution authorisation`. Filters
(3)–(5) covered the authenticated engine principal, the represented operator and the module; nothing
covered the **credential**. So a run admitted by a read-only, canary-ring-only token would, for its
entire mid-run life, be authorised against its *owner's* full authority — the attenuation would apply
at admission and evaporate immediately afterwards, which is worse than not having it, because the
operator believes the worker is confined. The credential's grant set is bound into the run row at
admission and is one side of every subsequent intersection.

**Filter (0) is not a formality — without it the whole protocol inverts.** The engine supplies the
`use_case_run_id` on every B4 call, and core resolves *whose authority to evaluate* by looking that
id up. So the id is a **selector for an identity**. If core does not bind the run to its caller, a
compromised or buggy module presents *another live run's id* and reads under **that** operator's
authority, up to that run's frozen ceiling — and core's own audit attributes the disclosure to the
innocent operator. The lookup would be genuine; the *selector* would be attacker-chosen. That is
on-behalf-of through the back door, on the same day ADR-1005's guard rejects it at the front door.
Two consequences, both normative: filter (0) as above, and **`use_case_run_id` must be an
unguessable, ≥128-bit random identifier** — never a sequence, because a guessable selector re-opens
the same hole from outside.

**Three details filter (0) must get right, or it will be weakened by the first person it inconveniences.**

- The engine principal is **per-module-deployment, shared by every replica** — not per-instance, or a
  second replica would fail filter (0) on every call and someone would "fix" high availability by
  loosening the filter.
- **A foreign caller is DENIED, never allowed to abort.** Only a call from the run's **own bound
  engine principal** that fails for another reason (module-version drift) aborts the run
  (`aborted`, reason `caller_mismatch`). A call from a *different* principal is denied, audited and
  alerted — it must never terminate someone else's run, or filter (0) becomes a remote kill switch
  for anyone who learns a run id, and run ids leak into logs and correlation headers even when they
  are unguessable.
- **State what filter (0) does NOT close, because it is easy to over-read.** It stops a *cross-module*
  pivot: module X cannot present module Y's run id. It does **not** separate two operators' runs
  *within one module deployment*, because they share the engine principal — so a compromised or buggy
  module can present the id of any run **it is itself concurrently executing** and read under that
  operator's authority, up to that run's frozen ceiling. That is the honest residual, and the
  containment for it is not another filter: it is the **scope ceiling** (the blast radius of the
  compromise is bounded by what those runs were already allowed to see, and the module already holds
  their data), plus **per-tenant or per-run process isolation** for any module whose concurrent
  ceilings span operators who must not be blended. A module handling multiple operators' data in one
  process is trusting that process; say so, rather than implying a filter has removed the trust.

**And the operator identity is never an argument.** The evaluate-as-operator seam that filter (4)
needs is server-internal impersonation, which is a dangerous thing to build: it must resolve the
operator **only** from the server-side run row. **No core API may accept an operator identity as a
parameter** — not from presentation, not from the engine, not from a scheduled job. If one ever
does, the on-behalf-of ban has been re-implemented as a feature.

Revoking the admitting operator, or shrinking their scope, therefore **kills the run mid-flight** —
D10's re-check-at-execution rule extended to the whole run lifetime. Filter (4) is the
`authorize_list_read` admit-then-filter chokepoint (ADR-0017 PR-A; #1715 prerequisite) evaluated **as the admitting
operator while the engine is the authenticated caller** — the server-internal *evaluate-as-operator*
seam that gate must grow, and a named prerequisite in the interlock below.

This per-call conjunction is the run-scoped instance of the platform authority-narrowing rule in
**ADR-0033**; it narrows, and can never widen.

### 5. Core owns the run state machine and reaps on TTL (P3)

The run row is a **guarded one-way state machine** — `admitted → executing → finalised | denied |
expired | aborted` — using the deployment-store transition pattern (guarded CAS transitions, never
an unconditional grid overwrite). The run store is a core-owned store, **born on Postgres**
(ADR-0012: fail-closed construction — and **authoritative**, not durability-on-top; see Decision 11).

Each use case declares a TTL in its manifest; core reads that TTL from **its ratified copy**
(Decision 13), version-locked at admission. A run's **read authority ends at `expires_at`**: filter (1)
of Decision 4 checks the clock inline on every call, so an overdue run is denied whether or not the
reaper has run. The reaper then terminalises overdue runs and writes the terminal audit row
(`use_case.run.expired`); it records the end, it is not what causes it.

The invariant this buys: **every admitted run reaches a terminal audit state.** No run merely stops
being mentioned. Expiry at `expires_at` revokes a run's **read** authority (checked inline, Decision 4 filter 1); reaping only terminalises, audits and cleans up. Neither voids an
Execution Plan the run already produced and a human already approved: an approved plan is authorised
in its own right and is re-checked against the *requester's* current authority at execution
(ADR-0033 §8). A reaper must never be able to silently un-approve a human's decision.

**It is bought by a reaper, not by construction** — and a reaper is a background thread, which is a
thing that can die quietly (the `PolicyEvaluator` precedent). So the invariant carries four
requirements, and it is worth exactly as much as they are:

- **A ceiling on the module-declared TTL** in core's ratified copy. A module must not be able to
  declare a run that outlives the evidence for it. It also carries a **floor**: the TTL must cover the
  *whole* lifecycle - admission, reads, compose, finalise, **and the seam-4b redemption** - not just
  the reads, or a tight TTL would systematically deny an operator their own just-composed result at the
  last step (a fail-closed sharp edge, Decision 12).
- **A liveness metric on the reaper, and an alert on stranded runs** (`admitted` or `executing` past its TTL - the wider set matters: a run that finalises but never redeems its release authorization sits in `executing` past TTL, and this alert is what surfaces it). If
  the reaper dies, overdue runs are not *terminalised or audited* - but they are **not
  read-authoritative**, because the inline `now < expires_at` check (filter (1) of Decision 4) denies
  every call on an expired run regardless of the reaper. The reaper is a janitor (terminalise +
  terminal audit + cleanup); a dead reaper is missing terminal evidence, stale state and retention
  pressure, alerted on - not an authority leak.
- **A retry on a failed terminal audit write.** D6's mutation rule means a failed audit write fails
  the transition closed — which for a reaper leaves the run non-terminal. Retry, or the run is
  stranded by the very rule meant to protect it. The inline expiry check still denies that stranded
  run's reads, so a failed audit write never preserves read authority; never gate expiry-denial on it.
- **An orphan sweep at boot.** A core that crashes mid-run leaves runs in `executing` with nobody
  driving them. On start, core sweeps them to a terminal state (`aborted`, reason `core_restart`)
  before serving. Core restart mid-run is otherwise an unhandled path — the run simply never ends.

Named, so the alert exists before the incident does (`docs/observability-conventions.md`):
`yuzu_use_case_reaper_last_success_timestamp` (gauge — alert on absence, or on age > 180 s for 5 m,
**critical**; the follow-the-rollup-pattern precedent, not `PolicyEvaluator`'s outcome-only
counters), `yuzu_use_case_reaper_tick_errors_total`, `yuzu_use_case_runs_stranded` (gauge — runs
`admitted`/`executing` past TTL; > 0 for 10 m is critical, because every one of them is an
un-terminalised run with no terminal audit row - its reads are already denied by the inline expiry
check, but its evidence and cleanup are stuck), `yuzu_use_case_run_terminal_audit_failures_total{reason}`,
`yuzu_use_case_runs_reaped_total{terminal_state}` and `yuzu_use_case_runs_orphaned_total`.

### 6. Revocation symmetry: a pulled module or capability aborts the run (P10)

The grant freezes the module version at admission, so operator revocation alone was not enough —
pulling a module version or a capability would have left in-flight runs executing against a
withdrawn contract. Decision 4's per-call check therefore also verifies **module-version and
capability liveness**; pulling either **aborts** the run (terminal `aborted`, reason
`capability_revoked`).

### 7. Only presentation calls the UCE (v1) (P6)

The UCE's invocation endpoint is internal and reachable **only** from presentation's mTLS service
identity. The grant records its **intended caller**, so a leaked grant is useless off-path. This is
defence in depth, not the primary control: the primary control is that the UCE can obtain **no fresh
fleet fact and no effect** without core (Decision 4).

**Say that precisely, because the looser version is false.** The engine is not empty. Everything
core has ever released to it persists in the `uce` database — stored results, its journal, and
derived state — in a database core's role cannot read. A compromised engine yields that corpus. It
is *why* Decision 10 re-admits every cached serve rather than trusting a run id, and *why* Decision
15 demands signed purge receipts rather than a report. "The engine can obtain nothing without core"
would be a comforting sentence and a wrong one.

Automation and agentic workers reach use cases through the **projected REST/MCP capability** on the
one public surface — never by calling the UCE. Scheduled and background runs enter through the same
internal path with the same admission — and **the human who armed the schedule is the ADMITTING
OPERATOR of every run it produces, while the credential they armed it with is the ADMITTING
CREDENTIAL of every one of them.** The schedule records both. This is not bookkeeping: without a
recorded arming credential, Decision 0's credential filter has no input on a scheduled run, and an
attenuated read-only worker token that arms a schedule would **launder every run it produces out of
its own attenuation** — the token cannot do the thing, but the schedule it armed can. **Revocation, deletion and expiry all
read the same way - the credential no longer authorises, so the schedule STOPS.** Rotation splits from
them: a **routine rotation** with a recorded successor (the new credential-level successor +
terminal-reason relation, interlock item (n) - not 2b §3.1's engine-principal `superseded_by`) re-binds
the schedule to the successor as an atomic audited authority change and it keeps running (no
equal-or-narrower-attenuation clause is needed here, unlike the plan rebind in ADR-0033 §8: a schedule
re-evaluates live confinement on **every** run it produces, so it protects no frozen prior approval -
the successor's own attenuation bounds the next run); a **compromise revocation** has no
successor for this purpose and stops the schedule like any other revocation. Core keys this on the
recorded `rotation_superseded`-vs-`compromise` classification, never on "same owner" (the twin of
ADR-0033 §8's plan-rebind rule). Naming expiry explicitly
matters twice: a nightly compliance scan armed with a 90-day token would otherwise fail *silently* on
day 91 (a security control that stops without saying so), or tempt an implementer into ruling
"expiry ≠ revocation" and keeping it running, which re-opens the laundering hole above. A stopped
schedule is **loud** — `yuzu_use_case_schedules_stalled{reason=credential_expired|credential_revoked|armer_demoted}`
is a gauge with an alert, not a log line. **Re-arming** is an authority change: audited and
re-checked, and *not* an effect-bearing edit under ADR-0033 §7 unless the definition itself changed,
so rotating a token does not re-trigger four-eyes on an unchanged effect. And the idempotency
namespace (Decision 1) keys on that credential, so a scheduled run is never a hole in that rule
either. Every filter in Decision 4 therefore evaluates against the
armer's **current** authority: a schedule whose armer is demoted or deleted stops producing runs.
There is no system principal that admits runs on nobody's behalf.

**This governs operator-facing runs** - runs that read confined fleet facts or drive fleet effects.
It does **not** re-home 2b §3.4's *autonomous-sync identity*, which acts under the engine principal's
own grants for autonomous work (external feed ingestion and the engine's own derived state) and is
**forbidden from reading operator-confined fleet facts or driving fleet effects**. That prohibition is
**enforced, not merely asserted**, and it is enforced by the filter that DOES apply: with no operator,
the represented-operator (confinement) filter is not-applicable, so the **authenticated-actor filter**
(the engine principal's own grants, which always applies - ADR-0033 §1) is the whole bound. The
autonomous-sync principal is therefore **granted no operator-confined fleet data class at all**; a
capability declaration that would let it read one is refused at manifest vetting (ADR-0033 §2). The
confinement is not dropped with the operator - it is that the actor was never granted the confined
classes, so there is nothing for a represented-operator filter to confine. Autonomous ingestion has no
admitting operator because it discloses nothing operator-attributable; the moment its
output is rendered to an individual operator, that read is a distinct, admitted, operator-confined run
(2b §3.4: "any read rendered to an individual operator is authorized as that operator"). Ingestion and
operator disclosure are different authority questions, and - a deliberate decision of this protocol,
not merely a restatement of 2b - only the second is a run under this protocol.

**Admitting operator and four-eyes requester root are two different questions, and a scheduled run is
where they come apart.** The *admitting operator* is the armer — that is whose live authority confines
every read. The *requester root* for four-eyes is the *set of humans who authored the schedule's
effect-bearing definition* (ADR-0033 §7), which includes the armer only if they authored it. Alice can
author an effect-bearing schedule and Bob can arm it: Bob's authority governs the runs, and **neither
Alice nor Bob may approve the effect** — Alice because she designed it, Bob because he requested it.
Collapsing the two roles into "the same human, named twice" is precisely the laundering §7 exists to
prevent, so this ADR does not do it. Direct-to-UCE access for any other caller requires a later
ADR; it is never a default that erodes.

### 8. Fact acquisition versus effects: mutating by default (P5 + P9)

Every dispatch the UCE requests through core is an **effect** unless read-only is attested at
**both** the vetted manifest (core's ratified copy) **and** the plugin-action metadata on the agent
side. This is the safe default, not a convenience:

- **Fact acquisition** (declared read-only/idempotent) executes under the run's frozen scope
  ceiling: no Execution Plan, no approval. The behavioural-PII audit chokepoint still applies
  **per verb** (`rest_audit.hpp`'s `emit_behavioral_audit`), so each kind of sensitive read stays
  separately countable for works-council purposes.
- **Effects** (everything else) cross core as an immutable, version-pinned **Execution Plan**, with
  plan-hash approval binding and authority re-checked at execution — **ADR-0033** owns that
  machinery.

The read-only attestation is enforced where the engine cannot reach: fact-acquisition dispatches
carry a **tagged read-only envelope** that the **agent-side plugin host** enforces — it refuses a
non-read-only action arriving under that envelope. Core **quarantines the module on mismatch**.
A single mis-declaration must not be able to both collapse RBAC granularity and skip the
plan/approval path with a human manifest diff as the only backstop.

**What that costs, stated before the vote rather than after it.** The plugin host cannot enforce
what the ABI cannot express, and **it cannot express this today**: `sdk/include/yuzu/plugin.h`
declares a plugin's actions as a flat `const char* const* actions` — a name array with **no
per-action metadata of any kind**, let alone a mutability class. So this leg is **an ABI change on
the compiler-stable plugin boundary** (`YUZU_PLUGIN_ABI_VERSION` 3 → 4, with
`YUZU_PLUGIN_ABI_VERSION_MIN` governing how long v3 plugins keep loading), rippling through the 49
in-tree plugins and any out-of-tree one. That is the hardest boundary in the codebase to change,
and it is on P9's critical path — not a detail to discover during implementation.

**And it covers less than it sounds like.** The envelope binds only **agent-dispatched plugin
actions**. A fact read that never reaches an endpoint — core's own stores, fleet truth, inventory,
findings — has **no plugin host to refuse it**, so for those reads the mutability classification is
core's alone: core's ratified mapping (Decision 13) decides, and the release log (Decision 11)
records. The agent-side envelope is defence in depth on the one path that leaves the building; it is
not the whole of P9.

### 9. Progress rides the one event spine; results are durable in the `uce` database (P4)

The UCE posts **run-scoped progress** to core; core fans it out subscriber-tagged on the **existing**
event spine — one bus, one taxonomy, no second stream protocol
(`docs/executions-history-ladder.md`'s standing invariant). Presentation routes by tag and makes no
event-level permission decision.

**But be honest about what "routes by tag" means for the TCB.** If core multiplexes one tagged
stream to presentation and presentation demultiplexes it to subscribers, then **presentation's
routing table is the confidentiality boundary between operators** — a routing bug is a cross-operator
leak, which is an authority-shaped failure, which INV-31-1 says presentation never performs. Two
honest resolutions, and G1's design must pick one explicitly: a **per-subscriber channel** (core
never hands presentation an event that subscriber may not see — the boundary stays in core), or the
multiplexed channel **with event confidentiality named as inside presentation's TCB**, alongside the
bearer-credential exposure ADR-0031 already admits. What is not acceptable is claiming the boundary
is in core while the demultiplexer is in presentation.

Results persist in the `uce` database keyed by `use_case_run_id`. Retrieval of a past result is a
re-admission (Decision 10), never a read of a durable object on run id. Retention rides the declared
per-module SLA (Decision 15).

**Retention has a mandatory ordering: the release log must outlive every result it re-confines.**
Decision 10's subset check reads the source run's released-input set out of the release log. If the
log is pruned while the cached result survives, the check has nothing to check against — and the
only two outcomes are both bad: deny every cached serve (the cache silently dies) or serve it
unchecked (the confidentiality rule silently dies). So **release-log retention ≥ result retention,
per module, enforced at manifest ratification** — a module whose declared result retention outlives
its release-log retention is refused at activation. A cached result whose release-log entry is gone
is **not servable**: it is re-derived or it is denied.

**Prerequisite, named (S8/G1):** the event spine's buses are **process-local today**
(`execution_event_bus.hpp`, `server.cpp`). "On the existing spine" across a process boundary
presumes a cross-process event transport that does not exist. **G1 — the cross-process event
transport — must be designed and landed before P4 ships.** It is an open question, recorded here as
a prerequisite rather than assumed away.

### 10. Cached results: a fast-lane re-admission that runs the subset check in core and mints a result-scoped grant (P8, and the S3 fix)

An aggregate cannot be un-blended. A stored result may be served **only** if the requesting
operator's **current** authority still covers the run's **full released-input set** — a subset check
against Decision 11's release log. If scope shrank, the cached result is **denied outright** and a
re-run under today's scope is offered. Results are immutable evidence: **whole, or re-derived —
never partially re-served.**

Where that rule is enforced, normatively:

1. A cached-result read **is a fast-lane re-admission**. Presentation calls core, not the UCE.
2. **Core runs the subset check** — and it is the **applicable conjunction of Decision 0**
   (the requesting operator's current authority, the requesting credential, and module liveness; the
   execution-authorisation filter is not-applicable to a read), credential term included, against the
   source run's released-input set as read from core's own release log. Not "the operator's authority": *the requesting credential's* authority. This is the
   path that actually hands bytes to a caller, so it is the last place that can afford to drop a
   filter — a read-only, canary-ring-only token whose **owner** happens to be allowed the production
   blend must not be able to request the cached result of a run that spans production.
3. On success, core mints a **result-scoped grant**: audience-bound to the intended caller,
   one-use, short-TTL, naming the **source `use_case_run_id`**, the digest of the released-input set
   it was checked against, and the requesting principal.
4. **The UCE serves cached bytes only against a result-scoped grant — never on a run id alone.**
5. **The UCE REDEEMS that grant at core before it serves a single byte, and core re-runs the subset
   check at redemption.** This is the load-bearing step, and it is one round trip:
   - Core performs a **guarded CAS** on the grant record (`unredeemed → redeemed`, the same
     one-way-transition pattern as Decision 5's state machine, in Postgres). The CAS is what makes
     "one-use" **true**: two concurrent redemptions, or two engine replicas, produce exactly one
     winner, and core — not the engine — is the one holding the fact.
   - Core **re-evaluates the subset check — the same applicable conjunction (Decision 0): the
     requesting operator's current authority, the requesting credential, module liveness, and the
     redeeming engine principal, credential term included — against authority as it is AT
     REDEMPTION**, not as it was at mint. This closes the window between
     the two: an operator whose scope shrinks, or a credential that is revoked, after the grant is
     minted is denied at redemption. Without this step the check is only as fresh as the TTL, which is
     exactly the S3 hole re-opened at a smaller size.
   - Core **writes the serve's release-log entry** as part of the same transaction, so the
     disclosure is recorded by the component that authorised it.
   - **All of this is ONE transaction** — the CAS, the re-check and the release-log write commit
     together or not at all. A CAS in one transaction and a check in another is a permitted reading
     of "then", and it is wrong: it would burn the grant on a check that later fails.
   - **Redemption is replay-safe, and a replay is re-checked.** The same engine principal
     re-presenting the same grant for the same serve-run within its TTL **re-runs the subset check**
     against the operator's authority *as it is now*: unchanged ⇒ the same authorization, and **no
     second release-log row** (a crash after redemption but before the bytes reach the client must
     not leave the operator unable to read their own result, nor record one disclosure twice);
     **scope shrunk in the interim ⇒ DENY.** Returning a cached authorization on replay would make
     the serve "as fresh as the TTL", which is the flaw this whole step exists to kill. A *different*
     caller, or a different serve-run, is refused outright.
   - Core returns the authorization; only then does the engine serve.
6. The re-admission **mints its own `use_case_run_id`**, recording `served_from_run_id`, and its
   release-log entry (written at step 5) inherits the source run's released-input set. Without this,
   a second disclosure — to a different principal, at a different time — would leave no evidence
   anywhere core can read. The release-log **dedup key is `(release grant id, serve-run id)`, never the
   source run alone**: a replay of the *same* grant and serve-run writes no second row (idempotent
   retry), while a *genuine* re-serve is a new serve-run with a new id and therefore a new row. Core
   cannot observe delivery, so the key must separate an idempotent retry from a real new disclosure, or
   the DSAR-critical log over- or under-counts. Since fresh (Decision 12) and cached serves now share
   this one redemption path, the key governs both.
7. A **serve-run is short and terminal**: it transits `admitted → finalised` **on redemption** (core
   cannot observe delivery, so it must not pretend to — the receipt attests what core authorised, and
   it carries the *source* run's canonical result hash because the bytes are the same bytes), or
   `denied` if either subset check fails. It never enters `executing`,
   because no engine composition happens. Decision 5's "every admitted run reaches a terminal audit
   state" therefore holds for serve-runs too.

**Why redemption is a core call, stated plainly, because the cheaper design is the tempting one.**
If the engine may serve on the grant alone, then the *one-use* property is enforced by the engine —
the component the grant exists to constrain — and its redemption state lives in a database core
cannot read. Two concurrent requests both see "unused"; two engine replicas both serve; if the
engine's redemption store fails, the natural failure is to *serve*. Every fail-closed rule in this
ADR (Decisions 11 and 14) is unreachable on a path that makes no core call. Redemption-at-core
collapses all of that: **the result-scoped grant stops being a bearer capability over data and
becomes a one-use ticket that core adjudicates.** It costs one round trip on a *cache hit* — and
Decision 10 already prices cache hits as "cheaper to deny than to serve".

**A cached result is servable only against a release-log entry that still exists.** The subset check
reads the source run's released-input set out of the log. If those rows have been pruned, the set
core reads is **empty** — and the empty set is a subset of *every* scope, so a naive check passes
**vacuously** and serves the old blend to a shrunken operator. That is the S3 attack wearing the
uniform of its own fix. So:

- The run row carries a **`released_input_digest`** written at finalisation. A subset check whose
  release-log rows do not reproduce that digest — because they were pruned, or because the read
  failed — is **not a pass with an empty set; it is a DENY**, with the result offered for re-run.
- **A MISSING digest denies, exactly like a mismatched one.** This is the third state, and it is the
  one a naive implementation skips: "compare the rows to the digest" with no digest present reads as
  *nothing to check*, which is the vacuous pass wearing a different hat. So: **only a `finalised` run
  has a servable result** (a run that read facts and never finalised has no digest and serves
  nothing), and the retention ordering extends to the run row — **run-row retention ≥ result
  retention**, alongside release-log retention ≥ result retention. Prune the evidence and you have
  pruned the result's right to be served.
- **Absent evidence is never a pass.** "No rows released", "rows released then pruned", and "no digest
  at all" must be distinguishable, and each of the last two is a deny.

### 11. Disclosure accountability is core's release log, not the engine's journal (P7)

The composed result lives in the UCE's journal — a database core's role **cannot read**, purged on
the engine's own SLA. So the primary disclosure record must be core's own.

**At each confined fact read, core records — per run, as it releases, never trusted from the
engine — the released `agent_id` set (compact form), the data classifications, and the verbs.**
This is the **release log**: a core-owned store, born on Postgres.

**"Compact form" must stay lossless at device granularity.** The log's two consumers both ask
per-device questions: a DSAR asks *"was THIS person's device disclosed, to whom"*, and Decision 10's
subset check asks *"does the operator's current scope cover EVERY device in the released set"*. A
compaction that stores a count, a scope expression, or a range that cannot be expanded back to the
exact `agent_id` set answers neither. Compact the *encoding* (a roaring bitmap, a compressed id
list); never compact the *content*. A rounded answer to a DSAR is not an answer.

**One row per fact read — not one row per device.** The `agent_id` set is a single compressed column
on that row. This is normative because the naive reading sinks the design: a fleet-wide read across
10,000 devices would become 10,000 synchronous INSERTs **on the fail-closed critical path of one
read**, and Decision 1's "many small runs" would multiply it. One row, one compressed set, ~1–2 KB;
any per-device projection is a derived index built in the same statement (the batch `unnest` INSERT,
#1683, is the precedent). Budget: the release-log write gets **≤20 ms of the 250 ms p95 view
budget**, and it is metered — a write failure fails a user-visible read closed, so its failure rate
is a critical alert, not a warning.

**The audit verb rides the same write.** The declaration (ADR-0033 §2) carries the capability's
`data_class` and `audit_verb`; a release of a device-attributable class emits `emit_behavioral_audit`
(`rest_audit.hpp`) **as part of the release-log write**, not as a separate call a future handler can
forget. Hand-wiring per-verb audit is what produced #1703; the engine surface adds a whole new class
of behavioural reads, and it must not inherit that pattern. **No release without its verb.**

- *"**Which devices**, of which data classes, under which verbs, went to which principal in which
  run"* is answerable **from core alone** — DSAR and works-council evidence never depend on the
  engine's journal. Note the precision: the release log records the *devices, classes and verbs*,
  **not the field-level payload**. That is the honest scope, and it is what a DSAR actually needs;
  promising field-level recall the log does not hold would be worse than a precise answer.

**Every confined fact read returns a `scope_basis` confinement marker, and core — not the engine —
computes it.** This is the quietest and most dangerous hole in the protocol, so it is closed here explicitly.
Confinement *removes rows*. If core hands back only the rows the operator may see with no marker, then
an `authority_scoped` "no vulnerable devices" is **the same bytes** as a global "no vulnerable
devices" - and an answer that covers only the caller's cohort gets read as a clean bill of health for
the whole fleet. The engine cannot tell them apart, and neither can the operator reading the result.
That is precisely what ADR-0033 §10's coverage envelope exists to make impossible - and §10 scopes the
envelope to *distributed* answers, so a confined **core-store** read, which is not one, would slip past
it.

So every B4 fact read returns, alongside the rows, a **`scope_basis` marker that core computes from the
caller's confinement STATUS, not from the data**: `authority_scoped` if the operator's confinement **ceiling** was below the run's intended scope on **any** read - a matter of the operator's authority, **not** of whether rows were actually removed (a confined read that happens to remove zero rows is still `authority_scoped`) - and `global` only if
**every** read ran under fleet-wide authority. It is computed **conservatively across the whole run** -
not from the operator's authority at finalisation - so a mid-run promotion cannot stamp `global` over
reads that were confined while the operator was narrow. This is **independent of query coverage**:
**completeness** (ADR-0033 §10) is relative to the **requested/intended scope** (did everything you
asked for answer), while `scope_basis` says whether that requested scope was itself capped by your
authority. A **fleet-wide statement** (e.g. "the fleet has no vulnerable devices") is licensed **only**
when the run's **intended scope was the whole fleet**, its **completeness is `complete`**, AND
**`scope_basis = global`** (authority did not truncate below the intended scope). `scope_basis = global`
alone **never** licenses a fleet claim: a fleet-authorised caller who intentionally scoped the query to
one group has `complete` over that group, not over the fleet. An `authority_scoped` result describes
only the caller's authorised cohort and is never a clean bill of health for the fleet, regardless of
whether any out-of-scope row happened to match. This is deliberately **not** a matched/withheld count:
a per-query figure for rows the caller may not see - even a single truncated-or-not bit - is itself a
one-bit existence oracle over forbidden data, the very disclosure confinement exists to prevent
(ADR-0017 INV-3: a confined caller never receives a count computed over rows outside their visible
set; cf. the Inventory catalogue-rollup exception, global-gated for exactly this reason). The numeric
matched/withheld figures are **core-internal**; they reach a caller **only when the recipient's full
applicable effective authority (Decision 0) resolves to global read** - not merely the requesting
credential, since the engine principal, represented operator or module envelope may each be narrower.

**Coverage is core-verified, never merely engine-asserted.** Decision 12 has the engine submit a
disclosure summary and a coverage envelope at finalisation — but core performed every fact read and
every dispatch, so **core holds the ground truth and MUST validate the engine's claim against it**.
Core rejects a finalisation whose declared coverage contradicts what core actually served (an engine
presenting a result as **fleet-`complete`** when `scope_basis` is `authority_scoped`, or declaring
`complete` over a fleet dispatch core recorded as partially timed out). Decision 11 records the release "never trusted from the engine"; coverage gets the same
posture, for the same reason. An engine that could self-attest completeness could launder a partial
answer into a clean bill of health, and the evidence chain would agree with it.

- The finalisation disclosure summary (Decision 12) becomes **corroboration plus result
  schema/coverage** — not the evidence.
- **A failed release-log write fails the read closed.** Rows do not leave core unrecorded. (This is
  the same posture as the platform mutation rule in ADR-0033 D6, applied to disclosure: an
  unattributable release is exactly the thing the log exists to prevent.)

### 12. Finalisation joins the journals; the receipt is integrity, not authority (D12)

Before release, the UCE **finalises** the run with core, submitting a canonical result hash and a
disclosure summary. Core records completion, the result schema, the coverage envelope
(**ADR-0033** owns the envelope's fields and completeness policy) and a link to the UCE's journal
entry, then issues the **finalisation receipt**. Presentation renders only a result whose run and
receipt agree.

The receipt proves **integrity** — that the bytes rendered are the bytes finalised under this run.
It proves **no authority**: nothing may be released *because* a receipt exists. **Receipt
verification is exposed on the public API**, so any client — human, agentic, auditor — can verify a
result independently.

**Finalisation is authority seam 4b (Decision 0), and the first serve redeems at core exactly like a
cached one.** A freshly composed result is released to presentation exactly once, and that release is
*authorised*, because the window between the last confined fact read and the render is one in which the
operator can be demoted, the requesting credential revoked, the module pulled, or the run expired. So
the fresh result is **not** handed straight to presentation. Finalisation mints a **release
authorization** - the same **result-scoped grant** object as Decision 10 (opaque, server-side,
one-use, short-TTL, durable state core holds), bound to
`(result_hash, use_case_run_id, requesting credential, engine principal, recipient)`, where `recipient`
is the **admitting operator principal** (a durable identity, never the ephemeral presentation session -
ADR-0031's sessions are G6/G7-open, so a presentation restart mid-run loses no result: the operator
re-fetches, which is a Decision 10 re-admission) - and the engine **redeems it at core before the first
byte moves**, exactly as it redeems a cached serve (Decision 10 step 5):

- a **guarded CAS** on the grant (`unredeemed → redeemed`), which makes the one-use property true;
- the **applicable live conjunction re-evaluated AT REDEMPTION** - authenticated engine principal, the
  represented operator's CURRENT authority, the requesting credential, module liveness, **and the run
  itself live and unexpired (`now < expires_at`, Decision 5)**; the execution-authorisation filter is
  not-applicable to a read;
- the **subset check against the run's `released_input_digest`** (written at finalisation): the
  requesting operator's CURRENT scope must still cover the run's released-input set, exactly as
  Decision 10 step 5 checks a cached serve - a demotion between the last read and render fails HERE, not
  merely on a weaker "is the operator still valid?" test;
- the disclosure's **release-log row written in the same transaction**.

This makes the first serve and every later re-fetch (Decision 10) **one mechanism**. The run stays
`executing` through finalisation and transitions `executing → finalised` **on successful redemption**
(mirroring Decision 10's serve-run), so "run live" holds until the bytes are authorised, and an engine
that finalises but never redeems is an `executing` run past its TTL - caught by
`yuzu_use_case_runs_stranded` and denied inline (Decision 5), never a silently stuck result. The receipt still
attests only *integrity* (that the bytes are the bytes finalised under this run); the redeemed release
authorization is what says *this recipient may receive it now*, and presentation renders only when the
redemption succeeds (the check is core's, enforced upstream of presentation by the B2 contract,
ADR-0031 - presentation never re-implements it, and cannot skip it). Redemption is **replay-safe**: a crash after the CAS re-runs the conjunction
against authority as it is now - unchanged re-authorises with no second release-log row; shrunk,
revoked or expired **DENIES** - the same rule as Decision 10. Core authorises the serve; it does not
observe delivery. A demotion, credential revocation, module pull or run expiry between the last fact
read and redemption therefore denies the fresh result exactly as it denies a cached one. Every such
denial - fresh or cached - emits `yuzu_use_case_release_denied_total{reason}` (`reason` = `demoted` |
`credential_revoked` | `module_pulled` | `expired` | `scope_shrunk`), a real-time signal rather than
audit-only, matching the `schedules_stalled` / `execution_plan_voided` convention.

**Two journals, linked — not merged.** They answer different questions and live in different
databases under different roles:

| Journal | Owner | Answers |
|---|---|---|
| **Use-Case business journal** | UCE (`uce` DB) | Which use case and module version ran; which inputs and fact references were used; which deterministic decisions were made; which plan was proposed; which business outcome was reported. |
| **Core fleet journal** | core (`yuzu` DB) | Who was authenticated and authorised; which exact plan and capability versions were accepted; what was dispatched to which endpoints; which effects succeeded, failed or remain uncertain; which compensating actions ran. |

They are joined by **immutable identifiers, never by a shared transaction**:

```
run_id · plan_id · execution_id · causation_id
```

(`run_id` here is the `use_case_run_id` — the two names denote one identifier, and the schema uses
`use_case_run_id` throughout.)

**The evidence envelope (D12) is a named schema deliverable, not a convention.** Today's
`AuditEvent` (`audit_store.hpp:16`) carries a single `principal` field alongside `principal_role`
and the `principal_class` actor-class column (landed on `dev`, c5bbbe23, Phase 3a — with `engine`
reserved until Phase 4). What it has **no** representation of is the thing an admitted run needs:
**which authority the action was taken under**, and no queryable run-id column. D12 adds:

- the **acting principal**, separated from the authority it acted under (`principal_class` already
  says *what kind* of actor it was; it does not say *whose* authority was spent);
- the **authority acted under** — the `use_case_run_id` or the delegation-artifact id;
- an **INDEXED `use_case_run_id`** column;
- and the columns **ADR-1005 Decision 5 already mandates for every engine-principal action** —
  the engine principal id, an explicit `is_delegated` flag, the delegated operator's identity, the
  **delegation-artifact id**, and a per-row `delegation_verification_status`. These are not new: they
  are an accepted requirement that has never had a schema. D12 is the migration that gives them one,
  and leaving them out would mean migrating the audit store twice.

It lands **with the audit-store Postgres migration** — the cheap moment, and the reason the
migration must not be designed without it. "Every result, plan, approval and execution traceable
through one `use_case_run_id`" is a query, and a query needs an index.

**The envelope is wider than `audit_events`, and scoping it narrowly would defeat it.** The
confidence condition says *every result, plan, approval and execution*. Those do not live in the
audit table: executions and responses are their own records, plans and approvals are ADR-0033's new
objects, and the composed result lives in the engine's journal in a database core cannot read. A
run id present only on audit rows buys a chain with three links missing — you could prove a run was
*admitted* and never reassemble what it *did*. So the run id is carried, as an indexed column, on:

| Record | Owner | Why the chain breaks without it |
|---|---|---|
| `audit_events` (D12 proper) | core | who acted, under whose authority |
| execution + response records | core | *what was dispatched and what came back* — the effects themselves |
| release-log entries (Decision 11) | core | which device data was disclosed to the run |
| Execution Plans + approvals (ADR-0033) | core | which effect was authorised, by whom, against which plan hash |
| the engine's business journal | engine (`uce`) | the domain explanation — joined **by identifier**, never by a shared transaction |

Each of these is cheap to add now and expensive after its own migration ships: retrofitting an
indexed column onto a populated executions or audit table is a schema change *plus* a backfill under
load. **The audit-store migration must not be the only one that gets the key.**

### 13. Core's ratified copy of the manifest is the binding runtime input; a manifest is a request (S4)

A module's manifest declares what it wants: use cases, capabilities, `(securable, operation, risk
tier)` mappings, mutability classes, TTLs, schemas, retention classes, coverage/completeness
policies, licence. **On manifest approval, core copies that mapping into a core-owned table.**

- **Runtime enforcement reads core's copy, never the manifest**, and the copy is **version-locked at
  admission**: a run that started under module version *N* is enforced against core's ratified
  mapping for *N* for its whole life, even if *N+1* activates mid-run.
- **A manifest is a request, never the runtime input.** The distinction is the whole security
  property: "what the engine declared, human-reviewed" is a review artifact; "what core ratified" is
  an enforceable one.
- *Who* vets the declaration, and on what namespace/tier rules — **ADR-0033** (D1-C, G3, G9).

Module packaging and activation, adopted from the counter-proposal:

| Package element | Contents |
|---|---|
| Signed module package | immutable version · publisher identity · manifest hash · compatibility range · entitlement |
| Module manifest | use cases · capabilities · risk tiers · mutability classes · schemas · retention · licence |
| Engine contribution | domain logic · `uce` migrations · derived state · optional worker (absent for a declarative-only module) |
| Presentation contribution | declarative views, forms and result renderers only — the rule and its rationale are **ADR-0033 §11** |
| Core Product Pack | Instructions · Workflows · Policies — a signed content bundle on the existing content plane |
| External capability declarations | registered outbound connector calls: schemas · destinations · egress policy — **no arbitrary module network access** |

| Activation check | Rule |
|---|---|
| signature · compatibility · entitlement | verified before activation |
| permission diff | vetted per **ADR-0033 §2** (namespace-bound, approved-then-diffed) — the gate this ADR's ratified copy is taken *at* |
| migrations · recovery plan | present and applied, or activation is refused |
| **retention ordering** | **release-log retention ≥ result retention**, and **run-row retention ≥ result retention** (Decisions 9 and 10) — a module whose result outlives its own evidence is refused |
| **backup retention** | **≤ the tombstone SLA** (Decision 15) — an engine whose backups outlive its erasure promise cannot keep the promise |
| **completeness policy** | **≥ core's ceiling for the declared risk tier** (ADR-0033 §10) — a module may not declare its own honesty threshold |
| ambiguity | **fail closed** |

Versions install side by side. **An in-flight run retains the exact module, use-case, workflow and
capability versions it began with** (and if one is *pulled*, Decision 6 aborts it — retention is not
resurrection). Licence expiry blocks **new** starts; it must never hide existing evidence or strand
a safe completion, cancellation or compensating recovery.

### 14. Engine behavioural-PII reads fail closed on audit-persist failure — on every surface (S6)

The platform posture (ADR-0033, D6) is: mutations fail closed on audit failure; reads keep their
surface's posture. MCP's surface posture is **set-and-proceed**. For engine tools that return
**device-attributable data**, that is an evasion path shaped exactly like the reads the
works-council controls exist for.

**Engine tools returning device-attributable data fail closed on audit-persist failure on every
surface, MCP included** — the REST posture (503 + `Sec-Audit-Failed`), not the dashboard/MCP
set-and-proceed one. Any exception is a formally recorded exception with compensating controls, in
ADR-1005's exception ledger — never a silent inheritance of the weaker surface posture.

This is consistent with Decision 11: core does not release device-attributable rows it cannot
account for.

### 15. Purge is proven, not reported (S7, hardening G4)

A device deleted in core leaves `agent_id`-tagged personal data in the `uce` database, which core's
role cannot read. G4's contract — core emits a durable **tombstone**; every engine purges within a
declared SLA and reports completion — relies, as drafted, on engine honesty. Reports are not proof.

The engine must supply **signed deletion receipts** — the purged tombstone ids, signed by the
engine principal's key, submitted to core through the same B4 seam as everything else. Core
verifies the signature and records the purge. **Core still reads nothing in the `uce` database.**

That last sentence is the reason for the choice. S7 offered a second option — a purpose-limited,
core-readable deletion-audit table inside `uce` — and it is **rejected here**: it would require
core's role to hold a `SELECT` grant on the `uce` database, which **ADR-0031's INV-31-3 forbids
outright** (no cross-component database access; core holds no grant on `uce`). A purge-proof
mechanism that dissolves the role boundary buys evidence by spending the isolation the two-database
split exists to provide. Receipts cost one signature and keep the boundary intact.

**The receipt proves a claim, not a fact — say so, and name what would upgrade it.** A signature
made by the engine's own key attests that the engine *says* it deleted. It does not reach a stolen
key, a compromised engine, or — the one that actually bites — **an untouched `uce` backup, WAL
archive or PITR window**, where the personal data lives on while the receipt stays valid. Two
requirements follow:

- **The purge SLA explicitly covers backups, WAL archives and replicas**, and the engine's declared
  backup retention must be **≤ its tombstone SLA**, checked at manifest activation. An engine whose
  backups outlive its erasure promise cannot honour the promise.
- The residual risk (engine dishonesty or compromise) is **recorded, with an owner**, not waved
  away. The control that would close it is **crypto-shredding**: per-device or per-tenant data keys
  held behind core's existing `KeyProvider`/`SecretCodec` seam (ADR-0010), so destroying the key
  renders engine-held data — backups included — unrecoverable **without core ever reading `uce`**.
  That is the upgrade path; it is not required for v1, and it is the answer to "how do you *know*?"

Core audits per-engine purge compliance against the declared SLA and **alerts on breach**. Signing
up to this is part of being an engine (a 2c-style hosting requirement).

## Sequencing interlock — no ballot-A5 code path ships before these land (S2)

A5 ratifies a **shape**. It is not available-now, and it consumes substrate that does not exist. As
prose, that has already failed once: the ballot's sequencing clause named two prerequisites and
omitted the two that carry its own evidence. So it is a **tracked interlock**, in the style of the
M3 parity gate — a named gate with a checklist, not a sentence in an ADR.

| # | Prerequisite | Why A5 cannot ship without it | Status today |
|---|---|---|---|
| **(a)** | **Phase-4 engine principals** (ADR-1005 exec plan) | Decision 4's mid-run caller is the engine principal. Without it there is no authenticated identity for the UCE to hold. | `principal_class=engine` is live on the HTTP request metric (PR 4.5); the rest of Phase-4 (RBAC-only enforcement, the ADR-0017 gate) is not. |
| **(b)** | **The ADR-0017 admit-then-filter gate (PR-A; decision #1714) + its open deny-precedence prerequisite #1715 + a server-internal evaluate-as-operator seam** | Decision 4 confines against the **admitting operator's** current authority while the **engine** is the authenticated caller. Both halves are needed. **And #1715 must resolve with DENY-precedence** (a global deny, or a confinement boundary, must never be overridden by a group allow): resolved the other way, filter (4), seam 4b and Decision 10 redemption all over-authorise a confined operator - the whole confinement edifice rests on this semantics, so the gate cannot ship until #1715 lands deny-precedence. | **Zero occurrences** of `authorize_list_read` in the server tree; #1715 (global/group deny precedence, PR-A prerequisite) is **OPEN**. #1716 is the closed doc-honesty companion, not this gate - do not read its closure as (b) satisfied. |
| **(c)** | **The D12 audit schema** (acting principal · authority ref · **indexed** `use_case_run_id`) | Decision 12. Without it, "no unjoined evidence" is not merely untested — it is **unqueryable**. Rides the audit-store Postgres migration. | `AuditEvent` has a single `principal` field. |
| **(d)** | **The P7 release-log schema** | Decision 11 *is* the disclosure evidence, and Decision 10's subset check **reads it**. Ship A5 without it and admitted runs exist whose disclosure cannot be proven from core-owned evidence. | Does not exist. Born-on-PG store, ADR-0012. |
| **(e)** | **G1 — the cross-process event transport** | Gates **Decision 9 only** (progress/events), not the whole of A5. The buses are process-local. | Open question; must be designed before P4 lands. |
| **(f)** | **Per-action mutability in the plugin ABI** | Gates **the fact-acquisition dispatch path only** (Decision 8). Without it the agent-side plugin host cannot refuse a non-read-only action, and the mutating-by-default posture has the human manifest diff as its **only** backstop — which Decision 8 itself says must never be the case. | `plugin.h` carries action **names** only (`const char* const* actions`); no mutability metadata. An ABI change (v3 → v4) across the 49 in-tree plugins. |
| **(g)** | **Derived-state confinement** — per-run provenance on derived rows, or a ban on cross-run derived state | Gates **any module that persists derived state across runs**. ADR-0031's INV-31-2 confines what the engine *receives*, not what it *retains*: a rollup computed under a wide run and read inside a narrower operator's run is confined by **nothing** in this set. ADR-0031 says it must close "before a module persists its first cross-run rollup" — that sentence is prose, and prose is what this interlock exists to replace. | Nothing exists. Not a line of engine code has been written, so this is free to fix now and a cross-operator disclosure to fix later. |
| **(h)** | **The runtime capability-declaration registry** (core's ratified-mapping table), **and the credential columns** (the run row's admitting-credential id + frozen grant snapshot, and the Execution Plan's requesting-credential id — Decision 0's credential filter has nowhere to live without them, at seams 2 and 5) | Gates **admission itself**. Decisions 1, 5 and 13 read the risk tier, the TTL and the mutability class from *core's ratified copy*. There is no such copy: securable types are a hard-coded C++ array (`rbac_store.cpp:217-244`, 21 entries) with **no runtime create path**. Without (h) the first implementation reads the manifest — which is the S4 failure this ADR rejects by name. | Unbuilt. ADR-0033 §2 calls it "the precondition for every rule in this section" and it appeared in no gate until now. |
| **(i)** | **Execution semantics: outcome correlation + the coverage envelope** | Gates **every distributed fact read and every effect**. ADR-0033 §10 requires `intended/contacted/responded/failed/timed_out`, and D11's Execution Plan requires a real outcome. The workflow engine marks a step **successful on dispatch** (`workflow_engine.cpp`) and does not correlate an `execution_id`. A finalisation receipt over that attests effects nobody confirmed, and "no vulnerable devices found" becomes indistinguishable from "62 devices never answered" — the exact sentence ADR-0033 §10 exists to forbid. | Coverage fields: zero occurrences in the tree. Dispatch-vs-outcome correlation: unwired. This is the memorandum's "repair execution semantics" step, now a gate. |
| **(j)** | **Capability projection** — generated OpenAPI + generated `tools/list` from core's registry | Gates **the agentic surface**, i.e. the thing voiding F-10 was for. `tools/list` iterates a **compile-time array** (`mcp_server.cpp`) and the OpenAPI document is a hand-typed literal (`rest_api_v1.cpp`). Activate a module today and its capabilities appear on **neither**. Without (j), an engine is reachable by nobody. *(Update 2026-09-08: the earlier claim that "INV-31-4's contract test cannot exist — you cannot diff registered routes against a hand-written document" is STALE — that drift test DOES exist and is green (a LEXICAL gate over literal registrations only — a non-literal direct verb call warns, a helper- or header-defined registration escapes SILENTLY; type-aware successor #2572), diffing `register_routes()` against the hand-typed `openapi_spec_json()`: #842/#3991/#3992, `scripts/ci/check-api-parity.py` + `test_openapi_spec_completeness.cpp`. What (j) still gates is the **generated** OpenAPI/`tools/list` projection from core's registry — #2678 — not the contract test.)* | Unbuilt (the generated projection; the drift test shipped — #842). |
| **(k)** | **Operational readiness** — the new stores in the readiness conjunction, and the reaper's liveness alert | Gates **admitting a run in anger**. Six new stores (run, release log, grants/receipts, approvals, plans, declarations) and none is in `/readyz`'s `stores_ok` conjunction; the reaper has no liveness signal, and its death strands terminal evidence and cleanup (read authority itself is denied inline by the `now < expires_at` check of Decision 4/5, not by the reaper). Every row in that conjunction was added because a store died and the server reported healthy. | Unbuilt. Metric names in Decision 5. |
| **(l)** | **Intra-module cross-run isolation** — per-tenant or per-run process isolation | Gates **any module whose concurrent scope ceilings span operators who must not be blended.** Filter (0) stops a cross-*module* pivot and explicitly does **not** stop an intra-module one (Decision 4): a compromised module can present the id of any run it is concurrently executing. The containment is isolation, not another filter — and the first module (vulnerability management) will serve many operators from one deployment, so this is not hypothetical. A module that cannot isolate must **declare single-tenant-per-deployment** and be deployed that way. Recorded as a gate because ADR-0031 named the same class of gap in prose once already, and prose is what this interlock exists to replace. | Nothing exists; no engine code is written, so it is free now. |
| **(m)** | **Per-principal quota caps** (2b PR 4.4, #1973): the **minimum per-principal concurrency/quota cap** #1973 names as a production prerequisite, plus the 2b §5 invocation-grant outstanding-count and issuance-rate caps and dual-side debit under delegation | Gates **admitting a run in production**. "Many small runs" (Decision 1) makes the admit path the throughput ceiling, and idempotency does not bound a caller minting distinct keys; ADR-1005 makes the per-principal cap a production prerequisite, and this interlock omitted it. **Scope note:** broader admission-rate / active-run / concurrent-fact-read / core-and-engine fan-out capacity policy - split by credential, engine principal, module and deployment - is a **separate** capacity decision, not settled here. | 2b/#1973 name these caps; none is enforced for engine principals today. |
| **(n)** | **A credential-level predecessor/successor relation + terminal-reason classification** (`rotation_superseded` vs `compromise`) on the credential classes that arm schedules and request Execution Plans, **with an authorized+audited classification-setting action (never self-set by the holder) and a retroactive reclassify-to-`compromise` path that voids rebound plans** | Gates **any approval-preserving rebind of a schedule or plan across a credential change** (ADR-0033 §8; Decision 7). Without it, core cannot tell a routine rotation from a compromise revocation, and "same owner" would let a compromise-revoked credential's replacement resurrect an approved effect. 2b's existing `superseded_by` is an engine-principal terminal successor, not this. | Unbuilt; 2b must be amended to add it. |

**Rule:** no ballot-A5 code path ships until **(a)–(d)** and **(h)** have landed — (h) joins the
unconditional set because admission *cannot be built* without core's ratified mapping; it is not a
capability gate but a dependency. The rest gate specific paths, and a module may ship without them
only if it does not walk them:

| Gate | Blocks |
|---|---|
| **(a)–(d), (h)** | **everything.** No run is admitted, no grant minted, no fact released. |
| **(e)** | Decision 9 — run progress and events across the process boundary. |
| **(f)** | Decision 8's **fact-acquisition dispatch** to an endpoint. A module may be admitted, confined, evidenced and finalised over **core-store** facts before (f) lands; it may not dispatch an action to an agent. |
| **(g)** | any module that **persists derived state across runs**. |
| **(i)** | any **distributed** fact read, and any **effect**. |
| **(j)** | the **agentic surface** — REST/MCP projection of engine capabilities. |
| **(k)** | admitting a run **in production**. |
| **(l)** | any module serving **more than one operator's runs concurrently from one deployment**. |
| **(m)** | admitting a run **in production** (joins (k)) - the per-principal invocation-grant caps. |
| **(n)** | approval-preserving rebind of a schedule or plan across a credential rotation (else every credential change forces fresh four-eyes). |

**This is not a delay tactic; it is the honest dependency graph.** Five reviewers, working
independently, each found a prerequisite the earlier interlock had missed — which is the strongest
possible evidence that the gate was doing its job and that prose would not have.

**Falsifier (what a violation looks like):** a merged PR that admits runs, mints grants or serves
results while the audit row cannot carry an indexed `use_case_run_id`, or while no release-log write
happens at fact-read time. If that PR can merge, the interlock is not tracked — it is prose again.

## Acceptance tests — the seven confidence conditions

Filed **verbatim** from the 13 July synthesis memorandum. These are acceptance gates *enforced by
tests, not convention*; they are this protocol's test plan. (Conditions 4 and 6 exercise machinery
**ADR-0033** and **ADR-0031** own respectively; they are quoted here whole because the memorandum
states them as one set, and the run is what joins them.)

- **No unadmitted run** — the UCE cannot execute without a valid Core-issued grant bound to the
  exact Use Case, versions, inputs and scope.
- **No authority in Presentation** — changing a Presentation route or template cannot grant access
  Core would deny.
- **No unjoined evidence** — every result, plan, approval and execution traceable through one
  use_case_run_id.
- **No partial-fleet ambiguity** — every distributed result reports intended, contacted, responded,
  failed and timed-out targets plus its completeness policy.
- **No private Core shortcut** — Presentation and UCE use documented, versioned Core APIs; a build
  or contract test detects undeclared endpoints.
- **No restart amnesia** — Presentation restart preserves sessions and replay; Core restart has an
  explicit reconnect-and-resume path.
- **No accidental second product** — Dashboard, REST and MCP enumerate the same registered
  capabilities and observe the same Core authority.

Two of these have a specific shape under this ADR worth naming:

- **"No unadmitted run"** is testable at the UCE-checks-grant seam: a request with no grant, an
  expired grant, a wrong-audience grant, a grant whose `input_hash` does not match the inputs
  (Decision 2), or a cached-result request with no **result-scoped** grant (Decision 10) — each is
  refused by the UCE, and each refusal is a test. A **fresh result whose represented operator was
  demoted, whose requesting credential was revoked, whose module was pulled, or whose run expired
  between the last fact read and redemption** is denied release at seam 4b (Decision 12): core refuses
  the release-authorization redemption and presentation renders nothing. That denial is a test too.
- **"No unjoined evidence"** is a *query*, run against a live database: for a sampled
  `use_case_run_id`, the admission row, every release-log entry, every plan, every approval, every
  execution and the finalisation receipt must all return. That query is the D12 index's reason to
  exist.

## Consequences

### The audit gap closes without core becoming a proxy

Core sees every invocation *as an invocation* — not indirectly, later, inferred from the fact reads
it happened to serve. That was the one thing the peer-UCE topology could not offer and the one
thing the proxy topology bought at the cost of core parsing every domain payload. The admitted run
buys it for the price of one round trip.

### Disclosure evidence stops depending on the engine

Decision 11 moves the primary record into core, where the role boundary means it survives the
engine's retention policy, the engine's bugs and the engine's honesty. It costs a write on every
confined fact read — and that write is on the fail-closed path, so it is on the critical path for
reads too. That is the price of being able to answer a DSAR without asking a module.

### Cached results become cheaper to deny than to serve

Decision 10 makes a cache hit run a subset check and mint a grant. A cache that has to re-admit is
not free — but the alternative is a cache that leaks a shrunken operator's old blend, which is not a
cache, it is an exfiltration primitive with a TTL.

### A run is a unit of cost

Because iterative agentic triage is many small runs (Decision 1), the admit path's cost is the
platform's agentic-throughput ceiling. One round trip, one audit row, one grant mint, and a fast
lane that skips approval routing entirely — that budget is a design constraint on every future
change to admission, not an implementation detail.

### Six new core stores, all born on Postgres

The run store (Decision 5), the release log (Decision 11), the grant/receipt records (Decisions 3
and 12), and — from ADR-0033 — the pending-approval objects, the Execution Plan records and the
capability-declaration tables: **six**, and the count matters because every one of them must appear in
the readiness conjunction (ADR-0031 INV-31-6, interlock item (k)). They are new, core-owned, and born
on Postgres under ADR-0012's contract —
fail-closed construction — and **all six are AUTHORITATIVE stores, not durability-on-top ones**.
That distinction is the difference between a working design and a fail-open one, so it is spelled
out here rather than left to the reader of ADR-0012: a durability-on-top store returns empty or
`false` on error and lets an in-memory layer be the truth. **These stores have no in-memory truth to
fall back on, and Decision 10's subset check READS the release log.** A durability-on-top read on a
transient pool error would return an empty released-input set, the subset check would pass
vacuously, and the cached blend would be served to a shrunken operator. An authority store that
answers "I don't know" must fail the request, never answer "nothing". They join the migration
ladder; they never land as SQLite.

### The interlock will feel like a delay, and that is the point

Five prerequisites sit unconditionally between "A5 is ratified" and "A5 code merges": (a)–(d), whose
absence means an admitted run whose disclosure cannot be proven - indistinguishable, in an audit, from
no admission at all - and (h), without which admission cannot be built at all. The rest gate specific
paths, and (k)/(m) gate admitting a run in production.

## Alternatives considered

- **Core on the byte path** (the pre-synthesis shape: core relays each invocation to the engine and
  re-aggregates the response). Rejected in **ADR-0031**: core would parse and re-aggregate every
  domain payload, which is core interpreting domain schemas — the exact coupling ADR-1005 exists to
  prevent.
- **The UCE self-authorises on the grant alone** — treat the grant as a capability token and let the
  UCE serve everything it covers. Rejected: the grant is frozen at admission, so this is
  authority-as-of-a-past-moment. Decision 4's server-side lookup is what makes mid-flight revocation
  possible at all, and mid-flight revocation is what makes a long run safe.
- **Serve a cached result on run id, with presentation checking scope.** Rejected (S3): it puts an
  authority decision in presentation, which ADR-0031's INV-31-1 forbids and which "no authority
  in presentation" tests against directly.
- **The engine's journal as the disclosure record**, with core reading it for DSAR. Rejected (P7):
  it requires core to hold a grant on the `uce` database — dissolving the role boundary that makes
  the two-database split worth having — and it makes GDPR evidence depend on a retention policy the
  engine owns.
- **The manifest as the runtime input** (enforce what the engine declared; human review as the
  backstop). Rejected (S4): a review artifact is not an enforcement artifact. Core's ratified copy
  costs one table and converts a review promise into a runtime property.
- **Trust the engine's purge report.** Rejected (S7): "we deleted it" is a claim; a signed receipt
  is evidence. The difference matters exactly once, in front of a regulator.
- **A core-readable deletion-audit table inside `uce`** (S7's second option). Rejected: it requires
  core to hold a grant on the `uce` database — the same reason the engine's journal is rejected as
  the disclosure record below. Signed receipts give the same proof without spending the role
  boundary.
