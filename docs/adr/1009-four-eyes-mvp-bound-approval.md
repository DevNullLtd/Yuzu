---
status: proposed
date: 2026-10-19
owner: Dave Rae
deciders: pending (not yet through /governance; no acceptance recorded)
scope: server -- two-person integrity (four-eyes) MVP: bound approval primitive, symmetric Guardian gate
amends: ADR-0021 Decision 9 (approval trigger, scope and break-glass); docs/yuzu-guardian-design-v1.1.md section 11.1
depends-on: ADR-1005, ADR-0033 (section 7, human roots), ADR-0021
context-refs: epic #6060, #6061 (PR #6163, merged), #6062, #6063, #6064, #6065, #6066, #6067, #2442, #4395, #4128
---

# ADR-1009 -- Four-eyes MVP: one bound approval primitive, a symmetric Guardian gate

## Binding status

**Proposed, not accepted.** The delivery map below is the plan for epic #6060. PR1 (#6163) is
merged and PR2 (#6062) puts the storage and redemption primitives of D2 to D4 in the tree with
this ADR. Anything attributed to PR3 to PR7 is **intent**, not shipped behaviour, and so is every
statement about what a redeeming surface will do with a bound ticket.

**Acceptance.** The status stays `proposed` when PR2 merges. It moves to `accepted` in a separate,
later change that flips `status`, records the deciders (left `pending` here on purpose) and
replaces the "pending" and "will supersede" wording in the ADR-0021 amendment banner, the
`docs/yuzu-guardian-design-v1.1.md` section 11.1 banner and the pointers in
`docs/guardian-mvp-contract.md` and `docs/reflex-design.md`. That change needs two things: the
`/governance` run on the PR2 range closed with its blocking findings addressed, and an approving
review by a maintainer other than the author, whose PR approval and merge are the recorded
evidence (`docs/agents/domain.md`, ADR Acceptance Convention). Until then no clause of this ADR is
a policy-floor source. The one exception is the conditions under "Accepted dormant code" below: they
are the terms on which PR2's dormant authorisation code was accepted, so they bind PR2 and the first
producer whatever this status says, and a producer that ignores them is a defect, not an unratified
proposal. Whoever flips this ADR owns the two banners in the same change.

## Context

Yuzu has one approval primitive, `ApprovalManager`, and one separation-of-duties rule:
`reviewer != submitted_by`. Around it:

- A ticket binds `definition_id` and a scope string, not the reviewed parameters or targets. What
  the reviewer saw and what later runs are not tied together.
- Redemption (`consume_ticket`) is wired for MCP only. A ticket minted on the REST or dashboard
  instruction path is never redeemed, and `submit()` has no origin that must be declared.
- Guardian deploy and push has no approval code. `docs/yuzu-guardian-design-v1.1.md` section 11.1
  and ADR-0021 Decision 9 describe the gate; nothing implements it, and no
  `/api/v1/guaranteed-state/approvals` route or break-glass flag exists in the tree.
- System callers skip the dispatch `ExecuteGate`.

ADR-1005's routed-concern row requires that approval stay one core-owned primitive: extend it,
never add a second gate.

## Decision

D1 describes merged behaviour. D2 to D4 describe what PR2 (#6062) puts in the tree: the columns,
the mint-time freeze, origin-declared consume and the excluded-roots refusal at approve. No
production code calls `submit_bound` or the caller-held-transaction `consume_ticket` yet, so what a
redeeming surface does with a bound ticket (compare, refuse, spend) is intent for PR3 and PR4 and
is marked as such below.

### D1. One primitive, extended

`ApprovalManager` remains the only approval store and the only place the four-eyes comparison
runs. PR1 (#6061, merged as #6163) made the reviewer decision reliable: approve and reject accept
only an interactive human session, run MFA step-up, fail closed on an unresolved identity (no
`"unknown"` reviewer), write an `attempted` audit row before the decision is applied, and judge
expiry on the database clock. PR2 builds on that and does not re-decide it.

### D2. A ticket binds the exact reviewed effect

At mint, a ticket freezes three things: `request_json` (the canonical request the reviewer sees:
parameters, targets, definition name and content hash), `request_digest` (digest of that frozen
request), and `excluded_roots` (the human roots barred from approving, resolved per ADR-0033
section 7). PR2 adds the columns and the mint-time freeze; the redeeming surfaces (PR3 for
Guardian, PR4 for instructions) are intended to compare what is about to run against the frozen
request and refuse on a mismatch. The approvals page renders the frozen request itself, so the reviewer reads the effect rather
than an identifier for it (context: #4395); the approval read routes carry the same fields.

### D3. Redemption is origin-declared

`consume_ticket` takes the origin the redeeming surface expects (`ApprovalOrigin`). A ticket
whose recorded origin differs refuses, and `kUnspecified` and `kUnrecognised` always refuse.
PR2 adds `kGuardianDeploy` and reserves the `guardian.` definition-id prefix alongside `mcp.`, so
no authored definition can impersonate a Guardian ticket. A second `consume_ticket` overload takes
a caller-held transaction connection so consumption commits or rolls back with the caller's own
effect (PR3 is intended to use it for the deploy write). A precondition denial gets its own audit
row and counter, written by the store for any redeemer that supplies a precondition.

### D4. Who may approve, who may submit

`approve()` refuses a reviewer whose root is in the ticket's `excluded_roots`. Engine principals
cannot submit gated effects in the MVP. ADR-0033 section 7 maps an engine principal to its named
human owner as a four-eyes root; that mapping is not yet needed, because the MVP refuses the
submission instead of rooting it.

### D5. Amendment to ADR-0021 Decision 9: the Guardian gate is symmetric and covers all enforce

Original Decision 9 gated only deploys containing "dangerous" content (dangerous enforce per the
H1 taxonomy, plus dangerous Reactions), exempted changes that reduce enforcement (section 11.1),
and retained break-glass as a single-principal override for the unified flow. Replaced, for
Guardian baselines, by:

> Any change to a Guardian baseline that arms, disables, deletes or empties enforce-mode content
> requires approval by a different human root, bound to the frozen request. Arm, disable, delete
> and empty redeploy are all gated. The gate applies to every baseline that contains any
> enforce-mode guard (all-enforce); it is not limited to the H1 dangerous subset. A single admin
> may perform an **emergency disarm** (disable, delete or empty redeploy of enforce content) with
> MFA step-up, a mandatory justification, a `critical` audit event and an alert. The emergency
> disarm mints no approval and does not pre-approve any later arm. Arm-direction break-glass is
> **not** provided in the MVP.

Why symmetric: removing guards is as harmful as adding them (an empty full-sync redeploy deletes
every omitted rule on the agent), and a gate that waves reductions through is a one-person bypass.
Why a disarm exception but no arm exception: a disarm reduces what Yuzu does to an endpoint, so
an incident responder needs it immediately; an arm increases it, and speed there is not worth a
single-person path. The rest of Decision 9 stands, as amended 2026-09-17 (the digest is computed
over spec content plus the resolved device-id list): digest binding over content, parameters,
escalation policy and assignment scope, and recompute-and-compare at compile (PR3).
The Reaction clause is unchanged and Reflex is outside this MVP.

### D6. Activation

One server setting, `four_eyes.mandatory`, default **off** until PR6 (the setting does not exist
yet). Until then PR2 to PR5 land the mechanism without changing who can approve or redeem anything
in an existing flow. PR2's observable changes are the `guardian.` authoring refusal, an extra audit row
and a new counter for an MCP precondition denial, and the extra read fields and page states for a
bound ticket (none exists yet). Snapshot serving (PR3) is intended to ship
unconditionally.

### Delivery map

| PR | Issue | Delivers | Status |
|---|---|---|---|
| PR1 | #6061 | Reliable reviewer decision (D1) | merged (#6163) |
| PR2 | #6062 | D2, D3, D4 (storage and redemption primitives; no producer) and this ADR | in tree with this ADR; ADR still proposed |
| PR3 | #6063 | Guardian approved snapshots, gated deploy (D5), compile-time digest recompute | intent |
| PR4 | #6064 | Instruction request freeze and redemption on REST and dashboard | intent |
| PR5 | #6065 | System-caller gate, mandatory pair set, scheduled-execution refusal | intent |
| PR6 | #6066 | Flip `four_eyes.mandatory`, metrics, alerts, docs | intent |
| PR7 | #6067 | Agent rejects stale-generation policy pushes | intent |

## Consequences

Intent unless it says "today". Nothing mints a bound ticket today and no surface compares a frozen
request, so none of the protections below is in force for a user yet.

- One mechanism for an auditor to test; MCP, instruction and Guardian tickets are meant to differ
  only by declared origin. Today the origin check is live for the MCP recall only.
- A ticket is meant not to be replayable on another surface or for another request. Today the
  surface half holds (origin must match); the request half needs the PR3 and PR4 redeemers to
  compare the frozen request.
- Reviewers are meant to see, and approve, the actual effect. Today the Approvals page can render
  a bounded, display-safe summary of a frozen request and says it is for orientation, but there is
  none to render, and the Approve request is not yet pinned to the digest the reviewer saw.
- `four_eyes.mandatory` does not exist yet (D6), so until PR6 the protection will exist but not
  be enforced.
- The emergency disarm is a deliberate single-person path; it is bounded to the direction that
  reduces enforcement and is detected, not prevented.

## Accepted dormant code, and what PR3 must satisfy first

PR2 lands authorisation code with no production caller: the `excluded_roots` refusal in `approve()`,
`submit_bound`, the `guardian_deploy` origin and the caller-held-transaction `consume_ticket`.
It all fails closed, but code that nothing exercises can rot unseen, so it is accepted on these
conditions (security-guardian `sec-1`, with the architect's five conditions):

1. The bound fields are not dashboard-only: every approval read (the legacy `GET /api/approvals`,
   `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}` and MCP `list_pending_approvals`) carries
   `request` (the frozen request as a JSON object), `request_digest` and `excluded_roots`
   (closes `arch-1`), so an agentic worker sees what a human sees.
2. The Approvals dialog does not claim more than the store can back (`arch-3`): it says the
   summary is for orientation and that what is approved is the whole request as stored under the
   digest shown. It makes no promise that the request cannot change after the decision: the
   Approve request carries only a comment and matches the ticket id and pending status, so
   that promise waits for the digest-pinned Approve below.
3. The first caller of `submit_bound` or the caller-held `consume_ticket` gets security-guardian
   and cpp-safety review on rollback and spent-ticket semantics, and a test that a rolled-back
   caller transaction leaves the ticket redeemable.
4. No bound ticket is minted until every replica runs a build that includes this change (an older
   replica's `approve()` ignores `excluded_roots`); the Upgrading guide states it. This is prose
   only today: `submit_bound` checks no deployment capability and the store has no replica
   registry. The first producer MUST establish it mechanically, not by an operator's say-so: it
   refuses to mint unless every replica it can enumerate (the ADR-2002 coordination seam)
   reports a build with migration v2 and this enforcement, treats a replica that is unknown,
   unreachable or silent as NOT upgraded, and refuses below that build while a bound ticket
   exists (see Rollback below). Proof: `submit_bound: a fleet that contains an unknown or
   older replica refuses to mint`, in `test_approval_manager_bound.cpp`.
5. PR3 lands in the same release window as PR2, or the dormant half is cut back out. Made
   checkable: PR3 (#6063) MUST merge before the first release tag that contains PR2, or a change
   that removes the dormant half MUST merge before that tag. The accountable owner is the epic
   owner (#6060), who records which of the two applies in #6060 before the tag is cut; the
   deadline is that tag. A tripwire keeps the question honest between now and then:
   `bound-approval primitives still have no production caller (ADR-1009 tripwire, not proof)`, in
   `test_approval_dormant_code_tripwire.cpp`, fails the day a production call to `submit_bound`, a
   second production `consume_ticket` call or a new `kGuardianDeploy` use appears, so the first
   producer cannot land without someone updating its allow-list and this section. It reads source
   text only and proves nothing about behaviour.

### PR3 entry conditions

Open findings that become conditions on the PR that first wires a producer or redeemer (#6063).
The consume-time recheck is in PR2 (`up-2`, `g8-sg-1`). Every read a consume makes runs the
origin, submitter and integrity checks (reviewer is not the submitter or an excluded root, an
approved ticket names a reviewer, excluded roots readable, request matches its digest), and the
consuming statement is pinned to the status, reviewer, request, digest, excluded roots, origin
and submitter of the last row examined, so a row examined as pending, rejected or expired cannot be
spent by a status-only flip. What that is NOT: the check and the statement remain two statements,
so a change to a column outside the pin is not noticed, and a writer with database access who
rewrites every pinned column consistently passes. It detects a row that moved by accident or by an
old build; it is not a boundary against a database writer, and on an autocommit connection (the
`cs-3` item below) the held overload gets only the pin.

Each condition below is a MUST, and each names the test that proves it. A named test is written
first and is red at the base of the PR that satisfies the condition; a test that cannot be made
red first is not evidence. Test names are the case titles in `tests/unit/server/` that the PR
adds.

- **Held-path denial observer** (`sg-4`): MUST NOT take a second pool lease while the row is
  locked, or MUST fire after the caller's transaction ends. Proof: `consume_ticket(PGconn*): with
  the pool exhausted the denial observer completes in bounded time and its audit row survives the
  caller's rollback`, in `test_approval_manager_bound.cpp`.
- **Held-path expiry** (`sg-6`): MUST use `clock_timestamp()` or a bounded transaction age, not the
  transaction-start `now()`. Proof: `consume_ticket(PGconn*): a transaction begun before expiry
  whose consume happens after it is refused as expired and the ticket is not spent`, in
  `test_approval_manager_bound.cpp`.
- **Lost commit acknowledgement** (`up-9`): a retry that finds the ticket consumed by the same
  caller, in the transaction identity the redeemer recorded, MUST reconcile from the redeemer's
  own record as idempotent success, never as "already used". The failure class is not new to
  PR3: the pooled MCP recall already has the same ambiguity (a lost acknowledgement after the CAS
  shows the caller an error and a retry "already used", one approval burnt, no double
  execution), and PR2 does not claim it unreachable. Proof: `consume_ticket(PGconn*): a
  retry after a lost commit acknowledgement reconciles from the redeemer's own record`, in
  `test_approval_manager_bound.cpp`.
- **Excluded roots** (`up-4`): MUST be resolved through the ADR-0033 section 7 human-root table,
  never raw strings, and `same_human_root` (which `approve()`, `reviewer_is_excluded` and the
  page's `viewer_is_excluded` now share) and the mapping from a session to its root MUST change in
  one commit. Proof: `approve: every real session spelling of an excluded human is refused`, in
  `test_approval_manager_bound.cpp`, which MUST exercise the actual session-to-root resolution
  (a local account, its `oidc:` and `saml:` identities, a token's owner, an engine's owner) end to
  end through the approve route, not only an equality helper.
- **Mint bounds** (`up-8`, `up-3`): `submit_bound` MUST dedupe a second identical pending request
  and enforce a per-submitter or per-origin cap, and the expiry sweep MUST NOT hold `mtx_` across
  a lock wait. Proof: `submit_bound: a repeat of a pending request returns the existing ticket`,
  `submit_bound: the per-submitter cap refuses the next ticket`, and `submit: a row-locked expiry
  sweep does not stall other mints`, in `test_approval_manager_bound.cpp`.
- **Audit evidence** (`co-1`, `co-2`): the redeemer MUST write its own spend audit row on the held
  connection (`AuditStore::log_in_txn`, so it commits or rolls back with the spend), and the
  decision audit row MUST carry the request digest. Proof: `consume_ticket(PGconn*): the spend
  audit row is written on the held connection and rolls back with it`, in
  `test_approval_manager_bound.cpp`, and `approve: the decision audit row carries the request
  digest`, in `test_approval_routes.cpp`.
- **Transaction contract** (`cs-3`): the caller-held overload MUST refuse unless the connection
  reports `PQTRANS_INTRANS`. On an autocommit connection `FOR UPDATE` releases after each
  statement and a rollback does nothing, so the overload degrades to the pooled one; today only
  the CAS pin (`g8-sg-1`) keeps a rewritten row from being consumed there, and a plain consume on
  such a connection still succeeds. Proof: `consume_ticket(PGconn*): a connection that is not in
  a transaction is refused and the row is untouched`, in `test_approval_manager_bound.cpp`.
- **Canonical request** (`cpex-5`): duplicate keys, number fidelity and serialisation of
  `request_json` MUST be settled at mint, so the bytes that are digested are the bytes that are
  executed (a number such as 123456789012345678901234567890 displays rounded in the summary and in
  the API `request`, and a duplicate key displays last-wins). Proof: `submit_bound: a request with
  a duplicate key or an inexact number is refused`, in `test_approval_manager_bound.cpp`.
- **Classification** (`co-4`): no secret-typed parameter MAY be frozen into `request_json` (clear
  text, never pruned; see the Server Administration retention note). Proof: `the producer's
  request builder refuses a parameter marked secret before submit_bound is reached`, in the PR's
  producer test file.
- **The decision is pinned to the digest the reviewer saw** (`g8-up-1`, `g8-up-2`, `g8-er-1`): the
  Approve request MUST carry the `request_digest` the reviewer displayed, and `approve()`'s update
  MUST add `AND request_digest = $N` (and pin `reviewed_by` and `excluded_roots` too), so a
  decision cannot land on bytes the reviewer did not see. BOTH submission paths carry it: the
  Approvals page dialog's POST and the Instructions tab's `hx-post` Approve button, which sends
  no body at all today.
  PR2 does not do this: the Approve POST carries only the comment, and nothing but the absence of
  any code that updates `request_json` stands between the rendered summary and the decision. A
  database trigger forbidding an update of the frozen columns is a second layer. Proof: `approve: a
  digest that differs from the stored one is refused and nothing is written` (Gate 5 `CH2-4`), in
  `test_approval_manager_bound.cpp`, plus route tests `approve: a bound ticket's approve POST
  without a digest is refused` for each of the page dialog path and the tab path, in
  `test_approval_routes.cpp` and `test_approvals_fragment_routes.cpp`.
- **Display fidelity** (`g8-sg-3`, `g8-up-2`): any surface that shows a frozen request to a
  reviewer MUST show it ASCII-escaped (no raw bidirectional, line-separator or control character)
  with one field per line, as `summarize_bound_request` does. It MUST also be free of starvation:
  no section may push another out of the summary. Definition and Hash are always shown, and
  Targets, Parameters, Definition fields and Other fields each have their own byte budget and say
  on their own line when they show fewer entries than the request holds; the sections a reviewer
  most needs (Targets, Parameters) precede the optional ones. Reordering alone is not enough
  (twelve 512-byte targets exceed the whole summary budget by themselves). Proof, which the PR
  that adds a producer or a second display surface MUST keep green and extend to the new surface:
  `summarize_bound_request: the summary is display-safe (ASCII only), whatever the request carries`,
  `summarize_bound_request: one field per line, so a value cannot pose as another field`,
  `summarize_bound_request: no section can starve another; each says when it is cut` and
  `summarize_bound_request: a section whose first entry alone exceeds its budget still keeps its
  heading and says nothing was shown`, in `test_approvals_page_render.cpp`.
- **Read tier** (`g8-sg-5`): BEFORE the first producer, a maintainer decides who may read the
  frozen request, which can name target devices. Option A: every `Approval:Read` holder, as today.
  Option B: only `Approval:Approve` holders and the submitter, the others getting the digest, the
  definition name and a target count. Today it is unconfined: with RBAC off, every authenticated
  session reads it; service-scoped tokens are refused. Either choice is a change to the shared
  `approval_row_json` and the page, never a per-surface list. There are SIX representations:
  the legacy `GET /api/approvals`, the v1 list, the v1 get, MCP `list_pending_approvals`, the
  Approvals page and the Instructions tab. Proof: for each of the six, a test through the real
  handler with a POPULATED request that a principal outside the chosen tier, and one whose
  management-group policy would not reach the named targets, receives no `request`, in
  `test_approval_routes.cpp`, `test_rest_api_events.cpp`, `test_mcp_server.cpp` and
  `test_approvals_fragment_routes.cpp`. The audit side of the same decision (the legacy list and
  the page write no `approval.read` row where the v1 routes and MCP do) is decided with it.
- **Integrity refusals get their own kind** (`g8-sg-2`, `g8-co-1`, `g8-up-3`): PR2 reports a
  redemption integrity failure as `kForeignOrigin`, so the MCP audit row reads `refused:
  foreign_origin`, a token the documentation defines as a cross-surface attempt, and the cause is
  only in the server log. The PR MUST add a server-side-only kind (`kIntegrityFault`) with its own
  counter and an audit row carrying a closed cause token (reviewer is the submitter, reviewer is
  an excluded root, excluded roots unreadable, digest mismatch, digest without a request, digest
  not computable), and MUST decide the client text in the same change (today a caller is told
  "already used" for an intact approved ticket). Proof: `consume: an integrity failure is counted
  and audited under its own kind and cause`, in `test_approval_manager_bound.cpp`.
- **Narrow list projection** (`sre-4`): a list read that elides `request_json` MUST return a
  distinct type, never an `Approval` whose empty `request_json` reads as unbound. Today
  `schedule_runner` and the Home panel fetch the column and ignore it, and a 100-row list carries
  up to 16 KiB per row. Proof: a compile-time test that the narrow row type has no
  `request_json`, and `query_lean: a bound ticket is not reported as unbound`, in
  `test_approval_manager_bound.cpp`.
- **Withdrawing a pending bound ticket** (`g8-hp-1`): `set_review_status` refuses
  `reviewer == submitter` for reject as well as approve, so a submitter cannot withdraw their own
  ticket and it sits in the queue (counting toward the pending caps) until a different reviewer
  rejects it or the seven-day sweep expires it. The PR MUST decide: add a submitter-withdraw verb
  with its own audit action, or record that none exists and that the page does not offer one. Proof:
  either `withdraw: only the submitter may withdraw a pending bound ticket, and it is audited` or
  `reject: the submitter is refused and the page does not offer it`, in
  `test_approval_manager_bound.cpp`.
- **Rollback** (`g8-up-4`): condition 4 above is forward-only. A build older than migration v2
  starts against a v2 schema (the runner skips versions it does not know and has no
  schema-ahead guard), reads a bound row as unbound and ignores `excluded_roots`. Rolling back
  while any bound ticket is pending or approved-and-unconsumed MUST be refused by the operator
  runbook, or those tickets MUST be rejected first. `upgrading.md` states the rule in prose
  today; the PR MUST add the detection query to it. Proof: a test that the query in
  `upgrading.md` finds a seeded pending and a seeded approved-and-unconsumed bound ticket, in
  `test_approval_manager_bound.cpp`. The pinned consuming statement backstops redemption only
  after the upgrade, not on the older build.

## Honest residuals and not in the MVP

- **Author laundering by a pre-mint cosmetic edit.** Excluded roots come from recorded history
  (submitter, deployer, creator, last editor). A person who edited the substance in the middle of
  that history, followed by a cosmetic edit from a colleague who then submits, is not excluded.
  Per-version author history is out of scope.
- **Stale-payload ordering** is not closed fleet-wide until PR7 (agent stale-generation rejection).
- **Mutating-class writes** (for example `filesystem.write_content`, `registry.set_value`),
  `tar.*`, `power_health.set_power_plan`, `printing.clear_queue` and `content_dist` via the
  deployment pipeline (#3686) are not in the mandatory set.
- **Scheduled execution of mandatory pairs is refused** (intent, PR5), not approved.
- **Engine-submitted gated effects are refused** (D4), not rooted to an owner.
- **MCP-driven approval is interactive-only**: MCP `approve_request` and `reject_request` always
  refuse (PR1; ADR-1005 exception).
- **SAML approvers are refused while step-up is on** (#4935, #6098); a SAML-only deployment has
  no working approver path.
- **Step-up window 0 collapses assurance to session-only.** `--mfa-step-up-window-secs=0` already
  logs a boot warning; PR6 is intended to add an operational alert. Requiring an enrolled factor
  of every approver is #6079.
- **Emergency disarm is single-admin and alert-only.**
- Arm-direction break-glass, per-version author history, and a plan-hash for Guardian group
  targeting are deferred.

## Alternatives considered

- **A second approval gate for Guardian.** Rejected: two gates drift apart and give an auditor two
  things to test (ADR-1005 row).
- **Digest-only binding with no stored request.** Rejected: the reviewer cannot be shown what the
  digest covers, and a mismatch cannot be explained to the operator.
- **Keeping the original Decision 9 trigger (dangerous subset, reductions exempt).** Rejected: an
  empty or disabling redeploy is the cheapest one-person fleet-wide change.
