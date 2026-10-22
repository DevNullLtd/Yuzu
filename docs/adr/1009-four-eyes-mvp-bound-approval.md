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

A bound ticket is never a scheduled one: `submit_bound` refuses a non-empty `schedule_id` with the
ordinary validation failure and writes nothing. `ScheduleRunner` matches approved tickets on
(schedule id, definition, scope) with no origin check and fires the schedule's own definition, so
a bound ticket that carried a schedule id could be fired without its frozen request, digest or
excluded roots ever being compared. The unbound scheduled path (#6096) is unchanged.

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

1. The bound fields are not dashboard-only. Every approval read MUST carry `request` (the frozen
   request as a JSON object), `request_digest` and `excluded_roots` for a bound ticket and
   nothing extra for an unbound one: the legacy `GET /api/approvals`, `GET /api/v1/approvals`,
   `GET /api/v1/approvals/{id}`, MCP `list_pending_approvals`, and the Approvals page and
   Instructions tab (closes `arch-1`), so an agentic worker sees what a human sees. Proof:
   `approval_routes: GET /api/approvals shows a bound ticket's frozen request as an object; an
   unbound row is unchanged`, `GET /api/v1/approvals/{id} and the list: a bound ticket carries
   request/digest/roots; an unbound row is unchanged; same Approval:Read gate` and `MCP
   list_pending_approvals: a bound ticket carries request/digest/roots; an unbound row is the
   legacy field set; tools/list declares the optional fields`, in `test_approval_routes.cpp`,
   `test_rest_api_events.cpp` and `test_mcp_server.cpp` (all exist today).
2. The Approvals dialog MUST NOT claim more than the store can back (`arch-3`): it says the
   summary is for orientation and that what is approved is the whole request as stored under the
   digest shown. It makes no promise that the request cannot change after the decision: the
   Approve request carries only a comment and matches the ticket id and pending status, so
   that promise waits for the digest-pinned Approve below. Proof: `operate pages: Approvals
   copy is exact and claims no second person`, in `test_operate_pages_ui.cpp`, whose pins forbid
   "cannot change after your decision", "frozen under the digest" and "exactly the effect shown"
   (exists today).
3. The first change that mints a bound ticket or consumes on a caller-held connection, under
   whatever name (a call to `submit_bound` or the caller-held `consume_ticket`, or a new store
   member that reaches the private bodies `submit_impl` or `consume_core`), MUST get
   security-guardian and cpp-safety review, and MUST roll the REAL effect and the ticket back
   together: the effect (the deploy) and the spend of the ticket commit or roll back in ONE
   transaction on the connection the ticket was consumed on, and a lost commit acknowledgement is
   reconciled from the redeemer's own record (see "Lost commit acknowledgement" below). Proof,
   in the producer's test file: `deploy: a rolled-back deploy leaves the ticket redeemable and
   the effect absent`, `deploy: a committed deploy spends the ticket and applies the effect in
   one transaction` and `deploy: a retry after a lost commit acknowledgement does not execute
   twice`. These MUST be EXECUTED against Postgres, not skipped: the PG tests skip silently
   (exit 0) when `YUZU_TEST_POSTGRES_DSN` is unset, so the PR MUST show the shard that runs them
   with zero PG skips. The held redeemer MUST NOT run DDL (CLUSTER, a rewriting ALTER TABLE,
   TRUNCATE) on the redeeming connection inside the redeeming transaction: the version pin below
   cannot see a table rewrite issued by the holding transaction itself.
4. No bound ticket is minted until every replica runs a build that includes this change (an older
   replica's `approve()` ignores `excluded_roots`); the Upgrading guide states it. This is prose
   only today, and NO replica-enumeration mechanism exists to make it more: `submit_bound` checks
   no deployment capability, the store has no replica registry, and ADR-2002 supports exactly
   one replica until its safe-to-scale gate lifts (section 7c); it has no enumeration of
   replicas and no report of their builds (a search of `server/core/src` finds a `replica_id`
   only in `ExecutionTracker`'s own bookkeeping). So the first producer MUST either build such a
   mechanism or cite an existing one, and it MUST establish two things, not by an operator's
   say-so: the expected replica set comes from a named source (not from whatever happens to
   answer), and a replica that is unknown, unreachable or silent counts as NOT upgraded. Proof:
   `submit_bound: a fleet that contains an unknown or older replica refuses to mint`, in
   `test_approval_manager_bound.cpp`.

   The rollback leg is a different kind of requirement, and no boot-time check in the NEW build
   can meet it: a build older than this change must not be able to act on a bound ticket, yet
   the migration runner applies only the versions above the stored one and has no
   newer-schema refusal, so an older binary STARTS against this schema, reads a bound row as
   unbound and cannot refuse itself. Nothing mechanical stops that today; only the operator
   rule in the Rollback bullet below does, and nothing mints a bound ticket yet. The first
   producer therefore MUST either make a bound ticket structurally unusable to an older build
   (it fails closed instead of reading the row as unbound), or adopt the operator rule as the
   control and prove its detection query (Rollback below). It MUST NOT cite a boot-time check in
   the new build as the control for this. Proof for the structural option, which no mechanism in
   the tree provides today and which is therefore unproven until the producer builds it:
   `upgrade: a reader that knows only migration v1 fails closed on a bound row`, in
   `test_approval_manager_bound.cpp`, loading the row through the base build's own select list.
   Proof for the operator-rule option: the Rollback bullet's detection-query test.
5. PR3 lands in the same release window as PR2, or the dormant half is cut back out. Made
   checkable: let TAG be any git tag, a release candidate (`-rcN`) included, for which `git tag
   --contains <the commit that merges PR2>` is non-empty. PR3 (#6063) MUST merge before the first
   such TAG, or a change that REMOVES the dormant half MUST merge before it. "The dormant half" is
   four things: the `excluded_roots` refusal in `approve()`, `submit_bound` (with
   `BoundRequest`, `SubmitError` and their validation), the `kGuardianDeploy` origin, and the
   caller-held-transaction `consume_ticket(PGconn*, ...)` overload with its
   `ConsumeTestStage` seam; migration v3's columns stay (they are forward-only and harmless
   empty). Removing them also touches their compile and test dependents: the `kGuardianDeploy`
   entry in the `yuzu_approval_precondition_denied_total` pre-seed loop in `server.cpp` (and the
   series' documentation in `metrics.md`), and the allow-list in
   `test_approval_dormant_code_tripwire.cpp`, whose exact counts fail once the origin is gone.
   The `guardian.` definition-id reservation is a separate, shipped decision that a removal
   states it keeps. The accountable owner is the epic owner of #6060, who records which of the two applies
   in a comment on #6060 before the first such TAG is cut; the deadline is that TAG. There is no
   release gate that checks this today. A tripwire keeps the question honest in between: `bound-
   approval primitives still have no production use (ADR-1009 tripwire, not proof)`, in
   `test_approval_dormant_code_tripwire.cpp`. It lexes every regular file under `server/core/src`
   and nowhere else, whatever its extension (so a caller moved into an `.ipp`, `.inl` or `.tpp`
   fragment is still seen), except an explicit list of documentation, data, image, font,
   certificate and archive extensions, skipped by repository convention and not because a compiler
   could not read them (an `#include` of a fragment under a skipped extension is an unscanned
   residual). It first applies translation phase 2, so a line splice, with or without whitespace
   after the backslash and with LF or CRLF line ends, cannot hide or split a name, and reports
   each hit on its original line (comments, and string, character and
   raw-string literals including their `u8`, `u`, `U` and `L` prefixes, are excluded), counts
   `submit_bound`, `consume_ticket`, `kGuardianDeploy`, the interleaving seam and the three
   names a store member needs to reach them without spelling those (`submit_impl`,
   `consume_core`, `BoundRequest`) in code, per file, and fails unless each count equals its
   allow-list entry exactly. Nothing is exempt: the store files are pinned like every other file
   (a member added there that mints or consumes through any of the seven raises a count and
   fails), a file with no entry is allowed none, and it also fails when the
   store, `mcp_server.cpp` or `server.cpp` is not scanned. Its own tests plant a producer, a
   store wrapper and prefixed literals in temp trees to show it is not blind. What it does NOT
   see: a wrapper that is only CALLED from elsewhere under its own name (the caller names the
   wrapper, not the primitive), the overload a changed declaration binds a call to, anything
   outside `server/core/src` (`server/core/include`, `common/include`, `sdk/include`, `tests/`),
   a generated file, a macro that pastes a name together, a few lexer shapes
   with no instance in the tree (a universal-character-name spelling, an unterminated block
   comment at end of file, a lone CR used as a line end; the test header lists them), and any
   behaviour. The one production `consume_ticket` call is also pinned by the text of its argument
   list, so replacing the pooled call in `mcp_server.cpp` with the caller-held overload (a
   connection first, same identifier count) fails with a message naming both lists; that check
   is lexical too. It is a tripwire for a careless first producer, not a control against a
   deliberate one.

   Any change to the tripwire's allow-list, its expected-count table, its pinned call shape or its
   skip list is the act that activates the dormant code, and a PR that makes one MUST carry a
   recorded review by a maintainer who is not its author (a PR-review obligation: the author
   and the proving-test evidence are named in the PR). NOTHING enforces this today. The test
   cannot see who reviewed, an author can edit the rules and their baseline together, the
   repository has no CODEOWNERS entry for the test, `approval_manager.*` or this ADR, and no
   branch-protection setting is claimed here; the failure message only names the conditions. The
   obligation stands until an enforced review owner exists.

### PR3 entry conditions

Open findings that become conditions on the PR that first wires a producer or redeemer (#6063).
The consume-time recheck is in PR2 (`up-2`, `g8-sg-1`). Every read a consume makes before its
consuming statement runs the origin and submitter checks, and, for a row that is approved and not yet consumed, the integrity
checks (reviewer is not the submitter or an excluded root, an approved ticket names a reviewer,
excluded roots readable, request matches its digest); a pending, rejected, expired or already
consumed row keeps reading as the ordinary refusal it is. The consuming statement is pinned to the
row VERSION of the last row examined, which is two values: `xmin` (the transaction that wrote the
version) and `ctid` (its tuple position). An update of the row by ANOTHER transaction between the
checks and the statement, in any column (`consumed_at`, `reviewed_at`, `definition_id` and the
rest included), moves `xmin`; a second write at the same (sub)transaction level (the held
overload, when the caller's own transaction wrote the row first) keeps `xmin`, because every
version written at one level carries that level's xid, and moves `ctid` (a write after a
SAVEPOINT carries the subtransaction's xid and moves `xmin` too, which only refuses more).
Neither value alone is a version: a plain VACUUM between two other transactions' writes can put
the new tuple back in the examined slot, and only `xmin` then tells them apart. For DML, either
mismatch makes the statement match nothing and read as the uniform not-consumable; the explicit
status, reviewer, request, digest, excluded-roots, origin and submitter pins are kept as defence
in depth. What that is NOT: the check and the statement remain two statements; a writer who can
replace the row wholesale or work below SQL is outside what it can tell; `xmin` is the raw
32-bit xid with no epoch, so a different writer that received the same xid after a wraparound
and reused the same slot would match; and, for the HELD overload only, a table-rewriting
statement issued by the holding transaction itself (CLUSTER, a rewriting ALTER TABLE, TRUNCATE
followed by a re-insert) can leave a changed row at the examined pair, which is why entry
condition 3 forbids DDL on the redeeming connection (the only production caller today is
pooled and cannot reach this). It also fails closed, with a false refusal: a no-op rewrite of
the row is a new version, and VACUUM FULL or CLUSTER can move `ctid` of an unchanged row. After
either, a retry (a fresh read of the new version) succeeds; when the other writer was a
concurrent consume or a real edit, the refusal is correct and the retry is refused again.
VACUUM FREEZE changes neither value and refuses nothing. It detects a row that moved by accident
or by an old build; it is not a boundary against a principal with database write access. On an
autocommit connection (the `cs-3` item below) the held overload gets only the pin.

Each bullet below is a MUST. Its Proof names the case title and file that demonstrates it,
except three that are descriptions rather than titles: the Classification proof's file (the
producer's test file does not exist yet), the first Narrow list projection proof (a compile-time
test) and the Rollback proof; the PR MUST pick the title and file for each and state them in its
description before review. A test the PR adds is written first and is red at the base of that PR;
a test that cannot be made red first is not evidence. Where a Proof says "keep green" (Display
fidelity), the tests already exist and pass at the base, so they cannot be red there: the PR MUST
keep them green and extend them to the new surface. Test names are the case titles in
`tests/unit/server/` that the PR adds.

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
- **Classification** (`co-4`): a secret-typed parameter MUST NOT be frozen into `request_json`
  (clear text, never pruned; see the Server Administration retention note), so the producer's
  request builder MUST refuse one. Proof: `the producer's request builder refuses a parameter marked
  secret before submit_bound is reached`, in the PR's producer test file.
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
  no section may push another out of the summary. The Definition line (and the Hash line when `definition` is an object) is never budgeted away, and
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
- **Read tier** (`g8-sg-5`): BEFORE the first producer, a maintainer MUST decide who may read the
  frozen request, which can name target devices. Option A: every `Approval:Read` holder, as today.
  Option B: only `Approval:Approve` holders and the submitter, the others getting the digest, the
  definition name and a target count. Today it is unconfined: with RBAC off, every authenticated
  session reads it; service-scoped tokens are refused. Either choice is a change to the shared
  `approval_row_json` and the page, never a per-surface list. There are SIX representations:
  the legacy `GET /api/approvals`, the v1 list, the v1 get, MCP `list_pending_approvals`, the
  Approvals page and the Instructions tab. Proof: for each of the six, a test through the real
  handler with a POPULATED request that a principal outside the chosen tier, and one whose
  management-group policy would not reach the named targets, receives no `request`, titled
  `read tier: <surface> withholds a populated request from a principal outside the tier` (one
  per surface) in
  `test_approval_routes.cpp`, `test_rest_api_events.cpp`, `test_mcp_server.cpp` and
  `test_approvals_fragment_routes.cpp`. The audit side of the same decision (the legacy list and
  the page write no `approval.read` row where the v1 routes and MCP do) is decided with it.
- **Integrity refusals get their own kind** (`g8-sg-2`, `g8-co-1`, `g8-up-3`): PR2 reports a
  redemption integrity failure as `kForeignOrigin`, so the MCP audit row reads `refused:
  foreign_origin`, a token the documentation defines as a cross-surface attempt, and the cause is
  only in the server log. The PR MUST add a server-side-only kind (`kIntegrityFault`) with its own
  counter and an audit row carrying a closed cause token (reviewer is the submitter, reviewer is
  an excluded root, approved with no recorded reviewer, excluded roots unreadable, digest
  mismatch, digest without a request: SIX tokens, plus the seventh cause the code also treats as
  a refusal, a digest that could not be computed, which today is a store error flagged
  `binding_check_unevaluated` and not a `kForeignOrigin` at all), and MUST decide the client text
  in the same change (today a caller is told
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
- **Rollback** (`g8-up-4`): the operator-rule option of condition 4's rollback leg. A build older
  than migration v3 starts against a v3 schema (a pre-#6096 build knows migration v1 only and a
  #6096 build without this change knows v1 and v2; the runner skips versions it does not know
  and has no schema-ahead guard, so the new build's boot check cannot stop the old one), reads a
  bound row as unbound and ignores `excluded_roots`. Rolling back while any bound ticket is
  pending or approved-and-unconsumed MUST be refused by the operator runbook, or those tickets
  MUST be rejected first. `upgrading.md` states the rule in prose today; the PR MUST add the
  detection query to it, unless it takes the structural option of condition 4 instead. Proof: a test that the query in
  `upgrading.md` finds a seeded pending and a seeded approved-and-unconsumed bound ticket, in
  `test_approval_manager_bound.cpp`. The pinned consuming statement backstops redemption only
  after the upgrade, not on the older build.
- **Never schedule-fired** (`schedule_id` refusal): a bound ticket MUST NOT be fired by
  `ScheduleRunner`. `submit_bound` refuses a non-empty `schedule_id` today, which is the only
  barrier, because the runner has no origin check of its own. PR3 MUST keep that refusal (or add
  an origin check to the runner in the same change that removes it), and any later producer of
  bound tickets inherits the same rule. Proof: `submit_bound: a bound mint with a schedule id is
  refused and writes nothing`, in `test_approval_manager_bound.cpp`.

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
