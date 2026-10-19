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

**Proposed, not accepted.** Committed for `/governance` review. The "Built by" column below is
the delivery plan for epic #6060; only PR1 (#6163) is merged. PR2 is the code half of #6062, in
review alongside this ADR. Anything attributed to PR3 to PR7 is **intent**, not shipped behaviour.

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
request and refuse on a mismatch. The approvals page renders `request_json`, not a bare digest
(#4395 class).

### D3. Redemption is origin-declared

`consume_ticket` takes the origin the redeeming surface expects (`ApprovalOrigin`). A ticket
whose recorded origin differs refuses, and `kUnspecified` and `kUnrecognised` always refuse.
PR2 adds `kGuardianDeploy` and reserves the `guardian.` definition-id prefix alongside `mcp.`, so
no authored definition can impersonate a Guardian ticket. A second `consume_ticket` overload takes
a caller-held transaction connection so consumption commits or rolls back with the caller's own
effect (PR3 uses it for the deploy write). A precondition denial gets its own audit row and counter.

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
single-person path. The rest of Decision 9 stands: digest binding over content, parameters,
escalation policy and assignment scope, and recompute-and-compare at compile (PR3).
The Reaction clause is unchanged and Reflex is outside this MVP.

### D6. Activation

One server setting, `four_eyes.mandatory`, default **off** until PR6. Until then, PR2 to PR5 land
the mechanism without changing who can do what. Snapshot serving (PR3) ships unconditionally.

### Delivery map

| PR | Issue | Delivers | Status |
|---|---|---|---|
| PR1 | #6061 | Reliable reviewer decision (D1) | merged (#6163) |
| PR2 | #6062 | D2, D3, D4 and this ADR | in review |
| PR3 | #6063 | Guardian approved snapshots, gated deploy (D5), compile-time digest recompute | intent |
| PR4 | #6064 | Instruction request freeze and redemption on REST and dashboard | intent |
| PR5 | #6065 | System-caller gate, mandatory pair set, scheduled-execution refusal | intent |
| PR6 | #6066 | Flip `four_eyes.mandatory`, metrics, alerts, docs | intent |
| PR7 | #6067 | Agent rejects stale-generation policy pushes | intent |

## Consequences

- One mechanism for an auditor to test; MCP, instruction and Guardian tickets differ only by
  declared origin.
- A ticket cannot be replayed on another surface or for another request.
- Reviewers see, and approve, the actual effect.
- `four_eyes.mandatory` is off, so until PR6 the protection exists but is not enforced.
- The emergency disarm is a deliberate single-person path; it is bounded to the direction that
  reduces enforcement and is detected, not prevented.

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
