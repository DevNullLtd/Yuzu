---
status: proposed
date: 2026-10-17
owner: Nathan Dornbrook / platform
deciders: Nathan Dornbrook, Dave Rae (companion ADR-1010/1011/1012 author; §11 reconciles the seams)
scope: server — the scope primitive every instruction dispatch starts from; how a scope is stored,
  how its membership is evaluated and re-evaluated, how a consumer tells a stale scope from a fresh
  one, when a scope is frozen and when it tracks the estate, and how one instruction's results become
  the next instruction's scope (scope walking)
builds-on: ADR-0033 §10 (Execution Plans — frozen targets, plan hash, narrow-only execution),
  ADR-0032 (every filter reads live except the ceiling), ADR-0036 (ResultSetStore on Postgres,
  typed targeting errors), ADR-0012 (server Postgres store contract)
amends: docs/scope-walking-design.md §5 (materialise-by-default) and §4.3 (silent stale-member drop);
  ADR-0033 §4 ("a stale approval re-resolves its scope at execution")
revised: 2026-11-21 — reconciled result-set evaluation metadata, sibling re-evaluation, scope
  consumption and admission with ADR-0075. The original proposal of 2026-10-17 added agent-site
  matching, guarded execution, frozen previews, starting scopes, cooling and scope DSL contracts.
related: ADR-1010 (impact / response-size attributes), ADR-1011 (fleet-heavy dispatch enforcement),
  ADR-1012 (explicit response completeness) — Dave Rae, drafts on `docs/adr-1009-impact-response-size`;
  docs/scope-walking-design.md; docs/authz-model.md; docs/adr/1005-headless-platform-use-case-engines.md;
  docs/adr/1007-concurrency-enforcement-scope.md; docs/adr/1008-rbac-management-groups-target-architecture.md;
  docs/plans/instruction-recovery-plan-2026-10-15.html (WP03/05/06/07/08/11/14); #5077 #684 #4115 #4494
  #6002 #5003 #4088 #4525
---

# 0072 — Scope lifecycle: definitions, evaluations, freshness, and the walk

> **Companion ADRs.** Dave Rae's ADR-1010 (impact / response-size attributes), ADR-1011 (fleet-heavy
> dispatch enforcement) and ADR-1012 (explicit response completeness) are drafts on his unpushed branch
> `docs/adr-1009-impact-response-size` (tip `32937fee4`, copied 2026-10-17). They decide what a dispatch
> *costs* and whether its answer is *whole*; this ADR decides what a dispatch *targets* and whether that
> target is *fresh*. The seams are reconciled in §11; the three decisions there (one digest builder, one
> completeness vocabulary, one "fleet-wide" test) bind both threads.

## Binding status

Proposed for acceptance alongside ADR-0075. On acceptance, every dispatch surface listed in D7 (manual, scheduled,
approved, workflow step, rerun, `/auto` deploy, result-set producers) must satisfy D7–D9 before the
split interlock's capability registry (ADR-0032) can call scope targeting "parity-complete". Nothing
here changes the admission-shape rule of the *Dispatch targeting* routed concern (an omitted target
is fleet-wide except for a `Destructive` pair); it changes what is **recorded** and **re-used**, not
what is **admitted**.

## Context

### The brief

An operator — human or agentic — works a fleet by iterative narrowing:

1. **Start** from a scope: *all Windows machines*.
2. **Observe** something about them: *which of those are running Chrome right now* — the responders
   form a new scope.
3. **Narrow again** from another observation: *which of those have a connection to the production
   payments web front end in Hong Kong*.
4. **Act** on the result, or keep walking.

Step 1 is a predicate over device attributes the server already holds. Steps 2 and 3 are
*observations*: they can only be answered by dispatching an instruction and collecting responses,
and the answer is true at the moment it was collected. Step 4 may be destructive.

Two things follow that the current design does not handle well. First, a scope must be **storable**
and **re-usable**: a schedule, an approval, a workflow step, a rerun and a child scope all need to
name one. Second, a stored scope **ages**. "All Windows boxes" two weeks ago is not "all Windows
boxes" today; "running Chrome right now" was only ever true at one instant. Sometimes the operator
needs the scope to be *invariant* — an approved change must land on exactly the cohort the approver
saw. Far more often they want it to *track* the estate — a scheduled hygiene check should reach the
laptops enrolled since it was written. Today there is no way to say which, no way to tell how far a
stored scope has drifted, and the surfaces that re-use scopes disagree with each other.

### Original baseline (2026-10-17)

The following findings record the state that prompted the first draft.

`docs/scope-walking-design.md` and ADR-0036 give us a **result set**: a named, TTL-bounded, owner-scoped
set of device ids with a `parent_id` lineage edge, a verbatim `source_payload`, and a
`from_result_set:<id>` scope atom. Membership is **materialised at creation and never re-derived**;
"re-eval" mints a *sibling* set with a new id. At dispatch the frozen membership is narrowed live by
`dispatch_confined_arms` — connected agents only, attribute predicates read live, intersected with the
caller's *current* visibility. Devices drop out; they never drop in.

That is exactly the rule ADR-0033 §10 states for Execution Plans ("targets are frozen in the plan;
execution may only narrow them … approval binds to the plan hash"). But:

- **Nothing implements Execution Plans.** No `ExecutionPlan`/`cohort_integrity` symbol exists under
  `server/`; the shipped `compute_plan_hash` (`command_capability_parsers.hpp`) hashes the target *arm
  label* ("scope", "ids"), not the device set — `tests/split_interlock_ledger.json` says so explicitly.
- **Schedules and approvals bind to the scope *string*** and re-resolve it at fire time
  (`schedule_runner.cpp`, `command_outbox_delivery.cpp`, `approval_manager.hpp`). Re-resolution can
  *add* devices — the opposite of §10, and the ambiguity §10 was written to remove. A raw alias stored
  on a schedule re-resolves newest-wins.
- **No execution records which devices were targeted.** `Execution` holds `scope_expression` and an
  `agents_targeted` *count*; `agent_exec_status` rows exist only for responders. "Who was reached" is
  reconstructed from "who answered".
- **Reruns dispatch nothing** (#684, #4115). **Workflow steps** fix `agent_ids` at run start and never
  narrow between steps. **Management groups** evaluate membership only at creation (ADR-1008 Context,
  UP-5) — frozen by accident, and `group:` is a whole-scope dispatch arm, so a group cannot be combined
  with a predicate.
- Three defects in the one surface that *does* freeze:
  - async result sets materialise from a response page capped at **100** (#5077; the recovery plan's
    WP07: 524 responders → a 100-member set), and a timed-out `pending` set is finalised as
    `materialized` with whatever arrived (`server.cpp` maintenance tick). `failed` is unreachable
    (#4494);
  - an **expired** (GC-pending) or **still-pending** set resolves as a *valid* scope — `member_set_owned`
    and the early gate check existence and ownership only. A pending set resolves *empty*, so
    `NOT from_result_set:<pending>` matches the whole visible fleet — the precise fail-open class
    ADR-0036 was written to close, reachable by a different door (#6002, filed with this draft);
  - the design's stale-member warning, dropped-id audit (§4.3), `?live=true` lazy resolve (§5) and
    `evaluated_at` are promised and absent. Members carry no timestamp of any kind.

### Revision baseline (2026-11-21)

At `DevNullLtd/Yuzu@ddb5649aba`, scope preview and dispatch already reject pending and failed sets.
A narrowing child inherits its parent's incompleteness. Positive references to incomplete sets
can only narrow, while `NOT`, `LEN` and `STARTSWITH` reject those sets. The maintenance tick reads
asynchronous responses in bounded pages and a read beyond the bound fails the set. See
`docs/scope-walking-design.md` §4.3 and the result-set maintenance tick in `server/core/src/server.cpp`.
The workflow builder's count-only estimate still renders an unresolved alias or degraded read as
zero. Rung 0 distinguishes that render from a genuinely evaluated empty scope.

[ADR-0075](0075-criteria-runs.md) builds criteria runs on this store. For example, a stored-inventory
run records its input specs and the admitted cohort in a result set. It records one verdict per
cohort device. A scope consumer receives the matched devices, and an unassessed device makes the
result incomplete for inversion. An explicit re-run uses the stored specs under current grants
and creates a sibling. For a mixed-input run, admission requires visibility through every input
gate. A device outside any gate contributes only to the excluded count. A device admitted at
creation stays in the cohort if visibility changes before delivery, with the affected input
recorded as withheld. An approval that later freezes the matched scope copies the device list and
binds the definition hash, sorted-members hash and device count. Its evidence survives the run's TTL.

[ADR-0073](0073-liveness-heartbeat-tag-deltas-topology-rpc.md) supplies the liveness boundary.
A heartbeat can establish connectivity. Scope freshness tracks relevant changes in membership inputs,
including actual tag changes. Software evidence comes from the inventory observation and facet
confirmation. A device that disconnects stays in the selected cohort and can be recorded as unreached.

### Prior art — 1E Tachyon

Read from the local mirror of the Tachyon 8.1 platform and SDK documentation (`D:\mnt\data\1e\`).

Tachyon stores **no scope at all**. Coverage is an unresolved expression over device attributes the
agent reported at connect; it is "applied at the Tachyon Server before the question is asked" and
"remains active for the duration of the question, so client devices that change their device details
… may subsequently be included … that may include new client devices that haven't previously
connected" (*Explorer home page, questions and responses*). A **follow-up** instruction is not a
server-side narrowing to the parent's responders: "all devices within the coverage will be re-asked
the same question, and the Tachyon client will apply the filter to the latest result on each device"
(*The action approval workflow*). That is why Tachyon forbids actions as parents (the chain would
re-run the action) and why "Rerunning an action is not allowed, as it can be risky".

The only frozen target in Tachyon is an explicit FQDN list. Staleness is not modelled: there is no
evaluation timestamp, no membership snapshot, and approval binds to the instruction, not to a device
set — a known issue admits "the workflow look[s] at the user's permission and not the scope of the
target devices". Management-group membership is re-evaluated on every inventory sync (recommended
daily) and lags reality by up to a day. The one piece of staleness machinery is `HashOfMembers` on a
management group, which the documentation never uses.

Lessons taken: (1) *live by default* is the right operator expectation; (2) a follow-up must re-check
the **condition**, not merely replay the parent's responders, or it acts on stale truth; (3) binding
approval to a device set, recording when a scope was evaluated, and bounding scope size are the three
things Tachyon lacks and an enterprise auditor asks for first.

### Prior art — Tanium, CrowdStrike, Aternity (surveyed 2026-10-17, public docs)

| Concept | Tanium | CrowdStrike Falcon | Aternity | This ADR |
|---|---|---|---|---|
| Expression scope | question filter (`from all machines with …`), **evaluated on each client** against its own sensors | FQL host-group `assignment_rule`, server inventory | dashboard attribute filter | `expression`, server-side (D2) |
| Named group | computer group: dynamic (sensor expression) or manual (hostname list); management group bounds authority, filter group narrows | host group: `dynamic` / `static` / `staticByID`; membership resolved at query time | none | `group` kind (D2) |
| Narrow from results | **drill down**: follow-up "scoped only to the endpoints that returned that result"; session-only, no id; **Deploy Action from results capped at 100 rows** | Fusion workflow: Device Query → loop → RTR per host, branch on tags or a script's **typed output** | none (per-device alert → runbook) | `narrowing` with a stored, hashed evaluation (D1/D3/D6) |
| Frozen cohort | manual group only | every RTR call is an explicit `host_ids` list | the alerting device | `frozen` binding to a result-set ID (D4) |
| Staleness signal | none; scheduled actions re-target on reissue and clients "re-evaluate sensors when checking actions for targeting criteria" | none; no timestamp, no hash | none | fleet generation + age budget (D5) |
| Two-tier targeting | action group = outer ceiling; per-action Targeting Criteria narrow inside it; **mandatory Show Preview** | host group + `optional_hosts` subset | n/a | authority ∩ starting scope (D12) ∩ operator scope; preview-is-dispatch (D8) |
| Re-execution guard | none | none | **cooling window** 1–24 h per device after a remediation, so a failed fix cannot loop | cooling (D14) |
| Record of reach | per-client action status | batch session results | per-run output | reached set on the execution (D7) |

What is taken, and from whom:

- **Tanium — evaluate the condition on the endpoint.** The cheapest and freshest place to answer
  "is Chrome running?" is the agent that owns the process table. ADR-0072 adopts this as the
  default site for a walk's matcher (D6) for an agent-evaluable query and as a pre-execution **guard** (D6b). Tanium's
  session-only drill-down and its 100-row cap on acting from results are the anti-pattern: a
  narrowed set that cannot be named, stored, hashed or approved. Interact shipped two defects where
  the results-grid filter was silently not carried into action targeting (Interact 2.3, 2.6
  release notes) — the "what you looked at is not what ran" class D7/D8 close by construction.
- **Tanium — two tiers plus a preview.** The action group is a ceiling the per-action criteria
  narrow inside, and the preview is mandatory. D12's starting scope and D8's ceiling approval are
  the same shape; D8 now also binds the dispatch to the previewed evaluation.
- **CrowdStrike — typed output drives the branch.** A Fusion workflow branches on a script's
  declared output schema. The matcher for a typed live query in D6 is type-checked against the query definition's declared
  result columns (DSL spec §11), so a walk cannot be authored against a column the query does not
  produce.
- **Aternity — a cooling window.** A device that just ran a remediation is withheld from the same
  remediation's tracking re-dispatch for a bounded period. Nothing in ADR-1007 (in-flight
  concurrency) or the design doc covers "recently completed"; D14 adds it.
- **What none of them have:** a stored, immutable evaluation with an id, a members hash, a
  completeness status and a parent snapshot for a narrowing. That remains this ADR's differentiator and nothing
  in the survey argues against it.

Sources: Tanium [Interact essentials](https://www.tanium.com/blog/tanium-interact-essentials-tech-talks-161),
[endpoint grouping](https://www.tanium.com/blog/endpoint-grouping-strategies-tech-talks-160),
[advanced question syntax](https://docs.tanium.com/interact/interact/example_advanced_questions.html),
[RBAC overview](https://help.tanium.com/bundle/ug_console_cloud/page/platform_user/console_rbac_overview.html),
[7.6.2.1204 release notes](https://kb.tanium.com/Release_Notes_Tanium_Server_and_Tanium_Client_(Version_7.6.2.1204)),
[Interact 2.3](https://kb.tanium.com/Release_Notes_Interact_(Version_2.3)) / [2.6](https://kb.tanium.com/Release_Notes_Interact_(Version_2.6)),
[drill-down study guide](https://open-exam-prep.com/study-guides/tanium-certified-operator/refining-questions/drill-down) (secondary);
CrowdStrike [host group (Terraform)](https://developer.crowdstrike.com/cac/terraform/provider/host-group/resources/host-group/),
[host group members](https://developer.crowdstrike.com/cac/terraform/provider/host-group/data-sources/host-group-members/),
[Real Time Response API](https://developer.crowdstrike.com/api-reference/collections/real-time-response/),
[Fusion features](https://www.crowdstrike.com/blog/new-falcon-fusion-features-refine-workflow-automation/),
[IT Automation scheduled task](https://developer.crowdstrike.com/cac/terraform/provider/it-automation/resources/it-automation-scheduled-task/);
Aternity [remediation triggers](https://help.aternity.com/bundle/release_news_agent_console_saas/page/console/topics/console_admin_remedy_mac.html),
[Intelligent Service Desk](https://www.riverbed.com/blogs/the-power-of-riverbed-aternity-intelligent-service-desk/),
[Run-control design write-up](https://marinadus.com/self-remediation/) (secondary; the cooling window and multi-device run are not in Riverbed's public docs).

## Vocabulary

| Term | Meaning |
|---|---|
| **Scope** | A definition of a device population. A stored observation of that population is an owner-scoped result set with its own `rs_<ulid>`. Each sibling records its own evaluation. |
| **Definition** | How the membership is computed. Immutable once written. Kinds: `expression`, `narrowing`, `explicit`, `group`. |
| **Evaluation** | An observation of a definition. Its result set carries the evaluation time, membership hash, counts, inputs and completeness. Once settled, the observation is immutable. |
| **Binding** | How a consumer (dispatch, schedule, approval, child scope) refers to a scope: `tracking` (resolve the definition under its freshness contract, where supported) or `frozen` (use the named result-set snapshot). |
| **Fresh / stale** | An evaluation is stale when its inputs may have changed since it ran (D5). Staleness is a *property of an evaluation*, decided at use time, never a background sweep. |
| **Decay** | Members of an evaluation that no longer exist, are decommissioned, or are not reachable. Computable without re-evaluating. Out-of-set only. |
| **Drift** | Devices that now satisfy the definition but are not in the evaluation, and vice versa. Needs a re-evaluation to compute. |
| **Walk / re-walk** | Evaluating a `narrowing` definition: evaluate the parent, dispatch the narrowing query to the parent's evaluation, match the responses. A re-walk is the same with a fresh parent observation. Criteria runs support explicit sibling re-runs. Automatic and scheduled criteria re-walks require a separate conduit design. |
| **Reached set** | At dispatch: evaluation members ∩ connected ∩ caller's current authority. Recorded on the execution. |
| **Matcher** | A predicate over a query's typed result columns that decides whether a responder is a member. Runs on the agent (`agent` site) when it is agent-evaluable, else on the server (`server` site). One evaluator, shared by both. |
| **Precondition** | A `(query, matcher)` pair carried on a dispatch. The agent runs the query, applies the matcher, and replies `matched` or `not_matched`; a chain is an ordered list of them, short-circuited on the first `not_matched`. |
| **Guard** | A dispatch option: the agent re-evaluates the scope's precondition chain immediately before the action and withholds itself if the chain no longer holds. Narrows only. |
| **Cooling** | A per-`(device, definition)` window after an execution during which a *tracking* re-dispatch of the same definition withholds the device. |

"Result set" remains the user-facing name for a scope whose definition is `narrowing` or `explicit`;
the REST/MCP surface keeps its `result-sets` paths. Nothing in this ADR renames a shipped route.

## Theory — why the decisions have the shape they do

Nothing in this section is a decision. It names the standard results the decisions are instances
of, so a reviewer can check a rule against its source rather than against the author's preference,
and so future measurement work can build on the same vocabulary.

### Order: scopes form a lattice; definitions and evaluations are a Galois connection

The universe is the fleet; scopes live in its powerset ordered by `⊆`, a complete lattice. A
narrowing is a **deflationary, monotone operator**: it never adds a member, and a larger parent
never yields a smaller child. A walk is a descending chain `S₁ ⊇ S₂ ⊇ S₃`. Lineage via
`parent_id` is a forest rooted at `expression` and `group` scopes; it stays a forest because every
form in D13 has exactly one receiver, which is why `parent_id` is single — a binary join would
make it a DAG and `parent_id` a list.

The definition / evaluation split is the **intension / extension duality** of Formal Concept
Analysis (Wille, 1982): the intent (the predicates) and the extent (the devices) are related by an
antitone Galois connection — adding a conjunct to the intent can only shrink the extent. That is the
structural half of `narrower_than` (D13) and the reason it is decidable from syntax alone for an
`AND`-extended expression or a `narrowing` child: those are lower in the intent order, so they are
lower in the extent order. `OR` and unrelated predicates carry no such order, hence `incomparable`
rather than a guess.

Negation is **relative complement**. `not(a) within parent` is `parent ∖ a`; a bare `NOT` is
complement in the universe, which is the fail-open class #6002 reports. D9 and D13's "`not` always
has a receiver" are one lattice fact stated at two sites.

### Computation: a walk is a semijoin program; a re-walk is stage fusion

A walk is `map(predicate on each endpoint)` followed by `reduce(set union of ids)`. Union is a
**commutative, associative, idempotent monoid**, so the reduce is order-free and replay-tolerant —
a duplicate reply under the agent's effectively-once dedup (ADR-2002 WS-0) cannot change
membership.

Chaining walks with the server between levels is *d* map-reduce jobs with a shuffle after each. A
filter chain has only **narrow dependencies** (each endpoint's answer depends on its own data
alone), so the stages fuse: D6's one-dispatch re-walk is **pipeline fusion with predicate
pushdown**, the optimisation a columnar engine applies to a chain of `WHERE` clauses and a
federated engine applies when it pushes a predicate into the connector. Targeting the dispatch at
the parent evaluation is a **semijoin reducer** (Bernstein & Chiu, 1981): the fleet is semijoined
with the parent's id set before any data moves, and ADR-1010's `response_bytes` is the cost those
programs were designed to minimise.

The matcher grammar's bound (column predicates plus `COUNT`) is the line between **distributive /
algebraic aggregates**, which decompose per partition, and **holistic** ones (median, cross-device
distinct count, percentile), which need the shuffle. Keeping agent-site matchers on the first side
of that line is what makes the agent and server evaluators agree (acceptance test 12). A
cross-device join is a **wide dependency** and belongs to the server-site path by construction.

### Time: freshness is a logical clock, not a set comparison

The fleet generation (D5) is a **logical clock on the universe**. Staleness is a clock comparison,
which is why it is exact for server-held inputs (`expression`, `group`) and only a budget for
observed ones (`narrowing`): an observation cannot be known stale without re-observing, so its
freshness is an age bound, never a fact. Decay (members gone) is computable from the clock and the
roster; drift (members that would now join) is not, and needs a re-evaluation.

### Measurement: a walk along a path is time-domain reflectometry on sets

Let a service path be hops `h₁ … hₙ` (ADR-0002's host and service nodes, read from the user
outward), `S₀` the affected cohort, and `Sₖ` the scope "members of `Sₖ₋₁` that reached hop `k`"
— a `narrowing` whose query is a synthetic probe. The **per-hop transmission ratio**
`Tₖ = |Sₖ₊₁| / |Sₖ|` is near 1 at a healthy hop and collapses at a broken one; it is the discrete
analogue of the reflection coefficient at an impedance discontinuity, and the first collapse is the
fault's position. Each evaluation is a stored, hashed, timestamped measurement, so the bisection
has an audit trail. Half-bracketing a chain is bisection (`d = 1` group testing); on a DAG with
shared infrastructure it becomes **Boolean network tomography** (Duffield, 2006) over a routing
matrix and **minimal hitting sets** (Reiter, 1987) for multiple faults, with identifiability
limits that are known in advance from the matrix. This is an illustration of how a later service-path
design could consume scope observations.

## Decision

### D1 — Each result-set ID names one observation

The result set stores the immutable definition that produced the observation. Membership stays
keyed by the result-set ID. Evaluation time, completeness and the membership hash belong to this
same set. A re-evaluation reads the stored definition under current authority, creates a sibling
with its own ID and records its lineage. Readers can continue to address the original while it is
retained. A narrowing child's `parent_id` identifies the actual parent result set it used.

### D2 — Four general scope definition kinds, all immutable

| Kind | Definition payload | Evaluation cost | Natural mode |
|---|---|---|---|
| `expression` | A scope-DSL string (today's grammar: `ostype`, `hostname`, `arch`, `agent_version`, `tag:`, `props.`, `from_result_set:`, `EXISTS`, boolean operators). `__all__` is the expression scope `true`. | Cheap — in-memory registry + stores, no agent round-trip. | tracking |
| `narrowing` | `parent` (scope id), `query` (an instruction definition + parameters, an inventory query, or a TAR query — today's `instruction_result` / `tar_query` / `inventory_query` payloads), `matcher`. | A dispatch to the parent's evaluation, or a store read for inventory queries. | tracking, but a walk is an observation — see D6 |
| `explicit` | A device-id list supplied by the caller (today's `manual_curate`, `POST /result-sets`). | None — the evaluation *is* the definition. | frozen |
| `group` | A management-group id. | Cheap — `ManagementGroupStore` membership. | tracking |

`group` is new as a *scope kind*: it lets `from_result_set:<group-scope> AND props.site == "HK"` be
written, which `group:` as a whole-scope arm never allowed. It does not replace the `group:` arm
(the admission shape rule stands); it gives groups a place in the walk and lets ADR-1008's
"evaluate only at creation" defect be fixed in one place (D5 applies to `group` like any other kind).

A criteria run is a specialized narrowing observation carried by the `criteria_run` source kind.
Its payload records the immutable named inputs, combination, target and window (ADR-0075 R2–R3).
Its single-input producer entry points and its run entry point use a shared evaluator.

Resolve aliases once at definition time (#4306). Reject a definition that still references an alias.
Hash the stored definition as written, with its resolved IDs, to produce `definition_hash`.

### D3 — Record the quality of each observation

Alongside source payload and members, the result set records its server-authored `evaluated_at`,
evaluating principal, fleet generation where applicable, source execution for a walk, completeness
and its reason, reachable count at observation, and SHA-256 over the sorted IDs selected by the
observation. A final criteria run selects only its matched IDs. R7–R8 of ADR-0075 account
separately for the verdicts of every device in the admitted cohort.

A set is complete when the observation accounts for the selection at its evaluation time. Bounded
reads, timeouts, degraded storage and matcher failures must never produce an apparently complete
prefix (#5077, #4494, recovery WP07). The result-set lifecycle is `pending`, `materialized` or
`failed`. A materialized result can be incomplete. A failed read can fail materialization.
For live walks, ADR-1012 governs response completeness. A narrowing child inherits a materialized
parent's incompleteness even if all of the child's own responses are Full. D9 specifies which uses
of a materialized incomplete set are safe. ADR-0075 R14 gives a run with any `not_assessed`
device the same protection. R8 reports the run's lifecycle separately from its verdict counts.

The membership hash supports comparison. A frozen approval binds the definition hash, membership
hash and selected count together (D8). Recording reachable count separately preserves the
difference between selection and reachability before decay (recovery WP05/WP06).

### D4 — Two binding modes; `tracking` is the default, `frozen` is the exception

A consumer refers to a scope either as **`tracking`** — "the current membership of scope S; if it is
stale, evaluate it again before you use it" — or as **`frozen`** — "exactly the membership of result set S;
never re-evaluate; narrow only".

| Consumer | Default | May override to | Notes |
|---|---|---|---|
| Interactive dispatch (REST/MCP/dashboard) | tracking | frozen | A fresh interactive evaluation is what the operator just looked at. |
| Child scope's parent (a walk) | tracking | frozen | The child's evaluation records which parent evaluation it used either way. |
| Schedule | tracking | frozen | A frozen schedule is a repeat on a fixed cohort (a staged rollout); a tracking schedule reaches new enrolments. |
| Approval-gated dispatch | **frozen** | tracking + ceiling | D8. |
| `Destructive`-classified dispatch | **frozen only** | — | "You may only destroy what you have looked at." A tracking binding is refused at the shape check, like `__all__` is today (#3685). |
| Workflow step | tracking | frozen | A workflow may bind a step's scope to the *previous step's result scope* — the walk inside a workflow (D6). |
| Rerun | tracking | frozen | A rerun is a new evaluation of the same definition, dispatched (fixes #684). |
| Policy / Guardian continuous evaluation | tracking | — | Already continuous; `from_result_set:` stays refused (PR-E2) until D6 cost bounds are proven. |

`from_result_set:<id>` reads the identified snapshot. Tracking is an explicit policy of an
eligible consumer that evaluates the definition and obtains a new snapshot. A future tracking
form in the DSL can relax the `assignment.mode: static` rule once its binding and authorization
contract ships. A criteria-run reference resolves as specified in ADR-0075 R14. R12 reserves
criteria re-evaluation for the explicit operator action and refuses tracking consumers, schedules
and `allow_rewalk` pending the conduit design.

### D5 — Staleness is decided at use time from a fleet generation and an age budget

The server keeps one monotonic **fleet generation** counter (a Postgres sequence, shared across
replicas), bumped on every event that can change an `expression` or `group` evaluation: agent
registration and decommission, an `ostype`/`hostname`/`arch`/`agent_version` change on reconnect, a
change to a stored tag, custom property or management-group membership. An ordinary heartbeat,
metric sample, command response or reassertion of the same tag leaves the generation unchanged.
Inventory freshness and per-facet confirmation for criteria runs follow ADR-0075 R5–R6.

An evaluation is **stale** at use time when either:

1. `fleet_generation` has moved since `evaluated_at` (for `expression` and `group` kinds — the inputs
   are entirely server-side, so "moved" is exact), **or**
2. `now − evaluated_at` exceeds the consumer's **freshness budget** (`max_age`, default 1 hour for
   interactive use, mandatory and explicit on schedules and approvals, bounded `[1 min, 30 days]`).

For `narrowing` kinds the generation test applies to the *parent* chain (a parent that moved makes
the walk stale) and the age test applies to the observation itself — an observation cannot be known
stale without re-observing, so its freshness is a budget, never a fact. For `explicit` kinds only
decay applies.

A tracking consumer that finds its evaluation stale **re-evaluates before use** (cheap kinds inline;
a `narrowing` re-walk is itself an operator dispatch and goes through every dispatch gate — see D6).
A frozen consumer never re-evaluates; it reports decay (D7) and applies its cohort-integrity
condition (D8).

`POST /api/v1/scope/preview` and MCP `preview_scope_targets` return, for a scope reference, the
evaluation that *would* be used, its age, whether it is stale and why, its decay (`unreachable`,
`decommissioned`), and — for cheap kinds — its drift (`would_add`, `would_remove`) computed by a dry
re-evaluation. This is Tachyon's "approximate target" done honestly (recovery WP03).

### D6 — A walk is an observation; the matcher runs where the data is

For a general single-query walk the proposed dispatch path is as follows. ADR-0075 R3–R7
specifies the multi-input run and the stored-inventory path, including reads without a dispatch.

1. Evaluate the parent under the child's binding (tracking → the parent's current, possibly
   re-evaluated, snapshot; frozen → the identified result set). Record its ID as the child's parent.
2. Dispatch the query to that parent evaluation as a frozen binding to the parent result-set ID —
   an ordinary operator dispatch: `dispatch_confined_arms`, the destructive gate (a narrowing query
   must be `ReadOnly`; an `AdminOrApproval` or `Destructive` pair is refused as a narrowing query —
   the Tachyon lesson, stated as a rule), the per-device concurrency claim (ADR-1007), the body cap.
   **When the matcher is agent-evaluable, it travels with the dispatch as a precondition** and each
   agent replies `matched` (with the payload, if the definition asks for it) or `not_matched`
   (no payload). When it is not — inventory and TAR queries, or a matcher over server-side data —
   the full responses come back and the server matches. The evaluation records `matcher_site`.
3. Gather until `agents_responded >= agents_targeted` or the gather deadline (today's 300 s pending
   timeout becomes the evaluation's `gather_deadline`, bounded `[30 s, 24 h]`, default 300 s). A
   `not_matched` reply **is an answer** for completeness.
4. Members = matched responders, from a **complete, bounded** read of the execution's responses
   (never a default-limited page). `complete` only if every targeted agent answered and the read was
   not truncated; else `incomplete` + reason.

**The matcher.** Extend `result_set_matcher` with row quantifiers, typed comparisons and named
input combinations under ADR-0075 R4. Use K3 internally and fold once at the boundary. For a
query with declared output columns, validate referenced columns at definition time. A later
agent-site implementation must give the same answer as the server on the same evidence and
coverage. Share pure decision code under `common/include/` when both sites need it (#2549).
Keep evaluation bounded and preserve typed unknowns when a row or its coverage is insufficient.

**A re-walk is one dispatch, not *d*.** Re-walking a chain of depth *d* ships the whole chain as an
ordered precondition list `[(Q₂, M₂), (Q₃, M₃), …]` in a single dispatch to the root
`expression`/`group` scope's fresh evaluation. Each agent runs the preconditions in order and
short-circuits on the first `not_matched`, replying `matched_through: k` (the deepest index it
passed). The server mints **one result set per level** from that one dispatch — level *i*'s members
are the agents with `matched_through ≥ i` — each with its own `parent_id`, so lineage
and completeness (sticky, D3) are recorded exactly as if the chain had been walked step by step.
This is Tachyon's agent-side chaining and Tanium's client-side filter, kept — and unlike either,
every level is stored. A chain containing a server-site matcher falls back to the step-by-step
walk from that level down.

Cost rules for general single-query walks:

- A re-walk is never implicit on a resolve. It happens only when a *consumer* uses a tracking
  binding whose evaluation is stale, and the consumer's request carries `allow_rewalk: true`
  (default `false` for REST/MCP, `true` for schedules — a schedule has declared its budget). Without
  it, a stale tracking binding **refuses** with a typed `SCOPE_STALE` error naming the evaluation,
  its age and the generation delta, so the caller can preview, re-walk explicitly, or bind frozen.
- Chain depth on the wire is bounded by `kLineageDepthCap` (10, existing). The preview reports the
  root evaluation's size. Criteria runs use only explicit sibling re-evaluation (ADR-0075 R12).

### D6b — Guarded execution: the cohort is frozen, the condition is fresh

A dispatch bound to a `narrowing` scope may carry `guard: preconditions`. The agent re-runs the
scope's precondition chain **immediately before** executing the action and, if the chain no longer
holds, withholds itself and replies `withheld: precondition_failed` — counted in D7, audited, never
silent. A guard **only narrows**, so an approval bound to the frozen evaluation's `members_hash`
still verifies (D8); the approver approved *who*, the guard enforces *what is still true*.

This is how the brief's two needs coexist: "kill Chrome on the 63 boxes I looked at" is approved on
the frozen cohort and executed the next morning only on the boxes still running Chrome. It is
Tachyon's "re-check the condition, not the responders" and Tanium's client-side re-evaluation of
targeting criteria at action time, applied to a stored cohort rather than instead of one.

Defaults: `guard: preconditions` is **on** for any `Destructive` or `AdminOrApproval` dispatch bound
to a `narrowing` scope and for every tracking schedule over one; `guard: none` is an explicit,
audited choice. A guard on an `expression`, `group` or `explicit` scope is a no-op (nothing to
re-observe). A guarded chain is bounded by the same depth cap and runs under the action's own
timeout budget; a precondition that cannot be evaluated (plugin absent, query error) withholds with
`precondition_unevaluable`, never falls open.

### D7 — Every dispatch binds to an evaluation and records what it reached

`Execution` records the selected result-set ID and binding mode, and the **reached set** is recorded
at dispatch as `agent_exec_status` rows in state `targeted` (today rows appear only on response), plus
counts: `selected` (evaluation members), `reachable` (connected), `authorized` (∩ caller's current
authority), `withheld` (per-OS kill switch, quarantine, plugin absent — the existing
`ConfinedDispatchOutcome` causes — plus `precondition_failed` / `precondition_unevaluable` (D6b) and
`cooling` (D14), each a distinct, countable cause), `unreached` (member not connected at dispatch). Decay of a frozen
binding is therefore observable per execution and the design's §4.3 "silently dropped" becomes
"recorded and reported, never silent" (recovery WP06).

`__all__` and `group:` dispatches record an evaluation too — a synthetic `expression`/`group`
evaluation minted at dispatch — so the executions ladder has one answer to "what did this reach"
regardless of arm.

### D8 — Durable and deferred dispatch obeys one rule: freeze-and-narrow, or track-with-a-ceiling

This implements ADR-0033 §10 for the surfaces that exist today and resolves the §4/§10 tension the
same way §10 does:

- **Approval binds to `(definition_hash, members_hash, device_count)`** of a frozen evaluation.
  These three values are the **target component of ADR-1011 D4's operation digest** — supplied by the
  scope store to the one canonical digest builder, never hashed a second way (§11.1). Execution
  narrows that evaluation by current authority and connectivity; a device may drop out, never in. A plan declares a **cohort-integrity condition** (`none` | `all_or_nothing` |
  `min_quorum: N` | `min_fraction: f`); a narrowed reached set failing it **parks** the execution
  (`SCOPE_COHORT_BROKEN`, audited) instead of running an unsafe subset.
- **An approval may instead bind a tracking scope with a ceiling** `(definition_hash, max_devices,
  max_age)`: "approve this hygiene action for whatever `ostype == windows` evaluates to at fire time,
  up to 3,000 devices, evaluated no more than 1 h before dispatch". Exceeding the ceiling parks the
  execution for re-approval. A ceiling approval is never valid for a `Destructive` pair (D4). The
  ceiling triple is the target component of the digest for a tracking binding (values on ADR-1013 D4's
  tracking form, held behind the ADR-1014 D3 ruling, 11.1); because
  `definition_hash` is stable across re-evaluations, ADR-1011 D5's "recompute the digest at every
  dispatch and hold on mismatch" holds a schedule when its *definition* changes and lets it run when
  only the *fleet* changed — which is exactly the distinction a tracking schedule needs and a
  selector-string digest could not make.
- **Schedules store a scope id + binding + freshness budget**, never a raw string. A tracking
  schedule re-evaluates at fire (today's behaviour, now explicit and ceiling-bounded); a frozen
  schedule repeats the same evaluation. General scope retention follows D10. Criteria runs have their own retention and refuse tracking schedules.
- **Reruns** mint a new tracking evaluation of the original execution's scope definition and
  dispatch it — unless the original was frozen, in which case the rerun offers both ("same cohort" vs
  "current membership") and refuses to guess.
- `/auto` deploy's frozen go-cohort and re-authorisation every tick is already this rule; it
  becomes a frozen binding to the pre-flight run's evaluation rather than its own targeting mechanism. An approval or conduit arm over a criteria run must retain its own evidence under D10.
- **The preview is the dispatch.** A dispatch may cite `preview_result_set_id`; the server refuses
  with `SCOPE_PREVIEW_MISMATCH` if that evaluation's `definition_hash` is not the one being
  dispatched, or — for a frozen binding — if the result-set IDs differ. Citing it is **mandatory**
  above `targetEstimationRequiredAbove` (existing definition field) and for every approval: the
  approver sees an evaluation (count, age, decay, drift), never a string, and that evaluation is the
  one bound. This closes the Tanium Interact class of defect where the filter the operator saw in
  the results grid was silently not applied to the action.

### D9 — Unusable evaluations fail closed, typed, and never match the fleet

ADR-0036 B2 and the scope-walking readiness contract govern resolution. Require ownership and
availability before inspecting status. A missing, foreign, expired, pending or failed reference
must never behave like a successful empty set. Preserve typed failures, owner-oracle safety and
the targeting audit. A pending reference can be retried; failure is permanent. A materialized
incomplete set may contribute to a positive reference, but any use under `NOT`, `LEN` or
`STARTSWITH` aborts permanently with `result_set_unusable`. In particular, no opt-in can turn
an incomplete inverted reference into the rest of the fleet. ADR-0075 R14 applies these rules
to the matched members from the first release that can create a run.

### D10 — Retain snapshot evidence for its consumer

General scope snapshots have the proposed reference-aware lifetime: retain a referenced snapshot
for its child, schedule, approval or retained execution. Sweep unreferenced, unpinned general
sets under clock-guarded GC and the applicable TTL. For general scope snapshots, retain the most recent complete observation and up to ten recent
observations per definition by default, plus referenced observations. The original defaults are a
one-hour idle TTL, 10,000 sets per owner and lineage depth ten. Bound membership per kind. Preserve a retained child's evidence when its parent becomes unavailable and fail closed if
a replay would require that parent. R10 of ADR-0075 specifies fleet-scale membership caps for
the affected store paths.

Criteria runs follow ADR-0075 R11 and R14. Set TTL from creation to deadline plus the warm setting,
then from finalization; use warm-only retention during the documented pre-export interval. After
cold export ships, reap warm rows only after expiry and confirmed export, and retain cold records
for 90 days. The default warm interval is 20 minutes after final. A later approval or conduit over matched devices copies the matched
list into its own durable evidence when binding. Refuse if that list is no longer available. A
hash alone cannot authorize an action. No external reference or pin extends a criteria run's TTL.

### D11 — Authority is read live; a stored set only narrows

Unchanged from ADR-0032/0033 and restated because a stored membership invites the mistake: an
evaluation stores the raw member set as the evaluator saw it. **Every** read (`members`, lineage,
preview) and every dispatch intersects it with the caller's *current* authority
(`authorize_list_read` / `dispatch_confined_arms`). Service-scoped tokens remain denied on the
producers (#4980). Sharing between operators (design §12) is still deferred; when it lands it is a
grant on the *scope*, and the recipient's reads still narrow by their own authority.

For criteria runs require the target to pass every input's device gate at creation. A device hidden
for even one input contributes only to the permitted excluded count. Later loss of input-specific
visibility for an already admitted device withholds that input as `withheld:<securable>` at
delivery. The original cohort stays fixed. ADR-0075 R9 supplies creator ownership, durable
authority and the distinct handling of token expiry or revocation.

### D12 — Instruction definitions declare a starting scope; the operator narrows it

`spec.scope` on an `InstructionDefinition` is today validated and ignored at dispatch. It becomes the
definition's **starting scope**: an `expression` scope the dispatch's operator-supplied scope is
intersected with (`AND`), never widened past. A definition with no `spec.scope` starts from `true`.
This is Tachyon's "compulsory scope … from Principal permissions" generalised to the instruction, and
it gives the brief's step 1 a home: the "Chrome running?" definition can declare
`spec.scope: ostype == "windows"` and no caller can point it at a Mac.

Targeting is therefore three tiers, each only narrowing the one above — Tanium's action-group /
targeting-criteria / preview shape with authority as the outermost tier: **caller's authority** (D11,
read live) ∩ **definition's starting scope** (this decision) ∩ **operator's scope** (the binding,
previewed per D8).

### D13 — Scope is a first-class value in the DSL

Today the YAML DSL has no scope primitive: a scope is a string in the scope-engine grammar, the
Policy `spec.scope` block is sugar that lowers to that string, `fromResultSet:` takes an alias that
re-binds newest-wins, and nothing can pass a scope between workflow steps or compare two. This
decision gives the DSL the objects the rest of this ADR stores.

**`kind: Scope`.** A declarable, importable object:

```yaml
kind: Scope
id: scope.payments.windows-fleet
spec:
  definition:            # exactly one of
    expression: 'ostype == "windows"'
    # narrowing: { parent: <scope id>, query: <definition id>, with: {…}, matcher: 'ANY row WHERE name == "chrome.exe"' }
    # explicit:  { agentIds: [...] }
    # group:     <management group id>
  binding: tracking      # tracking | frozen (freeze pins the selected snapshot identity at use)
  maxAge: 1h             # freshness budget for tracking use (D5); mandatory on schedules
```

The DSL id names the declared definition. Each observation has its own result-set ID (D1). An alias is a presentation label on the scope and is **never
resolved at dispatch**; `fromResultSet: <alias>` is retired in favour of `scope: <id>` once rung 11
lands (the alias charset rule and newest-wins resolution go with it).

**`scope` parameter type.** Added to the parameter type system (DSL spec §10) beside `string`,
`integer`, `boolean`, `enum`. A parameter of type `scope` accepts a declared scope reference or a frozen result-set ID and is validated as a reference the dispatching operator can read — never as
free text interpolated into a scope string. `InstructionDefinition.spec.scope` becomes either an
inline `definition:` or a `scope` reference, and is live per D12.

**Formation, never mutation.** Definitions are immutable (D2); the DSL forms new ones:

| Form | Produces | Notes |
|---|---|---|
| `narrow(parent, query, matcher)` | a `narrowing` definition | the walk (D6) |
| `and(a, b)` / `not(a) within parent` | an `expression` definition | `not` is always relative to a parent so it can never widen past it (D9) |
| `freeze(scope)` | a frozen binding to the scope's current evaluation | records the concrete result-set ID |
| workflow step `scope: { from: steps.<n>.matched }` | a `narrowing` whose parent is the previous step's scope and whose query is that step | the walk inside a workflow (D4's workflow row) |

**Comparison.** Three rules, each stated as to what it is decided on, and nothing else:

| Rule | Decided on | True when |
|---|---|---|
| `same_definition(a, b)` | `definition_hash` | hashes equal |
| `same_members(snapshot_a, snapshot_b)` | `members_hash` | hashes equal (the ids say *when*) |
| `narrower_than(a, b)` | structure, else members | structurally: `a` is `b` with extra `AND` conjuncts, or `a` is a `narrowing` child of `b`, or `a` is a frozen evaluation of `b`; otherwise on the two current evaluations' member sets; otherwise **`incomparable`**, returned as such, never guessed |

`narrower_than` is what D8 ("narrow only"), D12 ("never widened past") and D6b (a guard only
narrows) are all instances of; this decision names it once so the three sites share one function.

### D14 — Cooling: a device that just ran a remediation is not re-selected for it

An `InstructionDefinition` may declare `spec.cooling: <duration>` (bounded `[1 h, 24 h]`, default
none). After a device completes an execution of that definition, a **tracking** re-dispatch of the
same definition — a schedule, a policy remediation, a workflow loop, a re-walk-and-act — withholds
that device with `withheld: cooling` until the window elapses, counted in D7 and audited. An
interactive explicit dispatch may pass `ignore_cooling: true`, which is audited; a frozen
approval-bound dispatch is unaffected (the approver bound a cohort and the window is reported in
the preview's decay, not enforced against their decision).

This is Aternity's cooling window, generalised from "this remediation script" to "this definition":
a fix that did not take must not be re-applied on every tick, and the operator should see
`withheld: cooling` rather than a device that silently keeps appearing in the reached set. It is
distinct from ADR-1007's concurrency claim (in flight) and from D5's freshness (the scope); it is a
property of the *(device, definition)* pair's recent history, read from the executions ladder.

### D15 — The scope object contract: what it holds and what it answers

Each stored scope snapshot has a stable identity, immutable provenance and one observation.
This decision names its data and its methods once, so that the REST surface
(`/api/v1/scopes/{id}…`), its MCP twins (ADR-1005: every method has both, A4 envelope, A5
annotations) and the DSL forms (D13) are three views of one contract. Nothing here decides anything
D1–D14 did not; it fixes the shape in which those decisions are returned.

**Data — the scope (definition) record**

| Field | Type | Notes |
|---|---|---|
| `id` | `rs_<ulid>` | Stable for this snapshot. A re-run creates a sibling (D1). |
| `kind` | `expression` \| `narrowing` \| `explicit` \| `group` | D2. |
| `definition` | kind-specific | Expression string; or `{parent, query, with, matcher, matcher_site}`; or `{agent_ids}`; or `{group_id}`. Aliases resolved to ids at write time. |
| `definition_hash` | sha256 | Over the canonical definition. Part of the frozen approval binding and the key for `same_definition`. |
| `name`, `description` | string | Presentation only; never resolved at dispatch (D13). |
| `owner_principal` | string | Reads and dispatches narrow by the *caller's* current authority, never by this (D11). |
| `starting_scope` | scope id \| null | Set when formed from a definition's `spec.scope` (D12). |
| `parent_id` | scope id \| null | Lineage edge to the parent snapshot used (D1). |
| `depth` | int | Chain depth, `≤ kLineageDepthCap`. |
| `created_at`, `last_used_at` | timestamptz | Server clock, authored in SQL. |
| `pinned` | bool | Retention (D10). |
| `references` | counts by binder | Children, schedules, approvals, executions inside audit retention (D10). The object knows why it is alive. |
| `cooling` | duration \| null | Present when formed from a definition carrying `spec.cooling` (D14). |

**Data — evaluation metadata on that same result set** (D3)

| Field | Notes |
|---|---|
| `id`, `evaluated_at`, `evaluated_by` | Identity and audit. |
| `fleet_generation` | Staleness input (D5). |
| `parent_id`, `source_execution_id` | Lineage at an instant; which dispatch produced it. |
| `status`, completeness, `completeness_reason` | Store lifecycle plus the quality of the observed membership (D3). |
| `device_count`, `reachable_count`, `members_hash` | Observation counts and the selected-members digest for D8. |
| `matcher_site`, `matched_through_histogram` | Agent or server; for a one-dispatch re-walk, how many agents passed each level (D6). |
| `responses` | `{targeted, answered, matched, not_matched, partial, unknown}` summary. |

Members are **never inline** on the snapshot: they are a paged, authority-narrowed read.

**Methods — what the object answers.** Each is one REST route and one MCP tool twin.

*Inspect*

| Method | Returns |
|---|---|
| `describe()` | The scope record plus the snapshot’s evaluation summary. |
| `members(page)` | Member ids ∩ caller's current authority. Never the raw set. |
| `lineage()` | The parent chain and, per level, the evaluation used. |
| `history(limit)` | Retained related snapshots, newest first, under live authorization. |
| `references()` | Who holds it: schedules, approvals, children, executions. |

*Freshness* (D5)

| Method | Returns |
|---|---|
| `preview(binding?, max_age?)` | The evaluation that *would* be used; its age and generation delta; `stale` with reason; decay (`unreachable`, `decommissioned`, `cooling`); for cheap kinds drift (`would_add`, `would_remove`); for a narrowing scope the re-walk cost (root evaluation size). |
| `evaluate(allow_rewalk)` | A sibling result set carrying a fresh evaluation. The explicit act a `SCOPE_STALE` error points the caller to. |
| `freeze()` | A frozen binding to the identified result set, with its definition hash, selected membership hash and count. |

*Form* (D13). Every form returns a **new** scope; none mutates the receiver.

| Method | Produces | Refused when |
|---|---|---|
| `narrow(query, with, matcher)` | `narrowing` child | query pair is not `ReadOnly`; matcher names an undeclared column; depth would exceed the cap |
| `and(expression)` | `expression` child, conjunct appended | receiver is not `expression`/`group` |
| `not(expression)` | `expression` child, negation **relative to the receiver** | never widens; a `NOT` with no receiver is not a form |
| `explicit(agent_ids)` | `explicit` child | any id ∉ receiver's current evaluation |

*Compare* (D13)

| Method | Returns |
|---|---|
| `same_definition(other)` | bool, on `definition_hash`. |
| `same_members(other_snapshot)` | bool, on `members_hash`. |
| `narrower_than(other)` | `true` \| `false` \| `incomparable`, with `decided_on: structure \| members`. |
| `diff(snapshot_a, snapshot_b)` | `{added, removed, counts}` — drift over time (open question 6). |

*Use* (D4, D7, D8)

| Method | Returns |
|---|---|
| `bind(mode, max_age?, max_devices?)` | A binding `{result_set_id, definition_hash, mode, members_hash?, device_count?, max_devices?, max_age?}`. Its values are the target component of the ADR-1011 digest, serialised by ADR-1013's builder as the `evaluation` form with `definition_hash` carried as `scope_definition_hash` (§11.1), so an approval, a schedule and a dispatch all consume the same object. |
| `executions(limit)` | Executions that bound this scope, each with its reached-set counts (D7). |

*Lifecycle.* General scopes expose `pin()`, `unpin()` and `rename()`. These change retention or
presentation metadata. The definition and completed evaluation remain immutable. D10 governs the
fixed lifetime of criteria runs.

**Three rules the object enforces, so no caller can get them wrong**

1. Every read of members or counts narrows by the caller's current authority. The object never
   returns a raw set; a caller with no visibility gets `device_count: 0, authorized: 0`, not an
   error that leaks the real size.
2. A binding follows D9 readiness and incomplete-set rules, including matched-only consumption for a criteria run (ADR-0075 R14).
3. A form refuses when its result would be wider than the receiver. `not` and `explicit` are the
   two that could; both are defined relative to the receiver for that reason.

The criteria-run producer shares the evaluator and uses the create and re-evaluation surfaces of ADR-0075 R3/R12. A mixed-input run refuses automatic walking.

**Async.** `evaluate()` and `narrow()` on a `narrowing` scope return a pending result set
immediately and the caller polls `history()`/`describe()` or subscribes on `/api/v1/events`; the
gather deadline (D6) bounds how long `pending` can last. Cheap kinds evaluate inline. This follows
today's async producers and the A4 envelope already carries `retry_after_ms` for it (A5).

## The brief, traced

A scope may be reused as long as its consumer's binding permits. In the proposed general walk, a Windows
expression selects 2,800 devices. A read-only process query reaches 2,740 and records a child result set
of Chrome matches. If nine reached devices fail to answer, the walk records incomplete coverage. A
positive child may narrow those matches again. Missing responses never establish that a device has no
matching process. If an authorized operator explicitly repeats a supported walk, the new snapshots
preserve their own lineage and the previous observations keep their IDs. A tracking schedule and a
guarded action are later consumers of these snapshots.

Three examples pin the boundary for criteria runs under ADR-0075.

1. A stored-inventory run admits four devices. Two have recent confirmed software matches, one has a
   complete inventory without a match, and the fourth has never reported inventory. Heartbeats from the
   fourth device leave it in the cohort. At the deadline the run is final with two matched, one not
   matched and one not assessed. The matched-only atom selects two. Negation aborts because the fourth
   device could have matched.
2. The creator re-runs the saved specification after losing visibility over one device. The new result
   set is a sibling with a fresh window and the creator's live grants. It reports the newly excluded
   device only in the excluded count. The earlier snapshot keeps its observations and timestamps. For
   mixed-input runs a device hidden by any input gate at creation is excluded. Loss of one input's
   visibility after admission withholds that input, preserves the admitted device and prevents that
   delivery (ADR-0075 R9).
3. In the future act phase an approver freezes 63 matched IDs, their definition hash, membership hash
   and count. Five disconnect before execution. Of 58 reachable and authorized devices three fail their
   execution-time guard. The audit records 63 selected, 58 reachable, 58 authorized, three withheld, 55
   executed and five unreached. The approval retains the reviewed list independently of the run's
   lifetime. The target component remains verifiable. Approval of a re-run under ADR-0075 R12 authorizes
   a fresh observation and binds the inputs under that contract.

## Consequences

**Positive**

- One rule for every surface that re-uses a scope (manual, schedule, approval, workflow, rerun,
  `/auto`), and it is the rule ADR-0033 already states — this ADR is its first implementation.
- "Has this scope grown stale?" has a cheap, exact answer for attribute scopes and an honest,
  budgeted answer for observations. The answer is on the preview, the execution and the audit row.
- Approval binds to a membership hash; an auditor can prove what was approved was what ran, or see
  exactly how it narrowed. Tachyon cannot say this.
- Destructive actions can only target a cohort somebody has looked at — and, with the guard on,
  only the members of it on which the condition still holds.
- A supported general re-walk of any depth is one dispatch to the root scope; the matched-only reply keeps a walk's
  response volume proportional to the answer, not the fleet (ADR-1010).
- The 100-member truncation, the pending-resolves-empty fail-open, the unreachable `failed` status,
  the expired-set-still-valid gap and the missing target record are all closed by construction, not
  by individual patches.
- The DSL can name, pass, form and compare a scope (D13); a workflow can walk.

**Negative / costs**

- The new metadata changes a busy store under the ADR-0012 migration contract. Backfill from provable
  creation, readiness and completeness evidence. Keep missing historical evidence explicit. An unknown
  generation or unreadable historical membership cannot certify freshness or produce a trustworthy
  approval hash.
- General tracking of an observation chain can require a dispatch to its root. Preview exposes snapshot
  ID, age, budget and generation delta before an eligible operator opts into a re-walk. ADR-0075 runs
  use explicit whole-run re-evaluation and a new window.

- A wire change: the dispatched command gains a bounded `preconditions` list and the reply gains
  `matched_through` / `withheld` reasons. The matcher evaluator is a new pure-decision file under
  `common/include/` and must stay I/O-free (#2549); its grammar is deliberately column-level only.
- Guards and cooling add two new `withheld` causes to every zero-reach cascade site (the *Dispatch
  zero-reach cause discrimination* routed concern: five sites, grep every one).
- The fleet generation counter is a shared hot sequence; it is bumped on roster/tag/prop writes
  only, which are rare relative to heartbeats, but a tag-storm (a bulk re-tag) makes every
  expression scope stale at once — correct, and cheap to recover because expression evaluation is
  in-memory.
- Policy `fromResultSet` stays deferred; continuous evaluation over a tracking narrowing scope
  would re-walk on every tick.

## Alternatives considered

1. **Tachyon's model — never store a scope; follow-ups re-ask the parent's whole coverage with
   agent-side gating.** Always-fresh and needs no staleness bookkeeping, but it cannot freeze a cohort
   for approval, cannot answer "what did this reach" without a live denominator, and forbids actions
   as parents. Rejected as the *storage* model; its agent-side chaining is **adopted** as the
   evaluation mechanism (D6, D6b) with every level stored.
1a. **Tanium's drill-down as the walk.** Narrows from the responders, which is right, but the
   narrowed set lives only in the console session: no id, no hash, no lineage, and acting on it is
   capped at 100 rows. Rejected; D1/D3 are what it lacks.
1b. **CrowdStrike's explicit-list-only actions.** Every action is a `host_ids` list, so every action
   is frozen by construction and the scope work is pushed out to whatever built the list. Kept as the
   `explicit` kind, rejected as the only kind: it cannot express a tracking schedule or an approval
   ceiling.
2. **One mutable identity for every observation of a definition.** Replacing sibling result sets with a
   second evaluation namespace would change existing producer, consumer and lineage contracts. Keep
   sibling IDs and attach completeness, evaluation time and membership hash to each snapshot. Tracking
   consumers carry a definition and budget; frozen consumers retain the reviewed snapshot.

3. **Lazy `?live=true` on resolve (design §5).** Re-evaluating on every resolve hides the cost and
   makes an action's target shift mid-chain. Rejected in favour of explicit `allow_rewalk` and a
   budget.
4. **Version every input (per-member timestamps, per-store generations).** Exact drift for free, but
   it couples every store to the scope engine and the agent-observed kinds cannot be versioned
   anyway. One fleet generation plus an age budget gives the exact answer where exactness is
   possible and an honest budget where it is not.
5. **Always frozen.** Safe for approvals, wrong for every schedule and every "all Windows" scope
   written once and used for a year. Rejected; this is the design's current stance and the brief's
   "more frequent case is updated" is the correction.
6. **Always tracking.** Makes approval meaningless (it is Tachyon's known issue) and makes
   `Destructive` unsafe. Rejected.

## Relationship to other ADRs and docs

- **ADR-0033 §10** — defines the intended binding for existing surfaces; an *evaluation* is the Execution Plan's frozen
  target set, `members_hash` is the part of the plan hash that covers targets. §4's "re-resolves its
  scope at execution" is amended to "re-evaluates a *tracking* binding within its ceiling; a *frozen*
  binding narrows only".
- **ADR-0032** — "every filter reads live except the ceiling; a frozen snapshot may only narrow"
  (D11); the release log's insistence on storing exact `agent_id` sets is the same decision as D7.
- **ADR-0036** — the store stays Postgres-authoritative with typed targeting reads; D9 extends the
  typed-error set; the schema change is a new migration under the ADR-0012 contract.
- **ADR-1005** — scope walking stays core mechanism (its §"Core mechanism" list); the temporary
  `/api/scope/estimate` exception is superseded by the D5 preview on `/api/v1/scope/preview`.
- **ADR-1007** — per-device concurrency claims attach to the *reached set* (D7), which is now
  recorded, so a claim can be audited against the evaluation it was taken on. Cooling (D14) is the
  "recently completed" complement to its "in flight" claim and is read from the same ladder.
- **`common/include/` firewall (#2549)** — the shared matcher evaluator is a new file in that root.
  It is pure decision code (no I/O, no store or wire types) and therefore needs no CLAUDE.md
  exception; the implementing PR states that in its header banner.
- **`docs/yaml-dsl-spec.md`** — D13 adds `kind: Scope` (new §), the `scope` parameter type (§10),
  the row-matcher grammar (§9.1), and retires §9.3's alias resolution and its static-mode rule.
- **ADR-1008** — the `group` scope kind and D5's generation bump on group-membership writes close its
  UP-5 ("evaluate only at creation"). ADR-1008 is `proposed`; if it changes group evaluation
  semantics, D2's `group` row follows it.
- **`docs/scope-walking-design.md`** — §5 and §6 supply sibling re-eval and lineage. The general scope
  changes address incomplete references and revisit the
  `fromResultSet ⇒ assignment.mode: static` rule when the group and binding contracts land. Existing
authorization and audit apply to every producer.
- **`docs/plans/instruction-recovery-plan-2026-10-15.html`** — WP03 (preview counts), WP05/06
  (selected/reachable/authorized/withheld/unreached), WP07 (complete bounded read), WP08
  (evaluation → source execution), WP11 (one rule across surfaces), WP14 (re-evaluate truncated
  sets while preserving pinned evidence — evaluations are immutable, so a pinned evaluation is never
  rewritten; a re-walk adds one) are each a direct consequence of a decision above.

## §11 — Reconciliation with ADR-1010 / 1011 / 1012

What Dave's three ADRs decide, in one line each: **1010** — every catalogue row carries a
compile-authored `impact` (Light/Heavy) and `response_bytes` ceiling, and a finite ceiling is only
allowed where something enforces it. **1011** — a *heavy* row dispatched *fleet-wide* needs an
approval through the core-owned approval primitive, bound to a digest of the reviewed operation; schedules
and policies take that approval once at arm and revalidate the digest at every fire; audit-only
first. **1012** — a response says on the wire whether it is Full, Partial or Unknown; absence reads as
Unknown, degradation is sticky, and consumers (result sets first among them) must never read a
partial result as complete.

None of the three stores a scope or models its freshness; this ADR stores none of the cost or
completeness facts. They meet at three seams, and at each the rule is *one mechanism, two owners*.

### 11.1 One digest — the scope store supplies the target component

ADR-1011 D4 binds an approval to a SHA-256 over a canonical JSON of `(plugin, action, normalized
parameters, target selectors, definition content hash, fragment hash, effective declarations)`, built
by **one shared builder**. "Target selectors" is underspecified there (it is the selector *string* in
the precedent it cites), and a string digest cannot distinguish "the fleet changed" from "the target
changed", nor bind an approval to a device set as ADR-0033 §10 requires.

**Decision:** the target component of the ADR-1011 digest is defined by this ADR and supplied by the
scope store as **values in the typed, form-tagged struct of ADR-1013 D4**; the one builder serialises
it. The scope store never hands over a pre-canonicalised blob (a blob would move the digest's
concatenation-ambiguity risk into a second component's code, ADR-1013 D4), and the builder never
re-derives a digest from the scope string. The field names on the wire are ADR-1013's. A frozen
binding uses the typed frozen target component in the digest builder. Supply the immutable result-set
ID, scope definition hash, sorted membership hash and count. Reconcile ADR-1013 D4's field names with
its owner before freezing the wire contract. Any evaluation identity required by that builder denotes
this same snapshot. A tracking binding is one of D4's tracking forms (`all`, `group`, `groups`,
`scope`). Its definition hash and ceilings belong in the arm's reviewed preimage. ADR-1014's conduit
ruling gates those forms. The approval store copies the reviewed list when a ticket binds a run's
matched set (ADR-0075 R14). Capture the resolved snapshot for a dispatch using `__all__` or `group:` so
its eventual reach is explainable.

A raw `(plugin, action)` dispatch with an explicit id list is D4's `explicit` form. ADR-1011's
"approver sees the preimage" then shows the evaluation (count, age, decay) rather than a string —
recovery WP03 for the approver; per ADR-1013 D4 the member hash is over the unconfined set and a
confined approver sees only their own intersection count.

### 11.2 One completeness vocabulary — ADR-1012's, consumed at the evaluation

ADR-1012 D1 is the wire fact; D3 of this ADR is where that fact becomes a property of a *set*. The
snapshot records completeness separately from readiness. An incomplete parent propagates to a narrowing
child. A Full response can establish a negative match; missing, Partial or Unknown observations cannot
prove absence. Withheld delivery records its cause. For an ADR-0075 run, the final set exposes matched
devices to a positive reference. A `not_assessed` member makes inversion and other R14 unsafe operators
fail closed even if the general consumer can accept an incomplete positive target. Destructive targeting
has its own binding and gate.

ADR-1012's own list of things "fixed
separately because wire metadata does not repair them" — the 100-row default query, timeout
materialisation, single-chunk selection — is rung 1 of this ADR's ladder. The ADR-1010 evidence
consumer audit (`docs/adr/1010-evidence/consumer-audit.md`, not yet in the tree) is the checklist
for which readers of an evaluation must change before any agent-side lever is enabled for data that
feeds a walk.

### 11.3 One "fleet-wide" test — form before resolution, count after

ADR-1011 D1 classifies a dispatch as fleet-wide **by target form, before resolution** — scope
expression, `__all__`, `from_result_set:`, broadcast, or an explicit list above
`kHeavyFleetTargetThreshold` — deliberately, because "the scope, group and `__all__` forms have an
unknown count at decision time" and the form must be read "BEFORE batching, claim or narrowing can
erase it". This ADR does not change that: D7's evaluation is produced *by* resolution and arrives too
late for a pre-resolution guard, and a guard that waited for it would be the design ADR-1011 rejects.

Two refinements are offered, both strictly narrowing ADR-1011's conservative default, neither
required by it: (a) a **frozen** binding (an immutable result-set ID) has an exact `device_count` at decision
time with no resolution, so the form test may treat it like an explicit list and compare the count to
the threshold; (b) ADR-1011's audit row ("target form and count") should carry the snapshot ID once
D7 lands, so the audit-only release measures heaviness against real reached sets rather than forms.
ADR-1011 treating `from_result_set:` as unconditionally fleet-wide until (a) is adopted is correct
and loses nothing.

### 11.4 Where the ladders interlock

- Rung 0 and rung 1 of this ADR (fail closed on unusable evaluations; complete bounded read) precede
  ADR-1012 follow-up 3 ("consumers, in the order the audit ranks them") for the result-set reader.
- Rung 6 (approvals bind to the evaluation) ships **with** ADR-1011 follow-up 2 (the digest in the
  approval primitive) — one slice, one builder.
- Rung 5 (schedules store a scope id + binding + budget) ships **with** ADR-1011 follow-up 3
  (arm-time snapshot digests on schedules and the outbox) — the outbox binds the scope definition, snapshot ID and digest together.
- ADR-1011's `kHeavyFleetTargetThreshold` and this ADR's ceiling defaults are reviewed by `sre`
  against the same audit-only data.
- Rung 8 (agent-site matcher, matched-only replies) is the first lever that makes a walk's
  `response_bytes` (ADR-1010) proportional to the matched set rather than the targeted set. The
  catalogue row's `impact` classification is unchanged by it — the precondition-bearing dispatch is
  still a fleet-wide dispatch of a heavy query under ADR-1011 D1 — but the audit-only data will show
  the difference, and ADR-1010's "a finite ceiling is only allowed where something enforces it" is
  satisfied for walks by the evaluator, not by a declaration.

### 11.5 Conflicts, and which yields

| Point | ADR-1011/1012 | This ADR | Resolution |
|---|---|---|---|
| Approval binds to a selector string vs a device set | digest over "target selectors" | `members_hash` / `definition_hash` + ceiling | 1011's builder, this ADR's target component (11.1). ADR-0033 §10 requires the set; a string cannot satisfy it. |
| `from_result_set:` is fleet-wide | unconditionally, by form | frozen binding has an exact count | 1011 stands; refinement (a) is optional. |
| Incomplete set usable? | preserve explicit response completeness | incomplete positive references can narrow; inversion could widen | Apply D9 and ADR-0075 R14 when consuming a result set, and enforce the destructive dispatch gate independently. |
| Schedule revalidation | digest mismatch holds | fleet change must *not* hold a tracking schedule | Compatible once the target component carries `scope_definition_hash` (11.1); a selector-string digest would also be compatible but could not express the ceiling. |

## Migration ladder

The general scope migration preserves the following review units. ADR-0075 lists the criteria-run slices
and their own dependencies. Shipped safeguards below refer to DevNullLtd/Yuzu@ddb5649aba.

| Rung | Content | Related work |
|---|---|---|
| 0 | **D9 targeting safety.** The versioned preview already rejects unusable or unsafe references. Exercise pending, failed and incomplete inversion through REST and MCP. Address the workflow-builder estimate's ambiguous successful zero as a separate display change. | #6002, #5003 |
| 1 | **D3 bounded reads.** The maintenance tick pages responses, fails on overflow and carries failed and unanswered counts. Preserve this behavior; ADR-1012's explicit per-response coverage follows in slice 2. | #5077, #4494, #4407 |
| 2 | **D1/D3 observation metadata.** Add evaluation time, completeness and cause, and membership digest to result-set snapshots. Preserve old IDs and sibling lineage. Backfill from available evidence. Audit parent and counts at creation. | #4088, #4525, #4739 |
| 3 | **D5 tracking freshness.** Increment generation for scope-relevant changes, report age and drift in preview, and expose stale errors and the budget. Apply explicit re-walk only to eligible general walks. | — |
| 4 | **D7 execution recording.** Bind execution to its snapshot and binding mode. Record selected, reachable, authorized, withheld and unreached counts. Capture selection for `__all__` and `group:` too. | recovery WP05/06 |

| 5 | **D8 schedules + reruns**: schedules store scope id + binding + budget (migration from raw strings: resolve once, store as `expression` scopes, mark tracking); rerun dispatches. | #684, #4115 |
| 6 | **D8 approvals + preview-is-dispatch**: approval binds `(definition_hash, members_hash, count)` or ceiling; cohort-integrity condition; `Destructive` requires frozen; the previewed snapshot ID + `SCOPE_PREVIEW_MISMATCH`. `/auto` deploy rebinds to the pre-flight evaluation. | ADR-0033 §10 first implementation |
| 7 | **D2 `group` kind + D12 starting scope**; `fromResultSet` static-mode rule repealed; three-tier intersection at the chokepoint. | ADR-1008 UP-5 |
| 8 | **D6 agent-site matcher**: row-matcher grammar + shared evaluator under `common/include/`; definition-time type check against declared result columns; `preconditions` on the wire, `matched` / `not_matched` / `matched_through` replies; one-dispatch general re-walk producing one snapshot per level. | open question 1 (closed) |
| 9 | **D6b guarded execution**: `guard: preconditions` default-on for `Destructive`/`AdminOrApproval` over a narrowing scope; `withheld: precondition_failed` / `precondition_unevaluable` at all five cascade sites. | — |
| 10 | **D14 cooling**: `spec.cooling`, `withheld: cooling`, audited `ignore_cooling`. | — |
| 11 | **D13 DSL + D15 object surface**: `kind: Scope`, `scope` parameter type, formation forms, `narrower_than` + the two hash comparisons as one shared function, workflow `scope: { from: steps.<n>.matched }`; alias resolution at dispatch retired; `/api/v1/scopes/{id}` + MCP twins for every D15 method (ADR-1005 parity). | — |
| 12 | Docs: design doc rewritten to this vocabulary; DSL spec §9/§10/new Scope §; user-manual (rest-api, mcp, schedules, approvals); routed-concern row for *Scope walking* updated to name D5/D6b/D8/D9 as catastrophic clauses. | — |

Retain rungs 0 and 1 as regression baselines. Rung 2 supplies the criteria-run metadata. Rungs 3–12
describe general scope work; criteria-run creation can ship before general tracking, execution guards,
and the Scope DSL. Rungs 8–10 are the
competitor-derived additions and depend on rung 4 (recording) only; rung 11 depends on rung 2.

## Acceptance — the tests that prove it

1. A pending, failed, incomplete or expired set used under `NOT from_result_set:` aborts with
   `result_set_unusable` for a pending, failed or incomplete set. An expired reference produces its
typed unavailable result. No dispatch is sent.
2. Page all 524 matching responders and record all 524. Exceeding the supported bound fails
   materialization; a partial read never becomes a complete result.
3. Explicit re-evaluation assigns a new sibling result-set ID, preserves parent lineage and leaves the
   earlier observations intact. Verify differing visibility and inventory between the two runs.
4. An effective tag change, a registration, a decommission and a group-membership write each bump the fleet
   generation exactly once; a heartbeat does not.
5. An `expression` evaluation older than the budget, or behind the generation, is reported stale by
   preview and refused by a tracking dispatch without `allow_rewalk`.
6. A frozen dispatch after a member decommissions records `selected = n`, `reachable = n−1`,
   `unreached = 1`, and the approval's hash still verifies.
7. An approval bound to `members_hash` H refuses an execution whose evaluation hash ≠ H; a ceiling
   approval parks when `device_count > max_devices` or `age > max_age`.
8. A `Destructive` pair with a tracking binding is refused at the shape check (same site as `__all__`).
9. A `narrowing` query whose pair is not `ReadOnly` is refused at walk time.
10. The exact send set, not the handed-over `VisibleSet`, is asserted in every confinement test
    (routed-concern clause 5 of *Per-device dispatch visibility*).
11. A dispatch citing the previewed snapshot ID whose `definition_hash` differs from the dispatched
    scope's is refused `SCOPE_PREVIEW_MISMATCH`; an approval-gated dispatch without one is refused.
12. The same responses matched on the agent and on the server (same evaluator, two sites) yield
    byte-identical member sets and `members_hash`; a matcher naming an undeclared result column is
    refused at definition import.
13. A re-walk of depth 3 issues exactly one dispatch and mints three evaluations whose members are
    nested (`S3 ⊆ S2 ⊆ S1`) with correct parent result-set IDs; a `not_matched` reply counts
    toward completeness.
14. A guarded dispatch to a frozen evaluation on which one member's condition no longer holds
    records `withheld: precondition_failed = 1`, executes on the rest, and the approval's
    `members_hash` still verifies; a precondition that cannot run withholds with
    `precondition_unevaluable`, never executes.
15. A device that completed a `spec.cooling: 12h` definition is `withheld: cooling` from its
    tracking re-dispatch inside the window and re-included after it; `ignore_cooling` on an
    interactive dispatch is audited.
16. `narrower_than` answers structurally for an `AND`-extended expression and a narrowing child,
    on members for two unrelated expressions, and `incomparable` for a server-site matcher pair
    with no evaluations — never a guess.
17. For the proposed scope-object interface, `members()` for a caller with no visibility over the scope returns `device_count: 0,
    authorized: 0` and the same byte count as an empty scope; `explicit(ids)` with one id outside
    the receiver's evaluation is refused whole; `bind()` on an `incomplete` evaluation without
    `allow_incomplete` is refused and with it records the flag on the binding. A criteria run follows
the matched-only positive resolution and mandatory unsafe-operator refusal in R14.

## Open questions

1. **Matcher grammar extent.** D6 fixes the grammar at column-level predicates plus `COUNT`. Whether
   agent-side evaluation should ever see cross-row joins (e.g. "a process whose parent is …") or
   per-row arithmetic is deferred until a real walk needs it; the answer changes the evaluator's
   bound, so it is an ADR amendment, not a grammar patch.
1a. **Matched-reply payload size.** A `matched` reply carries the query payload only when the
   definition asks; whether a walk should be able to ask for *only the matching rows* (a projection
   on the agent) is the next ADR-1010 lever and needs the consumer audit first.
2. **Fleet generation granularity.** One counter is simple and exact; a per-attribute-family counter
   (roster / tags / props / groups) would let a tag-storm leave `ostype`-only scopes fresh. Decide
   after measuring how often expression scopes go stale in the UAT rig.
3. **Cross-operator sharing** (design §12) — a grant on the scope definition, reads narrowed by the
   recipient. Needs the `ResultSet` securable #5047 asks for first.
4. **Policy `fromResultSet`** — only viable with a frozen binding or a cheap (`expression`/`group`)
   parent; decide when PR-E2 is picked up.
5. **Membership diff over time** (design §12) now falls out of retained evaluations; whether to keep
   additional general-scope history for pinned scopes is a retention decision for the compliance owner.
ADR-0075 R11/R14 define run retention and later approval evidence.
6. **SQL as an agent-site-only matcher.** TAR's `tar.sql` already runs operator SQL on each
   endpoint through a read-only authorizer, and roadmap 15.C saves a TAR query as a result set
   with "returned ≥ 1 row" as the matcher. Generalising that to every query's result rows (a
   per-dispatch in-memory table over the declared result columns) would give a second matcher
   language, agent-site only, with `narrower_than` falling to members for it. The shared row-DSL
   evaluator stays the portable one; this is an addition, not a replacement, and the authorizer's
   bound (no `ATTACH`, no writes, time and row caps) is the design question.
7. **`project(evaluation, column)` as a form.** Reducing an evaluation to a list of attribute
   values that the next matcher binds as `IN <list>` is the one legitimate reduce-then-broadcast in
   the design (the HK payments prefixes in the brief are a literal today and should be a projection
   of another scope). Naming it as a D15 method keeps it from arriving as a string parameter.
