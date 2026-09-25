# Yuzu Policy Engine

## Table of Contents

- [Overview](#overview)
- [Policy Fragments](#policy-fragments)
- [Policies](#policies)
- [Compliance Tracking](#compliance-tracking)
- [Fleet Compliance Summary](#fleet-compliance-summary)
- [Cache Invalidation](#cache-invalidation)
- [CEL Expressions](#cel-expressions)
- [REST API Endpoints](#rest-api-endpoints)
- [YAML Schema Reference](#yaml-schema-reference)

---

## Overview

The policy engine provides **Guaranteed State** -- a desired-state enforcement
system where the server declares what state endpoints should be in, and agents
continuously evaluate and remediate drift.

The system is built on two primitives:

1. **PolicyFragment** -- a single check/fix/postCheck pattern that tests one
   condition and optionally remediates it.
2. **Policy** -- a named binding of a fragment to a set of devices via scope
   expressions, triggers, management group bindings, and input parameters.

Policies are defined in YAML using the `yuzu.io/v1alpha1` DSL (the same schema
used for instruction definitions) and are managed through the REST API and the
compliance dashboard.

The implementation is backed by `PolicyStore` (PostgreSQL, schema
`policy_store`, ADR-0056), which stores fragments, policies, triggers, group
bindings, input parameters, and per-agent compliance status. Dispatch is
coordinated fleet-wide across server replicas via a durable claim, so exactly
one replica dispatches a given policy's check per interval regardless of how
many replicas are running.

---

## Policy Fragments

A PolicyFragment is the atomic unit of compliance. It contains:

- **Check instruction** -- an instruction definition that evaluates the current
  state. The check compliance expression (CEL) determines pass/fail.
- **Fix instruction** (optional) -- an instruction definition that remediates
  drift when the check fails.
- **Post-check instruction** (optional) -- a follow-up check to verify the fix
  was successful.

### Fragment Structure

Each fragment stores:

| Field | Description |
|---|---|
| `id` | Auto-generated unique identifier |
| `name` | Human-readable fragment name |
| `description` | What this fragment checks and fixes |
| `yaml_source` | Verbatim YAML source (source of truth) |
| `check_instruction` | Instruction definition ID for the check step |
| `check_compliance` | CEL expression evaluated against check results |
| `check_parameters` | JSON parameter bindings for the check instruction |
| `fix_instruction` | Instruction definition ID for the fix step |
| `fix_parameters` | JSON parameter bindings for the fix instruction |
| `post_check_instruction` | Instruction definition ID for the post-check step |
| `post_check_compliance` | CEL expression for post-check evaluation |
| `post_check_parameters` | JSON parameter bindings for post-check |

### Example Fragment YAML

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  name: ensure-defender-enabled
  description: Verify Windows Defender real-time protection is active
spec:
  check:
    plugin: security
    action: defender-status
    compliance: "result.realtime_protection == true"
  fix:
    plugin: security
    action: enable-defender
  postCheck:
    plugin: security
    action: defender-status
    compliance: "result.realtime_protection == true"
```

---

## Policies

A Policy binds a fragment to devices, defining when and where compliance
checks run.

### Policy Structure

| Field | Description |
|---|---|
| `id` | Auto-generated unique identifier |
| `name` | Human-readable policy name |
| `description` | What this policy enforces |
| `yaml_source` | Verbatim YAML source (source of truth) |
| `fragment_id` | Reference to the PolicyFragment |
| `scope_expression` | Scope engine expression for device targeting |
| `enabled` | Whether the policy is active (can be toggled) |
| `inputs` | Key-value parameters passed to the fragment's instructions |
| `triggers` | When to evaluate. **Only `interval` triggers are honoured as declared — every other type is silently ignored and the policy falls back to hourly evaluation of its full scope regardless.** You can always confirm what's actually stored: `GET /api/v1/policies/{id}` (and the policy list, `GET /api/v1/policies`) return each trigger's `type` and parsed `config` verbatim, so fetching the policy and comparing that against the cadence you intended is a working diagnostic — see "Trigger Configuration" below (#4244). |
| `management_groups` | Group IDs this policy is scoped to |

### Trigger Configuration

Triggers are stored per-policy with type-specific JSON configuration. **Corrected 2026-09-11 (Gate-of-record pass 5, sec-P5-1/CHAOS-P5-1/CHAOS-P5-2 — the pass 4 wording below contained a false claim of its own, and undersold the parser's fragility):** non-interval trigger types are accepted and stored, but IGNORED — they do NOT suppress evaluation. `trigger_type` is a free-text column and every kind below is accepted and persisted without validation. The due-policy scheduling query is a **`LEFT JOIN`** from `policies` to `policy_triggers` filtered to `trigger_type='interval'` **in the join condition, not the `WHERE` clause** (`server/core/src/policy_store.cpp:1242-1252`) — so every enabled policy produces exactly one row whether or not it has an interval trigger. A policy with only a `file_change`/`service_status`/`event_log`/`registry`/`startup` trigger (or no trigger at all) still gets that row, with `config_json` = `NULL`, and `NULL` falls back to the **3600-second platform default** (`interval_from_config_json(..., default_interval_seconds)`). The practical effect: a policy configured with a non-interval trigger still evaluates — every hour, against its full declared scope — as if it had an `interval` trigger set to the default.

**What you CAN see, and how to use it (corrects an earlier, false "nothing surfaces this" claim):** the policy-detail and policy-list REST reads genuinely return each trigger's `id`, `type`, and parsed `config` — `GET /api/v1/policies/{id}` and `GET /api/v1/policies` (and their legacy `/api/policies` twins, in `server/core/src/compliance_routes.cpp`). The compliance routes (`/api/compliance`, `/api/compliance/{policy_id}`) return status counts and per-agent results, not triggers. Only these config keys are kept when a trigger is stored: `interval_seconds`, `path`, `event_source`, `event_id`, `expression`; any other key (for example `service`, `log`, `hive`, `key`) is dropped, so those triggers show a `null` or partial `config`. Fetch the policy and look at its `triggers` array: if there's no entry with `"type": "interval"` and a numeric `config.interval_seconds`, the policy is on the 3600s fallback regardless of what other trigger types are listed. **What is NOT surfaced:** no validation or warning at policy-create time that a declared trigger type has no effect on cadence, and no dedicated metric reporting the *effective* evaluation interval after the parser's fallbacks — so you have to go looking, nothing tells you proactively. Tracked as issue #4244.

**The `triggers:` parser is a hand-rolled line scan, not a real YAML parser, and it is fragile in ways that compound the above:**

1. **Indentation:** `extract_yaml_section` keeps only lines *more indented* than the `triggers:` key itself — a `- type:` line indented at the *same* level as `triggers:` (a perfectly common, idiomatic YAML list style) yields **zero triggers parsed**, silently. See the indentation requirement spelled out under "Policy" below.
2. **Duration parsing:** `interval_seconds` is read with `std::stoi`, which parses a numeric *prefix* and stops — `interval_seconds: 5m` (a human writing "5 minutes" the way they'd say it) parses as `5`, i.e. **5 seconds, not 300** — a 60× tighter cadence than intended, silently.
3. **Range handling:** a value `std::stoi` can't parse as an `int` (e.g. a value larger than ~2.1 billion but still within `int64_t` range) is caught and stored as a **raw string** instead of a number; at dispatch time that string is re-parsed with `std::stoll`, which succeeds — so an accidental huge value doesn't error, it silently produces a multi-year effective interval. The policy dispatches roughly once and then not again for a very long time, while `enabled` keeps reporting `true` the whole time — there is no sign anything is wrong short of noticing the policy stopped producing results.

| Trigger Type | Config Example | What actually happens |
|---|---|---|
| `interval` | `{"interval_seconds": 300}` | Evaluates on your declared cadence (floored at 60s) — **if** the trigger actually parsed; see the fragility list above. |
| `file_change` | `{"path": "/etc/hosts"}` | **Ignored for cadence purposes** — the file-change condition has no effect on *when* evaluation happens. The policy still evaluates every **3600s** (default) against its full scope. Visible via `GET /api/v1/policies/{id}` (the stored `config` has no `interval_seconds`). See #4244. |
| `service_status` | `{"service": "sshd"}` | Same as `file_change` above. See #4244. |
| `event_log` | `{"log": "Security", "event_id": 4625}` | Same as `file_change` above. See #4244. |
| `registry` | `{"hive": "HKLM", "key": "SOFTWARE\\..."}` | Same as `file_change` above. See #4244. |
| `startup` | `{}` | Same as `file_change` above. See #4244. |

If you need a policy to re-evaluate on a specific cadence, declare an explicit `interval` trigger with the `interval_seconds` you want (as a plain integer, not a duration string) at the correct indentation (see "Policy" below) — do not assume a `file_change`/`service_status`/`event_log`/`registry`/`startup` trigger changes *when* evaluation happens; it doesn't, and the policy will silently run hourly against its full scope regardless. (Real-time, kernel-backed enforcement for a narrower set of settings exists on the agent-side Guardian path — see `docs/yuzu-guardian-design-v1.1.md` — which is a different mechanism from this server-side policy trigger configuration.)

> **Common mistake 1 — no interval trigger:** pasting one of the non-`interval` examples above (or any policy with no `triggers:` block at all) does not mean "this policy never runs" — it means "this policy runs every hour against its full scope." Nothing in policy creation or the dashboard proactively surfaces that fallback as distinct from a deliberately-configured hourly interval — but `GET /api/v1/policies/{id}` does show you the stored trigger `config`, so you can check (#4244). If a policy's checks are expensive or its scope is large, declare an explicit `interval` trigger with a cadence you've chosen on purpose, rather than relying on (or being unaware of) the default.
>
> **Common mistake 2 — wrong indentation silently drops all triggers:** writing `- type: interval` at the *same* indentation as the `triggers:` key above it (rather than indented one level deeper) parses as **zero triggers**, not an error — the policy falls back to the 3600s default exactly as if you'd written no triggers at all. A policy you believe is checking every 24 hours (`interval_seconds: 86400`) can end up running **24× more often** than intended this way, with every layer reporting healthy. See "Policy" below for the indentation the parser actually requires.
>
> **Common mistake 3 — duration strings and oversized values:** `interval_seconds: 5m` parses to `5` (seconds), not 300 — a **60× tighter cadence** than a human reading "5m" as "5 minutes" would expect. And an `interval_seconds` value large enough to overflow a 32-bit int (but still fitting in 64 bits) doesn't error either — it silently produces a multi-year effective interval, so the policy dispatches once and then appears to just stop, while still reporting `enabled: true`. Always write `interval_seconds` as a plain integer number of seconds, and sanity-check the value you get back from `GET /api/v1/policies/{id}` against what you intended.

> **Trigger limit:** The agent's trigger engine enforces a configurable maximum trigger count (default: 2000). Triggers beyond this limit are rejected with a warning log message. This prevents runaway policy deployments from exhausting agent resources. The limit can be configured via the agent API. (Note: this is the *agent's own* `TriggerType` engine used elsewhere in the product, e.g. §17 of the capability map — distinct from the server-side `PolicyStore` trigger-type column described above, which does not dispatch through that engine at all.)

### Management Group Bindings

Policies can be scoped to specific management groups. When a policy is bound
to a group, only agents that are members of that group (or its descendant
groups) are subject to the policy's compliance checks.

### Example Policy YAML

```yaml
apiVersion: yuzu.io/v1alpha1
kind: Policy
metadata:
  name: baseline-security
  description: Enforce security baseline on production servers
spec:
  fragment: ensure-defender-enabled
  scope: "tag:environment = 'production'"
  triggers:
    - type: interval
      interval_seconds: 300
  managementGroups:
    - eu-production-servers
  inputs:
    severity_threshold: "high"
```

**The interval trigger's config key is `interval_seconds`, not `interval`.** The
loader reads it via `extract_yaml_value(item_block, "interval_seconds")`
(`server/core/src/policy_store.cpp:655`) — a trigger block with any other key
name (including the easy-to-guess `interval:`) parses with no `config_json`
and silently falls back to the **3600-second** platform default
(`policy_evaluator.hpp:107`), not the value you wrote. This corrects an
earlier revision of this manual that itself used the wrong key. *(Corrected
2026-09-10, Gate-of-record pass 4 item 1.)*

**Indentation matters, and it is stricter than valid YAML in general
(added 2026-09-11, Gate-of-record pass 5, CHAOS-P5-1).** The `- type:` line
above **must** be indented *more* than the `triggers:` key it belongs to —
in this example, `triggers:` is at 2 spaces and `- type: interval` is at 4.
`extract_yaml_section` (`server/core/src/yaml_scan.cpp:279`) discards every
line that is not strictly more indented than the section's own key, so the
equally-valid, equally-common YAML style where a list's dashes align with
their parent key —
```yaml
  triggers:
  - type: interval
    interval_seconds: 300
```
— parses as **zero triggers**, silently, with no error. Always indent
`- type:` at least one level deeper than `triggers:`, exactly as shown in
the example above.

---

## Compliance Tracking

The policy engine tracks compliance status per agent per policy. Each
`PolicyAgentStatus` record contains:

| Field | Description |
|---|---|
| `policy_id` | The policy being tracked |
| `agent_id` | The agent being evaluated |
| `status` | Current compliance state |
| `last_check_at` | Unix timestamp of last check evaluation |
| `last_fix_at` | Unix timestamp of last fix execution |
| `check_result` | JSON output from the last check instruction |

### Status Values

| Status | Meaning |
|---|---|
| `compliant` | Check passed -- the endpoint is in the desired state |
| `non_compliant` | Check failed -- the endpoint is not in the desired state |
| `unknown` | Not yet evaluated, status invalidated, or the agent did not respond to a check within the grace window |
| `fixing` | Fix instruction is currently running |
| `error` | Check or fix instruction failed to execute, **or the policy is misconfigured** (e.g. an empty compliance expression — a policy that checks nothing is reported as `error`, never `compliant`) |

---

## Automatic Evaluation

Enabled policies are evaluated automatically by a background thread that runs
every **10 seconds** (the evaluation cadence). On each tick the server:

1. Selects every enabled policy whose evaluation interval has elapsed.
2. Resolves the policy's management group(s) or scope expression to a target
   agent list.
3. Dispatches the bound fragment's `check` instruction to those agents (over
   the same command path operator-initiated commands use).
4. After a **15-second grace window**, reads each agent's response, evaluates
   the CEL `check_compliance` expression, and writes the per-agent verdict.

The evaluation interval is taken from the policy's first `interval` trigger
(`interval_seconds`, clamped to a 60-second floor). A policy with no interval
trigger defaults to **3600 seconds** (1 hour). Dispatch timing is durable
(stored in Postgres), so an ordinary server restart preserves each policy's
last-dispatched time and does not reset its interval clock. Only the first
boot after a Postgres cutover — when that table is still empty — makes every
enabled policy due immediately (a freshly authored policy evaluates within
~25 seconds of creation, the same as any other newly-due policy).

Verdict semantics: a plugin failure / timeout / rejection → `error`; a
non-responder after the grace window → `unknown`; a successful response that
fails the CEL → `non_compliant`; one that satisfies it → `compliant`.

Implementation/lifecycle: the thread is `PolicyEvaluator`
(`policy_evaluator.{hpp,cpp}`), wired in `server.cpp` against a hoisted shared
`command_dispatch_fn`; per-agent verdicts are written via
`PolicyStore::update_agent_status`. The `policy_eval_thread_` is **joined
before the stores are destroyed** in `~ServerImpl`/`stop()` — the eval thread
dispatches through those stores, so the join-before-stores order is a
use-after-free guard any shutdown refactor must preserve.

> **Remediation is never automatic.** Detection runs on the schedule above;
> applying a fix is always an explicit, operator-gated action (see
> `POST /api/policies/{id}/remediate` below). A server restart does **not**
> reset an in-flight `fixing` row — the durable claim behind it survives the
> process. If the replica dispatching a fix dies mid-flight, the stranded
> `fixing` row is instead aged back to `unknown` (and becomes eligible for
> re-evaluation) by a continuous, age-gated sweep once `last_fix_at` is older
> than `fixing_stale_seconds` (default 1800s) — not immediately, and not tied
> to any restart.
>
> **High Availability (HA): manual remediation is now safe on multi-replica servers.** Each target
> is claimed durably before the fix is dispatched, so two replicas cannot independently remediate
> the same agent. If a target has already exhausted its fix-retry cap for the policy, the
> remediation request is refused with HTTP 409 and the message "remediation already in flight or
> retry cap reached for this policy". The remediate response's `agents` count reflects **delivered**
> targets (the fix was actually dispatched to them), not attempted targets.
>
> **Scope of the guarantee.** The claim prevents two replicas from independently *claiming* the
> same `(policy, agent)` target only when both are running the **same schema version**. During a
> rolling upgrade across the migration boundary, an old binary that predates the durable claim can
> transiently run alongside a new one; that mixed-version window is gated today by issue #4014
> (which blocks running a second production replica) pending a durable cluster-capability admission
> gate. The exposure is one-directional — a row written by an old binary carries claim-generation
> `0`, a value a new binary never mints for its own claims. Separately, the guarantee is
> effectively-once, not exactly-once (consistent with ADR-2002): a replica that pauses for longer
> than `fixing_stale_seconds` between winning the claim and actually sending a command over gRPC —
> the fix, or the subsequent post-fix verify — can still deliver that one send after a sibling has
> reclaimed the target, because the wire send itself
> is not transactionally fenced. The durable claim prevents concurrent or duplicate *claims*; it
> bounds, but does not make impossible, a single late duplicate *dispatch* from a long-paused
> claim-holder.

### Forcing an immediate evaluation

`POST /api/policies/{id}/evaluate` dispatches a check immediately, ignoring the
interval. It returns `202` with an `execution_id`; verdicts land within roughly
15–30 seconds (next collection cycle).

---

## Fleet Compliance Summary

The `FleetCompliance` aggregate provides a fleet-wide view:

- **compliance_pct** -- percentage of (policy, agent) pairs that are compliant
- **total_checks** -- total number of tracked (policy, agent) pairs
- Breakdown by status: compliant, non_compliant, unknown, fixing, error

Per-policy summaries (`ComplianceSummary`) provide the same breakdown scoped
to a single policy.

The compliance dashboard (accessible at the Policies page in the web UI)
displays:

- Fleet compliance percentage with a color-coded bar
- Count of active policies
- Per-policy compliance percentage with drill-down to agent-level detail
- Per-agent status with last check time and check result

---

## Cache Invalidation

When a policy's check instruction or compliance expression changes, agents
need to re-evaluate. The policy engine supports:

- **Per-policy invalidation** -- Reset all agent statuses to `pending` for a
  specific policy, forcing re-evaluation on the next trigger.
- **Fleet-wide invalidation** -- Reset all agent statuses across all policies.
  Use sparingly, primarily after bulk configuration changes or server upgrades.

Both operations are available via the REST API.

---

## CEL Expressions

Compliance expressions use [Common Expression Language (CEL)](https://github.com/google/cel-spec),
a non-Turing-complete expression language designed for security policies. CEL
provides strong typing, compile-time checks, and no side effects.

Compliance expressions are stored in `check_compliance` and
`post_check_compliance` fields. They are evaluated against the check
instruction's result data to determine pass/fail.

Example expressions:

```
result.realtime_protection == true
result.value == "expected" && result.type == "REG_SZ"
result.signature_age < duration('24h')
```

---

## REST API Endpoints

All policy engine endpoints are under `/api/` (legacy prefix). They require a
**route-specific** `Policy:*` RBAC permission — `Read`, `Write`, `Delete` and
`Execute` are granted independently, so the per-row `Permission:` annotations
below are the authority, not a blanket Read/Write pair. The REST reference
(`rest-api.md`) carries the same values.

### Policy Fragments

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/policy-fragments` | List all fragments. Query params: `name`, `limit`. Permission: `Policy:Read`. |
| `POST` | `/api/policy-fragments` | Create a fragment from YAML. Permission: `Policy:Write`. Body must be a complete YAML document or a JSON envelope `{"yaml_source": "<full YAML>"}` — see worked example below. |
| `DELETE` | `/api/policy-fragments/{id}` | Delete a fragment by ID. Permission: `Policy:Delete`. |

#### Worked example — `POST /api/policy-fragments`

The `kind` is a **YAML field** inside the body, not an HTTP query
parameter or top-level JSON key. The server checks `kind: PolicyFragment`
on the parsed YAML; sending `?kind=PolicyFragment` in the URL or
`{"kind":"PolicyFragment"}` outside `yaml_source` is silently ignored. If
the YAML is missing the `kind:` line you'll get an HTTP 400 with the full
expected schema in the error body.

**JSON envelope (recommended for programmatic callers):**

```bash
curl -X POST http://localhost:8080/api/policy-fragments \
  -H "Content-Type: application/json" \
  -b cookie -d '{
    "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\nmetadata:\n  name: ssh-disabled\nspec:\n  check:\n    plugin: services\n    action: status\n    parameters: { name: sshd }\n    compliance: \"result.state != \\\"running\\\"\"\n"
  }'
```

**Raw YAML body (alternative — content-type other than `application/json`):**

```bash
curl -X POST http://localhost:8080/api/policy-fragments \
  -H "Content-Type: application/yaml" \
  -b cookie --data-binary @- <<'EOF'
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  name: ssh-disabled
spec:
  check:
    plugin: services
    action: status
    parameters: { name: sshd }
    compliance: 'result.state != "running"'
EOF
```

Both forms produce a 201 with `{"id": "<fragment-id>", "status": "created"}`.

### Policies

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/policies` | List all policies. Query params: `name`, `fragment_id`, `enabled_only`, `limit`. Permission: `Policy:Read`. |
| `POST` | `/api/policies` | Create a policy from YAML. Permission: `Policy:Write`. Body: same shape as `POST /api/policy-fragments` — full YAML in `yaml_source`, with `kind: Policy`. |
| `GET` | `/api/policies/{id}` | Get policy detail including compliance summary and `remediation_available` (true when the bound fragment defines a `fix` instruction). Permission: `Policy:Read`. |
| `DELETE` | `/api/policies/{id}` | Delete a policy and its compliance data. Permission: `Policy:Delete`. |
| `POST` | `/api/policies/{id}/enable` | Enable a disabled policy. Permission: `Policy:Write`. |
| `POST` | `/api/policies/{id}/disable` | Disable an active policy. Permission: `Policy:Write`. |
| `POST` | `/api/policies/{id}/evaluate` | Force an immediate compliance check, ignoring the interval. Permission: `Policy:Execute`. Returns `202` with `execution_id`; `409` if the policy has no check instruction or matches no agents. |
| `POST` | `/api/policies/{id}/remediate` | Manually remediate non-compliant agents. Permission: `Policy:Execute`. Only valid when `remediation_available` is true (else `409`). Optional body `{"agent_ids":[...]}` scopes the fix to a subset (intersected with the policy's own scope); absent ⇒ all currently `non_compliant` agents. Never automatic. |
| `POST` | `/api/policies/{id}/invalidate` | Invalidate agent-side cache for this policy. Permission: `Policy:Execute`. |
| `POST` | `/api/policies/invalidate-all` | Invalidate cache for all policies (fleet-wide). Permission: `Policy:Execute`. |

### Compliance

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/compliance` | Fleet compliance summary (total, compliant, non_compliant, etc.). Permission: `Policy:Read`. |
| `GET` | `/api/compliance/{policy_id}` | Per-policy compliance detail with per-agent statuses. Permission: `Policy:Read`. |

### HTMX Fragments

> These dashboard fragments are **not** `Policy:*`-gated — they resolve a session and
> nothing more (`compliance_routes.cpp`). That is a known gap, tracked as #4042; the
> per-route permissions above apply to the `/api/` surface only.

| Route | Description |
|---|---|
| `/fragments/compliance/summary` | Compliance dashboard summary fragment |
| `/fragments/compliance/{policy_id}` | Per-policy compliance detail fragment |

---

## YAML Schema Reference

Both policy kinds use `apiVersion: yuzu.io/v1alpha1`. The full DSL
specification is in `docs/yaml-dsl-spec.md`.

### PolicyFragment

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  name: <unique-name>
  description: <human-readable description>
  labels:
    category: <security|compliance|performance|custom>
spec:
  check:
    plugin: <plugin-name>
    action: <action-name>
    compliance: <CEL expression>
    parameters:             # optional
      <key>: <value>
  fix:                      # optional -- omit for check-only rules
    plugin: <plugin-name>
    action: <action-name>
    parameters:             # optional
      <key>: <value>
  postCheck:                # optional -- verify fix was successful
    plugin: <plugin-name>
    action: <action-name>
    compliance: <CEL expression>
    parameters:             # optional
      <key>: <value>
```

### Policy

**Do not put `#` comments inside the `triggers:` sequence — not on their own
line, not trailing a `- type:` entry, anywhere between `triggers:` and the
next sibling key.** The parser that reads `spec.triggers` (`policy_store.cpp:622-660`)
locates each trigger entry with a raw `std::string::find('-')` scan of the
whole `triggers:` block, before any comment-stripping happens — a stray `-`
character inside a comment (even an innocuous one like "non-interval" or
"re-evaluate", both hyphenated) is indistinguishable from a trigger's own
leading dash. The **first** `-` in the block sets the indent the scanner
uses for every entry, so a comment *before* the first real `- type:` line
silently parses **zero triggers** from an otherwise well-formed policy — no
error, no warning, just an empty trigger list. A comment trailing an entry
does a different kind of damage: values are not stripped of trailing
comments (`yaml_scan.cpp`, `extract_yaml_value`), so `- type: interval  # x`
is stored with type `interval  # x`, which is never treated as an interval
trigger. The example below is deliberately comment-free inside `triggers:` for
exactly this reason; only `type: interval` currently has any effect on
*when* the policy evaluates (see "Trigger Configuration" above and its
"Common mistake" callout) — every other type in the schema line below is
accepted, stored, and functionally ignored. *(Corrected 2026-09-10,
Gate-of-record pass 4 item 2 — an earlier revision of this example put
explanatory comments inside the sequence and broke on this exact bug.)*

**Also indent `- type:` deeper than `triggers:`, never at the same level**
(added 2026-09-11, Gate-of-record pass 5, CHAOS-P5-1) — see the worked
example and explanation under "Example Policy YAML" above; the schema below
uses the one indentation the parser accepts.

```yaml
apiVersion: yuzu.io/v1alpha1
kind: Policy
metadata:
  name: <unique-name>
  description: <human-readable description>
spec:
  fragment: <fragment-name-or-id>
  scope: <scope-expression>
  triggers:
    - type: <interval|file_change|service_status|event_log|registry|startup>
      interval_seconds: <seconds>
  managementGroups:
    - <group-name-or-id>
  inputs:
    <key>: <value>
```
