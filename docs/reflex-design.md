# Reflex design — agent-local Spark-bound automated response

Status: design-only (R0). Implemented incrementally by slices R1-R14 of the Spark/Reflex/DEX
programme; each slice cites the specific paragraph below it implements. Authoritative source:
`docs/adr/0021-spark-reflex-architecture.md` (Decisions 2, 4, 5, 6, 7, 8, 9, 10 and their Amendments),
`docs/spark-stage2-guardian-consumer-design.md`, `docs/yuzu-guardian-design-v1.1.md` §24. This
document is itself the canonical home for the fixed points below — later slices cite it rather than
re-deriving these rules; if a later slice's PR text disagrees with this file, this file wins unless
amended here first, in the same spirit as `docs/instruction-file-standard.md` "one canonical home."

## Terminology

(Reused verbatim from ADR-0021; restated here because this file, not the ADR, is what later slices
read line-by-line.)

- **Spark** — a use-case-agnostic detection trigger (type + params). Consumers receive events,
  never watcher instances. Reflex is one of three *sibling* Spark consumers (Guardian, DEX, Reflex)
  — never a specialization of another (ADR-0021 Decision 2).
- **Reflex** — an agent-local binding from a Spark to one or more Reactions, executed on the device
  the moment the Spark fires, with or without server connectivity.
- **Reaction** — one plugin invocation (plugin, action, params) within a Reflex's chain; runs
  sequentially, gated on the prior Reaction's result.
- **Reflex Set** — the deployable unit: a named, versioned, assigned collection of Reflexes.
  Individual Reflexes never deploy alone — exactly the Baseline grammar.

## YAML-authoritative Reflex Set grammar

`yaml_source` is authoritative (D7) — the server never re-derives content from `spec_json` alone;
`spec_json` is a compiled, canonical (key-sorted) projection used for the digest and the agent push.

```yaml
name: string                      # unique per docs/postgres-store-playbook.md UNIQUE constraint
                                   # version is NOT authored in yaml_source — see note below
enabled: bool
os_target: [windows|linux|darwin] # filters server-side before push; never rides the wire; the
                                   # agent's own platform string is "darwin", never "macos"
reflexes:
  - reflex_id: string             # unique WITHIN this set (not globally)
    name: string
    enabled: bool
    spark:
      type: file|service|disk|interval|startup|registry   # open set — see "Spark types" above;
                                                            # plist/process are PLANNED (A6/A7)
      params: {..type-specific..}   # schema per reflex_schema_registry.cpp spark_types()
    reactions:                      # sequential, <= 4 deep
      - plugin: string
        action: string
        params: {..}
        gate: always|on_success|on_failure   # first Reaction MUST be "always"; see "Reaction
                                              # success and timeout" below for what on_success means
        timeout_ms: uint32     # default 10_000, max 120_000
        capture_output: bool   # default false; captured output capped at 4 KiB
    cooldown_ms: uint32         # steady_clock-based per-reflex_id debounce
    max_per_hour: uint32        # hourly cap per reflex_id (reuses the existing DexRateLimiter
                                 # primitive, include/yuzu/agent/dex_rate_limiter.hpp)
    fire_on_arm: bool           # default false; see "Reaction success and timeout" below for the
                                 # startup/interval special case
assignment:
  - group_id: string
    disposition: include|exclude   # the closed Baseline-assignment vocabulary (baseline_store.hpp)
```

**`version` is server-bumped, never author-set, and is stripped from (or rejected in) authored
`yaml_source`** on submit — it is not part of the round-tripped, YAML-authoritative content D7
describes; a submitted `yaml_source` that includes a `version` key is either ignored (stripped
before storage) or rejected outright (R4's implementation picks one and is consistent about it),
never silently honored as an author-supplied version number.

Bounds, enforced by the R4 validator (`validate_reflex_set`): **at most 32 reflexes per set**, each
chain **at most 4 Reactions deep**, `reflex_id` unique within the set, `os_target` drawn from the
closed vocabulary above.

**Escalation policy is explicitly deferred** in this rebuild's Reflex v1 — ADR-0021 Decision 4
describes "so many chances over so much time, then act, or don't" as the target shape, but v1 ships
only the cooldown/hourly-cap primitives above. A future escalation-policy field is additive to this
grammar; do not treat its absence here as an oversight.

**`fire_on_arm` on a monostate spark type (`interval`, `startup`, `file`, `registry` — `SparkData` is
`std::monostate` for all four) fires the Reflex once, immediately, the first time it is armed** (there
is no "prior state" for these types to compare against, so "already true at arm time" is trivially the
arm event itself); on an edge-producing type (`service`, `disk`, `plist`, `process` — the types whose
`SparkData` carries a real payload, `ServiceSparkData`/`DiskSparkData` today) it fires only if the
persisted condition is already in the "true" state at arm time — `disk` fires only on a valid
`Breach` reading, never unconditionally at arm, exactly like every other edge type — see "Spark types
and per-type facts" below for the full per-type edge-value table.

## Substitution tokens (closed list)

A Reaction's `params` values may reference the firing Spark event via `{{spark.<fact>}}`, using the
literal `{{...}}` delimiter — matching the convention Reflex content actually implements (the same
one `policy_evaluator.cpp` and shipped content definitions already use), **not** the
`docs/yaml-dsl-spec.md` `${...}` convention documented for other content. A literal `{{` an author
needs verbatim is escaped `\{\{`; an unbalanced or unterminated token is a validation error. The
**only** legal facts, and which spark types can produce them, are listed under "Spark types and
per-type facts" below — `{{spark.key}}`, `{{spark.path}}`/`{{spark.pid}}` (Process only, planned),
`{{spark.service_state}}` (Service only), `{{spark.edge}}` (a closed, per-type enumeration, several
types produce none at all).

`validate_placeholders` (R4) rejects any `{{...}}` token outside this list, and rejects a fact not
published for the Reflex's own spark `type` (e.g. `{{spark.pid}}` on a `file` spark is a validation
error, not a silent empty substitution).

**Substitution is data-only — never shell-composed.** `{{spark.*}}` tokens are **forbidden** in any
parameter that reaches an interpreted context (a `script`/command-body parameter of `script_exec` or
any plugin that composes a shell/interpreter line from its params) and in every parameter of a
**dangerous** Reaction (`execute_gate != None` or `dispatch_class == Destructive`, per the safety
chokepoint) — `validate_reflex`/`validate_placeholders` (R4) refuse the Reflex at compile if a token
appears in either. Where substitution IS legal, the resolved value is passed as a discrete,
argv-style parameter, never interpolated into a composed command string — an attacker-controlled
Spark fact (e.g. a maliciously-named local file whose path becomes `{{spark.path}}`) cannot inject
shell syntax this way.

**Facts are re-validated at execution, against the fired edge, never against compile-time text.** At
fire time the executor re-resolves each referenced fact from the actual `SparkEvent` (e.g.
`{{spark.pid}}` is checked against the process's start time, so a pid recycled between the Spark
firing and the Reaction actually running is detected and refused rather than silently substituted
with an unrelated process's identity). If a referenced fact cannot be resolved at fire time (the
process already exited, the file already vanished), the **whole chain is refused**
(`reflex.aborted{unresolvable_fact}`) — never a partial substitution or an empty string.

**Resolved parameter values are excluded from the outcome journal.** `capture_output` (Reaction
stdout/stderr) is the only per-Reaction content persisted to `reflex_outcomes`; the actual resolved
`{{spark.*}}` substitutions (which may carry a user path, e.g. a resolved `{{spark.path}}`) are
**never** written to the journal or the outcome event — only a basename ever appears in any
persisted record, matching A7's privacy posture and D10's "no SID/username/user path" rule.

## Spark types and per-type facts (open set)

The Reflex grammar's `spark.type` is an **open set published server-side by
`reflex_schema_registry::spark_types()`** — it does **not** mirror
`agents/core/include/yuzu/agent/spark.hpp`'s `SparkType` enum verbatim, and the two must never be
assumed identical; a future type lands in both together (H2/G9 cross-check doctrine), and this
document is updated in the same PR that lands it. As of this document, the set is:

- **Shipped today** (present in `SparkType`, agent-side): `file`, `service`, `disk`, `interval`,
  `startup`, `registry` (Windows-only, gated by `os_target: windows`).
- **Planned, not yet landed** — tracked by the macOS Spark/Reflex programme: `plist` (macOS, lands
  at A6), `process` (ES-backed, lands at A7). A Reflex referencing either is a forward declaration
  the schema registry accepts today only if the underlying slice has actually shipped; until then
  they are absent from the published set, not silently accepted-but-inert.

**`{{spark.key}}` is the Reflex-authored watch key — it is NOT `spark_key()`'s internal wire
encoding.** `spark_key()` (agent-side) returns an opaque `"<type>|<params>"` string used purely for
watcher-table indexing; `{{spark.key}}` is a **per-type target accessor** over the Reflex's own
`spark.params` (e.g. the `path` param on a `file` spark, the `label` param on a `service` spark) —
the human-authored value, never the internal encoding. R5's `resolve_facts` implements the
per-type accessor explicitly.

**`{{spark.edge}}` is a closed, per-type enumeration — most types produce none at all:**

| Spark type | `{{spark.edge}}` values | Notes |
|---|---|---|
| `service` | `started` \| `stopped` \| `paused` | |
| `disk` | `breach` \| `recovery` | a threshold crossing, not a state name |
| `file` | *(none)* | `SparkData` is monostate for this type; no edge fact exists |
| `registry` | *(none)* | monostate |
| `interval` / `startup` | *(none)* | monostate; only `{{spark.key}}` is available |
| `plist` (planned, A6) | `changed` | provisional, confirmed when A6 lands |
| `process` (planned, A7) | `started` \| `exited` | provisional, confirmed when A7 lands |

A Reaction referencing `{{spark.edge}}` on a monostate type is a **validation error** at R4 — no
type-appropriate value exists to substitute, never a silently-empty string.

## Safety chokepoint — `dangerous_reactions_in_spec()`

A **sibling chokepoint** to `dangerous_enforce_in_spec` (`docs/yuzu-guardian-design-v1.1.md` §24) —
**not an extension of it**. `dangerous_enforce_in_spec` (`guardian_rule_spec.cpp`) is an
assertion-type plus a registry-key/service-name allowlist, a distinct mechanism; `dangerous_reactions_in_spec()`
is a separate classifier over `CommandCapabilityRegistry::classify(plugin, action)` (server-owned,
compile-authored; `server/core/src/command_capability.hpp`). Both independently follow the
EXTEND-never-fork doctrine for their own kind of dangerous content; a future unification of the two
mechanisms is an architect-level decision, not implied by either doc. `classify` yields an
`ExecuteGate` (`None|AdminOrApproval|AlwaysApproval`) and a `DispatchClass`
(`ReadOnly|Mutating|Destructive`). A Reaction is **consequential** — and therefore a "dangerous
Reaction" for the purposes of D4's consent gate and D9's approval gate — iff `execute_gate != None`
**or** `dispatch_class == Destructive`. An unclassified or ambiguous `(plugin, action)` pair is a
validation **error**, never a silent "assume safe."

**Reflex Reaction *execution* is agent-LOCAL dispatch, not server-mediated remote dispatch, and is
authorized exactly once — at deploy time — by this chokepoint plus the two gates below.** This
ruling is scoped to **Reaction execution only** — it does **not** describe the `__reflex__/push_sets`
leg that carries a compiled Reflex Set to the agent; see "Wire contract" below, which **is** a
dispatch site. Reaction execution never passes through the server's `classify_and_authorize_dispatch`
/ `DispatchCaller` chokepoint (`agent_registry.hpp`, the "Dispatch-caller approval provenance" routed
concern) — that chokepoint exists to gate an **operator's live remote command**, and there is no live
operator at spark-fire time to gate against. `command_capability.hpp`'s classification is reused for
its taxonomy only; a Reaction firing is explicitly **not** a `DispatchCaller` construction site and
stamps no dispatch approval provenance. Do not conflate the two:

| | Gates | When | Who/what checks |
|---|---|---|---|
| Server-mediated remote dispatch (ordinary commands, **and** the `push_sets` fan-out — see Wire contract) | `classify_and_authorize_dispatch` / `DispatchCaller` | Every dispatch, live | `agent_registry.hpp` |
| Reflex Reaction **execution** (agent-local) | consent gate (D4) + digest-bound approval (D9) | Once, at Reflex Set deploy | `reflex_set_spec.cpp` + `ApprovalManager` (server); `LocalDispatcher` executes unconditionally on the agent once armed |

This mirrors existing prior art: Guardian's own in-thread remediation and the pre-Reflex
`TriggerEngine`-driven local actions (retired by ADR-0021 Decision 5) never re-authorized per fire
either — authorization for agent-local, pre-declared automation lives at content-authoring/deploy
time, not at execution time. This is strictly about *execution*; the server-originated push that
delivers the content is a dispatch like any other, below.

### Reaction success and timeout

A Reaction's **success**, for `gate: on_success`/`on_failure` chain evaluation, is the plugin
action's own **typed result** (its structured status, not a bare process exit code) resolving to a
non-error outcome — matching how every other plugin-dispatch result is already judged elsewhere on
the platform, never a Reflex-specific redefinition. **A timeout counts as failure** — a Reaction
that exceeds `timeout_ms` never gate-admits a subsequent `on_success` step, and the chain's terminal
outcome for that Reaction is `timed_out`, distinct from both `completed` and an in-plugin `failed`.
**Not a consent mechanism:** v1's consent gate (see "Consent gate" below) admits a dangerous Reaction
on tag-consent alone and never reads an ordinary chain's `on_success`/`on_failure` result to do so —
an earlier draft of this document described a stricter "affirmative response TOKEN" rule for
`interaction.*` Reactions gating a dangerous Reaction; that rule was chain consent, which is not part
of v1 (see "Consent gate" below for why), so this paragraph's plain success/failure definition is the
only rule governing ordinary `on_success`/`on_failure` chain gating.

## Two-person approval (D9)

Any Reflex Set deploy whose compiled content contains at least one dangerous Reaction (per the
chokepoint above) requires approval by a principal representing a **distinct human root**, per
ADR-0033 §7's identity-resolution rule — not merely "a different principal string": an editor
approving through their own second API token must not satisfy this gate, and R9's implementation is
responsible for resolving every identity surface (session, API token, MCP principal) back to the
underlying human before comparing. Approval is bound to a **canonical digest**
(`canonical_reflex_digest(spec_json, assignment)`) — SHA-256 over key-sorted `spec_json` plus the
**resolved device-id list the assignment expands to at digest-compute time** (the same "resolved
device set" named throughout this section, expressed here as its sorted, deduplicated id list — the
literal bytes hashed), not the raw group/tag reference alone. Editing a Reaction's params, or a
management-group membership change that alters the resolved id list, invalidates the approval; see
"Device-set binding, re-tag, and membership drift" below.

**The approval REQUEST carries the digest the reviewer actually reviewed, and the server rejects on
drift.** **Decision, stated here because the symmetric digest formula above makes it load-bearing and
not previously settled: the approve-time comparison MUST be a live recompute** — over the row's
current `spec_json` AND a fresh resolution of the assignment's current device-id list — **never a
read back of a stored value**, so drift is caught from either source: an editor saving a new version
mid-review (a content edit), or a management-group membership change landing mid-review with no
content edit at all. Either way the approval call's digest no longer matches this live recomputation,
and the server returns a `409` — approving stale content, or a stale device-id list, is not silently
accepted as approving the current row. **A membership-resolution failure during this live recompute is
an evaluation error, refused, never a silent approve** — the same posture D4 takes on an unreadable
`TagStore` (see "Consent gate (D4)" below), applied here to the resolution this digest now depends on.
The digest is also **recomputed and compared at every compile** (`reflex_push_builder.cpp`),
fail-closed on mismatch or absence: see "Generation, undeploy, and push semantics" below for the exact
push-time refusal behavior (a stale/invalid-digest set is never silently downgraded, and a
`reflex.set.compile_refused` critical audit event fires).

**Break-glass is a NEW `ApprovalManager` capability, not an existing one Reflex merely reuses.**
Today's `ApprovalManager` has no emergency single-principal override, no `justification` field, and
no `ApprovalOrigin::kReflexDeploy` value — all three are new work this programme adds to
`ApprovalManager`, requiring their own security review at R9, not a drop-in reuse of an existing
mechanism. (AuthDB's login-lockout break-glass is a different control and does not transfer.) Until
that lands, Reflex deploy has **no** emergency override — a dangerous Reflex Set is blocked on
ordinary two-person approval with no bypass.

RBAC: Reflex gets its **own dedicated securable** (`Reflex`). Per §24's standing invariant, `Push`
stays Guardian-only and is never added to the `crud_ops[]` cross-seed array. **`Execute` is
different: `crud_ops[]` *does* include `Execute`** (it is only `Push` that sits outside it), so
Reflex's `Execute` permission is auto-granted to Administrator + ITServiceOwner by the existing
cross-seed loop like every other securable's `Execute` — this document does not claim `Execute`
is excluded from cross-seeding; it claims only that **`Push` is**, matching every other
non-Guardian securable. (Exact additional role assignments for `Execute` beyond the cross-seed
default are finalized and ratified at R7's own review.)

**Deploy fails closed if its own audit write fails.** `reflex.set.deploy` is an ADR-1005-class
mutation, and per that ADR's standing rule a mutation whose audit trail cannot be written must not
be allowed to silently succeed unaudited — a deploy whose `reflex.set.deploy` audit event fails to
write is refused, not applied-but-unlogged.

## Consent gate (D4)

A **preventive compiler gate**, not an authoring convention, and **one rule with no escalation
exception**: a dangerous Reaction (per the safety chokepoint above) is **REFUSED at compile unless
tag-consent holds — independent of any escalation policy.** There is no weaker "the compiler only
rejects `proceed`-on-exhaustion" reading. Escalation policy (deferred, see the grammar section) can
only decide *when*, inside a Reflex whose consent basis already holds, an already-consented action
proceeds — it never widens what a dangerous Reaction may do *without* consent. The platform gains an
operator-declared device classification via the free-form asset tag key `device_class` (`server` |
`workstation`) — **declared, never inferred**; see `docs/asset-tagging-guide.md` "Recipe: Reflex
consent gate." **An unclassified device is workstation-class — fail-closed.**

**v1 consent basis is the asset tag ONLY.** `evaluate_consent` (R4) admits a dangerous Reaction iff
**every resolved target device satisfies `device_class == "server"`**, established by a **direct
`TagStore::get_tag(agent_id, "device_class")` read** (never the scope-DSL's case-insensitive `tag:`
atom — a different mechanism with different case-folding semantics; see
`docs/asset-tagging-guide.md`). The match is **exact-byte** against the literal string `"server"`;
any other value, any differently-cased value, or an absent tag is `"workstation"`. Device-set
membership (management-group assignment → device ids) resolves via
`ManagementGroupStore::get_member_agents_in_subtrees`. ADR-0050's fail-closed construction/degrade
posture applies: an **unreadable** `TagStore` is an evaluation **error**, never treated as `true`.
Anything else — any resolved target that is not exact-byte `"server"` — is **refused at compile,
fail-closed**, full stop; there is no second admission path in v1.

**Consequence, stated plainly: in v1, no `interaction.*` Reaction can run on a workstation-class
device.** All five `interaction.*` actions (`notify`, `message_box`, `input`, `survey`, `set_dnd`;
`server/core/src/capability_decls/plugin_action_catalogue_d.hpp`) carry `.execute_gate =
ExecuteGate::AdminOrApproval`, which makes every one of them a "dangerous" Reaction under the safety
chokepoint's own classifier (`execute_gate != None` — see above) — including `message_box`, chain
consent's own only consent-eliciting mechanism. A dangerous Reaction on a workstation needs tag
consent it cannot have (the device is, by definition, not `device_class=="server"`), so v1 refuses
every `interaction.*` Reaction on a workstation, unconditionally, the same as any other dangerous
Reaction there. This is not a special case of the gate; it falls straight out of the single rule
above.

**Chain consent — recorded here as an explicit future extension, NOT part of v1, and here is why.**
An earlier draft of this document (the R0 brief) added a second admission path: an `interaction.*`
Reaction gated `on_success`, preceding the dangerous Reaction in the same chain, whose result is an
affirmative response token (`yes` from `buttons=yesno`, or `ok` ONLY from `buttons=okcancel`) would
satisfy consent for that one dangerous Reaction. **That path does not work as specified: it cannot
bootstrap.** Since every `interaction.*` action — including the prompt chain consent itself depends
on — is *itself* dangerous under the classifier above, admitting it under the chain-consent rule
would require a *preceding* consent it cannot have; on a workstation with no all-server tag, no
finite chain can ever acquire its first consent, because the very message that would elicit it is
gated behind the same rule it exists to satisfy. The owner's actual v1 decision was narrower than
that draft: **"We have asset tags. Use the asset tags."** Chain consent, if it is ever wanted, needs
its own design — most plausibly, a distinct classification (or a dedicated, narrower bypass) for
exactly the specific `interaction.*` Reaction whose sole purpose is eliciting the token that gates a
*subsequent* dangerous Reaction, separate from `interaction.*` Reactions used for other genuinely
dangerous purposes (an unsolicited `notify`, say) — but that carve-out is future work, not specified
here, and v1 ships without it. **R4 note:** if slice R4's own implementation work had already written
`consent_satisfied_by_chain` and the chain arm of `evaluate_consent` before this contract change
landed, both must be REMOVED — R4 absorbs this contract change by deleting the chain-consent code
path entirely, not by leaving it unreachable dead code behind the tag-only gate.

**A related, but now GENERAL, correctness defect — no longer a consent defect, since chain consent
is not in v1 — stays worth recording as an R5 prerequisite regardless: any future Reaction reading a
prompt result, on any platform, needs an honest failure signal.** `interaction_plugin.cpp`'s Windows
`MessageBoxW` failure/no-desktop path (`platform_message_box`, the `default:` arm on an unrecognized
return value) reports `response|ok` today — indistinguishable from a real `okcancel` affirmative —
instead of a distinct `status|unavailable` (macOS and Linux already do this correctly: `status|
not_reachable` and `status|unavailable|<reason>` respectively). This remains an R5 prerequisite for
whichever slice eventually consumes `interaction.*` results programmatically (chain consent, if and
when it lands with its own design, or any other future gate reading a prompt's response), but it is
a plugin honesty bug, not a hole in the D4 consent gate — v1's consent gate never reads an
`interaction.*` result at all.

**Device-set binding, re-tag, and membership drift.** The two-person approval (D9 below) binds its
digest to the **resolved device set at approval time**, not group IDs alone — a management-group
membership change **in either direction, growth or shrink**, invalidates it (the digest hashes the
resolved id list, so removing a device changes it exactly as adding one does), and the next compile
refuses until re-approved (see D9). Re-tagging a device (`device_class` changes) or a membership
change on an already-deployed, already-armed set triggers a **recompile**: the affected set's consent is
re-evaluated, and if it no longer holds, the set is **disarmed** on the affected device(s) via the
explicit removal push described in "Generation, undeploy, and push semantics" below (a
generation-advancing removal, never a compile-refusal HOLD, and never left silently armed under a
now-false consent basis).

**A device that leaves the resolved set entirely must not be treated as one of Rule 1's "affected
agents" — this is a REQUIREMENT this document states, not a behavior Rule 1's text above already
guarantees on its own.** Removing a device from scope can only preserve or vacuously satisfy D4's
"every resolved target device satisfies `device_class == 'server'`" gate — it can never break it —
so a pure shrink cannot reach Rule 2's consent-loss removal path, and per the paragraph above it DOES
trigger Rule 1's digest-mismatch HOLD for the set's remaining, still-in-scope devices. Rule 1(a)'s
"resend the prior, still-valid `full_sync` snapshot" **must be a per-agent rebuild of the set's
last-approved content against CURRENT targeting, never a literal replay of a stored artifact to its
original recipient list** — `reflex.proto`'s `ReflexSet` comment ("the server resolves the assignment
to a concrete device set BEFORE building this message") describes the ordinary, never-refused compile
path; R9 must implement the HOLD path so it re-resolves targeting the same way, never reusing a
recipient list captured at the set's last successful compile. Under that requirement, a departed
device is excluded from its own next push-build because it is no longer re-resolved as a target, not
because the HOLD mechanism itself skips it — it must never be left running the set on stale,
unreviewed grounds merely because HOLD is keeping the set alive for devices still in scope.

**Acknowledged gap this document does not close: no trigger or time bound is stated for when the
departed device's own next push-build actually happens.** The requirement above says what that
push-build must do when it runs, not what makes it run. A membership change unconditionally triggers
a recompile of the affected Reflex Set (stated above), but that recompile's HOLD outcome is about the
set's remaining, still-in-scope devices — it says nothing about scheduling a push-build for the
departed device specifically. If no other event happens to produce one (background reconcile,
heartbeat-driven `get_status` round-trip, or some other push-build cause R9 defines), a departed
device could in principle go unrevisited indefinitely, the same open-ended shape as the offline
residual window below, but reachable here even while fully online. R9 must name a concrete trigger (or
bound) for the departed device's own next push-build, or treat this identically to the acknowledged
offline gap below; this document does not pre-decide which.

**`device_class` write authorization.** Because `device_class` is the sole input to this
safety-relevant compiler gate, setting or changing it is **not** a bare `Tag:Write` operation — it
requires **`Reflex:Write` or admin**, and is recorded under a dedicated audit verb
(`reflex.device_class.tag_set`, alongside the `reflex.set.*` verbs below). The existing
service-scoped-token confinement helper `authz::service_scope_may_mutate_tag_key`
(`docs/auth-architecture.md` clause 6) is **extended** to cover `device_class` — a service-scoped
token must clear this check, checked BEFORE the scoped gate and value-blind, exactly like every
other admission-deciding tag key. This is an EXTEND, never a parallel gate.

## Wire contract

Two independent legs, both opaque `payload` bytes on the existing `CommandRequest`/
`CommandResponse` bidi stream — **no gateway regen for either leg** (matches the existing
`__guard__` precedent: no `guaranteed_state_pb`/`reflex_pb` module exists on the Erlang side).

**Control leg — reserved plugin name `__reflex__`** (R1 arms both interception halves, mirroring
`__guard__`: load-time in `plugin_loader.cpp`'s `kReservedPluginNames`, dispatch-time in
`agent.cpp` before the plugin scan):

| Direction | plugin | action | payload |
|---|---|---|---|
| Server → Agent | `__reflex__` | `push_sets` | `ReflexSetPush` |
| Server → Agent | `__reflex__` | `get_status` | (none) |
| Agent → Server | `__reflex__` | `status` | `ReflexSetStatus` |

`ReflexSetPush.removed_set_ids` carries the explicit removal shape for a `full_sync=false` delta —
see "Generation, undeploy, and push semantics" below for the full refusal-vs-removal split; it is
unused (must be empty) on a `full_sync=true` push, where omission from `sets` already means removed.

**`push_sets` IS a `DispatchCaller`/system-reserved-dispatch site — it copies the
`__guard__.push_rules` pattern exactly, never the "Reaction execution is not a dispatch" ruling
above (that ruling covers agent-local Reaction firing only).** Concretely: the server builds a
`SystemReservedPush`-class `DispatchCaller{.system = true}` (mirroring `push_rules`'s real
construction — `.principal_is_admin` is NOT set; `agent_registry.hpp`'s `classify_and_authorize_dispatch`
returns before reaching the admin/provenance arm for a `system` caller, so the flag would be inert
either way, and no `approval_provenance` list entry is needed for this site), carries its own
`capdecl` row in the capability declarations so the
`consteval` sweep classifies it rather than leaving it an unclassified miss, and goes through
`send_system_reserved` (`dispatch_confined_arms.hpp`) like every other system-originated push. R9
decides explicitly, at implementation time, whether `push_sets` is **quarantine-gated** (subject to
the #881 containment gate like an operator dispatch) or **exempt** (like `push_rules`, which is
itself exempt because a quarantined device must still receive its cached policy) — this document
does not pre-decide that, but the decision must be recorded, not left implicit.

**`__reflex__` control commands stay CLAIMED through `CommandDedupStore`** — the routed
dedup row's "dedup is the SAFE DEFAULT for future reserved names" stands, and `__guard__` remains
the **only** dispatch that bypasses the claim. `push_sets` mints a **per-push unique command id**
(`"__reflex__-<hex>"`, mirroring Guardian's own `__guard__-reconcile-<gen>-<rand>` minting) so a
re-push (retry, reconcile) is dedup'd as a genuinely new command, never replayed as the old one;
`get_status` likewise never reuses a command id across calls.

**Outcome leg — reuses the existing `__guard__`/`event` channel.** Reflex does **not** get its own
outcome proto message. A fired/completed/failed/aborted/suppressed Reflex chain is reported as an
ordinary `GuaranteedStateEvent` (`plugin="__guard__" action="event"`) with the new
`GuaranteedStateEvent.family` field set to `"reflex"` (field 21, proto3 default `""` == `"guardian"`
for backward compatibility with every pre-Reflex agent build, which never sets the field). **`family`
is a CLOSED set at ingest — `{"", "guardian", "reflex"}` — validated at the router
(`guardian_ingest.cpp`); any other value is refused and counted on an `ingest_errors`-style metric,
never silently treated as `"guardian"`.** `rule_id` is **empty for every `family=="reflex"` row** —
it is never repurposed as `<set_id>/<reflex_id>` (that would resurrect exactly the `__observation__`
rule-id-squatting pattern ADR-0021 Decision 6 retires `family` in order to *stop* doing). `set_id`
and `reflex_id` are instead **additive fields on `GuaranteedStateEvent`** (own field numbers,
alongside `family`), carried directly rather than encoded into an overloaded string. `event_type` is
drawn from `reflex.{fired,completed,failed,timed_out,aborted,suppressed_sampled}`, `event_id` is the
correlation id below.

**`severity`/`guard_type`/`guard_category` on a `family=="reflex"` row.** Unlike the
`rule_id="__observation__"` DEX sentinel — whose own doc comment states its severity-enrich is a
no-op specifically because it has no rule to enrich against — a Reflex row is **not** exempted from
these fields; the ingest router populates `severity` from the fired Reaction's own classification
(a dangerous Reaction's `fired`/`failed` outcome carries at least `medium`; a non-dangerous
Reaction's outcome carries `low`), `guard_type` is the literal string `"reflex"` (distinguishing it
in any query/dashboard that groups by `guard_type` from a real Guardian guard type like
`"registry"`/`"scm"`), and `guard_category` is `"event"` (Reflex sparks are event-driven, never a
periodic condition check in the Guardian sense).

**`suppressed_total`'s source is the agent-local counter, not a server-side derivation from sampled
`suppressed_sampled` events.** The two would disagree if `suppressed_total` were instead computed
server-side by counting `suppressed_sampled` events — sampling means most suppressions never emit an
event at all (that is the point of sampling), so a server-derived count would systematically
undercount. `suppressed_total` in `ReflexStatus`/`ReflexSetStatus` is the agent's own running
counter of every suppression, journal-persisted (see "Generation, undeploy, and push semantics"
below), independent of how many of those suppressions were *also* sampled into an emitted event.

**Upgrading agents before servers is UNSAFE; server-first is mandatory, not merely preferred.**
`family` (field 21) and its closed-set validation at the ingest router are both **new in this same
change** — an old (pre-Reflex) server's `guardian_ingest.cpp` reads `family` nowhere at all, so the
closed-set rule above does not exist on it to do any refusing. Sent field 21 arrives at an old
server as an unrecognized protobuf field, is dropped by the parser, and the row is read exactly as
if `family` had never been set — which resolves to the proto3 default `"guardian"`. **The practical
consequence: an old server files a Reflex outcome as a Guardian drift event**, not as a refusal and
not as a visible error — a silent misfiling, the opposite of the fail-loud behavior the closed-set
rule is meant to provide once it exists. That rule only protects the *reverse-safe* direction: a new
server talking to an old agent, where `family=""` correctly and intentionally resolves to
`"guardian"` because no pre-Reflex agent ever sets it. The rollout order is therefore fixed —
**server upgrades before any agent build that sets `family`/`set_id`/`reflex_id` is deployed** — and
this is a hard prerequisite, not a recommendation. `docs/user-manual/upgrading.md` gains the
operator-facing version of this note at R6, once the server and agent changes both exist to describe.

This keeps Reflex on the **same single unsolicited-event channel and the same single server-side
ingest router chokepoint** that ADR-0021 Decision 6 established — only the event *store* is
Reflex-specific (`reflex_outcomes`, R3/R10), never the router.

**Correlation ids — two distinct, deliberately different-looking namespaces, do not confuse them:**

- **Command id** for the `__reflex__`/`push_sets` command: `"__reflex__-<hex>"` (double
  underscore, matches the reserved-plugin-name prefix — mirrors the `__guard__-` convention).
- **Event id** for a Reflex outcome: `"reflex-<agent>-<nonce>-<seq>"` (single leading token, no
  double underscore) — boot-nonce'd so a restart cannot collide sequence numbers with a
  not-yet-acked prior journal entry.

Both prefixes are recognized by the executions-ladder skip rule below; they are not interchangeable
and a future reader must not assume one implies the other.

## Generation, undeploy, and push semantics

**Refusal and removal are two different causes and MUST NOT share a mechanism — conflating them was
the design's own internal contradiction (a compile refusal claiming to "hold" the agent's last
accepted generation, while a consent-loss disarm needs exactly the opposite: an armed dangerous set
must stop being armed the moment its consent basis becomes false, never stay silently held under a
now-false basis).** The two causes are split:

1. **Validation or digest-drift refusal of a NEW generation candidate (`reflex.set.compile_refused`)
   HOLDS the agent's last accepted generation — it is never expressed as a `full_sync` removal.**
   `full_sync=true` **replaces the agent's entire active Reflex Set collection with exactly what the
   message contains**, so a refused set silently *omitted* from a `full_sync=true` push would be
   *disarmed*, not held — the server therefore does **not** advance to a new `full_sync=true`
   snapshot for the affected agents at all while a refusal is outstanding. It either (a) resends the
   prior, still-valid `full_sync` snapshot — **a per-agent rebuild against CURRENT targeting, never a
   literal replay of a stored artifact to its original recipient list** (see "Device-set binding,
   re-tag, and membership drift" above for why this distinction is load-bearing on a shrink) — (the
   refused set is correctly absent because it was never in a valid snapshot to begin with) or
   (b) sends a `full_sync=false` delta that omits the refused set_id from both `sets` and
   `removed_set_ids` (see below) — the delta's own omission convention ("absent = untouched") leaves
   it held exactly as last applied. R9 picks one of (a)/(b) and states it in its own implementation
   notes.
2. **Consent loss (a re-tag or membership change that makes a previously-consented, already-armed
   set's consent basis false — D4 above) or an explicit undeploy is a REMOVAL, never a hold.** The
   server sends an explicit removal push that **advances the generation** and disarms exactly that
   set: either a `full_sync=true` snapshot containing every other currently-valid set (including any
   set independently held under rule 1, at its last-accepted content) minus the now-unconsented or
   undeployed one, or, when only the removal is needed and resending the whole snapshot is wasteful, a
   `full_sync=false` delta naming the set_id in `removed_set_ids`. **A refusal (rule 1) and a
   legitimate removal of a different set (rule 2) can both be honoured in the same delta**, because
   they use disjoint parts of the message: the refused set_id appears in neither `sets` nor
   `removed_set_ids` (untouched), while the removed set_id appears only in `removed_set_ids` — no
   choice between "hold everything" and "replace everything" is forced on the server just because two
   different causes are active on the same agent at once.

**Consent-loss disarm has a real, acknowledged residual window while a device is offline — "the
moment its consent basis becomes false" above describes how the trigger is handled server-side (the
re-tag or membership change is picked up and the disarming push queued without added delay of its
own), not when the DEVICE actually stops.** For THIS disarm path (a still-in-scope device whose D4
consent basis turns false), the removal push described in this section is the sole delivery
mechanism — a distinct case from the departed-device/HOLD scenario above, which disarms by
exclusion-from-targeting rather than by a removal push; v1 has no agent-side consent lease, expiry,
or dequeue-time recheck.
An agent that is offline when its consent basis turns false keeps running its previously-armed
dangerous Reaction, unchanged, until it reconnects and applies the removal. This is a genuine gap on
D4 — the platform's headline consent guarantee, not an ordinary operational trade-off elsewhere in the
platform. It is unresolved here — this is not merely a restatement of ordinary push latency. Closing
it (an agent-side lease/expiry, or narrowing the "moment" claim above to explicitly cover only
connected devices) is future design work, not decided by this
document.

- **Identical generation is a no-op.** If the agent's already-applied generation matches the
  incoming push's generation, the agent applies nothing and re-arms nothing — an ordinary reconnect
  that re-delivers the same snapshot must not spuriously re-fire `fire_on_arm` Reflexes or reset
  cooldown/hourly-cap state.
- **The agent rejects a push carrying a lower generation than its currently-applied one** (two
  deployers racing, or a reordered redelivery) — a monotonic-generation floor, checked before any
  apply.
- **Undeploy/disable aborts in-flight chains and drains the queue**, reporting
  `reflex.aborted{undeploy}` for every chain that was running or queued at the moment of undeploy —
  "undeploy complete" is never reported while a dangerous Reaction is still executing on the
  agent's worker pool.
- **Per-Reaction completion is recorded, not just the chain's terminal outcome** — a crash mid-chain
  (Reaction 1 of 4 applied, agent restarts) leaves a durable record of *which* Reactions actually
  ran, so a later operator/automation pass has something to reconcile against, rather than a device
  silently wedged half-applied with no record of what happened.
- **A half-applied chain (the `reflex.aborted{restart}` case above) is never resumed and never
  compensated.** There is no re-entry point that picks a chain back up from Reaction 2 of 4, and no
  agent-side rollback of Reaction 1's effect — "aborted, never resumed" (Runtime shape, below) means
  exactly what it says: the chain that was interrupted is simply over. The chain **re-runs in full
  only on a NEW qualifying Spark edge** (a fresh fire, subject to the Reflex's own cooldown/hourly-cap
  budget like any other fire) — never as a resumption of the interrupted attempt. **This makes
  idempotent-on-reapply an authoring requirement for every Reaction in a chain**, one the compiler's
  safety chokepoint cannot enforce (it is a semantic property of the plugin action, not a syntactic
  one visible in the YAML): a Reaction that is not safe to run twice must not be authored into a
  chain a crash could leave half-applied and later re-fire whole. An operator's only visibility into
  a half-applied chain is the `reflex.aborted{restart}` outcome row itself plus the per-Reaction
  completion records above — there is no separate "partial chain" surface.
- **Deleting the last (or only) Reflex Set for an agent still pushes an empty `full_sync=true`** —
  there is no such thing as "nothing to push, so nothing is sent"; an empty collection is a real,
  delivered state, so an agent that was offline during the delete does not keep a stale dangerous
  chain armed indefinitely with no server record of the deletion ever reaching it.
- **Cooldown, hourly-cap, and fired/suppressed counters are journal-persisted, not in-memory-only** —
  they survive an agent restart and are **not** reset by re-arm (re-applying the same or a newer
  generation never gives a rate-limited Reflex a fresh budget it would not otherwise have earned).
- **The agent trusts the server (mTLS channel identity) for push authenticity and never independently
  re-verifies the `digest` field** — `digest` is a server-side approval-binding and compile-integrity
  mechanism (D9), not a second authentication layer the agent is expected to check; this is stated
  explicitly so no later slice adds agent-side digest verification believing it closes a gap that
  does not exist on the agent's trust boundary.
- **A pre-Reflex agent build** (one that predates `__reflex__` support entirely) reports "plugin not
  found" for `push_sets`/`get_status`, and — because it never composes the `yuzu.reflex_generation`
  heartbeat tag — the server-side reconcile that would solicit `get_status` never fires for it either.
  Such an agent's Reflex state is therefore reported as a fixed terminal status, **`unsupported`**
  (distinguishable from `--reflex-disable`, which does compose the tag with `yuzu.reflex_disabled=1`,
  and from "offline," which is a connectivity state, not a capability state).

Runtime shape (unchanged claims, restated alongside the semantics above):

- Reflex is a **queued** SparkEngine consumer (ADR-0021 Decision 3) — never inline. Per-Reflex-Set
  concurrency is 1 (serialized chain execution within a set); a worker pool of 2 serves all sets.
  **Reflex maintains its own arm/disarm chokepoint** — analogous to, but a *separate* seam from,
  Guardian's `GuardianEngine::reconcile_rule_locked()` (which is Guardian's own seam, not reusable by
  Reflex) — and its `stop()` is **sticky**: once stopped, Reflex does not re-arm without an explicit
  restart, matching the Spark/Guardian precedent.
- Detached, bounded reaction workers are counted into the agent's hard-exit grace sum — the same sum
  `GuardianEngine::active_io_workers()` feeds today (`guardian_engine.cpp`), summed alongside
  Guardian's own IO/send workers and Reflex's reaction workers under one name; **there is no
  `active_detached_workers()` rename** — a Reaction stuck in a blocking syscall cannot be joined or
  force-cancelled, so it must stay counted, never silently dropped from the sum (the same
  ORPHAN-EXIT CONTRACT `docs/yuzu-guardian-design-v1.1.md` §24 documents for Guardian's send
  executor).
- A chain in progress is journaled with a `chain:` marker; on agent restart, an in-flight marker is
  **aborted, never resumed** (`reflex.aborted{restart}` outcome) — Reflex chains are not
  crash-resumable.
- `event_id` sequence numbers are boot-nonce'd (see above), with the nonce sourced from a **CSPRNG,
  at least 64 bits wide** — a low-entropy (e.g. boot-second-derived) nonce risks an `event_id`
  collision across a crash-loop, which the store's PK-dedup would then silently drop as a
  "redelivery" of an unrelated event.
- Any Reflex maintenance work sharing a joined thread (journal paging, etc.) must carry its own
  `steady_clock` cadence — time-paced, never wake-paced (§24's journal-maintenance invariant applies
  verbatim; R8's `ReflexOutcomeJournal::maintenance_tick` implements this).
- **Cooldown/hourly-cap windows are measured on `steady_clock`, which is per-OS in its
  suspend-blindness.** A laptop's `steady_clock` typically halts across sleep on macOS/Linux but
  Windows' equivalent monotonic clock does not behave identically across all sleep states — a
  cooldown window can therefore span a different amount of real wall-clock time depending on OS and
  sleep behavior. This is a documented, accepted quirk, not a defect to fix here: `suppressed_total`
  and cooldown timing are **not cross-OS-comparable** aggregate metrics for exactly this reason.
- **`last_fired` (`ReflexStatus`) is the agent's own wall clock, not a server-authored timestamp** —
  an agent with a skewed clock reports a skewed `last_fired`, same as every other agent-authored
  timestamp on the platform; the server does not correct it. `fired_total` is journal-persisted (see
  above) and is never reset by a restart or a re-arm — only an explicit set-delete/redeploy resets
  the counter for that Reflex.

## Chokepoints future routes must clear

Named here so R7/R9/R11/R12 do not have to re-derive which existing gate applies — every future
Reflex-touching surface clears its **own** applicable set, never a new parallel mechanism:

- **Every new REST/MCP handler** (R7, R9's deploy/undeploy, R11's MCP twins) clears
  `require_permission`/`require_scoped_permission` (RBAC, including the service-scope confinement
  table) on the `Reflex` securable, has a `body_cap_policy.hpp` row (pre-auth request-body cap), and
  responds in the standard A4 envelope shape (`rest_a4_envelope.hpp`) — exactly like every other
  mutating REST route on the platform; this document does not invent a Reflex-specific exception to
  any of the three.
- **The `__reflex__` control leg** clears `CommandDedupStore`'s claim (see "Wire contract" above —
  claimed by default, `__guard__` is the only bypass) and the two-halves reserved-plugin-name
  intercept (load-time `plugin_loader.cpp`, dispatch-time `agent.cpp`), mirroring `__guard__`'s own
  server-side solicited-reply-drop and `get_status`-intercept handling in `agent_service_impl.cpp`.
- **`push_sets`** additionally clears the system-reserved-dispatch chokepoint (see "Wire contract"
  above — `SystemReservedPush`, `send_system_reserved`, the quarantine-gated-vs-exempt decision).

## Executions-history ladder stance

Reflex fire-and-react events are **agent-local automation, not operator-initiated dispatch** — they
get **no executions-tracker row and no SSE bus publish**. `notify_exec_tracker` — **server-side**,
in `agent_service_impl.cpp` (not agent-side; the agent has no executions-tracker concept to skip) —
and the server's ingest path both skip any id carrying the `__reflex__-` (command) or `reflex-`
(event) prefix. This is the **fourth** skipped id family, not a third: the existing set is
`polchk-*`, `preflight-*`, `deployment-*`, **and `bundle-*`** — `docs/executions-history-ladder.md`
is the accruing registry of record for the full list; R6/R10 additionally register the
`reflex-`/`__reflex__-` prefixes there when they land, rather than leaving this document as the
only place they are written down. **Any future SSE tile surfacing Reflex activity needs its own
`classify_reflex_event_for_scope` twin** (mirroring the existing per-consumer confined-projection
sanitizer pattern) and its own pin test — it must not be bolted onto the existing bus consumer set
without one.

## Outbox sharing and ingest limits

Reflex outcomes and Guardian drift events share the agent's single `__guard__` outbox (they are the
same wire channel, per "Wire contract" above) — this section defines the guards that stop Reflex
from starving Guardian, and Guardian's own enforcement evidence, of that shared, bounded resource.

- **Reflex outcomes get their own lane/quota inside the shared outbox** — a burst of Reflex
  `suppressed_sampled`/`fired` events (up to 32 reflexes × their own `max_per_hour` caps, across
  potentially several event types each) must not be able to fill the outbox and cause Guardian's own
  drift/remediation evidence to back up or drop. **The interim ordering rule, effective from R0:
  under backpressure, Guardian drift and remediation events are enqueued ahead of Reflex events** —
  Guardian is the compliance-enforcement plane and Reflex outcomes are a lower-priority evidentiary
  stream sharing its wire, so a full outbox drops or defers Reflex events first, never the reverse.
  The exact numeric reservation (a reserved slot count, a priority tier, or a per-family drop-oldest
  policy) is an R6/R8 implementation decision; only the *ordering itself* is settled here, so no
  implementation slice can pick a scheme that starves Guardian instead.
- **Every Reaction's `capture_output` is capped at 4 KiB, but the outcome as a whole is capped to fit
  the ingest clamp.** `GuaranteedStateEvent.detail_json` (which carries the whole `ReflexOutcome` as
  JSON) is subject to the server's existing ~16 KiB ingest clamp; today an over-cap `detail_json` is
  silently **cleared** before the `family` demux even runs. A chain with several captured Reactions
  can exceed 16 KiB (4 × 4 KiB raw, more once JSON-escaped) well before hitting any per-Reaction
  cap. The agent therefore applies a **per-Reaction truncation marker**: if the assembled
  `detail_json` would exceed the ingest clamp, later Reactions' `capture_output` is dropped from the
  payload and the JSON records which ones were truncated (`"truncated": ["reflex_id", ...]`) — the
  event still ships, with an honest record of what is missing, rather than being silently cleared to
  nothing by the server-side clamp.
- **Every fire produces exactly one terminal outcome row, or the loss is signaled.** `reflex_outcomes`
  is claimed as CC7.2 change-detection evidence (see "Observability" below); that claim is only true
  if a fired chain reliably produces exactly one terminal row (`completed`/`failed`/`aborted`). The
  outbox quota above, the truncation marker above, and the journal's own delivery guarantee together
  are what make this hold; if any of them cannot guarantee it in a given implementation, the CC7.2
  claim in "Observability" below must be narrowed or withdrawn in that slice's own PR text — it is
  not carried forward silently.
- **Evidentiary rows have a retention floor**, distinct from the operator-configurable TTL below: an
  operator setting the TTL very short must not be able to make CC7.2 evidence disappear before an
  auditor could plausibly review it. The exact floor value is an R10 decision (see the
  clock-guarded-retention adoption-register row it must record), matching the discipline the Periodic
  Access Reviews "no-prune" precedent (`docs/auth-architecture.md`) sets for evidentiary rows
  generally — this document requires a floor exists, not a specific number.

## Privacy (D10)

- Outcomes record end-user **choices**, not identity: button choice + timestamps + reaction results
  only, **never** free-text input, **never** a SID/username/user path. Device-scoped only. (See
  "Substitution tokens" above: resolved `{{spark.*}}` param values are explicitly excluded from this
  journal — "reaction results" means the Reaction's own outcome, not its resolved input params.)
- `capture_output` is opt-in per Reaction (default `false`), capped at 4 KiB, and a per-device
  outcome drill (including any captured output) is an **access-audited** surface via the existing
  `rest_audit.hpp` chokepoint (`emit_behavioral_audit`) — never a bare read. The drill's audit write
  follows a **named retention class** under `common/include/yuzu/audit_retention_rules.hpp`'s
  `classify` (assigned at R10, alongside a stated fail-closed-vs-set-and-proceed decision for the
  write itself — see `device.live.*`'s fail-closed precedent in the routed device-pages concern as
  the default lens, not an automatic copy). **`capture_output` is RAW plugin stdout/stderr — it is
  NOT covered by the "never a SID/username/user path" guarantee above by construction.** A
  `script_exec`-class Reaction can easily emit a diagnostic line containing a user path
  (`/home/alice/...`) on stderr with no malicious authoring required, which the bullet above's
  blanket D10(a) rule otherwise contradicts. This must be closed one of two ways, decided at R6
  (executor + outcome mapping) and stated in that slice's own PR text, not left implicit: either a
  **default-deny, per-action typed output projection** is applied before persistence (an action opts
  in only once its own projection strips identity-shaped content), or `capture_output` is
  **restricted to the subset of actions that define such a projection**, with every other action's
  `capture_output` refused at compile. Shipping raw, unprojected capture for every action is not a
  compliant reading of D10(a).
- Operator-configurable TTL on Reflex outcomes (D10d) — implemented as a clock-guarded retention
  sweep (`docs/clock-guarded-retention.md`; R10 records the adoption-register row), **bounded below
  by the evidentiary retention floor above** — the TTL can be lengthened by the operator, never
  shortened past the floor.
- Fleet-level aggregates are aggregate-first and floor at the shipped `kDexCohortFloor` (an
  aggregate over 1-2 devices is a de facto per-device view); per-device drill stays audited per the
  bullet above.
- Deliberately deferred to the works-council enablement backlog (not omissions): per-category
  collection toggle, an individual-view kill switch, pseudonymization.

## HA — background-job classification and readiness

Reflex introduces four pieces of server background work; each gets an explicit
`BackgroundJobClass` — one of exactly three enumerators (`ReplicaSafe`, `FencedLeaderOnly`,
`DisabledUntilFixed`; `server/core/src/background_jobs.hpp` — the live per-surface registry the
Fenced-leader-election routed concern requires every loop to consult, **never a second
"which loops are leader-only" list**). At implementation time (R9/R10/R13) each of these four
passes gets its own named row in `kBackgroundJobs` (a new side-effecting pass is a diff against
that array, never a silent addition, per its own header contract) and its dispatch site wraps in
`leader_gate_permits<background_job_class("<pass>")>(leader_elector_.get())` — the same pattern
`command_outbox.deliver` and `schedule_runner.tick` use today at their call sites in
`server.cpp`'s scheduling thread.

**Correction: that call-site wrapper is NOT the fence, and an earlier draft of this section said it
was — that was wrong and is corrected here.** `leader_gate.hpp`'s own header banner states this in
caps: **"THIS IS THE ATTEMPT GATE, NOT THE CORRECTNESS FENCE"** (`leader_gate.hpp:18`) —
`leader_gate_permits<>()` reduces to a lock-free `elector->is_leader()` read, and a momentarily-stale
leader (a paused-but-not-yet-fenced-out ex-leader) can still pass it. Relying on the wrapper alone as
the double-dispatch guarantee is exactly the CATASTROPHIC-IF-VIOLATED failure the Fenced-leader-election
routed concern's clause (1) names: **the actual guarantee against a paused ex-leader is
`LeaderElector::epoch_fence_sql()`, embedded directly in the durable claim's WRITE, never a cached
"I am leader" bool.** `command_outbox_store.cpp` is the shipped precedent for the shape:
`epoch_fence_sql(leader_lock_name, leader_epoch)` is spliced into the `WHERE` clause of the claim's
own `INSERT`/`UPDATE` statement (`claim_and_enqueue_on`, `command_outbox_store.cpp:148`; `mark_sent`,
`:307`; `mark_failed`, `:318`) — the fence lives IN the write, not beside it. **The Reflex
compile/`push_sets` loop (R9) — the `FencedLeaderOnly` row below — MUST follow this same shape**: the
durable write that claims or advances a device's target Reflex generation (whatever store row R9
lands to represent "this generation is now committed to push") embeds `epoch_fence_sql(expected_epoch)`
in that write's own `WHERE`/`INSERT ... WHERE` clause, exactly like `command_outbox_store.cpp` does —
either as a first-class fenced write of its own, or by routing `push_sets` through the existing
command-outbox primitive rather than inventing a second one. The `leader_gate_permits<>` wrapper at
the loop's dispatch site stays required too (clause 2 — it is what stops a non-leader from even
ATTEMPTING the compile/push in the first place, cheaper than reaching the fenced write on every
tick), but it is the attempt gate, not the correctness guarantee.

**Per clause 3 of the same routed concern, the OPERATOR-SYNCHRONOUS Reflex deploy path (the REST/MCP
deploy handler covered in "Chokepoints future routes must clear" above, which runs on whichever
replica received the request) must NOT be epoch-fenced.** It is arbitrated by its own guarded
compare-and-swap on the `ReflexSetStore` row (approval-digest match, R9) — the same two-dispatch-planes
split `PolicyEvaluator::dispatch_due` (leader-gated, fenced) vs `PolicyEvaluator::remediate`
(operator-synchronous, its own per-`(policy,agent)` CAS, never fenced) already establishes for policy
remediation. **So there are two distinct Reflex writes, arbitrated two different ways: the REST/MCP
deploy handler's write to `ReflexSetStore` (operator-synchronous — a guarded CAS, gates on the
approval digest, never epoch-fenced) is what an operator's deploy call performs; the background
compile/`push_sets` loop's claim-and-dispatch write (leader-driven — epoch-fenced per above) is what
turns an already-deployed, already-approved row into an actual push to agents.** Confusing the two
— fencing the operator path, or leaving the background path merely leader-gated without a fenced
write — is the violation this correction exists to prevent. R9 pins a paused-ex-leader regression
test proving a fenced-out replica's push attempt is rejected at the write, not merely skipped at the
gate.

| Loop | `BackgroundJobClass` | Why |
|---|---|---|
| `reflex_outcomes` TTL sweep (R10) | `ReplicaSafe` | A clock-guarded, advisory-locked SINGLE-WRITER retention pass (ADR-0012 per `docs/clock-guarded-retention.md`) is the textbook `ReplicaSafe` case per the enum's own definition — it matches every existing clock-guarded reaper in `kBackgroundJobs` (`response_store.reap_expired`, `guaranteed_state_store.reap_expired`, `session_store.reap_expired`, `app_perf_fleet_store.run_retention_prune`, `preflight_run_store.run_retention_prune`, `deployment_run_store.run_retention_prune`, `audit_store.cleanup_once` — all `ReplicaSafe`), none of which is `FencedLeaderOnly`. |
| Compile + `push_sets` dispatch (R9) | `FencedLeaderOnly` | Side-effecting singleton dispatch — two replicas independently pushing *different* generations of a dangerous Reflex Set to the same agent is a double-dispatch risk on a destructive surface, the same shape `schedule_runner.tick`/`command_outbox.deliver` are `FencedLeaderOnly` for today. |
| `get_status` reconcile-on-heartbeat (R9) | `ReplicaSafe` | Read-only census refresh; safe for every replica to do independently (mirrors `policy_evaluator.collect_ready`'s `ReplicaSafe` classification, not its sibling `policy_evaluator.dispatch_due`'s `FencedLeaderOnly`). |
| Fleet-metric delta tracking (R13) | `ReplicaSafe`, with the double-count rule stated at R13 | Each replica computes its own last-seen delta (mirrors `health_store.recompute_metrics`'s per-replica read-only gauge pattern); R13 must state how a multi-replica deployment avoids double-counting a delta two replicas both observe. |

**Both new Postgres stores join the server's `/readyz` conjunction** — `ReflexSetStore` (R3) and the
`reflex_outcomes` table (R10, inside the same store) are not readiness-invisible; a degraded Reflex
store must surface the same way every other `stores_ok` component does.

**Bounded resource shape, per agent:** a **ceiling on Reflexes-armed-per-agent** (distinct from the
existing ≤ 32-reflexes-per-*set* bound — an agent can have several sets deployed at once), a
**bounded per-agent Reflex job queue**, and a **stated drop policy** (oldest-first, matching the
existing `queue_dropped` counter's semantics) are all required — with a 2-worker pool and Reactions
up to 4 × 120 s each, many simultaneously-armed sets firing near-together can otherwise hold a
worker for minutes with no defined behavior for what happens to the rest of the queue.

## Observability — tags, metrics, audit verbs (reserved vocabulary; R8/R13 implement)

Heartbeat tags (composed by `reflex_heartbeat.hpp`, R8): `yuzu.reflex_running`,
`yuzu.reflex_generation`, `yuzu.reflex_sets_armed` always present; `yuzu.reflex_disabled=1` only
when `--reflex-disable`; sparse per-reflex counters omitted (not zeroed) when unused.

Fleet Prometheus families (R13): gauges
`yuzu_fleet_reflex_{reporting,disabled,sets_armed,unsupported}{os}`; counters
`yuzu_fleet_reflex_{fired,completed,failed,timeouts,queue_dropped,events_missed}_total{os}` plus
`yuzu_fleet_reflex_aborted_total{os,reason}` — the `reason` label follows
`docs/observability-conventions.md`'s standard bounded-label, pre-seeded-to-0 convention (the same
shape as `yuzu_nvd_sync_failures_total{reason}` and the `InstructionStore`/`RuntimeConfigStore`
degrade families), one series per named `reflex.aborted{<reason>}` cause used elsewhere in this
document (`restart`, `undeploy`, `unresolvable_fact` today). **`reason` is drawn from a fixed,
code-defined enum of named abort causes, mirrored server-side as its own `constexpr` array — the
same discipline as `kQuarantineGateOutcomes` and `kSystemReservedPushResults` in
`server/core/src/dispatch_confined_arms.hpp` — and is never a raw agent-reported string copied into
the label.** The abort cause arrives from the agent inside the event's `detail_json`, so the server
normalizes any value outside the known enum to a fixed `unrecognized` bucket before it can become a
Prometheus label; a later slice adding an abort cause extends the enum and the array in a code
change, never by accepting a new string at runtime. **The `os` dimension follows the fleet-rollup
absent-not-zero rule exactly as its `{os}`-only siblings do:** a given `os` has no `reason` series
at all until at least one agent of that OS reports an abort, and once that `os` is present every
known `reason` value is pre-seeded to 0 for it. This counter is what makes the "every fire produces
exactly one terminal row, or the loss is signaled" guarantee below actually hold for a plain watchdog/timeout abort that follows no sequence
gap, which previously had no fleet-level signal at all
(server-held, last-seen-delta with reset detection — a genuinely new fleet-metric shape this
document introduces, not a precedented one; R13 documents it in
`docs/observability-conventions.md` alongside landing it, since neither of that doc's two existing
fleet-gauge shapes covers a server-held delta counter); server-side
`yuzu_server_reflex_{deploy,compile_refused}_total` pre-seeded labels. **R13 reserves a
`yuzu-reflex` alert group** (`docs/prometheus/yuzu-alerts.yml`) covering `compile_refused` (page —
every dangerous set fleet-wide going refused at once is a silent mass-disarm), `queue_dropped`,
`events_missed`, and `unsupported`-vs-deployed drift — **no alert ships in R0 itself.**

Audit verbs (R7/R9/R10): `reflex.set.{create,update,delete,deploy,undeploy,approval_required,
compile_refused}`; `reflex.device_class.tag_set` (D4 write-gating, above); `reflex.outcome.view`
(per-device drill, ADR-0017 `authorize_list_read` confinement); `reflex.fragment.access_denied`
(dashboard, service-scoped-token confinement, R12).

**One table, outcome → per-agent status counter → heartbeat tag → fleet family**, so the three
partially-disjoint vocabularies above are read together rather than cross-referenced by hand:

| `event_type` | `ReflexStatus` counter | Heartbeat tag | Fleet family |
|---|---|---|---|
| `reflex.fired` | `fired_total` | (sparse, omitted when 0) | `yuzu_fleet_reflex_fired_total` |
| `reflex.completed` | — (implicit: fired without failed/timed_out/aborted) | — | `yuzu_fleet_reflex_completed_total` |
| `reflex.failed` | — | — | `yuzu_fleet_reflex_failed_total` |
| `reflex.timed_out` | — | — | `yuzu_fleet_reflex_timeouts_total` |
| `reflex.aborted` | — | — | `yuzu_fleet_reflex_aborted_total` *(reason-labelled; every abort increments this regardless of cause; one that ALSO follows a SparkEvent seq gap additionally increments `events_missed` — the two are not mutually exclusive, they count different things)* |
| `reflex.suppressed_sampled` | `suppressed_total` (agent-local, independent of sampling — see above) | — | `yuzu_fleet_reflex_events_missed_total` *(the sampled subset only; `suppressed_total` itself does not ride the fleet metric, only the per-device status)* |
| *(SparkEvent seq gap, no fired event)* | — | — | `yuzu_fleet_reflex_events_missed_total` |
| *(outbox drop)* | — | — | `yuzu_fleet_reflex_queue_dropped_total` |

`yuzu.reflex_sets_armed` and `yuzu.reflex_generation` are set-level/agent-level heartbeat tags, not
per-event counters, and have no row above by design.

SOC 2 rows (R13): CC6/CC8 two-person deploy control; CC7.2 change-detection evidence via the
outcome journal — **conditional on "Outbox sharing and ingest limits" above: every fire produces
exactly one terminal outcome row, or the loss is signaled** (the `yuzu_fleet_reflex_aborted_total`
reservation just above is part of what makes the "signaled" half hold). If that precondition cannot
be guaranteed in a given implementation, this CC7.2 claim must be narrowed or withdrawn in that
slice's own PR text per the same rule stated there — it is not carried forward silently just because
it is also written here.

## Pending routed-concern row (NOT added to `.claude/routed-concerns.md` — see reason below)

`.claude/routed-concerns.md` measures **37,810 of its 40,000-character budget** as of this writing
(`tests/test_issue_docs.py`) — 2,190 characters of headroom, not enough for the row below on its
own, and independently over the "pay-as-you-go" ~500-character self-funding threshold in
`docs/instruction-file-standard.md` (a PR that ships no code has nothing else in that file to trim
to self-fund it). This is a known, called-out possibility in this slice's own brief. **R1 owns
landing this row** — it lands the row text below (kept current against this file, re-copied if this
file's own consent/dispatch/wire wording has changed since) together with a ≥ 500-character trim
elsewhere in `.claude/routed-concerns.md` in the **same PR**, not deferred further. Copying this
text verbatim rather than hand-authoring a new version is the **discipline** that keeps the two
files aligned — it is not a mechanism that enforces it; no check currently catches the two drifting,
so treat this file as the correction point if they ever do:

> | Reflex — agent-local Spark→Reaction automated response (ADR-0021 D2/D4/D5/D6/D7/D8/D9/D10). Reflex is
> a SIBLING consumer of Spark, never a Guardian specialization (D2) — YAML-authoritative content
> (D7), deployed only as a Reflex Set (D4), gated on the dedicated `Reflex:Execute` securable (§24's
> `Push`-is-Guardian-only invariant is unaffected — Reflex never touches `crud_ops[]`/`Push`).
> CATASTROPHIC: (1) the **consent gate** — a dangerous Reaction (per `dangerous_reactions_in_spec()`,
> a SIBLING chokepoint to `dangerous_enforce_in_spec`, fed by `CommandCapabilityRegistry::classify`)
> is REFUSED unless all-server tag-consent (a direct `TagStore` read, byte-exact `"server"`,
> unclassified/absent = workstation) holds — independent of escalation policy. **v1 has NO chain
> consent** — all five `interaction.*` actions are themselves dangerous
> (`ExecuteGate::AdminOrApproval`), so a chain-consent rule cannot bootstrap its own first consent;
> chain consent is a future extension, not yet designed, and no `interaction.*` Reaction can run on a
> workstation-class device in v1. **Because that tag is v1's ENTIRE consent boundary, writing
> `device_class` is not a bare `Tag:Write`**: it requires `Reflex:Write` or admin, is audited under
> `reflex.device_class.tag_set`, and EXTENDS `authz::service_scope_may_mutate_tag_key` (checked
> BEFORE the scoped gate, value-blind) — never a parallel gate; (2) **digest-bound two-person approval**
> (D9) from a DISTINCT HUMAN ROOT (ADR-0033 §7), recomputed and compared at every compile, 409 on
> review-time drift, fail-closed on mismatch — break-glass is a NEW, not-yet-built ApprovalManager
> capability; (3) Reflex Reaction EXECUTION (never `push_sets`, which IS a dispatch site) is
> agent-LOCAL (`LocalDispatcher`), authorized ONCE at deploy by (1)+(2) — never
> `classify_and_authorize_dispatch`/`DispatchCaller`; do not conflate the two. (4) Outcomes live in a
> Reflex-only table (`reflex_outcomes`), demuxed at the shared Guardian ingest router by a CLOSED-SET
> `GuaranteedStateEvent.family` (`""`/`"guardian"`/`"reflex"`, unknown value refused) — `rule_id`
> stays EMPTY for reflex rows, and Guardian's blast-radius/alert-router observers MUST NOT fire on
> one. (5) No executions-ladder tracker row / SSE bus entry for `reflex-*`/`__reflex__-*` ids — a
> future SSE surface needs its own `classify_reflex_event_for_scope` twin; `__reflex__` control
> commands stay CLAIMED through `CommandDedupStore` (`__guard__` is the only bypass). |
> `docs/reflex-design.md` + `docs/adr/0021-spark-reflex-architecture.md` (Amendments) |
> `security-guardian` + `cpp-safety` + `docs-writer` on `reflex_*.{hpp,cpp}`,
> `agents/core/include/yuzu/agent/reflex_engine.hpp`, `proto/yuzu/reflex/v1/reflex.proto`, the
> `__reflex__` intercept in `agent.cpp`, or `GuaranteedStateEvent.family` handling in
> `guardian_ingest.cpp` |

## Cross-references (for the slices that implement this document)

R1 (`__reflex__` reserved name), R2 (Spark-consumer hoists), R3 (`ReflexSetStore` schema), R4 (YAML
validator + safety/consent chokepoints), R5 (Spark runtime), R6 (executor + outcome mapping), R7
(REST + RBAC — owns `docs/agentic-first-principle.md` A4/A5 for its new REST routes), R8 (agent
wiring), R9 (deploy/approval/push), R10 (ingest/outcomes/TTL), R11 (MCP twins — owns A4/A5 for its
new MCP tools), R12 (dashboard), R13 (observability), R14 (macOS proof — Demo A/B end-to-end
evidence; not yet given its own `docs/roadmap.md` Phase 20 issue number, tracked under the phase as
a whole until one is filed).

**Slice → roadmap mapping.** All fourteen R-slices above implement this single document; none maps
1:1 onto `docs/roadmap.md` Phase 20's four Issue rows (20.1-20.4), which group by *capability*, not
by *slice* — R3/R4 together deliver 20.1, R9 delivers 20.2, R1/R2/R5/R6/R8 together deliver 20.3, and
R7/R10/R11/R12/R13 together deliver 20.4. R14 (macOS proof) cuts across all four and is not its own
Issue row.
