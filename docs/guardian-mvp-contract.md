# Guardian MVP — Frozen Contract & Design Decisions (Windows-first)

> **Status:** core contract locked 2026-05-30 (open items tracked in §10). This document is the build basis for two
> work streams: the **agent/server backend** (built first) and the **Guardian
> dashboard** (built in a separate conversation against this contract). It records
> decisions reached in a design grill and the **deltas they imply against
> `docs/yuzu-guardian-design-v1.1.md`** — where the two disagree, *this document
> wins for the MVP*, and the design doc should be reconciled to v1.2 in a later pass.

## 1. Purpose

Stand up a **demo-grade, Windows-first** vertical slice of Guardian: a predetermined
registry value is altered → Guardian detects the drift on-box → reports it → it shows
up server-side. **Detect-and-alert first**, then detect-and-**remediate**. The rule
must enforce **locally, offline, within milliseconds** — no server round-trip on the
hot path.

**Cross-platform note:** "Windows-only" scopes the **agent enforcement side** of this
MVP — the Spark/guard implementations. The *contract* (proto, REST, store, status,
Baselines, schema registry) is **platform-agnostic by construction** and must stay
that way: future iterations add **Linux** (next; design §15–18) and **macOS** (after;
§19–22) purely by registering new Spark/Assertion *types* (inotify/netlink/sysctl
sparks, `config-value-equals` assertions, …) and platform-gating new guard sources in
meson — **no wire/contract changes**. Per-machine applicability is the Guard's
`os_target`/precondition; never bake Windows-isms into a contract surface.

**Non-functional bar:** NFRs are held **exceptionally strong** throughout, not bolted on —
performance, scalability, reliability, resource use, and especially **network-kindness**
(fleet scale: thousands of agents, so redundant chatter multiplies). Every decision below
is expected to pick the lean option: event-driven over periodic resend; cheap signals
(generation ints, digests) on channels that already fire, rich payloads only on
divergence; dedup / bound / debounce; the enforcement hot path stays off the network and
off locks. See memory `feedback-nonfunctionals-exceptionally-strong`.

## 2. Current state (what is already landed)

- **PR 1 (proto + store):** `proto/yuzu/guardian/v1/guaranteed_state.proto`
  (package `yuzu.guardian.v1`); `GuaranteedStateStore` (`guaranteed-state.db`,
  `rules` + `events` tables, CRUD, batch event ingest, retention reaper), wired in
  `server.cpp`, metrics `yuzu_server_guardian_*`.
- **PR 2 (control-plane skeleton):** REST `/api/v1/guaranteed-state/{rules,push,events,status,alerts}`
  (RBAC securable `GuaranteedState`); **`/status` and `/alerts` are hardcoded
  placeholders.** Agent `GuardianEngine` **stub** — persists pushed rules to KV under
  namespace `__guardian__`, answers `get_status` by reporting **every rule `errored`**
  (honest: no guards run yet), **emits no events**. `agent.cpp` wires `start_local()`
  (pre-Register), `sync_with_server()` (post-Register, reserved for the event drain),
  `__guard__` dispatch, `stop()`.

**Gaps this MVP closes:** no Spark/guard runs (no detection); the agent emits no
events; **`agent_service_impl.cpp` has no `__guard__` event/status handler** — the
server literally cannot ingest a drift event today; no status storage; no dashboard.

## 3. Vocabulary (placeholders — renameable later, see §5 deltas)

| Term | Meaning | Notes |
|---|---|---|
| **Guardian** | the engine/product | settled |
| **Baseline** | a deployable, scopable collection of Guards | control-plane only |
| **Guard** | one enforced unit = Spark + Assertion + remediation | was design's "Rule". **MVP code = `GuaranteedStateRule`/`rule_id` (G5)**; post-rename target id `GuardianGuard`/`GuardDef` (bare `Guard` too generic) |
| **Spark** | the trigger — detection mechanism that fires evaluation (registry-change, ETW, service-status…) | was design's "Guard" (detection component); renamed to avoid the existing **Trigger Engine** collision; **placeholder, disliked** |
| **Assertion** | the desired-state check ("value must be 1") | **placeholder, disliked** |
| **remediation** | `alert` or `remediate` (+ method/params/decisions) | |

Placeholders are safe to use: they live as concept/field names, never as
wire-format-defining values (type discriminators are `"registry-change"` /
`"registry-value-equals"`, not `"spark"`). Proto **field numbers** are the wire
contract; renaming a field/message is source churn only.

**Naming during the MVP (G5):** the table above is the *target* ubiquitous language —
what docs/UI/this contract use. **MVP *code* keeps the existing `GuaranteedState` /
`rule_*` identifiers** so the subsystem stays internally consistent; one dedicated PR
renames everything to `Guardian`/`guard` over a consistent codebase soon. So in MVP
code, "Guard" = `GuaranteedStateRule`/`rule_id`, "Baseline" = `guaranteed_state_baselines`,
etc. Net-new concept words with no prior name (`spark`/`assertion`/`remediation`) are
used as-is — they aren't renames, so they create no split-brain.

## 4. Frozen contract

1. **Typed Protobuf is the agent's source of truth for what to enforce.** The agent
   **never parses YAML** (honors the project's no-runtime-YAML stance, #625, and
   "Protobuf is the source of truth for the wire protocol"). `yaml_source` becomes a
   **server-generated, read-only rendering** for display/audit/diff.
   *Defended vs the Instruction Engine convention: instructions also execute from
   structured wire data, not parsed `yaml_source` (the runtime never reads YAML;
   `InstructionDefinition` carries structured columns alongside `yaml_source`). Only the
   authoring-time derivation arrow flips — Guardian rules have no build step, so the
   structured form is authored-first instead of derived-at-build.*

2. **The authoritative, signed artifact is the canonical JSON (RFC 8785 / JCS) of the
   structured Guard** — sorted keys, compact, NFC-normalized at authoring — *not*
   `yaml_source` and *not* raw proto bytes (proto serialization is non-deterministic,
   and a `gpb`↔`protoc` gateway hop would break byte-signing). Signing surface =
   identity (`guard_id`, `name`, `version`) + `spark` + `assertion` + `remediation` +
   `enforcement_mode` + `enabled`. `yaml_source` renders one-way from this form, so it
   can't drift. When signing lands (deferred PR 12), HMAC is over these canonical bytes.
   (Delta to design §11.2.) *See G3.*

3. **A Guard is three `{type, map<string,string> params}` blocks** — `spark`,
   `assertion`, `remediation` — plus `enabled`/`enforcement_mode`/`version`. New
   Spark/Assertion/remediation **types are added by registering a JSON Schema, not by
   editing the proto.** The **agent never sees schemas** (it reads param values by key,
   dispatching on `type` — same pattern as `CommandRequest{action, map parameters}` and
   `InstructionDefinition.parameter_schema`).
   **The schema registry is an agentic-first discovery surface, not a dashboard
   convenience (A1 parity / A2 discovery):** the catalog + per-type JSON Schemas are
   exposed on **every plane — a REST endpoint *and* an MCP resource/tool** (the
   dashboard is one consumer). Schemas **encode value-dependent formats as discriminated
   subschemas** (JSON Schema `if/then` / `oneOf` keyed on a discriminator such as
   `value_type`) so the per-type encoding is machine-discoverable, not prose. Authoring
   validation failures return the **A4 structured error envelope**
   (`rest_a4_envelope.hpp`) so an agent self-corrects. Inputs are accepted leniently,
   **stored + returned canonical**; `GET` echoes the canonical form a caller would
   re-`POST`.

4. **Event reporting — push enforces / reports observe / server enriches.**
   - `event_type` is an **open string** over a **frozen v1 taxonomy**:
     `drift.detected`, `guard.armed`, `guard.compliant`, `guard.unhealthy` (MVP);
     `drift.remediated`, `remediation.failed` (remediate); `resilience.escalated`,
     `reconciliation.swept` (later). Unknown types render generic, not broken.
     `guard.compliant` is the agent's **on-change** signal that a watched value is at /
     returned to expected (emitted on the compliant↔drift edge only, never in steady
     state); it drives the server-side compliance census (`guardian_agent_rule_status`).
   - The agent reports **observation-only** fields (`rule_id`/guard id, `event_type`,
     `guard_type`, `guard_category`, `detected_value`, `expected_value`,
     `detection_latency_us`, agent-stamped `timestamp`; + `remediation_*` on remediate
     events).
   - The **server stamps `agent_id`** from the **cert-bound, authenticated session**
     (#827 agent_id↔session, #1118 mTLS identity; `agent_service_impl.cpp` Subscribe).
     The event proto has **no `agent_id` field by design** — it can't be spoofed.
   - The server **enriches** `rule_name` and `severity` from the rule store by id
     (deleted-rule edge → `"unknown"`). Severity/description/tags are **never pushed
     to the agent** (display metadata only).

5. **Status — dedicated table, push-reported, server-aggregated, staleness-first.**
   - New table `guaranteed_state_agent_rule_status` (G5 naming), one row per `(agent_id, rule_id)`:
     `status`, `drift_count`, `remediation_count`, `last_evaluation`, `last_drift`,
     `guard_healthy`, `last_notification`, `consecutive_remediation_failures`,
     `last_remediation_error`, `resilience_state` (`retrying|open|terminal`),
     `updated_at`. **Status is NOT derivable from the events table** (absence of a
     drift event ≠ compliant).
   - **Reported by push** on the `__guard__` channel: a full snapshot once at
     `sync_with_server`/reconnect, then **only on a per-guard status transition** —
     **no periodic rich resend** (network-kind). Liveness comes from the Heartbeat
     (Decision 9), which carries a cheap `guardian_status_digest`; the server pulls a
     full status only on digest mismatch. `get_status` (pull) stays for on-demand
     refresh. `agent_id` server-stamped as in §4.
   - **Taxonomy (open string, frozen):** `compliant`, `drifted`,
     `remediation_failed` (detected, fix attempted, unsuccessful — distinct from
     `drifted` and from `errored`), `errored` (guard deaf — compliance unprovable),
     `exempt` (precondition excludes), `stale` (**server-derived from heartbeat
     freshness** — no heartbeat within N× the interval; *not* from status-push freshness,
     since status is transition-only; never agent-reported).
   - **Rollups** across **fleet / guard / agent / management-group / baseline** are
     `GROUP BY`/`JOIN` over the per-`(agent,guard)` rows. Management-group rollup
     **JOINs the existing `ManagementGroupStore` membership** (hierarchy-aware), no
     denormalized column. Each rollup carries **per-state counts** + a **worst-of
     badge** (`remediation_failed`/`errored` red > `drifted` amber > `compliant`;
     `exempt` out of denominator; `stale` surfaced distinctly).

6. **Baseline — control-plane only; the agent never hears the word.** Deploying a
   Baseline = the **server expands it to its member Guards and pushes Guards** (push =
   enforcement-only). `InstructionSet`-shaped store (`guaranteed_state_baselines`).
   **M:N to Guards via a join table** `guaranteed_state_baseline_rules(baseline_id,
   rule_id)` **from day one** (don't build the 1:N one-way door). An agent's effective Guard set = **set-union of Guards from every
   deployed Baseline whose scope includes that agent** (dedup; re-push via the proto's
   `full_sync`). Provenance ("why is this Guard here?") is a server-side query, not
   stored state. No behaviour conflict is possible because **the Guard owns its
   behaviour; the Baseline only groups + scopes.**

7. **Deploy/scope — Baselines are the *only* deployable/scopable unit.** Device scope
   attaches to the **Baseline** (reusing the **existing Scope engine/DSL** — do not
   fork one; the platform is consolidating on a single scope engine). Per-machine
   applicability is handled by the Guard's **precondition / `os_target`** (agent-side),
   orthogonal to device scope. Single-Guard Baselines cover the "deploy one Guard"
   case. Matches Intune/Jamf "assign profiles to groups."

8. **Rename — GuaranteedState→Guardian and rule→guard, incremental, folded together.**
   See memory `project-guardian-rename`. The proto package, metrics, KV namespace, and
   plugin name are already Guardian; the lagging half is the server store / REST / RBAC
   / audit / proto-message-names. **Not a global find-replace** — RBAC securable
   string, REST v1 paths, DB table/file names, and audit verbs each carry persisted
   data / public-contract weight and need migration + compat. **For the MVP, new
   surfaces keep the existing `GuaranteedState`/`rule_*` naming (G5)** for internal
   consistency — a complete rename over a consistent codebase is mechanical and
   low-risk; a split `guardian_*`-beside-`guaranteed_state_*` base is where rename bugs
   hide. Target vocabulary (Guard/Baseline/Spark) lives in docs/UI; code identifiers lag
   until the dedicated rename PR.

9. **Guard distribution & sync — push + heartbeat-reconcile.** Delivery is one path: a
   Subscribe-stream push (`__guard__ push_rules` via `agent_registry.send_to()`). Three
   triggers: **immediate** (any Guard/Baseline/deploy change), **startup** (enforce
   cached Guards from KV pre-network via `start_local`; reconcile post-network via
   `sync_with_server`), **periodic/reconnect** (every Heartbeat the agent reports its
   applied `policy_generation` in `HeartbeatRequest.status_tags`; the server compares
   and pushes if behind). `policy_generation` is the convergence primitive (already in
   proto + agent KV) — a **global counter** for the MVP (per-agent effective-set content
   hash is the scale-correct successor, deferred). No new RPC/loop: the existing
   periodic Heartbeat is the *check*, the existing push is the *delivery*. Also closes
   the reconnect half of G6. The heartbeat additionally carries a cheap
   `guardian_status_digest` (sibling to `policy_generation`) so lost status transitions
   converge without any periodic rich status push (N2, network-kind).

10. **Operational safety — debounce / races / retry** (design §6.5 / §8.4 / §8.5).
    - **Debounce is three levels:** *input* (per-Spark `debounce_ms`, default `0` —
      Slice A), *remediation* (per-Guard ~5ms re-entrancy window absorbing the
      self-triggered write — Slice C), *audit/event* (per-Guard collapse of >3 identical
      events/1s into one event-with-count — **Slice A, default-on**, so a thrashing value
      can't flood the store even in alert-only).
    - **Races:** the RegNotify *re-arm gap* is backstopped by a **reconciliation sweep**
      (periodic re-read+compare — **Slice A**; reconciliation checks *state*, Decision 9
      checks *policy* — orthogonal). *Self-remediation* re-entrancy and *drift-storm*
      (RaceDetector, sliding-window drifts/s) are **Slice C**. Store writes use
      **`RETURNING`**, never `sqlite3_changes()` (#1033).
    - **Retry = resilience strategies** (`remediation.resilience`): `Fixed` / `Backoff`
      (`initial_delay`/`multiplier`/`max_delay`/`jitter`) / `Escalation` (`steps[]` of
      `method`+`params`+`max_failures`+`retry_delay`, `on_exhausted`) — config grammar
      per §6.6. **Slice C**, already observable via the decision-5 status columns.

11. **Offline durability — events durable, status not.** **Status** is a snapshot:
    recomputed and reported on reconnect, **no buffer** (Decision 9 handles policy
    convergence). **Events** are an append-only log → a **durable, bounded local
    journal** (reuse the agent's SQLite/KV; table keyed by monotonic `event_seq` +
    `event_id` UUID; design §3.1): append off the hot path (MPSC + writer thread, §8.3),
    drain on `sync_with_server` + periodically when connected, **delete only after server
    ack** (~~at-least-once~~; the server dedups by `event_id`). **Bounded** (ring-buffer
    eviction + an "N dropped" marker), pressure cut by Decision 10's audit/event
    debounce. Journal **HMAC integrity deferred** (PR 12). The **G2 event-sink is
    durability-agnostic**, so the first demo may use an in-memory queue and upgrade to
    the durable journal with **no wire/contract change** — the durable journal is the
    standing target.

    **Superseded (2026-07-21):** this is a documentation correction, not a behaviour
    change - delete-only-after-server-ack was never actually built this way; only the
    struck-through delivery-guarantee framing above was ever wrong. The rest of this
    decision (append-only log, bounded ring-buffer, HMAC-deferred, durability-agnostic
    event-sink) stands as designed and built. The delivered journal's guarantee is
    crash-durable, duplicate-tolerant, bounded-retry redelivery, not true at-least-once
    (no server batch-ack); deletion is retention-driven instead, and an entry that ages
    out unacknowledged is a rare, counted loss, not silent. The "N dropped" ring-buffer
    marker referenced above has the same live-visibility gap as that counter - no
    dashboard/REST/MCP surface exposes either today (tracked #2298). See [Reconnect
    replay
    traffic](user-manual/guaranteed-state.md#reconnect-replay-traffic-durable-lifecycle-journal)
    and the `yuzu_server_guardian_events_redelivered_total` row in [Guardian
    metrics](user-manual/metrics.md#guardian-metrics) for the shipped characterization.

## 5. Deltas / amendments to `yuzu-guardian-design-v1.1.md`

- **§6/§7 (DSL & wire):** the agent enforces from **typed proto structured blocks**,
  not parsed `yaml_source`. Extend `GuaranteedStateRule` with `spark`/`assertion`/
  `remediation` `{type, params}` blocks (additive, proto-compat-safe). `yaml_source` →
  server-generated rendering.
- **§11.2 (signing):** HMAC over the **canonical JSON (JCS / RFC 8785) of the
  structured Guard**, not `yaml_source` and not proto bytes. (See G3.)
- **§7.1 (`GuaranteedStateEvent`):** `agent_id` server-stamped (no agent field);
  `rule_name`/`severity` server-enriched.
- **§7.2 (wire integration) — G2:** `CommandResponse` had no `plugin`/`action` field,
  so the design's `__guard__` event/status framing was not buildable. **Add additive
  `string plugin=7; string action=8; bytes payload=9;` to `CommandResponse`** (core
  `agent.proto`; proto-compat-safe). Guardian routes via an early intercept in the
  server Subscribe read loop; binary payloads use `payload` (`bytes`), not `output`
  (`string`) — also fixes the existing `get_status` binary-in-string issue.
  **Also add `string event_id` to `GuaranteedStateEvent`** (agent-generated, stable
  across retries) — required for G6's ~~at-least-once~~ dedup; the proto had no event id (N1).
  The dedup mechanism itself is unchanged; the "at-least-once" delivery-guarantee framing
  was later narrowed - see the Decision 11 superseded-note above.
- **New — status storage:** the design folded "fleet aggregation" into PR 4 but
  specified **no status storage**. This contract adds the `guaranteed_state_agent_rule_status`
  table + push-status reporting + real `/status` aggregation + staleness.
- **New — Baseline grouping layer** (M:N, baselines-only-deploy). Not in v1.1.
- **Status taxonomy** adds `remediation_failed` and `stale`.
- **Vocabulary:** rule→**Guard**; detection-component "Guard"→**Spark**; +**Baseline**.

## 6. Deferred (out of MVP; design preserves room)

- **Two-person integrity / approval workflow for *enforce* Baselines** (design §11.1)
  — **essential for the product, explicitly not in this MVP.** Alert-only bypasses
  approval anyway; grill the approval contract at the **remediate phase**.
- **Single unified platform scope engine** — acknowledged future consolidation, not
  scheduled (memory `project-single-scope-engine`). MVP reuses the existing engine.
- **M:N Baseline-membership UX** and **per-Baseline `enforcement_mode` override**
  (alert-here/remediate-there) — schema is ready (join table can later carry an
  optional `mode_override` column); UX/behaviour deferred.
- **Rule signing** (HMAC over structured form) — model agreed, implementation later.
- **Schema↔handler single-source generator** (G9 risk) — a type's server JSON Schema and
  its agent handler are hand-kept-in-sync for the MVP (guarded by a cross-check test);
  generating both from one definition to eliminate drift is a later refinement.
- **`registry-write` remediation threat model + dangerous-target guardrails (Slice-C
  gate).** An operator-authored `registry-write` is, in effect, arbitrary SYSTEM-privileged
  mutation across every in-scope endpoint — the class of feature where this codebase has
  shipped CRITICAL injection vulns when governance was skipped (CLAUDE.md). Before the write
  path lands: a threat model + dangerous-key **denylist** (`…\Run`, `Image File Execution
  Options`, service-config keys, …) + bounds on what a single `Push` principal can do. Not
  needed for Slice A (alert-only, no writes); `security-guardian` will require it for Slice C.

## 7. Build sequencing (backend, this conversation)

- **Slice A — detect-and-alert, real push path (the demo):**
  proto: add `spark`/`assertion` blocks → REST create accepts a structured Guard,
  server renders `yaml_source` + denorm + canonical form → **build the Guardian push
  fan-out** (the current `/push` is a stub — G12; resolve scope via the existing Scope
  Engine + deliver via `agent_registry.send_to()`, reusing the instruction-dispatch path)
  → typed `push` →
  agent: parse typed proto (no YAML), **Registry Spark** (`RegNotifyChangeKeyValue` +
  `WaitForMultipleObjects`, lift `trigger_engine.cpp:365-463`), minimal evaluator
  (`registry-value-equals`), emit `drift.detected` →
  agent→server drain via an **event-sink** wired in `agent.cpp` — writes
  `CommandResponse{plugin:"__guard__", action:"event", payload:<GuaranteedStateEvent>}`
  via the existing async stream writer under `stream_write_mu_` (needs the G2 proto
  fields) → **server ingest:** a branch **at the top of the Subscribe read-loop body, before the RUNNING/terminal status
  split** (`agent_service_impl.cpp` ~L897, **status-agnostic** — *not* inside the `RUNNING`
  branch where `__timing__` sits, or a `status=SUCCESS` Guardian message falls through to
  the terminal `else` and is mis-routed into the response store) routes
  `plugin=="__guard__"` by `action` — `event` → `insert_event` (stamp cert-bound
  `agent_id`, enrich name/severity), then `continue` (skips response store +
  executions tracker).
  *Verify on native Windows: author Guard → push → flip `HKLM\SOFTWARE\YuzuTest\Flag`
  → `GET /api/v1/guaranteed-state/events` shows the drift (<100 ms).*
  Slice A also lands the **startup self-test** (sentinel round-trip → `guard_healthy` +
  `guard.armed`/`guard.unhealthy`; proves kernel wiring, N3), the **reconciliation
  sweep** (startup + interval re-read/compare — the re-arm-gap *and* post-startup-deaf
  backstop, G8 / Decision 10), **audit/event debounce** (collapse-with-count), and the
  Decision 9 startup/heartbeat reconcile. Events flow through the durability-agnostic
  event-sink (Decision 11) — in-memory queue acceptable for the first demo, durable
  journal the near-term default.
  **Decompose (L1):** **A1** = bare detect → event → ingest demo, *including the G12 push
  fan-out* (the long pole — core distribution, not demo scaffolding; "real path"
  reconfirmed); **A2** = self-test + reconciliation + debounce; **A3** = durable journal.
  Resist A1 swelling into "the whole backend."
- **Slice B — status:** `guardian_agent_rule_status` table + push-status reporting +
  real `/status` aggregation + staleness.
- **Slice C — remediate:** `remediation` block (`registry-write`), `drift.remediated`/
  `remediation.failed` events, `remediation_failed` status, minimal resilience; then
  grill the approval contract.
- **Baseline entity:** tables + REST + deploy=union-expansion (needed before the
  dashboard's manage/deploy; can land alongside B/C).

Offline/ms requirement is structural: Guards run locally from KV-cached typed rules;
the Spark→evaluate→remediate loop never calls the server (design §3.2, §4, §8.3).

## 8. Dashboard handoff (separate conversation)

**Requirements (operator-stated):** view current status of active Guards across
**fleet / per-guard / per-agent / per-management-group / per-baseline**; **make /
manage / deploy** Guards and Baselines. A Guard is composed as **Spark (+params) →
Assertion → alert|remediate (+params/decisions)**; **Baseline scope** sets the device
targeting. Deploy is **Baseline-level**. "Refinement and additional detail to follow."

**Server surfaces the dashboard consumes (must exist before/with the dashboard):**
- schema-registry **discovery surface (REST + MCP)** — Spark/Assertion/remediation type
  catalogs + per-type JSON Schemas (discriminated subschemas for value-dependent
  formats) + A4 validation errors; drives dynamic forms, but the dashboard is one
  consumer (A1/A2);
- structured create/update for Guards and Baselines (server derives canonical +
  `yaml_source` + denorm);
- deploy (Baseline → union-expand → push); Baseline ↔ Guard membership (M:N);
- `/status` aggregations (fleet/guard/agent/MG/baseline + staleness) + `/events`
  timeline;
- scope picker — **reuse the existing Scope engine** surface, do not invent one.

**Conventions (non-negotiable):** HTMX, server-rendered, **dark-theme only**; **do not
use the `frontend-design` plugin** (product UI, not marketing). Page pattern:
`compliance_ui.cpp` (HTML shell) + `compliance_routes.cpp` (routes); fragments at
`/fragments/guardian/...`; add a **Guardian** nav link to every page nav bar
(~10 files). RBAC securable `GuaranteedState` (→ `Guardian` after rename).

## 9. Grill resolutions (decisions log)

- **G2 — agent→server event/status transport (RESOLVED: Option A).** `CommandResponse`
  has no `plugin`/`action` field (verified `agent.proto:143-160`), so the design's
  `__guard__` event wire was not buildable, and unsolicited events have no `command_id`
  to correlate. **Add additive `string plugin=7; string action=8; bytes payload=9;` to
  `CommandResponse`.** The agent writes Guardian events/status via the existing async
  stream writer; the server's Subscribe read loop gets a branch **at the top of the loop
  body, before the RUNNING/terminal status split** (`agent_service_impl.cpp:897`; *not*
  inside the RUNNING branch where `__timing__` sits — a `status=SUCCESS` Guardian message
  would otherwise fall through to the terminal `else` and mis-route) that routes
  `plugin=="__guard__"` by `action` and `continue`s — keeping Guardian out of the response
  store / executions drawer, reusing the cert-bound `agent_id`. `bytes payload` also fixes the existing
  `get_status` binary-in-`string` (`output`) issue. Core-proto change → architect /
  build-ci + proto-compat (additive, safe). *Rejected:* B (`command_id`-prefix
  convention — stringly-typed, conflates routing with correlation); D (dedicated RPC —
  re-plumbs the cert-bound identity Subscribe already gives us).
- **G3 — canonical/signed form (RESOLVED: canonical JSON).** "Canonical serialization"
  was undefined and proto serialization is non-deterministic (map ordering; the
  `deterministic` option is "stable within a binary," not across versions/languages/
  time — and Yuzu's Erlang `gpb` gateway hop is a second impl that would break
  byte-signing). **Authoritative + signing surface = canonical JSON (RFC 8785 / JCS):**
  sorted keys, compact, NFC-normalized at authoring; over identity + spark + assertion
  + remediation + enforcement_mode + enabled. Decouples signing from proto evolution
  (matters given the active rename), is inspectable for forensic diff, and reuses
  existing `nlohmann/json`. Must be a deliberately-implemented, JCS-vector-tested
  function (naive `dump()` is not canonical). Implementation deferred with signing
  (PR 12); definition locked now. *Rejected:* proto-deterministic (no cross-impl/time
  guarantee; gateway hop).
- **G4 — registry value typing + agentic-first encoding (RESOLVED).**
  `map<string,string>` can't distinguish `REG_DWORD 1` / `REG_SZ "1"` / `REG_BINARY 01`.
  `registry-value-equals` params: `hive` (HKLM|HKCU|HKCR|HKU|HKCC), `key`, `value_name`
  (`""`=default), `value_type` (REG_DWORD|REG_QWORD|REG_SZ|REG_EXPAND_SZ|REG_BINARY|
  REG_MULTI_SZ), `expected` string-encoded **per type**: DWORD/QWORD = decimal (accept
  `0x…` → canonical decimal); SZ/EXPAND_SZ = literal; BINARY = lowercase hex, even
  length; MULTI_SZ = JSON-array-string (deferred). Evaluator compares **type-aware**
  (`value_type` mismatch = drift); the **same encoding feeds `registry-write`
  remediation** (`RegSetValueExW`). Chosen over a typed proto `oneof` because
  string-in-JSON is cleaner for REST/agentic authoring than proto3-JSON + base64, and
  preserves decision-3 extensibility. **Promotes decision 3** to an agentic-first
  discovery surface (REST + MCP, discriminated subschemas, A4 errors, lenient-in/
  canonical-out). Reinforces G3 (all values are strings → no float canonicalization).
- **G5 — `rule`/`guard` naming seam (RESOLVED: consistency-now).** The draft mixed
  `guardian_*`/`guard_id` with the proto's `rule_id`. Per the user (new to the project,
  minimize churn now, but rename completely soon): **MVP code keeps existing
  `GuaranteedState`/`rule_*`** (`guaranteed_state_baselines`,
  `guaranteed_state_baseline_rules`, `guaranteed_state_agent_rule_status`; REST under
  `/guaranteed-state/`; proto keeps `GuaranteedStateRule`/`rule_id` + additive
  spark/assertion/remediation blocks). Target vocab in docs/UI only; one dedicated
  complete-rename PR soon over a *consistent* base (safer than a split). *Reverses* the
  earlier "born Guardian" lean and updates memory `project-guardian-rename`.
- **Decision 9 — Guard sync (RESOLVED: push + heartbeat-reconcile).** Verified the
  Heartbeat RPC + periodic heartbeat thread (`agent.cpp:1194`) + `status_tags` map +
  `agent_registry.send_to()`. One Subscribe push delivery path; triggers = immediate
  change-push / startup (cache-then-reconcile) / periodic+reconnect (heartbeat carries
  `policy_generation`). Global generation counter for MVP. No new RPC/loop. Closes G6's
  reconnect half.
- **Debounce / races / retry (RESOLVED, design §6.5/§8.4/§8.5).** Three debounce levels
  (input per-Spark Slice A; remediation 5ms Slice C; audit/event collapse-with-count
  Slice A default-on). Re-arm-gap → reconciliation sweep (Slice A; state-check ≠ Decision
  9 policy-check); self-remediation + drift-storm RaceDetector Slice C; stores use
  `RETURNING` (#1033). Retry = resilience strategies (Fixed/Backoff/Escalation, §6.6
  grammar) Slice C, already observable via decision-5 status columns.
- **G6 — offline durability (RESOLVED).** Status = snapshot, no buffer (recompute on
  reconnect; Decision 9 handles policy convergence). Events = **durable bounded local
  journal** (agent SQLite/KV, `event_seq`+`event_id`, ~~at-least-once~~, server dedups by
  `event_id`, ring-buffer bound, HMAC deferred PR 12). The G2 event-sink is
  durability-agnostic → in-memory queue allowed for the first demo, durable journal
  swaps in with no contract change. Decision 9 already closed the reconnect half.
  **Superseded (2026-07-21):** only the struck-through delivery-guarantee framing above
  is superseded - the rest of this resolution stands. Delivered as crash-durable,
  duplicate-tolerant, bounded-retry, not true at-least-once; see Decision 11 above and
  [Reconnect replay
  traffic](user-manual/guaranteed-state.md#reconnect-replay-traffic-durable-lifecycle-journal)
  for the shipped characterization.
- **N2 — status reporting cadence (RESOLVED: transition-only + heartbeat liveness).**
  Rich `GuaranteedStateStatus` is sent at sync/reconnect then **only on transition** — no
  periodic resend (network-kind). Liveness/staleness derives from the **Heartbeat**, not
  status pushes; the heartbeat carries a cheap `guardian_status_digest` (sibling to
  `policy_generation`) and the server pulls full status only on digest mismatch or
  reconnect. Reframes decision 5e (`stale` = no heartbeat, not no status). Two distinct
  mechanisms: rich status → `__guard__`/Subscribe; cheap signals → Heartbeat.
- **N3 — guard self-test / health (RESOLVED: in MVP, G8's second half).** A registry
  watch can go silently deaf (KEY_NOTIFY denied, handle invalidated) and falsely report
  compliant — unacceptable for an enforcement product (NFR: reliability). **Startup
  self-test** (sentinel write → wait ≤500ms for round-trip → delete; OK → `guard_healthy`
  + `guard.armed`, fail → `guard.unhealthy` + `errored`) is NFR-cheap (one local
  write+delete at startup, in-memory health atomics, wire already has the fields). Ongoing
  deafness is caught by the **reconciliation sweep** (already Slice A) — no periodic probe
  chatter. `guard.armed`/`guard.unhealthy`/`guard_healthy` stay in MVP. Periodic re-probe
  deferred. **`guard_healthy` semantics:** "wired at startup" (+ reconciliation backstop),
  *not* "notifications currently live" — a watch that dies post-startup keeps
  `guard_healthy=true` while reconciliation silently covers at interval latency; the
  dashboard health badge must reflect that, not overclaim.
- **G7 — `action` vs `enforcement_mode` (RESOLVED; mode taxonomy revised M3 / #1209).**
  Not redundant — orthogonal: `remediation.action` (`alert-only|enforce|quarantine`) =
  authored intent; `enforcement_mode` (`enforce|audit`) = operational mode, and the
  separate `enabled` boolean (proto field 5) is the on/off kill lever. Effective =
  `!enabled` (no guard) > `audit` (force alert-only, ignore action) > `enforce` (do
  `action`). **Revision:** an earlier draft folded "disabled" into the mode as a third
  value (`enforce|audit|disabled`); the shipped store + REST instead validate
  `mode ∈ {enforce, audit}` and route disable through `enabled` — which the dashboard
  enable/disable toggle and the agent's `if (!rule.enabled) continue` arming guard both
  rely on. The 2-state mode + `enabled` together are the master gate. Keeps a per-rule
  operational dry-run/kill lever (design §6.1). MVP Slice A =
  `action:alert-only` + `mode:enforce`; Slice C adds `action:enforce`; `quarantine`
  deferred.
- **G9 — schema-registry storage (RESOLVED: static C++ catalog).** Guardian types are
  code-coupled (a `type` exists only if the agent implements its handler), so adding one
  is already a code change — a DB-table/runtime-extensible registry (the Instruction
  Engine pattern) buys nothing here. Server holds a **static C++ registry**
  `{kind, type, json_schema}`, exposed via `GET /api/v1/guaranteed-state/schemas`
  (+ per-type) and an MCP resource, **cacheable (ETag/version, fetch-once — NFR-kind)**.
  Agent has handlers compiled in (never sees schemas). **Risk recorded (→ §6):** a type's
  server schema and agent handler can silently drift — MVP mitigation is a **cross-check
  test**; single-source generator deferred. *Rejected:* DB-table (overkill for a fixed
  capability catalog), files (no runtime content reads).
- **G10 — Baseline lifecycle + multi-scope (RESOLVED).** Lifecycle = **`draft ↔
  deployed`** (MVP): create→draft; deploy(scope)→expand + push to in-scope agents + bump
  `policy_generation`; edit-while-deployed→re-expand + **re-push to affected agents only**;
  undeploy→recompute affected agents' union (of *other* deployed Baselines) + push the
  reduced set; delete only from draft. **NFR:** never a fleet-wide re-push on one Baseline
  edit — only agents in the affected scope (current ∪ previous). Targeting —
  **SUPERSEDED (2026-06-03) by `docs/guardian-baseline-model.md`.** This contract resolved
  targeting as *one Scope-DSL expression per Baseline*; the baseline-model doc revises it to
  an **assignment of included − excluded management groups** (exclude wins — the Intune/Jamf
  model), with the Scope DSL relocating *inside* dynamic management groups (Smart Groups) and
  a per-Guard **Prerequisites** gate added on top. The lifecycle (`draft ↔ deployed`) and the
  affected-agents-only re-push NFR above are unchanged. Deferred: archived state,
  versioning/rollback.
- **G11 — forward-compat on unknown types (RESOLVED *for now — may revisit*).** Same trap
  as silently-deaf: the wrong answer is confidently-wrong. Agent **applies known Guards,
  never fails the whole push**, and marks any Guard with an unknown
  Spark/Assertion/remediation `type` as **`errored`** + a one-time reason event
  (`unsupported type X; agent vN`) — **never silently ignored**. Near-term NFR optimization
  (not MVP-blocking): agent reports its supported type-set (= compiled handlers, also the
  G9 reconciliation signal); server **pre-filters pushes by capability** to avoid wasted
  bandwidth and to show "unsupported on agent X" cleanly; agent `errored` is the backstop.
- **G12/G13 — verified in code (RESOLVED).** **G12 (negative):**
  `/api/v1/guaranteed-state/push` is currently a **stub** — it audits + returns 202 with
  `fan_out_deferred_pr3=true` / "agent delivery is asynchronous"
  (`rest_api_v1.cpp:3663-3732`); it does **not** resolve scope or deliver to agents. So
  the Guardian push fan-out (scope → in-scope agents) must be **built** in Slice A,
  **reusing the existing instruction-dispatch path** (Scope Engine + `agent_registry.send_to()`),
  not reinvented. Decisions 6/9 assumed a working fan-out — design unchanged, but it's real
  build work. **G13 (positive):** `ManagementGroupStore` exposes `get_descendant_ids()` /
  `get_ancestor_ids()` / `get_children()` (`management_group_store.hpp:56,73,74`) —
  hierarchy-aware per-MG rollup (decision 5) is supported: expand a group to its
  descendants and JOIN status rows.

## 10. Grill queue status

Core contract (§4) is locked. **All grill items from both passes are now resolved**
(logged in §9) — remaining work is build, not design. Lower-severity notes below are
non-blocking.

**Resolved in the second pass:** N1 (`event_id` → folded into the G2 proto change);
C1–C3 (vocab-table code id, stale `guardian_agent_rule_status` ref, broken §6 pointers);
N2 (status transition-only + heartbeat liveness/digest — network-kind); N3 (startup
self-test in Slice A, reconciliation as the ongoing backstop); G7 (`action` = intent,
`enforcement_mode` = master gate); G9 (static C++ schema catalog; schema↔handler drift
risk recorded in §6); G10 (draft↔deployed lifecycle, affected-agents-only re-push, single
Scope-DSL expression per Baseline); G11 (unknown type → `errored`, never silent; server
capability pre-filter near-term — *may revisit*); G12 (`/push` is a stub — scope→agent
fan-out unbuilt, build in Slice A reusing instruction dispatch); G13
(`ManagementGroupStore::get_descendant_ids()` exists — hierarchy MG rollup supported).

**Lower-severity (noted, not blocking):** Slice A decomposition (L1 — split into A1 bare
demo / A2 reconciliation+debounce / A3 durability); canonical-JSON keys use *target*
vocab deliberately so signing survives the rename (L2 — a feature, not a slip); "<100 ms"
is a target not a guarantee (L3); decision-6 provenance is *derived from* stored
deployment/scope state, not separately materialised (L4).

## 11. Advisor review (2026-05-30)

A stronger reviewer passed the frozen contract: **build-ready, no third grill pass needed.**
Folded: (1) the `__guard__` intercept must sit at the **top** of the Subscribe read loop,
status-agnostic — *not* mirrored from `__timing__` inside the RUNNING branch (or
`status=SUCCESS` messages mis-route); (2) a **`registry-write` threat-model + dangerous-key
denylist** Slice-C gate (§6); (3) **A1/A2/A3 decomposition** with the G12 push fan-out named
as A1's long pole; (4) **`guard_healthy` = startup-wiring** clarification (anti-overclaim).
"Real path" reconfirmed — the fan-out is core distribution, not scaffolding. Verdict: stop
examining, start building A1 on a clean branch.
