---
status: accepted
date: 2026-08-04
owner: "@Doomgoose (Alex Young)"
deciders: "@Doomgoose (author). PR1.5b, dev-team wave-1 package p5-plugin-config-plane."
scope: server — plugin configuration, plugin secrets, per-action kill switch
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback), ADR-0008 (substrate architecture), ADR-0010 (secrets-at-rest envelope encryption), ADR-0012 (server Postgres store contract), ADR-0017 (management-group confinement list reads), ADR-0033 (access control spine), ADR-0036 (authoritative-read type-distinguishability)
related: ["0009-per-store-first-boot-backfill-cutover"]
context-refs: ["#2568", "#2580", "docs/postgres-store-playbook.md"]
---

# 3005 — Plugin config/secret plane + per-action kill switch

> **Amendment pending: ADR-3006 (plugin management, proposed 2026-10-06).** ADR-3006 sets
> the direction that the kill switch described here becomes one layer of a wider enablement
> model: enforced on the endpoint as well as at dispatch, targetable beyond operating system,
> no longer seeded off for any plugin on new installations, and changed under a permission of
> its own, which would supersede "REST authorization — existing operations only" for it.
> Nothing has changed in the product yet: until the work that follows ADR-3006 lands, this ADR
> describes what ships, and it remains the record of the store and its fail-closed evaluation.

> **Implementation status (2026-09-07 ADR reconciliation):** Shipped — `PluginConfigStore::get_kill_switch`/`set_kill_switch` (`server/core/src/plugin_config_store.hpp:29,188,192`) and `plugin_config_routes.{hpp,cpp}` exist and are wired. Shipped: PR #3134 ("feat(server): plugin config/secret/kill-switch plane + typed schedule params (PR1.5a/b)"), merged 2026-08-15. Per-OS kill-switch rows (schema v2): see "Update (2026-10-03, #5294)".

## Context

Default-off plugins (later PRs in this wave) need somewhere to keep operator-supplied
configuration, a place to keep secret material (API keys, webhook tokens) that must never
round-trip back to a client in plaintext, and a per-action kill switch an operator can throw
without a redeploy. None of this existed before this package; it is built born-on-Postgres
(ADR-0006 — every server store migrates, none stays SQLite) rather than as a new SQLite store,
following `docs/postgres-store-playbook.md`'s greenfield recipe exactly (`offline_endpoint_store.hpp`
and `auth_db.cpp`/`pg::SecretCodec` are the two worked references this store's shape is drawn
from).

## Decision

### Schema and posture

Schema `plugin_config_store` (ADR-0008 naming rule: snake_case of the full class name including
`Store`). Posture: **authoritative** (ADR-0012 §1) — there is no in-memory layer standing in as
"the real answer" the way `OfflineEndpointStore`'s durability-on-top posture assumes; a runtime
DB failure is surfaced as a typed `std::expected<T, PluginConfigStore::Error>`, never silently
collapsed to an empty/false result (ADR-0036).

Three tables, one schema:

- **`configs`** — `(plugin, key)` unique, plain `value` TEXT. Freely readable.
- **`secrets`** — `(plugin, key)` unique, `sealed_value` BYTEA (a `SecretCodec` v1 envelope).
  **Write-only**: no method on `PluginConfigStore`, anywhere, returns a secret's plaintext.
  `set_secret`'s own return value (`SecretMeta`) has no `value` field — the write-only contract
  is structural, not a discipline every call site has to remember.
- **`kill_switches`** — one row per `<plugin>` (whole-plugin) or `<plugin>.<action>` switch that
  an operator has EXPLICITLY flipped at least once, keyed by a canonical `scope_key` TEXT column.
  Absence of a row means "enabled" (not killed) — the table only grows when something is thrown.

### Secret handling (ADR-0010)

One `SecretCodec` instance is owned by **this store alone** — the per-store instance model the
playbook's amended §3 ("Instance model") prescribes and `AuthDB` demonstrates, not a shared
fleet-wide codec. The construction sequence, matching `AuthDB`'s worked example exactly:

1. The server constructs a `SecretCodec` (ctor only — no `init()` yet).
2. `PluginConfigStore`'s own constructor registers its ONE secret column —
   `plugin_config_store.secrets.sealed_value`, primary key `scope_key` — immediately after its own
   schema migration runs (register-before-init).
3. The server calls `secret_codec.init(conn)` right after the `PluginConfigStore` constructor
   returns.

**KEK-rotation-surface enrolment (#2568/#2580) — CLOSED by the constructing/wiring package
(PR1.5c/1.6c, p14).** `register_secret_column` made `plugin_config_store.secrets.sealed_value`
*eligible* for `rotate`/`rewrap`; p14 finished the job by constructing this store's dedicated
`SecretCodec` (`plugin_config_secret_codec_`, `server.cpp`, declared after `pg_pool_` and
`auth_key_provider_` per the destruction-order rule below) and enrolling it into the live
`kek_ops_.{rotate,rewrap,status}` surface alongside `auth_secret_codec_`. `server.cpp`
generalized those three seams from a single hard-coded `auth_secret_codec_` member to a
`kek_enrolled_codecs()` list (`ServerImpl::kek_enrolled_codecs()`) so a future third consumer
needs only an addition to that list. The multi-codec rotate mints the new KEK version **once**
(via `auth_secret_codec_->rotate_kek()` only) and then brings every other enrolled codec onto it
under the SAME `secrets_kek_op` advisory lock hold — each secondary codec's `init()` resyncs its
in-memory `active_version_` from the shared `secrets.kek_meta` table (a no-mutation re-verify,
safe to call repeatedly post-boot), then `rewrap_all()` re-wraps that codec's own registered
columns. This is deliberately NOT N independent `rotate_kek()` calls, which would mint N
divergent KEK versions — see `ServerImpl::kek_enrolled_codecs()`'s doc comment (server.cpp) for
the full contract. An operator's `/rotate` or `/rewrap` request (REST or MCP) now re-wraps
`plugin_config_store.secrets.sealed_value` too.

That sequence is pinned at the `SecretCodec` level by
`tests/unit/server/test_secret_codec.cpp`'s `[pg][secrets][multicodec]` case: two codecs over one
database, each with its own registered column, rotate on the first, and assert that **exactly one**
new live `kek_meta` version exists, that both codecs report the same `active_kek_version()`, that
both stores' rows carry the new version, and that both still decrypt. It is mutation-proven rather
than assumed green — omitting the second codec's `rewrap_all()` fails it with the second store's
rows still on the old generation (`1 == 2`), which is precisely the silent stranding this design
exists to prevent.

`set_secret` encrypts under a **fresh DEK per write** (never DEK reuse — a secret update mints a
new sealed blob from scratch). The SecretId AAD `row_pk` is the deterministic `scope_key`
(`<plugin>.<key>`, via `plugin_config_parsers.hpp::canonical_plugin_key`) — a TEXT identity
computable from the request alone, not a DB-assigned numeric row id. This is a deliberate
departure from `AuthDB::mfa_init_enrollment`'s worked pattern (which reuses an *already-existing*
`users.id` — no row has to be created to learn it): a brand-new secret's `(plugin, key)` has no
pre-existing row to hang an id off, so a numeric-id version would need a "get-or-create the row,
learn its id, THEN encrypt" round trip — which either commits a placeholder row with an
empty/invalid `sealed_value` before encryption succeeds, or mutates an existing row's
`updated_by`/`updated_at` before the encrypted blob exists (both were defects in an earlier
revision of this store; a security review caught them — HIGH, static-read). Because
`scope_key` is derived purely from the validated (plugin, key), no DB round trip is needed before
encrypting: encrypt first, THEN one atomic `INSERT ... ON CONFLICT (scope_key) DO UPDATE ...
RETURNING`. Two concurrent writers for the same (plugin, key) compute the identical AAD
deterministically, so there is no window in which a writer's ciphertext is bound to an AAD
identity different from the row it ends up stored under.

### Fail-closed kill-switch evaluation

`PluginConfigStore::action_allowed(plugin, action)` is **the** chokepoint every dispatch-gating
caller of a non-protective pair must use — never `get_kill_switch` (the display/inspection
accessor the REST GET route uses) for a go/no-go decision. Resolution order: action-level row
wins over a plugin-level row; no row at either level defaults to "not killed" (`true`). **Any** store error — closed store,
lease timeout, query failure — collapses to `false` (disabled), inside `action_allowed` itself,
in the one place every caller shares. This is the ADR-0036 rule applied directly: a
silently-empty/false-collapsed kill-switch read is exactly the fail-open shape that rule exists to
forbid, so the collapse happens explicitly rather than being left for each call site to
(mis)remember. `action_allowed` uses a shorter bounded lease (300 ms) than ordinary CRUD (1.5–2 s)
because its doc comment names it as a potential hot dispatch-gating path — a fail-closed posture
makes giving up fast always safe here (a timeout only ever means "disabled").

### Update (2026-08-18, #3265) — reserved-namespace kill-switch scope grammar

The kill-switch scope grammar
(`plugin_config_parsers.hpp::parse_kill_switch_scope`) accepts a **reserved-namespace** plugin
name of the form `__<identifier>__` (e.g. `__guard__`, matching the `__guard__`/`__observation__`
convention used elsewhere in this codebase) in addition to an ordinary `is_valid_identifier`
plugin name. This is scoped to the kill-switch grammar only — `is_valid_identifier` and
`parse_plugin_key` (config/secret row addressing) are UNCHANGED and continue to reject a
reserved-namespace plugin.

Without this, every `system_reserved` dispatch capability whose catalogue `plugin` starts with
`__` (`core_dispatch_capabilities.hpp`'s `__guard__.push_rules`) was kill-switch-**unreachable**:
`is_valid_identifier`'s first-byte-must-be-`a`-`z` rule made `parse_kill_switch_scope` return
`nullopt` unconditionally, which `action_allowed`'s own documented contract ("an unresolvable
scope must never resolve to allowed") collapses to `false` — so `__guard__.push_rules` was
**permanently kill-switched off**, with no kill-switch row ever having been set, on every
Postgres-backed server (i.e. every server, ADR-0006/0007). This silently dropped every Guardian
rule push (`/api/v1/guaranteed-state/push`, Baseline deploy, and the reconcile re-push) — the
caller saw a normal `202 {"queued":true,"agents":0}` response and audit row — `agents=0` was technically
present, but indistinguishable from any other ordinary zero-match case (no agents in scope, none online),
so nothing identified a kill switch as the cause.
`echo.fleet_snapshot` and `asset_tags.sync`, the other two `system_reserved` capabilities, were
unaffected (neither plugin name starts with `_`).

The fix restores `action_allowed`'s documented default: with no kill-switch row for
`__guard__`/`__guard__.push_rules`, the dispatch is allowed. The scope remains fully
kill-switchable like any ordinary plugin.action — an operator can still explicitly disable
`__guard__.push_rules` (whole-plugin or action-level) via
`PUT /api/v1/plugin-config/__guard__/kill-switch` (`?action=push_rules`) or the MCP twin
`set_plugin_kill_switch`, and that switch is honored exactly as for any other capability.

### Update (2026-10-12) — `__guard__.push_rules` is protective

The paragraph above is superseded for `__guard__.push_rules`. It stays kill-switch-ADDRESSABLE
(a row can still be stored and read back, so #3265's reachability fix stands) but is no longer
kill-switch-REFUSABLE: it joins the quarantine plugin's four actions as a protective action
(`yuzu::protective::is_protective_action`, `common/include/yuzu/protective_actions.hpp`) that no
plugin-enablement gate may refuse — the all-OS kill switch, the per-OS withhold and its presence
read, the plugin-presence filter and a degraded store. The four quarantine actions were exempt
only from the containment gate before; this change newly exempts them from every enablement gate
too, and the Fail-closed rule above applies to non-protective pairs only. A contained device must
keep receiving the rules that make containment meaningful. The operator lever for stopping rule
delivery is disabling or removing the rules (state-only: the agent disarms them on its next
reconcile). Refusing a kill-switch write for a protective pair is deferred until ADR-3006 D3's
enablement catalogue replaces the kill-switch write surface; until then a stored row is
informational only.

### Update (2026-10-03, #5294) — per-OS kill-switch rows

A kill switch can now be narrowed to one agent OS, so a new OS leg can ship off where the plugin
is already on.

- **Schema v2.** `ALTER TABLE kill_switches ADD COLUMN os TEXT NOT NULL DEFAULT ''` (v1 is
  unchanged; it shipped in a release). `scope_key` stays the unique identity and takes the form
  `<plugin>[.<action>][@<os>]`; `@` is outside the identifier grammar, so no existing key can
  collide. Existing rows read back as `os=''`: nothing flips on upgrade.
- **Closed OS set.** `os` is one of `windows`, `linux`, `darwin` (`is_valid_agent_os`; the source
  of truth is `kAgentOs` in `agents/core/src/agent.cpp`, so adding an agent OS means updating
  both). `macos` or a typo is refused rather than becoming a silently ineffective row.
- **AND of layers.** The effective state is the plugin/action layer AND the OS layer
  (`resolve_kill_switch`, pure). A per-OS row only ever narrows; it never widens an OFF plugin or
  action row, and a missing per-OS row falls back to the plugin/action state. Inside the OS layer
  `<action>@<os>` wins over `<plugin>@<os>`.
- **One read.** `kill_switch_decision(plugin, action)` is the single-statement, fail-closed read
  behind `action_allowed` (which is now `kill_switch_decision(...).has_value()`). It returns
  `nullopt` when killed for every OS or degraded, else the set of OS values whose per-OS switch
  is OFF. `get_kill_switch(plugin, action, os)` reports the EFFECTIVE `enabled` and attributes
  `reason`/`set_by`/`updated_at` to the row that produced the decision (never an ON row beside
  `enabled=false`), naming it in `source`.
- **Enforcement.** The set travels on `ClassifiedCommand::kill_switched_os()` and is turned into
  a per-target filter in `dispatch_confined_arms` (priority: contained, then OS-killed, then
  plugin-absent) from `AgentRegistry::ids_with_os`, which covers local sessions AND presence-backed
  ids from other replicas (local wins). An id whose OS is unknown everywhere is not withheld
  (absence of data is not a killed OS). Dispatches with no per-OS row pay nothing: an empty set
  does no presence read and keeps the unfiltered broadcast fast path.
- **Degraded presence fails closed.** With a non-empty OS set, an unreadable presence store
  refuses the whole dispatch before targeting (`os_gate_unreadable`) instead of enforcing on local
  sessions only. A fail-closed containment gate outranks it: containment already withholds every
  id, so the presence read is skipped and the reported cause is `containment_unreadable`.
- **Claims.** An OS-withheld id has already taken its per-device concurrency claim, so it is the
  fourth bucket released with not-sent, quarantined and unknown-plugin ids.
- **Dry run.** The MCP pre-dispatch authorization dry run has no target, so it cannot see the
  per-OS layer; an "allowed" dry run followed by `sent=0` with `kill_switched_os_count > 0` is
  expected.
- **Operator surface.** `GET/PUT /api/v1/plugin-config/{plugin}/kill-switch` and the MCP
  `get_plugin_kill_switch` / `set_plugin_kill_switch` take an optional `os`; the audit `target_id`
  gains the `@<os>` suffix. The zero-reach cascades report `kill_switched_os` (permanent) and
  `os_gate_unreadable` (retryable) as distinct causes.
- **Send-time check.** `AgentRegistry::send_to` and the local-session loop of `send_to_all` also
  refuse a session whose OS is in the command's set, so every local caller (including
  `send_system_reserved`) is covered and a session that registers after the dispatch-time presence
  snapshot is still withheld. The residual is `send_via_directory` (remote ids, no session), which
  relies on the presence snapshot. A send-time refusal counts as undelivered.
- **Presence ceiling.** `ids_with_os` reads `live_presence()`, which is `Truncated` above 100,000
  rows. Above that, a plugin/action with a per-OS OFF row is refused fail-closed with
  `os_gate_unreadable` until the fleet drops below the cap; this is the same cap `evaluate_scope`
  already aborts on.
- **Cascade order.** The aggregate zero-reach cascade keeps the pre-existing #3424 order and so
  reports `plugin_not_found` ahead of `kill_switched_os`; the per-OS withhold is always disclosed
  by the `agents_kill_switched_os` / `withheld_kill_switched_os` counts, so a mixed answer is
  incomplete, not false.
- **Rollback and mixed versions.** A server older than this change ignores `<plugin>@<os>` rows and
  applies a `?os=` PUT as the plugin-level row; see the upgrading guide ("Behaviour change: per-OS
  plugin kill switch rows (#5294)").
- **Scope.** This is the mechanism only; no plugin is wired to a per-OS seed here.

### Update (2026-10-17, ADR-3006) — enablement tables (schema v3)

Schema v3 adds the durable half of the enablement model to the same schema. It is purely
additive (v1 and v2 are untouched) and the rows are read and written by `EnablementStore`
(`enablement_store.hpp`), a sibling accessor; `PluginConfigStore` owns the migration only. The
tables ride the existing dump; the continuity anchor file (below) is the one extra artefact to
keep with a backup. The store has no operator surface yet: rules are authored by a later release
(ADR-3006 D10/D14).

- **Three tables.** `enablement_rules` (persisted rules), `enablement_endpoints` (one row per
  registered endpoint: identity, the registration-order guard, `input_gen`, `resolved_version`,
  desired and reported `(epoch, counter, hash)`) and `enablement_meta`. `enablement_meta` is ONE
  typed row (`id = 1`) holding `store_id`, `epoch`, `counter`, `rules_version`, `overlay_hash`,
  `job_cursor`, `issuer_epoch` (the highest leader epoch that has issued a batch) and the
  regression declaration. One row, so every writer that must serialise (counter reservation, the
  freeze, the `rules_version` bump, the rule-count cap) locks the same row. `enablement_endpoints`
  is created with `fillfactor = 80`: measured at 2M rows, the hourly report write stays HOT
  instead of landing 30-40% HOT, and the choice is free because v3 is new; making it later would need a table rewrite.
- **Posture.** Authoritative (ADR-0012 s1); every read is a typed `std::expected`, and every
  acquire is bounded (`try_acquire_for` / `with_txn_for`, plus `SET LOCAL statement_timeout` on the
  batch write: about 20 s worst case per batch, never unbounded).
- **Caps at the boundary.** Rules (1000 active, 64 units per rule, id as `is_valid_identifier`,
  selector 4096 bytes and `audit_ref` 128 bytes, neither with a control byte), the registration
  identity (hostname 256 bytes, OS and arch 32, agent version 64, no control byte), the agent id
  (256 bytes, no control byte), report fields (non-negative epoch and counter, hash empty or 64
  lowercase hex), a batch (at most 2000 rows, because it holds the meta-row lock for its whole
  transaction) and the anchor file (512 bytes).
- **Provenance spellings are frozen** by the first persisted row: `operator`, `carried_over`,
  `system` (a `CHECK` constraint and `to_wire` / `parse_provenance`).
- **Write on change.** An identical report inside an hour writes nothing; a re-resolution that
  reaches the stored hash re-stamps the row without touching `desired_*`; a re-registration of an
  unchanged identity moves only the registration-order columns.
- **Registration-order guard.** The identity is written by `upsert_on_registration`, which carries
  `(boot_id, seq)`. The registration observer that wires it in (a later change; `AgentRegistry`
  assigns no such field today) must assign `seq` under the registry's mutex in the critical
  section that installs the session, so that within a process it IS install order. The upsert is
  conditioned on it, so an older registration that completes late matches zero rows and cannot
  overwrite a newer registration's identity or `input_gen`. A different `boot_id` always wins: across processes the
  write is last-writer, the per-replica registry's status quo (a cross-replica order needs a
  shared presence seam, not this store).
- **`input_gen` invalidation.** A registration that CHANGES the identity (hostname, OS, arch or
  agent version) bumps `input_gen` and clears `resolved_version`, so the row is re-resolved, never
  erased; an identical re-registration (a reconnect) changes neither, so a reconnect storm does
  not re-stale the fleet. Whether unchanged rows are restamped at all after a `rules_version`
  bump is the resolver-job change's decision (a restamp rewrites every row once, and
  `resolved_version` is indexed, so at fleet scale it is a large write). A mixed-version window
  (a rolling upgrade or a rollback) flips the overlay hash at each old-version replica's restart
  and re-stales the fleet each time; that is bounded by the rollout and accepted, because a
  release ordinal would make a rollback's hash lose and leave the overlay recorded wrongly.
- **`record_report` is one conditional `UPDATE`.** The `CASE` that clears `pending_since` and the
  `WHERE` that suppresses a duplicate are evaluated against the row's current version under its
  row lock, so a report equal to the PREVIOUS desired state never clears `pending_since` for a
  state issued in between. An exact acknowledgement clears `pending_since`; a report BEHIND the
  row's issued `(epoch, counter)` reopens it (keeping the original age while still pending), so
  pending-with-age holds whenever the endpoint is behind. A report above the store's highest
  `(epoch, counter)` is flagged (`report_ahead`) and counted, never declared here.
- **The epoch fence at the batch write.** `(epoch, counter)` is issued only inside
  `set_desired_batch`, by the leader. Its first data statement is one `UPDATE` of the meta row
  that reserves the counter range, requires `regressed_at IS NULL` and embeds
  `LeaderElector::epoch_fence_sql`, in a READ COMMITTED transaction (ADR-2002 s3 and s6, the
  command outbox's idiom). A paused ex-leader's batch matches zero rows and is rejected; a
  declaration committed before the statement is seen, and one committing concurrently blocks on
  the row lock and is re-checked. The fence's `leader_state` subquery is read under the statement
  snapshot and is not re-run when the `UPDATE` waited on the row lock (verified on PostgreSQL 18),
  so the meta row's own columns carry the second check, which IS re-evaluated after the wait:
  `issuer_epoch` (the statement requires `issuer_epoch <= $epoch` and sets it) rejects a leader a
  successor has already superseded, and `rules_version = $planned` rejects a batch planned before
  a rule or overlay write moved it. Zero rows is `Regressed`, `Fenced` (leadership lost) or `StalePlan` (the rules moved while the
  epoch still stands), and the job re-plans. A
  stamp of an unchanged row holds only while the row still carries the `desired_hash` the planner
  observed, so a row rewritten in between is re-resolved, never marked current. The residual is a
  handover committing between the statement's snapshot and its row-lock acquisition with no other
  holder of the lock, the same narrow effectively-once window the command outbox accepts.
  (`FOR KEY SHARE` on the `leader_state` row would not close it: the elector's epoch update is a
  non-key update, which `FOR KEY SHARE` does not block; `FOR SHARE` would.)
- **The continuity anchor.** `<data_dir>/enablement-anchor` (three lines: store id, epoch, counter)
  is this host's witness of the highest `(epoch, counter)` it has seen. A PRESENT anchor that names
  another store (with a counter above 0 on either side), is ahead of the store, or holds bytes
  that are not an anchor declares the store
  regressed (`regressed_at` is set, issuing freezes, `/readyz` reports it; this store has no way to
  clear it, because accepting a regressed state starts a new ordering of states, ADR-3006 D14,
  which the operator flow that follows owns). An anchor that EXISTS but cannot be read
  (permissions, descriptors, a directory in its place) is an I/O fault, not evidence about the
  store: boot refuses to start with the cause logged, and `write_anchor` returns `Failed`
  (counted); nothing is declared, because a declaration has no way back in the product. A MISSING
  anchor is only unwitnessed: counted, latched on `/readyz` for that boot and then written, so
  every later restore on the host is witnessed. An agent reporting above the store's highest
  (`ReportAhead`) is the second witness: counted and surfaced here, declared by the later change
  that issues desired state. The anchor is NEVER lowered: `write_anchor` reads the file and then
  `enablement_meta` on every write (in that order, under a process-wide mutex, so a concurrent
  advance never reads as a file ahead of the store), refuses while regressed, and declares a
  regression instead of lowering a file that is ahead of the store (a dump restored under a running
  server). The anchor is per host and outside the dump: one persistent data directory per replica,
  never shared or cloned; a lagging replica or a failed-over leader has a weaker witness; one
  replica's declaration is cluster-wide through the database while the other replicas' `/readyz`
  stays stale until they restart in this release; an ephemeral data directory makes the
  mechanism inert (every boot is unwitnessed). The contents are fsynced before the rename, so a crash can
  never leave a torn anchor (which would read as a false regression); the directory entry is
  best-effort, so a crash right after the rename may leave the previous anchor, which is at or
  below the store (Ok on restart). This change writes the anchor on an unwitnessed boot and never
  lowers it; rewriting it after each batch arrives with the resolver job, and a crash between a
  batch commit and that write leaves the file below the store, also Ok.
- **Departure from ADR-3006 D14 (recorded 2026-10-18).** D14 says a store that has been restored
  or rebuilt starts as regressed unless continuity with the last ordering it issued is shown. For
  a missing anchor file the rule is: a missing anchor is unwitnessed only, counted, latched on
  /readyz, then written. So a dump restored
  onto a host with no anchor file is not regressed by the file; `ReportAhead` is the second witness
  that covers it once the change that issues desired state declares from it. A PRESENT anchor that
  disagrees still regresses, with the narrowing recorded next.
- **Narrowing of the store-id mismatch trigger (recorded 2026-10-18).** A `store_id_mismatch`
  regresses only when the anchor's counter or the store's counter is above 0. When both are 0
  nothing was ever issued, so there is no ordering to have lost: the verdict is Unwitnessed
  (counted through `yuzu_server_enablement_anchor_unwitnessed_total`, latched on `/readyz` as
  `anchor_unwitnessed_at_boot`), one warning names the old and new store id, and the existing
  unwitnessed-path write rewrites the anchor with the current store id; `write_anchor` does not
  re-declare in that case either. A restore-then-re-upgrade at counter 0 therefore no longer pages.
  A garbled or unparseable anchor still regresses (`anchor_unparseable`), and a resource or
  permission error stays the retryable Unavailable path. Genuine regressions (`store_behind`, or a
  mismatch with a counter above 0) keep the support-guided exit. This narrows the ADR-3006 recovery
  rule alongside the missing-anchor rule above.
- **Overlay changes.** A release that changes the unit overlay (a unit, its OS bits or a
  requirement edge) bumps `rules_version` at boot (`sync_overlay_hash`), so every row becomes stale.
- **The loader's two duties** (`make_persisted_rule`, `enablement_resolver.hpp`): a rule refused at
  load is quarantined, counted (`yuzu_server_enablement_rules_rejected_total{reason}`), logged (one
  line per refused rule per load, with a neutralised id and the label only) and listed, never
  silently omitted; and the unit names
  rules reference that this release does not know are computed at load with `resolve()`'s own
  predicate, gauged (`yuzu_server_enablement_unresolved_units`) and alerted. The count of refused
  rules is also a gauge (`yuzu_server_enablement_rules_quarantined`), because a refused rule is a
  standing condition (its unit stays on) that a counter's `increase()` forgets within the hour.
- **Not here.** The resolver job that issues desired state, the registration observer and the
  durable plugin inventory, tag and property invalidation, delivery and the regression declaration
  from agent reports, REST and MCP authoring and audit, the dispatch cutover that consumes the
  inventory, purging retired rows (nothing is ever deleted automatically) and cross-replica
  registration ordering. `enablement_endpoints` holds hostname and agent version per agent but is
  not yet in the agent decommission cascade (`agent_decommission.hpp`'s standing rule: a new
  per-agent store is registered there with its list, count and blast-radius docs). The table holds
  no row until the registration observer lands, so nothing is retained in this release; adding
  `delete_agent` and the cascade membership is a binding prerequisite of the registration-observer
  change, not an option.

### REST authorization — existing operations only

Every route gates on `PluginConfig` or `PluginSecret` with an operation drawn **only** from
`Read`/`Write`/`Delete`:

| Route | Securable:Operation |
|---|---|
| `GET /api/v1/plugin-config` (list) | `PluginConfig:Read` |
| `GET /api/v1/plugin-config/:plugin/:key` | `PluginConfig:Read` |
| `PUT /api/v1/plugin-config/:plugin/:key` | `PluginConfig:Write` |
| `DELETE /api/v1/plugin-config/:plugin/:key` | `PluginConfig:Delete` |
| `PUT /api/v1/plugin-config/:plugin/:key/secret` | `PluginSecret:Write` |
| `DELETE /api/v1/plugin-config/:plugin/:key/secret` | `PluginSecret:Delete` |
| `GET /api/v1/plugin-config/:plugin/kill-switch` | `PluginConfig:Read` |
| `PUT /api/v1/plugin-config/:plugin/kill-switch` | `PluginConfig:Write` |

There is **deliberately no `Suspend` operation** and no `PluginSecret:Read` operation. A new
`Operation` enumerator would force a change to `rbac_store.cpp`'s `ops[]` array and collide with
the in-flight #2703 RbacStore-to-Postgres migration; the kill-switch flip is expressed as a
`PluginConfig:Write` instead, which is both sufficient (an operator who can write plugin config
can also throw its kill switch) and avoids the collision entirely. The secret plane exposes only
`set`/`delete` (write operations) — **no GET or list route for secrets exists at all** — so no
`PluginSecret:Read` is declared; a write-only plane needs no read operation to gate. `set_secret`'s
response body (`SecretMeta`) is the surface a caller uses to learn "was my secret accepted, and
when" without ever exposing its value.

List routes (today: only `GET /api/v1/plugin-config`) go through
`RbacStore::authorize_list_read` (ADR-0017, `rbac_store.hpp:307`) rather than a bare permission
check, per this package's spec. This resource is **not** agent-scoped, so the `AdmitScoped`
decision — a management-group-CONFINED grant, whose `visible_agents` names agent ids — has no
principled interpretation here: there is no correspondence between agent ids and plugin/key rows
to filter by. `AdmitScoped` is therefore treated identically to `DenyAll` (403): a
confinement-scoped grant for `PluginConfig:Read` is refused rather than silently served
unfiltered (which would widen a device-scoped grant to fleet-wide platform configuration) or
silently served empty (which would look like a successful-but-vacuous read rather than a denial).
Only `AdmitAll` (a global grant, or RBAC loaded-and-disabled) serves the list.

### Audit

Every config write, secret write, and kill-switch flip routes through `rest_audit.hpp`'s
`detail::emit_behavioral_audit` and — matching that helper's documented REST-JSON posture — fails
closed with `503` when the audit row could not be persisted, rather than the "set a header and
proceed" posture some HTML-dashboard fragment routes use. A secret write's audit `detail` string
is built by `plugin_config_parsers.hpp::redact_secret_for_audit`, a function that takes only the
`(plugin, key)` coordinate and has no parameter through which a plaintext value could reach it —
the redaction is structural, not a call-site discipline. The one log line on the encrypt-failure
path (`set_secret`) uses the parallel `redact_secret_for_log` helper for the same structural
reason, applied to `spdlog` rather than the audit trail.

**Ordering: audit before mutate, not after.** Every mutation route in `plugin_config_routes.cpp`
emits its audit row and checks it persisted **before** calling the store mutation, not after. An
earlier revision of this store audited after mutating; a security review (HIGH, static-read) noted
that ordering means an audit-store outage lets every write commit while returning 503 to the
client with no audit evidence at all — the exact failure this posture exists to prevent, just
moved one step later. Every field a mutation route audits (plugin/key/action from the URL,
value/reason from the validated request body) is available before the store call, so gating on
audit persistence first is possible without inventing a two-phase attempt/confirm protocol or a
cross-store transactional outboxes (both out of scope for a new-files-only package with no shared
audit-store access). Each route re-validates its input with the same `plugin_config_parsers.hpp`
grammar the store enforces internally immediately before auditing, so a plain 400-shaped
validation failure never first burns an audit row it turns out not to need; `plugin_config.delete`
and `plugin_secret.delete` additionally treat "target already absent" specially — the config route
pre-checks existence via `get_config` (a read, not a mutation) so a double-delete/retry still
answers 404 with no audit row at all, matching the pre-reorder behaviour for that case exactly; the
secret route has no equivalent existence check available (the secret plane is write-only by
design, with no GET route or store method to ask "does this exist"), so a delete of an
already-absent secret key records an audit row for the attempt before discovering that. The
residual gap this reordering does NOT close: a mutation can still rarely fail *after* a successful
pre-mutation audit (a lease timeout, a concurrent-delete race, an encrypt failure) — that gap is
narrow and infrastructure-shaped, categorically smaller than "any audit-store hiccup silently
permits an unaudited write," which is the gap actually being closed here.

### List truncation signal

`list_config` caps results at 5,000 rows (`kListRowCap`, defensive — not expected to bind in
practice for a config/secret plane). Rather than silently dropping rows past the cap with no
signal, the store fetches one row past the cap to detect overflow and exposes it via an optional
`bool* truncated` out-parameter; the REST list route surfaces it as `meta.truncated` in the JSON
response. A caller that ignores the parameter (every existing call site did, before this) sees the
exact same rows as before; the REST surface is the one caller that now reads it.

## Open items — deliberately NOT closed by this package

**KEK-rotation-surface enrolment — CLOSED, see "KEK-rotation-surface enrolment" above.** p14
(PR1.5c/1.6c) constructed this store's dedicated `SecretCodec` in `server.cpp` and enrolled it
into the generalized `kek_ops_.{rotate,rewrap,status}` seam
(`ServerImpl::kek_enrolled_codecs()`) alongside `auth_secret_codec_`. No residual gap remains on
this item.

**Agent-side secret delivery does not exist.** `yuzu_ctx_get_secret`
(`agents/core/src/agent.cpp:463`) is a hard-coded `nullptr` stub. This package is **server-side
only**: it stores and seals secret values and exposes a write-only REST surface, but nothing
delivers a decrypted secret to a running plugin instance on an agent. Wiring that path needs a
secret-delivery threat model — how a secret crosses the server/agent boundary, what proves the
requesting agent/plugin is who it claims to be, and what the blast radius of a compromised agent
is — that does not exist yet and is out of scope for this package. Any later PR wiring
`yuzu_ctx_get_secret` must write that threat model first; it must not bridge this store's sealed
values to an agent by simply calling `SecretCodec::decrypt` from a request handler without one.

## Consequences

- `PluginConfigStore` is a new construction-fail-closed dependency the server startup sequence
  must add alongside every other Postgres store (ADR-0012's "wire into `server.cpp`" step) — this
  package does not touch `server.cpp` (scope discipline; a new-files-only package), so wiring is
  the integrating PR's job, against the exact `register_plugin_config_routes(HttpRouteSink&,
  yuzu::server::plugin_config::Deps)` signature this package's `plugin_config_routes.hpp` declares.
- `docs/postgres-migration-ladder.md` gets a new "born-on-Pg, no backfill" row for
  `plugin_config_store` — added by a different package in this wave (p6), not here (boundary
  discipline).
- The kill switch this package builds started as **read-only enforcement infrastructure** — it
  exposed `action_allowed` for a caller to consult, but no dispatch path called it. That gap was
  closed in a later remediation round: `ServerImpl::build_classified_command`
  (`server.cpp`) now consults `action_allowed(cap.plugin, cap.action)` on every classified
  dispatch and refuses with a distinct, separately counted `KillSwitched` denial reason. This
  paragraph is kept as the historical record of the original scope decision; it no longer
  describes the current state.
- Construction hand-rolls acquire-lease/run-migration/release rather than calling a named
  `open_with_migrations` helper the playbook describes — that helper has no discoverable
  implementation anywhere in the tree today, and every existing store (including the playbook's
  own worked reference, `offline_endpoint_store.cpp`) hand-rolls the identical sequence too. This
  store matches that established precedent rather than inventing a one-off construction path;
  introducing the actual shared helper is a substrate-level (`server/core/src/pg/`) change outside
  this package's owned files.
