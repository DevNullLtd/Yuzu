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

> **Implementation status (2026-09-07 ADR reconciliation):** Shipped — `PluginConfigStore::get_kill_switch`/`set_kill_switch` (`server/core/src/plugin_config_store.hpp:29,188,192`) and `plugin_config_routes.{hpp,cpp}` exist and are wired. Shipped: PR #3134 ("feat(server): plugin config/secret/kill-switch plane + typed schedule params (PR1.5a/b)"), merged 2026-08-15.

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
caller must use — never `get_kill_switch` (the display/inspection accessor the REST GET route
uses) for a go/no-go decision. Resolution order: action-level row wins over a plugin-level row;
no row at either level defaults to "not killed" (`true`). **Any** store error — closed store,
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
`tar.fleet_snapshot` and `asset_tags.sync`, the other two `system_reserved` capabilities, were
unaffected (neither plugin name starts with `_`).

The fix restores `action_allowed`'s documented default: with no kill-switch row for
`__guard__`/`__guard__.push_rules`, the dispatch is allowed. The scope remains fully
kill-switchable like any ordinary plugin.action — an operator can still explicitly disable
`__guard__.push_rules` (whole-plugin or action-level) via
`PUT /api/v1/plugin-config/__guard__/kill-switch` (`?action=push_rules`) or the MCP twin
`set_plugin_kill_switch`, and that switch is honored exactly as for any other capability.

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
