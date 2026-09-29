# ADR-0050: TagStore → PostgreSQL (Wave 2)

- **Status:** Accepted
- **Date:** 2026-08-14
- **Deciders:** pg workstream (Wave 2 batch 3, alongside `AnalyticsEventStore` ADR-0049 /
  `SoftwareDeploymentStore` ADR-0051)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012, ADR-0036 (typed-read
  program policy), ADR-0045 (the sibling store this migration is modeled on)

## Context

`TagStore` (`tags.db`, `server/core/src/tag_store.{hpp,cpp}`, ~640 LOC pre-migration) holds
per-agent key→value tags — free-form operator/API/MCP-authored labels, agent self-reported
`scopable_tags` (re-synced on every Register), and the four fixed structured categories
(`role`/`environment`/`location`/`service`). One table, composite PK `(agent_id, key)`, with
`source` OUTSIDE the key carrying the #1411 precedence rule (an agent write never clobbers an
operator/API row for the same key).

**This store is dispatch-critical — the security shape the kickoff doc named.** Tags are
scope-resolution input three ways:

1. `tag:<key>` atoms in the scope DSL resolve through this store
   (`AgentRegistry::evaluate_scope` — scope decides WHICH AGENTS a command reaches);
2. service-scoped API tokens are confined by the `service` tag (`derive_exec_visible` +
   `auth_routes`' scoped-permission gate);
3. dynamic service management groups populate their membership from `agents_with_tag`.

A silently-empty tag read under a degraded store mis-resolves all three — depending on
expression shape it under-targets OR over-targets a dispatch (the #2500 targeting-widening
family). The SQLite original collapsed "no such tag" and "the read failed" into the same empty
result on most reads (the deliberate exception: `agents_with_tag_checked`, B-2b — see the
supersession note below).

## Decision

Migrate to PostgreSQL schema **`tag_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server `PgPool`. `sqlite3_changes()` → `RETURNING` (#1033).
Modeled on `CustomPropertiesStore`/ADR-0045 (near-identical data model, merged two days
earlier), with the deltas below called out explicitly.

### Posture: authoritative (ADR-0012 §1), typed reads across the board

Tags are irreducible operator intent plus agent-reported state the operator may already scope
on. **Every** read returns `std::expected<T, TagReadError>` (`kDegraded` on a store/pool/query
failure) — unlike ADR-0045, no read here stays plain-container, because every read surface
feeds or can feed a decision: `get_tag` (service-scope confinement gate, asset-tag push),
`get_all_tags`/`get_tag_map` (REST/MCP agent records an agentic caller acts on),
`agents_with_tag` (confinement + group membership + operator targeting queries),
`get_values_for_keys` (the scope preload), `get_compliance_gaps`/`get_distinct_*`/
`get_values_for_key` (operator-facing reporting where a silent empty reads as "compliant"/
"untagged"). Writes return `std::expected<void, std::string>` with `kTagDbErrorPrefix`
(`"db_error: "`) marking DB failures so REST/MCP classify degrade → 503 / caller error → 400
(#3097), and `set_tag_checked` now PROPAGATES a failed write (the SQLite original validated,
then swallowed the write result and reported success).

**Supersession (B-2b):** the pre-migration store deliberately kept TWO accessors —
`agents_with_tag_checked` (degrade-distinguishable, added for `derive_exec_visible`) and a
collapsing `agents_with_tag` "kept as the stable, unchecked entry point [because] callers
across the tree already destructure a plain vector" (its own comment). This ADR removes the
collapsing accessor and renames the typed one over it. The recorded rationale dies in this
same PR's caller sweep (every caller now handles the typed shape), and the 2026-07-25 program
policy (ADR-0036, playbook "Authoritative reads must be type-distinguishable") postdates B-2b
and mandates the widening at migration time. The rename is deliberate: any un-swept caller
fails to compile rather than silently inheriting a collapsed read.

### Schema

Column-for-column with the SQLite original (`updated_at` becomes `BIGINT`), plus
`tag_store_meta` for the backfill marker/fingerprint (the ADR-0045 bookkeeping-table shape):

```sql
CREATE TABLE tags (
    agent_id    TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'server',
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (agent_id, key)
);
CREATE INDEX tags_key_value_idx ON tags (key, value);

CREATE TABLE tag_store_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
```

The PK serves every per-agent read; `tags_key_value_idx` serves `agents_with_tag` (key or
key+value), `get_distinct_values`, `get_values_for_key` and the scope preload's
`key = ANY($1::text[])`.

### Source precedence (#1411) survives the substrate change — verified empirically

The agent-sourced upsert becomes `INSERT ... ON CONFLICT (agent_id, key) DO UPDATE SET ...
WHERE tags.source = 'agent' RETURNING agent_id`; non-'agent' sources upsert unconditionally.
Per the playbook's rule that `ON CONFLICT ... DO UPDATE ... WHERE` semantics are never shipped
on reasoning alone, the four cases were verified against live Postgres 18 before the code was
written: fresh agent insert (1 row returned), agent-over-agent (1 row, updated),
operator-unconditional (1 row), agent-over-operator (0 rows, NO error, operator row intact).
The 0-row case is reported as SUCCESS (a clean precedence no-op) — inside `sync_agent_tags`'
transaction this matters: a declined self-assignment must not roll back the rest of the
agent's sync. `sync_agent_tags` keeps its all-or-nothing DELETE(source='agent')+reinsert shape
via `pool_.with_txn_for` (governance UP-1 on the original: a mid-sync failure rolls back to
the agent's prior complete tag set, never a partial wipe — re-proven by a trigger-based
fault-injection test, replacing the SQLite authorizer hook).

**Gate 7 hardening (governance perf-F1/UP-2):** the reinsert is ONE batched
`unnest($keys, $values)` upsert — two statements per sync regardless of tag count (the
first cut was K+1 sequential round-trips pinning a shared-pool connection per Register,
and the pool is shared with the dispatch-critical scope preload and RBAC reads); the
per-row precedence `WHERE` was re-verified against live Postgres 18 in batched form
(operator-sourced conflict rows declined while the same statement updates/inserts the
agent rows around them). One sync is capped at **256 tags** (`kMaxSyncTags`) — the proto
map is unbounded and gRPC's 4 MB default admits ~10^5 entries; an over-cap sync is
refused whole (deterministic, prior set retained, caller error not db_error). Writes
also reject an `agent_id` that is empty, over 256 bytes, or carries an embedded NUL —
libpq's text binds are C strings, so a NUL would silently truncate the identity at the
DB seam while `AgentRegistry` keys the session by the full string (governance UP-2).

### `tag:<key>` scope-DSL fail-open — closed at the resolver, with one deliberate asymmetry

`evaluate_scope`'s `tag:` resolver called `TagStore::get_tag` per agent inside the fleet loop
under `mu_` — against Postgres that is N sequential blocking network calls under the registry
lock, and its degraded read collapsed to `""` (the #2500-class fail-open, identical to what
ADR-0045 closed for `props.<key>`). Fixed the same way: a shared
`yuzu::scope::collect_attribute_suffixes` AST walk (new, in `scope_engine` — also used by MCP
`preview_scope_targets`, which had the same per-agent loop) + one
`TagStore::get_values_for_keys` bulk query per evaluation; a degraded preload ABORTS the whole
evaluation (`nullopt`).

**Deliberate asymmetry vs props:** a NULL `tag_store` with a `tag:` atom does NOT abort,
where a null props store does. Tags have a first-class in-memory source —
`session->scopable_tags`, checked FIRST in the resolver (pre-existing precedence, preserved
exactly) — that legitimately answers `tag:` atoms without any store; props have no such
source. In production the store cannot be null post-migration (fatal at boot); a null store is
a test/embedded configuration running on in-memory tags alone. A DEGRADED (non-null, failing)
store always aborts.

### Preload cost envelope and the caching deferral (governance perf-F2)

Measured on live Postgres 18 (EXPLAIN ANALYZE, 10k agents × 5 keys = 50k rows): a
two-key preload materializes ~20k rows in ~2.5 ms server-side, ~600 KB transferred,
via a bitmap index scan on `tags_key_value_idx` — per scope evaluation. The cost
scales with fleet × referenced keys, and part of it is dead weight (the loop visits
connected agents only, and `scopable_tags` shadows agent-sourced rows). Two
optimizations were considered and REJECTED: filtering `source <> 'agent'` in the
preload (a sync-failure window would make the store and the in-memory view diverge
for exactly the rows being shadowed), and caching the preload (ADR-0012 §4's rules —
positive-only, generation-guarded invalidation on own writes, provenance — are
unsatisfiable on a dispatch-targeting path where a stale positive TARGETS THE WRONG
AGENT). The per-evaluation query is the deliberate steady state; revisit only with a
measured fleet-scale problem in hand.

### Bulk reads replace point-lookup loops (NFR)

- `get_compliance_gaps` was a per-agent × per-category `get_tag` loop (N×4 point lookups) —
  now two queries on one lease. Semantics preserved: only agents with ≥1 tag row are
  evaluated; a category with an empty-string value counts as missing (both pinned by tests).
- The settings tag-compliance fragment issued up to nine store queries per render — now two.
- `push_asset_tags_to_agent` read 4 category tags individually — now one `get_tag_map`.
- MCP `preview_scope_targets` called `get_tag_map` per agent — now the same bulk preload as
  `evaluate_scope`, and a degraded preload fails the tool call (it previews dispatch
  targeting).

DEX/network cohort snapshot providers stay render-degraded by policy (ADR-0036's
render/telemetry carve-out) — noted inline at both call sites.

### Secrets: none

Tag keys are validated identifiers (1–64 chars `[a-zA-Z0-9_.:-]`); values are free-form text
(max 448 bytes). No dedicated secret column and no secret-valued tag convention in the tree
(checked: no caller writes credential material through this store). Same free-text caveat and
same conclusion as ADR-0045: ADR-0010's seam targets columns the STORE commits to holding
secret material, not free text an operator could misuse.

### Backfill (ADR-0009) — mandatory, fingerprint-verified, direction-aware

All four live sources backfill (`server`, `agent`, `api`, `mcp` — the header's stale
three-source comment predated MCP): operator-authored rows are irreducible intent, and
agent-sourced rows are scope-live state an operator may already target by (they also re-sync
on the next Register, but a gap between cutover and first re-sync would mis-resolve scope).
An unrecognised legacy `source` value is WARNED about and preserved verbatim, never refused —
the legacy schema never constrained the column, and the precedence rules treat any non-'agent'
source as operator-authoritative.

Mechanics follow ADR-0045/`RbacStore` post-#2703 unmodified: SHA-256 content fingerprint over
a canonical serialization of the RAW legacy rows, stamped with the completion marker in the
SAME transaction via the monotonic-promotion upsert (`DO UPDATE ... WHERE value = 'sourceless'
OR value = EXCLUDED.value RETURNING value`, `PQntuples()==0` on a real fingerprint = hard
refusal); holder-side verification on any later boot that still finds a local `tags.db`;
`legacy.close()` before move-aside (the Windows rename fix); one-release rollback window.

**Delta from ADR-0045 — row conflicts are DIRECTION-AWARE** (the `DeploymentStore` shape),
because `updated_at` gives tags a real direction signal where custom-properties' plain
`ON CONFLICT DO NOTHING` had none to use. `(agent_id, key)` is IDENTITY (a PK conflict IS the
identity match); `value`/`source`/`updated_at` are LIFECYCLE. Per conflicting row, compared
against the SANITIZED legacy values (a prior partial run inserted sanitized bytes):

| stored vs legacy | outcome |
|---|---|
| identical on all three | benign no-op, skip |
| stored `updated_at` strictly ahead | benign no-op, WARN (replica's legacy snapshot predates live progress) |
| legacy `updated_at` strictly ahead | **FAIL CLOSED** (rollback-then-roll-forward evidence; never silently discard the later write) |
| tied `updated_at`, differing content | **FAIL CLOSED** (two writes the second-granularity clock cannot order) |

A row inserted fresh mid-backfill that then loses to a concurrent writer (`PQcmdTuples()=="0"`
on the guarded insert) also fails closed rather than silently mixing two writers' rows. A
legacy file whose `updated_at` column is not INTEGER-typed (TEXT/NULL — SQLite's loose
typing would coerce it to 0 and silently mark every row "oldest" for the direction
compare) refuses the read outright (governance UP-14).
Recovery runbook: `docs/ops-runbooks/tag-store-backfill-recovery.md`.

**Known gap, recorded not hidden:** the release upgrade test
(`scripts/test/test-upgrade-stack.sh`) asserts backfill survival for the inventory store only
— no Wave 2 migration (Discovery/Deployment/CustomProperties/Notification included) has added
a per-store assertion, and this one follows that precedent rather than bolting a one-store
check onto the script. The right fix is one shared assertion sweep covering every
`migrate_from_sqlite` store (seed via old-release API → assert via new-release API), filed as
a follow-up for the wave rather than per-PR. Until it lands, backfill correctness evidence is
the unit-level decision-tree suite in `test_tag_store.cpp` (`[tag_store][backfill]`).

### Lifecycle

Constructed at its ORIGINAL `server.cpp` site (inside the `pg_pool_ && !startup_failed_`
guard), NOT moved down into the later PG-store section: the "Wire up store pointers for
AgentServiceImpl" block a few lines below hands `agent_service_` the raw pointer, and a
construction site after that block leaves the service's pointer null forever. `stop()` unwires
`agent_service_.set_tag_store(nullptr)` then resets the store BEFORE `pg_pool_.reset()`.
`/readyz` AND `/healthz` both carry a `tag_store` row from the start (the readyz-vs-healthz
drift class the health block's own comments document). Backfill failure is fatal
(`startup_failed_`).

## Considered and rejected

- **Keeping the collapsing `agents_with_tag` accessor for "compatibility"**: rejected — see
  the B-2b supersession note; the compatibility argument is circular once the same PR sweeps
  every caller, and a surviving collapsing accessor is exactly how a future caller silently
  inherits a fail-open read.
- **Aborting scope evaluation on a NULL tag store (full symmetry with props)**: rejected —
  it would break in-memory-only `tag:` resolution (`scopable_tags`), a real, working
  configuration with no store failure to distrust. The asymmetry is documented at the resolver.
- **Plain `ON CONFLICT DO NOTHING` for backfill row conflicts (the ADR-0045 shape)**:
  rejected — tags have a usable direction signal (`updated_at`) that custom-properties'
  conflict handling never exploited; ignoring it would silently keep Postgres's value even
  when the legacy side demonstrably progressed further (the ADR-0009
  rollback-then-roll-forward case the `DeploymentStore` review rounds forced).
- **Refusing unknown legacy `source` values**: rejected — would brick the mandatory backfill
  over a value the old store accepted; preserved verbatim + warned instead.
- **Changing the resolver's scopable_tags-first precedence** (arguably #1411-adjacent — a
  live agent's self-report shadows an operator store row during scope evaluation, opposite of
  the store-first cohort reads): out of scope for a substrate migration; preserved exactly and
  pinned by a test. If it is to change, that is its own reviewed decision.

## Amendment — 2026-08-20: resolver precedence flips to store-first (#3295)

The "Considered and rejected" entry above ("Changing the resolver's
scopable_tags-first precedence... out of scope for a substrate migration...
If it is to change, that is its own reviewed decision") named exactly this
change and deferred it. #3295 is that reviewed decision: `evaluate_scope`'s
`tag:<key>` resolver is now **store-first** — a TagStore row of any source
wins over a connected agent's live `scopable_tags` claim; the in-memory
value answers only when the store has no row at all for that `(agent,
key)` (a gateway-proxied agent, whose tags never reach the store via
`ProxyRegister` — tracked as #3372; or a tag not yet synced).
Additionally, `register_agent` now drops an agent-claimed `service` key
from the session entirely at ingest, mirroring the store-side purge
`sync_agent_tags` already performed (#3289) — and, separately, drops any
key/value pair failing `TagStore::validate_key`/`validate_value` (charset,
length) before it can reach the in-memory fallback either, so an
oversized or malformed self-report can never answer a `tag:` lookup for a
store-miss agent, matching the validation `sync_agent_tags` already
applies on the store side.

This does NOT reopen the "Aborting scope evaluation on a NULL tag store"
rejection above — a NULL store with no row to check still falls through to
the in-memory value, matching a real test/embedded configuration with no
store to distrust. It also does not disturb the DEGRADED-store fail-closed
contract (a store/pool/query error still aborts the whole evaluation).

The one accepted behavior change from the flip: if an agent's most recent
`sync_agent_tags` write failed (`agent_service_impl.cpp` logs "prior tag
set retained, agent re-syncs on next Register"), the store can briefly hold
a stale agent-authored value while the live session holds a fresher one —
store-first now returns the stale value where session-first would have
returned the fresh one. Accepted: the store remains the single source of
truth for `tag:` scope-DSL evaluation, and the row self-heals on the
agent's next successful sync.

A second, narrower residual window (pre-existing, not introduced by this
flip): the bulk store preload snapshots `tag_values` before `mu_` is
taken — a single bulk query rather than a per-agent round-trip while
holding the lock, the same "N sequential blocking Postgres calls held
under `AgentRegistry::mu_` is both a fail-open surface and a
lock-hold-during-network-I/O violation of ADR-0012 §2(b)" reasoning
ADR-0045 states for `props.<key>`. A concurrent operator write that
commits after the snapshot but before the per-agent loop reaches that
agent is invisible to that ONE `evaluate_scope` call — but what the
resolver returns for it depends on whether a row for that `(agent, key)`
already existed at snapshot time. If it did not (the write is a fresh
INSERT), the lookup misses and the call answers from the in-memory
fallback, indistinguishable from the pre-#3295 behavior for that one call.
If a row already existed (the write is an UPDATE, or a DELETE), the lookup
still hits — the call returns the pre-race, now-stale store value, never
the fallback; this collapses into the same stale-value shape as the
failed-resync trade-off above, not into session-first behavior. Either
way the window is bounded to one call and self-corrects on the very next
`evaluate_scope` call (a fresh preload). This shape already existed for
`props.<key>` before this PR; it is now also true for `tag:<key>`.

Full precedence rule: `docs/asset-tagging-guide.md` "Tag source precedence
(read time, scope-DSL, #3295)"; cross-references: `docs/adr/1006-service-scope-default-deny.md`,
`docs/auth-architecture.md`.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production
Yuzu fleet has ever run a pre-Postgres build of any store — the mandatory,
fingerprint-verified, direction-aware backfill this ADR designed (across all four tag
sources) was real, working code that never had real legacy data to protect. The
"Recovery runbook" line earlier in this ADR is now dead: `docs/ops-runbooks/
tag-store-backfill-recovery.md` is deleted along with the mechanism it documented.

`TagStore::migrate_from_sqlite()` and its private helpers/types (`kSourcelessFingerprint`,
`is_known_source`, `legacy_has_table`, `sha256_hex`, `legacy_text`, `LTag`,
`LegacySnapshot`, `append_field`, `canonicalize_legacy_snapshot`,
`fingerprint_legacy_snapshot`, `legacy_fingerprint`) are removed
(`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623). `tag_store_meta`
— whose entire purpose was the backfill idempotency marker — is dropped via a
version-bumped `{2, "DROP TABLE IF EXISTS tag_store_meta;"}` migration, not edited into
v1: this store IS constructed in production, so v1 has actually run against real
dev/UAT databases. `server.cpp`'s boot path now runs
`legacy_sqlite_probe::warn_if_legacy_rows` over `tags` instead — silent unless real rows
are found, never blocks boot. The dedicated `yuzu_server_tag_store_backfill_total`
metric and its `YuzuTagStoreBackfillNotCompleted` Prometheus alert are also removed;
`set_metrics()`/the `metrics_` pointer stay — the read-degrade counter
(`yuzu_server_tag_store_read_degrade_total`) is unrelated and still live.
