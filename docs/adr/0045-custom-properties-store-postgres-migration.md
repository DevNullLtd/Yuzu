# ADR-0045: CustomPropertiesStore → PostgreSQL (Wave 2)

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** pg workstream (one of four parallel Wave 2 easy-store migrations, alongside
  `NotificationStore`/`DiscoveryStore`/`DeploymentStore`)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012, ADR-0036 (typed-read
  program policy)

## Context

`CustomPropertiesStore` (`custom-properties.db` today, `server/core/src/custom_properties_store.{hpp,cpp}`,
~465 LOC pre-migration) holds typed, operator-authored per-agent metadata — free-form key/value
properties (`custom_properties`, PK `(agent_id, key)`) plus optional per-key type/validation
policy (`custom_property_schemas`, PK `key`). Properties are usable in scope expressions via
`props.<key>` (`AgentRegistry::evaluate_scope`, `docs/asset-tagging-guide.md`), which makes this
store's read path feed dispatch/targeting decisions, not just dashboard display.

Picked as one of the "4 easiest of the 12 not-yet-migrated Wave 2 stores" (file size, table count,
zero FK coupling to any other store — verified by grep, no `FOREIGN KEY`/`REFERENCES` in the
original `.cpp`). The store has existing test coverage (`test_custom_properties_store.cpp`,
550 lines pre-migration) to port/extend.

**Why this is not purely routine, despite the "easy" bucket:** the same class of fail-open the
`ResultSetStore` migration (ADR-0036) closed for `from_result_set:<id>` scope atoms was latent
here too. `AgentRegistry::evaluate_scope`'s `props.<key>` resolver called
`props_store->get_value(id, prop_key)` per agent inside the fleet loop, collapsing "no such
property" and "the read failed" to the same empty string. Under `NOT props.<key>` (or `!=`), an
empty resolution is a match — so a transient Postgres blip under the pooled connection this
migration introduces would silently invert to "every agent matches," a fleet-wide dispatch
fail-open reachable without any code the operator wrote being wrong. This ADR's scope therefore
extends to `AgentRegistry::evaluate_scope`'s `props.<key>` resolution, not only the store itself.

## Decision

Migrate to PostgreSQL schema **`custom_properties_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server `PgPool`. `sqlite3_changes()` → `RETURNING` (#1033).

### Posture: authoritative (ADR-0012 §1)

Device custom properties and their schemas are irreducible operator-authored asset-tagging data,
not expendable telemetry — confirmed per the kickoff doc's explicit prompt to re-derive posture
from the code rather than trust the ladder doc's provisional entry. Every read whose result can
feed a `props.<key>` scope/dispatch decision (`get_properties`, `get_property`, `get_value`,
`get_property_map`, and the new bulk `get_values_for_keys`) returns
`std::expected<T, CustomPropertiesReadError>` — `kDegraded` on a store/pool/query failure, never
collapsed into the empty/not-found success shape (ADR-0036 program policy). Non-scope-feeding
reads (`list_schemas`, `get_schema` — admin-surface display only) stay plain-optional/container,
matching the `ResultSetStore`/`ManagementGroupStore` precedent of scoping the typed-read widening
to exactly the reads that can feed a decision.

### Schema

Two independent tables, column-for-column with the SQLite original (`updated_at` becomes
`BIGINT`), plus a new `custom_properties_meta` (key/value) for the backfill's idempotency marker
and source fingerprint — the same bookkeeping-table shape `RbacStore`/`ManagementGroupStore` use,
not a data table:

```sql
CREATE TABLE custom_properties (
    agent_id    TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    type        TEXT NOT NULL DEFAULT 'string',
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (agent_id, key)
);
CREATE INDEX custom_props_agent_idx ON custom_properties (agent_id);

CREATE TABLE custom_property_schemas (
    key               TEXT PRIMARY KEY,
    display_name      TEXT NOT NULL DEFAULT '',
    type              TEXT NOT NULL DEFAULT 'string',
    description       TEXT NOT NULL DEFAULT '',
    validation_regex  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE custom_properties_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
```

### Cross-table validation stays application-layer, not a Postgres FK/CHECK

The kickoff doc flagged this as a decision to make explicitly rather than default silently:
`set_property`'s `validate_against_schema` reads `custom_property_schemas` for the given key and
enforces type/regex before the write — ported as application-layer logic on the same lease as the
write (ADR-0012 §2(c): one logical operation, not two acquires), unchanged from the SQLite
original's behavior. **No FK added**, for two reasons: (1) a schema is optional per-key *policy*,
not a fixed enum a property's `type` column must reference — most keys never get a schema row at
all, which a FK from `type` cannot express; (2) `delete_schema` must not cascade or block on
existing property rows (the SQLite original's `DELETE FROM custom_property_schemas` never touched
`custom_properties`, and preserving that — "delete schema removes validation, existing values
untouched" — is itself asserted by a ported test). A real FK would either forbid this delete or
silently orphan/cascade in a way the original behavior never had.

### Secrets: none

Property values are free-form operator-set text (max 1024 bytes). No dedicated secret column, no
schema commitment to structured secret material. An operator *could* paste a credential-shaped
string into a property value, but that is true of any free-text field in the product (a tag
value, a management-group description) and is not, on its own, grounds for `SecretCodec` —
ADR-0010's secrets seam targets columns the *store* commits to holding secret material, not free
text an operator could theoretically misuse. Stated explicitly per the kickoff doc's prompt, not
silently assumed.

### `props.<key>` scope-DSL fail-open — closed at the resolver, not just the store

`AgentRegistry::evaluate_scope` (`agent_registry.cpp`) already preloads `from_result_set:<id>`
membership once, before the per-agent loop, aborting (`nullopt`) on a degraded preload — the fix
`ResultSetStore`'s migration (ADR-0036) added for the identical fail-open shape. `props.<key>`
resolution is now given the same treatment:

- A new `collect_props_keys` walks the parsed scope AST (mirroring `collect_result_set_ids`) to
  find every `props.<key>` atom referenced.
- A new `CustomPropertiesStore::get_values_for_keys(keys)` bulk-preloads
  `agent_id -> (key -> value)` for exactly those keys in ONE query (`WHERE key = ANY($1::text[])`
  via `pg::to_text_array`), never a per-agent round-trip — the same reasoning that motivated the
  `from_result_set:` preload (N sequential blocking Postgres calls held under
  `AgentRegistry::mu_` is both a fail-open surface and a lock-hold-during-network-I/O violation of
  ADR-0012 §2(b)).
- A `kDegraded` preload result **aborts the whole scope evaluation** (`nullopt` at the time this
  ADR was written; `evaluate_scope` widened again to `std::expected<..., ScopeEvalError>` by
  #4981 PR-1, `ScopeEvalError::Kind::StoreDegraded` for this exact case), exactly like a
  `member_set_owned` degrade — never silently resolves every `props.<key>` atom to `""` (no
  match), which inverts to "matches every agent" under `NOT`/`!=`.
- A scope with no `props.<key>` atom is unaffected — the preload is a no-op, and every existing
  `evaluate_scope` call site already collapses the abort via `.value_or(std::vector<std::string>{})`
  (the same `H1`-established pattern used for the `from_result_set:` fix), so no call site needed
  a signature or behavior change beyond this.

### Backfill (ADR-0009) — mandatory

Custom properties and schemas are operator-authored asset-tagging data that cannot be
re-derived — mandatory, one-time, idempotent, fail-closed `migrate_from_sqlite()`. Follows the
`RbacStore` post-#2703 reference shape (`docs/postgres-store-playbook.md` "Local source absence
never creates terminal migration state on its own") **unmodified for the fingerprint stamp
mechanics**: a SHA-256 content fingerprint of the legacy `custom-properties.db` is stamped
alongside the completion marker in the SAME transaction via `RbacStore`'s monotonic-promotion
`DO UPDATE ... WHERE` upsert (never a plain `ON CONFLICT DO NOTHING`), so a later boot that still
holds a local legacy file verifies the marker was actually derived from THIS file's content
before trusting it (never a bare "marker present → skip") — closing the holder-side gap
`ManagementGroupStore`'s backfill has not yet ported.

**Governance correction (Gate 2 security-guardian, this PR):** an earlier revision of this store
simplified `stamp_complete` to a plain `ON CONFLICT DO NOTHING` on the theory that "nothing else
writes `custom_properties`/`custom_property_schemas` before first boot completes" makes any two
racing writers' fingerprints interchangeable. That reasoning holds only when every racing
replica's legacy file has *identical* content — it does not hold for two replicas racing first
boot with *different* real legacy content (a realistic case: independently-seeded pre-cutover
servers being merged into one Postgres deployment). In that case both replicas' per-row
`ON CONFLICT DO NOTHING` inserts on the DATA tables also silently interleave — the loser's rows
land, then loses the marker/fingerprint race, then logs success and moves its own legacy file
aside, permanently discarding the fact that the resulting table is a mix of both replicas' data
with no record either operator can recover from. The fix — shipped in this same PR, not deferred
— is `RbacStore`'s exact `stamp_complete` mechanics: promote (`DO UPDATE ... WHERE value =
'sourceless' OR value = EXCLUDED.value`) rather than no-op on a fingerprint collision, and treat
"this call's own fingerprint lost to a DIFFERENT real value" as a hard failure this replica's own
boot must refuse on (`PQntuples() == 0` on the `RETURNING` read). See
`docs/ops-runbooks/custom-properties-store-backfill-recovery.md` for the operator-facing recovery
procedure this produces.

**What IS still sized down from `RbacStore`'s full state machine**, deliberately: this store has
no revoke-vs-reseed conflict, so it needs none of `RbacStore`'s revoke-coordination locking or
its `rbac_enabled`-flag read-back-verification step — only the fingerprint-promotion mechanics
above carry over. Rows are inserted per-row inside one transaction, `ON CONFLICT DO NOTHING`
(config data is small; the ~27-store playbook's array-batching guidance targets high-volume
ingest, not reference-sized tables). Legacy file moved aside after a verified backfill
(one-release rollback window).

### Lifecycle

`stop()` (`server.cpp`) resets `custom_properties_store_` explicitly, before `pg_pool_.reset()`
— matching every other migrated store's belt-and-braces discipline (declaration order alone
would also be safe here, since the store has no background thread or other consumer holding a
borrowed pointer to unwire first, but the explicit reset keeps the destruct-before-pool
discipline uniform and doesn't rely on a future reader re-deriving why declaration order happens
to be safe). The store is already in the `/readyz` conjunction (`server.cpp`, unchanged by this
migration — it predates it as a placeholder `is_open()` check that now reflects the real
Postgres-backed state). Construction is fail-closed (ADR-0007/0012 §1): a reachable database
whose schema can't migrate/open, or whose mandatory backfill fails, sets `startup_failed_` and
the server refuses to serve.

## Considered and rejected

- **A real FK from `custom_properties.type` to a schema-type enum**: rejected — see "Cross-table
  validation stays application-layer" above; the data model has no fixed-enum relationship to
  express, and a FK would change `delete_schema`'s observable behavior.
- **A plain `ON CONFLICT DO NOTHING` fingerprint stamp** (this store's own first-draft
  simplification): rejected after Gate 2 review found it silently drops data on a
  divergent-legacy-content concurrent first boot — see the governance correction above. The
  monotonic-promotion upsert is ported from `RbacStore` unmodified; there was no correct way to
  size this specific mechanic down further.
- **`RbacStore`'s revoke-coordination locking and `rbac_enabled` read-back-verification**:
  rejected as genuinely over-scoped for this store — no revoke path exists here, and there is no
  analogous single security-critical flag to verify. This is the part of `RbacStore`'s machinery
  that stays out; the fingerprint-promotion mechanics above do not.
- **Leaving `props.<key>` resolution as a per-agent store call**: rejected — reproduces the exact
  `ResultSetStore`/ADR-0036 fail-open one hop later, and holds `AgentRegistry::mu_` across N
  sequential blocking Postgres round-trips.

## Consequences

- `props.<key>` scope resolution now aborts (denies the dispatch/arm, the safe direction) rather
  than silently matching the whole fleet on a Postgres blip — closes a fail-open this migration
  would otherwise have introduced by moving a previously-synchronous SQLite read onto a pooled
  connection with real failure modes.
- `AgentRegistry::evaluate_scope` gains one new bulk preload query per scope evaluation that
  references `props.<key>`, symmetric with the existing `from_result_set:` preload; no call site
  needed a signature change.
- Tests → `YUZU_REQUIRE_PG_DB_TPL`-equivalent (`PgTestTemplate` + a file-owned pool,
  TRUNCATE-reset per test, the `test_product_registry_store.cpp` pattern) for CRUD/schema/bulk
  coverage; backfill / fresh-database tests use plain `YUZU_REQUIRE_PG_DB` against their own
  per-test database.

## Follow-ups

- `ManagementGroupStore`'s backfill has not yet ported the holder-side fingerprint-verification
  gap this store's backfill was built with from the start (tracked separately per the playbook's
  existing note — not new to this ADR).
- **Write-path degrade is not type-widened** (governance Gate 6 compliance-officer, this PR):
  `set_property`/`delete_property`/`list_schemas`/`upsert_schema` collapse a Postgres
  pool-timeout/query-error into the same generic result a genuine validation-failure/not-found/
  empty-list case produces (400/404/200-empty respectively) — unlike `get_properties`, which was
  widened to a distinguishable `503`. This is unchanged, byte-identical behavior from the SQLite
  original (confirmed via `git show origin/dev:server/core/src/custom_properties_store.cpp`) and
  the same posture `ManagementGroupStore`/`ResultSetStore` document for their own un-widened
  writes — not a regression this migration introduces, but the Postgres migration makes a
  degrade a materially more routine occurrence than a local SQLite file error ever was.
  Documented in `docs/user-manual/rest-api.md`'s per-route notes; widening to a typed
  degraded-vs-not-found distinction on the write path is tracked as a follow-up, not fixed here
  (matches `ResultSetStore`'s own "not yet widened — tracked as a follow-up" framing for the
  identical class of un-widened write).
- **Legacy-file removal after the one-release rollback window** (ADR-0009) is an unautomated,
  repo-wide convention with no per-store tracking issue — not specific to this store; worth one
  umbrella issue across the ~15-store ladder rather than a per-store follow-up here.
- Wave 2 continues with the other three parallel easy-store migrations
  (`NotificationStore`/`DiscoveryStore`/`DeploymentStore`); no ordering dependency on this one.

## Update (2026-08-14) — write-path degrade classifier lands for `set_property`/`upsert_schema`

The "Write-path degrade is not type-widened" follow-up above is now PARTIALLY resolved, per an
adversarial re-review (fjarvis) of the merged PR #3065.

`set_property` and `upsert_schema` keep their `std::expected<void, std::string>` shape, but every
genuine DB/lease-failure `unexpected()` in both (store-not-open, pool-acquire timeout, the
schema-validation lookup's own query failure, the write's own query failure) is now prefixed with
the new public `kCustomPropertiesDbErrorPrefix` constant ("db_error: "), mirroring
`DeploymentStore`'s `kDeploymentDbErrorPrefix` idiom. Their REST routes (`PUT
/api/agents/:id/properties/:key`, `POST /api/property-schemas`) classify on that prefix and now
return a distinguishable `503` for a genuine outage, `400` only for caller-input/schema-validation
failures — closing the gap where a Postgres blip during either write was indistinguishable from
the caller's own bad input. `docs/user-manual/rest-api.md`'s per-route notes are updated to match.

`get_schema` and `delete_schema` are separately widened from a plain `std::optional`/`bool` to
`std::expected<..., CustomPropertiesReadError>` (reusing the existing typed-read enum, not the
string-prefix idiom — these are pure store-level API surface with **no current REST caller**;
schema lookup/delete are only exposed today via `GET /api/property-schemas`'s bulk `list_schemas`).
Widened ahead of a future caller inheriting the SQLite-era not-found/degrade conflation neither had
a documented justification for (unlike `list_schemas`/`delete_property`, which the fjarvis review
confirmed already carry adequate "why it's safe" reasoning and were deliberately left as-is).

**Not fixed, deliberately:** `delete_property` and `list_schemas` keep their existing
bool/plain-container shape — the fjarvis review found both already carry a recorded justification
(admin-surface/non-scope-feeding, matching the prior SQLite contract), so there was no defect to
fix, only ones lacking that reasoning (`get_schema`/`delete_schema`) or an active route bug
(`set_property`/`upsert_schema`).

**Known gap, disclosed rather than closed:** no REST-route-level test asserts the new 400-vs-503
split for either route (the existing coverage is store-level, asserting the prefixed error string
directly) — the route's classification is a single `if` branch mirroring `discovery_routes.cpp`'s
already-tested `is_deployment_db_error` pattern, and building new route-level test infrastructure
for these two handlers (which are registered inline in `server.cpp`, not through a separately
testable `register_routes(HttpRouteSink&, ...)` overload) was judged disproportionate to this fix's
scope.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production
Yuzu fleet has ever run a pre-Postgres build of any store — the mandatory
monotonic-promotion-fingerprint backfill this ADR ported from `RbacStore` was real,
working code that never had real legacy data to protect.

`CustomPropertiesStore::migrate_from_sqlite()` and its private helpers (`legacy_has_table`,
`sha256_hex`, `legacy_text`, `append_field`, `canonicalize_legacy_snapshot`,
`fingerprint_legacy_snapshot`, `read_legacy_snapshot`, `legacy_fingerprint`, and the
`LProperty`/`LSchema`/`LegacySnapshot` types) are removed
(`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623). `custom_properties_meta`
— whose entire purpose was the backfill idempotency marker — is dropped via a
version-bumped `{2, "DROP TABLE IF EXISTS custom_properties_meta;"}` migration, not edited
into v1: this store IS constructed in production, so v1 has actually run against real
dev/UAT databases. `server.cpp`'s boot path now runs `legacy_sqlite_probe::warn_if_legacy_rows`
over the two legacy tables (`custom_properties`/`custom_property_schemas`) instead — silent
unless real rows are found, never blocks boot. The dedicated
`yuzu_server_custom_properties_backfill_total{result}` metric and
`docs/ops-runbooks/custom-properties-store-backfill-recovery.md` are both removed — there is
no backfill left to observe or recover from.
