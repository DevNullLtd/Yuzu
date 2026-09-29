---
status: accepted
date: 2026-07-15
owner: platform (engine-principals program)
deciders: maintainer decision (Tr3kkR) — fresh-start migration locked; security-guardian to confirm the ADR-0009 carve-out reconciliation
scope: server — `ApiTokenStore` (API/MCP bearer tokens), its cutover from SQLite to PostgreSQL,
  and the new `principal_kind` column that seeds the engine-principals program
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0010 (secrets-at-rest), ADR-0012 (server Postgres store contract), ADR-1005 item 2b
  (engine principals & delegation — `docs/auth-engine-principals-design.md`)
related: docs/postgres-migration-ladder.md (Wave 3 → Done); #1330 (Postgres ladder 5:
  secrets stores migration — api-tokens + ca); plan PR 4.1 of the engine-principals program
---

# 0030 — `ApiTokenStore` Postgres migration + `principal_kind` (fresh-start, no backfill)

## Context

`ApiTokenStore` (`server/core/src/api_token_store.{hpp,cpp}`) issues and validates the bearer
tokens used by the REST API and MCP surfaces. It is currently a SQLite store
(`api-tokens.db`) holding `token_id`, `token_hash` (SHA-256 of the raw token — the raw token
itself is never persisted), `name`, `principal_id`, `scope_service`, `mcp_tier`, `created_at`,
`expires_at`, `last_used_at`, and `revoked`. ADR-0006 commits every server store to Postgres;
ADR-0009's original text carved secret-bearing stores (`api_token`, `ca`) out of the standard
first-boot-backfill mechanism pending a dedicated secrets-at-rest design. That design landed as
ADR-0010 and re-scoped the carve-out: `api_token` and `ca` hold no plaintext secret material —
only verify-only hashes / key references — so they were reclassified **unblocked** and released
onto the normal migration ladder (`docs/postgres-migration-ladder.md`, Wave 3, "hash-only
unblocked"). This ADR is that per-store migration, and is PR 4.1 of the engine-principals
program (`docs/auth-engine-principals-design.md`, ADR-1005 item 2b): the program's first slice
needs a `principal_kind` column on the token store to later admit `'engine'` principals
alongside `'human'` ones (a later PR; this one only adds the column and seeds it `'human'`).

## Decision

**Migrate `ApiTokenStore` to PostgreSQL as schema `api_token_store`, table `api_tokens`, with a
fresh-start (no-backfill) cutover, and add `principal_kind`.**

### Schema

- Schema name `api_token_store` (ADR-0008 Update naming rule: `snake_case(FullClassName)`
  including the `Store` suffix).
- Table `api_tokens` carries the existing columns unchanged in meaning
  (`token_id`, `token_hash`, `name`, `principal_id`, `scope_service`, `mcp_tier`, `created_at`,
  `expires_at`, `last_used_at`, `revoked`), plus:
  - `principal_kind TEXT NOT NULL DEFAULT 'human' CHECK (principal_kind IN ('human', 'engine'))`.
    Every token minted before and after this migration is `'human'`; `'engine'` is not yet
    reachable by any code path — it is reserved by this migration so the later engine-principals
    slice (which arms `'engine'`-kind validation/authorization) is a pure logic change, not
    another schema migration.

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1). This store backs token validity for every
authenticated REST/MCP request and the "Sign out everywhere" / stolen-laptop revocation path:

- **Construction fails closed.** If the Postgres schema cannot be opened or migrated, the
  server refuses to start (`startup_failed_`) rather than serve with a store that might
  silently accept forged or already-revoked tokens.
- **A runtime read error denies.** `validate_token` returning an error must be treated as "not
  valid" (fail-closed-safe) — never fall through to "unauthenticated request treated as
  anonymous/admin" or to a stale cache entry past its TTL.
- **A revoke/delete error is surfaced, never a silent success.** `revoke_token`,
  `revoke_for_principal`, and `delete_token` back "Sign out everywhere" and manual revocation;
  an operator who revokes a stolen laptop's token must be told if the revoke did not actually
  land, not receive a false "done".

This mirrors the posture already recorded for the other Wave-3-unblocked/Done authoritative
stores on the ladder (e.g. `VulnFindingStore`, `PreflightRunStore`).

### Hash-only, not secret material — ADR-0009 carve-out reconciliation

`ApiTokenStore` stores only a verify-only SHA-256 hash of each token, never the raw token or
any other secret material. Reconciling explicitly with ADR-0009's text (which this ADR
supersedes for this one store):

- ADR-0009's original "Consequences" section listed `api_token`/`ca` as **out of scope** for
  its backfill mechanism, reasoning that "a plain `migrate_from_sqlite()` copy into Postgres
  columns is forbidden for secret material." That reasoning targets *secret* material — data an
  attacker who reads the column can use directly (a plaintext credential, a private key). A
  verify-only hash is not that: possession of `token_hash` does not let an attacker
  authenticate (the whole point of hashing), so copying it column-to-column carries none of the
  risk ADR-0009's carve-out was written to prevent.
- ADR-0009's own **Update** (citing ADR-0010) already reached this conclusion in the abstract:
  `api_token`/`ca` are "hash-only / key_ref-only (no plaintext secret columns) and are
  **unblocked** onto the normal ladder." This ADR is the concrete per-store instance of that
  update — it does not need `SecretCodec` and does not run the ADR-0010 envelope-encryption
  backfill transform, because there is no plaintext to encrypt.
- **This reconciliation text supersedes ADR-0009's original carve-out language as applied to
  `ApiTokenStore` specifically** (ADR-0009's carve-out remains in force for `auth`, `webhooks`,
  `offload_targets`, and `runtime_config`, which do hold `SecretCodec`-gated plaintext-adjacent
  material). `security-guardian` reviews this PR to confirm the hash-only classification holds
  for every column added or touched (in particular, that `principal_kind` introduces no new
  secret-bearing surface — it does not).

### Fresh-start migration — no backfill (locked)

Unlike the general ADR-0009 backfill mechanism (mandatory for config/reference and audit;
skippable only for TTL'd ephemeral stores), **`ApiTokenStore`'s cutover ships no
`migrate_from_sqlite()` at all.** A new, empty Postgres `api_token_store.api_tokens` table is
created; the legacy `api-tokens.db` SQLite file is no longer opened by the server after this
migration lands (not even read-only for a rollback window). This is a locked maintainer
decision, not a default this ADR arrived at independently — recorded here because it is a
deliberate, documented departure from ADR-0009's default backfill-mandatory framing:

- **Consequence — operator-facing:** every API token and MCP token minted before the upgrade is
  invalidated. Operators must re-mint all API/MCP bearer tokens after upgrading to the release
  that ships this migration. This is called out in the changelog fragment for this PR and
  should be called out again in the release notes for whichever release ships it.
- **Why this is acceptable here** (unlike, say, `RbacStore` or `AuditStore`, where fresh-start
  is explicitly rejected by ADR-0009): API tokens are operator-mintable, cheap, and
  self-service to replace — there is no equivalent of "365 days of SOC 2 audit history" or
  "hand-authored RBAC policy" being discarded. Forcing a re-mint on a substrate cutover is also
  a reasonable hygiene event in its own right (an opportunity to prune stale/forgotten tokens),
  and it is convention-aligned: every prior Yuzu server store on this ladder has migrated
  greenfield / born-on-Postgres (`docs/postgres-migration-ladder.md`, Done section) — this store
  had existing SQLite data, but the maintainer elected to treat the cutover the same way rather
  than build and maintain a one-off hash-copying backfill path for a single release's rollback
  window.
- This is a store-specific override, not a general relaxation of ADR-0009: the default backfill
  mechanism (mandatory for config/reference and audit, skippable-behind-a-flag for TTL'd
  ephemeral stores) is unchanged for every other store still on the ladder.

## Considered and rejected

- **Standard ADR-0009 backfill** (copy `token_hash` and metadata rows from `api-tokens.db` into
  the new Postgres table, retain the legacy file read-only for one release). Technically
  straightforward — hashes copy safely with no transform needed — but rejected by the
  maintainer in favor of the simpler fresh-start cutover; re-minting a bearer token is low-cost
  for operators and avoids building a bespoke rollback-window path for a store this cheap to
  repopulate.
- **`principal_kind` as a separate table / join** (e.g. a `principal_kinds` lookup table).
  Rejected as needless indirection for a two-value enum gated by a `CHECK` constraint; a future
  third kind (if one ever arrives) is a one-line migration either way.

## Consequences

- `ApiTokenStore` moves from `sqlite3*` to `pg::PgPool&`. Construction inlines the standard
  born-on-PG idiom — a pinned `pool_.acquire()` lease + `PgMigrationRunner::run(lease, kStoreName,
  migrations())` + `open_ = true` — matching every sibling store (`preflight_run_store`,
  `deployment_run_store`, `vuln_finding_store`); it is wired into `server.cpp` inside the
  `if (pg_pool_ && !startup_failed_)` guard per the playbook — a store that cannot open is a
  fatal startup error.
- All runtime statements schema-qualify `api_token_store.api_tokens`; mutate-and-return paths
  (`create_token`, `revoke_token`, `revoke_for_principal`, `delete_token`) use `RETURNING`
  rather than `sqlite3_changes()` (#1033).
- The in-memory validate-token LRU cache and its revoke-generation TOCTOU guard are preserved
  unchanged — they sit above the store and are agnostic to the underlying engine.
- No `migrate_from_sqlite()` exists for this store and none should be added later without a
  fresh ADR — its absence is intentional, not a gap.
- `docs/postgres-migration-ladder.md`'s `ApiTokenStore` row moves from Wave 3 to Done, citing
  this ADR.
- The `principal_kind` column is inert in this PR (always `'human'`); the engine-principals
  program's later slice(s) add the code paths that mint and validate `'engine'`-kind tokens
  against `docs/auth-engine-principals-design.md`'s trust-tier/delegation model. No further
  schema change to this table is anticipated for that follow-on work.
- **Operator-facing:** existing API and MCP bearer tokens stop working on upgrade; operators
  must re-mint them. See the changelog fragment for this PR and the `## ⚠️ Breaking` section in
  `docs/user-manual/upgrading.md`.

## Follow-ups and accepted risks (governance review, 2026-07-15)

The full governance pipeline (13 agents) and a prior Hermes ×2 + architecture adjudication cleared
this migration with 0 CRITICAL/HIGH. The following were recorded as accepted risks or tracked
follow-ups rather than in-PR changes — none blocks the substrate migration:

- **Multi-instance token-revocation propagation (accepted, tracked).** The Postgres substrate now
  permits running multiple server replicas against one database — a topology the single-file SQLite
  store previously precluded. `validate_token` uses a per-process 60-second cache, so a token
  revoked on replica A can remain accepted on replica B until that replica's cache entry expires (≤
  60 s). Single-instance deployments are unaffected. Proper close (cross-replica cache invalidation
  / shorter TTL / a version column) is folded into the concurrency-hardening follow-up (#2173).
- **`create_token` racing `revoke_for_principal` (accepted, tracked).** Under READ COMMITTED on
  independent pooled connections, a `create_token(principal)` committing concurrently with a bulk
  `revoke_for_principal(principal)` can leave the new token live — a window the old shared
  `db_mtx_` closed. Tracked with #2173.
- **`create_token` DB-error attribution (tracked).** The store now surfaces DB-unavailable /
  pool-timeout errors from `create_token`; the REST/settings callers currently map every
  `create_token` failure to the CSPRNG-entropy metric/audit marker. HTTP status is correct (503);
  the metric/audit label is not. Belongs to the tracked typed-`create_token`-error follow-up.
- **Legacy `api-tokens.db` disposal (accepted risk).** The migration deliberately does not delete
  the old SQLite file; it is inert (never read) and hash-only (verify-only SHA-256 + non-secret
  metadata: `principal_id`, `name`, `scope_service`), so it is not secret material. It is left in
  place as a one-release rollback breadcrumb and to avoid destructive filesystem action at boot; a
  boot-time warning tells the operator it can be removed. Automating its removal (installer/upgrade
  script) is a follow-up.
- **No audit event for the bulk invalidation.** The fresh-start cutover emits no audit row for the
  invalidation itself (there is nothing to enumerate — the old rows are never read); the evidence
  trail is this ADR + the changelog + the boot-time warning. A `system.*` startup audit row is a
  possible follow-up if an access-review artifact needs to cite the event directly.
- **`principal_kind` C++-side allowlist (PR 4.2 prerequisite).** Integrity of the column relies
  today on the DB `CHECK (principal_kind IN ('human','engine'))`; no caller supplies a non-default
  value yet. When engine-principals PR 4.2 wires caller-supplied `principal_kind`, an explicit
  C++-side validation must be added before the DB round-trip.
