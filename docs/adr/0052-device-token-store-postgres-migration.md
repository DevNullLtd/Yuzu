---
status: accepted
date: 2026-08-18
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 2/3 batch-4 migration worker, following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 3 secret-gated row, resolved verify-only-hash below)
scope: server — `DeviceTokenStore` (device authorization tokens, capability 18.8), its cutover
  from SQLite to PostgreSQL, its ADR-0009 backfill, and its dormancy record
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0010 (secrets at rest), ADR-0012 (server Postgres store contract)
related: docs/postgres-migration-ladder.md (Wave 3 -> Done); docs/adr/0048-license-store-postgres-migration.md
  (same dormancy family, same era — LicenseStore); docs/adr/0051-software-deployment-store-postgres-migration.md
  (same dormancy family, same era — SoftwareDeploymentStore); docs/adr/0043-deployment-store-postgres-migration.md
  (single-table IDENTITY/LIFECYCLE backfill template this migration follows most closely)
---

# 0052 — `DeviceTokenStore` Postgres migration (authoritative, dormant, with backfill)

## Context

`DeviceTokenStore` (`server/core/src/device_token_store.{hpp,cpp}`) persists device authorization
tokens (capability 18.8) — bearer credentials an operator issues, scoped to a device and/or
instruction definition, validated on every request an agent presents one against. It was
previously a SQLite store (`device-tokens.db` by convention — the legacy path is caller-supplied,
matching every other migrated store), guarded by a single `shared_mutex`, single table
`device_auth_tokens`.

### DORMANT — verified 2026-08-18 against `origin/dev`; resolves the kickoff's open dormancy question

**Nothing in production constructs this store.** `rest_api_v1.hpp`'s `register_routes` overloads
take `DeviceTokenStore* device_token_store = nullptr`, and the `/api/v1/device-tokens*` route
family in `rest_api_v1.cpp` registers only `if (device_token_store)` — no call site anywhere in
the server passes a non-null pointer. `AgentRegistry` holds only a nullable
`DeviceTokenStore* device_token_store_` via `set_device_token_store`, read inside
`register_agent`'s W1.5/#823 revoke-on-re-registration path.

**The kickoff doc left open whether this store was never-wired or unwired — pickaxing the
history answers it: UNWIRED.** `git log --all -S"make_unique<DeviceTokenStore>"` finds it:
construction WAS wired by `acc6c481a` ("Add T2 capabilities with governance fixes for 9 blocking
findings") — `device_token_store_ = std::make_unique<DeviceTokenStore>(dt_db)`, alongside
`sw_deploy_store_`/`license_store_` in the same `Phase 7: Software Deployment, Device Tokens,
Licensing` block — and removed by `2fcfb95b5` ("Decompose server.cpp god object") in the exact
same diff hunk that dropped `SoftwareDeploymentStore`'s and `LicenseStore`'s construction sites.
All three stores are the identical **UNWIRED** family (ADR-0048/0051's "same two commits"
finding), not a distinct never-wired one — `DeviceTokenStore` is simply the third member,
confirmed here rather than assumed. (History note: `acc6c481a` and `495c3f2e8` are duplicate
commit objects — identical tree and message, different parents — a pre-existing artifact of this
repo's history; `acc6c481a` is cited here to match the exact hash ADR-0048/0051 already use for
the same event.) Re-verify with `git show 2fcfb95b5 -- server/core/src/server.cpp
| grep -B3 device_token_store_`. Confirmed with the product owner (2026-08-18) that this is a
deliberate current state (the same T2-capability shelving as its siblings), not an accidental
regression.

**Re-wiring the store at boot is explicitly OUT OF SCOPE for this migration.** This ADR migrates
the store's persistence layer only.

**Backfill is NOT skippable on the strength of that dormancy.** The store WAS constructed during
the `acc6c481a..2fcfb95b5` window, so a deployment that upgraded through that window can hold a
real `device-tokens.db` with genuinely issued (and possibly since-revoked) tokens. There is no
production fleet today (memory: "fresh-build does not downgrade a defect/obligation" is the
standing rule this ADR follows), so the backfill code path below is shipped and unit-tested but
has, like the store's own construction, zero production callers as of this writing —
`server.cpp` calls neither. It is wired the moment a future change re-constructs
`DeviceTokenStore`; the expected legacy filename is `device-tokens.db` (the pre-removal
construction site's argument).

## Decision

**Migrate `DeviceTokenStore` to PostgreSQL as schema `device_token_store`, table
`device_auth_tokens`, with a standard ADR-0009 first-boot backfill.**

### Schema

- Schema name `device_token_store` (ADR-0008 Update naming rule — also matches the original
  SQLite `MigrationRunner::run(db_, "device_token_store", ...)` tracking name unchanged).
- `device_auth_tokens` carries the existing columns unchanged in meaning and type mapping
  (`TEXT`→`TEXT`, `INTEGER` epoch-seconds columns→`BIGINT`, `INTEGER` boolean-as-0/1→`BOOLEAN`).
  `token_id` stays a **client-generated `TEXT` primary key** (32 lowercase-hex chars,
  `generate_token_id()`'s existing CSPRNG-derived format, unchanged) — pre-migration ID contracts
  are kept exactly, per the Wave 2/3 lesson from #3062/#3157/#3174.
- `idx_device_token_device` (on `device_id`) is preserved from the pre-migration schema.
  `idx_device_token_hash` is **not** reproduced: `token_hash`'s `UNIQUE` constraint already backs
  it with an index in Postgres (it was always a redundant duplicate index even in the
  pre-migration SQLite schema).
- A new table, `sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT
  NULL)`, is the backfill idempotency tracker (see Backfill below) — not part of the application
  data model.

### Secrets (ADR-0010) — Wave 3 classification resolved

**Verify-only hash, no `SecretCodec` involvement.** `token_hash` is a SHA-256 hash of the raw
token (`hash_token()` — checked EVP SHA-256 on every platform since #3351; originally a
BCrypt-on-Windows/OpenSSL-elsewhere split, kept cross-platform-identical to the pre-migration
store — see the 2026-08-22 amendment below); the raw token (`ydt_<64 hex chars>`) is generated,
hashed, and returned to the caller ONCE at `create_token` time — it is never persisted. This is
the same posture as
`LicenseStore`'s `license_key_hash` (ADR-0048) and `ApiTokenStore`'s token hash (PR 4.1) — this
is exactly why this Wave 3 store is migratable now without waiting on any further secrets-seam
work: the ladder's "verify/hash (confirm in ADR)" placeholder is confirmed here, against the
code, not assumed from the ladder row's wording. Backfill copies `token_hash` byte-for-byte
(verify-only data — a hash has nothing to "transform" into), never re-derives or re-hashes it.

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime — this is an
auth-credential store, not durability-on-top:

- **Construction fails closed**, same template as every other Postgres-backed store.
- **A silently-empty/false read or a silently-swallowed revoke is an auth bypass** — a stale
  token treated as still valid, or a revocation an operator issued never taking effect. Every
  reader/mutator therefore returns `std::expected<..., std::string>`: `list_tokens` (was a bare
  `std::vector`, silently empty on error), `revoke_token` (was `bool`, now
  `std::expected<void, std::string>` distinguishing `not_found: ` from a genuine DB failure),
  `revoke_by_principal` (was `int64_t`, now `std::expected<int64_t, std::string>` — see the #823
  fail-open hazard below). `create_token` was already `std::expected<std::string, std::string>`
  and keeps that shape, now additionally prefixing genuine DB/lease failures with
  `kDeviceTokenDbErrorPrefix` so they are distinguishable from CSPRNG-exhaustion and
  caller-input-validation errors (see the REST classification fix below).
- **`validate_token`'s typed `RejectedToken`/`DeviceTokenValidateError` contract is preserved
  EXACTLY** (#1052/#1053, W1.3) — same enum values, same field-population-by-variant table, same
  ordering (not_found → revoked → expired → unbound_legacy → binding_mismatch). Every genuine
  transaction-level PG error reaching `validate_token` collapses to
  `DeviceTokenValidateError::internal_error`, never a benign rejection reason — labelling a store
  fault as `not_found` would pollute the not-found/SIEM signal exactly as `LicenseStore`'s
  parallel finding (#1056) already established for this store's own pre-migration code. (gov
  unhappy-path UP-3: this is deliberately narrower than "every PG error" — the pre-flight `!open_`
  guard at the top of `validate_token`, which fires when the store itself failed to construct,
  collapses to `invalid_input`, not `internal_error`, unchanged from the pre-migration store's own
  contract — see `device_token_store.hpp`'s doc comment on `invalid_input`: "Empty / malformed raw
  token, or store closed." Wire behavior is unaffected either way — all variants collapse to the
  same 401 — but a boot-time Postgres outage would report through the `invalid_input` SIEM/metric
  bucket rather than `internal_error`.) `device_token_rejection.hpp`'s wire-boundary-collapse
  contract (every variant → the same 401/UNAUTHENTICATED response) is untouched — it depends on
  the enum shape, not the store's internal transport.
- **`validate_token` runs the read (row-locked, `SELECT ... FOR UPDATE`) and the accepted-path
  `last_used_at` bump inside one transaction** — the PG equivalent of the pre-migration store's
  single-`unique_lock`-for-the-whole-critical-section discipline (its own comment: "avoid TOCTOU
  ... a concurrent revoke_token could slip through between the read and the write"). A concurrent
  `revoke_token`/`revoke_by_principal` on the same row blocks until the transaction commits,
  rather than racing it.
- **Capacity note for the future wiring PR (gov Gate 6 sre)** — `kValidateTimeout` (`device_token_store.cpp`, 2000ms)
  bounds only the pool-acquire wait; the `SELECT ... FOR UPDATE` lock-wait inside `with_txn_for`
  runs to `lock_timeout_ms` (10000ms default), a real worst case well past the 2s figure the
  constant's name suggests. Once wired, `validate_token` is a genuine per-request
  bearer-credential hot path on httplib's thread-per-connection model, so a lease blocked on a
  contended row pins an HTTP worker, not just one slow response — pool saturation converts
  directly into worker starvation. The wiring PR should revisit `kValidateTimeout` toward a
  sub-second fail-fast budget and confirm pool sizing against anticipated validation QPS (the
  `PgPool`'s `Options` are shared cross-store today, no per-store knob). Mitigating factor: distinct
  tokens hash to distinct rows, so lock contention serializes per-device, not globally — a chatty
  single device only ever serializes against itself. **Extension (#3401, gov Gate 6 sre round 2)**:
  the same acquire-vs-lock-wait exposure applies to `register_agent`'s `revoke_by_device` call, on
  the gRPC thread pool rather than httplib's — a synchronized mass-reconnect (e.g. a gateway
  bounce, agents retrying with no initial jitter) drives concurrent `revoke_by_device` calls
  against the same shared `PgPool` on the registration path specifically. The wiring PR's capacity
  review should cover both paths, not just `validate_token`.
- **ADR-1005 note for the future wiring PR (gov Gate 4, round 3)** — wiring this store live makes
  its capability reachable for the first time, which triggers ADR-1005's REST+MCP parity
  requirement: every device-token behavior must be reachable via versioned REST *and* MCP, or
  carry a recorded exception in ADR-1005's exception ledger. No MCP twin exists today (correctly —
  a dormant, unreachable capability has no reachability claim to except), so the wiring PR is the
  one that must either add an MCP twin or record the exception, not this one.
- **`revoke_by_principal`'s #823 security-shaped hazard, closed by typing it.** This method is
  the re-registration-time defence against a briefly-impersonated agent (#779) replaying a
  previously issued token. The pre-migration signature (`int64_t`, 0 on both "nothing to revoke"
  and "the database call failed") could not distinguish those two cases — a DB blip during
  re-registration would silently leave the impersonated identity's prior tokens live, with
  nothing surfaced. `revoke_by_principal` now returns `std::expected<int64_t, std::string>`
  (store exposes the typed channel unconditionally, per ADR-0036's "the store exposes the type
  regardless of the current caller" — `AgentRegistry::register_agent`'s one call site currently
  only logs on failure, since re-wiring construction is out of scope for this migration and the
  call site has zero live production callers today; a future re-wiring should revisit whether a
  revoke failure ought to block the registration outright).
- Every genuine DB/lease failure is prefixed `db_error: ` (`kDeviceTokenDbErrorPrefix`, a
  store-local constant — deliberately not a reuse of `kLicenseDbErrorPrefix`/
  `kSwDeployDbErrorPrefix`, per ADR-0048's "Considered and rejected" precedent: a future rename
  of one store's prefix must not silently affect another's route classification).
  `rest_api_v1.cpp` gets a local three-way classifier, `device_token_error_status`, mirroring
  `license_error_status`'s contract-pin style: `not_found: ` → 404 (`revoke_token`'s missing-id
  case — preserves the pre-migration DELETE route's 404, which a blanket
  `DeploymentStore`-style binary classifier would have regressed to 400), `db_error: ` → 503,
  anything else (validation/business-rule errors, e.g. `create_token`'s "principal_id cannot be
  empty") → 400. A companion `device_token_client_message` helper never echoes a genuine
  DB/lease failure's raw `PQerrorMessage()` text to the client (mirrors `sw_deploy_client_message`
  — those fragments are internal implementation detail, not caller-actionable feedback).
- **The REST `create_token` failure path was previously CSPRNG-only by construction** (the
  pre-migration store could only fail `create_token` on entropy exhaustion or the
  already-unreachable "principal_id empty" case) — `POST /api/v1/device-tokens`'s handler
  unconditionally labelled every failure `csprng_unavailable:` and bumped the
  `yuzu_secure_random_failure_total{site=device_token}` counter. The migrated store can now ALSO
  fail `create_token` on a genuine Postgres error, which is not a CSPRNG condition — the handler
  now branches on `kDeviceTokenDbErrorPrefix` first: a genuine DB failure gets its own 503 +
  `Retry-After: 5` + `device_token.create`/`failure` audit path with the generic
  `device_token_client_message`-redacted detail (never the CSPRNG label, never the PRNG metric
  bump); everything else falls through to the original CSPRNG-shaped handling unchanged. Without
  this split, a Postgres blip during token issuance would be mislabelled `csprng_unavailable` in
  both the audit trail and SIEM-facing metrics — a false attribution a future incident responder
  would have had to debug around.

### `/readyz` / `/healthz`

**Not wired.** Every other migrated authoritative store on this ladder is wired into both
conjunctions, but `DeviceTokenStore` has no construction site in `server.cpp` at all (see
Context) — mirroring how the store is not constructed, it is not probed either, matching
`LicenseStore`/`SoftwareDeploymentStore`'s identical precedent. Recorded explicitly so this does
not read as an oversight: when a future change re-wires construction, add the `/readyz`/
`/healthz` conjunction entries at that time.

### Backfill (ADR-0009)

**Mandatory, standard single-table shape, fingerprint-verified** — matches `DeploymentStore`
(`docs/adr/0043-...md`, #3062) most closely among the already-migrated stores: a client-generated
surrogate `token_id`, single table, no small-human-chosen-identifier collision risk `RbacStore`
has to guard against.

- A replica with no local `device-tokens.db` (or a present-but-schema-less one) computes and
  stamps a `sourceless` sentinel fingerprint, exactly as `DeploymentStore` does. A fileless
  replica's boot never permanently blocks a later, DIFFERENT holder replica's real legacy data —
  the fingerprint is per-content, not a single fleet-wide completion flag (ADR-0040/#2697's
  "Local source absence never creates terminal migration state on its own" anti-pattern; a
  regression test proves the exact fileless-then-holder sequence).
- A replica holding real rows computes a SHA-256 fingerprint of a canonicalized, sorted,
  length-prefixed serialization of the table's rows (`device-token-legacy-fingerprint-v1`),
  scanned in `token_id ASC` (PK) order so two replicas whose legacy files order the same row set
  differently still acquire Postgres row locks in the same sequence during backfill INSERT,
  closing the deadlock class `LicenseStore`/`DeploymentStore`'s own Gate 8 architect finding
  closed for their scans.
- **Conflict handling on `token_id` (`ON CONFLICT (token_id) DO NOTHING RETURNING token_id`)
  partitions the compared columns into IDENTITY and LIFECYCLE, per the kickoff's explicit
  classification**: IDENTITY = `token_hash`, `name`, `principal_id`, `device_id`,
  `definition_id`, `created_at`, `expires_at` (write-once at INSERT — no other method mutates
  them); LIFECYCLE = `last_used_at`, `revoked` (both monotone — `last_used_at` only grows via
  `GREATEST()`, `revoked` only ever moves false→true, never back). An IDENTITY mismatch fails the
  backfill closed, naming both sides, the same class as every other migrated store's IDENTITY
  conflict.
- **The LIFECYCLE direction check applies the SAME fail-closed-on-legacy-ahead rule
  `DeploymentStore`/`LicenseStore`'s rank-based template already uses (gov Gate 3 architect,
  corrected from an earlier draft that mischaracterized this as a divergence — both siblings also
  fail closed when the legacy side is strictly ahead; verify against their own conflict-handling
  code, not this paragraph).** This store's field just doesn't need a rank computed: `revoked` is
  a two-value monotone flag with no terminal-tie case a multi-value status enum has to resolve —
  the store-specific point (flagged by the kickoff) is that `revoked` is not bookkeeping, it is
  the auth-bypass-relevant field:
    - Legacy shows `revoked=true`, Postgres currently holds `revoked=false` → **FAILS THE
      BACKFILL CLOSED**, the same treatment as an IDENTITY mismatch. Silently keeping Postgres's
      stale "still active" value would resurrect a credential the operator explicitly killed —
      exactly the ADR-0009 rollback-then-roll-forward shape (an operator revoked this token while
      running the pre-migration binary), except here the "evidence being discarded" is a security
      control, not a status label, which is why this ADR does not follow the sibling stores'
      "WARNING-log and keep Postgres's value" treatment for this one field.
    - Postgres already `revoked=true`, legacy still shows `revoked=false` → benign no-op,
      WARNING-logged. `revoked` is monotone, so Postgres being ahead is the ordinary shape of
      post-migration progress (an operator revoked it live after this legacy snapshot was taken).
    - `last_used_at`-only divergence (both sides agree on `revoked`) → always a benign no-op
      regardless of which side is numerically higher — it is bookkeeping with no auth-bypass
      consequence either direction. The backfill never updates an existing row in any of these
      three cases; only the fail-closed case aborts the whole transaction.
- Every legacy `token_id`/`token_hash` is validated as 32/64-lowercase-hex respectively **before**
  either can reach Postgres (gov security-guardian MEDIUM precedent, `LicenseStore`/ADR-0048): an
  invalid-UTF-8 or non-hex byte in a hand-edited/corrupted legacy value would otherwise reach
  Postgres raw and fail the INSERT with an opaque server-side constraint error that retries
  identically on every future boot against the same corrupt file. The other free-text columns
  (`name`/`principal_id`/`device_id`/`definition_id`) go through the same `sanitize_pg_text`
  UTF-8-strictness pass `LicenseStore`/`SoftwareDeploymentStore` use.
- The mid-scan-corruption guard is the same shape as `DeploymentStore`'s/`LicenseStore`'s: the
  terminal SQLite step code must be `SQLITE_DONE`, never merely "loop exited", so a corrupt page
  is never silently treated as an empty/complete table.
- **Memory is bounded; the legacy table is never materialized (#3399).** The fingerprint is a
  streaming SHA-256 over the `token_id ASC` scan — one encoded row resident at a time, not the
  whole table — byte-identical to the sorted-canonical-form hash a naive materialize-then-sort
  implementation would produce, because every encoded row starts `<32>:<token_id>` and `token_id`
  is the table's PK, so sorting the encodings and scanning in PK order produce the same sequence
  (pinned by a golden-fingerprint regression test). The copy pass re-reads the same SQLite
  snapshot and inserts in `kBackfillBatchRows` (500) row batches, each one
  `INSERT ... SELECT FROM unnest(...) ON CONFLICT (token_id) DO NOTHING RETURNING token_id`
  (`software_inventory_store.cpp`'s batched-insert pattern, ADR-0016/#1664) — conflicts are the
  batch rows `RETURNING` did not cover, and go through the same IDENTITY/LIFECYCLE classification
  above.
  Resident state is therefore O(500 rows) regardless of legacy table size, closing the gap
  `QuarantineStore`'s post-materialization row cap (ADR-0047, itself flagged as a gap in that
  ADR's own UP-6) would otherwise reintroduce here. **Deliberately no row cap**: unlike
  `QuarantineStore`, a cap would convert ordinary fleet growth into a boot refusal with no
  data-integrity justification — device tokens plausibly scale with device count, and streaming
  removes the reason a cap existed in the first place.
- **Retry contract is fail-closed and all-or-nothing.** The copy pass's batch inserts, every
  conflict read-back, the SQLite snapshot close, and the marker `INSERT` all run inside ONE
  Postgres transaction. The fingerprint pass (pass 1) runs BEFORE that transaction even opens —
  it performs no Postgres reads or writes at all, so it is fail-closed independently: any failure
  there (a mid-scan read error, a hex-validation failure) returns before `pool_.with_txn` is ever
  called, leaving nothing to roll back. Any failure inside the Postgres transaction — a batch
  statement error, an IDENTITY/LIFECYCLE fail-closed classification, a pass-1/pass-2 row-count
  mismatch, or a failure to close the SQLite snapshot — leaves the marker unstamped, so the NEXT
  BOOT re-fingerprints and retries the WHOLE file from scratch; a partial prior attempt never
  leaves partial rows (a fault-injection regression test proves this for a multi-batch failure
  specifically, not just a single-row one). This is the same contract the pre-#3399 per-row loop
  had — restructuring the copy pass into batches did not change it.
- **Legacy read discipline (#3398).** The read-only SQLite connection sets
  `PRAGMA busy_timeout=5000` (restoring the pre-migration store's setting, dropped by the initial
  rewrite; matches `SoftwareDeploymentStore`'s measured A/B precedent) and wraps the schema probe
  and both backfill passes in one deferred `BEGIN` snapshot transaction, so a legacy file merely
  held by a concurrent writer's lock is waited out — rather than surfaced immediately as a
  corruption-flavoured "scan aborted mid-read" — and both passes are guaranteed to see identical
  bytes.
- Legacy files are read READ-ONLY and never deleted/moved — retained for the ADR-0009
  one-release rollback window.

### Test-file drift discovered beyond the kickoff's own inventory

The kickoff doc named `test_device_token_store.cpp` and `test_device_token_rejection.cpp` as the
two files needing to "stay green." Compiling against `origin/dev` surfaced two more construction
sites the kickoff's own verification missed — the exact playbook warning ("long-lived migration
branches accumulate test-file drift against the pre-migration API... budget for it on every
`dev`-merge") this store's own precedents (`LicenseStore`/ADR-0048 found `test_rest_api_t2.cpp`;
this migration additionally found it in `test_rest_api_tokens.cpp` and
`test_agent_registry_token_revocation.cpp`, neither named by the kickoff or by ADR-0048/0051):

- `test_rest_api_t2.cpp` — four store-behaviour `TEST_CASE`s plus one cross-store case, ported to
  a local `t2_device_token_tpl` (mirrors that file's existing `license_store_tpl`/
  `t2_sw_deploy_tpl` pattern). The file's `unique_temp_path`/`TempFileGuard` helpers and their
  `<filesystem>`/`fs::` alias became dead code once the last SQLite-file-backed store in that
  file (`DeviceTokenStore`) migrated — removed rather than left as an unused-function warning.
- `test_rest_api_tokens.cpp` — `RestTokensHarness` unconditionally constructs a
  `DeviceTokenStore` (used by the F-002 CSPRNG device-token cases). Its `device_token` member
  moves from a `TempDbFile` to a `PostgresTestDb`/`PgPool` pair sharing the same
  `[pg]`-SKIP-if-unset/FAIL-if-broken posture as the file's existing `ApiTokenStorePg` helper.
  **One test case's tag surface widened as a direct, unavoidable consequence**: "REST tokens:
  unopened token DB returns 503 on every route, never 404" (`issue347`/`ch3`) deliberately uses a
  fake-unreachable `PgPool` for `ApiTokenStore` so it never needed real Postgres — but the SAME
  harness also constructs a real `DeviceTokenStore`, which (post-migration) has no SQLite
  fallback at all. The test now needs `[pg]` too; this is not scope creep, it is the store having
  genuinely lost its SQLite-backed independence from Postgres availability.
- `test_agent_registry_token_revocation.cpp` — three of its four `TEST_CASE`s construct a
  `DeviceTokenStore` directly (the fourth exercises the store-unwired defensive-default path and
  needs no store at all); all three ported to the shared `devicetokenstore` `PgTestTemplate` key
  and gained `[pg]`.

All four files (plus `test_device_token_store.cpp`'s own rewrite) share the same
`"devicetokenstore"` `PgTestTemplate` key — one migration paid across the whole suite, replay-
verified per `docs/postgres-store-playbook.md` step 7, mirroring `SoftwareDeploymentStore`'s
cross-file `"swdeploystore"` key-sharing precedent (rather than `LicenseStore`'s per-file
`"licensestore"`/`"licensestore_t2"` split — both patterns are sanctioned by the playbook; this
migration follows the sharing one since all four files' setup is byte-identical).

## Considered and rejected

- **A binary (prefix-only) error classifier** for `device_token_error_status`, matching
  `DeploymentStore`/`discovery_routes.cpp`'s shape. Rejected for the identical reason ADR-0048
  rejected it for `LicenseStore`: the pre-migration `DELETE /api/v1/device-tokens/:id` route
  already distinguished 404 (not found) from a generic failure, and a blanket binary classifier
  would regress that to 400 for a dormant route with zero behavioral cost today but a needless
  regression the moment the route is ever re-wired live.
- **Computing an explicit `DeploymentStore`-style rank for `revoked`/`last_used_at`.** Rejected —
  not because the sibling rank template's own direction rule differs (gov Gate 8 architect,
  corrected: `DeploymentStore`/`LicenseStore`'s rank check is ALREADY direction-asymmetric —
  fail-closed on legacy-ahead, benign WARN on stored-ahead — so reusing it on a boolean would
  PRESERVE that asymmetry, not lose it, the same point the Backfill section above makes). The
  actual reason is simpler: `revoked` is a two-value monotone flag with no terminal-tie case a
  multi-value status enum has to resolve, so a rank computation has no other purpose here — a
  direct two-branch check states the identical fail-closed-on-legacy-ahead invariant more plainly
  than inventing a rank scheme just to immediately collapse it back to two outcomes would.
- **Sharing `kDeviceTokenDbErrorPrefix` with an existing constant.** Rejected on the same grounds
  ADR-0048 rejected it for `LicenseStore` — different file, no existing coupling, no reason to
  risk one store's rename silently reclassifying another's routes.

## Consequences

- Every device-token read/write now surfaces a genuine database error to its REST caller as a
  503 instead of a silently-empty/-false SQLite-mutex-guarded result. Because the store is
  dormant, this has zero production behavioral effect today — it takes effect the moment a
  future change re-constructs `DeviceTokenStore`.
- `AgentRegistry::register_agent`'s #823 revoke-on-re-registration call site now surfaces (via a
  log line) a genuine revoke failure instead of silently discarding it — still best-effort at
  that call site (re-wiring whether it should block registration is out of scope), but no longer
  indistinguishable from "nothing to revoke."
- The legacy `device-tokens.db` is retained for one release (ADR-0009 rollback window) once a
  future re-wiring gives it somewhere to be found, then removed per the standard cadence.
- `DeviceTokenStore` moves from "SQLite, mutex-serialized" to "Postgres, pool-concurrent" —
  matches every other migrated store's concurrency model.
- The store's dormancy — and that it is UNWIRED, not never-wired, sharing its exact removal
  commit with `LicenseStore`/`SoftwareDeploymentStore` — is now a recorded, verified fact (this
  ADR + the ladder row) rather than a kickoff-doc guess a future reader would have to
  re-archaeology or, worse, propagate uncorrected.

## Amendment — 2026-08-21: `revoke_by_device` closes the #823 gap (#3401); input bound + checked hashing (#3351)

`revoke_by_principal` was never the #823 re-registration sweep it was documented as; registration
now fails closed on a revoke failure; and #3351's activation-gating hardening lands alongside it.

Doomgoose's external review of this migration (round 3) surfaced `#3401`: `revoke_by_principal`'s
own doc comment above (and this ADR's own "closed by typing it" bullet) describes it as *"the
#823 re-registration defence"* — that description was wrong from the day #823 shipped, not
introduced by this migration. `AgentRegistry::register_agent` calls it with `info.agent_id()`, but
`principal_id` is the *issuing operator's username* (`DeviceAuthToken::principal_id`, "Username who
created it") on every production issuance path (`rest_api_v1.cpp`'s `POST /api/v1/device-tokens`
writes `session->username` there) — never an agent_id. The sweep therefore matched zero rows on
every real re-registration; the existing test suite masked this because its fixtures set
`principal_id == device_id == agent_id`, a shape no production path produces.

The fix adds `revoke_by_device(device_id)` — same shape as `revoke_by_principal`
(`std::expected<int64_t, std::string>`, empty-input no-op, `WHERE device_id = $1 AND revoked =
false RETURNING token_id`), no schema change (the existing `idx_device_token_device` index gets
its first query consumer) — and retargets `AgentRegistry::register_agent`'s call site to it.
`revoke_by_principal` is kept: it is a legitimate owner-scoped bulk revoke ("every token I,
personally, issued"), just never the #823 mechanism; its doc comment is corrected rather than the
method removed.

`register_agent` also now fails CLOSED on a genuine revoke failure (ADR-0012 §1) — refusing the
registration rather than installing a session the sweep could not clear stale tokens for — and the
revoke call moves OFF the registry mutex (two-phase: snapshot prior-entry-exists + the store
pointer under `mu_`, revoke off-lock, re-verify and install under `mu_` again), following
`sweep_revoked`'s snapshot-off-lock precedent in the same file. The prior comment's claim that
holding `mu_` across the call gave an "atomicity" guarantee was itself overstated — nothing else in
`AgentRegistry` reads `device_auth_tokens`, so the lock never actually serialized anything against
it; the real invariant (`revoke commits before install`) holds under the two-phase structure
without the lock. Both gRPC callers (`agent_service_impl.cpp` `Register`, `gateway_service_impl.cpp`
`ProxyRegister`) surface a refusal as `grpc::Status(UNAVAILABLE, ...)`, never `accepted=false` —
the agent's reconnect loop (`agents/core/src/agent.cpp`) treats the latter as a **permanent**
rejection, not a retryable one.

Bundled in the same PR, `#3351` (filed alongside `#3401` during this migration's original
governance round, same activation-gating posture): `sanitize_pg_text` was rewritten to the linear
reserve-and-append shape (`#2691` precedent, `response_store.cpp`) rather than its prior O(n²)
find+replace loop; `create_token` and `migrate_from_sqlite`'s legacy-field reads now reject (never
silently clamp) any free-text field exceeding 256 raw bytes, measured before sanitization can grow
the string; the legacy SQLite read switched from a NUL-truncating C-string read to a length-aware
`sqlite3_column_bytes` read (mirrors `audit_store.cpp`) so an embedded NUL is defanged to U+FFFD
rather than silently dropping everything after it; and `hash_token`'s Windows-only, four-call,
entirely unchecked BCrypt branch (a failure anywhere in that chain silently produced the hex of 32
zero bytes — a constant hash for every input) is removed outright in favor of a single checked EVP
SHA-256 call (`sha256_hex`) on every platform — OpenSSL is a required dependency on Windows
regardless of linkage (see this repo's vcpkg notes), so the platform split no longer has a reason
to exist. Output bytes are identical (both were SHA-256), so no previously-hashed token is
invalidated.

All of the above remains dormant-store defence-in-depth: `server.cpp` still passes
`/*device_token_store=*/nullptr`, so none of this is reachable in production today. It closes
before the wiring PR, per this ADR's original dormancy record above and `#3422`'s still-open
question of what mechanically enforces that ordering.

## Amendment — 2026-08-22: hardening round (Gate 5/6 findings on the above)

Governance's unhappy-path/chaos passes on the `#3401` fix identified one race the two-phase
restructure itself introduces (not present before it), which this round fixes; three
observability/correctness follow-ups from the same passes; and confirms several other findings as
pre-existing, out of scope, or already covered.

**Fixed here — supersede detection (Gate 4 unhappy-path UP-1, Gate 5 CH-1a).** Splitting the
revoke off `mu_` opened a window the OLD single-locked implementation did not have: because
`register_agent` used to hold `mu_` across the ENTIRE call (revoke included), two concurrent calls
for the same `agent_id` were fully serialized end to end — install order always matched lock-
acquisition order. With the revoke off-lock, a second call for the same `agent_id` can now run its
own phase 1, revoke, and phase 2 to completion (install a session, map a live stream) entirely
within a first, slower call's revoke window. Without a check, the slower call's phase 2 would then
overwrite the map with a fresh, unmapped session — silently orphaning the winner's live stream, a
dispatch black hole. The fix: phase 1 now snapshots the *session itself* (`shared_ptr`, not a bool)
under `mu_`; phase 2 re-reads and compares by pointer identity before touching anything. A
mismatch means a newer registration already won — this call yields (`std::unexpected`, same
retryable-`UNAVAILABLE` path already built for a revoke failure, its own `reason` label) rather than
overwriting a live session with a stale one. An entry that was instead *removed* (not replaced)
between phase 1 and phase 2 is not "superseded" — nothing live to protect — and installs normally.
This **restores** the old implementation's ordering guarantee; it does not add a new one, and it
does not touch the separate, pre-existing register→Subscribe gap (a registration landing after
phase 2 but before the caller's own `Subscribe` call) — that gap is unchanged by this diff, exactly
as it was before. Verified by a deterministic test-only interleave hook
(`set_register_agent_interleave_hook_for_test`, `test_agent_registry_token_revocation.cpp`) that
fires a second `register_agent` call synchronously inside the first call's revoke-to-install
window — chosen over a real-thread race because the property under test is "what does phase 2 do
when the entry changed under it," not "can we reproduce OS scheduling," and a timing-based test
would be flaky for no additional coverage. The realistic-timing variant (an actual `pg_sleep`-held
row lock racing real threads) is tracked as a follow-up chaos scenario (CH-1b), not a merge gate.

**Fixed here — REST create-token error classifier, three-way (Gate 4 consistency-auditor C-1).**
The POST `/api/v1/device-tokens` handler's own classifier was two-way (`kDeviceTokenDbErrorPrefix`/
`internal_error:` → 503 fault; everything else assumed CSPRNG exhaustion), so the store's
`invalid_input_length:`/`principal_id cannot be empty` validation errors fell into the CSPRNG arm
by elimination — wrong audit reason, wrong Prometheus counter, and (unlike the other two arms,
which agree on 503) a real status-code error, since a validation failure is a 400, not a 503.
Unreachable via REST today (the route pre-clamps `name`/`device_id`/`definition_id` at 256 bytes,
and the harness's own `auth_fn` refuses an empty `session_user` outright, matching production —
`principal_id` can never be empty through a real session). Verified by inspection against
`device_token_store.cpp`'s enumerated `create_token` error strings plus the store-level pinned-
string tests already added for #3351, not a full REST round-trip — forcing an empty principal_id
through the harness would require defeating `auth_fn`'s own gate in a way no production path can,
which would be a false-representative test, not real coverage.

**Fixed here — metric naming + pre-seed (Gate 6 sre).** `yuzu_agent_registration_refused_total`
(singular) is renamed to `yuzu_agents_registration_refused_total`, matching its siblings
`yuzu_agents_registered_total`/`yuzu_agents_connected` added in the same function; both reason
values (`device_token_revoke_failed`, `superseded_by_concurrent_registration`) are now pre-seeded
at construction (`kNvdCountedReasons` precedent) so `absent()`-style alerting has a series to watch
from a healthy boot rather than only after the first failure.

**Also fixed — capacity note extension (Gate 6 sre).** The existing "Capacity note for the future
wiring PR" above covered only `validate_token`'s httplib-worker-starvation risk; it now also names
`register_agent`'s `revoke_by_device` call on the gRPC thread pool as the same acquire-vs-lock-wait
exposure, on the registration path specifically.

**Confirmed, not fixed here — tracked as follow-ups:**
- **Sequential impostor-evasion of the sweep (UP-2)** — `prior_exists` (does an `agents_` entry
  currently exist) is the only gate on running the revoke; an identity holder disconnecting before
  the legitimate device's next `Register` skips it entirely. Pre-existing (not introduced by this
  diff, not addressed by it), a genuine design tension between preserving the pre-issuance
  operator workflow and closing disconnect-evasion, not a same-PR-fixable bug — files as a decision
  issue.
- **Reconnect-storm / gRPC-thread-pinning compound (UP-3/UP-4, Gate 5 CH-2)** — pre-existing agent
  backoff (no jitter) and gRPC thread-pool sizing characteristics, unrelated to this diff's own
  correctness; tracked as a pre-release follow-up (P1), not a merge gate.
- **Migration fail-closed abort is all-or-nothing (UP-6)** — matches this same function's
  pre-existing hex-format-validation precedent (already aborts the whole migration on one
  malformed row); the new length-bound check adds one more reason using an already-established
  philosophy, not a new failure class. Rejected as a design change; noted for the wiring-PR
  checklist.
- **No `audit_log` row for the automated revoke sweep (Gate 6 compliance-officer)** — the REST-
  driven `device_token.create`/`device_token.revoke` routes emit an audit row; the automatic #823
  sweep inside `register_agent` emits only an `spdlog` line and a counter (the registry holds no
  `AuditStore` reference — see `sweep_revoked`'s own comment on the same point). `E6`-capped today
  (the store is dormant), real once live — close before the wiring PR, alongside `#3422`.
- **No `audit_log` row for the supersede refusal either (Gate 8 security-guardian) — and this one
  is live today, not `E6`-capped.** Same gap, same underlying cause (`AgentRegistry` has no
  `AuditStore` reference at all), but the supersede check runs regardless of store wiring, so this
  is a real, present audit-trail gap, derived MEDIUM (non-blocking — MEDIUM doesn't meet the
  BLOCKING bar, and fixing it means threading an `AuditStore` dependency into `AgentRegistry`, a
  real architectural addition disproportionate to this hardening round). Track as its own,
  higher-priority item alongside the dormant one above — do not let the two share one disposition.
- **Straggler revoke can sweep a later, unrelated re-issued token (Gate 8 unhappy-path UP-12)** —
  `revoke_by_device` is unscoped in time: a pathologically delayed loser's revoke (stuck behind a
  `FOR UPDATE` wait — see the capacity note above) can commit after an operator has legitimately
  reissued a fresh token for a subsequent reconnection of the same device, silently revoking it.
  `E6`-capped today (the store is dormant); add to the wiring-PR capacity/correctness checklist
  alongside the existing pool-contention note.
- **Customer-assurance framing (Gate 6 enterprise-readiness)** — any security-questionnaire or
  pilot-readiness answer about this history should name `#3422` explicitly (what mechanically
  enforces closing these gates before the store goes live) rather than resting on "dormant" alone,
  and should lead with the fix's rigor (external review, root-caused, converted to fail-closed)
  rather than "it didn't matter because nothing called it."

**Correction to "dormant" (docs-writer + Gate 8 unhappy-path UP-13):** most of the above remains
dormant-store defence-in-depth like the round above — the revoke-failure refusal path, the
input-length bound, the linear sanitize, and the checked hashing are all gated on a wired
`DeviceTokenStore` (`server.cpp` still passes `nullptr`). The supersede check is not: phase 2's
pointer-identity compare runs on every `register_agent` call, store or no store, so a genuine
concurrent-registration race is caught in production today, and its
`yuzu_agents_registration_refused_total{reason="superseded_by_concurrent_registration"}` series
is exposed on every server's `/metrics` right now, pre-seeded at 0. The only live-today surface
this round adds is that refusal-and-retry path and its metric — restoring the ordering the old
single-locked implementation already gave for free, not a new capability. (Correction to the
Gate 8 docs-writer finding that prompted this paragraph: `docs/user-manual/metrics.md` does not
in fact catalog `yuzu_agents_registered_total`/`yuzu_agents_connected` either — the doc is a
curated query/dashboard reference, not an exhaustive metrics catalog — so this is a pre-existing
gap affecting the whole `yuzu_agents_*` family, not one this round newly introduces; a metrics
catalog pass is a separate, larger piece of work.)

## Update (2026-09-02) — `migrate_from_sqlite()` retired

**Supersedes the "Backfill is NOT skippable on the strength of that dormancy" caution above.**
That caution (written 2026-08-18) reasoned that the `acc6c481a..2fcfb95b5` window meant a real
`device-tokens.db` with genuinely issued tokens *could* exist even though the store is dormant
today. ADR-0009's fresh-start-by-default amendment (2026-08-25, one week later) establishes the
blanket program-wide fact this per-store hedge did not yet have available: no production Yuzu
fleet has ever run a pre-Postgres build of *any* store (`project_no-production-fleet-fresh-build`
standing fact) — this store's historical SQLite-era construction window included, since Yuzu had
no production deployments during it either. The hedge was reasonable given what was known at the
time; the later blanket fact resolves it the same direction the other 17 already-migrated stores
were resolved.

`DeviceTokenStore::migrate_from_sqlite()`, its `LegacyDeviceTokenRow`/`LegacyStep`/`Sha256Stream`
helpers, and the `sqlite_backfill_source` marker table are removed
(`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623). Unlike a store with a live
Postgres deployment, this store's `migrations()` were never run against any real database at all —
nothing in production ever constructed `DeviceTokenStore` even after this ADR's PG migration
merged (see "Dormancy" above), so there is no drift risk from editing schema version 1 in place
(the `sqlite_backfill_source` `CREATE TABLE` is simply deleted from it) rather than issuing a
version-bumped `DROP TABLE IF EXISTS` migration. This is the same practical justification
PolicyStore's removal used (ADR-0009 §"authoring contract"), reached by a different route: that
store's v1 had never *shipped*; this store's v1 had never *run*.
