# ADR-0057: WebhookStore → PostgreSQL (Wave 3, first SecretCodec-migrating store past AuthDB)

- **Status:** Accepted — shipped PR #3563, merged 2026-08-25; `webhook_store.cpp` is PG-native
  (`PgPool`/`pg_exec`), zero live `sqlite3_` calls (comments only), re-verified 2026-09-07.
- **Date:** 2026-08-20
- **Deciders:** pg workstream; security-guardian + cpp-safety + docs-writer (Gate 2/3)
- **Parents:** ADR-0006/0007/0008/0009/0012 (substrate/backfill/store contract); ADR-0010
  (secrets-at-rest envelope encryption — this store is its second production consumer, after
  `AuthDB`'s `mfa_totp_secret`, and the template for the two remaining Wave 3 stores,
  `OffloadTargetStore` and `RuntimeConfigStore`).

## Context

`WebhookStore` (`webhooks.db` today, `server/core/src/webhook_store.{hpp,cpp}`) lets operators
register outbound HTTP(S) webhooks that fire on fleet events (`agent.registered`,
`execution.completed`, `dex.blast_radius`, `dex.signal`, …). Two tables, one internal FK
CASCADE:

```sql
CREATE TABLE webhooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL,
    event_types TEXT    NOT NULL DEFAULT '*',
    secret      TEXT    NOT NULL DEFAULT '',      -- plaintext HMAC signing secret
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);
CREATE TABLE webhook_deliveries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id   INTEGER NOT NULL,
    event_type   TEXT    NOT NULL,
    payload      TEXT    NOT NULL,
    status_code  INTEGER NOT NULL DEFAULT 0,
    delivered_at INTEGER NOT NULL,
    error        TEXT    NOT NULL DEFAULT '',
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);
```

Wave 3 on the ladder (`docs/postgres-migration-ladder.md`) — the secret-gated class, migrated
last because it needs the ADR-0010 seam. `webhooks.secret` is one of the four recover-plaintext
columns ADR-0010 named as gating: `auth` (shipped 2026-07-16, `mfa_totp_secret`), `webhooks`
(this ADR), `offload_targets`, `runtime_config`. `WebhookStore` signs every delivery with
`hmac_sha256(secret, payload)` — it needs the RAW secret at signing time, so the
verify-only-hash pattern (`api_token`/`ca`/`scim_store`) is impossible here; this is exactly the
`SecretCodec` case ADR-0010 exists for.

Current API surface (`webhook_store.hpp`/`webhook_routes.cpp`): `create_webhook`, `list`
(never returns the secret), `delete_webhook`, `get_deliveries`, `fire_event`. **No
update/enable-disable/rotate-secret endpoint exists.** This is load-bearing for the backfill
design below (§Backfill).

## Decision

Migrate to PostgreSQL schema **`webhook_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server `PgPool`.

### Schema

```sql
CREATE TABLE webhooks (
    id          BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    url         TEXT    NOT NULL,
    event_types TEXT    NOT NULL DEFAULT '*',
    secret      BYTEA,                              -- SecretCodec envelope; NULL iff !has_secret
    has_secret  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  BIGINT  NOT NULL,
    CHECK ((has_secret AND secret IS NOT NULL) OR (NOT has_secret AND secret IS NULL))
);
CREATE TABLE webhook_deliveries (
    id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    webhook_id   BIGINT  NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type   TEXT    NOT NULL,
    payload      TEXT    NOT NULL,
    status_code  INTEGER NOT NULL DEFAULT 0,
    delivered_at BIGINT  NOT NULL,
    error        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_delivery_webhook_ts ON webhook_deliveries(webhook_id, delivered_at);
CREATE TABLE sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT NULL);
```

**`payload` leakage check (verified, not assumed).** Every `fire_event`/`deliver_single` call site
was audited: the delivered/logged `payload_json` is built from event-context fields (agent id,
hostname, execution/command identifiers, DEX signal metadata) at the call sites in
`agent_service_impl.cpp`/`server.cpp` — never from the webhook's own `secret`. The
`webhook_deliveries.payload` column is therefore clean of secret material by construction, and
gets the same `sanitize_pg_text` treatment as every other free-text column, nothing more.

`secret` keeps its column name and moves TEXT→BYTEA (the `mfa_totp_secret` precedent for type).
`has_secret` is the **independent, non-secret flag** ADR-0010 §Decision-1's anti-downgrade rule
requires: "no secret configured" (the pre-migration `secret = ''` case — an unsigned webhook is
a real, supported configuration) must never be represented by column emptiness, or a SQL-write
insider could NULL the column and ride an empty-means-no-auth read path to silently disable
signing. The `CHECK` constraint makes the invariant structural, not just documented — verified
directly: a hand attempt to set `secret = NULL` on a `has_secret = TRUE` row is rejected by
Postgres itself (`test_webhook_store.cpp`, "NULL secret with has_secret=true is a hard decrypt
error").

### Posture (ADR-0012 §1) — split by operation class

- **`webhooks` create/list/delete: AUTHORITATIVE/fail-hard.** Operator-authored integration
  config; a silent empty/false on a DB error reads as "no webhooks configured" or "nothing
  happened", neither of which is true. `create_webhook`/`delete_webhook` return
  `std::expected<T, WebhookWriteError>` (`invalid_url` = 400, `store_unavailable`/`db_error` =
  503 — the #3097 classification the ladder's other Wave-2/3 stores already carry). `list()`
  returns `std::optional<std::vector<Webhook>>` — the ADR-0036/postgres-store-playbook
  type-distinguishable-reads policy applies here the same way it applied to `DiscoveryStore`:
  webhook visibility is a genuine security-adjacent question ("what external systems receive
  fleet event data"), not pure display, so a degraded read 503s rather than rendering as "none
  configured".
- **`fire_event`'s internal enabled-webhook scan: deliberately fail-soft.** It can run on a gRPC
  handler thread (Register/execution-completion), so it uses a short bound
  (`kFireEventAcquireTimeout=300ms`) and degrades by skipping this tick's firing (logged +
  counted via `yuzu_server_webhook_fire_event_degraded_total`), never blocking or erroring the
  caller. This is the ADR-0036 "deny-or-benign" carve-out, stated explicitly per the playbook's
  requirement to say so rather than leave it unstated: a dropped webhook notification on a
  transient DB blip is benign availability degradation, not a security fail-open — nothing is
  over-authorized, an operator simply doesn't get pinged this once.
- **`get_deliveries`: stays a plain container** (empty on error) — delivery HISTORY is an audit
  convenience, not itself a decision surface, mirroring `ResultSetStore::lineage`'s carve-out.
- **`record_delivery` (the delivery-log write): fail-soft but surfaced** — returns `bool`,
  logs + counts (`yuzu_server_webhook_delivery_log_failed_total`) on failure rather than silently
  discarding it (kickoff lesson 3; the write itself stays best-effort, matching every other
  worker-pool-thread write in this store).

### Secrets (ADR-0010 headline of this migration)

- **Decrypt-on-use at the signing site.** `deliver_single` (a `StoreWorkerPool` worker thread)
  decrypts `secret` immediately before the HMAC call and lets the `SecureBuffer` fall out of
  scope right after — the raw secret exists in memory only around that one call, on every exit
  path including an exception. ADR-0010 §Consequences permits caching the decrypted secret for
  a whole delivery *batch*; this migration deliberately **declines that option** and decrypts
  per-delivery instead — the kickoff's instruction was stricter than the ADR's allowance, and as
  the template PR for the remaining two Wave-3 stores it takes the stricter path. Per-value AES-
  GCM cost is negligible at webhook volumes (ADR-0010 §Consequences already names this).
- **Fail-closed on decrypt failure — never fire unsigned, never fire with an empty secret.** A
  webhook whose `has_secret=true` row fails to decrypt is skipped ENTIRELY: no HTTP call is
  made, `record_delivery` logs `status_code=0, error="secret_unavailable"`, and the metric
  `yuzu_server_webhook_delivery_secret_unavailable_total` increments. This is the concrete
  instance of the ADR-0010 example that motivated the rule in the first place
  (`webhook_store.cpp`'s pre-migration "empty means no auth" path).
- **`hmac_sha256` takes `std::string_view`, never `std::string`,** for the secret parameter —
  passing a decrypted `SecureBuffer` through a `const std::string&` would make an unzeroized
  copy, which the ADR-0010 zeroization rule forbids for secret bytes.
- **Serial-PK allocate-before-encrypt (ADR-0010 Amendment).** `create_webhook` reserves the row
  id via `nextval(pg_get_serial_sequence(...))` on its own short lease (released before
  encrypting), encrypts with that id as the AAD row-PK, then `INSERT ... OVERRIDING SYSTEM
  VALUE` on a fresh lease — never INSERT-then-UPDATE, which would transiently write a non-blob
  value to `secret`.
- **Instance model — own `SecretCodec`, shared `KeyProvider`.** `server.cpp` constructs a
  dedicated `webhook_secret_codec_`, reusing `auth_key_provider_` (the same `FileKeyProvider`
  `auth_secret_codec_`/`plugin_config_secret_codec_` already share — one KEK per database is
  install-wide custody, not a per-store resource). Construction order mirrors `AuthDB`'s block
  exactly (`docs/postgres-store-playbook.md` step 3): codec ctor → `WebhookStore` ctor
  (registers `{"webhook_store","webhooks","secret","id"}`) → `is_open()` gate →
  `SecretCodec::init()` on a pinned lease → `migrate_from_sqlite`. `webhook_secret_codec_` joins
  `kek_enrolled_codecs()` (live KEK rotation surface) and the
  `yuzu_server_secret_decrypt_failures_total` metrics export loop — the latter was previously
  `auth_secret_codec_`-only, silently missing `plugin_config_secret_codec_` too; generalizing
  the export loop over `kek_enrolled_codecs()` fixes both in the same change.
- **Teardown ordering — `auth_key_provider_.reset()` moved.** A still-draining delivery decrypts
  (touches `webhook_secret_codec_`, transitively `auth_key_provider_`) right up until
  `WebhookStore::quiesce()` proves it drained, which now happens up to 60s into `stop()` —
  well past where `auth_key_provider_.reset()` used to run (right after the other codecs, near
  the top of the teardown sequence). `stop()` now resets `webhook_secret_codec_` and
  `auth_key_provider_` immediately after the webhook/offload delivery-pool drain, not before it.
  `~ServerImpl`'s plain (declaration-order) destructor was already safe — `webhook_secret_codec_`
  and `webhook_store_` are declared after `auth_key_provider_`, so reverse-order destruction
  tears them down first regardless; only `stop()`'s *proactive* reset sequence needed the fix.

### Backfill (ADR-0009) — MANDATORY, both tables

Configs+secrets are unconditionally mandatory (ADR-0009's own classification). The delivery log
is **also treated as mandatory here**, not skippable-telemetry like `ResponseStore`: unlike
`ResponseStore` it carries no TTL/prune (nothing ages it out), so the "history ages out, a clean
cut is acceptable" justification does not hold, and one transaction already covers both tables
at this store's scale (tens-to-low-thousands of rows, ADR-0010's own volume estimate for this
class).

- **Idempotency model: a per-legacy-CONTENT fingerprint SET** (`sqlite_backfill_source`,
  `DeploymentStore`'s shape), not `NotificationStore`'s single-marker-with-holder-side-reverify.
  Chosen because `webhooks` rows have a real (if currently unbuilt) post-migration LIFECYCLE for
  `secret` — a future rotation endpoint must never have its write clobbered by a re-run backfill
  — and the per-row ON-CONFLICT-then-IDENTITY-compare loop is what actually enforces that,
  unconditionally, for every replica and every retry; the fingerprint set only makes an
  unmodified legacy file a cheap no-op on a later boot, it is not the safety mechanism.
- **Conflict handling, IDENTITY vs the secret.** Because no update/enable/rotate endpoint exists
  today (§Context), every `webhooks` column except `secret`/`has_secret` is write-once —
  IDENTITY here is `(url, event_types, enabled, created_at)`. On an id conflict: an IDENTITY
  mismatch fails the whole backfill closed (naming the row); an IDENTITY match is a benign skip,
  and **`secret`/`has_secret` are never compared or re-written** — whatever Postgres already
  holds wins, unconditionally. This is the forward rule for when a rotation surface eventually
  ships: a secret rotated post-cutover in PG must never be clobbered by a re-run backfill, and
  because the marker+fingerprint gate means backfill's row-level logic never runs again once
  `sqlite_backfill_source` records this content, that forward case is already closed structurally,
  not just by convention.
- **`webhook_deliveries` rows are pure IDENTITY** (append-only telemetry, no lifecycle at all) —
  a conflicting id must match byte-for-byte or the backfill fails closed naming the row.
- **Orphaned deliveries fail closed.** A legacy `webhook_deliveries` row whose `webhook_id` does
  not match any legacy `webhooks` row is refused (naming the row) rather than silently dropped —
  both the legacy and migrated schema enforce the FK via CASCADE, so an orphan is corruption,
  not a real upgrade artifact (`SoftwareDeploymentStore`'s referential-closure reasoning).
- **Secrets transform, never copy** (ADR-0010). Every legacy plaintext secret is encrypted
  BEFORE the backfill transaction opens (no lease held across crypto, ADR-0012 §2(b)) — the
  legacy id is already fixed (preserved via `OVERRIDING SYSTEM VALUE`), so the AAD row-PK is
  known upfront and no INSERT-then-UPDATE dance is needed. An encrypt failure aborts the WHOLE
  backfill closed.
- **Fingerprint excludes the plaintext secret bytes — a deliberate, security-motivated choice**
  (caught before it shipped: the fingerprint canonicalization includes only a `has-secret` bit
  per row, never the secret itself). The fingerprint is stored in a plain Postgres column
  (`sqlite_backfill_source.fingerprint`), readable by anyone with `Infrastructure:Read`-class
  access, alongside every OTHER webhooks column in cleartext. Hashing the plaintext secret into
  it would let a SQL-insider brute-force a low-entropy legacy secret offline against the stored
  hash — exactly the adversary ADR-0010 exists to defend against. This is sound *because* of the
  conflict rule above: a legacy file that differs from an already-migrated one only in a secret
  VALUE (has-secret bit unchanged) verifies as identical, and post-marker, `secret` is never
  re-imported by backfill regardless — there is nothing for a finer-grained fingerprint to
  protect. Count-prefixed per table (the `LicenseStore` two-section-sequence lesson).
- **`id` preservation** — `OVERRIDING SYSTEM VALUE` on both tables, sequences advanced past the
  migrated max in the same transaction (`NotificationStore` precedent) — load-bearing for
  `webhook_deliveries.webhook_id`'s FK.
- **Legacy file disposition (ADR-0010 §Consequences (a)–(d) — first store to actually implement
  this; `AuthDB` was fresh-start/no-backfill, so this is the program's first secret-bearing
  legacy-retention window in practice):**
  - (a) **0600 forced, POSIX only** — on the legacy file **and any pre-existing `-wal`/`-shm`
    sidecars**, before the legacy file is opened for reading, and re-applied to every moved-aside
    artifact (main file and sidecars alike) once the backfill completes (defence-in-depth;
    `auth.cpp`'s belt-and-suspenders idiom for credential-bearing files). The WAL can carry the
    same pre-checkpoint plaintext secret pages the main file's own force protects, so it gets the
    identical restriction at BOTH points in the file's lifecycle — a sidecar whose move-time
    rename fails (so it's never touched by the move-aside step) still isn't left unprotected,
    because the read-time force already covered it independently. The move-aside step's own
    success claim is honest about this: it only logs "(0600, ...)" when every chmod it attempted
    AND every sidecar rename actually succeeded — a partial failure (e.g. one sidecar's rename or
    chmod fails while the main file succeeds) logs a degraded variant naming the earlier warning
    instead. `std::filesystem::permissions` with owner-only POSIX bits is a silent no-op on
    Windows (no ACL is touched, the call reports success) — gov Gate 3 cross-platform caught an
    earlier revision of this ADR and the shipped code both claiming "0600" unconditionally, which
    was false there. Both are now `#ifndef _WIN32`-guarded and the Windows-side log line does not
    claim a restriction that did not happen. No compensating Windows ACL exists for this path
    today (unlike `key_provider.hpp`'s `WinOwnerOnlyDacl` for the KEK file itself) — tracked as a
    follow-up, not fixed here: issue #3593.
  - Moved aside (never deleted) on a verified backfill, WAL/SHM sidecars carried across
    (`AuditStore`/ADR-0040 precedent — an unclean shutdown's committed tail lives in `-wal`, and
    the retained copy is unopenable standalone without it, **and both files carry the same
    secret-confidentiality requirement as the main file, per (a) above**).
  - (b) **Operator purge flag**: not built in this PR — tracked as a follow-up issue
    (`docs/postgres-migration-ladder.md` row + a filed issue), consistent with ADR-0010's own
    framing ("an operator purge flag allows early deletion" — a capability, not a mandate on
    every consuming store's first PR).
  - (c) **Rotation guidance**: recorded in `docs/user-manual/rest-api.md`'s Webhooks section —
    operators whose backup posture for the one-release retention window is unknown should
    rotate (delete-and-recreate; no update endpoint exists) webhook signing secrets after the
    window closes (all are re-issuable at zero data loss, matching ADR-0010's stated cost).
  - (d) **Next-release deletion**: tracked on the ladder row, implemented and upgrade-tested when
    that release ships, per ADR-0009's standard one-release rollback window.

## Considered and rejected

- **Batch-cache the decrypted secret for a delivery run** (ADR-0010 §Consequences' named
  allowance). Rejected for this store: the kickoff's instruction is stricter than the ADR's
  allowance, and as the template PR for `OffloadTargetStore`/`RuntimeConfigStore` it sets the
  precedent at the stricter bar rather than the permitted floor. Per-delivery decrypt cost is
  negligible at webhook volumes.
- **NotificationStore's single-marker-with-holder-side-reverify idempotency shape.** Rejected in
  favor of `DeploymentStore`'s per-content fingerprint set — see §Backfill; the deciding factor
  is `webhooks`' real (even if not yet built) post-migration secret lifecycle, which
  `NotificationStore`'s simpler table has no analogue of.
- **Including the plaintext secret (or a hash of it) in the backfill fingerprint.** Rejected —
  see §Backfill; a security-relevant, not just a design-taste, decision.
- **A single fleet-wide `webhook_secret_codec_` shared with `auth_secret_codec_` instead of a
  dedicated instance.** Rejected — ADR-0010's own "Instance model" note names this as possible
  in principle but requiring every registrant's construction to precede one deferred `init()`
  call, "a materially easier invariant to violate" than one-codec-per-store. Sharing the
  `KeyProvider` (not the `SecretCodec`) is the actually-prescribed shape, and what this ADR does.

## Consequences

- `webhooks.secret` is envelope-encrypted at rest; a stolen `pg_dump` or Postgres volume snapshot
  recovers no webhook signing secrets without the separately-backed-up KEK (ADR-0010's
  restore-pairing invariant now applies to this store too).
- The REST surface (`webhook_routes.cpp`) gains the #3097 400-vs-503 classification on
  create/delete, and `GET /api/webhooks` gains `has_secret` in its response (a non-sensitive,
  previously-invisible signal — operators could not previously tell "no secret configured" from
  "list omits it either way").
- Every `WebhookStore` construction site (there is exactly one, `server.cpp`) and every test that
  constructs one directly now needs Postgres + a `FileKeyProvider`/`SecretCodec` — the
  SQLite-era `WebhookStore(":memory:")` constructor is gone. `test_agent_service_impl.cpp`'s
  `EventSinkScope` (the only other direct constructor in the tree, per
  `docs/postgres-store-playbook.md`'s test-file-drift note) now builds a self-contained
  `[pg]`-tagged fixture (`test_webhook_store_pg_helper.hpp`, shared with
  `test_webhook_store.cpp`) instead.
- `/readyz` and `/healthz` needed NO change — both already probed `webhook_store_->is_open()`
  from the #3261 hardening round; the same accessor now reflects Postgres reachability instead
  of a SQLite handle.
- Tests → `YUZU_REQUIRE_PG_DB_TPL`-equivalent via the shared `WebhookStorePg` fixture
  (self-contained, not pool-supplied — mirrors `AuthDbPg`, not `NotificationScope`, because a
  fresh `FileKeyProvider`/`SecretCodec` pair per fixture is part of what's under test); backfill/
  migration tests use the same fixture plus a hand-built legacy SQLite file.

## Follow-ups

- **#3562** — operator purge flag for a retained legacy secret-bearing file (ADR-0010
  §Consequences (b), webhook-specific instance of the program-wide capability).
- **#3561** — `webhook_deliveries` has no retention/prune pass; unlike `ResponseStore` it was
  deliberately given a mandatory (not skippable) backfill, but no future retention policy was
  decided at migration time.
- **#3590** — the backfill idempotency check compares sanitized-stored text against raw,
  unsanitized freshly-read legacy bytes; on invalid-UTF-8 legacy content, two replicas racing
  the same backfill (or the same replica across boots) can spuriously disagree.
- **#3591** — a bundle of minor REST/test hardening gaps (`event_types` array-form input, an
  unbounded webhook-id parse, a test-fixture prefix convention, a missing signed-delivery test).
- **#3593** — no compensating Windows ACL for the retained legacy secret-bearing file (POSIX-only
  0600 today, both the main file and its `-wal`/`-shm` sidecars).
- **#3594** — `hmac_sha256`'s own failure (OpenSSL `HMAC()`/Windows BCrypt) is unchecked on both
  platforms; could fire a garbage/empty signature instead of skipping the delivery.
- **#3595** — the legacy-backfill read loop can trigger `std::vector` reallocation, potentially
  leaving secret bytes in a freed, unzeroized buffer.
- **#3613** — a deleted webhook can be silently resurrected if a stale legacy `webhooks.db`
  snapshot (predating the delete) is replayed through the backfill path; no tombstone table
  exists to prevent it.
- **#3614** — a delivery racing `delete_webhook` can fire successfully but leave no durable
  delivery-log row (FK failure, fail-soft), indistinguishable in metrics from ordinary DB
  degradation.
- `OffloadTargetStore`/`RuntimeConfigStore` (the remaining Wave-3 stores) should read this ADR as
  their template — in particular the fingerprint-excludes-secret-bytes decision and the
  teardown-ordering fix, both of which generalize directly (see `docs/postgres-store-playbook.md`
  for both, spelled out generically). Also worth reading before copying the backfill's
  `LegacySecretWiper`-style wipe-after-the-fact pattern verbatim: reading legacy plaintext
  directly into a zeroizing buffer type from the start would make that pattern unnecessary
  (architect, gov Gate 3, PR #3563 full-PR review) — a cleaner shape for a store starting fresh.

## Update (2026-09-03) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production Yuzu
fleet has ever run a pre-Postgres build of any store — the mandatory, both-tables,
fingerprint-verified backfill this ADR designed was real, working code that never had real
legacy data to protect. `WebhookStore` shipped this backfill (PR #3563) the same day the
amendment landed, too late for the "don't build it" guidance to reach it — see ADR-0009's own
Update for that timing note.

`WebhookStore::migrate_from_sqlite()`/`migrate_from_sqlite_impl()` and their backfill-only
helpers (`kSourcelessFingerprint`, `safe`, `append_field`, `sha256_hex`, `LegacyWebhook`,
`LegacyDelivery`, `canonicalize_legacy`, `move_legacy_aside`) are removed
(`chore/retire-migrate-from-sqlite-batch-a`, tracking issue #3623). `sqlite_backfill_source`
— whose entire purpose was the backfill idempotency marker — is dropped via a version-bumped
`{2, "DROP TABLE IF EXISTS sqlite_backfill_source;"}` migration, appended after the
already-shipped v1 rather than edited in place: this store IS constructed in production, so v1
has actually run against real dev/UAT databases.

**The 0600+sidecar hardening this ADR designed for the read-time force is NOT retired — it
generalizes.** `legacy_sqlite_probe::harden_legacy_file_0600` (new, `legacy_sqlite_probe.hpp`)
extracts `migrate_from_sqlite_impl`'s own inline 0600+`-wal`/`-shm` block into the shared helper
this store's own file header already pointed future secret-bearing callers toward ("extend,
never fork"). `server.cpp`'s boot path now calls `harden_legacy_file_0600` then
`legacy_sqlite_probe::warn_if_legacy_rows` over `webhooks`/`webhook_deliveries` instead of the
backfill — WARN-only (never refuse-boot) on a real legacy row found, same posture as every other
store in this retirement batch.

**No move-aside.** With nothing migrated, `move_legacy_aside`'s `.migrated-<epoch>` rename would
misdescribe what happened to the file (nothing was actually carried over), so the legacy file —
now hardened to 0600 in place, main file and sidecars alike — is left at its original path. The
WAL/SHM sidecar 0600-enforcement regression tests this ADR's own "Adversarial review" history
added (PR #3563) moved to `test_legacy_sqlite_probe.cpp` against the new shared helper; the
companion move-aside-failure regression test has no remaining subject and was not carried
forward.

**Follow-up disposition:** #3590 (idempotency check comparing sanitized-vs-raw legacy bytes) and
#3595 (secret bytes surviving in a freed `std::vector` reallocation buffer) are both moot — the
code paths they describe no longer exist. #3613 (a deleted webhook resurrected by a stale legacy
snapshot replay) is also moot — nothing replays the legacy file into Postgres anymore, so there
is no resurrection path. #3562 (operator purge flag for a retained legacy secret-bearing file)
and #3593 (no compensating Windows ACL for that file) both still apply, re-scoped onto
`harden_legacy_file_0600`'s POSIX-only retained file at its original path rather than a
`migrate_from_sqlite_impl`-produced `.migrated-<epoch>` copy. #3561/#3591/#3594/#3614 are
unaffected by this retirement (none touch the backfill).
