---
status: accepted
date: 2026-08-25
owner: platform (Postgres substrate migration program)
deciders: parallel wave batch-8 migration worker — the LAST un-started store on
  `docs/postgres-migration-ladder.md`
scope: server — `RuntimeConfigStore` (persistent runtime configuration overrides), its cutover
  from SQLite to PostgreSQL (ADR-0009's fresh-start-by-default class — no backfill), and the
  ADR-0010 secrets seam for `oidc_client_secret` — the store's own per-KEY (not per-column)
  secrecy model
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0010 (secrets-at-rest envelope encryption), ADR-0012 (server Postgres store contract),
  ADR-0036 (authoritative-read type-distinguishability)
related: docs/postgres-migration-ladder.md (Wave 3 -> Done, last row); ADR-3005
  (`PluginConfigStore`, the precedent for a shared config namespace where only SOME
  entries are secret); AuthDB `mfa_totp_secret` (the precedent for a secret column most
  rows never populate); ADR-0057 (`WebhookStore`, the nullable-column-plus-flag shape
  considered and rejected for this store's different problem — see Considered and
  rejected); ADR-0039 (`ResponseStore`, the skippable-backfill reference shape this
  migration follows)
---

# 0060 — `RuntimeConfigStore` Postgres migration (per-key secrecy, last store on the ladder)

## Context

`RuntimeConfigStore` (`server/core/src/runtime_config_store.{hpp,cpp}`, 289 lines pre-migration —
the smallest store on the ladder) persists a fixed allow-list of key/value overrides
(`allowed_keys()`) that override startup CLI/env defaults: retention windows, `log_level`,
`plugin_signing_required`, DEX alert-routing knobs, and the six `oidc_*` Settings-configurable
OIDC parameters. One key, `oidc_client_secret`, is a credential. It was stored **plaintext**
pre-migration — the redaction hardening (`config_secret_keys.{hpp,cpp}`,
`runtime_config_view.{hpp,cpp}`, `test_runtime_config_secret_redaction.cpp`) closed four
plaintext-*disclosure* paths (startup log, `GET /api/config`, the `config.update` audit detail,
the PUT response echo) but explicitly left at-rest encryption for this migration, per its own
header comment.

This was the last store on `docs/postgres-migration-ladder.md` to START migration work (across
Wave 2 and Wave 3 — not scoped to one wave; `InstructionStore` is Wave 2, `WebhookStore` and
`OffloadTargetStore` are Wave 3) — every other server store either had already migrated to
Postgres or had a migration in flight at the time this ADR was drafted (`WebhookStore`/ADR-0057,
`InstructionStore`/ADR-0058, `OffloadTargetStore`/ADR-0059, none part of this change).
`WebhookStore`/ADR-0057 and `InstructionStore`/ADR-0058 have both since merged;
`OffloadTargetStore`/ADR-0059 is now the only server store remaining on the ladder. Once it
lands, every server store is on the Postgres substrate (NvdDatabase excluded by a recorded owner
override, M1a).

**The headline problem this ADR resolves is per-KEY, not per-column, secrecy.** Unlike
`WebhookStore`/`OffloadTargetStore` (one secret column per row) or `AuthDB` (one secret column,
`mfa_totp_secret`, NULL for most rows but every row is the SAME kind of thing — a user), this
store's single `runtime_config` table holds MANY DIFFERENT keys sharing one `value` column, and
`is_secret_config_key(key)` decides — at the row level, by key — whether that value is a
credential. `SecretCodec::register_secret_column` registers a whole (schema, table, column);
its rotation/rewrap scan and `oldest_kek_version_in_use` walk EVERY row in that column with only
an `IS NOT NULL` filter (`secret_codec.cpp`) — so a single shared `value` column mixing plaintext
config and ciphertext secrets was never viable without forking the codec (`config_secret_keys.hpp`
is the correct place to extend this class of decision — never fork `SecretCodec` itself).

## Decision

### Schema: `runtime_config_store`

```sql
CREATE TABLE runtime_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  BIGINT NOT NULL
);

CREATE TABLE runtime_config_secrets (
    key          TEXT PRIMARY KEY,
    sealed_value BYTEA NOT NULL,
    updated_by   TEXT NOT NULL DEFAULT '',
    updated_at   BIGINT NOT NULL
);
```

### Secrets discrimination: a TABLE split, not a nullable column or a type tag

`is_secret_config_key(key)` decides which table a key's row lives in — never both, with one
deliberate transitional exception (below). This is the same shape `PluginConfigStore` (ADR-3005)
uses for its `configs`/`secrets` split, and it is the precedent this ADR follows, NOT
`AuthDB`'s nullable-`mfa_totp_secret`-in-one-table shape: `PluginConfigStore`'s namespace is
"plugin config, where the CALLER decides per-entry whether a `(plugin, key)` pair is a secret" —
structurally identical to "runtime config, where `is_secret_config_key` decides per-entry whether
a key is a secret." `AuthDB` was considered and rejected as the primary precedent because its
secret column lives on a table whose rows are all the SAME kind of thing (a user); ours are not
(a `heartbeat_timeout` row and an `oidc_client_secret` row have nothing in common except sharing
an allow-list).

Registered secret column: `{"runtime_config_store", "runtime_config_secrets", "sealed_value",
"key"}` — `key` (TEXT) is directly supported as the AAD pk_column (no `encode_bigint_pk`
translation needed, unlike AuthDB's BIGINT `id`).

**Empty-secret rule, preserved exactly.** `runtime_config_secrets.sealed_value` is `NOT NULL`
because the row's mere PRESENCE is the "has a real, non-empty secret" signal — the store never
writes an empty ciphertext there. Setting a secret key to `""` deletes any `runtime_config_secrets`
row for that key and instead upserts `runtime_config(key, value='', updated_by, updated_at)` —
the SAME plain table a non-secret key's empty value would use. This is why an explicitly-cleared
secret still reports `updated_by`/`updated_at` (pinned by
`test_runtime_config_secret_redaction.cpp`'s "an EMPTY secret survives redaction as empty" case):
the attribution lives in a real row, just not an encrypted one, because there is nothing to
encrypt. Redaction (`get()`/`get_all()`) is unaffected — `is_secret_key()` decides whether to
redact, not which table the value came from.

**Becomes-secret-later story.** A key not currently in `kSecretKeys` that gains a plaintext row
in `runtime_config`, then LATER gets added to `kSecretKeys` in some future release, is not
retroactively encrypted by this migration — it keeps its plaintext row in `runtime_config` until
the NEXT `set()` call. `is_secret_config_key(key)`, not storage location, is what decides
redaction: `get_all()`/`get()` redact a plain-table row for a key classified secret today the
same as a secrets-table row, and `read_secret()` — the sole accessor returning a real value —
checks `runtime_config_secrets` FIRST and falls back to a non-empty plain-table row for the same
transitional key, so the value is never silently lost (nor silently reported as unset to a caller
that needed it — see "Zeroization fix" below for why this fallback specifically had to be
restored during review), just not yet encrypted. `set()` is the ONLY path that materializes the
transform: writing a non-empty value for a secret key encrypts it into
`runtime_config_secrets` AND deletes any stale `runtime_config` row for the same key in the SAME
transaction, so the plaintext echo does not persist past the next write. "Next write envelopes
it" is the accepted answer rather than a retroactive re-encryption pass, which no other store on
the ladder implements either.

### Posture: authoritative / fail-closed (ADR-0012 §1)

Runtime config feeds auth/OIDC behaviour directly: the startup override pass
(`apply_runtime_config_overrides`) applies the real OIDC client secret via `read_secret()`, and
`GET /api/config` is the route `security-hardening.md` tells an operator to check before deciding
whether to rotate a disclosed credential. A silently-empty read on either path is a fail-open (the
pre-existing, tracked CH-2/Task#10 defect this migration closes as a side effect of adopting the
ADR-0036 typed-read contract, not as separately-scoped work). Widened to
`std::expected<..., std::string>`: `get_all()`, `get()`, `read_secret()`. `set()` already returned
`std::expected<void, std::string>` pre-migration; DB/crypto failures now carry the
`kRuntimeConfigDbErrorPrefix` marker (aliasing the shared `kDbErrorPrefix`, `store_errors.hpp` —
NOT an independent literal, governance Gate 4 consistency-auditor finding on the first version of
this migration) so `server.cpp`'s PUT handler classifies 503 (genuine failure) vs. 400
(caller-input validation), mirroring `ProductPackStore`/`InstructionStore`'s convention.

**`get_value()` is deliberately NOT widened** — the playbook's explicit deferral clause ("say so,
don't leave it unstated"). Every current call site was audited: DEX alert-routing/blast-radius/
cohort-export knobs are deny-or-benign (a degraded read means "no routes configured," not a
security decision); `plugin_signing_required` feeds only a UI status badge
(`render_plugin_signing_fragment`) and an ADMIN-ONLY, manually-`curl`'d distribution endpoint
(`GET /api/v1/agent/plugin-policy`, `docs/user-manual/agent-plugins.md`: "the manual workflow
today is `curl` + `jq` + write... Automatic agent-side fetch is a forthcoming change") — confirmed
by grep that no code in `agents/` consumes that route today, and confirmed that the REAL
server-side pack-install enforcement gate (`ProductPackStore::require_signed_packs_`) is set from
the `--allow-unsigned-packs` CLI flag at boot (`server.cpp`), never from this store. If a future
caller wires either into a genuine grant/enforce/skip decision, it must switch to `get()`.

### Zeroization fix: `read_secret()` replaces `get_all_with_secrets()`/`get_with_secrets()`/`get_value_with_secrets()`

The version of this store first proposed for governance review had `get_all_with_secrets()`/
`get_with_secrets()`/`get_value_with_secrets()` — a public API returning a real decrypted secret
as plain `std::string`, via an anonymous-namespace `decrypt_sealed_value()` helper that discarded
the `SecureBuffer` `SecretCodec::decrypt()` returns into a `std::string` copy. `cpp-safety`
(governance Gate 3) flagged this as a policy-floor violation of ADR-0010 §1's explicit
requirement — "Store methods that return recovered secrets to in-process callers return the
zeroizing buffer type as well, not `std::string`" — independently affirmed by `compliance-officer`
against `WebhookStore::deliver_one`'s already-compliant in-tree pattern (decrypt, use the
`SecureBuffer` immediately, let its destructor wipe it, never copy to `std::string`). This is a
policy floor, not operational severity, so it gated regardless of derived band; per this
program's standing rule that a self-granted exception to an explicit ADR requirement needs
adjudication by someone other than its proposer, the resolution here is a code fix, not a
documented exception.

**The fix, once traced, also closed two other open items for free.** `set()`'s own branches
guarantee, by construction, that a `runtime_config_secrets` row exists if and only if a key's
real value is non-empty — meaning `get_all()`/`get()` never actually needed to decrypt anything to
answer "is this secret set": row PRESENCE is the whole signal. So:

- `decrypt_sealed_value()` now returns `std::expected<SecureBuffer, std::string>`.
- A new `read_secret(key) -> std::expected<std::optional<SecureBuffer>, std::string>` is the ONLY
  store method that ever returns a real secret value, and the ONLY thing left calling
  `decrypt_sealed_value()`. Its sole production caller (`apply_runtime_config_overrides()`) copies
  from the buffer straight into `cfg_.oidc_client_secret` — itself a plain, non-zeroizing
  `std::string` by pre-existing design (populated identically from `--oidc-client-secret` at
  boot) — and lets the buffer wipe itself the instant that copy is made, mirroring
  `WebhookStore::deliver_one`'s scoping discipline.
- `get_all()`/`get()` are rewritten to derive redaction from `runtime_config_secrets` row
  presence (plus an `is_secret_key()` check for the becomes-secret-later transitional case, where
  a real value can still be sitting in the plain table) and NEVER decrypt at all. This also
  resolves the two-SELECT atomicity race the first version of this ADR recorded as accepted (see
  "Considered and rejected" below) — both functions now read both tables in ONE `UNION ALL`
  statement, one MVCC snapshot, no window for a concurrent `set()` to make a key transiently
  vanish.
- This also shrinks the practical residual of the decrypt-failure blast-radius question below: the
  live `GET /api/config` route no longer decrypts at all, so a bad secret can only ever fail
  BOOT, never a live read.

`get_all_with_secrets()`/`get_with_secrets()`/`get_value_with_secrets()` are removed outright, not
kept as an unused-in-production convenience — leaving them in place, even unreferenced, would
still be a store method returning a real secret as `std::string`, the exact shape the floor
exists to close. Test call sites that asserted against them (`test_runtime_config_store.cpp`,
`test_runtime_config_secret_redaction.cpp`, `test_settings_routes_oidc.cpp`) now go through
`read_secret()` via a small test-local helper that materializes the buffer into a `std::string`
purely to compare against a literal the test itself hardcoded — a test-only convenience over a
synthetic value with no real confidentiality at stake, not the production pattern.

### Concurrency fix: advisory lock on `set()` (and `remove()`) for a secret key

Governance's unhappy-path/chaos-injection passes found and empirically reproduced a race: two
concurrent `PUT /api/config/oidc_client_secret` calls — one clearing the secret (empty value),
one setting a real one — each run in their own `with_txn_for` transaction with no lock between
them. Depending on commit order, the clearing caller's `DELETE` on `runtime_config_secrets` could
land before the setting caller's `INSERT`, so the CLEAR reports `applied: true` while the
concurrently-set secret silently survives. Derived severity: I3 (wrong result presented as
correct — the caller cannot tell), EXPOSURE E3 (an authenticated actor at its own privilege,
no downgrade), band HIGH — BLOCKING. `set()` now takes a transaction-scoped
`pg_advisory_xact_lock(hashtextextended('runtime_config_store:secret:' || key, 0))` as the FIRST
statement in both of its secret-key branches (empty-clear and non-empty-set), serializing any two
concurrent writers to the SAME key — the same per-key advisory-lock idiom as
`ResultSetStore::pin`/`software_licensing_store.cpp`. A non-secret key's `set()` needs no lock: it
is already one atomic `INSERT ... ON CONFLICT` statement. Regression-tested with the same
held-lock technique as `BaselineStore`'s row-lock TOCTOU test (`test_baseline_store.cpp`): a
second connection holds the identical advisory lock, and `set()` (and, after the Gate 8 fix below,
`remove()`) is asserted to genuinely BLOCK on it before returning successfully once released. The
proof polls `pg_locks` for the caller to appear queued as a waiter before starting a further fixed
hold (quality-engineer, Gate 8) rather than sleeping a fixed window before releasing and hoping the
caller was scheduled in time — a scheduling-luck source of flakiness on a contended CI box that a
bare sleep-then-release shape does not eliminate.

**Gate 8 re-review (architect + security-guardian, independently) found the same lock missing from
`remove()`** — it deletes from both tables for any key with no lock at all, so a concurrent
`remove()` racing a `set()` on the same secret key was still unserialized. Not proven to reproduce
the identical false-`applied:true` shape the `set()`-vs-`set()` race did (`remove()` only ever
deletes, never inserts, so there is no "wrong value silently survives" outcome to construct the
same way) and zero production callers exist today (`server.cpp`/`settings_routes.cpp`/
`rest_api_v1.cpp` never call it) — latent, not live — but the fix is the same three lines, so it
shipped in this round rather than deferred. `remove()` now takes the identical
`kSecretKeyLockSql` unconditionally, before either `DELETE`, regardless of whether `key` classifies
as secret — deliberately asymmetric with `set()`, which locks only its secret-key branches.
`remove()` is cold path (no hot-path cost to taking a lock unconditionally) and always touches both
tables regardless of key classification, so there is no equivalent "which branch" question to
answer the way `set()`'s does.

### Post-merge hardening: `read_secret()`'s own two-SELECT race

A later governance round on a follow-up change to this store re-derived, from three
independent angles (unhappy-path, chaos-injector, enterprise-readiness), a race in
`read_secret()` itself that the "Zeroization fix" section above did not close: unlike
`get_all()`/`get()`, `read_secret()` still ran its becomes-secret-later plain-table
fallback as a SECOND, separate, un-transacted `SELECT` after the first came back empty.
A concurrent `set()` promoting the key from plain to secret could commit entirely between
the two SELECTs, so `read_secret()` returned `nullopt` ("genuinely unset") while a real
secret existed the whole time — the identical I3 (wrong-result-presented-as-correct)
shape the `set()`-vs-`set()` advisory lock above exists to prevent, reached through the
read side instead of the write side. Same fix as `get_all()`/`get()`: fold both tables
into ONE `UNION ALL` statement (secrets-table row and plain-table row, in that
precedence), so there is no window between two round trips for a concurrent writer to
land in. No lock needed on the read side either, for the same reason `get_all()`/`get()`
need none — a single statement is one MVCC snapshot, so there is nothing to serialize
against. `read_secret()`'s nullopt returns for the genuinely-unset and explicitly-cleared
cases are now logged at `info` ("no stored override found"), distinct from the `warn`-level
read-degrade logging on an actual query/crypto failure, so an operator's boot log can tell
"never configured" from "a read anomaly returned empty" (compliance-officer rider on this
fix).

### Decrypt-failure blast radius: adjudicated MEDIUM, not HIGH — record kept, not silently resolved

A separate chaos-confirmed finding: if `oidc_client_secret`'s stored ciphertext ever becomes
undecryptable (KEK/DB pairing mismatch after a restore, corrupted envelope), `read_secret()`
fails, and `apply_runtime_config_overrides()` fails the WHOLE boot closed — not just the OIDC
feature. Two readings were on the table. The first-pass sketch called this HIGH under I5's
raise-clause (a), reasoning that `GET /api/config` (before the Zeroization-fix redesign above) was
an "ordinary request path" reachable without special conditions. On review, the correct read is
MEDIUM: I5's raise clause is for an ACTOR-triggerable crash on a request path, and a KEK/DB
pairing mismatch is an environmental condition (E0/E5), not an actor action; more importantly,
**fail-closed boot on a substrate/crypto failure is this codebase's deliberate, existing posture**
for every store on the SecretCodec seam — `AuthDB`'s TOTP secrets and `WebhookStore`'s signing
secret already carry the identical contract (`docs/user-manual/server-admin.md`'s "Key management
(secrets KEK)" section, `kek_unresolvable`/`kek_corrupt` startup error prefixes already
documented there). The CONTRACT is not new — fail-closed on an undecryptable secret. The
PER-FAILURE BLAST RADIUS is not identical, though, and the adjudication should say so plainly
(sre, Gate 8; correction, docs-writer, Gate 8): a whole-KEK/DB pairing mismatch is caught by the
shared boot-time fingerprint check for the entire `secrets` schema and is already boot-fatal for
every SecretCodec consumer alike, so it is NOT the differentiator here. The genuine differentiator
is a single corrupted envelope (one row) under an otherwise-healthy KEK: `AuthDB` and
`WebhookStore` both decrypt their secret lazily, per-request, so one corrupted row denies exactly
the one login attempt or the one delivery that touches it. `RuntimeConfigStore` decrypts
`oidc_client_secret` eagerly, inline during `apply_runtime_config_overrides()`, which every other
startup step is sequenced after — so the same one-row failure denies the entire server boot.
That is a genuinely wider blast radius than either sibling for the identical class of failure, not
an equivalent one — and MEDIUM still stands despite it, for a reason wider than "matches
precedent": the alternative
is fail-OPEN, not a narrower fail-closed. A server that instead booted past an undecryptable
`oidc_client_secret` would come up with SSO silently broken (empty client secret, auth attempts
failing downstream with no boot-time signal an operator would see) — a worse outcome than a loud,
diagnosable refusal to start. The residual fix is proportionate to MEDIUM: an actionable error
message at the point `apply_runtime_config_overrides()` fails, naming the KEK-mismatch recovery
path, not a behavior change. Both readings are recorded here — this is the adjudication, not a
downgrade applied without one.

### Backfill: SKIPPED, per ADR-0009's fresh-start-by-default amendment (landed 2026-08-25, PR #3622)

ADR-0009's original text defaulted config/reference stores to MANDATORY backfill, and an earlier
draft of this ADR built exactly that: a `TagStore`-shaped `migrate_from_sqlite()` (content
fingerprint + completion marker on a `runtime_config_meta` table, direction-aware conflict rules
for non-secret keys, transform-not-copy encryption for `oidc_client_secret`, move-aside-on-success
for the legacy file). ADR-0009 has since been amended (fresh-start-by-default, landed on `dev` as
PR #3622): no production fleet has ever run a pre-Postgres Yuzu build, so the "protect a live
fleet's data" premise the mandatory default assumed is empty for `RuntimeConfigStore` — the
amendment names this store explicitly as one of the migrations the new default applies to. This
ADR's own "Considered and rejected" entry below records what the dropped mandatory-backfill
draft looked like, as a worked example for the next reader of ADR-0009's amendment.

**This store follows `ResponseStore`/ADR-0039's skippable-class shape for the copy itself** — no
`migrate_from_sqlite()`, no `runtime_config_meta` completion-marker table, no legacy-file copy —
**but NOT for the boot-time signal**, per the amended `docs/postgres-store-playbook.md`'s
detect-and-warn obligation: unlike `ResponseStore` (purely TTL'd telemetry, where a silent reset
is genuinely benign), this store holds real operator-authored config, so silence would be a
fail-open if "no production fleet" ever turns out to be locally wrong for a given install.
`RuntimeConfigStore::warn_if_legacy_data_present()` opens the legacy `runtime-config.db`
READ-ONLY at boot (`server.cpp`'s construction site, before `apply_runtime_config_overrides()`)
to check whether its `runtime_config` table exists and holds any rows — silent when it doesn't
(the unremarkable case: a genuine fresh install, or any boot after the first), a defensive
`spdlog::warn` when the file exists but cannot be read as a database (corruption should never be
silently waved through), and a loud `spdlog::warn` naming the exact row count when real overrides
are found (the case this obligation exists for). It never migrates, moves, or deletes the file, and
never reads its CONTENT for any purpose beyond the boot-time row count — detection only. It DOES
force the file's permission bits (and any `-wal`/`-shm` sidecar's) to 0600 before ever opening it
(external adversarial-review finding, post-merge hardening round: an unclean pre-migration shutdown
under `PRAGMA journal_mode=WAL` can leave the pre-checkpoint plaintext secret pages sitting in a
sidecar the main file's own hardening never touched — same idiom as `WebhookStore`'s identical
obligation, `docs/postgres-migration-ladder.md`'s `WebhookStore` row). That is a permission-bits
mutation, not a content one; the distinction matters because the file is otherwise genuinely
inert. Operators whose legacy file DID hold real overrides reapply them via Settings once after
upgrading past this release; see `docs/user-manual/upgrading.md`.

**The legacy file's CONTENT is left in place, untouched, indefinitely** (its permission bits are
not — see above) — nothing in this migration reads its content for any purpose beyond the
boot-time row count, moves it aside, or deletes it (contrast the dropped mandatory-backfill draft,
which would have moved a successfully-backfilled file aside under ADR-0009's one-release
rollback-window convention). A pre-migration install that set
`oidc_client_secret` therefore has that plaintext secret sitting in `runtime-config.db`
indefinitely post-upgrade, now surfaced to the operator by the row-count warning above rather than
never mentioned at all. Not auto-remediated here (deleting an operator's file on their behalf is
its own hazard); recorded as an operator action item instead — see `docs/user-manual/upgrading.md`'s
"delete or secure it" bullet.

This is a DEVIATION from ADR-0009's ORIGINAL "mandatory for config/reference stores" default
(`RuntimeConfigStore` IS a config/reference store by that ADR's own classification) but NOT from
its current, amended text, which now requires exactly what this section describes — recorded here
for anyone reading this ADR without also having read ADR-0009's amendment.

### `/readyz` / `/healthz`

`/readyz`'s `StoreCheck` vector was already wired pre-migration and is unchanged by this
migration; `is_open()` never flips post-construction, so this stays belt-and-braces,
matching every other migrated store on the ladder. `/healthz` was NOT wired the same way
at initial migration — a gap independently found by architect and sre in the post-merge
governance hardening round (see "Post-merge hardening" above) and closed in that same
round: `runtime_config_ok` now feeds both `/healthz`'s `all_stores_ok` conjunction and its
`"stores"` JSON block (`{"runtime_config_store", runtime_config_ok ? "ok" : "error"}`),
so the two probes now agree on which stores exist.

### `SecretCodec` instance model

Own instance (`runtime_config_secret_codec_`), constructed over the SHARED `auth_key_provider_`
(the KEK material is install-wide, ADR-0010 §2 — this is the FOURTH `SecretCodec` instance backing
that one `FileKeyProvider`, after `auth_secret_codec_`, `plugin_config_secret_codec_`, and
`webhook_secret_codec_` (ADR-0057, already merged when this migration was authored) — chronological
count, not `server.cpp`'s construction-order line position, where this store's ctor call happens to
sit above `webhook_secret_codec_`'s).
Construction sequence in `server.cpp` mirrors `PluginConfigStore`'s exactly: construct the codec
(ctor only) -> construct `RuntimeConfigStore` (registers `runtime_config_secrets.sealed_value`
immediately after its own schema migration) -> `SecretCodec::init()` on a pinned lease ->
`warn_if_legacy_data_present()` -> the boot override pass. Any failure at any step is a fatal
startup error (`startup_failed_ = true`), never a serve-degraded config plane.

`runtime_config_secret_codec_` joins `kek_enrolled_codecs()` (live KEK rotation surface) and,
because that function also drives the `yuzu_server_secret_decrypt_failures_total` metrics export
loop (ADR-0057's precedent — see its "SecretCodec instance model" section), the metrics export too
— both in the same enrollment line. **Post-merge hardening**: the initial version of this migration
omitted this enrollment (external adversarial-review finding, PR #3632) — a KEK rotation silently
never re-wrapped the OIDC client secret while `/kek/status` reported `rotation_complete: true`, and
the secret would have become permanently undecryptable once the pre-rotation KEK version was later
retired. Fixed by adding the one enrollment line, matching `webhook_secret_codec_`'s.

## Considered and rejected

- **A nullable `value_enc BYTEA` column alongside the existing `value TEXT` column, in the SAME
  `runtime_config` table** (the initial design sketch, before `PluginConfigStore`'s already-merged
  `configs`/`secrets` table split was found). Rejected once the closer precedent was found: a
  second column still requires the same "does this row's secrecy live in column A or column B"
  branching at every read/write call site that a table split gets for free via presence, AND it
  would have been a NOVEL discrimination scheme on the ladder rather than reusing an
  already-reviewed, already-merged one.
- **`WebhookStore`'s (ADR-0057, merged after this ADR was drafted) `has_secret BOOLEAN` +
  nullable `secret BYTEA` + `CHECK` constraint shape** — structurally the same family as the
  nullable-column sketch above, confirmed once ADR-0057 actually merged. It is the RIGHT choice
  for webhook's problem (every row is the SAME kind of thing — a webhook — with one secret column
  that is legitimately null for an unsigned webhook); it is NOT impossible to adapt to this store's
  problem (a per-key `has_secret` flag on `runtime_config` could in principle work row-by-row too),
  but it would reproduce exactly the same call-site branching burden the nullable-column sketch
  above was rejected for — "does this key's secrecy live behind a flag or in the plain column" at
  every read/write, which a table split gets for free via presence. `PluginConfigStore`'s table
  split remains the correct precedent here on ergonomic grounds, not because the alternative is
  unworkable.
- **Widening `get_value()` to `std::expected`.** Rejected as disproportionate — no live call site
  feeds a security decision (verified above), and widening would touch several call sites across
  `server.cpp`/`settings_routes.cpp` for no behavioral benefit. Recorded explicitly per the
  playbook's deferral clause rather than left unstated.
- **Keeping `get_all_with_secrets()`/`get_with_secrets()`/`get_value_with_secrets()` around,
  unused in production, once `read_secret()` existed.** Considered as a smaller diff during the
  Zeroization fix (see "Decision" above) — rejected because an unused-but-present method
  returning a real secret as `std::string` is still the exact shape the governance floor exists
  to close, and because leaving it in place invites a future caller to reach for the familiar
  name instead of the compliant one.
- **Retroactively re-encrypting a becomes-secret-later plaintext row at boot**, instead of
  "next write envelopes it." Rejected — no other store on the ladder does this, and a boot-time
  encrypt-on-read would mean `read_secret()` (a read) has a write side effect, which none of
  its callers expect and which would need its own transaction/failure-handling story for a
  scenario that (today) can never actually occur — `kSecretKeys` has exactly one entry and it
  has always been secret.
- **A mandatory, fingerprinted `migrate_from_sqlite()`** (`TagStore`'s shape: content fingerprint +
  completion marker, direction-aware conflict rules for non-secret keys, transform-not-copy
  encryption for `oidc_client_secret`, move-aside-on-success for the legacy file) — an earlier
  draft of this ADR built exactly this, per ADR-0009's original "mandatory for config/reference
  stores" default. Rejected once ADR-0009 was amended (fresh-start-by-default, PR #3622): no
  production fleet has ever run a pre-Postgres Yuzu build, so the mandate's premise (protecting
  real operator config at risk of loss) is empty for this migration, and the single most complex
  piece of it would have existed solely to guard against a scenario that has not occurred. This
  does not mean no legacy file can ever exist on a given install — a non-production/staging/pilot
  environment could still have set real overrides, which is exactly why the detect-and-warn
  obligation (see "Backfill" above) exists as the narrower substitute for a full backfill. See the
  "Backfill" section above.
- **Adding a `scripts/test/test-upgrade-stack.sh` survival assertion for a runtime-config value
  (e.g. a `log_level` override + `oidc_client_secret` `is_set`) across the previous-release →
  HEAD image swap.** Moot once backfill was dropped — there is nothing to survive the cutover by
  design (ADR-0009's amendment explicitly supersedes this requirement for a skip-by-default
  store). Before backfill was dropped, `git log` on that script showed only the flagship
  `feat/pg-migrate-inventory-store` work had added a per-store assertion there — `TagStore`,
  `PolicyStore`, `PluginConfigStore`, and `ProductPackStore` (all mandatory-backfill, all
  required by ADR-0009's ORIGINAL text to have one) never implemented theirs, a compliance gap
  in those migrations rather than evidence the requirement was never real.

## Consequences

- `RuntimeConfigStore`'s constructor signature changes from `(const std::filesystem::path&)` to
  `(pg::PgPool&, pg::SecretCodec&)` — every construction site (`server.cpp`,
  `test_settings_routes_oidc.cpp`, `test_settings_routes_dex_alerts.cpp`,
  `test_runtime_config_secret_redaction.cpp`) updated to the PG substrate contract.
- `get_all()`, `get()`, `read_secret()` return `std::expected<..., std::string>` instead of a
  plain container/`optional` — closes the pre-existing CH-2/Task#10 defect (a degraded store
  silently reading as "nothing configured") as a consequence of adopting the ADR-0036 typed-read
  contract this migration requires anyway, not as separately-scoped work.
- `PUT /api/config/:key` now returns 503 (not 400) on a genuine DB/crypto write failure,
  distinguished via the `kRuntimeConfigDbErrorPrefix` marker on `set()`'s error string; `GET
  /api/config` returns 503 on a genuine read failure from `get_all()` (previously this route
  could not distinguish a degraded read from "nothing configured" at all).
- `apply_runtime_config_overrides()` (boot) now returns `bool`; a read failure is a fatal startup
  error (`startup_failed_ = true`) rather than a silently-skipped override pass.
- No REST/API-visible change to `GET /api/config`'s success-path JSON shape, `PUT
  /api/config/:key`'s 200 response, or any Settings UI behavior beyond the one-time cutover
  reset below — the migration is otherwise storage-layer-only from an operator's perspective.
- **Any runtime config override set before this release does NOT carry over on the first
  Postgres cutover** — the one operator-visible consequence of the fresh-start decision, and a
  one-time event (a boot that finds `runtime_config_store` already populated, i.e. every boot
  after the first, is unaffected). `docs/user-manual/upgrading.md` documents the row-count boot
  warning and the "reapply your overrides" instruction.
- `test_runtime_config_store.cpp` is new (no general store test file existed pre-migration) and
  has no legacy-copy/backfill coverage by design, though it does cover the detect-and-warn
  obligation (`warn_if_legacy_data_present()`) and the `set()` advisory-lock race fix (held-lock
  regression test, `BaselineStore` technique); `test_runtime_config_secret_redaction.cpp` and
  `test_settings_routes_oidc.cpp` keep every pre-migration assertion's INTENT, adapted to the
  widened `std::expected` API, `read_secret()`, and `PgTestTemplate` construction.
- `get_all()`, `get()`, and `read_secret()` each gain a
  `yuzu_server_runtime_config_read_degrade_total{reason}` counter
  (`store_not_open`/`pool_acquire_timeout`/`query_error`/`crypto_error`), matching
  `ProductPackStore`/`CustomPropertiesStore`'s #1675 observability convention.
- `get_all()`, `get()`, and (as of the post-merge hardening round) `read_secret()` all read the
  plain and secrets tables in ONE `UNION ALL` statement, not two separate SELECTs — the two-SELECT
  atomicity race an earlier version of this migration recorded as accepted is resolved by this
  shape, not left open (see "Zeroization fix" and "Post-merge hardening" above).
