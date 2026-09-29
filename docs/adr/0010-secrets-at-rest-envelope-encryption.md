---
status: accepted
date: 2026-06-10
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; HITL session 2026-06-10 (#1319)
scope: platform — secret material at rest in the server's Postgres substrate
builds-on: ADR-0006 (PostgreSQL substrate), ADR-0008 (substrate architecture), ADR-0009 (backfill cutover)
---

# 0010 — Secrets at rest: app-side envelope encryption behind the KeyProvider seam

## Context

ADR-0004/0006/0009 all carry the same load-bearing carve-out: "server-side durable state in
Postgres" is **not** "secrets in a plain Postgres column." The api-token and CA store
migrations were deferred behind this ADR.

Inventorying what the server actually persists reshapes the problem. The stores the carve-out
named turn out to be the clean ones: `api_tokens.db` holds only SHA-256 token hashes
(verify-only), and `ca.db` holds cert metadata plus an opaque `key_ref` — the CA root private
key already lives **outside** the database behind the `KeyProvider` seam
(`server/core/src/key_provider.hpp`: `FileKeyProvider` 0600 PEM in a 0700 dir today, a future
`Pkcs11KeyProvider`/`HsmKeyProvider` with zero caller change). The recover-plaintext secret
columns are elsewhere:

| Secret | Store / column | Today |
|---|---|---|
| MFA TOTP secrets | Postgres `auth.users.mfa_totp_secret` | **`SecretCodec`-encrypted (shipped 2026-07-16)** — see the Update below |
| Webhook signing secrets | `webhooks.db` `webhooks.secret` | plaintext (omitted from `list()`) |
| Offload-target credentials | `offload_targets.db` `auth_credential` | plaintext |
| OIDC client secret | Postgres `runtime_config_store.runtime_config_secrets.sealed_value` | **`SecretCodec`-encrypted (ADR-0060)** |

> Historical note: the original table (2026-06-10) also listed a `sessions.session_token`
> row against the then-SQLite `auth.db`. The `auth`/`scim_store` Postgres cutover (ADR-0006
> Wave 3, 2026-07-16) **dropped** the `sessions` table outright rather than migrating it —
> sessions are, and always were, in-memory-authoritative (`AuthManager::sessions_`); the
> SQLite-era DB mirror was a permanent dead-write, never read back. There is no durable
> session-token column on any substrate to encrypt.

Verify-only material — operator password PBKDF2 hashes, API/device/enrollment token SHA-256
hashes, MFA recovery-code hashes, license-key hashes — is not secret-recoverable and is fine
in plain columns on any substrate.

The threat model this ADR must answer: (a) **db-dump exposure** — a stolen `pg_dump`, a
mis-secured backup, or a snapshot of the Postgres volume; (b) **insider with SQL access** — an
operator or attacker who can run queries but does not own the server host; (c) what lands in
routine backups.

**Residual risk (explicit non-goals).** This design does **not** defend against: compromise
of the server host itself — an attacker who can read the 0600 KEK file recovers everything
(the answer to that is the PKCS#11/KMS provider swap, not this ADR); plaintext secrets in
live process memory (mitigated only by zeroization discipline); and note that the
SQL-insider coverage rests on the assumption that SQL access does not imply read access to
the server's keys directory — true for a separate or managed Postgres and for SQL-only
access on colocated deploys, but it is an assumption, stated here so reviewers don't infer
coverage the design doesn't have.

## Decision

**Secret columns in Postgres are envelope-encrypted app-side. The KEK lives behind the
existing `KeyProvider` seam and never enters Postgres.**

1. **Mechanism.** AES-256-GCM via the OpenSSL the server already links. Each secret value is
   encrypted with a fresh data-encryption key (DEK); the DEK is wrapped by the install's
   key-encryption key (KEK). One opaque column holds a versioned blob:

   ```
   ver || kek_version || wrap_nonce || wrapped_dek || wrap_tag || data_nonce || data_tag || ciphertext
   ```

   Normative rules (the implementation PR's security review checks conformance to these,
   it does not re-derive them):
   - **AAD binding (anti-swap):** the payload encryption uses AES-GCM
     AAD = `(ver, store namespace, table, column, row primary key)`; the DEK wrap uses the
     same tuple **plus `kek_version`**. Encrypted values are therefore **non-relocatable**
     — an insider with SQL *write* access cannot swap blobs between rows/columns and have
     the server decrypt one secret in another's context (e.g. recovering an offload
     credential through the webhook-HMAC path). `kek_version` lives in the **wrap-layer
     AAD only, deliberately**: rotation re-wraps the DEK (recomputing the wrap tag under
     the new version) without touching the payload, so the payload tag must not depend on
     `kek_version` — including it there would invalidate every payload tag at first
     rotation and brick all secrets behind the fail-closed rule (empirically reproduced
     with live AES-GCM in the #1333 adversarial review). Version integrity is preserved:
     a tampered blob `kek_version` fails the wrap-layer tag check.
   - **Wrap algorithm:** AES-256-GCM with its own independent random nonce (`wrap_nonce`);
     one primitive throughout rather than a separate AES-KW dependency.
   - **Nonces and DEK single-use:** 96-bit nonces, fresh per encryption; a DEK encrypts
     exactly one value exactly once — updating a secret mints a fresh DEK (never DEK reuse
     under a new nonce). KEK rotation re-wraps only; it never touches `data_nonce`/payload.
   - **Canonical AAD serialization:** naive concatenation of the AAD tuple is ambiguous
     (`"a"+"bc"` ≡ `"ab"+"c"` — exactly the swap class AAD exists to defeat). Each field
     is length-prefixed (u32-BE length before each field); row PKs use one canonical
     encoding (BIGINT → fixed 8-byte BE); the `kek_version` bytes in the **wrap** AAD are
     byte-identical to the blob's field. Covered by a round-trip + boundary-shift test.
   - **Blob v1 pins widths:** `ver` u8; `kek_version` u32-BE; nonces 12 bytes; tags 16
     bytes; `wrapped_dek` fixed 32 bytes (raw GCM output, tag separate) — every field but
     `ciphertext` is fixed-width, so `ciphertext` is the remainder and needs no framing.
     Decode rejects blobs below the fixed minimum length before slicing.
   - **Decrypt-failure semantics — fail closed at EVERY store that calls
     `SecretCodec::decrypt`:** a GCM tag failure is the tamper signal — refuse the
     operation, emit an audit event + metric, and **never** degrade to an empty secret.
     Concrete examples of why empty-on-failure is dangerous: `webhooks.secret` and
     `offload_targets.auth_credential` both have existing "empty means no auth" code
     paths (`webhook_store.cpp`, `offload_target_store.cpp`), so it would silently
     disable signing/auth. The audit event carries **identifiers only** (the AAD tuple:
     store, table, column, row PK, kek_version) — never ciphertext, plaintext, DEK, or
     key bytes.
   - **NULL/absent semantics (anti-downgrade):** AAD stops blob *swap*, not blob
     *deletion*. A NULL or absent value in a secret column whose row is configured to
     carry a secret is a **hard error** (same handling as a tag failure), never "no
     auth". "No secret configured" must be represented by an independent non-secret
     flag/column, never by column emptiness — otherwise an SQL-write insider NULLs the
     column and rides the empty-means-no-auth path to disable signing without ever
     touching the crypto.
   - **Encrypt-failure semantics:** if `SecretCodec::encrypt` fails (CSPRNG failure
     minting a DEK/nonce, provider error), the surrounding store write/transaction
     **aborts** — a failed encrypt never results in writing plaintext (or anything else)
     to the column. Every `RAND_bytes` return is checked.
   - **No decryption oracle to callers:** external surfaces (REST/MCP/dashboard) receive
     one generic "unavailable" error for every decrypt-failure class — an external caller
     must not be able to distinguish decrypt-failure from not-found (existence/tamper
     oracle). The failure-class taxonomy (`tag_mismatch`/`kek_unresolvable`/
     `malformed_blob`) appears only in the server-side audit event and metric.
   - **Zeroization:** `SecretCodec` `secure_zero`s DEKs and decrypted plaintext buffers
     once consumed (mirrors the `KeyProvider::load_key` caller contract). Codec
     interfaces use a non-copyable, move-only zeroizing buffer type (`OPENSSL_cleanse`
     in the destructor — resists dead-store elimination); `std::string` at the boundary
     bounds, not guarantees, zeroization, so it is not used for key/secret bytes. (The
     existing `yuzu::secure_zero` in `sdk/include/yuzu/secure_zero.hpp` is string-only;
     the implementation adds a span overload or uses `OPENSSL_cleanse` directly — no
     third idiom.) Store methods that return recovered secrets to in-process callers
     return the zeroizing buffer type as well, not `std::string`. EVP contexts are
     RAII-owned (`EVP_CIPHER_CTX_free` on all paths, the `x509_ca.cpp` idiom). Codec
     errors return `std::expected<T, std::string>` (`runtime_config_store` precedent) and
     never embed secret material in error strings.

   Decryption happens in the store class, never in SQL.

   **Stable-identity constraint:** because AAD binds to `(store, table, column, row PK)`,
   secret-bearing tables must use stable primary keys, and any migration or feature that
   changes row identity — surrogate-PK churn from delete-and-reinsert upserts, table
   rebuilds that renumber serials, table/column renames, or a Postgres schema (store
   namespace) rename — must decrypt-and-re-encrypt through `SecretCodec` as part of that
   migration, never copy blobs.
2. **Key custody.** The KEK is 32 bytes of CSPRNG output (`RAND_bytes`, return value
   checked — CSPRNG failure at generation is `startup_failed()`), generated on first boot
   (same bootstrap pattern as the default certs), custodied behind the `KeyProvider` seam
   (`key_id = "secrets-kek-v<N>"`): `FileKeyProvider` 0600/0700 today (on Windows the
   equivalent is a restrictive DACL granting only the service account — POSIX mode bits
   are an approximation there, and the implementation must state the NTFS posture
   explicitly); PKCS#11/KMS/HSM later by swapping the provider, with `key_ref` opaque to
   all callers. The KEK is never written to Postgres, never logged, never exported by any
   API. **The codec↔provider contract is wrap/unwrap, not key export** (#1333 review
   HIGH-2): `SecretCodec` never handles raw KEK bytes — the provider interface for this
   use is `generate_kek() → key_ref`, `wrap_dek(key_ref, dek, wrap_aad) → wrapped+tag`,
   `unwrap_dek(key_ref, wrapped, tag, wrap_aad) → dek`, and a deterministic
   `kek_check_value(key_ref)`. `FileKeyProvider` implements these locally over its 0600
   file (raw key loaded, used, and zeroized *inside the provider*); a PKCS#11/KMS provider
   delegates to the token, so a **non-exportable** KEK is fully supported — the
   `load_key`/raw-export path is NOT part of the SecretCodec contract. Custody mechanics:
   - **Atomic write:** `store_key` for the file provider writes temp-file → fsync → rename,
     so power loss during first-boot generation can never leave a torn KEK file that
     "resolves" but fails every decrypt as pseudo-tamper.
   - **Fingerprint registration:** at KEK generation/rotation the substrate records
     `(kek_version, key-check value, created_at)` in a substrate meta table. The KCV comes
     from `kek_check_value(key_ref)`: for `FileKeyProvider` the SHA-256 of the key
     material (safe — full-entropy 256-bit key, no dictionary angle); a non-exportable
     provider derives it deterministically on-token (e.g. ciphertext of a fixed test
     vector). KCVs are non-secret (standard practice) and are the one KEK-related artifact
     allowed in the database. At boot, `SecretCodec` init —
     substrate-level, before stores open — verifies that **every kek_version registered in
     the meta table resolves through `KeyProvider` to material matching its fingerprint**.
     This catches: backup skew (keys dir older than the DB), a torn/corrupt KEK file
     (fingerprint mismatch ≠ tamper), and the dual-server case below — each with a
     distinct, actionable error instead of a flood of per-row decrypt failures.
   - **Fail-closed boot:** any unresolvable or fingerprint-mismatched registered KEK →
     `startup_failed()` with a distinct `kek_unresolvable` / `kek_corrupt` log token
     (operators must be able to triage this separately from "DB down"), matching
     ADR-0007's posture — a loudly-down server over one silently serving with unreadable
     secrets.
   - **KEK residency:** lives *inside the provider*. `FileKeyProvider` loads its raw KEK
     once into a non-copyable zeroizing buffer at first use (one resident copy beats N
     transient ones, `OPENSSL_cleanse` on every exit path — the zeroization rule covers
     every KEK representation, not just DEKs/plaintext) and re-reads only on rotation;
     `SecretCodec` holds `key_ref`s, never key bytes.
   - **Topology rule (one KEK per database):** in the FileKeyProvider era the supported
     topology is **one server instance per database**. Two servers first-booting against
     one Postgres with separate keys directories would each mint an independent
     `secrets-kek-v1` and read each other's writes as tamper. The fingerprint registration
     makes this fail loudly: the second server's boot check finds a registered fingerprint
     it cannot match and refuses. Multi-server (HA/blue-green) requires shared custody —
     a shared keys directory or the KMS/PKCS#11 provider — and is out of scope until then.
3. **Key hierarchy & rotation.** KEK rotation mints `secrets-kek-v<N+1>` and re-wraps DEKs
   (cheap: re-encrypt the small wrapped-DEK blob, not the payload). The blob's
   `kek_version` field makes rotation incremental and interruptible. DEK-per-secret means
   a single leaked DEK exposes one value, not a class. Rotation lifecycle rules:
   - **Discovery by scan is acceptable at our volumes** (the secret-bearing tables are
     tens-to-low-thousands of rows: operators × TOTP, webhooks, offload targets, one OIDC
     row; sessions are hashes and excluded), and the `kek_version` field sits at a fixed
     offset in the blob header, so "find rows wrapped under v<N>" is a cheap header scan.
     If a secret table ever outgrows scan-trivial, the escape hatch is a denormalized
     `kek_version` column kept consistent with the blob field — not mandated now.
   - **Completion signal:** rotation is complete when a verified scan shows zero rows
     referencing v<N>; the substrate exposes `oldest_kek_version_in_use()` so the
     operator (and the runbook) can confirm before retiring anything.
   - **Safe retirement:** an old KEK version may be deleted from `KeyProvider` storage
     only when (a) zero stored blobs reference it AND (b) the oldest database backup the
     operator intends to honour no longer contains blobs wrapped under it (a restored
     backup needs the KEK versions its rows reference). The server refuses
     `delete_key` on a KEK version that condition (a) fails — premature retirement is
     permanent, unrecoverable loss of every un-rewrapped row. Retirement is recorded
     (audit event) as destruction evidence.
   - **Concurrent-update safety:** re-wrap is read-rewrap-write and must be
     compare-and-swap (`WHERE secret_blob = <value read>`); a plain write would silently
     revert an operator's mid-rotation secret update to the old value under the new KEK.
   - **KEK lifecycle audit events:** `kek.generated`, `kek.rotated`, `kek.retired`, and
     `secret.decrypt_failure` are audit-taxonomy entries from the first implementation
     PR, with failure classes distinguished: `tag_mismatch` (tamper) vs
     `kek_unresolvable` (config/key loss) vs `malformed_blob` (parse). Metric:
     `yuzu_server_secret_decrypt_failures_total{store, failure_class}` (counter), per
     `docs/observability-conventions.md`. A systemic class (`kek_unresolvable`) must not
     bury a genuine single-row `tag_mismatch` — distinct classes make that triageable.
4. **The substrate rule** (replaces the store-name carve-out): **no plaintext
   recover-plaintext secret may land in a Postgres column.** Secret columns are either
   (a) verify-only hashes, or (b) envelope-encrypted blobs as above. Every store migration
   that touches a secret column gets `security-guardian` review.
5. **Session tokens stop being secrets at rest.** They are bearer values looked up by
   presented value (verified: every access path in `auth_db.cpp` keys by presented token or
   by username; the REST surface revokes by username/self and never lists stored values), so
   they convert to SHA-256 hashed (verify-only) storage during the `auth.db` migration — the
   same pattern as API/device/enrollment tokens — rather than being encrypted. One less
   recover-plaintext class. Preconditions recorded: unsalted SHA-256 is sound here *only*
   because session tokens are 256-bit server-generated random values (it would not be for
   low-entropy material), and any future "list active sessions" UX must use display IDs
   (precedent: `api_token_store.cpp` `hash.substr(0,24)`), never recovered tokens.
   Sequencing note: AuthDB session rows are currently dead-writes (the in-memory
   `AuthManager::sessions_` map is the authoritative read path), so the hash conversion
   should ride with the session-persistence work rather than migrating the column twice.
6. **Key material stays out of the database entirely.** The CA root key, default-cert and TLS
   private keys remain behind `KeyProvider` as today. This ADR does not move them and no
   future store migration may.
7. **Scope ruling for the deferred stores.** Because `api_token` (hash-only) and `ca`
   (key_ref-only) contain no plaintext secret columns, their Postgres migrations are
   **unblocked** onto the normal ladder (per-store ADR + `security-guardian` review as
   already mandated). The stores this ADR actually gates are the ones with recover-plaintext
   columns: `auth` (TOTP secrets; sessions convert to hashes), `webhooks`, `offload_targets`,
   and `runtime_config` (OIDC client secret).

## Considered and rejected

- **`pgcrypto` (db-side encryption).** Rejected. Keys must be supplied to SQL, so they
  transit statement text — visible to `pg_stat_activity`, statement logging, slow-query
  logs, and any insider with SQL access, which is precisely the adversary in the threat
  model. It also ties crypto policy to the database engine and puts key handling on the
  wrong side of the connection.
- **Keeping all secrets out of Postgres in a dedicated encrypted home (extended
  KeyProvider-style vault).** Rejected as the *general* mechanism. It is the right shape for
  single-row trust anchors (CA root, TLS keys — where it remains the rule), but for
  row-per-entity secrets (a TOTP secret per operator, a signing secret per webhook) it
  creates a second durable store that must be operated, backed up, and kept transactionally
  consistent with the row data it shadows — reintroducing the multi-store coordination
  problem the Postgres consolidation exists to remove.
- **Transparent disk/volume encryption only (LUKS/FDE/cloud-volume).** Not a substitute: it
  protects against stolen disks, not against `pg_dump` exfiltration or SQL-level access, and
  is invisible to backups taken through the database.
- **Encrypting verify-only hashes too.** Rejected as scope creep; hashes are already
  non-recoverable, and uniform encryption would complicate lookup-by-hash indexes for no
  threat-model gain.

## Consequences

- **Backups — the restore-pairing invariant.** `pg_dump` and volume snapshots contain
  ciphertext and wrapped DEKs only — a database backup alone recovers no secrets, **and
  therefore a database restore is unusable without the matching keys directory**. DB
  backups and keys-dir backups are a *pair*: restoring a dump to a fresh install (new
  `KeyProvider` dir) orphans every encrypted secret by design. The KEK file (or future KMS
  handle) must be backed up **separately and offline**, exactly like the CA root key (same
  SRE note as `key_provider.hpp`), and the restore-verification drill must restore *both
  halves together* and confirm a clean fingerprint check at boot. Losing the KEK orphans
  TOTP enrollments, webhook secrets, offload-target credentials, and the OIDC client
  secret — all re-enrollable/re-issuable, but at operator pain (every TOTP-enrolled
  operator re-enrolls; every webhook secret is re-issued and its downstream consumer
  reconfigured; every offload credential re-issued).
- **Break-glass (KEK permanently lost).** Two parts, both deliberate:
  - **Admin login survives KEK loss by design:** MFA recovery codes are verify-only PBKDF2
    hashes — they need no KEK. An admin whose TOTP secret is undecryptable signs in via a
    recovery code and re-enrolls TOTP. KEK loss is painful, never a total lockout.
  - **Voided-secrets boot:** an explicit operator flag (named at implementation, e.g.
    `--accept-voided-secrets`) boots the server treating all undecryptable values as
    *absent-and-must-be-re-set* — loudly logged and audited, never silent. Without the
    flag, the fail-closed boot stands. This converts a DR-without-keys event from a hard
    outage into a documented re-enrollment procedure.
- **Operator documentation home:** the KEK backup/rotation/restore-drill and break-glass
  procedures land in `docs/user-manual/server-admin.md` under a "Key management"
  subsection (alongside the CA root key guidance) with the first implementation PR.
  Key-escrow / split-custody is acknowledged as a known enterprise questionnaire item:
  unsupported in the FileKeyProvider era, addressed by the KMS/PKCS#11 provider swap.
- **The pg substrate (#1320) grows a `SecretCodec` helper** (`server/core/src/pg/`):
  encrypt/wrap/unwrap/decrypt + KEK-version bookkeeping (the fingerprint meta table and
  `oldest_kek_version_in_use()`), used by every store that owns a secret column. It takes
  a `KeyProvider&`; tests use a temp-dir `FileKeyProvider`. Build-graph note:
  `key_provider.{hpp,cpp}` is currently compiled into the main server target — when `pg/`
  becomes a library depending on it, extract KeyProvider into a leaf target first or the
  meson graph cycles.
- **Migration backfills that touch secret columns transform, not copy** (ADR-0009 note):
  plaintext SQLite values are encrypted (or hashed, for sessions) on the way in. The legacy
  read-only `.db` retained for one release still contains plaintext — do **not** scrub it
  (that breaks ADR-0009's rollback net), but the window is hardened, not merely documented:
  (a) the cutover verifies/forces 0600 on retained secret-bearing legacy files; (b) an
  operator purge flag allows early deletion once rollback confidence exists — purge does a
  best-effort overwrite before unlink, but on journaled/SSD storage overwrite guarantees
  are weak, which is why the rotation guidance in (c) is the primary mitigation; (c) the
  per-store ADR instructs operators to treat window-era data-dir backups as secret-bearing
  and to rotate webhook/offload/OIDC secrets after the window if backup posture is unknown
  (all are re-issuable); (d) the next-release deletion is implemented and upgrade-tested,
  not left aspirational. Verification note: fresh-DEK-per-encrypt makes ciphertext
  nondeterministic, so backfill verification is **decrypt-and-compare** (never byte
  comparison), and interrupted-backfill re-runs detect already-transformed rows via the
  blob version header / a completion marker, not by value.
- **Operational cost.** One more trust-anchor file in the certs/keys directory; KEK rotation
  is an operator procedure (incremental re-wrap) to document in the user manual; per-value
  AES-GCM cost is negligible at our volumes for four of the five classes (TOTP per MFA
  login, OIDC at startup/refresh, offload per flush). The webhook signing secret is the
  potential hot path (per outbound delivery): implementations **may** cache the decrypted
  signing secret in memory for the lifetime of a delivery batch, provided the buffer is
  zeroized after — consistent with the zeroization contract, no premature optimisation
  forced or foreclosed.
- **`security-guardian` review is structural:** any PR adding or migrating a secret column
  cites this ADR and carries that review (the routed-concern row in CLAUDE.md).

## Review record

`security-guardian` design review, 2026-06-10 (#1319): **APPROVE-WITH-CHANGES**, all changes
folded into this text. Verified against code: the session-token access patterns (§Decision 5),
the api_token/ca clean-store claims (§Decision 7), and inventory completeness (independent
sweep of all 38 schema-bearing server stores — a larger denominator than ADR-0007's "~29
concrete stores" / CLAUDE.md's "~27 migrating stores" because it counts every file with a
CREATE TABLE, including reference/read-only ones — found exactly the five columns above, no
others; Entra directory-sync client secrets are request-scoped and never persisted). Findings
folded:
AAD anti-swap binding, wrap-algorithm/nonce/DEK-single-use rules, versioned blob format,
decrypt-failure semantics, zeroization, KEK provisioning + fail-closed boot (S-1…S-7);
residual-risk statement (T-1); session preconditions + sequencing (T-2/T-3); hardened
one-release retention window (R-1). Code note fixed alongside: `runtime_config_store` falsely
commented `oidc_client_secret` as "encrypted at rest" (I-1).

Full `/governance` run on PR #1333, 2026-06-10 (Gates 1–8, 12 agent reviews): the run
verified fold fidelity, re-verified every code-grounded claim independently (no ADR-0008-class
false premise), and surfaced four design gaps amended into this text in the same PR: KEK
retention/retirement lifecycle + completion signal (§Decision 3), the restore-pairing
invariant + break-glass position (§Consequences — including the observation that MFA recovery
codes are verify-only hashes and survive KEK loss by design), the one-KEK-per-database
topology rule + fingerprint registration (§Decision 2), and NULL/absent anti-downgrade
semantics (§Decision 1). Implementation-phase chaos scenarios (CH-1…CH-8: DR restore without
keys, backup skew + audit-flood masking, mid-rotation crash + premature retirement, dual
server, torn KEK, rewrap CAS race, NULL-out downgrade, rename re-bind) are attached to #1320
and the per-store migration issues.

Adversarial review by @fjarvis (PR #1333, 2026-06-10, Claude+Codex cross-examination + Hermes
×2): **REQUEST CHANGES**, both HIGHs valid and folded 2026-06-11. HIGH-1 found a genuine
self-contradiction the 12-agent governance run missed and reproduced it with live AES-GCM:
`kek_version` in the *payload* AAD + re-wrap-only rotation ⇒ first rotation invalidates every
payload tag and bricks all secrets behind the fail-closed rule. Fixed: `kek_version` moved to
the wrap-layer AAD only (where rotation recomputes it); payload AAD is the identity tuple.
HIGH-2: the seam promised "HSM swap with zero caller change" while requiring raw-key export —
fixed by making the codec↔provider contract wrap/unwrap (`generate_kek`/`wrap_dek`/
`unwrap_dek`/`kek_check_value` over opaque `key_ref`), so non-exportable keys are genuinely
supported. MEDIUMs folded: encrypt-failure aborts the transaction (never writes plaintext),
no decryption oracle to external callers, KEK zeroization inside the provider, zeroizing
return types for secret-returning store methods, checked `RAND_bytes`. LOW: purge-overwrite
honesty note. (His other MEDIUMs — canonical AAD encoding, universal fail-closed — were
already fixed in the governance amendment round, which his review predates.)

## Amendment — implementation deltas (#1320 PR 4, PR #1396, 2026-06-12)

The first implementation PR ships the mechanism as specified, with four recorded
deltas (none weakens a normative rule):

1. **The seam is its own interface.** The six KEK methods live on a separate
   `KekProvider` interface rather than growing `KeyProvider` (interface
   segregation): the raw-PEM CA/TLS custody contract and the wrap/unwrap secrets
   contract are disjoint, and the realistic split deployment — KMS/PKCS#11 for
   secrets, file for the CA root — needs them separable. `FileKeyProvider`
   implements both; `SecretCodec` takes a `KekProvider&`.
2. **`resolve_kek(key_id) → optional<key_ref>` is a fifth seam method** (plus a
   sixth, `delete_kek`, whose only sanctioned caller is
   `SecretCodec::retire_kek`). Boot verification needs it: `kek_meta` records
   versions + check values only — never refs — so the codec re-derives each
   version's opaque ref through the provider (file path / PKCS#11 `CKA_LABEL` /
   KMS alias). Any future provider must implement it.
3. **Per-value codec errors are typed**, `std::expected<T, SecretCodec::Error>`
   with a `FailureClass` enum (`tag_mismatch`/`kek_unresolvable`/
   `malformed_blob`/`crypto_failure`) instead of the `std::string` this ADR
   sketched — the enum is load-bearing for the metric label and makes the
   collapse-to-generic-"unavailable" rule mechanically checkable. Boot errors
   are likewise typed (`InitError::Kind`, adding the distinct
   `kek_unresolvable`/`kek_corrupt` operator tokens). Lifecycle operations keep
   `std::string` (the `PgMigrationRunner` convention).
4. **`kek_meta` carries `kcv_alg` (default `'sha256'`)** so versions minted by a
   future non-exportable provider, whose check values derive differently, can
   coexist with file-provider versions across a provider swap.

One forward rule for the per-store migration ADRs, recorded here so four stores
don't invent it divergently: because the AAD binds the row PK, **serial-PK
tables must allocate the key before encrypting** (`nextval('<seq>')` first,
then INSERT the encrypted blob with that id) — never INSERT-then-UPDATE, which
would transiently write a non-blob value to a secret column in violation of
§Decision 4. The wiring PRs should also share ONE `Error → A4-envelope`
mapping helper, not per-store ad hoc collapses.

## Update (2026-07-16) — first production consumer shipped: `auth.users.mfa_totp_secret`

`SecretCodec` had no production caller until the `AuthDB` Postgres cutover (ADR-0006). The auth
store registers `mfa_totp_secret` (BYTEA) as a secret column from inside its own constructor
(the row PK is `users.id`, a `BIGINT GENERATED ALWAYS AS IDENTITY`). The serial-PK-must-
allocate-before-encrypting rule above is satisfied trivially here, not by an explicit two-step
INSERT-then-UPDATE dance: a `users` row always already exists (created at account
creation/seeding, `mfa_totp_secret` starting `NULL`) by the time MFA enrollment ever runs, so
the id is always known before the first encrypt call — enrollment is inherently an `UPDATE ...
WHERE id = $n`, never part of the row's initial `INSERT`. `server.cpp`'s boot sequence follows
the ordering this ADR's Amendment implies but does not spell out: `SecretCodec` is constructed
(`auth_secret_codec_`, `server.cpp`), then `AuthDB`'s own constructor registers `mfa_totp_secret`
as a secret column, then `SecretCodec::init()` runs (verifies/generates the KEK-wrapped DEK for
whatever is registered by that point — `AuthDB`'s column only). `ScimStore` is constructed
**after** and takes **no `SecretCodec` reference at all** (`ScimStore(*pg_pool_)`) — it has no
secret columns of its own (SCIM tokens stay a verify-only SHA-256 hash), so it is not a codec
consumer and never receives one. A store/decrypt failure on `mfa_totp_secret` is treated as its
own fail-closed `AuthDBError::SecretUnavailable` outcome by every MFA-state reader, never
collapsed into "not enrolled" — see `docs/auth-architecture.md` "MFA / TOTP" and "MFA fails
closed on secret-read failure". The worked construction-order recipe is captured in
`docs/postgres-store-playbook.md` step 3, for the next store (`webhooks`/`offload_targets`/
`runtime_config`) to follow.

**Instance model (architect note, so the next consumer doesn't inherit an init-ordering
trap).** `SecretCodec::init()` validates every column registered **so far** — it has no way to
know whether more registrants are still to come. The shape this ADR and the playbook actually
prescribe is therefore **one `SecretCodec` instance per consuming store**, not one shared
instance fleet-wide: construct the codec → that store's own constructor registers its column(s)
→ that same store's `init()` call runs (register-before-init, scoped to one store). `AuthDB` is
the worked example (`auth_secret_codec_` in `server.cpp`) — it owns its codec instance
exclusively; `ScimStore` does not share it (see above), and no other store references it. A
**shared codec across multiple stores is possible in principle** (multiple stores' constructors
all registering into the same instance before a single deferred `init()`), but it requires
sequencing **every** registrant's construction ahead of that one `init()` call — a materially
easier invariant to violate than "one store, one codec, register-then-init immediately." Unless
a future change has a specific reason to share, give each new secret-bearing store its own
`SecretCodec` instance.
