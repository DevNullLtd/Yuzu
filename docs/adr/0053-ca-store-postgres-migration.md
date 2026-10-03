---
status: accepted
date: 2026-08-18
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 3 migration worker (batch 4), following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 3)
scope: server — `CaStore` (Yuzu internal CA inventory + lifecycle: root, issued-cert inventory,
  CRL version history), its cutover from SQLite to PostgreSQL, and its ADR-0009 backfill
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0010 (secrets at rest), ADR-0012 (server Postgres store contract), ADR-0036
  (authoritative-read type-distinguishability program policy)
related: docs/postgres-migration-ladder.md (Wave 3); docs/pki-architecture.md (routed reference);
  docs/adr/0048-license-store-postgres-migration.md (the authoritative-with-backfill /
  IDENTITY-LIFECYCLE / kXxxDbErrorPrefix template this migration follows most closely)
---

# 0053 — `CaStore` Postgres migration (authoritative, PKI routed-concern, with backfill)

## Context

`CaStore` (`server/core/src/ca_store.{hpp,cpp}`) is the inventory + lifecycle store for Yuzu's
internal CA: the root certificate (metadata only — the private key lives behind `KeyProvider`,
never in this store), the issued-certificate inventory, and the CRL version history. It is a
Wave 3 store on `docs/postgres-migration-ladder.md`, listed there as "unblocked" ahead of its
Wave-3 siblings because it holds no envelope-encrypted secret column — `key_ref` is an opaque
`KeyProvider` reference, not key material, so `SecretCodec` is not involved (confirmed below).

This is a PKI routed-concern store (`.claude/routed-concerns.md`): the catastrophic invariants —
key-never-in-the-DB, the shared `sign_agent_csr` signer, and the revoked-status read path staying
fail-closed — are preserved unchanged by this migration; only the storage engine changes.

`CaStore` was previously SQLite (`ca.db`, tables `ca_root`, `ca_issued`, `ca_crl_versions`,
migrations v1–v5) guarded by a single connection mutex, with a second, coarser `crl_publish_mu_`
serialising CRL-number allocation. It is wired live in `server.cpp` (`ca_store_`), consumed by
`ca_routes.cpp` (the `/api/v1/ca/*` REST surface + the Settings CA panel), `mcp_server.cpp`
(`list_issued_certs`/`revoke_certificate`), and `default_certs.cpp` (first-boot bootstrap).

## Decision

**Migrate `CaStore` to PostgreSQL as schema `ca_store`, tables `ca_root`, `ca_issued`,
`ca_crl_versions`, with a standard ADR-0009 first-boot backfill.**

### Schema

Schema name `ca_store` (ADR-0008 Update naming rule). A single consolidated `v1` migration folds
in every column the SQLite store's five migrations (v1–v5) added incrementally — those existed
only to upgrade already-deployed local files; no Postgres database predates this schema, so there
is nothing to incrementally ALTER. The partial index `idx_ca_issued_status ON ca_issued(status)
WHERE status = 'revoked'` carries across as-is (Postgres supports partial indexes natively).
`ca_crl_versions.der` becomes `BYTEA` (was `BLOB`); every other column keeps its pre-migration
type and name unchanged (`TEXT`→`TEXT`, `INTEGER` epoch-seconds/count columns→`BIGINT`).
`serial_hex TEXT PRIMARY KEY` and `ca_root.id INTEGER PRIMARY KEY CHECK (id = 1)` are kept exactly
(pre-migration ID contracts, per the Wave 2/3 lesson).

A new table, `sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT
NULL)`, is the backfill idempotency tracker — not part of the application data model.

### Secrets (ADR-0010) — resolves the Wave 3 "unblocked" note

**Asserted and unchanged by this migration: `key_ref` is the ONLY root-key-adjacent column, and
it is an opaque `KeyProvider` reference (a file path in Milestone 1), never the key itself.** No
column in any of the three tables holds secret material — `cert_pem` values are PUBLIC certs, not
keys. `SecretCodec` is therefore not involved; this store does not belong in a future secrets-seam
wave.

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime — the database is the
source of truth for the revoked-certificate set. A silently-empty/-false read on `is_revoked` /
`list_revoked` would silently accept a certificate that should have been rejected, or publish a
CRL that omits a real revocation — exactly the fail-open shape ADR-0036 exists to close. Every
reader/mutator whose false/empty result could feed that class of decision returns
`std::expected<..., std::string>`, prefixed `kCaDbErrorPrefix` ("`db_error: `") on a genuine
DB/lease failure — **with one deliberate, documented exception: `is_revoked()`**.

#### `is_revoked()` stays a plain `bool`, fails closed to `true`

This is the mTLS-accept security gate (`ServerImpl::is_peer_cert_revoked`), on the per-heartbeat/
Subscribe/Register-reauth hot path. Rather than expose a third ("couldn't tell") state a caller
could accidentally fold into "not revoked," every degradation mode — a non-hex serial (pre-
existing), a lease timeout, a query error (both new failure modes a networked Postgres substrate
makes far more likely than a local SQLite file) — returns `true`: "treat as revoked, refuse."
This mirrors `ApiTokenStore::validate_token`'s existing hot-path-degrades-to-the-safe-answer
precedent (both are auth-gate reads with the same shape). The catastrophic-if-violated PKI
invariant this store's kickoff cited verbatim: *"Degrade → error → treat as revoked / refuse,
never silent-pass."*

**Operational consequence, stated explicitly:** during a sustained Postgres outage, every
heartbeat/Subscribe/Register-reauth is rejected fleet-wide, not just genuinely-revoked agents.
Since the return value alone cannot distinguish "the DB is down" from "a real mass-revocation
sweep," `is_revoked()` emits a distinct, explicit log line on every degraded-path return
(`CaStore::is_revoked: database unavailable ... this is a DEGRADED-DB rejection, NOT a real
revocation`) so an operator diagnosing mass rejection has the signal in hand without having to
infer it.

#### `list_revoked()` — type-distinguishable, and its callers must abort, never proceed on empty

`list_revoked()` feeds CRL construction (`publish_crl()`'s revoked-set) and the PR3 HIGH-2
re-issue-block guard (`sign_agent_csr`'s scan for an existing revoked, non-expired cert on the
requesting `agent_id`). A silently-empty read on either call site is dangerous in a DIFFERENT way
than `is_revoked`'s own degradation: it does not merely deny one request, it can (a) publish a CRL
that claims nobody is revoked when real revocations exist (un-revoking every cert in every cache
that trusts that CRL), or (b) let a revocation-bypass re-enrollment through — the exact bug class
HIGH-2 (#1239) closed. Both `server.cpp` call sites were updated to treat a `list_revoked()`
`unexpected` as an abort signal (refuse to publish / refuse to issue), never as "empty means
nothing is revoked."

#### Revocation-sweep tick — reads the revoked set once per tick, aborts on a degraded read

The ~15s tick that tears down any live Subscribe stream whose agent leaf has since been revoked
does **not** call the fail-closed `is_revoked()` once per live agent. `is_revoked()`'s
fail-closed-to-`true` shape is correct for a single bounded mTLS accept, but reused once per live
agent inside a sweep it turns a transient Postgres outage into "every enrolled agent was just
revoked" — every stream torn down, and a `session.cert_revoked` audit row written for each: a
durable false compliance record, not merely an availability blip. The sweep instead reads the
revoked-serial set **once per tick** via a dedicated, cheap, unlabeled read
(`CaStore::list_revoked_serials()` — same WHERE clause and partial index as `list_revoked()`, but
no `cert_pem`/`ORDER BY`, so it stays cheap independent of `list_revoked()`'s own growth) and
**aborts the sweep entirely** on a degraded read — logs, increments
`yuzu_server_ca_revocation_sweep_read_failures_total`, and leaves every live stream untouched
rather than treating a read failure as mass revocation. The per-request gate (`is_peer_cert_revoked`)
is unchanged — still fails closed for its own bounded accept — so an agent revoked immediately
before an outage keeps its live stream for the outage's duration (no *new* access is granted; the
sweep is defense-in-depth on top of the per-request gate, not the only enforcement point).
`list_revoked()` itself is deliberately left reading the full row set for its own two callers
(CRL publish, the reissue-block guard): both fail CLOSED and LOUD on a degraded read already (an
operator-visible enrollment failure / an aborted publish with its own failure counter), which is
a materially different risk than the sweep's original fail-OPEN-and-silent shape — fixing only the
sweep is neither an under- nor an over-fix.

#### Root-singleton first-boot race (the one genuinely new problem)

Under per-instance SQLite this race never existed — each server instance held its own local
`ca.db`. A shared Postgres substrate makes it possible for two instances to independently generate
CA root material (their own key, their own self-signed cert, their own three default leaves,
written to their own local cert directory via `FileKeyProvider`) and race to establish it as
canonical.

**Resolution — split the write API:**

- **`try_insert_root(root)`** — the NEW, race-safe first-boot entry point. `INSERT ... ON
  CONFLICT (id) DO NOTHING RETURNING ...`: at most one caller's row is ever inserted. Every
  caller, winner or loser, reads back the SAME row that is now canonical — the loser does **not**
  get told "you lost" as a bare boolean; it gets handed the actual winning `CaRoot`, and MUST
  compare its returned fingerprint against what it generated to learn which happened (never
  locally infer "I won" from anything but the returned value).
- **`set_root(root)`** — kept, unconditional REPLACE (`ON CONFLICT (id) DO UPDATE`), the
  pre-migration `INSERT OR REPLACE` contract verbatim. Used by the two callers that legitimately
  intend a replace: PR6 subordinate-CA import (`ServerImpl::import_subordinate_chain` — an
  explicit, single-writer, operator-triggered re-root of an ALREADY-established root) and test
  seeding. **Never called from first-boot generation** — porting `set_root`'s semantics onto that
  path (as a naive migration might) would have the RACE LOSER silently clobber the winner's root
  with its own, orphaning the winner's already-enrolled agents in the instant between — the
  precise wrong outcome kickoff flagged.

**The loser's side (`default_certs.cpp`):** a losing caller has already generated complete,
unusable key material (nobody else holds its private key). What this migration guarantees is
DB-level: **exactly one root is ever established**, and every other racer fails closed — it never
writes its own material as though it were authoritative, and never silently operates under, or
overwrites, a root it doesn't recognise. Multi-replica HA over one shared `ca_store` Postgres +
one shared `--ca-dir` volume is **not an officially supported deployment topology today** (see
"Self-heal" below); a single-instance-per-directory deployment never reaches this branch at all,
since `try_insert_root` only ever contends against itself in that shape. The real fix is tracked,
not this migration's job: `docs/adr/2002-high-availability-architecture.md` WS-6 ("PKI/CA HA")
plans moving the CA key off local disk entirely (a `SecretCodec` blob in Postgres) plus a durable
CRL-publication state machine — status `planned`, `docs/ha-delivery-matrix.md`. The self-heal
mechanism below is a stopgap that keeps a shared-directory topology safe in the meantime, not the
eventual architecture.

**Tested** (`try_insert_root — a losing caller reads back the winner, never clobbers it`,
`[ca_store][pg][root][security]`): two `try_insert_root` calls with distinct root material against
the same store — the second call returns the FIRST call's root verbatim (fingerprint and
`cert_pem`), and a subsequent `get_root()` confirms the stored row is still exactly the winner's.

#### Self-heal and the bootstrap advisory lock

An established install (`ca_store` already holds a root) whose on-disk default-cert set is
missing, incomplete, or corrupt — a crash mid-bootstrap, a bad partial restore, a lost volume
file — self-heals rather than requiring the heavyweight "clean re-root" operator runbook: if the
local CA key still resolves at the exact path `ca_store`'s root recorded, AND cryptographically
pairs with that root's cert (`pki::cert_matches_key`), this instance re-mints the three default
leaves under the SAME root. This is directory access to the material that minted the root, not a
standalone proof of instance identity — every process sharing the same cert directory (a shared
volume across HA replicas, or a self-heal resumer racing an original instance that is merely slow
rather than dead) satisfies it identically. Two mechanisms keep this safe under that ambiguity:

- **A Postgres session advisory lock** (`yuzu:default_certs_bootstrap`, non-blocking try + bounded
  retry) serializes every entry into the purge-and-regenerate critical section — both the normal
  winning-the-race path and the self-heal path route through the same lock, and re-validate
  (`try_use_existing_complete_set`) once inside it in case a sibling finished while this instance
  waited. A liveness round-trip on the lock-holding connection runs immediately before the
  completion marker is written, closing the gap where the connection dies mid-critical-section
  (killed, idle-reaped, network-blackholed) without the process dying — Postgres releases the
  session lock the instant that connection ends, and nothing else would otherwise notice.
- **Cert/key-pairing verification on every idempotent fast-path check** (not just chain
  verification) means a mismatched pair that lands on disk despite the lock — from any cause —
  self-heals on the very next boot instead of validating as intact forever.
- **The CA private key is written to disk only after a candidate is confirmed the sole winner** of
  `try_insert_root`'s CAS, never speculatively beforehand — multiple simultaneous candidates on a
  shared directory would otherwise all race to write the same well-known `default-ca.key` path,
  and whichever write lands last silently detaches the established root from its real private key
  regardless of which candidate actually won the CAS, permanently defeating every future self-heal
  attempt for that root.

**A losing racer polls the shared cert directory for the winner's complete set (UP-3)** for up to
15s before falling back to refusing boot — the winner's completion marker is written last, so a
partial/in-flight write is never adopted. This turns "needs a restart to pick up the winner's
certs" into "self-heals within the same boot attempt" for the common case; a winner that hasn't
finished within the window (contention, a slow Postgres) still falls back to the original
fail-closed-and-restart behavior, never a hang.

#### `has_root()` / `get_root()` split — two callers needed the typed channel, two did not

`get_root()` becomes `std::expected<std::optional<CaRoot>, std::string>`. A NEW `has_root()`
convenience collapses a degraded read to `false` — kept **only** for the two production call
sites genuinely safe with that collapse: a background CRL-freshness-sweep tick skipping
harmlessly, and the `/readyz` `ca_root` signal, where "can't prove a root exists" SHOULD read as
unhealthy anyway. Two other call sites needed the typed channel instead:

- `default_certs.cpp`'s B-2 guard ("never silently re-root a populated CA," #1238) calls
  `get_root()` directly and fails closed (refuses to proceed) on a genuine read error — collapsing
  this ONE call site's degraded read to "no root" would let a fresh CA generation proceed and
  silently re-root a fleet that already has one, precisely the danger B-2 exists to prevent.
- **`server.cpp`'s boot-time PKI wiring block** (the `run()` code that wires the per-agent cert
  signer, the revocation checker, and the peer-cert recognizer) was **initially left on
  `has_root()`** in this migration's first two commits — an oversight caught by adversarial review
  (Kimi + Codex, both independently, 2026-08-20), not by the author. `has_root()`'s collapse turns
  a transient Postgres lease/query failure at this ONE call site into "no root," which silently
  skips wiring the revocation checker for the rest of the process's life — no retry, no periodic
  re-check. A revoked Yuzu-issued agent cert would then pass `Register`/`Subscribe`/heartbeat
  unchecked until the next restart: a fail-open security regression, and exactly the ADR-0036
  reviewer test this store's OTHER read paths were built to satisfy ("could a silently-false read
  gate a downstream grant/enforce/skip decision? If yes, fail closed, never empty") — just missed
  on this one call site. **Fixed**: the block now calls `get_root()` directly; an `unexpected` sets
  `startup_failed_ = true` and returns from `run()` immediately — this call site runs BEFORE
  `BuildAndStart()`, so nothing is listening yet, matching the bare-`return`-on-failure precedent
  the TLS-credential checks a few dozen lines below already use at this same pre-`BuildAndStart`
  point in `run()` (no listener to tear down, unlike the later SCIM-boot-failure recheck, which
  fires AFTER `BuildAndStart()` and so needs the heavier `stop()` call to close what is already
  open). A genuinely-empty root (`nullopt` — operator brought their own certs) is unchanged: skip
  wiring, no signer, same pre-PKI contract as before.

### Write-path failure classification (#3097 precedent)

- **`record_issued`** — `std::expected<void, std::string>`. A PG unique-violation (SQLSTATE
  `23505`) on `ca_issued.serial_hex` is classified distinctly, prefixed `kCaDuplicateSerialPrefix`
  ("`duplicate_serial: `"), separate from `kCaDbErrorPrefix` — resolves the #1276 flake lead
  (kickoff item 2). **Finding:** `x509_ca` mints a random 128-bit serial per issuance
  (`x509_ca.hpp`), so a genuine production collision is astronomically unlikely; no repro of a
  real collision was found in this migration's test fixtures or in the current tree. The
  classification is real infrastructure regardless — a future caller can retry issuance with a
  freshly-minted serial on this specific error rather than treating it as an outage — but this
  narrows, rather than closes, #1276: the flake is more likely a test-fixture serial reuse than a
  live collision, and is left open for whoever last touched it to close or re-scope with this
  finding in hand.
- **`revoke`** — `std::expected<bool, std::string>`. `Ok(true)` = transitioned; `Ok(false)` = a
  genuine, successful business answer (unknown/already-revoked — audited `result=denied`, per
  `docs/pki-architecture.md`'s existing taxonomy); `unexpected` = a genuine DB/lease failure,
  audited `result=failure` and surfaced as REST 503 / MCP `kInternalError` — **never folded into
  `denied`**, which would falsely record a database outage as a rejected revoke attempt (a false
  compliance record). `ca_routes.cpp`'s `RevokeOutcome` enum gained a `StoreError` member
  alongside the existing `NotFound`/`RevokedCrlStale`/`RevokedCrlPublished`, mapped to 503 on both
  the REST and dashboard-wrapper revoke handlers; `mcp_server.cpp`'s `revoke_certificate` handler
  mirrors the same three-way split.
- **`next_crl_number`** — `std::expected<std::uint64_t, std::string>`. The pre-migration SQLite
  version silently returned `1` on ANY read error — safe by accident under SQLite (a stray `1`
  either collides loudly against `record_crl`'s duplicate-refusal once real CRLs exist, or is
  merely stale-but-harmless before any CRL has ever been published) but unsafe to carry forward
  once the table can hold real cross-boot history: `server.cpp`'s `publish_crl()` now aborts the
  whole publish attempt on a `next_crl_number` error rather than substituting a default.

### CRL version continuity (kickoff item 4 — stated explicitly)

The CRL sequence must not regress or fork across cutover. Three parts:

1. **Backfill resumes above the legacy max, never regresses to 1.** Legacy CRL rows are inserted
   into `ca_crl_versions` before the store ever computes `next_crl_number()` in steady state, so
   `MAX(version)+1` naturally resumes above the highest backfilled version — tested explicitly
   (`migrate_from_sqlite — full happy-path backfill`: after backfilling a CRL at version 1,
   `next_crl_number()` returns 2, never 1).
2. **A version collision is always loud, never a silent clobber** — unchanged by this migration:
   `record_crl` is a plain `INSERT` (never `ON CONFLICT ... DO UPDATE`), so a duplicate version is
   refused, not overwritten. This was already true under SQLite; it remains true under Postgres.
3. **Cross-instance CRL numbering remains a tracked, NOT-newly-introduced limitation.** The
   pre-migration `ca_store.hpp` already documented this exact gap for a hypothetical HA/multi-
   instance/DB-restore scenario (#1240 UP-4) — true durable cross-instance numbering (an
   auto-retry-on-conflict republish loop spanning the CA-key-load-and-sign step) is explicitly
   OUT OF SCOPE for this migration, which ports the persistence layer, not a new HA feature nobody
   asked for here. `server.cpp`'s `publish_crl()` keeps its existing shape: `next_crl_number()`
   and `record_crl()` as two separate, short-lived leases with NO lease held across the CA-key-
   load-and-sign step in between (unchanged — the correct "never hold a lease across disk/signing
   work" shape, ADR-0012 §2) under its own process-local `crl_publish_mu_` member (unrelated to
   `CaStore::publish_next_crl`'s own, differently-scoped mutex — see below).

### `CaStore::publish_next_crl` — kept, zero production callers (verified)

Grep across the whole tree (`.cpp`/`.hpp`, excluding its own definition and test file) finds no
call site outside `ca_store.{hpp,cpp}` and `test_ca_store.cpp`. `server.cpp`'s actual production
CRL-publish path (`publish_crl()`) reimplements the same allocate→build→record shape manually,
under its OWN `crl_publish_mu_` member, calling `next_crl_number()`/`list_revoked()`/`record_crl()`
directly rather than through this method's `CrlBuilder`-callback abstraction. Kept for API/test
parity (it is unit-tested and may be a future convenience surface); internally hardened to abort
(return `nullopt`, consume nothing) on a `next_crl_number()`/`list_revoked()` read failure rather
than silently building a CRL over a wrong number or a possibly-incomplete revoked set — the same
fix class as the production path's own hardening above, applied so the untested-in-production
method does not carry a latent version of the identical bug.

### Update (2026-09-23): cross-instance CRL numbering delivered by HA WS-6 slice 6.1

Point 3 above and the "zero production callers" section are superseded. `publish_next_crl` is now
the ONLY production CRL publish path: `server.cpp`'s `publish_crl()` loads the CA key, then calls
it with a pure signing callback. `ServerImpl::crl_publish_mu_` is removed; `CaStore`'s old mutex
is replaced by a bounded `std::timed_mutex` taken before the lease, so one process parks at most
one pool connection on the lock. `record_crl()` became `record_crl_for_test()` (test seeding
only), and `next_crl_number()` is a read-only peek. The method runs one transaction that sets a
transaction-scoped `lock_timeout`/`statement_timeout` (so the bound survives a DSN whose
`options=` suppresses the pool's), takes `LOCK TABLE ca_store.ca_crl_versions IN SHARE ROW
EXCLUSIVE MODE`, re-checks `ca_root`'s fingerprint against the one the caller loaded (a
subordinate import in between returns `RootChanged`; the caller retries once), reads
`MAX(version)+1` and the revoked set on the same connection, signs, inserts and commits. The lock
serialises publishers across every replica sharing the database, so numbering is strictly
increasing with no duplicates, and a CRL never omits a revocation its predecessor carried.

**Migration v3** adds a nullable `ca_crl_versions.revoked_count` — how many revoked certs the CRL
was built from — with no backfill (NULL reads as "not covered"). `has_unpublished_revocations()`
compares it with the current revoked count in one statement, and the leader's freshness pass
republishes when they differ, so a revoke whose own publish failed reaches the CRL without a
second revoke. That comparison relies on the revoked set being append-only, so
`delete_issued_by()` now keeps revoked rows, and **migration v4** adds a `BEFORE DELETE OR
UPDATE` row trigger (`ca_issued_keep_revoked`) rejecting any change to a revoked row — the
guarantee holds against an older binary during a rolling upgrade, not just in this code — before this change, regenerating the default certs
deleted a revoked default leaf's row, which also made `is_revoked()` accept it again. The v3 DDL
runs under `SET LOCAL lock_timeout = '30s'`, and each publish also sets
`idle_in_transaction_session_timeout` so a frozen holder cannot keep the lock.

ADR-0012 §2(b) forbids holding a lease across "network, disk, or other external work". Loading
the key is disk work and happens before the lease is taken; signing a key already in memory is
in-process CPU work, so running it under the lease is not a departure from §2(b). A future
`KeyProvider` backed by a KMS, HSM or PKCS#11 would turn signing into network work under the lease
and needs a redesign (or an ADR-0012 exception) before it lands — the `CrlBuilder` "pure CPU work"
contract in `ca_store.hpp` is where that shows. Points 1 and 2 (no default number on a read
failure; no clobbering) still hold. Residual limits — point-in-time restore, async-failover commit
loss and the runbook clear of `ca_crl_versions` restart numbering at the surviving MAX+1 — are
listed in `docs/pki-architecture.md`. See ADR-2002 §8 "Update (2026-09-23)".

### Backfill (ADR-0009)

**Mandatory, three-table, fingerprint-verified** — extends `LicenseStore`'s (ADR-0048) two-table
canonicalization design to three: `ca_root`, `ca_issued`, `ca_crl_versions`. All three are created
together, atomically, by the pre-migration SQLite `CaStore`'s v1 migration — no version of the
shipped binary can produce a legacy file holding some-but-not-all of the three, so that shape
fails the whole backfill closed (the same corrupt/hand-edited-file bias as an unrecognised enum
value).

- **`ca_root` (0-or-1 row, singleton):** ALL-IDENTITY, per the kickoff's explicit classification —
  any mismatch against an already-established row fails the backfill closed. The insert uses the
  SAME `ON CONFLICT (id) DO NOTHING`-then-readback-and-compare shape as `try_insert_root()`, so it
  is race-safe against a concurrent `try_insert_root()` caller or a concurrent sibling backfill by
  construction (whichever INSERT lands first wins; everyone else reads back that row).
- **`ca_issued`:** IDENTITY (`subject`, `san`, `purpose`, `not_after`, `issued_at`, `issued_by`,
  `enrollment_request_id`, `cert_pem`, `issuer_fingerprint`, `issuer_key_id` — write-once at
  `record_issued()`, no other method mutates them) vs LIFECYCLE (`status`, `revocation_reason`,
  `revoked_at` — mutated only by `revoke()`). Direction resolved by a `cert_status_rank`
  (`active`=0 < `revoked`=1 terminal < unrecognised=2, rejected before ever reaching Postgres):
  Postgres strictly ahead (already revoked; the legacy snapshot predates it) is a benign
  WARNING-logged no-op, keeping Postgres's revoked state; **legacy strictly ahead, or both
  revoked but disagreeing on `revocation_reason`/`revoked_at`, fails the boot closed** — the
  kickoff's explicit instruction, verbatim: *"revoked-in-legacy/active-in-PG fails closed, never
  un-revoke."*
- **`ca_crl_versions`:** `version` is the natural conflict key. Byte-identical `der` at the same
  version is a benign no-op (the same CRL, backfilled twice); a DIFFERENT `der` under the SAME
  version is an RFC 5280 crlNumber fork and fails the boot closed — never silently pick a side.
- Every legacy `status` value is validated against the known enum set BEFORE it can reach
  Postgres (mirrors `LicenseStore`'s precedent for the identical class of exposure).
- Legacy files are read READ-ONLY and never deleted/moved — retained for the ADR-0009
  one-release rollback window.

### Observability

Three counters cover this store's failure/security-relevant surfaces, all boot-pre-seeded to 0 so
`increase(...) > 0` catches even the first occurrence rather than the series being entirely
absent from `/metrics` until it first fires: `yuzu_server_ca_crl_publish_failures_total`,
`yuzu_server_ca_reissue_blocked_total{reason="revoked_identity"}` (a revoked identity attempting
to re-provision — the control working as intended, not a failure, but worth an operator's
attention), and `yuzu_server_ca_revocation_sweep_read_failures_total`. A dedicated `yuzu-pki`
Prometheus alert group (`docs/prometheus/yuzu-alerts.yml`) covers all three
(`YuzuCaCrlPublishFailing`, `YuzuCaRevocationSweepReadFailing`, `YuzuCaReissueBlocked`). The
bootstrap advisory lock's connection-pool floor (effectively 2 even at the smallest deployment
size — the outer critical-section lease and its own nested per-call leases share one pool) is
documented in `server-admin.md`'s "Connection-pool sizing" section.

### `/readyz` / `/healthz`

Unchanged wiring — `has_root()` (now the fail-soft convenience, not the B-2 gate) already feeds
the existing `/readyz` `ca_root` signal (`server.cpp`); `is_open()` already joins the standard
store conjunction. No new wiring needed; the existing signal now correctly reflects a genuine
Postgres read failure as "unhealthy" rather than the pre-migration file-open check.

### Upgrade-test coverage — known gap, not unique to this store

`scripts/test/test-upgrade-stack.sh` carries exactly one store-specific data-survival assertion
(the original ADR-0009 generic-inventory pilot, `git log` shows no other touch to this file or
`test-fixtures-verify.sh`). None of the sibling Wave 2/3 migrations that followed it — LicenseStore
(ADR-0048), DeploymentStore, SoftwareDeploymentStore (ADR-0051) — added their own dedicated
previous-release-SQLite → new-release-Postgres assertion either; each relies on the harness's
generic `fixtures-verify` pass (asserts overall server health/migration success post-upgrade, not
per-store content). This migration follows that same precedent rather than being the first to
diverge from it: CA issued-cert + CRL history backfill is exercised by `test_ca_store.cpp`'s
dedicated `migrate_from_sqlite` suite (real legacy-schema fixtures, fingerprint verification,
idempotent-rerun) but not by the end-to-end upgrade harness. Closing this gap — for CaStore and
its siblings alike — is tracked as a follow-up on `docs/postgres-migration-ladder.md`, not solved
here.

## Considered and rejected

- **Folding `has_root()` entirely into `get_root()` and updating every call site to the typed
  form.** Rejected as unnecessary churn: the two remaining `has_root()` callers (a background
  sweep tick, `/readyz`) are demonstrably safe with a degraded-collapses-to-false read, and
  forcing them onto the richer type would add call-site verbosity with no behavioral benefit.
  Keeping `has_root()` as a documented, narrow convenience — with an explicit doc-comment warning
  against using it for a security-relevant gate — was judged clearer than either extreme
  (blanket-typed everywhere, or blanket-bool everywhere). That doc-comment warning existed from
  this migration's first commit; it just did not stop the author from missing one of its own
  call sites (see "Adversarial review" below) — a warning comment narrows the class of mistake, it
  does not substitute for checking every call site against it.
- **Solving cross-instance CRL numbering (auto-retry-on-conflict) as part of this migration.**
  (Since delivered by HA WS-6 slice 6.1 with a table lock rather than a retry loop — see "Update
  (2026-09-23)" above.) Rejected as scope creep beyond "migrate the persistence layer" — it is a pre-existing, already-
  tracked (#1240 UP-4) limitation this migration does not worsen (a collision was always refused
  loudly, never silently), and building the retry loop correctly requires re-running the CA-key-
  load-and-sign step, which crosses into `server.cpp`'s signing orchestration, not this store.
- **A single shared `kCaDuplicateSerialPrefix`/`kCaDbErrorPrefix` reused from another store's
  constants.** Rejected per the established Wave 2/3 precedent (ADR-0048's "Considered and
  rejected"): each store's error-prefix constants stay local so a future rename of one cannot
  silently affect another.

## Review History

This is a compact provenance record — what ran, what it found, what happened to it. Current
design truth lives in `## Decision` above, not here. Full structured findings (trigger/impact/
exposure/epistemic-status per this repo's derivation scheme, plus provenance and disposition) are
in the committed ledger: `governance.d/ca-store-postgres-migration.Hq3Wpm.jsonl` (53 findings,
15 review passes). Resource-ownership detail for the bootstrap-lock/first-boot-key custody
chain — a policy-floor artifact independent of this history, not process narrative — lives in its
own durable file: `docs/resource-ledgers/default-certs-bootstrap-lock.md`.

| # | Pass | Reviewers | Findings | What stood out |
|---|---|---|---|---|
| 1 | Adversarial review | Kimi K2.7 + Codex GPT-5.5 (external, independent, each compiling + running the real suite) | 1 HIGH fixed, 1 MEDIUM fixed, 1 LOW deferred (pre-existing) | Both models independently found the boot-time `has_root()`/`get_root()` regression before cross-examining each other — the strongest finding class this process produces |
| 2 | Gate 3 (domain-triggered) | architect, cpp-expert, cpp-safety, quality-engineer | 1 HIGH fixed, 2 SHOULD fixed, 3 deferred (bounded) | The unscoped inventory-purge race — a distinct first-boot defect the adversarial round missed |
| 3 | Gate 4 | happy-path, unhappy-path, consistency-auditor | 2 HIGH fixed, 1 SHOULD documented, 1 NICE deferred | UP-1 (sweep fail-closed-amplification, a false compliance record); UP-2 (a crash-recovery gap Gate 3's fix widened — superseded by pass 4) |
| 4 | Gate 8, round 1 | security-guardian + unhappy-path | 2 HIGH fixed, 1 NICE fixed | Both independently found UP-2's own self-heal fix had a concurrency gap — a static ownership proof, not a claim/CAS |
| 5 | Gate 8, cpp-safety domain re-review | cpp-safety | 1 SHOULD documented, 2 NICE fixed | The bootstrap lock's own pool-size floor |
| 6 | Gate 8, narrow closure re-verify | security-guardian + unhappy-path (independent re-reads, not the diff) | 1 NICE fixed | Confirmed pass 4's findings CLOSED — only the reporting domain signs off its own finding |
| 7 | Gate 5/6 | chaos-injector, compliance-officer, sre, enterprise-readiness, docs-writer, architect | 1 HIGH fixed, 1 MEDIUM documented, 3 SHOULD fixed, 4 SHOULD deferred, 4 NICE (mixed) | C5-1: a fencing-token gap in pass 4's own lock fix — lock-holding *connection* could die without the *process* dying |
| 8 | cpp-safety + security-guardian re-review of C5-1 fix | cpp-safety, security-guardian | 2 policy floors fixed, 1 NICE deferred (pre-existing) | A `const_cast`-then-write UB (cpp-safety's enumerated floor) + a missing Resource Ledger |
| 9 | cpp-expert gap-fill | cpp-expert | 3 NICE fixed | First review of the fix-round commits — routed-concerns' trigger is unconditional on any C++ change, this coverage cell had been empty |
| 10 | Post-governance follow-up (operator-directed) | claude, self-found | 1 SHOULD fixed | Two more metrics with CAPG-022's missing-boot-seed gap, same code region |
| 11 | UP-3 build (operator-directed) | claude, self-found | 1 HIGH/BLOCKING fixed (pre-existing) | The key-clobbering race: 7/8 pre-fix repro runs red, 0/15 post-fix |
| 12 | cpp-safety + security-guardian re-review of UP-3 fix | cpp-safety, security-guardian | 1 SHOULD, 1 policy floor fixed, 1 MEDIUM documented | Restructuring this round deleted the committed Resource Ledger with no replacement — floor, caught pre-push |
| 13 | cpp-safety closure re-verify | cpp-safety | 2 SHOULD fixed | Retry-guard presence-vs-count masking risk; unspecified-on-false output-parameter contract |
| 14 | Operator re-derivation, routed-concern catch-up | security-guardian, cpp-expert, docs-writer, cpp-safety | 1 SHOULD, 2 NICE fixed, 1 INFO deferred | Pass 13 itself had gone unrecorded — the gap this section exists to close |
| 15 | Re-verify of #3475's CI-flake fix (routed-concern) | cpp-safety | 1 NICE fixed | "each racer's" overstated it — one hits a primed pool connection |

**Notable process findings, not product findings.** Three overclaims caught and retracted
**before** being used as sign-off evidence — compliance-officer evaluated this as evidence of a
sound review process: (1) a regression test cited as closure for pass 4 didn't reliably reproduce
the pre-fix corruption (60 runs in a throwaway worktree; reframed onto the lock's ordering proof);
(2) a log line claimed "this instance provably minted it" after the nearby comment had already
been corrected away from that claim; (3) a Gate 8 finding asserted `upgrading.md` describes
multi-replica HA as supported, contradicting this ADR's own Decision section.

**Post-governance follow-up (operator-directed).** Two items sre's Gate 6 pass deferred (CA
metrics alert rules, the bootstrap lock's pool-size floor in the capacity doc) were fixed rather
than filed as issues — see "Observability" above.

**UP-3 (self-heal without a restart) and a pre-existing defect it surfaced.**
Consistency-auditor's Gate 4 pass deferred UP-3 as a larger, separately-scoped change; built here
on operator request. A losing racer now polls the shared cert directory for the winner's complete
set for up to 15s before falling back to the original refuse-and-restart behavior (see "Self-heal
and the bootstrap advisory lock" above). Building it surfaced an independent, pre-existing defect:
every first-boot candidate wrote its CA private key speculatively to the shared well-known
`default-ca.key` path *before* racing `try_insert_root`'s CAS, so whichever candidate's write
landed last silently detached the established root from its real private key regardless of which
candidate won — permanently defeating every future self-heal attempt for that root. Verified
empirically: a 6-racer test against one shared `TempDir` reproduced this on 7 of 8 runs before the
fix, 0 of 15 after. Fixed: the CA key is now written to disk only after a candidate is confirmed
the CAS's sole winner; `key_ref` itself is computed beforehand (a pure path calculation, no I/O).
Recorded as CAPG-043, pass 11, HIGH/BLOCKING (I1+I2, E4+E5), fixed.

**Pass 12 — cpp-safety + security-guardian domain re-review of this fix (2026-08-21).** One SHOULD
fixed (the poll loop now cross-checks the fingerprint of what it just validated, true by
construction but unasserted). One BLOCKING policy-floor fixed — this round's ADR restructuring had
deleted the bootstrap-lock chain's committed Resource Ledger with no replacement; moved to
`docs/resource-ledgers/default-certs-bootstrap-lock.md`, extended with this pass's own resource.
One MEDIUM documented, not fixed (sibling-refusal window; see that file). Findings:
`governance.d/ca-store-postgres-migration.Hq3Wpm.jsonl` pass 12.

**Pass 13 — cpp-safety closure re-verify.** Two SHOULD fixed: the racing-boot test's mixed-failure
retry guard checked presence, not count, of the known CAPG-042 refusal log line (could mask a
coincidental unrelated failure); the fingerprint-mismatch branch could leave `out` populated with
a validated-but-wrong-root set on the poll-timeout path — unreachable today, reset defensively and
documented anyway.

**Pass 14 — routed-concern catch-up, prompted by an operator re-derivation** ("has necessary
governance been run?"). `default_certs.{hpp,cpp}` unconditionally triggers security-guardian/
cpp-safety/docs-writer, and cpp-expert on any C++ change — neither pass 12's nor 13's fix commit
had run all four. All four PASS; docs-writer found pass 13 itself had gone unrecorded, fixed above.

**Self-caught, not a review finding: the new UP-3 test was itself scheduling-dependent.** A
subsequent full 10-shard suite run hit a legitimate, non-buggy scheduling outcome the test's
log-evidence assertions weren't tolerant of — all six racers' `get_root()` checks landed after
the winner had already committed, so all six correctly took the pre-existing UP-2 path and none
exercised this fix's new branch, failing `REQUIRE(logs.find("lost the first-boot CA-root
race")...)`. Not weakened (a soft check trades "sometimes red for a good reason" for "always
green regardless of whether it verifies anything," worse than an occasional red); instead
wrapped in a bounded retry of the whole scenario (fresh directory and store each attempt, up to 15
as of PR #3475's CI-flake fix, widened from 5), mirroring `test_mcp_stream_bridge.cpp`'s `#3357`
"quiesce before the experiment" shape — exceeding the bound is still a hard `REQUIRE` failure,
never a silent pass. A `std::latch` start-barrier was tried alongside the widened bound and
reverted — measured WORSE locally (13/15 failures): `PgPool` connects lazily, so a racer's real
work happens well after any barrier releases (pass 15 re-verify, table below).

## Consequences

- Every CA read/write now surfaces a genuine database error to its REST/MCP/dashboard caller as a
  503/`kInternalError`/error-panel instead of a silently-empty/-false SQLite-mutex-guarded result,
  EXCEPT `is_revoked()`, which deliberately keeps its bool/fail-closed-to-`true` shape by design
  (see above) — this is a live behavioral change for every already-wired CA surface, unlike
  `LicenseStore`'s dormant-store precedent.
- The first-boot CA-root race is now handled correctly for the first time — under SQLite it was
  structurally impossible (each instance had its own file), so there was never a "correct"
  behavior to preserve; this migration is establishing new, tested behavior, not porting existing
  behavior.
- `CaStore` moves from "SQLite, single-connection-mutex-serialized" to "Postgres, pool-concurrent"
  — matches every other migrated store's concurrency model.
- The legacy `ca.db` is retained for one release (ADR-0009 rollback window), then removed per the
  standard cadence.
- `#1276`'s flake lead is narrowed (see "Write-path failure classification" above) but not closed
  — a genuine production serial collision remains believed-negligible given random 128-bit
  serials, and this migration adds the typed-retry infrastructure without asserting the flake's
  root cause is fully diagnosed.

## Update (2026-09-03) — `migrate_from_sqlite()` retired

**Supersedes the "retained for one release" sentence above.** ADR-0009's fresh-start-by-default
amendment (2026-08-25) establishes that no production Yuzu fleet has ever run a pre-Postgres
build of any store — the mandatory, three-table, fingerprint-verified backfill this ADR designed
was real, working code that never had real legacy data to protect.

`CaStore::migrate_from_sqlite()` and its private helpers/types (`LegacyRootRow`, `LegacyIssuedRow`,
`LegacyCrlRow`, `sha256_hex`, `append_field`, `canonicalize_legacy`, `sqlite_table_exists`,
`safe`, `kSourcelessFingerprint`) are removed (`chore/retire-migrate-from-sqlite-batch-a`,
tracking issue #3623). `sqlite_backfill_source` — whose entire purpose was the backfill
idempotency marker — is dropped via a version-bumped `{2, "DROP TABLE IF EXISTS
sqlite_backfill_source;"}` migration, appended after the already-shipped v1 rather than editing
it in place: this store IS constructed in production, so v1 has actually run against real
dev/UAT databases. `server.cpp`'s boot path now runs `legacy_sqlite_probe::warn_if_legacy_rows`
over `ca_root`/`ca_issued`/`ca_crl_versions` instead of the backfill — WARN-only (never
refuse-boot) on a real legacy row found, same posture as every other store in this retirement
batch; the issued-cert/CRL evidence-chain concern the original mandatory backfill protected
against a real installation never having existed to trigger it.
