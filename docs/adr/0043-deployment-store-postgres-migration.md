---
status: accepted
date: 2026-08-12
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 2 migration worker, following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 2)
scope: server — `DeploymentStore` (operator-initiated ad-hoc deployment jobs, Issue 7.7), its
  cutover from SQLite to PostgreSQL, and its ADR-0009 backfill
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract)
related: docs/postgres-migration-ladder.md (Wave 2 -> Done); docs/adr/0036-result-set-store-postgres-migration.md
  (the authoritative-with-backfill template this migration follows)
---

# 0043 — `DeploymentStore` Postgres migration (authoritative, with backfill)

## Context

`DeploymentStore` (`server/core/src/deployment_store.{hpp,cpp}`) persists operator-initiated
ad-hoc deployment jobs — SSH / group-policy / manual agent installs (Issue 7.7). It is a Wave 2
store on `docs/postgres-migration-ladder.md`. It was previously a SQLite store
(`deployment-jobs.db`, table `deployment_jobs`) guarded by a single `shared_mutex`.

**Naming trap:** `DeploymentStore` is a different, older concept from `DeploymentRunStore` (the
`/auto` Deploy feature's stage->execute state machine, schema `deployment_run_store`, already
Born-on-PG). Same English word, unrelated stores — this ADR does not touch
`deployment_run_store.*`/`deployment_engine.*`.

## Decision

**Migrate `DeploymentStore` to PostgreSQL as schema `deployment_store`, table `deployment_jobs`,
with a standard ADR-0009 first-boot backfill.**

### Schema

- Schema name `deployment_store` (ADR-0008 Update naming rule: `snake_case(FullClassName)`
  including the `Store` suffix).
- `deployment_jobs` carries the existing columns unchanged in meaning and type mapping
  (`TEXT`→`TEXT`, `INTEGER` epoch-seconds columns→`BIGINT`). No foreign keys, no constraint
  changes.
- `id` stays a **client-generated `TEXT` primary key** (`DeploymentStore::generate_id()` — a
  64-bit `mt19937_64` value formatted as 16 hex chars, mirrors
  `AccessReviewStore::generate_campaign_id`). Deliberately NOT switched to a Postgres-generated
  identity column — that would change the ID format/contract for any existing caller
  (`/api/deployment-jobs/:id`'s route regex is anchored on `[a-f0-9]+`).
- A new table, `sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT
  NULL)`, is the backfill idempotency tracker (see Backfill below) — not part of the application
  data model.
- No secrets. Every column is plain application data (hostnames, OS/method enums, status,
  timestamps, an operator- or agent-supplied error string) — no `SecretCodec` involvement.

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime:

- **Construction fails closed**, same template as every other Postgres-backed store: a schema
  that cannot migrate/open sets `startup_failed_` in `server.cpp`.
- **The database IS the source of truth for deployment-job state.** There is no in-memory
  authoritative layer above this store. A silently-empty `list_jobs` would read as "no
  deployments ever ran"; a silently-`false` `update_status`/`cancel_job` would let an operator
  believe a state change landed when it didn't. Both are correctness failures, not merely
  durability ones, so every reader/mutator returns `std::expected<..., std::string>` — a DB
  error is never papered over as an empty/not-found result (playbook "Authoritative reads must
  be type-distinguishable"). `get_job` in particular returns
  `std::expected<std::optional<DeploymentJob>, std::string>`: `nullopt` is a successful read of
  zero rows, `unexpected` is a genuine failure — the two REST call sites in
  `discovery_routes.cpp` were updated accordingly (503 on `unexpected`, 404 only on `nullopt`;
  previously a DB blip on the SQLite path silently read as 404).
- Every genuine DB/lease failure across all five store methods is prefixed `db_error: `
  (`kDbErrorPrefix`) -- a machine-checkable idiom mirroring `AccessReviewStore`'s `not_found: `
  convention (`rest_api_v1.cpp`'s `access_review_error_status`) -- so `discovery_routes.cpp` can
  classify a route's `unexpected` as 503 (DB outage) vs 400/404 (validation/business rule)
  without pattern-matching ad hoc message text. Hardening-round fix (adversarial review,
  2026-08-12): the initial cut only fixed the two READ routes; `create_job`/`cancel_job`
  collapsed every failure -- including a genuine Postgres outage -- to 400 until Kimi and Codex
  both independently found this and it was closed the same round.
- `cancel_job` mutates via a single guarded `UPDATE ... WHERE status IN ('pending','running')`
  rather than a check-then-write pair, so it stays race-safe against a concurrent second
  cancel/status-update without the SQLite version's `shared_mutex`. The zero-rows-matched
  follow-up read that distinguishes "not found" from "wrong state" for the error message is
  best-effort under concurrency (a race there can only change which message is reported, never
  the mutation's correctness).

### Backfill (ADR-0009)

**Mandatory** — an in-flight or completed deployment job is real, irreducible operator intent
(matches the ladder's Wave 2 framing: "operator state that cannot be lost").

**Content-fingerprinted, not a single fleet-wide completion flag** (revised in an
adversarial-review hardening round, 2026-08-12 -- Kimi and Codex both independently found, then
jointly confirmed under cross-examination after Kimi initially missed it, that the ORIGINAL
single-row `sqlite_backfill` marker violated the playbook's "Local source absence never creates
terminal migration state on its own" rule: a fileless replica's "nothing to backfill" stamp
would permanently wave through a DIFFERENT, holder replica's real legacy data on its next boot,
because the marker's `SELECT 1 ... LIMIT 1` short-circuit didn't care WHICH replica set it or
why). The shipped design instead tracks completion PER DISTINCT LEGACY-FILE CONTENT in
`sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT)`:

- A replica with no local legacy file (or a present-but-schema-less one) computes and stamps a
  `sourceless` sentinel fingerprint.
- A replica holding real rows computes a SHA-256 fingerprint of a canonicalized, sorted
  serialization of ITS OWN rows and checks/stamps THAT specific value.
- A holder's real fingerprint is a different primary-key value than `sourceless` and can never be
  satisfied by another replica's sourceless stamp, so it always proceeds to copy its own data --
  the anti-pattern is closed structurally, not by re-ordering two checks.
- The mid-scan-corruption guard is unchanged in shape: the terminal SQLite step code must be
  `SQLITE_DONE`, not merely "loop exited", so a corrupt page never gets silently treated as an
  empty table and fingerprinted/stamped. This check now runs BEFORE any Postgres round trip at
  all (fingerprinting happens client-side, before the completion lookup), so a corrupt file can
  never even reach the fingerprint check.
- Legacy files are read READ-ONLY and never deleted/moved -- retained for the ADR-0009
  one-release rollback window (matches `ResultSetStore`'s choice, not `RbacStore`'s move-aside).
- `server.cpp` treats a backfill failure exactly like a migration/open failure -- fatal,
  `startup_failed_`, never a serve-degraded state.

**Deliberately simpler than `RbacStore`'s post-#2703 reference shape** (refuse on ANY column
mismatch — the operator-recovery runbook this historically pointed to, `rbac-store-backfill-recovery.md`,
was retired along with `RbacStore::migrate_from_sqlite()` itself, #3623): that complexity exists
there because RBAC identifiers (role/group names) are small and human-chosen, so two independently-
authored grants can legitimately collide on name and both need operator adjudication.
`DeploymentStore`'s `id` is a 64-bit random surrogate key (`generate_id()`) — outside an
astronomical id collision (the rare case the IDENTITY branch below exists to catch), a shared id
is always the SAME logical job observed twice: via a replica re-reading its own already-migrated
file, or via a data directory that was cloned or restored to provision a second replica and then
diverged. This is a deliberate, documented divergence from the reference shape (playbook: "copy
the SHAPE... record which way you went"), not an oversight.

**Per-row conflict handling.** The backfill insert (`INSERT ... ON CONFLICT (id) DO NOTHING
RETURNING id`) checks `PQntuples()`, not merely `PGRES_COMMAND_OK` — proving a statement executed
is not proof this row won the conflict (the anti-pattern `docs/postgres-store-playbook.md`'s
"Anti-patterns reviewers reject" section documents; `AuditStore::stamp_complete`, ADR-0040, #2697,
is the worked example that motivated the rule). On a conflict, the existing row is read back and
compared against the legacy row in two classes, because they behave differently once a row has
been migrated once:

- **Identity** (`target_host`, `os`, `method`, `created_at`) is set once at INSERT and never
  mutated afterward — `update_status`/`cancel_job` touch only the lifecycle columns below. A
  conflicting row whose identity differs is therefore provably outside this store's model
  (corruption, a hand-edited legacy file, or an astronomical id collision), and the whole backfill
  transaction fails closed with a message naming both the stored and legacy identity values.
- **Lifecycle** (`status`, `started_at`, `completed_at`, `error`) legitimately changes
  post-migration via live traffic on whichever replica migrated the row first. Which side is
  AHEAD decides the outcome, using the status enum's natural order
  (`pending < running < {completed, failed, cancelled}`, the three terminal states tied at the
  same rank): if Postgres's status is strictly ahead of the legacy row, or the two sides are tied
  at the SAME status — a legacy snapshot predating progress already live in Postgres — this is a
  benign no-op; Postgres's value is kept and the drift is WARNING-logged (naming all four
  lifecycle values on both sides) so it stays visible without blocking the boot. Two directions
  fail the whole backfill transaction closed instead, the same as an identity mismatch: the LEGACY
  row is strictly ahead of Postgres (see Finding A below), or the two sides are tied at rank but
  report DIFFERENT terminal statuses — e.g. one `completed`, the other `failed` — since rank alone
  can't order two disagreeing final outcomes (see Finding UP-E below).

This still does not need `RbacStore`'s refuse-on-mismatch COMPLEXITY (no operator-adjudicated
"which value is right" branch for the ordinary case) — but it does need the underlying discipline
the playbook already names as universal ("a 'first writer wins' contract... needs
`PQcmdTuples()`... or `RETURNING` + `PQntuples()`"), which is now applied consistently to both the
per-row insert and the marker insert (an identical marker fingerprint is proof two writers
legitimately agree on content; a `DO NOTHING` conflict there was already a genuine no-op).

The SQL shape here (plain `DO NOTHING` + a separate read-back `SELECT` + an application-level
comparison) deliberately diverges from the playbook's `DO UPDATE ... WHERE <condition> RETURNING`
recipe for "two writers can legitimately agree on identical content": backfill-vs-backfill is
lock-safe (Postgres blocks the conflicting `INSERT` until the winner commits), so the only live
race window is against an already-serving sibling's normal traffic on that exact row between the
failed insert and the read-back — and since IDENTITY columns are write-once (never touched by
that traffic), the race can only ever perturb what the read-back sees among the LIFECYCLE columns,
never fabricate an identity mismatch. Worst case is therefore a stale lifecycle comparison
resolved by the direction check above, never silent data loss, so the simpler two-statement shape
was kept over the atomic recipe (playbook: "record which way you went").

**Finding A (gov unhappy-path, hardening round 4): the direct structural counterpart of the
lifecycle fix, in the opposite direction.** ADR-0009's rollback-then-roll-forward window means the
pre-migration SQLite-only binary can run again after a rollback and genuinely progress a job's
lifecycle further than Postgres ever saw (Postgres isn't written to while rolled back). Silently
keeping Postgres's less-advanced value on roll-forward — as "same identity, different lifecycle is
always benign" would suggest — would discard that real progress with only a WARNING log as
evidence, inside a legacy-file retention window that itself expires after one release. Fixed:
the direction check treats a legacy row ranked strictly ahead of Postgres's current value as
the suspicious case and fails the boot closed, same remediation shape as an identity mismatch.

**Finding UP-E / cpp-expert Finding 1 (hardening round 5): a same-rank divergence among the three
terminal states was initially left as the benign, Postgres-wins case** — accepted in the paragraph
above as a narrow edge case matching this store's general "trust the live value" posture. That
acceptance did not survive review: `completed` vs. `failed` vs. `cancelled` genuinely disagreeing
about which terminal outcome occurred is not "who's further along" (rank has no opinion between
tied values), it's a contradiction about what actually happened, produced by the exact same
rollback mechanism Finding A's fix already treats as real. Two independent reviewers (cpp-expert,
unhappy-path) found this in the same round. Fixed: a same-rank, different-status pair between the
terminal states now fails the boot closed too, alongside the strictly-ahead case above — a
same-status tie (differing only by timestamp or error text) remains the benign no-op it always
was.

**Finding UP-F (hardening round 5): the shared fail-closed remediation message gave backwards
guidance for the new legacy-ahead/terminal-disagreement cases.** It read "inspect/fix the
referenced row in the retained read-only legacy file" for every failure class — written when every
reachable failure had the legacy file as the plausible suspect. Finding A's fix inverted that for
its own case: `failure_detail` there names Postgres as the stale/contradicted side. An operator
following the old wrapper text literally could edit the legacy file to match Postgres, destroying
the only evidence of what the pre-migration binary actually did — laundered through the exact
remediation path the message recommended.

**Finding UP-H (hardening round 5, verification pass): the first UP-F fix over-generalized — it
still unconditionally pointed at "the guidance above," but only 2 of the 5 failure branches
(identity mismatch, legacy-ahead/terminal-disagreement) actually embed row-vs-row content in
`failure_detail`.** The 3 genuine DB-error branches (insert failure, read-back failure,
marker-stamp failure) carry only a raw Postgres error — nothing to "compare against Postgres's
current row" for, and the marker-stamp case doesn't even name a row id. Fixed: a
`row_conflict_guidance` flag, set only in the two branches that actually carry side-specific
guidance, now selects between two remediation texts — the row-comparison guidance where it applies,
and a plain "this is a database or legacy-file-read failure, resolve the underlying error and
restart" text everywhere else. Re-derived severity: the reviewer's own native label was SHOULD, but
the recorded facts (confusing-but-honest guidance, no destructive action implied, distinct from
UP-F's directly-harmful instruction) derive LOW/NICE per the standard rubric — recorded as a
disagreement between native and derived severity rather than silently accepting either label.

**Finding DW-8 (hardening round 5): the legacy file's `status` column was read with no
validation.** `create_job`/`update_status` both reject anything outside the 5 known status values
before it reaches Postgres — but the legacy-file read loop in `migrate_from_sqlite` didn't, so a
hand-edited or corrupted legacy file's garbage status could land in Postgres on a row's first
(non-conflicting) insert. Because `lifecycle_rank`'s unrecognised-value fallback is already
maximal, a corrupted stored value could then never be seen as "behind" any future legitimate
legacy row, permanently masking the corruption as benign. Fixed: the legacy-read loop now
validates each row's status against `lifecycle_rank`'s own maximal-fallback sentinel before it can
reach Postgres at all, before any Postgres round trip — the same fail-closed-before-Postgres
posture the mid-scan-corruption guard already uses.

`canonicalize_legacy_jobs`'s field serialization uses length-prefixed fields
(`<byte-length>:<bytes>`, the standard netstring/bencode technique) rather than raw `\x1f`/`\x1e`
delimiter bytes: a delimiter byte inside a field's own content could shift a row's apparent field
boundary enough to make two DIFFERENT row sets hash identically, which the length-prefixed
encoding closes structurally (verified by a dedicated shifted-field-boundary regression test).

**Hardening history:** this design went through five review rounds before landing — an
adversarial PR review (fjarvis: Kimi+Codex) found the missing `PQntuples()` check above; a Gate 8
re-review (security-guardian+docs-writer) found the first fix over-corrected to fail closed on
ANY conflict, including a benign identical re-encounter; a second Gate 8 re-review (unhappy-path)
found that fix in turn still failed closed on ordinary lifecycle progress in a legitimate
multi-replica boot sequence, which is what the identity/lifecycle partition resolved; a third
Gate 8 re-review (unhappy-path again) found that partition was itself directionless — Finding A
above — which the status-order direction check resolves; a fourth Gate 8 re-review (cpp-expert,
cpp-safety, unhappy-path, docs-writer, consistency-auditor) found the direction check's own gaps —
Findings UP-E, UP-F, and DW-8 above — which the terminal-disagreement check, the corrected
remediation message, and the legacy-status validation resolve respectively; a same-round
verification pass (the same four reviewers re-checking their own findings' fixes) found one more
refinement — Finding UP-H above — and one stale ADR paragraph (this section's own UP-F
description, corrected in place rather than recorded as a further stacked round). Each round is
recorded in its governance ledger fragment (`governance.d/deployment-store-pg*.jsonl`); this section states
only the design that shipped.

**Trade-off accepted:** unlike `RbacStore` (which stats the legacy path cheaply before touching
Postgres, and skips entirely once the file is moved aside post-migration), this design reads the
local legacy file on every boot for as long as it remains in place, because "already migrated" is
now a content-addressed question that can only be answered by hashing the content. Accepted as
negligible here -- the file is small (ad hoc deployment jobs, not a high-volume table) and boots
are infrequent.

## Considered and rejected

- **Switching `id` to a Postgres `SERIAL`/`IDENTITY` column.** Rejected — see Schema above; would
  break the REST route's id format contract for no benefit (uniqueness is already adequate via
  the 64-bit RNG surrogate key).
- **`cancel_job` as an explicit `SELECT ... FOR UPDATE` + `UPDATE` transaction** (to make the
  not-found-vs-wrong-state error message race-free too, not just the mutation). Rejected as
  disproportionate: this is a low-frequency, operator-driven action (a human cancelling one job),
  not a security invariant — the single guarded `UPDATE` already makes the state transition
  itself correct under concurrency, and a mis-attributed error message under a genuine
  concurrent-write race is a cosmetic edge case, not a correctness one.
- **Wiring `deployment_store_` into `/readyz`/`/healthz`.** Initially deferred (see git history)
  with the rationale that sibling Phase-7 SQLite stores (`DirectorySync`, `PatchManager`,
  `DiscoveryStore`) aren't wired into either conjunction either. **Reversed in the governance
  Gate 3 sre review**: that comparison was to the wrong reference class — those three are
  pre-migration SQLite stores that predate the readyz-wiring discipline entirely, not evidence
  that omission is normal for a migrated Postgres store. Every OTHER migrated authoritative
  store on this ladder (`rbac_store`, `result_set_store`, `access_review_store`,
  `mgmt_group_store`, `api_token_store`, `engine_principal_store`, ...) IS wired into both.
  `DeploymentStore` was the sole exception. sre also verified `open_` is set exactly once
  (constructor success) with no runtime path that ever flips it back to `false`, so wiring it in
  carries zero risk of a spurious readyz/healthz flip — it is now wired into both, for parity and
  to stop this store being cited as precedent for a future genuinely-regressable one.
- **Fixing the pre-existing, dead `deployment_discovery_routes.inc` fragment's stale API calls
  in this PR.** Kimi's [DS-3]/Codex's [C-PG-004] (both LOW) found that this orphaned file --
  superseded by `discovery_routes.cpp` before this migration started, retained only as a fixture
  for `test_body_cap_route_inventory.cpp`'s route-inventory scan, never `#include`d or built
  (verified: `rg -n "deployment_discovery_routes"` finds no include/meson entry) -- still calls
  `DeploymentStore`'s pre-migration signatures and would fail to compile if ever resurrected.
  Deferred rather than fixed here: the file predates this migration and isn't part of its diff;
  fixing it is unrelated scope creep against the "small changes, small files" standing rule.
  Tracked as a follow-up issue instead.

## Consequences

- Every deployment-job read/write now surfaces a genuine database error to its REST caller as a
  503 instead of a silently-empty/-false SQLite-mutex-guarded result — an operator sees "service
  unavailable" instead of a misleading "no jobs"/404/generic 400 on a transient database blip.
  (Initially true only for the two read routes; the two write routes were fixed to match in the
  2026-08-12 hardening round -- see Posture above.)
- The legacy `deployment-jobs.db` is retained for one release (ADR-0009 rollback window), then
  removed per the standard cadence.
- `DeploymentStore` moves from "SQLite, mutex-serialized" to "Postgres, pool-concurrent" —
  matches every other migrated store's concurrency model; no separate follow-up needed.
- A fileless replica can never permanently block a holder replica's real deployment-job history
  from reaching Postgres (the HIGH finding this ADR's Backfill section documents closing) --
  verified by the empirical fix, not just by design review: `tests/unit/server/test_deployment_
  store.cpp`'s backfill test suite covers the sourceless/real/idempotent/mid-scan-corruption
  cases against a live Postgres instance.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes a blanket
program-wide fact this ADR's backfill design predates: no production Yuzu fleet has
ever run a pre-Postgres build of any store. The fingerprint-verified,
IDENTITY/LIFECYCLE-partitioned backfill this ADR designed (and later stores
copied — DeploymentStore is the "DeploymentStore/TagStore shape" cited across the
ladder) was real, working code — but it never had real legacy data to protect.

`DeploymentStore::migrate_from_sqlite()` and its private helpers (`sha256_hex`,
`append_field`, `lifecycle_rank`, `canonicalize_legacy_jobs`, `safe`) are removed
(`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623). `sqlite_backfill_source`
is dropped via a version-bumped `{2, "DROP TABLE IF EXISTS sqlite_backfill_source;"}`
migration, not edited into v1 — this store IS constructed in production, so v1 has
actually run against real dev/UAT databases. `server.cpp`'s boot path now runs
`legacy_sqlite_probe::warn_if_legacy_rows` over `deployment_jobs` instead — silent
unless real rows are found, never blocks boot.
