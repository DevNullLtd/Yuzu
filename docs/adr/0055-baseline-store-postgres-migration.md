# ADR-0055: BaselineStore → PostgreSQL

- **Status:** Accepted — shipped PR #3517, merged 2026-08-24; `baseline_store.cpp` is PG-native
  (`PgPool`/`pg_exec`), zero live `sqlite3_` calls (comments only), re-verified 2026-09-07.
- **Date:** 2026-08-19
- **Deciders:** pg workstream, security-guardian + docs-writer review (Guardian routing per CLAUDE.md)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009, ADR-0012; ADR-0038
  (`GuaranteedStateStore` → PostgreSQL, the closest Guardian-domain precedent — this
  ADR follows its posture/catastrophic-read reasoning directly); the TagStore (ADR-0050)
  / RbacStore (#2703) fingerprint-verified backfill shape; ADR-0052/#3398/#3399
  (`DeviceTokenStore` backfill hardening — `sanitize_pg_text` applied here too, see
  "Backfill" below); ADR-0053 (`CaStore`, #3475 — the racing-first-boot precedent the
  "Concurrency at boot" section below responds to); `docs/yuzu-guardian-design-v1.1.md`
  §9.1 (schema) + §24 (standing invariants); `docs/guardian-baseline-model.md`.

## Context

`BaselineStore` (`server/core/src/baseline_store.{hpp,cpp}`) is the server-side Guardian
**Baseline** store — the named, deployable collection of Guards
(`docs/guardian-baseline-model.md`). Three tables today (`guardian-baselines.db`, SQLite):
`guaranteed_state_baselines` (the Baseline row, including `deployed_snapshot` — the
member set captured at last deploy), `guaranteed_state_baseline_rules` (M:N live
members), `guaranteed_state_baseline_groups` (assignment: included − excluded
management groups). Bounded operator-authored config, not a high-write/telemetry
store — no retention reaper.

CLAUDE.md "Guardian engine — stores" names this store's catastrophic invariant
directly: push fan-out + heartbeat reconcile gate on `deployed_member_rule_ids()`,
sourced from each deploy's `deployed_snapshot`, **not** the live member set — what's
enforced stays behind `Push`, not `Write`.

## Decision

Migrate to PostgreSQL schema **`baseline_store`** (ADR-0008 naming), construction
fail-closed (ADR-0012 §1), on the shared server `PgPool`. The agent is untouched —
this is pure control-plane config; the agent never hears the word "Baseline".

### Schema

The three tables port with SQLite idioms translated (`INTEGER` timestamps → `BIGINT`;
short table names per the current naming convention — `baselines` / `baseline_rules` /
`baseline_groups`, schema-qualification replacing the legacy `guaranteed_state_baseline*`
flat-namespace prefix). The in-schema FK from the two child tables to `baselines` (`ON
DELETE CASCADE`) ports unchanged; the deliberate absence of a `rule_id`/`group_id` FK
(those reference `guaranteed_state_store`/`management_group_store` — different schemas)
also ports unchanged, matching the pre-migration store's cross-file reasoning.

### Posture (ADR-0012 §1) — uniformly authoritative

Unlike ADR-0038's split-by-table-family posture, every table here is operator-authored
Guardian enforcement config with no bounded/re-derivable telemetry tier to carve out —
so the whole store is **authoritative**, simpler than its GuaranteedStateStore sibling:

- **Baseline CRUD writes — fail-hard** (unchanged from pre-migration):
  `create_baseline`/`update_baseline`/`delete_baseline`/`set_members`/`set_assignment`
  stay `std::expected<..., std::string>`, `kConflictPrefix`-tagged conflicts mapping to
  HTTP 409.
- **The catastrophic-read set (CLAUDE.md Guardian invariant).** `deployed_member_rule_ids()`
  — **both overloads** (the fleet-union used by the push fan-out + heartbeat reconcile,
  and the per-Baseline form used by the baseline-anchored per-device compliance REST
  view) — move to `std::expected<..., std::string>`. The pre-migration SQLite store
  returned a plain container, empty-on-degrade; that was fine under SQLite's
  open-or-not binary failure mode but is exactly the fail-open shape ADR-0036/0038
  closed elsewhere under Postgres's richer failure surface (lease timeout, query
  error). Every push/reconcile/REST consumer now aborts (503 / no-op push, sentinel
  `-2`) on `!result`, mirroring `GuaranteedStateStore::list_rules()`'s handling exactly
  — never fans out an empty deployed-set indistinguishable from "nothing deployed" (a
  fleet-wide silent disarm) or renders a device falsely "compliant" (0 guards reported).
  A malformed **or genuinely empty** stored `deployed_snapshot` is **not** a degrade —
  it is a successful read that contributes nothing to the union, unchanged,
  fail-closed-by-construction behavior pinned by the pre-migration store's own doc
  comment.
- **`get_members_checked()`** — a new degrade-distinguishable twin of the pre-existing
  plain `get_members()`, for the ONE call site (the deploy handler,
  `guardian_routes.cpp`) that writes a live-member read into a **durable** enforced
  snapshot. A lease timeout there previously (silently) risked persisting
  `deployed_snapshot = "[]"` — a durable disarm of that Baseline, strictly worse than a
  transient read failure elsewhere, and a real Postgres runtime path (pool-lease
  timeout) that SQLite's single-file-open-or-not model never exercised. Every other
  `get_members()` caller (dashboard fragments, the "drifted from deployed" diff) stays
  render-only / deny-or-benign and keeps the plain empty-on-degrade container
  (ADR-0038 "deferred widening" class) — a full widening of every read touches ~10
  call sites for no additional safety, out of scope for this PR.
- Every other read (`list_baselines`/`get_assignment`/`baselines_containing_rule`/
  `list_deployed_baselines`/counts) stays plain container/`size_t`, empty-on-degrade —
  dashboard display only, never an enforce/target decision.

### Backfill (ADR-0009) — mandatory, fingerprint-verified

Deployed baselines + their snapshots are live enforcement state — a lost deploy
snapshot disarms or mis-scopes enforcement — so backfill is mandatory, not skippable.
Follows the **TagStore/RbacStore post-#2703 shape**
(`docs/postgres-store-playbook.md` "Local source absence never creates terminal
migration state on its own"), not ADR-0038's simpler marker-only shape which predates
that lesson: a `baseline_store_meta` k/v marker pair (`backfill_complete` +
`backfill_source_fingerprint`, a SHA-256 over the canonicalized legacy content,
`"v1:<hex>"`), stamped together in one transaction as a monotonic promotion (a
`sourceless` value may be promoted by a real fingerprint; a real value is never
overwritten). A replica that still holds its own local legacy file when the marker is
already set **verifies that file's content against the stored fingerprint**
(holder-side verification) before trusting the marker — refusing
("HOLDER-SIDE VERIFICATION FAILED") rather than silently accepting a completion this
replica's data was never part of.

**Scaled to three tables with FKs — the specific design this ADR records:**

- All three legacy tables are read inside **one deferred SQLite transaction** (load-
  bearing here, unlike TagStore's single-table case: a torn read across the parent and
  its two child tables could fingerprint/migrate a parent whose children were captured
  from a different instant).
- **Parent rows** (`baselines`) are migrated per-row, **direction-aware on
  `updated_at`** (the DeploymentStore/TagStore shape) — IDENTITY is `baseline_id` (a PK
  match); every other column is LIFECYCLE. Identical → benign no-op. Postgres
  strictly ahead → benign no-op, warn-logged. Legacy strictly ahead, or tied with
  differing content → **fails closed**, unstamped (a future boot retries). A fresh
  legacy `name` colliding with a DIFFERENT already-live `baseline_id`'s `UNIQUE(name)`
  also fails closed — a name conflict between this replica's legacy data and live
  Postgres data cannot be auto-resolved.
- **Child rows** (member + assignment) are copied **only for a parent freshly inserted
  this pass.** A baseline that already existed live (Postgres-ahead or identical)
  already has complete, authoritative children via `set_members`/`set_assignment`'s
  own atomic full-replace semantics — re-merging its legacy children row-by-row would
  be redundant at best and a stale partial overwrite at worst. This is safe against a
  concurrent writer: the freshly-inserted parent row is uncommitted-and-invisible to
  every other transaction until this one commits, so nothing else could have written a
  member/assignment row against it in the interim. This is the one place BaselineStore's
  three-table M:N-with-atomic-replace shape diverges from TagStore's flat single-table
  design, and from GuaranteedStateStore's five-independent-tables design — it was
  chosen because it is simpler AND provably correct for this specific shape, not
  because it was copied from a precedent.
- Legacy file retained read-only, moved aside (`.migrated-<epoch>`) after a verified
  backfill — one release rollback window, matching every other migrated store.
- **Text sanitization (ADR-0052/#3398/#3399 hardening pass, applied here retroactively):**
  every free-text field — on EVERY write path, live CRUD and backfill alike, including
  `baseline_id`/`rule_id`/`group_id` themselves — is scrubbed via `sanitize_pg_text`
  (invalid UTF-8 → U+FFFD, then embedded NUL → U+FFFD) before it reaches a bound
  parameter, matching TagStore/RbacStore/CustomPropertiesStore/DeviceTokenStore. Without
  this, an embedded NUL silently truncates at libpq's text-format bind (`pg_exec.hpp`
  binds via `.c_str()`, no explicit length) — for an id column, that is a *wrong-row*
  hazard (a write or a lookup silently landing on a different, truncated id), not just a
  display glitch. The backfill's direction-aware "identical" compare uses the SAME
  sanitized values on both sides (TagStore's exact reasoning: a prior partial pass
  stored sanitized bytes, so raw-vs-stored would false-mismatch on precisely the rows
  sanitization touched). Two enum-shaped legacy fields get validation instead of mere
  sanitization, since they are validated on every LIVE write but were previously
  unvalidated at rest in the legacy file: a legacy `lifecycle` outside
  `{draft, deployed}` and a legacy assignment `disposition` outside
  `{include, exclude}` each fail the backfill closed, naming the offending row, rather
  than reaching `deployed_member_rule_ids()`'s `WHERE lifecycle = 'deployed'` filter (or
  an assignment reader) as a silently-inert third state.
- **Deliberately NOT ported: DeviceTokenStore's (#3399) streaming/batched-`unnest`
  backfill rewrite.** That rewrite exists because device tokens are a per-agent-scoped
  table whose size tracks fleet size (unbounded materialization risk); Baselines are a
  small, operator-curated, fleet-wide catalog — dozens to low hundreds of rows, the
  store's own header comment's "bounded operator-authored config (not a multi-GB/day
  stream)" — the same scale class as `TagStore`/`GuaranteedStateStore`, both of which
  also fully materialize their legacy snapshot and are the shipped, governance-approved
  precedent this migration follows instead. Porting the streaming rewrite here would be
  disproportionate complexity for no safety gain at this store's actual scale.

### Concurrency at boot (2026-08-24 hardening pass, prompted by ADR-0053/#3475)

`CaStore`'s migration surfaced a first-boot race class specific to ITS design (multiple
replicas racing to *generate* a new root cert, a single-winner CAS with no pre-existing
data to fall back on). `BaselineStore`'s backfill is a different shape — copying
*existing* legacy data, not generating new state — but the underlying question
("what happens when two replicas' boots overlap against one shared Postgres database")
deserves the same explicit answer, not an assumption inherited silently:

- **Two replicas backfilling from identical legacy content** (a shared golden image,
  or a shared volume mounted twice) converge safely and require no operator action.
  Whichever racer's `INSERT ... ON CONFLICT (baseline_id) DO NOTHING` reaches Postgres
  first wins the row; Postgres's row-level lock on a conflicting insert **serializes**
  the second racer's attempt (it blocks until the first commits, then resolves as a
  real conflict) — this is a property of Postgres's MVCC insert path, not a coin-flip
  outcome dependent on CPU scheduling, **for the two racers that actually reach that
  INSERT concurrently**. The blocked racer's own `migrate_from_sqlite` call refuses
  THAT pass (`PQcmdTuples()=="0"`, "concurrent writer inserted mid-backfill — refusing
  (re-run will compare directions cleanly)") rather than trying to re-derive the
  direction compare inline mid-transaction; an immediate single-threaded retry
  (matching `server.cpp`'s existing "a failed backfill sets `startup_failed_`, the
  orchestrator restarts that replica" contract — no new self-heal-without-restart
  machinery was added, unlike `CaStore`'s operator-requested enhancement) then finds
  the row already present with identical content and completes normally.
  **Correction (2026-08-24 governance re-review):** whether both racers reach the
  contested INSERT at all is itself schedule-dependent — `migrate_from_sqlite` checks
  the `backfill_complete` marker via a plain SELECT before the row-locked transaction;
  a racer whose marker check lands after the other has already committed takes the
  holder-side-verification "already complete" path instead, never reaching the INSERT.
  So this IS the same class of scheduling uncertainty as `CaStore`'s UP-3 test, not a
  guaranteed-deterministic exception to it — `test_baseline_store.cpp`'s `[concurrency]`
  test now adopts the same bounded re-attempt-until-observed shape (30 attempts) rather
  than asserting determinism a single unbarriered run can't prove. What IS deterministic,
  and is the actual safety property this store relies on, is that *whichever* path a
  racer takes — the row-lock refusal or the holder-side marker check — neither can ever
  produce duplication or silent data loss; only which of the two accepted code paths
  gets exercised on a given run is schedule-dependent.
- **Two replicas backfilling from genuinely divergent legacy content** (a real
  deployment error — two different files ended up "the" legacy source for different
  replicas) is refused, not silently merged, whichever replica's fingerprint-stamp
  attempt loses the `backfill_source_fingerprint` monotonic-promotion race — covered by
  the sequential "holder-side fingerprint mismatch refuses" test. One residual property,
  inherited from the TagStore/RbacStore shape this ADR follows rather than introduced
  here: because the row-insert transaction and the fingerprint-stamp transaction are
  two SEPARATE transactions (the TagStore two-phase shape), a divergent racer's OWN
  distinct rows can already have committed by the time its fingerprint-stamp attempt
  loses and reports failure — the failure means "this replica's completion was not
  recorded as authoritative," not "nothing from this replica's legacy file reached
  Postgres." A genuinely divergent multi-replica deployment already needs manual
  reconciliation per the refusal's own log message; this is a pre-existing, accepted
  property of the shape, not a new gap.

### Lifecycle / concurrency

No background thread (bounded operator config, no retention reaper — unchanged from
pre-migration). The SQLite single-writer `shared_mutex` is deleted; Postgres real
concurrency replaces it. Mutate-and-return uses `RETURNING` (#1033); no
`sqlite3_changes()`-after-step survives.

## Considered and rejected

- **ADR-0038's simpler marker-only backfill** (no fingerprint, no holder-side verify):
  rejected — it predates the #2697/#2703 lesson and the kickoff plan for this
  migration explicitly calls for fingerprint verification; Baseline data is
  operator-authored fleet-wide config (the RbacStore/TagStore/CustomPropertiesStore
  family), not GuaranteedStateStore's bulk-telemetry-plus-config mix.
- **DeploymentStore/LicenseStore's per-distinct-legacy-file `sqlite_backfill_source`
  table** (multiple independently-valid legacy files, each fingerprinted and marked
  separately): rejected — that shape fits genuinely per-host-divergent data
  (ad-hoc deployment jobs, license activations). Baselines are a single shared
  fleet-wide control surface (like tags, RBAC, custom properties), so the single
  global marker + holder-side-verify shape is the correct family match.
- **Full `std::optional`/`std::expected` widening of every read** (list_baselines,
  get_assignment, etc.): rejected for this PR — none of those reads feeds an
  enforce/target decision (the playbook's deny-or-benign class); tracked as a
  follow-up if a future consumer changes that classification.
- **Merging legacy children into an already-live parent's member/assignment set**
  (union rather than skip): rejected — `set_members`/`set_assignment` are
  whole-set-replace by design; a merge would silently resurrect a Guard/group an
  operator had deliberately removed post-cutover on the live side.

## Consequences

- The push fan-out and heartbeat reconcile gain an explicit degraded-store abort path
  (503 / sentinel `-2` / audited `degraded` result) — a behavior change: previously a
  broken store could (in principle) fan out an empty deployed-set; now it refuses.
  Changelog fragment + a `docs/user-manual/guaranteed-state.md` note if warranted.
- The baseline-anchored per-device compliance REST view (`GET
  /api/v1/guaranteed-state/baselines/{name}/devices/{agent_id}`, `rest_api_v1.cpp`)
  now 503s on a degraded `deployed_member_rule_ids(baseline_id)` read instead of
  silently rendering "0 guards, fully compliant".
- Tests: `tests/unit/server/test_baseline_store.cpp` moves to
  `YUZU_REQUIRE_PG_DB_TPL` + a file-local `PgTestTemplate` (`"baselinestore"` key,
  shared with any other file needing the same store set — `test_guardian_routes.cpp`
  and `test_rest_guaranteed_state.cpp` both attach to it). New coverage: the
  catastrophic-read set's snapshot-not-live-members invariant, malformed-snapshot-is-
  a-skip-not-a-degrade, `get_members_checked()`'s degrade-distinguishability, and five
  backfill scenarios (populated/idempotent, fresh-install, Postgres-ahead-skips-
  children, legacy-ahead-fails-then-retry-succeeds, live-name-conflict-fails,
  holder-side-mismatch-refuses).

## Follow-ups

- Full read-widening of the deny-or-benign reads, if a future consumer starts feeding
  one into an enforce/target decision (none does today).
- `remove_rule_everywhere()`/`remove_group_everywhere()` (the Guard-delete /
  management-group-delete cross-store cleanup hooks) remain unwired from any live
  caller — unchanged from pre-migration; wiring them is a later slice
  (`docs/guardian-baseline-model.md`).
- **Adversarial-review findings, out of this PR's scope (pre-existing, unchanged by
  this diff — verified via `git diff <merge-base>..HEAD`):**
  - `guardian_routes.cpp`'s deploy/delete handlers call
    `store_->bump_policy_generation()` (on `GuaranteedStateStore`, ADR-0038) and discard
    the result; a failed bump leaves the policy generation un-advanced while the deploy
    is reported success, so an offline/reconnecting agent may not be caught by the
    heartbeat reconcile. HIGH, both reviewers confirmed. Belongs to
    `guaranteed_state_store.*`, not `baseline_store.*` — already tracked as **#3281**
    (filed from PR #3277's adversarial review, same finding, same both-reviewers/
    adjudicated-pre-existing shape; no new issue needed).
  - Same handlers treat `BaselineStore::get_baseline()` returning `nullopt` (which
    conflates a degraded store with a genuine not-found) as "Baseline not found". LOW,
    both reviewers confirmed; pre-dates the Postgres migration (the SQLite-era
    `get_baseline` had the identical signature). **Partially fixed** (governance
    hardening round, commit `998db5eec`): `get_baseline` now takes an optional
    `bool* store_ok` — the same pattern already used for `get_baseline_by_name` —
    and `deploy_baseline` (the one call site this PR's own diff touches) is wired to
    it, pinned by a handler-level test that kills the connection after open. The
    other two call sites (`update_baseline_from_form`, `delete_baseline_action`) are
    pre-existing code this diff never touches and remain on plain `get_baseline()`
    with no `store_ok` — same out-of-scope reasoning as the `bump_policy_generation`
    finding above; tracked as **#3512**.
- **Governance-deferred follow-ups (this PR's own hardening rounds, tracked not
  silently dropped):**
  - Handler-level degrade tests for the `GET .../device-compliance` REST route and
    `server.cpp`'s heartbeat-reconcile/push-fan-out abort paths (only `deploy_baseline`
    got one) — **#3513**.
  - `update_baseline`'s full-column overwrite has no optimistic-concurrency guard; a
    concurrent rename between `deploy_baseline`'s read and write is silently clobbered
    (`deployed_snapshot` itself stays correct, only metadata) — **#3514**.
  - No dedicated `docs/ops-runbooks/baseline-store-backfill-recovery.md` (5 of 8
    sibling mandatory-backfill stores have one; not universal precedent, kept SHOULD) —
    **#3515**.
  - The malformed-`deployed_snapshot` divergence warn-logs (added this round) have no
    accompanying Prometheus counter — sre disagreed with deferring this indefinitely
    given its repeat-fire characteristic on the enforcement chokepoint; kept log-only
    to avoid opening new metrics-plumbing surface mid-round — **#3516**.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes a blanket
program-wide fact this store's mandatory-backfill design predates: no production Yuzu
fleet has ever run a pre-Postgres build of any store. The fingerprint-verified
per-row-direction-aware backfill this ADR designed was real, working code — but it
never had real legacy data to protect.

`BaselineStore::migrate_from_sqlite()` and its private helpers (`sha256_hex`,
`legacy_text`, `legacy_has_table`, `append_field`, `canonicalize_legacy_snapshot`,
`fingerprint_legacy_snapshot`, `read_legacy_snapshot`, `legacy_fingerprint`, and the
`LegacyBaselineRow`/`LegacyMemberRow`/`LegacyGroupRow`/`LegacySnapshot` types) are
removed (`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623).
`baseline_store_meta` — whose entire purpose was the backfill idempotency marker
(fingerprint + `backfill_complete`) — is dropped via a version-bumped `{2, "DROP TABLE
IF EXISTS baseline_store_meta;"}` migration, not edited into v1: unlike the DORMANT
trio (DeviceTokenStore/LicenseStore/SoftwareDeploymentStore), this store IS
constructed in production, so v1 has actually run against real dev/UAT databases.
`server.cpp`'s boot path now runs `legacy_sqlite_probe::warn_if_legacy_rows` over the
three legacy tables (`guaranteed_state_baselines`/`guaranteed_state_baseline_rules`/
`guaranteed_state_baseline_groups`) instead — silent unless real rows are found, never
blocks boot. This moots #3515 (the missing backfill-recovery runbook) — there is no
backfill left to recover from.
