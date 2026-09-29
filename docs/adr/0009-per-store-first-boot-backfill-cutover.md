---
status: accepted
date: 2026-06-09
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; grill-with-docs design session 2026-06-09
scope: platform — how each existing server SQLite store cuts over to Postgres
builds-on: ADR-0006 (Postgres substrate), ADR-0008 (substrate architecture)
---

# 0009 — Existing stores cut over via a one-time, idempotent first-boot backfill

## Context

ADR-0006 migrates ~29 existing server SQLite stores to Postgres incrementally (strangler), each
behind its own per-store ADR. This ADR fixes the *mechanism* every such migration uses, so the
per-store ADRs don't each re-invent it. The risk is data loss / corruption on a live store
during cutover. The stores fall into classes with different durability needs: TTL'd ephemeral
(response 90d), SOC 2 retained (audit 365d), config/reference (rbac, tags, baselines,
management-groups, policies, custom-properties, product-packs — operator state that cannot be
lost), and build-time-seeded (instructions — re-seeded from embedded content, plus operator
additions). The upgrade-test rig (`scripts/test/docker-compose.upgrade-test.yml`) already
exercises previous-release → new-release and is the natural gate.

## Decision

**Big-bang per store via a one-time, idempotent first-boot backfill.** When a migrated store
comes up on Postgres, finds its Postgres schema empty **and** a legacy `<name>.db` SQLite file
present, it copies rows over (a per-store `migrate_from_sqlite()` step) and stamps itself
migrated; subsequent boots skip it. The backfill runs **at startup, before the server serves**,
and **fails closed** on any error (the server refuses to start rather than serve half-migrated
data).

- **Backfill is mandatory** for config/reference stores and for `audit` (SOC 2 retention).
- **Backfill may be skipped** (behind a flag) for purely TTL'd ephemeral stores (`response`) —
  history ages out, so a clean cut with a bounded gap is acceptable.
- **The legacy SQLite file is retained for one release** as a rollback net, then removed in
  the following release. Backfill never mutates it; a store with a wired erasure path must,
  however, delete the same subject/device from the rollback copy so rollback cannot resurrect
  data whose erasure was reported successful.
- Each per-store migration's upgrade-test must assert that config/reference/audit data survives
  the previous-release-SQLite → new-release-Postgres transition.

## Considered and rejected

- **Dual-write window per store** (write both engines, read SQLite, flip reads to Postgres,
  then drop SQLite). Zero-gap and trivially reversible, but ~29× the complexity and a
  long-lived two-engine code path running through the entire multi-quarter program — the exact
  cost ADR-0007's single-backend decision exists to avoid.
- **Cutover with no backfill (fresh start everywhere).** Simplest code, but it discards
  operator config and SOC 2 audit history — unacceptable for the reference and audit stores.

## Consequences

- Each per-store migration carries a `migrate_from_sqlite()` implementation and an upgrade-test
  assertion; the recipe is uniform, so per-store ADRs focus on schema, not mechanism.
- The rollback window is exactly one release (the retained legacy file: backfill reads it only;
  wired subject/device erasure may delete rows). A defect discovered
  after the legacy file is removed has no in-place rollback — so the one-release retention and
  the upgrade-test gate are load-bearing, not optional.
- **Secrets stores (`api_token`, `ca`) are explicitly out of scope for this mechanism.** They
  migrate last and only behind a dedicated secrets-at-rest ADR (envelope encryption / KMS /
  `pgcrypto`) + `security-guardian` review — a plain `migrate_from_sqlite()` copy into Postgres
  columns is forbidden for secret material (the ADR-0004/0006 carve-out).

  **Update (ADR-0010, 2026-06-10):** the dedicated secrets-at-rest ADR landed as ADR-0010,
  with a scope ruling that differs from the sentence above: `api_token` and `ca` are
  hash-only / key_ref-only (no plaintext secret columns) and are **unblocked** onto the
  normal ladder; the stores that actually require the secrets mechanism are `auth`,
  `webhooks`, `offload_targets`, and `runtime_config`. The decided mechanism is app-side
  AES-256-GCM envelope encryption (`SecretCodec`); `pgcrypto` was considered and rejected.
  Backfills that touch secret columns transform (encrypt/hash), never copy — see ADR-0010.

  **Update (`ResponseStore`/#2691, 2026-08-08):** "behind a flag" above overstated the
  mechanism for the first store to actually exercise the skippable class. No flag was
  built, and none is needed: `ResponseStore` skips backfill **unconditionally** — on
  cutover the legacy `responses.db` is never read. (Correction, 2026-08-25: an earlier
  version of this paragraph claimed "a one-time loud boot log records 'response history
  reset on Postgres cutover'" — no such log exists; `ResponseStore` logs only its generic
  `"ResponseStore initialized (schema {}, retention={}d)"` line, with nothing distinguishing
  a fresh start from any other boot. See `docs/postgres-store-playbook.md`'s Backfill bullet
  for the detect-and-warn requirement this gap motivates for a future skip-by-default store
  holding real operator data — that requirement lives in the playbook's authoring guidance,
  not restated in full here.)
  There is no compliance or config-durability requirement to preserve response rows across
  the cut (unlike the config/reference and audit classes above), so a conditional flag would
  add a knob nobody has a reason to turn off. `ResponseStore` is the reference case for this
  class: a future purely-TTL'd, purely-ephemeral store should also skip unconditionally, not
  gate the skip behind a flag, unless a specific store has a reason this one doesn't.

  **Update (`ProductPackStore`/ADR-0054, 2026-08-23):** the "must... delete the same
  subject/device from the rollback copy" sentence above literally names mutating the
  retained legacy file as the mechanism. `ProductPackStore` satisfies the clause's
  *purpose* — rollback cannot resurrect data whose erasure was reported successful — via a
  different, and for this store's shape a *stronger*, mechanism: `uninstall()` stamps a
  durable Postgres-side tombstone (`deleted_pack_ids`) in the same transaction as its
  delete, under an advisory lock closing the obvious check-then-insert race. The FIRST TIME
  a given legacy file's exact content is seen (its whole-file fingerprint has no prior
  marker), `migrate_from_sqlite()` checks every unmatched row against the tombstone before
  treating it as fresh content; a later pass against byte-identical content is a safe
  no-op skip (that content was already fully reconciled, tombstone-checked, in the
  transaction that stamped its marker) rather than a re-check. This closes the *permanent,
  shared* resurrection hazard (a redeployed or newly-joined replica's own stale
  legacy-file copy) that a literal per-file mutation cannot reach at all, since that
  mechanism only protects the one replica whose file was written — it does nothing for a
  sibling replica's separate copy. The literal mechanism is deliberately NOT also
  implemented: writing to the legacy file at `uninstall()` time would introduce a write
  path into the one artifact that exists specifically as a rollback safety net, so a
  partial/failed write during an uninstall could corrupt the rollback net itself — while
  still only covering a single replica. That is a strictly worse trade for a benefit the
  tombstone doesn't need.

  **What the tombstone substitution does NOT close:** an operator who rolls the server
  BINARY back to the pre-migration (SQLite-only) release, during the one-release rollback
  window, reads `product-packs.db` directly — that binary has no knowledge Postgres or
  `deleted_pack_ids` exist, so an uninstalled pack's catalog row can reappear for the
  duration of the rollback. This residual is accepted, on grounds specific to
  `ProductPackStore` and NOT a general precedent: the resurrection is metadata-only. The
  pack's actual content (`InstructionDefinition`/`PolicyFragment`/`Workflow` rows) lives in
  separate, still-live SQLite stores that `uninstall()`'s `uninstall_fn` callback attempts
  to delete — ordinarily permanently, though a `PolicyFragment` still referenced by another
  policy is a documented, logged exception (`uninstall()` tolerates that one failure and
  still completes the pack-level delete + tombstone; see `PolicyStore::delete_fragment`'s
  own referential-integrity refusal) — a binary rollback does not restore anything that
  *was* deleted, and there is no automatic/boot-time caller of `install()` anywhere in this
  codebase, so nothing re-materializes pack content short of a fresh, explicit `install()`
  call (the `#802` signature gate constrains what such a call may install; it is not itself
  what prevents an automatic reinstall). Nothing executable resurfaces; the operator sees a
  stale catalog listing, not reinstated content — though a lookup that follows one of that
  listing's item ids into another endpoint (fetch/execute an instruction by id, for
  example) will 404 against content already deleted, which is expected during the window,
  not a new fault. Re-uninstalling under the old binary mutates the legacy file directly
  (the pre-migration code path always did); once the row is absent from a later re-scan of
  that file, there is nothing left to resurrect regardless of the tombstone.

  **This reasoning is store-scoped and MUST be re-derived, not copied, by the next store
  whose wired erasure path covers genuinely personal or regulated subject/device data**
  (the clause's original target) rather than operator-authored catalog metadata over
  separately-erased content. That store will likely need the literal per-file mechanism
  this update declines for `ProductPackStore`.

  **Update (fresh-start-by-default, 2026-08-25 — operator directive):** the "Backfill is
  mandatory for config/reference stores" bullet above assumed a real fleet with real
  legacy data to protect. That has never been true — no production fleet has ever run a
  pre-Postgres build of any Yuzu store — so for every migration still to come (as of this
  writing: `InstructionStore`, `OffloadTargetStore`, `RuntimeConfigStore`), the default
  flips: **skip `migrate_from_sqlite()` entirely, unconditionally, the same way
  `ResponseStore` already does** (Update above), rather than build a backfill and plan to
  remove it later. This is not a narrowing of what backfill protects — the mandate's
  entire premise (preserving real operator config / real SOC 2 audit history across a real
  upgrade) is empty while there is nothing real to preserve. Retired for the same reason,
  same day: `PolicyStore`'s already-shipped backfill (ADR-0056, commit `f46cefe8e`) — see
  `docs/postgres-migration-ladder.md`'s `PolicyStore` row.

  (`WebhookStore`/PR #3563 merged with a full `migrate_from_sqlite()` already built the
  same day this amendment landed, ahead of it reaching that PR — too late for the "don't
  build it" guidance to apply retroactively. Its backfill TEST suite is being retired in
  the same pass as the other already-migrated stores' backfill tests below; its production
  `migrate_from_sqlite()` stays for now, same as the others.)

  (`InstructionStore`/PR #3602 is a DIFFERENT situation from `WebhookStore`'s, not the same
  one — it is still OPEN, unmerged, as of this amendment landing, with a full mandatory
  backfill already built under the pre-amendment text. Unlike `WebhookStore`, nothing here
  is retroactive: #3602 should drop that backfill before merging, not keep it — this default
  now governs it directly, the same as any other not-yet-merged `InstructionStore` work. Its
  reviewer had already separately requested changes for unrelated bugs in the backfill's
  conflict-resolution logic; removing the backfill entirely resolves those findings along
  with bringing the PR into line with this default.)

  **This default is conditional on the fact, not permanent policy.** It holds only while
  "no production fleet" stays true. If a real external deployment (a design partner, a
  pilot customer, a dogfooded production instance) exists or is committed to before a
  given store migrates, that store's own per-store ADR must re-derive whether backfill is
  needed for IT specifically — do not cite this update as blanket cover once the premise
  changes. `AuditStore` (already migrated, ADR-0040, backfill built and shipped) is the
  one store where this would matter most if the premise ever flips retroactively: audit
  evidence cannot be regenerated the way config or cache state can, so its already-built
  backfill is deliberately NOT being retired alongside `PolicyStore`'s, and is not a
  candidate for retroactive removal generally — see the ladder's `AuditStore` row. A future
  store whose data is similarly irreplaceable (not just operator-authored-and-reconstructible)
  should weigh that before defaulting to skip.

  **Existing stores already migrated WITH a backfill are unaffected by this update** —
  removing their already-built `migrate_from_sqlite()` is a separate decision (tracked as
  ongoing cleanup, not mandated by this ADR), and per `docs/postgres-store-playbook.md`'s
  authoring contract, an in-place schema-DDL edit is safe only for a store whose schema
  version was never shipped (`PolicyStore`'s case); every other store's removal needs a
  proper version-bumped migration, not a copy of that shortcut.

  **This supersedes two specific sentences above for a skip-by-default store, and no others:**
  the Decision bullet requiring "each per-store migration's upgrade-test must assert that
  config/reference/audit data survives the previous-release-SQLite → new-release-Postgres
  transition" does not apply — there is no transition to assert for a store with nothing
  copied across; and the Consequences bullet stating "each per-store migration carries a
  `migrate_from_sqlite()` implementation and an upgrade-test assertion" is no longer a blanket
  requirement for a migration that lands under this default. Every other Decision/Consequences
  bullet (the legacy-file rollback-window retention, the fail-closed construction posture, the
  secret-transform-never-copy rule for the documented-exception case) is untouched.

  **Update (in-place-edit exception, stated precisely, 2026-09-02):** the sentence above —
  "an in-place schema-DDL edit is safe only for a store whose schema version was never
  shipped" — names the easy-to-check proxy, not the actual invariant it protects. The real
  requirement is that no already-applied migration version's CONTENT changes: `PgMigrationRunner`
  tracks a bare version integer and only ever applies a migration with `version > current`, so
  editing an already-shipped version's SQL text in place is inert for any database that has
  already passed it — the edited text simply never runs again there. "Never shipped" is one way
  to guarantee that (an unshipped version has, by definition, never been applied to any
  database); it is not the only way. `DeviceTokenStore`/`LicenseStore`/`SoftwareDeploymentStore`
  (`chore/retire-migrate-from-sqlite-batch-b`, #3623) each shipped a v1 migration to `dev` but
  are provably never constructed anywhere in production (their own ADR Updates — 0048/0051/0052
  — verify this via `server.cpp` construction-site archaeology), so their v1 never ran against
  any persistent database either, satisfying the actual invariant despite failing the literal
  "never shipped" wording. The corrected rule: an in-place edit to an already-shipped migration
  is safe when that version is proven to have never executed against a real database — whether
  because it was never shipped, or because it shipped but the store was never constructed. What
  remains unsafe either way, and is the actual hazard this ADR's original sentence exists to
  prevent, is RENUMBERING an already-applied version to a higher slot — that forces the runner
  to re-apply it, which is exactly the class of bug #3623's own `ProductPackStore` fix corrected
  (a version-bumped `DROP` was mistakenly inserted at an already-shipped store's used slot,
  renumbering its content to a higher version instead of being appended after it).

  **Update (production-code removal completed, 2026-09-03):** two sentences above are now
  superseded by completed work, not merely by intent. The parenthetical at "its production
  `migrate_from_sqlite()` stays for now, same as the others" (`WebhookStore`) is superseded —
  its production `migrate_from_sqlite()` was retired in `chore/retire-migrate-from-sqlite-batch-a`
  (#3623), see ADR-0057's own Update. And "removing their already-built `migrate_from_sqlite()`
  is a separate decision (tracked as ongoing cleanup, not mandated by this ADR)" is superseded
  for the full set: `chore/retire-migrate-from-sqlite-batch-b` (#3898, merged 2026-09-02) retired
  12 stores' production code, and `chore/retire-migrate-from-sqlite-batch-a` (#3623) retired the
  remaining 6 (`WebhookStore`, `CaStore`, `InventoryStore`, `RbacStore`, `ManagementGroupStore`,
  `QuarantineStore`) — each per that store's own risk profile, not a copy-paste of the mechanical
  template, per the original tracking issue's own acceptance criteria. That closes all 18 stores
  named in #3623. `AuditStore` remains the sole exception, unaffected by either PR — see the
  "This default is conditional on the fact, not permanent policy" paragraph above for why. A
  future store's own retirement, if one is ever added to the ladder after this ADR's amendment,
  should follow the version-bumped-append shape these two PRs established, not re-derive it.

  **Update (hard cutover — the `AuditStore` exception withdrawn, 2026-09-04):** the paragraph
  above beginning "`AuditStore` (already migrated, ADR-0040, backfill built and shipped) is the
  one store where this would matter most if the premise ever flips retroactively" is superseded.
  That paragraph reasoned from the premise holding ("no production fleet has ever run a
  pre-Postgres build") and kept `AuditStore`'s backfill as insurance against the premise being
  locally wrong for evidence specifically. The operator's direction inverted the question: not
  "is the premise still true," but a deliberate policy choice regardless — no migration path
  held open, for any store, full stop, accepting permanent audit-trail loss as the failure mode
  if the premise is ever wrong for this store. `AuditStore::migrate_from_sqlite()` was retired
  in `chore/retire-migrate-from-sqlite-auditstore` (#3623) — see ADR-0040's own Update for the
  full trace, including why this is a plain `DELETE` of the marker rows rather than `RbacStore`'s
  poison. This closes the 19th and last store on the ladder; #3623 is now fully resolved with no
  store carrying a live `migrate_from_sqlite()`. A leftover `audit.db` still gets a boot-time
  WARN (`legacy_sqlite_probe::warn_if_legacy_rows`) — this Update withdraws the backfill, not
  the detect-and-warn obligation every other retired store already carries.
