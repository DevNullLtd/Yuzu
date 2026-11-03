# Echo activity record — Implementer's Guide

Companion to `docs/user-manual/echo.md` (operator-facing). This doc is for
engineers maintaining the Echo plugin or building features on top of Echo.
It captures the design intent, the on-disk format, and the operational
behavior you cannot derive from the code alone.

For the historical product vision and rollout plan, see
[`docs/echo-warehouse-plan.md`](echo-warehouse-plan.md). For the OS support
matrix, see [`docs/user-manual/echo.md`](user-manual/echo.md#os-compatibility-matrix).

---

## 1. What Echo is for

Echo is a **forensics + inventory** capability, not a SIEM and not an EDR.
The design point is "what was happening on this machine at time T, with
no pre-configuration", which has two distinct uses:

1. **Forensic timeline reconstruction.** When an incident is reported,
   an operator can run a query like "show me every process named
   `chrome.exe` that started on this host between 2026-03-01 and
   2026-03-08" and get an answer regardless of whether logging was
   enabled at the time. The collector defaults are tuned so 90+ days of
   activity fits in single-digit MB on a typical workstation.

2. **Cheap inventory snapshots.** The same data — the most recent
   process list, the open TCP connection map, the running services —
   doubles as an always-fresh inventory source for dashboards and
   compliance evidence. Because the live tier is row-count-bounded, a
   `SELECT * FROM $Process_Live` always returns "now-ish".

What Echo is **not**:

- Not a kernel-mode probe. All collection is poll-based via documented
  user-mode APIs (`CreateToolhelp32Snapshot`, `/proc/*`, `sysctl`,
  `GetExtendedTcpTable`, `proc_listallpids` + `proc_pidfdinfo`,
  `systemctl`, `launchctl`, `WTSEnumerateSessionsW`, `getutxent`).
  Anything that lives shorter than the fast collector interval
  (default 60s) is invisible.
- Not a transport for events. Echo persists everything locally; the
  server queries on demand via the `query` and `sql` actions. There is
  no push-to-server stream and no aggregation across hosts at write
  time.
- Not encryption-at-rest, not compression. See
  §3 for the current on-disk format and the planned posture.

---

## 2. Architecture

```
                ┌────────── echo plugin ──────────┐
collect_fast    │ enumerate_processes()           │       fold (one transaction
  (60s) ──────► │ enumerate_connections()         │ ───►  with the baseline) into
                │   diff vs echo_state             │       <src>_hourly_r /
collect_slow    │ enumerate_services()            │       <src>_daily_r /
  (300s) ─────► │ enumerate_users()               │       <src>_monthly_r
                │   diff vs echo_state             │       (+ echo_dict)
                │ fold_*_events()                 │
rollup          │ run_retention():                │
  (15min) ────► │   guarded capped DELETE (time)  │ ───►  paced, clock-guarded
                │   row-count trim (2 plain tables)│
                │ run_budget():                   │
                │   evict old hourly rows         │ ───►  holds echo.db under
                │ dictionary sweep (weekly)       │       db_budget_bytes
                └─────────────────────────────────┘
```

Flow:

1. The trigger engine fires `collect_fast` / `collect_slow` / `rollup` on
   their respective intervals (configurable via the `configure` action).
2. Each collector enumerates its source, reads the previous snapshot
   from `echo_state` (a key-value table inside `echo.db`), diffs them with
   `compute_*_events()` to produce typed event rows, and folds them with
   `EchoDatabase::fold_*_events()`: the events become tier contributions
   (`echo_fold.hpp`, section 3.1) written to the hourly, daily and monthly
   tables in one transaction with the baseline. There is no aggregation
   pass and no raw capture row.
3. Periodically (`rollup` action, 15 min default) the maintenance pass runs
   `run_retention` (time-based, clock-guarded, over the physical `_r` tables).
   Each tier has independent retention (90 days hourly, 180 days daily, a
   year monthly).
4. The same maintenance pass then holds the database to its byte budget
   (`db_budget_bytes`), in this fixed order: retention, `run_budget`, the
   one-off conversion `VACUUM` gate, file hygiene (`incremental_vacuum(256)`
   and a WAL checkpoint), then the weekly dictionary sweep. `run_budget` takes
   only hourly rows older than 48 hours (5 days for `procperf`), from the
   largest hourly table, oldest bucket first, in 1,000-row transactions that
   also bump the persisted eviction counter, stopping after 2 seconds. The
   daily and monthly tiers carry the same events at a coarser grain and are
   never touched. It pauses while an `echo.sql` read holds the WAL above its
   allowance and retries on the next pass. A table whose probe or delete fails
   is skipped for the rest of that pass while the others continue; the pass
   counts as failed and arms no catch-up. A pass that ends on the deadline
   with rows left to evict arms a catch-up slice that `do_collect_fast` runs
   after its collect (outside `collect_mu_`, under `try_lock` on
   `rollup_mu_`, so it never waits on a rollup). Every slice of that drain
   runs with the clock reading the arming pass was admitted with, never a
   later forward one: a slice has no retention-guard contact of its own. It
   reads a fresh clock only to refuse: a clock that stepped BACK below the
   admitted reading disarms the drain (`budget_slice_clock`), because that
   reading's floors would sit above rows written since the step. The
   conversion `VACUUM` writes its deferral marker before it runs and clears it
   on success, and `incremental_vacuum(256)` repeats while the pass's deadline
   allows (at least one step). An unusable stored `db_budget_bytes` (present
   but not a whole number of at least 32 MiB) is "unknown", never the
   default, and the pass is skipped. The budget is hard for eligible data
   pages and soft for the WAL, and rows that are never evicted can hold used
   pages above the target; `budget_over_bytes` in `status` reports the
   overage, measured when `status` runs. A new source is picked up by the
   budget from the roll-up declarations with no change (it is listed in
   `budget_hourly_eligible_sources()`, which `test_echo_aggregator.cpp` pins
   to a literal so a new source is a decision).

Two in-memory structures keep the folded event volume down. `HourlySeenSet`
(`echo_hour_dedup.hpp`) is membership-only, holds at most 20,000 keys, is
cleared on any change of hour (forward or backward) and on overflow (counted in
`status`), and is used through copy-filter-commit, so a failed insert re-filters
identically. Rows it drops are not counted, so `load_count` and `connect_count`
for de-duplicated rows are distinct combinations per hour. `pid_name_` is the
plugin's in-memory pid-to-name map under `collect_mu_` (capped at 65,536; a name
stays usable 120 s after its process exits; exited entries past that grace are
erased before any wholesale clear) and fills `process_name` on `tcp` and
`module` rows.

The schema registry (`echo_schema_registry.cpp`) is the single source of
truth for retention behavior and per-OS support metadata; the tier columns come
from the roll-up declarations (`FoldSourceDef`, `echo_fold_schema.cpp`), which
the registry copies into each tier's `GranularityDef`. Adding a new capture
source means: append to `build_sources()`, populate `os_support`, write the
collector, write the diff, wire the typed fold, write tests, and declare the
source's roll-up columns (a `FoldSourceDef`, a `*_delta` in `echo_fold.hpp` and
their test pins, section 3.1). The roll-up DDL is generated from that
declaration.

---

## 3. Local persistence

**Path.** `<agent_data_dir>/echo.db`. On Windows defaults to
`C:\ProgramData\yuzu\agent\echo.db`; on Linux/macOS to
`/var/lib/yuzu/agent/echo.db`.

**Format.** Plain SQLite 3, WAL journal mode (`echo_db.cpp` sets
`PRAGMA journal_mode=WAL` at open time). Pages are SQLite-default
(4 KB) and the file uses SQLite's standard schema — readable by any
external tool that can speak SQLite. **The on-disk database is NOT
encrypted and NOT compressed.** This is by design today (zero
runtime dependency, zero key-management surface) but is the target of
two planned changes:

- **Encryption-at-rest** via SQLCipher (deferred — would require
  vcpkg port + key derivation from the agent's TPM-bound identity
  certificate, similar to how the agent's gRPC client cert is bound).
- **Page-level compression** via SQLite's `zlib`-backed VFS shim
  (deferred — typical Echo rows compress 4-6× because of repeated
  process names and remote addresses, but the wins are dwarfed by
  retention-default tuning).

If you ship a feature that places sensitive data in Echo (private keys,
session tokens, customer PII), be aware that the cmdline redaction
patterns are the **only** content-protection layer today. Add new
patterns to `kDefaultRedactionPatterns` in `echo_collectors.hpp` rather
than scrubbing per-callsite.

**Schema versioning.** `echo_db.cpp` runs an idempotent migration at open
time. Current schema version is **9** (legacy `tar_events` was retired at v3 in
PR M14, but `kCreateSchema` kept recreating it on every open — v5 stops that and
drops it from already-migrated databases, #2093). Bumps go in the same
function, never in `applies_*` collectors.

### 3.1 Roll-up-only storage model

**Roll-up is the only model.** The recorded design ruling is: "roll-up mode should be the only way
of operating for echo at all, I don't want this as a configurable thing, it's the only method of
operation." So there is no config key, flag, mode switch, environment variable or runtime toggle
between raw capture rows and roll-ups, and none is to be added. Every collector folds through
`EchoDatabase::fold_*_events()` (an `EchoFold` the database owns); the raw `<src>_live` tables and the
aggregation chain are gone, and schema v10 (below) is the flip.

**Where it lives.** `echo_fold_schema.{hpp,cpp}` declare the 17 sources' tier columns and
generate the DDL; `echo_fold.{hpp,cpp}` hold the pure fold core (bucket math, `TierAccumulator`,
the 17 `*_delta` functions) and the `EchoFold` writer. Per-column `role`, `merge`, `interned`,
`generated_expr` and `guard` are additive fields on `ColumnDef` (`echo_schema_registry.hpp`).
`echo_db_v10_migration.cpp` holds the one-transaction migration from schema v9 (below).

**Shape.**
- `echo_dict(id, text)` holds every interned string once. A text key is stored as `<key>_id`.
- `<src>_<tier>_r` is the physical table: bucket column (`hour_ts` / `day_ts` / `month_ts`), keys,
  merged measures and `VIRTUAL` generated `*_avg` columns. ONE unique index
  `<src>_<tier>_r_uq (bucket, keys...)` is both the UPSERT target and the bucket index retention
  uses.
- `<src>_<tier>` is a view carrying the registry tier's existing column names in their existing
  order first, then the new columns. A text key resolves through a correlated dictionary lookup,
  not a `JOIN`: SQLite reports an unselected join table as a column-less top-level read, which the
  operator-SQL authorizer cannot tell from a direct dictionary read. `usage` keeps its own tables
  and has no roll-up DDL.
- The enrichment columns are those a source's `*_delta` leaves unnamed: they are written as 0 /
  empty and are carried by the tier, so a tier is declared once.

**Merge.** `kSum` adds, `kMax` / `kMin` keep the extreme, `kLast` takes the incoming value only if
its guard column (`last_ts`, ...) is >= the stored one, so a late older event never overwrites a
newer one (a tie takes the later arrival). A `kMin` column (`rtt_us_min`, `min_run_s`) is written
on every event: the INSERT carries the value, so its `NOT NULL DEFAULT 0` never enters a `MIN()`;
only a delta that writes a placeholder 0 holds the minimum at 0 (the `netqual` delta does for
`rtt_us_min`). Averages are `*_sum` plus `samples`; the `*_avg` names are generated, so consumers
keep their columns and every average is an exact weighted mean (an INTEGER-declared one truncates
it, as the legacy rollup's `CAST(AVG(..) AS INTEGER)` does).

**Cursor sources.** `power`, `removable` and `registry` fold through `fold_cursor_rows`, with a
durable per-source ring (`echo_fold_seen`, newest 4096 keys). A key already in the ring is a replay
when its 64-bit digest matches (not folded, cursor still advances) and a permanent key collision
when it does not (everything rolls back). The digest covers exactly what the raw store compares to
recognise a replay, never `snapshot_id`: `power` is the action, detail and `ts` (no `ts` for a
`capture_gap`); `removable` is its stored payload plus `ts` (no `ts` for `capture_gap` or
`present_at_baseline`); `registry` is the action plus, unless it is a `capture_gap`, hive, key
path, value name, data type, data, data size, the previous type, data and size, and `observed_at`
-- never `ts`, `actor_pid`, `actor_image` or `detail`. An empty or NUL-bearing `record_key`
refuses the batch.

**Event times are trusted as given.** A bucket comes from the event's own UTC stamp: no clamp, no
counter. Accepted residual: a stamp inside the representable domain but far in the future makes a
bucket only age-based eviction removes. The one refusal is a stamp outside 0001-01-01 ..
9999-12-31 UTC, which no calendar can bucket, and a non-finite measure (NaN or infinity): that
single event is rejected and the rest of its batch folds. Rejections are counted in `echo_config` `fold_rejected_events_total`, in the same
transaction as the fold (a rollback leaves it unchanged), and logged once per batch with the first
offending stamp only. `echo.status` does not report the counter.

**One lock, one order.** `EchoFold` holds a single `op_mu_` across every fold, GC, cache read and
cache publication; lock order is `op_mu_` then `EchoDatabase::mu_`. New strings are interned
inside the transaction and join the cache only after COMMIT. One `EchoFold` instance fronts a
database. Counts come from `RETURNING`, never `sqlite3_changes()`. `echo_dict.id` is
`AUTOINCREMENT`, so an id is never reused: any deleter of `echo_dict` rows goes through `EchoFold`
(which clears its cache); one that does not leaves dangling ids (the view reads NULL), never ids
naming another string. `fold_rows` is additive, not idempotent: a snapshot source is replay-safe
only because its baseline `StateWrite` commits in the same transaction. The cursor ring is
first-sighting FIFO: a record re-offered after 4096 newer keys of its source folds again (`kSum`
double counts; `kMax`, `kMin` and `kLast` do not).

**Dictionary GC.** `gc_dictionary` scans the live set once per pass into a temp table
(`echo_dict_orphan`, dropped at the pass end), then deletes the orphans by id, 2000 per statement,
until none remain or the deadline passes. `op_mu_` is held for the pass, so no fold adds a
reference meanwhile; a retention delete only creates orphans. The deadline is cooperative: a
progress handler interrupts a running statement (its batch rolls back) and the loop checks before
each batch starts. A pass whose scan outruns the deadline deletes nothing and reports
`live_set_built = false`. It does not cover mutex acquisition, `BEGIN IMMEDIATE`'s 5 s busy wait or
COMMIT I/O. A real failure is returned as an error, never as an empty success. An interned string
outlives its last row until the next pass.

**`echo.sql` and the authorizer.** The views read the dictionary and the `_r` tables, so
`echo_query_authorizer` lets those tables be read ONLY when SQLite reports the access under a
roll-up view (plus a column-less `COUNT(*)`-style read of a `_r` table, which exposes only a row
count the view already shows, and only while every view is a WHERE-less single-table projection,
which the DDL test pins). That rule is sound only because `validate_and_translate_sql` refuses
`WITH`: SQLite reports a CTE's reads under the CTE's name, so a CTE named after a view would
otherwise reach the dictionary. The validator translates `$` names first (in code and in quoted identifiers, never in a literal or
comment), then runs its keyword check on the literal-, comment- and quoted-identifier-stripped
translated query: the bytes SQLite runs. A bound-parameter marker (`$ @ : # ?`) is refused, because
a variable token such as `$x(--)` swallows text the keyword check must see. The same validator
refuses `NATURAL` and `USING` joins: SQLite resolves their shared columns before name resolution,
so those reads never reach the authorizer; `ON` joins carry every read through it. A query that
starts with `WITH` gets `only SELECT queries are allowed`; `WITH` elsewhere, `NATURAL` and `USING`
get `query contains forbidden keyword: <word>` with the replacement (a subquery, or `ON`). The
authorizer rule is defence in depth behind those refusals, not the closure. Direct reads of `echo_dict`, `echo_fold_seen` and any `_r` table, and the `usage_*`
tables, stay denied.

**The v10 switch-over.** `EchoDatabase::open()` runs the schema ladder (the v2..v8 steps, then v9, the
table rename) and then the v10 step. The v10 step runs only from v9: a step below it that failed
rolled itself back and is retried on the next open, and the open is REFUSED meanwhile (a retryable
error), so the version never skips past a step that did not finish. A database with none of the
retired tables just gets the roll-up schema installed. Otherwise `migrate_to_v10` does, in ONE
`BEGIN IMMEDIATE` transaction:

1. Pre-check: the volume holds twice the file free, else the open fails with a message that begins
   with `kFreeSpaceRefusalPrefix`; the plugin then loads offline (`storage_state|offline|free_space`,
   no trigger registered) instead of failing to load. A free-space figure that cannot be read is a refusal too (the 2x check is mandatory, never skipped) and is logged; a database with nothing to migrate needs no room.
2. Rename each old summary tier to `<name>_legacy`, install the roll-up schema, then convert every
   legacy row into the interned table (an average becomes `avg * samples`, a sum column is rebuilt
   from it, the keys intern through the dictionary).
3. Finish the tier-to-tier roll-ups the old aggregator had not yet performed, using each source's
   `rollup_<src>_<to>_at` mark (absent means "fold all"), then fold the raw rows at or after the
   first old tier's mark (`ts >= mark`: a mark is the half-open end of the last rolled bucket).
   The marks are read once and validated before any of this: a mark that is not an integer, a
   populated old tier whose own mark is absent, or a coarser tier's mark ahead of its finer tier's
   fails the migration with the key, value and table named (an absent mark means "fold everything
   into that tier", so a damaged one read as absent would double count what the tier already holds).
   A mark ahead of the clock (`mark > now`, or above `kEchoMaxPlausibleNow`) was written during a
   forward clock excursion that later healed; the old pass returned early on `last_mark >= boundary`,
   so nothing after it was ever summarised, and the mark proves nothing. It is untrusted: the floor
   becomes the end of the newest bucket at or before the clock that the converted tier holds (what
   was provably summarised; a bucket the excursion itself wrote is ahead of the clock too and is
   never the floor, or every raw row written since the clock healed would be dropped as
   summarised), clamped to the clock, the decision is logged once per mark with the figures, and
   the rows below that floor are counted in the "older than the mark" figure. A converted tier
   with no bucket at or before the clock cannot bound the fold: folding everything would add every
   raw row on top of the upper tiers that already hold them, so the migration refuses with the
   source, tier, mark and clock named, unless the source holds no raw row and no converted bucket
   at all (the pre-v10 pass wrote a mark for every source and tier whether or not it had rows, so
   after a forward excursion every never-used source carries one; it bounds nothing, is ignored
   and logged, and the migration proceeds). The trust rule is the old budget pass's bare
   `mark > now` (no tolerance, `acd22e776` `echo_aggregator.cpp` `raw_budget_candidates`), so a
   migration clock behind every stored mark (a restored snapshot, a reset real-time clock) takes
   the same path: bounded by the converted tier, or refused until the clock or the mark is
   repaired. Known limit, two triggers of one mechanism: a raw row the excursion itself stamped
   ahead of the clock folds again on top of the converted future bucket that already holds it;
   and a migration clock set back from a SANE mark (a restored snapshot, an NTP step) makes the
   mark untrusted by the same rule, and the clamp to the clock folds the raw rows between the
   clock and the mark again on top of the buckets that hold them (an upper bound on the raw read
   would close both; not built). A sane mark is used exactly as stored; the migration does not
   otherwise decide per row whether a below-mark raw row was summarised.
   Sixteen decoders read the raw columns through `legacy_live_columns()`; a row the delta rules
   reject is counted and dropped. Raw rows older than that mark are dropped with the raw tables, by
   design: the old roll-up already summarised them, except rows a process-event backfill wrote with
   historical timestamps and rows the old aggregator's clock-gap clamp skipped while the mark still
   advanced. The old `GROUP BY` destroyed the row identity that would tell the two apart, so folding
   them would double-count the first group; the migration logs how many it left unfolded. The usage
   fold read the raw process rows through its own cursor, `usage_hwm_id`: the process rows past it
   (the stored `usage_lag_events`, normally 0) are fed to `usage_fold_in` in this same transaction,
   so a lagging usage fold loses nothing it would have credited when the cursor is deleted; the
   log line carries the rows past the cursor, the stored counter and how many of them were folded
   (a row past the cursor but below the roll-up floor is not read and is in the "older than the
   mark" figure). They are fed only when the usage fold would have credited them, through the
   fold's own predicate (`usage_active_in`): usage enabled and the lifecycle Active, with the
   active generation parsed as `usage_lifecycle_state` parses it (an empty or malformed
   `usage_active_generation` is 0 and reads Active against an absent or 0 `usage_generation`,
   exactly as the next tick would read it; a stricter parse here would feed nothing and then
   delete the cursor). `process_enabled` is deliberately not consulted: the pre-v10 fold left its
   cursor in place while process was disabled and credited the rows once process was re-enabled,
   and the migration folds the raw rows into the process tiers regardless, so the rows reach usage
   now or never (`usage_fold_in` credits the events it is handed while process is disabled; only
   its event-less sweep stays idle). Decided ONCE before the chunk loop; a PendingBaseline tick
   stamps a baseline and folds nothing, so the migration feeds nothing and stamps nothing (decided
   per chunk, the first chunk's stamp would turn the next into a retrospective fold of the rows
   the baseline excluded). An Active lifecycle with no cursor row is the damage the pre-v10 fold
   refused on (both keys were written in one transaction) and refuses the migration with the
   repair named (`DELETE FROM echo_config WHERE key = 'usage_active_generation';`: usage then
   re-baselines on the first tick, which deletes `usage_live`, so the open usage runs are
   forgotten and the lagged rows are not credited); a malformed `usage_lag_events`
   (informational) is logged and the migration continues. A migrated tier
   row carries the columns v9 did not have (`parent_name`, `abnormal_exit_count`, tcp `failed_count`
   and `listen_*`, user `disconnect_count`, removable `partition_count`) as blank or 0, so a bucket
   spanning the upgrade holds two process rows per (name, user): the migrated one with a blank
   `parent_name` and the live one with the real parent. A legacy bucket outside years 0001-9999 or
   an average that is not a finite sum is refused before any write to that tier, with the table,
   column and row id named.
4. Seed the replay ring with the newest 4096 `record_key`s of each cursor source, drop the retired
   tables, delete the rollup marks, `usage_hwm_id` and `usage_lag_events`, create the empty `$X_Live`
   shim views (`legacy_live_shim_ddl()`), and write `schema_version` 10.

A failure at any step, a crash or a power loss before the commit leaves the retired tables intact and the
next open retries from v9. After the commit `open()` refuses if the connection is not in autocommit mode
(a wedged connection is never published), checkpoints and truncates the WAL, and runs one `VACUUM`
when the volume holds twice the new file free (else it records `auto_vacuum_deferred_at` and the daily
maintenance pass retries). The log line carries the duration, rows converted, rows folded, rows
rejected, replay keys seeded, tables dropped, file sizes and the WAL size at commit. The migration needs
the retired tables' own column lists, which live in `echo_fold_schema.cpp` (`legacy_live_columns`); they
are the last copy of the raw schema and exist only to read old files and to answer `$X_Live` reads.

Three operational facts about the migration. (1) Plugin `init()` blocks for the whole migration:
`agents/core/src/agent.cpp` runs every plugin's init in its load loop (about :1057-1085), before the
Register RPC and before the heartbeat thread starts (about :2005 and :2582), so the agent registers
after the migration, and the Windows SCM and systemd (`Type=simple`) have no readiness deadline it can
trip. Agent-level start-to-registered time is not measured. (2) The transaction's WAL is not bounded by
the file's size: 325.7 MB on a 241.8 MB file (1.35 times) in the one measurement. The twice-the-file
free-space pre-check covers that case (WAL plus new file about 404 MB under the 483 MB demanded); no
general bound is proven. (3) A failed earlier step (v8) makes `open()` refuse before the roll-up step
runs; the plugin's init fails (`init_failed` in the heartbeat's `yuzu.plugins_failed`) until a start
succeeds.

Consequences for code that reads the store:
- `echo_usage.cpp` is fed the process fold's events inside the process transaction
  (`usage_fold_in` rides `fold_rows`'s `extra` hook), so there is no read marker and no lag;
  `PendingBaseline` stamps and folds nothing. A fault in either half rolls back both, and the retried
  tick folds both once.
- `purge_source` deletes the source's `_r` rows and `echo_fold_seen` rows and sweeps the dictionary.
- The status counts (`<src>_rows`, `<src>_oldest_ts`) read the finest tier; `<src>_live_rows` prints the
  same figure for one release.
- `is_fold_view` is case-sensitive: a query that names a view `Process_Hourly` does not reach it.
- No fold view may gain a WHERE, JOIN or filter: the pinned column-less `_r` read is sound only
  while every view is a WHERE-less, JOIN-less single-table projection.
- A `kLast` enrichment column is replaced by a later event that omits the field; a `historical`
  mapdrive event's identity is remembered, as a hash, in the replay ring under the source
  `mapdrive_historical`, so a retried enumeration adds no second count; netconn has a high-water
  mark in `echo_config` and no transactional replay guard through `fold_rows`.
- Any deleter of `echo_dict` rows goes through `EchoFold`.

**Releases.** Cut no release between the change that introduced v10 and the dashboard change that
follows it: until then the Echo pages, the process-tree viewer and the canned queries in
`echo_warehouse.yaml` still read the raw names (empty on v10) or label hourly buckets as raw rows.

**Adding a source or tier.** Five edits, each pinned by a test that fails until it matches: the
registry row (`build_sources()`, section 8) (the tiers' `GranularityDef`s are derived from the
roll-up declarations, so the registry's tier lists and the declarations cannot drift); a `FoldSourceDef` at the same index in
`fold_sources()`; a `*_delta` in `echo_fold.hpp`; the count pins in `test_echo_fold.cpp` (17
sources, 34 tiers, 18 registry tiers, 16 shims); the capability TSV rows and the regenerated
`docs/os-capability-matrix.md`.

---

## 4. Persistence across upgrade / uninstall / reinstall

| Operation | echo.db behavior |
|-----------|-----------------|
| **In-place agent upgrade** | echo.db is preserved (lives in the agent data dir, not the install dir). Schema migration runs at first open of the new binary: the v10 roll-up migration converts every raw row and old summary into the tiers in one transaction (section 3.1), or refuses for lack of free space and leaves the file untouched. Afterwards the file is trimmed to `db_budget_bytes` on the first maintenance pass (used pages above the budget less 16 MiB; hourly rows older than 48 h, 5 days for `procperf`), and an older file is converted to incremental auto_vacuum by one `VACUUM` once it is at or under the target or eviction is exhausted and the volume has twice the used size free; rollups continue. On Windows, the first open also re-secures `echo.db` and its sidecars, and refuses the open when the files are owned by an account other than SYSTEM, Administrators or the agent's (for example after the agent's service account changed; the new account also needs access to the files): see `docs/user-manual/echo.md` "Data storage". |
| **Uninstall** (`yuzu-agent --remove-service`, MSI uninstall) | echo.db is **left in place** by design. The data dir is operator-managed; uninstall removes the binary and service registration only. To wipe Echo data, delete `<data_dir>/echo.db` explicitly. |
| **Reinstall over an existing data dir** | The new binary opens the existing echo.db, runs migration if the schema version differs, and resumes collection. State in `echo_state` may be stale (see §5). On Windows, files left by a different agent account are refused rather than adopted (`docs/user-manual/echo.md` "Data storage"). |
| **`data_dir` change** (config update) | The new directory has no echo.db — the next collect_fast creates it from scratch. The old echo.db at the previous path is orphaned but not deleted. Operator concern, not Echo's. |
| **An older agent on a migrated file (not supported)** | An older agent does NOT refuse a v10 `echo.db`: no earlier build checks `schema_version` against a ceiling, so it opens the file, its warehouse DDL fails on the `<source>_live` shim views (`views may not be indexed`) and every collector write errors, so it records nothing and reads only the empty views; nothing is dropped or rewritten, but the install is useless until the file is replaced. Not supported and it will not work: never run an older agent on a migrated file; there is no return to an earlier agent build. An automatic OTA rollback (the updater rolling back a build that failed to verify) lands on the same file and the same applies (`docs/user-manual/upgrading.md` "Returning to an earlier agent build is not supported"). |
| **Corruption detected at open** (#559) | `EchoDatabase::open` runs `PRAGMA integrity_check`; on failure the corrupt file and its `-wal`/`-shm`/`-journal` sidecars are renamed to `echo.db.corrupt-<epoch>` in the same directory (collision-safe if a second corruption lands in the same epoch-second) and a fresh database is initialised (a sidecar that can't be moved is removed so the new DB can't replay it). All `echo_state` (collector snapshots, `<source>_enabled` flags) resets to defaults; collection resumes against the empty DB. The agent logs `echo.db.corruption_detected`; the sidecar is **not** auto-deleted (operator recovers it). If the corrupt file can't be moved aside (read-only/locked/perms), open **fails closed** — Echo refuses to load rather than trust the corrupt DB. **Fleet visibility:** the plugin publishes `heartbeat.db_corruption_total` / `heartbeat.db_quarantine_last`, bridged to the `yuzu.plugin.echo.*` heartbeat tags; the server exposes `yuzu_fleet_echo_db_corruption_agents` and writes an `echo.db.corruption_quarantined` audit row — see docs/user-manual/echo.md "Fleet visibility". |

The "leave data on uninstall" rule is identical to other Yuzu agent
state stores. If a customer asks for "delete echo data on uninstall",
that is a deployment-tooling change (MSI custom action), not an Echo
plugin change.

> **Collect gate and retention share `canonical_source_enabled`.** Both
> `source_enabled()` (`echo_aggregator.cpp`) and `run_retention()` decide a
> source's state through it: `run_retention()` calls `source_enabled()` itself,
> and `source_enabled()` maps the stored value through
> `canonical_source_enabled(stored_value)`, which maps anything other than the
> literal `"true"` to non-enabled (`"false"` → disabled, anything else →
> `"errored"`). This is load-bearing: a value the plugin never writes fails
> **closed** — collection stops *and* retention preserves the rows — instead of
> a bare `!= "false"` that would treat a tampered/corrupt value as enabled and
> let retention delete the paused window (#560). `source_enabled()` also fails
> closed on a failed config read (closed database, SQL error): the registry
> default applies only to a confirmed-absent row. When adding a new capture
> source, gate collection on `source_enabled(*db_, "<name>")` and do **not** add
> a parallel `== "true"`/`== "false"` check or a raw `get_config("<src>_enabled",
> ...)` read — every collect, retention and purge gate for every registered
> source goes through the one helper, so the registry's `default_enabled` is
> the only place a default lives. Collect and retention gates use
> `source_enabled()` (an unreadable flag skips); discard, drain and purge
> decisions use `source_enabled_state()`, which distinguishes a confirmed
> `true`/`false` from an unreadable flag so a destructive path never acts on a
> failed read.
>
> **`paused_at` is cleared on any non-`true` → `true` re-enable.**
> `apply_source_enabled_transition` (`echo_aggregator.cpp`) canonicalises the
> previous stored value before **both** legs, so the disable leg fires on
> `prev_canon != "false"` and the re-enable leg clears `<source>_paused_at` on
> `prev_canon != "true"`. The two are exact mirrors over the tri-state: an
> `errored → true` recovery clears `paused_at` to `"0"` identically to a
> `false → true` re-enable, so a recovered source never reports `enabled=true`
> with a stale paused timestamp (#560). Idempotent `true → true` is a no-op and
> does not touch `paused_at`.

---

## 5. Startup detection / restart caveat

When the agent restarts, the saved `network` / `process` state in
`echo_state` is **stale** — it captures the world as the previous
process saw it, which may be hours or days ago. The next collect_fast
cycle compares the stale `previous` to a fresh `current` and emits
events for every difference.

For the **TCP collector specifically** this means: every connection
that was open both before the shutdown and after the restart appears
as a `connected` event in the timeline, because the state read from
`echo_state` does not include it (or includes a different connection
table). This is a known double-capture caveat.

The tradeoff was deliberate: the alternative — suppressing post-restart
"new" connections by some heuristic — risks dropping legitimate
re-establishment events (an attacker re-opening a C2 channel after a
reboot looks identical to a legitimate connection re-establishment).
Forensic completeness wins; analysts learn to read the post-restart
spike as a snapshot reset rather than 200 net-new connections.

The behavior is pinned by
`tests/unit/test_echo_warehouse.cpp::"Echo diff: TCP post-restart with
empty previous yields all-connected"`.

For **process and service collectors** the same principle applies but
the operational impact is smaller — long-running processes and
services appear as `started` events, which matches what an analyst
asking "what was running after the reboot?" expects to see anyway.

For **user sessions** there is no double-capture: the tty/session_id
is identical pre- and post-restart for the same logged-in user, so
the diff shows no change.

---

## 6. Device impact expectations

Steady-state CPU cost on a typical 8-core workstation, measured against
`v0.10.0` on a 5950X dev box:

| Phase | CPU | Wall time |
|-------|-----|-----------|
| `enumerate_processes()` (200 procs) | ~3 ms | ~5 ms |
| `enumerate_connections()` (300 sockets) | ~8 ms | ~10 ms |
| `enumerate_services()` (140 services) | ~50 ms | ~80 ms (dominated by `systemctl` fork on Linux) |
| `enumerate_users()` (5 sessions) | <1 ms | <1 ms |
| `compute_*_events()` (full diff) | <2 ms total | <3 ms |
| `fold_*_events()` (~50 events, batched) | ~1 ms | ~2 ms |
| Rollup pass (15 min) | ~5–15 ms | ~20 ms |

Worst observed full collect_fast: ~25 ms. Worst observed collect_slow:
~150 ms (Linux `systemctl list-units` on a host with 400 units; macOS
`proc_listallpids` + per-fd `proc_pidfdinfo` on a host with 5000
sockets — consider raising `fast_interval` if the per-cycle cost
exceeds your latency budget).

Disk usage at default retention:

- live tiers: 4 × 5000 rows ≈ 20K rows total. ~3–5 MB depending on
  cmdline length.
- hourly: 24h × ~50 distinct process names ≈ ~1200 rows/day. ~30 MB
  over a year.
- daily: 31d × ~50 names ≈ ~1500 rows/month. ~5 MB/year.
- monthly: 12 × ~50 ≈ 600 rows. trivial.

A workstation kept at default retention sits comfortably under 50 MB
of Echo data over a year of normal use. A noisy CI host with hundreds
of helper processes per minute can exceed 500 MB; the
`process_stabilization_exclusions` knob (issue #59) is the intended
mitigation.

The redaction pass is regex-free (substring match, case-insensitive)
and runs once per process per collect cycle. At typical pattern
counts (5 default + 0–10 operator-added) it is dominated by the
`tolower` cost on cmdline; expect <1 µs per process.

---

## 7. Supportability without the upstream page

This file plus `docs/user-manual/echo.md` plus
`docs/echo-warehouse-plan.md` are the canonical Echo references. The
schema registry is queryable at runtime via the `compatibility` action
(per-source/OS matrix) and the `status` action (effective config). If
you find yourself reaching for an external doc or a "what does this
field mean" answer that isn't in this doc tree, file an issue — that's
the gap to close.

Routine debugging entry points:

| Symptom | Where to look |
|---------|---------------|
| "Echo isn't recording anything for source X" | `echo.status` output → `<source>_enabled` row. Then `compatibility` action to confirm OS support. Then check the agent log for "Echo plugin initialized". |
| "Query returns 0 rows but I know the event happened" | Check the collect interval (`fast_interval` / `slow_interval`) vs the event lifetime — anything shorter than the interval is sub-resolution. |
| "TCP collector shows a flood of `connected` events" | Almost always a restart artifact. Confirm against the agent's start time. |
| "echo.db is huge" | `status` returns `db_size_bytes` (used pages plus the WAL, not the file size) against `db_budget_bytes`. If it's growing without bound, check that the maintenance pass (`echo.rollup`, the budget pass) is running and `budget_over_bytes`: there is no aggregation pass any more, and the tiers grow only through the folds and shrink only through retention and the byte budget; confirm the triggers registered in `init()`. A file that stays large while `db_size_bytes` is within budget is an older database waiting for its one-off `VACUUM` (`db_auto_vacuum|deferred` means a conversion was wanted and could not run: the volume lacked twice the used size free, or the `VACUUM` failed; the marker clears only when a conversion succeeds). `budget_over_bytes` above 0 has several causes: a long `echo.sql` read pinning the log (clears at the next checkpoint), an eviction pass that failed (retried next pass), a pass skipped by the retention clock guard (`retention_guard|__budget__|<n>`), an unreadable setting (`db_budget_bytes|unknown`), a catch-up still draining, or only exempt rows left (hourly rows under 48 hours, daily and monthly rows, the `usage` tables, paused or errored sources and `netconn`, `netqual`, `power`, `removable`, `registry`); see the user manual, "If `budget_over_bytes` stays above 0". |
| "Schema migration failed at startup" | `agent.log` will show `EchoDatabase: migrated to schema version N` on success or the SQLite error on failure. Migrations are idempotent — fixing the underlying issue and restarting will retry. |

For new-source bring-up, the smallest viable change is: add a
`CaptureSourceDef` to `build_sources()`, write the platform collectors
+ enumeration function, write the diff, write tests, and add the source's
`FoldSourceDef`, `*_delta` and test pins (section 3.1). The roll-up DDL is
generated from the declaration.

## 8. Adding a capture source

A **capture source** is a snapshot-and-diff observer (births/deaths of host
state) — like `process`, `tcp`, `service`, `user`. ARP and DNS (ADR-0015) are the
worked example. Follow the **core capture-source pattern** below — do **not** copy
the self-contained *tier* files (`echo_perf.*`, `echo_proc_perf.*`, `echo_netqual.*`),
which are derived-metric samplers with their own headers and pure helpers, a
different shape.

The core pattern (mirror network/service/user — none of which have a per-source
header):

1. **`agents/plugins/echo/src/echo_collectors.hpp`** — add the collected-snapshot
   struct (e.g. `ArpEntry`), the `enumerate_<source>()` declaration, and the typed
   `compute_<source>_events()` diff declaration. **Watch for Win32 macro
   collisions** — `interface` is `#define interface struct` under the full
   `<windows.h>` (the server pulls it via httplib), so a member named `interface`
   breaks the moment a TU without `WIN32_LEAN_AND_MEAN` includes the header; name
   it `iface`.
2. **`agents/plugins/echo/src/echo_<source>_collector.cpp`** (new) — `#include
   "echo_collectors.hpp"`; implement `enumerate_<source>()` per platform with
   `#ifdef _WIN32` / `#elif __APPLE__` / `#elif __linux__`, returning `{}` on
   platforms whose collector is `kPlanned`. Enforce a per-cycle cap with a
   `spdlog::warn` on truncation (there is no agent `/metrics` and no event bus, so
   a log line is the truncation signal — not a metric or audit event).
3. **`echo_db.{hpp,cpp}`** — add the event struct (e.g. `ArpEvent`, next to
   `NetworkEvent`) and `fold_<source>_events()` (mirror `fold_arp_events`: a thin wrapper that
   builds the source's `TierAccumulator` with its `*_delta` and folds it through
   `EchoFold` in one transaction with the optional baseline `StateWrite`).
4. **`echo_diff.cpp`** — implement `compute_<source>_events()`: an `unordered_map`
   keyed on the source's identity (delimiter `\x1f`, which never appears in the
   data) → `appeared`/`removed`. Keep value-only fields (TTL, entry_type) **out**
   of the key so they don't churn the warehouse.
5. **`echo_schema_registry.cpp`** `build_sources()` — add ONE `CaptureSourceDef`.
   This is the single source of truth for retention and per-OS support (the roll-up columns are
   declared in `fold_sources()`, section 3.1; each tier's `GranularityDef` is derived from them): it auto-drives the warehouse DDL, the
   `$Name_Tier` → `name_tier` translation, the read-only-SQL authorizer allowlist
   (`is_queryable_table`, the #760/#631 chokepoint — **no hardcoded list to
   touch**), and the `status` / `compatibility` / `configure` / `snapshot` actions.
   Untrusted operator SQL (`echo.sql`) runs only through
   `EchoDatabase::execute_user_query` (read-only connection + that authorizer);
   the trusted `execute_query` is for registry-generated SQL only — never route
   operator input to it.
   Declare a row for **every** OS (`kSupported`/`kSupportedConstrained`/`kPlanned`/
   `kUnsupported`) — the schema-invariant test requires it. Budget eligibility is structural: a
   source with an `hourly` roll-up tier has hourly rows older than 48 h (5 days for `procperf`)
   evicted under size pressure, and the drift-guard test in `test_echo_aggregator.cpp` pins the
   eligible set, so a new source fails loudly until it is added there. **Every capture source ships `default_enabled =
   true`** (Alex ruling 2026-10-21: all sources, every OS, no exceptions). The
   registry-wide test in `test_echo_schema_registry.cpp` fails any source that
   declares `false`, so a new source must ship enabled. The retrospective-reach
   control is the source's `<name>_lookback_seconds` key where one exists
   (`0` = forward-only), not the enable flag. A default-on source MUST state
   its default in its user-manual page, its changelog fragment, and the SOC 2
   data inventory — never only in a code comment. An agent that stored
   `<name>_enabled = "false"` before a source's default flipped is brought to
   the new default by a one-time, version-gated `echo.db` migration (see the v8
   block in `EchoDatabase::open`), not by changing the registry alone.
6. **`echo_plugin.cpp`** — add a leg in `collect_fast_impl` (or `collect_slow_impl`)
   gated on `source_enabled(*db_, "<source>")`: enumerate → diff →
   `typed.empty() ? db_->set_state(key, json) : db_->fold_<src>_events(typed,
   StateWrite{key, json})` (events and baseline commit in one transaction, #1654).
   On failure emit `error|<src> insert failed` (had events) or
   `error|<src> state_save_failed` (baseline-only) and call
   `note_health(<registry name>, "insert_failed"|"state_save_failed")`; on success
   `note_health(<registry name>, "events_recorded")`. A leg that never calls
   `note_health` reads `never_ran` in status. For a non-core source (netqual, module, arp, dns, …) a failure is
   non-fatal (no `error|` line — don't fail the core legs' tick). Add `do_query`/`do_export` `type` branches if the source
   should appear in those actions.
7. **`agents/plugins/echo/meson.build`** — add the new `.cpp` to the
   `shared_library` sources; add any new Windows import lib (`dnsapi` for DNS).
8. **Content** (`content/definitions/`) — add `<source>_enabled` to
   `crossplatform.echo.configure` (the MCP/REST + GUI toggle path) and any canned
   `echo.sql` drill-downs.
9. **Server GUI** (optional) — the Capture-sources frame
   (`render_echo_capture_sources`) lists the eleven core sources (the original ten plus
   `registry`, which also adds the sixth `System` category chip) in a static array
   (`kSources` in `echo_process_tree.cpp`, plus the Push allowlist in
   `echo_tree_routes.cpp` and `kSrc` in `device_routes.cpp`); a new source is toggled through `echo.configure`
   until it is added to both; presentation metadata (category, always-on, `$`-name, badges)
   lives in that render function. Device-level panels (no pid) go in the
   process-tree pane (`render_echo_*_panel` + an `echo_tree_routes` fragment).
10. **Tests** — extend `test_echo_schema_registry.cpp` (every source has all three
    OS rows; every source in the `default_enabled=true` registry-wide invariant),
    `test_echo_diff.cpp` (appeared/removed + cap), `test_echo_warehouse.cpp` (DDL +
    `$`-name translation + authorizer), and add a `test_echo_<source>.cpp`; the roll-up pins are
    listed in section 3.1 ("Adding a source or tier").

**`usage` is not an example of this pattern.** It is a DERIVED source (a fold over
the process fold's events, `echo_usage.cpp`/`echo_usage.hpp`) — no `enumerate_<source>()`, no
`compute_<source>_events()` diff, no collector `.cpp` of its own. Its lifecycle
(`usage_set_enabled`/`usage_ensure_baselined`, echo_usage.cpp) runs on a
`Disabled`/`PendingBaseline`/`Active` state machine, not the diff/poll cadence
above. It still gets a `CaptureSourceDef` row in `build_sources()` (step 5) so
the schema/`$Name_Tier` translation/queryable-table allowlist machinery applies
uniformly, but a new capture source should follow the numbered steps above, not
`echo_usage.*`.

### 8.1 Streaming sources and the `ProcStreamCollector` contract

Most sources are snapshot-and-diff pollers (above). A **streaming source**
instead consumes a live kernel event feed (ETW, Endpoint Security, an nstat
kctl socket). The standing rule is: a streaming source implements the
`ProcStreamCollector` lifecycle contract — `start()` returns false → caller
degrades to the poll; `drain()` moves buffered events out each fast tick;
`dropped()`/`kernel_dropped()` for backpressure visibility; `stalled()` +
idle-fallback; `method_name()` for the status field — reusing the shared
`EventRing<T>` bounded ring, **never a hand-rolled parallel ring/retry path**.

The interface is **not required to be `ProcStreamCollector` itself** when the
drained event type is not `ProcEvent`. The established precedent is
`ImageStreamCollector` (module loads, `docs/echo-module-loads.md` §M1): a
**sibling interface with the identical lifecycle contract**, because its
drained type is `ModuleEvent`. The contract, not the base class, is the
invariant.

**`BoundedPendingQueue<Event>` (`echo_cursor.hpp`, Wave 6) is a third bounded
buffer in this plugin and a deliberate exception to "reuse `EventRing<T>`.**
It exists because a cursor source's drain must be NON-DESTRUCTIVE: entries stay
queued until the event+cursor transaction commits, and are then released by
SEQUENCE, so a failed insert retries the same batch and an overflow eviction
between snapshot and ack cannot destroy an entry that was never committed.
`EventRing<T>`'s `drain()` removes on read, which cannot express that. Use
`EventRing<T>` for a stream whose loss is acceptable and counted; use
`BoundedPendingQueue` when the events are forensic and the sink is
transactional. Do not add a fourth.

**The `registry` source (`echo_registry_source.{hpp,cpp}`, pure core in
`echo_registry_parsers.hpp`) is the third `CursorSource` and the precedent for a
cursor source whose durable state is a snapshot baseline plus a position
cursor.** What it adds to the pattern:

- **Two stores, one transaction.** What changed comes from a
  `RegNotifyChangeKeyValue` subtree watch and a per-root baseline diff; each
  root's baseline lives in an `echo_state` row (`registry:<root>`) and is written
  by `insert_registry_events_and_cursor` (a fold) in the SAME transaction as the rows and
  the cursor, so a baseline can never advance without the rows that explain it.
  A baseline read goes through the tri-state `try_get_state`; `get_state`'s
  empty-on-failure would read a transient SQLite error as "no baseline" and
  silently re-baseline. The baselines hold each value's type, size and hash (a baseline an
  older build wrote also holds a rendered prefix) and are readable through
  `echo.sql`;
  `purge_source("registry")` erases the tiers, the replay ring, the cursor row and every
  `registry:%` baseline in one transaction.
- **Four read statuses.** Complete, Absent, Unreadable, Capped. Removals are
  derived only from Complete and Absent reads; an Unreadable read changes
  nothing and a Capped one only adds and updates, so a partial read can never
  fabricate a deletion. Unreadable means the root, or any key beneath it other
  than an access-denied child, could not be read (an open, a query or an
  enumeration failure there makes the whole root Unreadable). Only an
  access-denied child is isolated: it is listed in the read's `skipped` set, the
  rest of the root is read as usual, and the diff keeps what the baseline holds
  beneath the denied key. That holds for up to `kSkippedCap` (32) children per
  read; the 33rd makes the read Capped, which derives no deletion in that root.
  A root going Unreadable, or the denied set gaining a member, writes one
  `gap:unreadable:<root>` row; the set is kept in the cursor so a steady state,
  a shrink or a clear writes nothing. A Capped read's list is partial, so it can
  add to the stored set but never shrinks it, and the stored set is clamped to
  `kSkippedCap` names so a root that stays Capped cannot grow the cursor row.
  Keys are opened with `REG_OPTION_OPEN_LINK`, so a watched key that is itself a
  symbolic link is recorded as the link (its `SymbolicLinkValue`) and its target
  is never followed: following it would let a user point this agent's SYSTEM
  token at a key they cannot read, and the price is that writes under a link a
  user planted over their own `Run` key are invisible. The reader's enumeration
  is index-driven, so `read_key` compares each key's value count, subkey count
  and last-write time before and after walking it; a difference means the key
  was written to mid-walk, and the read is Capped (no removals, root re-read at
  the next tick), never Complete, because a deletion at an index already passed
  would otherwise hide a surviving entry and report it removed.
- **Reconcile.** Every `kReconcileEveryTicks` (12) slow ticks every root is
  re-read whether or not the watch fired (hourly at the default 300 s
  `slow_interval`). It finds what the watch missed (a notify lost to a watcher
  that is not running, an unarmed root) and a child that became denied after the
  last read: the watch mask is `NAME | LAST_SET`, so a permission change raises
  nothing.
- **A root's first read is silent.** A root not yet baselined (first run, a user
  hive loaded at logon, a user who logged off and back on, a re-enable) has its
  first read taken as the baseline, with no rows. Writes made to it between the
  hive loading and that read, up to one slow interval, are folded into the
  baseline and are not recorded; no per-root gap row is written, since a logon
  would add one per root per user.
- **Rows land in the tick that observes the change, or the next one, and the writer is
  correlated, not verified.** A candidate is held only while `now - window_hi <
  kEtwSettle100ns` (5 s), and a notify window closes 1 s after the last notify, so a
  burst that ended more than about 6 s before the tick is written in that same tick;
  a burst nearer the tick, and every change found without a key-watch notify (the
  hourly reconcile, or a root with no live watch: its window ends at the end of the
  read, after `now`), is held to the next one. A change whose marker
  cannot depend on a later event (`attr:off`, `attr:lost-restart`: both are decided
  before any event is consulted and only ever become more true within a run) is not
  held at all and is written in the tick that sees it, so a restart's whole
  reconcile (every change in it is `attr:lost-restart`) never sits in the cursor
  row; `attr:degraded` is held like any other, since a later tick can still record
  a loss over its window. The mechanism, the `attr:*` precedence, loss epochs and
  exactly what an attribution does and does not establish are written once, in the
  banner of `echo_registry_parsers.hpp` (the row key: `registry_diff_record_key`),
  with its residuals: a change that had no value-write event, an event delivered
  more than the settle interval after its window closed with no counted loss (a
  starved consumer, suspend/resume), an ambiguity any local process can force, and
  an `actor_image` read when the event was delivered. Every user-manual sentence
  must keep saying "a lead to verify, not proof".
- **`RegistryEtwBuffer` is not `BoundedPendingQueue`.** It releases by sequence
  identity like `ack_through`, but selectively: after a commit it retires the
  events older than the minimum root `window_base` (`retention_watermark`) that
  no held candidate's window covers (`release_event`). The events a held
  candidate still needs are interleaved with ones it does not, which a prefix
  release cannot express. `EventRing` (`echo_proc_stream.hpp`) was not reused for the
  same reason: it evicts by position, and this buffer must release selectively by
  sequence identity. It is not persisted: a restart, or a disable and
  re-enable, loses it, and the candidates it would have attributed are written
  `attr:lost-restart`. A root that is never completely read keeps its
  `window_base` at 0 and is left out of the watermark while it has no unread
  notify: every wide-window candidate of such a root has `window_lo` 0, before
  `events_since`, so it finalises `attr:lost-restart` whatever the buffer holds,
  and an idle one that stays Capped does not pin the buffer for the fleet. An
  unread notify changes that. A root the read budget deferred, or one marked
  again while it was being read, has no candidate yet, so the held-window test
  protects nothing of it: its next read builds a narrow window from the first
  unread notify, and until that read the floor stays at
  `max(window_base, first - slack)` (the pending stamps are passed to
  `retention_watermark`; the same floor ages the loss epochs). The pin ends when
  the root is read, which the fair rotation bounds. A root that was complete once
  keeps its last `window_base` whatever its status afterwards (`retention_watermark`
  is status-blind on purpose: its next wide-window diff, hourly or on recovery,
  would otherwise be correlated to a bystander with no loss recorded). An idle root
  therefore holds the watermark up to an hour back, since the hourly reconcile
  re-reads every root, and one that stays Unreadable or Capped holds it there for as
  long as it does. The buffer fills to the cap (65536 events: about 18 host-wide
  registry writes per second against a root last read an hour ago, about 110 against
  one last read ten minutes ago) and the eviction shows as recurring `gap:loss`
  rows and `attr:degraded`, marked and never silent (no volume guard is added).
  Lifting the pin would need a retained-floor marker in the cursor and a stitch rule
  that a window starting below it is `attr:degraded`: a design change, not a fix.
- **The cursor row is a third content store.** Besides the rows and the
  baselines, `held` carries each waiting candidate's rendered new value (and its
  old value only when the baseline came from an older build) until the next tick at most (readable through `echo.sql` as `echo_cursor`; erased by
  `purge_source("registry")`). A candidate held when the source is disabled stays in
  the row until re-enable (then written `attr:lost-restart` with its original
  `observed_at`; the disable does not drop it, since it is a change observed before
  the pause and the re-enable re-baselines silently) or `purge_source` on the paused
  source. Cursor decode treats `window_base`, `held` and `loss` as optional so a
  cursor written by the key-watch-only source decodes as present; a malformed one
  would re-baseline every root. The cursor is written as version 2 whenever it
  holds `held` or `loss` and as version 1 otherwise; decode accepts both and
  takes any other version as lost (`gap:cursorlost`, re-baseline). That is what
  makes a rollback loud: the key-watch-only build reads only version 1, so it
  takes a cursor holding changes as lost, where a build that ignored the unknown
  field would re-encode the cursor without them and drop changes whose baseline
  had already advanced, with no row. Decode also clamps a held candidate's window
  to a non-negative, ordered one, so a corrupt row cannot overflow the stitch's
  `now - window_hi`.
- **The Windows ETW code has no unit seam and no fault-injection test of the
  callback.** `WinEtw` (the session and consumer handles each behind a RAII
  owner, one `ProcessTrace` worker, a `noexcept` callback that contains every
  exception and counts a decode failure) is covered by compile plus the
  `[registry][windows]` live cases, which need an elevated agent and SKIP with a
  named reason otherwise. Teardown order is explicit in `WinEtw::stop()`:
  CloseTrace (it unblocks `ProcessTrace`), join, then stop the session. A
  session that cannot open is degrade-not-fail (`registry_capture_method` =
  `notify`, rows `attr:off`; the start-failure warning carries the Win32 error);
  one that dies after it opened is logged once and not restarted. The session takes the default
  ETW security descriptor (the sibling sessions set none either), so members of
  Performance Log Users can attach to the stream (value names, pids and sizes,
  system-wide) or stop it; a stop is detected (`ProcessTrace` returns) and shows
  as `attr:off`. The image name is looked up once per pid when its first event is
  delivered, refused when the process was created after the event (the pid was
  reused), and cached for five minutes, so it can be stale under pid reuse. The
  session name is salted with the agent's pid, so a crash leaks the session until
  the host restarts and only a successor with the same pid stops it (the
  `ERROR_ALREADY_EXISTS` retry); the sibling `YuzuEchoProcEtw` and `YuzuEchoModuleEtw`
  sessions leak the same way and nothing sweeps `YuzuTar*` sessions at start. The
  operator runbook (`logman query -ets`, `logman stop <name> -ets`) is in the
  manual's Health bullet.
- **Windows warehouse columns are NOT NULL.** "Not applicable" is `''`/`0`, and an
  empty `data_type` distinguishes an absent value from an empty one.

**`NstatClient` (`echo_netqual_nstat.*`) is the second such case and a
deliberate, documented exception to a literal `ProcStreamCollector` subclass:**

- Its drained lifecycle type is `NstatFlowEvent` (a TCP 4-tuple open/close),
  not `ProcEvent`, so — exactly like `ImageStreamCollector` — it cannot be a
  `ProcStreamCollector` subclass without templating that base on its event
  type.
- It carries **one extra verb the streaming contract has no room for**:
  `snapshot_quality()`, a repeatable live-table read (no drain) that feeds the
  `netqual` quality leg. One kctl socket backs **two** consumer surfaces (the
  tcp lifecycle stream *and* the netqual snapshot), which the single-stream
  `ProcStreamCollector` shape does not model.
- It nonetheless **honours the contract verbatim**: `EventRing<NstatFlowEvent>`
  reused (not forked), the same `start()/drain()/dropped()/kernel_dropped()/
  stalled()/method_name()` surface, the same degrade-to-poll fallback. It adds
  no parallel backpressure or retry idiom.

If a future streaming source's drained type *is* `ProcEvent`, subclass
`ProcStreamCollector` — do not add a third parallel interface. A new sibling
interface is justified only by a genuinely different drained type, as here.
