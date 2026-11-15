# Bulk device-CI read: database collation drift, evidence and residual

Scope: `GET /api/v1/hardware/ci` and the MCP tool `list_hardware_ci_records` (a keyset walk over
`device_inventory_store.device_ci`, built for a daily pull into an external CMDB). This note records
what was measured, what the fix covers, and what it does not.

## The defect

A text primary key is ordered by the database's default collation, which comes from the operating
system's C library (or ICU) when the database is created. If a library or operating-system upgrade
changes the collation rules under an existing database, the primary key index no longer matches the
order the server's `ORDER BY` and `>` comparisons use. A keyset walk (`WHERE agent_id > $cursor ORDER
BY agent_id LIMIT n`) then silently skips rows. The server detects the mismatch only by reporting a
gauge (`yuzu_pg_collation_version_mismatch`, up to about an hour after the drift begins) and stops no
read.

## Method

A throwaway PostgreSQL 18.4 container, a libc `en_US.utf8` database, and 50,030 mixed-case and
punctuated `agent_id` values in `device_ci`, the index built fresh. The database collation was then
changed under the existing primary key index with `UPDATE pg_database SET datcollate='C'` and no
`REINDEX`.

This is a mechanical emulation of a libc or ICU upgrade, not a measured glibc version bump. The skip
rates below are therefore an upper-bound illustration of the mechanism, not a forecast for any real
upgrade.

## Results

| Case | Page size (`limit`) | Ids seen of 50,030 | Skipped | Duplicates | Error |
|---|---|---|---|---|---|
| Healthy | 1, 7, 1000 | every id once | 0 | 0 | none |
| Drifted, database-collation keyset | 1 | 38,085 | 11,945 | 0 | none, normal ending |
| Drifted, database-collation keyset | 7 | 38,097 | 11,933 | 0 | none, normal ending |
| Drifted, database-collation keyset | 1000 | 39,003 | 11,027 | 0 | none, normal ending |
| Drifted, `COLLATE "C"` keyset on a `COLLATE "C"` index | all | all 50,030 | 0 | 0 | none |

The failure is silent: no error, a normal end of walk, and a consumer that retires devices absent
from the pull would retire real ones.

A second reproduction, by the architect review, on the named single-device read: after the same
collation change, `agent_id = $1` served by the primary key missed 32,764 existing ids, and
`agent_id COLLATE "C" = $1`, served by the new index, missed none. This mattered because the
documented safety step for a consumer is to confirm a device with `?agent_id=<id>` before retiring it.

The same review observed table growth from 20,000 to 33,868 rows during an upsert run under drift (a
stale primary key admitting a second row for an `agent_id` that exists). That figure is reported as an
illustration of the write-side exposure below and is not relied on.

## The fix

- Migration `device_inventory_store` v4 adds `device_ci_agent_id_c_idx ON device_ci ((agent_id
  COLLATE "C"))`, additive and idempotent (`IF NOT EXISTS`, not `CONCURRENTLY`, because the runner
  applies a migration in a transaction).
- Every `agent_id` comparison in the read is spelled `COLLATE "C"`: the cursor bound, the scope
  membership test, the single-device filter and the `ORDER BY`. The result is the byte order of
  `agent_id`, which no library upgrade can change, and each page is an index scan. Correctness comes
  from the `COLLATE` spelling; the index keeps the read from becoming a scan plus a sort per page
  (about 317 ms a page at one million rows).
- At each start the server checks that the index exists with the byte-ordered definition and logs a
  WARN naming the manual statement when it does not. The read stays correct without it.

## Residual exposures (not fixed by this change)

1. **The primary key and every write.** Upserts into `device_ci` still go through the primary key,
   which follows the drifting database collation. A stale primary key can admit a second row for an
   existing `agent_id`. The stored data itself is not protected.
2. **Every other keyset read** in the server that orders or compares a text key by the database
   collation can still skip or repeat rows under drift.
3. **Detection delay.** The mismatch gauge is report-only and can lag the drift by up to about an
   hour; it stops no read and no write.
4. **PR 3.** A gate on a mismatch and a pause of writes while one stands belong to a later change
   (PR 3). Until it ships, items 1 to 3 stand.
5. **A complete walk is not a snapshot.** A device registered or removed during the walk, or a change
   of the caller's scope between pages, can be missed. A consumer confirms a device with
   `?agent_id=<id>` using a global-read credential before retiring it; an empty confirm page means no
   stored record or outside the credential's scope, so it is read as "not found", not "deleted".

## Owner acceptance of the residual: PENDING, not recorded

No owner has accepted residual exposures 1 to 4. This section is a placeholder and does not record an
acceptance.

- Owner: (not recorded)
- Date: (not recorded)
- Review trigger: (not recorded)
