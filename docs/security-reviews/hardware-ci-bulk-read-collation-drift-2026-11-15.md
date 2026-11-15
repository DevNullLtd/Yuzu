# Bulk device-CI read: database collation drift, evidence and residual

**Date:** 2026-11-15
**Change:** `GET /api/v1/hardware-ci` and the MCP tool `list_hardware_ci_records` (a keyset walk over
`device_inventory_store.device_ci`, built for a daily pull into an external CMDB), with migration
`device_inventory_store` v4. Code commits under test: `390104150e` (the byte-ordered keyset), `e40adb34a9` (the byte-ordered
named read, the robust migration and the index check at open) and `fd490b9d31` (the exact index-shape
check).
**Branch:** `feat/hardware-ci-bulk-read`
**Status:** implemented; owner acceptance of the residual exposures below is PENDING and not recorded.
**Author of the measurements:** the change author's governance run (Claude Code session). The
independent reproductions below were made during review, by a separate reviewer in that run.

This note records what was measured, what the fix covers, and what it does not.

## The defect

A text primary key is ordered by the database's default collation, which comes from the operating
system's C library (or ICU) when the database is created. If a library or operating-system upgrade
changes the collation rules under an existing database, the primary key index no longer matches the
order the server's `ORDER BY` and `>` comparisons use. A keyset walk (`WHERE agent_id > $cursor ORDER
BY agent_id LIMIT n`) then silently skips rows. The server detects the mismatch only by reporting a
gauge (`yuzu_pg_collation_version_mismatch`, up to about an hour after the drift begins) and stops no
read.

## Method

A throwaway PostgreSQL 18.4 container (`postgres:18.4-bookworm`), a libc `en_US.utf8` database, and
50,030 mixed-case and punctuated `agent_id` values in `device_ci`, the index built fresh. The database
collation was then changed under the existing primary key index with
`UPDATE pg_database SET datcollate='C'` and no `REINDEX`. The exact statements are in the appendix.

This is a mechanical emulation of a libc or ICU upgrade, not a measured glibc version bump. The
results below illustrate the mechanism only; a real upgrade differs (which ids move, and so how many
rows a walk skips, depends on the old and new rules and on the ids).

## Results

| Case | Page size (`limit`) | Ids seen of 50,030 | Skipped | Duplicates | Error |
|---|---|---|---|---|---|
| Healthy | 1, 7, 1000 | every id once | 0 | 0 | none |
| Drifted, database-collation keyset | 1 | 38,085 | 11,945 | 0 | none, normal ending |
| Drifted, database-collation keyset | 7 | 38,097 | 11,933 | 0 | none, normal ending |
| Drifted, database-collation keyset | 1000 | 39,003 | 11,027 | 0 | none, normal ending |
| Drifted, `COLLATE "C"` keyset on a `COLLATE "C"` index | (page size not recorded) | all 50,030 | 0 | 0 | none |

The failure is silent: no error, a normal end of walk, and a consumer that retires devices absent
from the pull would retire real ones.

An independent reproduction during review, on the named single-device read (setup: 50,000 mixed ids,
the primary key built under `en_US.utf8`, `datcollate` then set to `C`, no `REINDEX`): after the
collation change, `agent_id = $1` served by the primary key missed 32,764 existing ids, and
`agent_id COLLATE "C" = $1`, served by the new index, missed none. This mattered because the
documented safety step for a consumer is to confirm a device with `?agent_id=<id>` before retiring it.

The same independent reproduction, in a second setup (20,000 mixed ids, the same collation change, then
an upsert of every existing id with `INSERT ... ON CONFLICT (agent_id) DO UPDATE` under drift),
observed the table grow from 20,000 to 33,868 rows (a stale primary key admitting a second row for an
`agent_id` that exists). That figure illustrates the write-side exposure below and is not relied on.
Both reproductions are in the appendix and were re-run when this note was written (the named-read
count came out at 32,792 on that run, the growth at 33,868 again).

Cost of the index: the 317 ms a page quoted below was measured on PostgreSQL 18.4 with one million
rows and no index on the byte-ordered expression (every page a scan plus a sort); 16 concurrent
walkers saw an average of 3.3 s a page. With the index a page at depth took about 1 ms.

## The fix

- Migration `device_inventory_store` v4 adds `device_ci_agent_id_c_idx ON device_ci ((agent_id
  COLLATE "C"))`, additive and idempotent (`IF NOT EXISTS`, not `CONCURRENTLY`, because the runner
  applies a migration in a transaction).
- Every `agent_id` comparison in the read is spelled `COLLATE "C"`: the cursor bound, the scope
  membership test, the single-device filter and the `ORDER BY`. The result is the byte order of
  `agent_id`, which no library upgrade can change, and each page is an index scan. Correctness comes
  from the `COLLATE` spelling; the index keeps the read from becoming a scan plus a sort per page
  (about 317 ms a page at one million rows, measured as above).
- At each start the server checks that the index exists with the byte-ordered definition and logs a
  WARN naming the manual statement when it does not. The read stays correct without it.

## Residual exposures (not fixed by this change)

1. **The primary key and every write.** Upserts into `device_ci` still go through the primary key,
   which follows the drifting database collation. A stale primary key can admit a second row for an
   existing `agent_id`. The stored data itself is not protected, and this read would serve the pair
   twice; a page boundary between the two copies would hide one of them.
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

## Contract for the follow-up change (PR 3)

PR 3 owns the write-side control. For this read it must:

- **Not gate this read on the collation check.** The read no longer depends on the database
  collation, so a refusal on a failed or mismatching check would make a safe read unavailable.
- **Not bind an ordering epoch into this read's cursor.** If it binds anything, it must bump the
  cursor prefix from `h1` to `h2`, because `h1` now means "the last device in byte order" and an old
  cursor would otherwise be read under a different meaning.
- **Ship the `device_ci` write pause.** Writes and the primary key remain exposed (residual 1), and
  the pause is the control for them.
- **Leave the keyset SQL and the C index expression untouched.** The query's `COLLATE "C"`
  spellings and the `((agent_id COLLATE "C"))` index must stay byte-for-byte what they are, or the
  index stops serving the query.
- **Rewrite the "only reports" sentences in the docs** (`rest-api.md`, `inventory.md`,
  `mcp.md`, `server-admin.md`, the SOC 2 answer, the changelog fragment and the OpenAPI description) once
  the pause ships, because "the server only reports a mismatch and stops no write" stops being true.

## Owner acceptance of the residual: PENDING, not recorded

No owner has accepted residual exposures 1 to 4. This section is a placeholder and does not record an
acceptance.

- Owner: (not recorded)
- Date: (not recorded)
- Review trigger: (not recorded)

## Appendix: reproduction

Image `postgres:18.4-bookworm` (libc locale `en_US.utf8` is built into it), a superuser connection, a
scratch container. Run everything with `psql -v ON_ERROR_STOP=1`. The commits under test are listed at
the top. The id load below reproduces the shape of the original id set (mixed case, punctuation,
digits) and has the same count; the original set is not preserved, so the skip counts you get will
not match the Results table. The mechanism is the same: the drifted walks end normally and serve
fewer ids than exist (on the re-run made for this note, 7 ids at `limit` 1 and 1,005 at `limit` 1000),
while the `COLLATE "C"` walks serve all 50,030.

### A. The keyset walk (CH-1 rig)

Setup, as the superuser, connected to the `postgres` database:

```sql
CREATE DATABASE ch1 TEMPLATE template0 LOCALE_PROVIDER libc LOCALE 'en_US.utf8';
\c ch1
CREATE TABLE t (agent_id text PRIMARY KEY);
-- 50,000 generated ids in four shapes, plus 30 fixed punctuated ones
INSERT INTO t
SELECT CASE g % 4 WHEN 0 THEN 'agent-' || g
                  WHEN 1 THEN 'PC-' || g
                  WHEN 2 THEN 'Host_' || g
                  ELSE 'a-B' || g || '-z' END
FROM generate_series(1, 50000) g;
INSERT INTO t VALUES ('Agent-1'), ('agent_1'), ('agent-1'), ('agent1'), ('pc-0042'), ('Zeta'), ('zeta'),
  ('AB'), ('ab'), ('a b'), ('a-b'), ('a_b'), ('-x'), ('_x'), ('10'), ('2'), ('B-1'), ('b-1'), ('b_1'),
  ('Z-9'), ('z-9'), ('A1'), ('a1'), ('1a'), ('1A'), ('x y'), ('x-y'), ('X_Y'), ('x.y'), ('X.Y')
ON CONFLICT DO NOTHING;
ANALYZE t;
SELECT count(*) FROM t;
```

The walk and its oracle. `walk(lim, coll)` pages through `t` with a keyset walk and records every id
it served; `coll` is the empty string for the database-collation query and ` COLLATE "C"` for the
shipped one. The four result rows are the rows served, the distinct ids, the ids of `t` missing from
the walk (`EXCEPT`) and the ids served more than once.

```sql
-- walk(lim, coll): serve t page by page with a keyset walk, record every id served.
-- coll is '' (database collation, the old query) or ' COLLATE "C"' (the shipped query).
CREATE OR REPLACE FUNCTION walk(lim int, coll text) RETURNS TABLE (k text, n bigint) LANGUAGE plpgsql AS $f$
DECLARE lastv text := NULL; ids text[]; pages int := 0; total int;
BEGIN
  DROP TABLE IF EXISTS walked;
  CREATE TEMP TABLE walked (seq serial, agent_id text);
  SELECT count(*) INTO total FROM t;
  PERFORM set_config('enable_seqscan', 'off', true);
  PERFORM set_config('enable_sort', 'off', true);
  PERFORM set_config('enable_bitmapscan', 'off', true);
  LOOP
    EXECUTE format('SELECT coalesce(array_agg(agent_id), ARRAY[]::text[]) FROM
                    (SELECT agent_id FROM t WHERE ($1 IS NULL OR agent_id%1$s > $1)
                     ORDER BY agent_id%1$s LIMIT $2) q', coll) INTO ids USING lastv, lim;
    EXIT WHEN coalesce(array_length(ids, 1), 0) = 0;
    INSERT INTO walked (agent_id) SELECT unnest(ids);
    lastv := ids[array_length(ids, 1)];
    pages := pages + 1;
    EXIT WHEN pages > 2 * total / lim + 50;   -- safety stop
  END LOOP;
  RETURN QUERY SELECT 'rows_served', count(*) FROM walked;
  RETURN QUERY SELECT 'distinct_ids', count(DISTINCT agent_id) FROM walked;
  RETURN QUERY SELECT 'missing_vs_oracle', count(*) FROM (SELECT agent_id FROM t EXCEPT SELECT agent_id FROM walked) m;
  RETURN QUERY SELECT 'duplicates', count(*) FROM (SELECT agent_id FROM walked GROUP BY agent_id HAVING count(*) > 1) d;
END $f$;
```

Healthy, then the C index, then the drift, then every walk again (reconnect after the `UPDATE`):

```sql
SELECT * FROM walk(1, '');            -- healthy: 50030 / 50030 / 0 / 0
SELECT * FROM walk(1000, '');         -- healthy: 50030 / 50030 / 0 / 0
CREATE INDEX t_agent_id_c_idx ON t ((agent_id COLLATE "C"));
ANALYZE t;
\c postgres
UPDATE pg_database SET datcollate = 'C' WHERE datname = 'ch1';   -- no REINDEX
\c ch1
SELECT * FROM walk(1, '');            -- drifted: ids missing, no error
SELECT * FROM walk(1000, '');         -- drifted: ids missing, no error
SELECT * FROM walk(1, ' COLLATE "C"');     -- all 50030, nothing missing
SELECT * FROM walk(1000, ' COLLATE "C"');  -- all 50030, nothing missing
```

The `UPDATE` of `pg_database.datcollate` is the emulation of a library change; PostgreSQL prints a
`database "ch1" has no actual collation version` warning on the next connection, which is expected.

### B. The named read, independent reproduction

The same table `t` and the same drifted database. For every id, count how many rows `agent_id = $1`
(primary key) and `agent_id COLLATE "C" = $1` (the new index) find:

```sql
\c ch1
SET enable_seqscan = off; SET enable_bitmapscan = off; SET enable_hashjoin = off; SET enable_mergejoin = off;
DO $$
DECLARE r record; n int; miss_pk int := 0; miss_c int := 0; tot int := 0;
BEGIN
  FOR r IN SELECT agent_id FROM t LOOP
    tot := tot + 1;
    EXECUTE 'SELECT count(*) FROM t WHERE agent_id = $1' INTO n USING r.agent_id;
    IF n = 0 THEN miss_pk := miss_pk + 1; END IF;
    EXECUTE 'SELECT count(*) FROM t WHERE agent_id COLLATE "C" = $1' INTO n USING r.agent_id;
    IF n = 0 THEN miss_c := miss_c + 1; END IF;
  END LOOP;
  RAISE NOTICE 'total %, named-read misses via the primary key %, via the C index %', tot, miss_pk, miss_c;
END $$;
```

On the re-run for this note: 32,792 of 50,030 misses through the primary key, 0 through the C index.

### C. The write-side growth, independent reproduction

```sql
CREATE DATABASE ch2 TEMPLATE template0 LOCALE_PROVIDER libc LOCALE 'en_US.utf8';
\c ch2
CREATE TABLE t (agent_id text PRIMARY KEY, x int NOT NULL DEFAULT 0);
INSERT INTO t (agent_id)
SELECT CASE g % 4 WHEN 0 THEN 'agent-' || g WHEN 1 THEN 'PC-' || g
                  WHEN 2 THEN 'Host_' || g ELSE 'a-B' || g || '-z' END
FROM generate_series(1, 20000) g;
\c postgres
UPDATE pg_database SET datcollate = 'C' WHERE datname = 'ch2';
\c ch2
SET enable_seqscan = off;
INSERT INTO t (agent_id, x) SELECT agent_id, 1 FROM t ON CONFLICT (agent_id) DO UPDATE SET x = 2;
RESET enable_seqscan;
SELECT count(*) AS rows_after, count(DISTINCT agent_id) AS distinct_ids FROM t;
```

On the re-run: `rows_after` 33,868, `distinct_ids` 33,864 (the table grew from 20,000 rows, with
duplicate `agent_id` values admitted through the stale primary key).
