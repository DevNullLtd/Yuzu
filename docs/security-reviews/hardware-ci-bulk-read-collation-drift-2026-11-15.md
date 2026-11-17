# Bulk device-CI read: database collation drift, evidence and residual

**Date:** 2026-11-15
**Change:** `GET /api/v1/hardware-ci` and the MCP tool `list_hardware_ci_records` (a keyset walk over
`device_inventory_store.device_ci`, built for a daily pull into an external CMDB), with migration
`device_inventory_store` v4. Code commits under test: `390104150e` (the byte-ordered keyset), `e40adb34a9` (the byte-ordered
named read, the robust migration and the index check at open) and `fd490b9d31` (the exact index-shape
check), `f025c558a0` (the WARN text) and `a8bea07368` (the route rename to `GET /api/v1/hardware-ci`).
**Branch:** `feat/hardware-ci-bulk-read`
**Status:** implemented; the residual exposures below were accepted by the owner for release on 2026-11-15, with the review trigger the merge of PR 3 (the `device_ci` write pause). The acceptance is recorded in the section "Owner acceptance of the residual" and is not posted to GitHub.
Residuals 1, 3 and 4 below, and the Defect section's statements that the server stops no read and no write, describe the state before PR 3; "PR 3 outcome" records what the pause and the gate change.
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

The write-side consequences of the same drift are measured in the next section ("Independent
validation"); the growth figure of an earlier second setup (20,000 mixed ids, a single set-based
upsert, the table growing from 20,000 to 33,868 rows) is repeated in appendix C, with its oracle
corrected.

Cost of the index: the 317 ms a page quoted below was measured on PostgreSQL 18.4 with one million
rows and no index on the byte-ordered expression (every page a scan plus a sort); 16 concurrent
walkers saw an average of 3.3 s a page. With the index a page at depth took about 1 ms.

## Independent validation (2026-11-15)

A second reproduction, made while the fix round for this change was reviewed, measured the
consequences of the drift for every code path that goes through the primary key, using the ingest
and decommission shapes the server really issues. Setup: a throwaway `postgres:18.4-bookworm`
container, a libc `en_US.utf8` database, 20,000 `device_ci`-shaped rows with mixed-case,
punctuated and hexadecimal ids (6,000 `agent-NNNNNN`, 4,000 `Agent_N`, 4,000 `PC-N`, 6,000 upper and
lower case md5 strings), then `UPDATE pg_database SET datcollate='C'` and a reconnect, no `REINDEX`.
Each case was run on the table as it stood after the stated step.

| Case | Result |
|---|---|
| Point lookups by primary key (the hash-skip `SELECT`, the per-id reads `GET /api/v1/hardware/{id}` and MCP `get_hardware_ci`, the upsert conflict probe) over the 20,000 existing devices | 12,219 not found (61%) |
| Four full-ingest cycles, `INSERT ... ON CONFLICT (agent_id) DO UPDATE` once per device per cycle, physical rows after each cycle | 34,119, 36,151, 37,214, 37,842 (from 20,000) |
| `unique_violation` errors in those cycles | 0, 0, 34, 62 (ingest starts failing from the third cycle) |
| The byte-ordered keyset walk over the table after the four cycles | 37,668 rows served for 20,000 devices; 14,291 devices served more than once, with divergent content; for 115 devices the newest stored copy is not the copy served; no device missing |
| Decommission, `DELETE FROM device_ci WHERE agent_id = $1` once per device on a fresh 20,000-row table | every statement succeeds; 7,781 rows removed for 20,000 devices; 12,219 decommissioned devices stay stored |
| The walk after that decommission | serves 12,219 rows, the ghost devices |

A second independent run of the ingest case gave 20,000 to 33,868, 35,604 and 36,126 rows. On the
re-run made for this note (the same scripts, one run) every figure in the table was identical to the
first measurement, because the setup is deterministic.

What the table shows, in terms of mechanism:

- A stale primary key cannot find a row that exists, so the conflict probe of an upsert misses it and
  inserts a second physical row; later cycles add more. From the third cycle some inserts are also
  refused with `unique_violation`, which is a failed ingest for that device (the measured outcome;
  the path inside the index that produces it was not analysed).
- The byte-ordered walk reads the table in an order the stale primary key does not govern, so it
  sees nearly every physical row (37,668 of 37,842 in the run below: a `>` cursor drops a copy that shares its `agent_id` with a page boundary) and every device: duplicate rows for one device are served, with different content, and the
  copy served need not be the newest.
- The decommission statement succeeds and reports success whether or not it removed a row
  (`device_inventory_store.cpp`, near line 1176), so a device the stale primary key cannot find is
  never removed and the walk keeps serving it.
- `GET /api/v1/devices/{id}` reads the in-memory session registry (`device_api.cpp:49`,
  `lookup_device` through `registry_.get_session`): it answers only for a device with a live session
  on the serving replica. A long-offline device answers `404` although its record exists, so a `404`
  there is not evidence that a CI record was removed.

Caveats, all of which bound how these numbers may be used:

- This is a mechanical emulation (a catalogue `UPDATE` under an existing index), not a measured libc
  or ICU upgrade. The rates are an upper bound for a real upgrade, where only some ids change order;
  the mechanisms are what the note relies on.
- Each figure is from one run on one container (PostgreSQL 18.4).
- The index plans were forced with `enable_seqscan = off` (and `enable_bitmapscan = off`) for the
  primary-key cases, because a 20,000-row table would otherwise be read by a sequential scan that
  does not touch the stale index at all. A production table large enough to be served by its index
  behaves this way without the setting.

## The fix

- Migration `device_inventory_store` v4 adds `device_ci_agent_id_c_idx ON device_ci ((agent_id
  COLLATE "C"))`, additive and idempotent (`IF NOT EXISTS`, not `CONCURRENTLY`, because the runner
  applies a migration in a transaction).
- Every `agent_id` comparison in the read is spelled `COLLATE "C"`: the cursor bound, the scope
  membership test, the single-device filter and the `ORDER BY`. The result is the byte order of
  `agent_id`, which no library upgrade can change. Correctness comes from the `COLLATE` spelling; the index makes
  an index scan available for each page, and the plans measured on a representative table use it,
  which keeps the read from becoming a scan plus a sort per page (about 317 ms a page at one million
  rows, measured as above). The planner decides; nothing forces the plan.
- At each start the server checks that the index exists with the byte-ordered definition and logs a
  WARN naming the manual statement when it does not. The read stays correct without it.

## Residual exposures (not fixed by this change)

1. **The primary key and every write.** Upserts, decommission deletes, the hash-skip read and the
   per-id reads of `device_ci` still go through the primary key, which follows the drifting database
   collation. Measured on the emulation above (not a prediction for a real upgrade, see its caveats):
   61% of existing devices are not found by primary key, so the hash-skip and the per-id reads
   (`GET /api/v1/hardware/{id}`, MCP `get_hardware_ci`) report a stored device as missing, and so
   does the roster-keyed read that fills the CI columns of the device list (`list_device_ci_for`,
   `GET /api/v1/hardware`: it looks the roster's ids up in the primary key; not measured separately
   here, same mechanism); every
   full-ingest cycle adds physical rows (20,000 to 37,842 in four cycles) instead of updating them;
   from the third cycle ingest also fails with `unique_violation` for some devices (refused ingest);
   the byte-ordered walk then serves duplicate rows for one device with divergent content, and for
   some devices not the newest copy; and a decommission succeeds without removing the row (7,781 of
   20,000 removed), so ghost devices stay stored and the walk serves them. The stored data itself is
   not protected. This change fixes none of it; the write pause (PR 3) is the control.
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
   `GET /api/v1/devices/{id}` is not a substitute: it answers only for a device with a live session,
   so its `404` does not show that a record was removed. A CI is retired only through the
   integrator's own decommission process, never from absence in a walk or from that `404`.

## Contract for the follow-up change (PR 3)

PR 3 owns the write-side control. For this read it must:

- **Decide, deliberately, whether to withhold this read while the check reports a mismatch.** The
  read's SQL is correct under drift (byte-ordered, served by its own index), but the table contents
  may not be: duplicate and ghost rows can be present (residual 1). PR 3 chooses between serving the
  read with a caveat and refusing it while the mismatch gauge stands; either way it must NOT change
  the byte-order SQL or the index to do so.
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

## PR 3 outcome

PR 3 (#7730) adds the `device_ci` write pause and a read gate. This section records what it closes and
what it leaves; it is a design outcome, not new measurement, and it does not rewrite the sections above,
which describe the report-only state this note was written against (the Defect section and residuals 3
and 4 say the server stops no read and no write: that stopped being true when PR 3 merged). The code is
in `server/core/src/pg/pg_collation_check.{hpp,cpp}` (the gate), `device_inventory_store.{hpp,cpp}` and
`device_ci_ingestion.cpp` (the write pause), `device_ci_read_gate.hpp` and `hardware_ci_page_model.*`
(the read gate).

**What it closes.** Each replica keeps a gate derived from the last conclusive collation check:
Trusted, Mismatch (stays through checks that cannot run) or Unproven (no conclusive check since the
process started).

- Residual 1, writes: while the gate reads Mismatch, agent ingest of the device-CI source is refused
  before the blob is parsed (acknowledged `need_full`, so the agent resends in full on its backoff; no
  wire change), and the device-CI removal of a decommission is not attempted (reported as a failed
  store with a distinct reason, `details.write_paused`). `ci.last_seen` stops advancing while the
  pause stands. Unproven does not pause writes.
- Residual 1, reads by primary key: while the gate is not Trusted, the per-device CI read (`GET
  /api/v1/hardware/{id}`, MCP `get_hardware_ci`, the dashboard) and the roster-keyed CI columns of `GET
  /api/v1/hardware` answer in their existing degraded state instead of reporting a stored device as
  missing.
- Residual 4, the gate: this read (`GET /api/v1/hardware-ci`, MCP `list_hardware_ci_records`) is
  refused with a retryable `503` (`retry_after_ms` 60000) while the gate is not Trusted, with no
  override flag. The keyset SQL, its `COLLATE "C"` spellings and the `device_ci_agent_id_c_idx`
  expression are unchanged, and the cursor prefix stays `h1` (no epoch is bound into the cursor).

**What stays.**

- Residual 2, every other keyset read over a text key follows the database collation and is not gated.
- Residual 3, the detection delay: a replica sees a mismatch at its next check, up to about an hour
  after the drift begins, and decides for itself; writes in that window are not paused, and a write that
  passed the check just before the gate flipped is not stopped. Rows duplicated before the pause began
  are not repaired by it.
- Other stores' text-keyed unique indexes are not gated (`endpoint_state`, whose text primary key is
  written on every heartbeat, is a named example) and agent registration is not gated.
- A start whose first check cannot run leaves the gate Unproven (reads refused, writes accepted) until
  a repeat concludes, usually about a minute after the repeat thread starts. **Unproven is not always
  transient:** when the database records a collation version and the host reports none, or the catalog
  read is refused, or an INVALID index exists in the schema `device_inventory_store` while the two
  versions are equal (the hold-only guard below), every check is unreadable and the gate stays Unproven for as long as the state
  stands: the bulk read stays refused, the per-device CI reads stay degraded, writes are NOT paused, and
  there is no override flag (D3 stands). The documented catalog exit (setting the recorded version to
  NULL) needs a superuser, which managed PostgreSQL usually does not give (reasoned, not tested) and it
  also silences detection.
- A repeat thread that cannot start (a thread or task limit) leaves the gate as the start-time check
  left it until the next restart: a Mismatch gate then keeps writes paused and reads refused. The
  server logs an ERROR line; there is no retry of the thread start.
- The gate follows the version comparison, not proof of a rebuilt index: `REFRESH COLLATION VERSION`
  before the reindex has finished reopens writes and reads over stale indexes. The one guard, added in
  this change and HOLD-ONLY, is that a check finding the versions equal while an invalid index exists
  in the schema `device_inventory_store` (typically a failed `REINDEX ... CONCURRENTLY`) counts as could
  not run and holds the gate; it never enters Mismatch and never pauses writes.
- Replicas decide independently (a request behind a load balancer can be refused by one and served by
  another; a write can land on a replica still reading Trusted); a decommission during a pause leaves
  the device's CI row stored until the DELETE is re-issued after the repair; on resume every device
  whose sync fell due resends a full record within about 15 minutes, with no server-side admission
  limit (the sizing is an estimate: see the server-admin "Resume" paragraph). No audit row marks the
  start or end of a pause.
- Unverified, carried over: that `ALTER DATABASE ... REFRESH COLLATION VERSION` cannot record a first
  version when the database records none (measured once, on PostgreSQL 18.4), the emulation figures in
  this note (one run), and the roster-keyed read's misses (same mechanism, not measured separately).

**Why the gate stays although point reads could be made byte-ordered.** The alternative recorded here
is that the primary-key point reads (`get_device_ci`, the roster-keyed read) could be made correct under
a collation change by spelling their comparison `agent_id COLLATE "C" = $1`, which the byte-order index
from migration v4 serves. The gate stays anyway because the write side still arbitrates on the primary
key: `ON CONFLICT (agent_id)` follows the database collation, so a duplicated device is still written
twice, and a read of a duplicated device returns more than one row whichever way its comparison is
spelled. Making the point reads byte-ordered would hide the symptom without stopping the corruption.

**Owner review trigger.** The 2026-11-15 acceptance below names the merge of this change as its review
trigger, and the owner revisits it then. Nothing in the "What it closes" and "What stays" lists
records a new acceptance; the only new owner statements are the session decisions in the next
subsection, limited to what it lists.

### Owner session decisions, 2026-11-16

Recorded by the orchestrating session from the owner's answers in the working session. They are internal
decisions: not a signature, not independent review, not an external approval, and not posted to GitHub.
The first seven are the decisions D1 to D7 of the plan the change was built from; the last four are the
owner's answers to the governance run's findings on 2026-11-16.

- D1. The bulk read is REFUSED (retryable `503`, `retry_after_ms` 60000) while the gate is not Trusted;
  no override flag.
- D2. No ordering epoch in the cursor; the prefix stays `h1` (it means "the last device in byte
  order", which stays valid across a repair). This knowingly does not deliver the part of #7730's
  acceptance criterion 3 that asks for cursors bound to the ordering epoch (the other part, open
  residuals filed or accepted by the owner, is addressed by this section and the follow-up issues to be
  filed). The consequence is documented for integrators: after a collation refusal restart the walk from
  the first page.
- D3. Unproven refuses the reads but does not pause writes (a failed read of the facts is not evidence
  of a mismatch, and pausing every device's CI for it would be an outage of its own).
- D4. The per-device and roster-keyed CI reads degrade under the same condition.
- D5. A refused ingest is a distinct deferred outcome, not an error, decided at the ingest seam before
  the blob is parsed.
- D6. The change closes #7730 only once the follow-up issue for the other text-keyed stores (D7) exists;
  until then it says "Part of #7730".
- D7. Other stores' text-keyed unique indexes (`endpoint_state`, written on every heartbeat, is a named
  example) and agent registration are not gated; follow-up issue #8104. This is an exposure statement outside residuals 1 to 4 above.
- 2026-11-16, invalid index: a HOLD-ONLY guard ships in this change (an invalid index in the schema
  `device_inventory_store` holds the gate, never enters Mismatch).
- 2026-11-16, Unproven for ever: the case where the database records a version and the host reports
  none, or the catalog read is refused, is documented plainly; D3 stands; there is no override flag.
- 2026-11-16, residuals: replica skew, the detection delay of up to about an hour, other text-keyed
  stores including `endpoint_state` and agent registration, and the resume burst of full resends are
  accepted as design limits of this change (owner session decision, not a renewed 2026-11-15
  acceptance); they are disclosed in the manual and follow-up issues are #8104 (residuals) and #8105 (the resume burst and the refusal discriminator).
- 2026-11-16, repeat thread start failure: an ERROR log and the documentation, no retry machinery.

## Owner acceptance of the residual

The repository owner accepted residual exposures 1 to 4 (the list above, including the measured
write-side behaviour) for release.

- Decision recorded by the orchestrating session from the owner's answer in the working session; it
  is not a signature and not an external approval.
- Owner: the repository owner (Dave).
- Date: 2026-11-15.
- Scope: residual exposures 1 to 4 above. Item 5 (a walk is not a snapshot) is a rule for consumers of
  the read, not an accepted exposure.
- Review trigger: the merge of PR 3, the change that adds the `device_ci` write pause. The
  acceptance is revisited then. The owner set no end date.
- No GitHub comment was made. The pull request description is expected to repeat this record.

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
CREATE TABLE ids AS SELECT agent_id FROM t;
\c postgres
UPDATE pg_database SET datcollate = 'C' WHERE datname = 'ch2';
\c ch2
SET enable_seqscan = off;
INSERT INTO t (agent_id, x) SELECT agent_id, 1 FROM t ON CONFLICT (agent_id) DO UPDATE SET x = 2;
RESET enable_seqscan;
SELECT count(*) AS rows_after, count(DISTINCT agent_id) AS distinct_ids FROM t;
```

The first run of this note counted distinct ids with `count(DISTINCT agent_id)` and got `distinct_ids`
33,864. That figure is an artefact and must not be used: the planner answers that query with an index-only
scan of the stale primary key (`Index Only Scan using t_pkey`), whose order no longer matches the
comparison the distinct step uses, so equal ids are not adjacent and are counted more than once. With
index scans disabled the same `count(DISTINCT agent_id)` returns 20,000, which is the true number of
distinct ids. Use an oracle that does not touch the index: force a
sequential scan and group by the byte value of the id, which is a hash aggregate.

```sql
SET enable_indexscan = off; SET enable_indexonlyscan = off; SET enable_bitmapscan = off;
SELECT count(*) AS rows_total FROM t;
SELECT count(*) AS distinct_ids
  FROM (SELECT agent_id COLLATE "C" FROM t GROUP BY agent_id COLLATE "C") g;
SELECT count(*) AS ids_with_more_than_one_row
  FROM (SELECT 1 FROM t GROUP BY agent_id COLLATE "C" HAVING count(*) > 1) g;
-- the stored id set equals the original id set, compared by hash (needs `CREATE TABLE ids AS
-- SELECT agent_id FROM t` before the drift)
SELECT md5(string_agg(agent_id, ',' ORDER BY agent_id COLLATE "C"))
  FROM (SELECT DISTINCT agent_id COLLATE "C" AS agent_id FROM t) d;
SELECT md5(string_agg(agent_id, ',' ORDER BY agent_id COLLATE "C")) FROM ids;
```

On the re-run, with the original `count(DISTINCT agent_id)` still reading 33,864: `rows_total` 33,868,
`distinct_ids` 20,000, `ids_with_more_than_one_row` 13,868 (20,000 plus 13,868 is 33,868), and the two
md5 values equal (`d9648d27d72b3f6b4fa9dd12a3124e1f`), so no device was lost and 13,868 were
duplicated. One run on one container.
