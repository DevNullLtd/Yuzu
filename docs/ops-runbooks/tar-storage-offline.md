# Runbook: TAR storage offline on an endpoint

Background: `docs/user-manual/tar.md` "The retention clock guard", issue #2361.

> **There is no alert for this.** The agent has no `/metrics` endpoint, TAR's
> guard counters are in-memory and reset on agent restart, and the offline state
> is only visible if someone runs `tar status` against the device or opens its
> Capture-sources frame. An endpoint whose forensic window has stopped being
> collected is exactly the endpoint least likely to be interrogated. Treat this
> runbook as reactive until a fleet-wide signal exists (tracked follow-up).

## Symptom

`tar status` returns non-zero and replies with two lines and nothing else:

```
error|TAR storage is offline on this endpoint; the database was closed after a
transaction could not be rolled back. ...
storage_state|offline
```

Note the ORDER: `error|` comes first, because server and dashboard consumers key
off the output starting with `error|`. On the dashboard, `/tar` Capture-sources
and the `/device` page both surface that line instead of the sources grid.

## What has actually happened

A retention or collector transaction failed, and the ROLLBACK that followed ALSO
failed with the transaction still open. Rather than let subsequent writes join a
transaction that will never commit - being reported durable and then lost at
restart - the agent CLOSES the TAR database. Every `TarDatabase` method then
fails closed.

**Impact while offline:**
- Collection has stopped. No new TAR data for this device.
- Retention has stopped. The device's retention commitment is NOT being met.
- `tar configure` will not persist.
- Historical data is usually still READABLE through `tar sql`, which uses a
  separate read-only connection. The `error|` line tells you whether that is
  true on this device - do not assume it.

## Recovery

**Restart the agent.** That is the only recovery; there is no automatic
re-open. The database file itself is normally intact - this is a connection
state problem, not corruption.

After restart, confirm with `tar status`:
- `storage_state|ok` as the first line
- `record_count` present and increasing on subsequent polls

## Diagnosis before you restart

Restarting clears the evidence, so collect first:

1. Agent log around the failure - look for `TarDatabase: ROLLBACK failed and the
   connection is STILL in a transaction`. The sqlite error text on that line is
   the actual cause.
2. **Disk space** on the agent's data volume. A full disk is the most likely
   cause, and restarting into a still-full disk simply reproduces it on the next
   rollup tick - a sawtooth of dark endpoints.
3. Filesystem health and permissions on `tar.db`.
4. Whether the device was force-powered-off mid-write.

## Escalate when

- The same device goes offline repeatedly after restarts, especially with disk
  space available. That suggests filesystem or storage-layer faults.
- Many devices report it at once - look for a common image, deployment, or
  storage backend rather than treating each individually.

## Related states that are NOT this

- `retention_guard_declines_total` non-zero with `storage_state|ok`: the clock
  guard declined a pass. Different problem; nothing was deleted, and it usually
  means the device's clock moved or it was dark for more than 30 days. No action
  beyond fixing time sync.
- `retention_guard_failures_total` non-zero with `storage_state|ok`: one or more
  tables could not be probed or deleted. Retention has stopped for those tables
  specifically, so `tar.db` grows. Check the per-table
  `retention_guard_failed|<table>|<n>` lines.

Read the two totals TOGETHER: a zero declines total only means the clock is
behaving if the failures total is also zero.
