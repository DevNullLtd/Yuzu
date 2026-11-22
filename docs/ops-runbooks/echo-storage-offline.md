# Runbook: Echo storage offline on an endpoint

Background: `docs/user-manual/echo.md` "The retention clock guard", issue #2361.

> **Alert coverage.** Two different states report `storage_state|offline`:
>
> - **Offline at open** (`storage_state|offline|<reason>`: `free_space`, `migration_failed`,
>   `open_failed`). The agent retries by itself (below) and the fleet sees it: heartbeat tag
>   `yuzu.plugin.echo.storage_offline`, gauge `yuzu_fleet_echo_storage_offline{reason}`, alert
>   `YuzuEchoStorageOffline` (held 30 minutes). See "Offline at open: the agent retries".
> - **Wedged rollback** (bare `storage_state|offline`, the rest of this runbook). **There is no alert
>   for this.** The agent has no `/metrics` endpoint, Echo's guard counters are in-memory and reset on
>   agent restart, and the offline state is only visible if someone runs `echo status` against the
>   device or opens its Capture-sources frame. An endpoint whose forensic window has stopped being
>   collected is exactly the endpoint least likely to be interrogated. Treat this part as reactive
>   until a fleet-wide signal exists (tracked follow-up).

## Offline at open: the agent retries

`echo status` replies with `error|` first and then `storage_state|offline|<reason>`:

| Reason | Meaning | What to do |
|---|---|---|
| `free_space` | The volume holds less than twice `echo.db` plus its write-ahead log; the v10 migration was refused and nothing changed. | Free the space. The agent checks again at its next retry; no restart is needed. |
| `migration_failed` | The v10 roll-up step failed (the agent log names the table, key or row), ran past its per-attempt deadline, or waited on an earlier migration step that had not finished. The file is untouched. | Read the agent log. A damaged mark or an out-of-range bucket needs the repair in `docs/user-manual/upgrading.md` ("Behaviour change: Echo stores roll-ups only"), made on the STOPPED agent; a lock or a full volume clears by itself. |
| `open_failed` | Any other failure met on a retry, or collection failed to start after the database opened. | Read the agent log. If the log says the collection start failed, restart the agent. |

The agent retries the open 1, 5 and 15 minutes after the first failure and then hourly, with no
limit. Each migration attempt is bounded by a deadline (60 seconds plus 2 seconds per MiB of the
file, doubled for every attempt that ran out of time, capped at one hour) and rolls back if it
hits it. A failure that repeats costs a full read of the file (the integrity check) per attempt
and, when it reaches the migration, a write-ahead log that can outgrow the file (measured at 1.35
times the file in one run; no general bound is proven); it does not fix itself, so repair or
escalate rather than wait. Collection stays stopped until an attempt succeeds, then
`storage_state|ok` returns on its own.

## Symptom

`echo status` returns non-zero and replies with two lines and nothing else:

```
error|Echo storage is offline on this endpoint; the database was closed after a
transaction could not be rolled back. ...
storage_state|offline
```

Note the ORDER: `error|` comes first, because server and dashboard consumers key
off the output starting with `error|`. On the dashboard, `/echo` Capture-sources
and the `/device` page both surface that line instead of the sources grid.

## What has actually happened

A retention or collector transaction failed, and the ROLLBACK that followed ALSO
failed with the transaction still open. Rather than let subsequent writes join a
transaction that will never commit - being reported durable and then lost at
restart - the agent CLOSES the Echo database. Every `EchoDatabase` method then
fails closed.

**Impact while offline:**
- Collection has stopped. No new Echo data for this device.
- Retention has stopped. The device's retention commitment is NOT being met.
- `echo configure` will not persist.
- Historical data is usually still READABLE through `echo sql`, which uses a
  separate read-only connection. The `error|` line tells you whether that is
  true on this device - do not assume it.

## Recovery

**Restart the agent.** That is the only recovery; there is no automatic
re-open. The database file itself is normally intact - this is a connection
state problem, not corruption.

After restart, confirm with `echo status`:
- `storage_state|ok` as the first line
- `record_count` present and increasing on subsequent polls

## Diagnosis before you restart

Restarting clears the evidence, so collect first:

1. Agent log around the failure - look for `EchoDatabase: ROLLBACK failed and the
   connection is STILL in a transaction`. The sqlite error text on that line is
   the actual cause.
2. **Disk space** on the agent's data volume. A full disk is the most likely
   cause, and restarting into a still-full disk simply reproduces it on the next
   rollup tick - a sawtooth of dark endpoints.
3. Filesystem health and permissions on `echo.db`.
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
  specifically, so `echo.db` grows. Check the per-table
  `retention_guard_failed|<table>|<n>` lines.

Read the two totals TOGETHER: a zero declines total only means the clock is
behaving if the failures total is also zero.
