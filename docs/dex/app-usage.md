# App usage: which executables ran on a device

DEX (Digital Employee Experience) app usage answers one question for one
device: which executables ran there recently, how often and for how long. A
second read, [fleet usage per application](#fleet-usage-per-application), answers
it across the fleet for each application on the Apps list.

[Back to the hub](README.md) | [Surface map](surfaces.md)

The dashboard panel and the per-device route are **per device**. Neither is
interactive-use or foreground time, and nor is the fleet read.

## What it is

For each executable on a device the projection holds:

- the first and last time it was seen, within the window Echo's usage tier keeps
  on the device (31 days; Echo has no setting to change it);
- the number of runs and the total run seconds over the trailing 30 days.

An executable is named by its lowercase file name. These reads never return a
full path, process id, command line or user name.

## Why it is useful

- **Check one device against what is installed.** Comparing a device's installed
  software with what ran there shows software nobody uses on that machine. The
  read is per device and keyed by executable name, so it is not a fleet-wide
  count.
- **Support questions.** "Has this application run on this laptop recently, and
  when last?" gets a direct answer.
- **What the data holds.** It is machine-scope run history. The projection that
  is served names executables and counts runs, and does not name users.

## What feeds it and how to enable it

1. Echo's **process source** records process starts and stops on the device.
2. Echo's **usage fold** pairs them into runs and keeps one row per executable
   per UTC day. It is on by default and controlled by Echo's `usage_enabled`
   setting, and coverage only begins once the source is active.
3. The **`app_usage` plugin** reads that fold read-only. Its `last_used` action
   is also what the agent's daily sync calls, roughly once a day, to send the
   projection to the server.
4. The server stores it and serves it through the routes below.

`--dex-disable` does not stop Echo or this sync. See
[collectors and plugins](collectors-and-plugins.md#the-app-usage-plugin).

## Using it in the dashboard

Open a device page and look for the **Application usage** panel. It lists each
executable with its first seen, last seen, runs and run seconds over the last 30
days, from the device's most recent daily report. The figures reflect that last
report, not the live device.

An executable missing from the list has not run inside the retained window. It
does not mean it never ran or is not installed.

## REST

`GET /api/v1/forensics/agents/{id}/app-usage` returns `{agent_id, apps[],
collected_at}`, where each app has `exe_key`, `first_seen`, `last_seen`,
`run_count_30d` and `total_seconds_30d`. `collected_at` is the collection time
the device reported, and the answer is the last stored report at whatever age it
is. An empty list with `collected_at` 0 means no report from the device has been
stored; an empty list with a real `collected_at` means it reported and nothing
had run inside its retained window. A degraded store returns `503`, never an
empty `200`.

## MCP

`get_agent_app_usage` takes `agent_id` and returns the same data. The fleet read
below has no MCP tool yet.

## Fleet usage per application

`GET /api/v1/dex/apps/usage` answers, for each application on the Apps list, how
many devices ran it, for how long and how often, and how often it crashed or hung
per hour of use. The rows are the Apps rows, in the same order (at most 100
applications). There is no dashboard view for it yet.

Parameters, all optional:

| Parameter | Values | Default |
|---|---|---|
| `window` | `24h`, `7d`, `30d`, `all` | `7d` |
| `platform` | `all`, `windows`, `macos`, `linux` | `all` |
| `slice` | `fleet`, `platform`, `group`, `tag` | `fleet` |
| `group` | a management group id, at most 256 bytes of text with no control characters (valid UTF-8); required with `slice=group`, refused otherwise | none |
| `tag_key` | a device tag key; refused unless `slice=tag` | `model` |
| `floor` | an integer from 1 to 10000 | `1` |

An off-enum or out-of-range value, a parameter given outside its slice and a
`group` that cannot name a group (empty, over 256 bytes, a control character or
invalid UTF-8) are a `400` that leaves no audit row and runs no read. A `group`
that is well formed but names no management group is also a `400`
(`unknown management group`); it is never a `200` with the whole fleet in the
`other` cell, and it does leave its audit row (see
[Fleet permissions and audit](#fleet-permissions-and-audit)).

Each application carries:

- `state`: `matched`, `no_usage` (no reporting device ran it) or `ambiguous_name`
  (its usage name is shared by two applications, so neither is attributed);
- `devices`, `run_seconds_30d` and `launches_30d`, summed over the devices that
  reported usage for it. `devices` is the real count when the figures are below
  the floor, `0` for `no_usage`, and `null` for `ambiguous_name`;
- `cells`: the same figures per cell of the slice (`fleet`; a platform; the group
  and everyone else; each tag value);
- `exposure_rate`: crashes plus hangs per process-hour of use (`per_hour`, an
  object of `estimate`, `lower`, `upper` and `reliable`, at the score policy's
  confidence level; `estimate` and `upper` are `null` when not finite), the
  `hours` of use it divides by, the raw `crashes` and `hangs`, and the `basis`;
  or `null` with `rate_withheld` naming why.

### How to read the figures

- **Estimated.** The agent reports a trailing 30-day total, so every response says
  `basis: estimated_from_30_day_usage`. The rate scales run time to the window
  (window days over 30). `window=all` has no length, and a window longer than the
  observation retention would need a second estimate, so those give
  `rate_withheld` of `unbounded_window` or `window_exceeds_retention` and no rate.
- **A withheld figure is `null`, never `0`.** An `ambiguous_name` application
  withholds its `devices` as well. `rate_withheld` is one of
  `below_floor`, `no_usage`, `ambiguous_name`, `unbounded_window`,
  `window_exceeds_retention`, `zero_usage` or `no_statistic`.
- **Fresh devices only.** A device counts only when the server received its usage
  state in the last 48 hours of the database clock (`freshness_window_hours`), so a
  replica clock that is out of step cannot change the count. `reporting_devices`
  and `stale_devices` count the devices that have reported usage at least once (a
  fresh and an older usage state respectively); `population` minus both is the
  devices that never have. A stale device adds to no figure. `population` is the
  devices in the platform scope online now, and `0` is a valid answer: every
  application then reads `no_usage`. A new fleet reads `no_usage` everywhere until
  the first daily usage sync lands.
- **Process-hours, not user hours.** Run time is summed per process run, so
  concurrent instances add up.
- **Raw crash and hang counts.** They are not capped per device. Events clustered
  on one crash-looping device make the interval falsely narrow, so read a narrow
  interval on a few devices with that in mind.
- **Cell kind is the key; a label is data.** A cell has a `kind` of `named`,
  `untagged` or `other`. A tag value of `other` or `(untagged)` is a `named` cell
  with that label, never the residual, so a consumer keys on `kind` and escapes
  the `label`.
- **At the default floor of 1 a cell can be one device's figures.** Raise `floor`
  to publish only cells of at least that many devices.

### The floor applies to one table only

`floor` is the least number of devices a published figure needs. A cell below it
merges into the `other` cell, and an application whose total is below it
publishes its device count only. That protects the table in front of you and
nothing else: two slices, two windows or a slice and the fleet total can be
subtracted to isolate a small group. Treat the floor as a guard on one response,
not on the set of responses a caller can ask for.

### Fleet permissions and audit

The route needs both `GuaranteedState:Read` and `Forensics:Read`, because the body
names the applications that crash. While RBAC is off, `Forensics:Read` is
administrator-only, so only an administrator can call it. Under RBAC the
permissions are checked across all of a principal's roles, so the route is open to
the Administrator role and to a principal assigned both the built-in Viewer role
(`GuaranteedState:Read`) and the ForensicsAnalyst role (`Forensics:Read`).
ForensicsAnalyst alone is refused because it lacks `GuaranteedState:Read`. A
service-scoped token is refused.

Every request that passes parameter validation writes a `dex.apps.usage.view`
audit row **before** the read, with an empty target and the request shape (window,
platform, slice, the tag key or group id asked for, floor). The row names no
device and no agent id. If the row cannot be stored the route answers `503` with
`Sec-Audit-Failed: true` and does not read. The row records the request that was
admitted, not its outcome: an unknown-group `400` or a `503` after the row still
leaves it, while a `400` for a malformed parameter is refused before it and leaves
none. Unlike the Apps list, this aggregate is audited, because it reads
Forensics-tier usage and at the default floor of 1 a cell can be one device's
figures.

The usage figures are computed over the caller's visible devices only: the route
hands the caller's device scope to the model, which filters its device list before
the figures are built. The application list itself is the fleet list that
`GuaranteedState:Read` already serves, so it is not filtered. The filter is inert
for every caller admitted today (with RBAC off only an administrator passes, and
`Forensics:Read` has no group-scoped tier), so this is not per-group confinement.

### Cache, budget and failure

- A built answer is reused for 30 seconds for an identical request and an
  identical visible device set, so `as_of` can be up to 30 seconds old. A failure
  is never cached.
- At most 4 fleet usage reads run at once. A request over that is a `503` with
  `concurrency_budget`, retryable. A usage request also takes one slot of the
  Apps list's own read budget, so heavy use of one can make the other answer
  `concurrency_budget`.
- A failed read is a `503` that names the reason, never a `200` with zero figures:
  `pool_acquire_timeout`, `query_error`, `statement_timeout`, `concurrency_budget`,
  `apps_degraded`, `group_unavailable` or `tag_unavailable` carry `retry_after_ms`
  2000. `no_population` (no fleet source wired) and `invalid_request` carry no retry
  hint, and so does `fleet_too_large` below. The four owner reasons
  (`pool_acquire_timeout`, `query_error`, `statement_timeout`, `concurrency_budget`)
  count `yuzu_server_guardian_read_degrade_total` with source `dex_usage`; the other
  causes count on the underlying store's own degrade family (`apps_degraded` on
  source `guardian_state` when the Apps read itself degraded, and on none when the
  score policy was unreadable, `group_unavailable` on
  `yuzu_server_mgmt_group_read_degrade_total`, `tag_unavailable` on
  `yuzu_server_tag_store_read_degrade_total`).

### Runbook: `fleet_too_large`

`fleet_too_large` means at least 3 consecutive statement timeouts spanning at
least 2 minutes with no success in between: the on-request read no longer fits its
10-second bound. A stall shorter than 2 minutes stays a retryable
`statement_timeout`; a database-wide stall of 2 minutes or more can reach
`fleet_too_large` too, and the first successful read clears it. The `503` carries
no `retry_after_ms`, because retrying a read that is over its bound does not help.

- **Scale.** Measured on one test host over a synthetic dataset of about 205 usage
  rows per device, the read costs about 68 microseconds per online device: 4.1
  seconds at 60,000 devices. By extrapolation the 10-second bound is reached near
  150,000 online devices. That is a measurement on one host, not a guaranteed
  ceiling; the read has not been measured past 60,000 devices.
- **What helps.** Only `platform=` narrows the read. The `group` and `tag` slices
  only assign cells, so they read the whole platform scope. An index on the
  executable key did not change the query plan in that measurement. There is no
  operator-side fix today; the state clears on the first successful read.
- **What is unaffected.** Other DEX routes, including the Apps list, keep working.
- **Pool pressure.** Usage reads and Apps reads each have their own budget of 4 (a
  usage request holds an Apps slot only while it reads the Apps list), so up
  to 8 pool leases can be in use at once. If reads time out together with slow
  acquires, check `yuzu_pg_pool_in_use` and `yuzu_pg_acquire_wait_seconds`, and
  raise `--postgres-pool-size` if they show pressure.

## Using the plugin directly

The `app_usage` plugin can be run on a device through the normal instruction
path:

| Action | Definition | Answers |
|---|---|---|
| `summary` | `crossplatform.app_usage.summary` | Totals per executable over the trailing `days` (default 30), ranked by `run_time` or `run_count`, with a health row for the fold. |
| `last_used` | `crossplatform.app_usage.last_used` | First and last seen per executable and runs over the trailing 30 days. `exe` narrows it to one executable. |
| `foreground` | `crossplatform.app_usage.foreground` | Always "not captured". Focus time is not collected. |

Read the health row of `summary` before treating a result as complete.

## Permissions and audit

| Surface | Permission | Audit |
|---|---|---|
| Per-device REST route, MCP tool, dashboard panel | `Forensics:Read`, scoped to the device. Administrator and ForensicsAnalyst hold it by default. | `app_usage.agent.view`, written before any data is served. If the row cannot be stored the read fails closed: REST answers `503` with `Sec-Audit-Failed: true`, MCP answers with an error and no data, and the dashboard panel shows a note instead of the figures. |
| `app_usage` plugin actions | `Forensics:Read`, administrator or approval | Standard command audit |
| Fleet REST route | `Forensics:Read` and `GuaranteedState:Read` | `dex.apps.usage.view`, written before the read (after parameter validation) and failing closed, as described [above](#fleet-permissions-and-audit) |

A service-scoped token is refused on the REST route and the MCP tool, and the
dashboard panel shows a permission note instead of data, because the service
owner role does not hold `Forensics:Read`.

## Limits and privacy

- This is behavioural data about what people run. That is why access to these
  reads is limited to the Forensics permission and every read is audited.
- The app-usage reads never return a process id, command line or user name.
  Users appear only as a count in the plugin's `summary`. The data they come
  from is wider, on the device. Echo's process source sees process ids and the
  owning user, and on Linux its collector also reads each command line; Windows
  and macOS capture none. The usage tables that hold process ids and user names
  are blocked from `echo.sql`. The process tiers and the process baseline stay
  readable through `echo.sql` with `Infrastructure:Read`, which is not the
  Forensics permission. They hold process names and the owning user (the
  baseline also holds process ids) but no command line.
- It is wall-clock run time of the process, not interactive use.
- History starts when the usage fold started. There is no "since install" figure.
- The panel is built from the device's last stored report, whatever its age, so
  it can be older than a day if the device has not reported since.

## Platform coverage

| Platform | Source | Status |
|---|---|---|
| Windows | Process start and stop events | Supported |
| Linux | `/proc`; names are truncated to 15 characters | Supported |
| macOS | Endpoint Security when entitled, otherwise polling, so short-lived processes can be missed | Constrained |

## Related pages

- [App performance](app-performance.md): CPU and memory per application.
- [Collectors and plugins](collectors-and-plugins.md): Echo and the plugin.
- [The `app_usage` plugin README](../../agents/plugins/app_usage/README.md): actions and caveats.
