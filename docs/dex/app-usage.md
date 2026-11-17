# App usage: which executables ran on a device

DEX (Digital Employee Experience) app usage answers one question for one
device: which executables ran there recently, how often and for how long.

[Back to the hub](README.md) | [Surface map](surfaces.md)

App usage is **per device**. It is not a fleet rollup, and it is not
interactive-use or foreground time.

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

`get_agent_app_usage` takes `agent_id` and returns the same data.

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
| REST route, MCP tool, dashboard panel | `Forensics:Read`, scoped to the device. Administrator and ForensicsAnalyst hold it by default. | `app_usage.agent.view`, written before any data is served. If the row cannot be stored the read fails closed: REST answers `503` with `Sec-Audit-Failed: true`, MCP answers with an error and no data, and the dashboard panel shows a note instead of the figures. |
| `app_usage` plugin actions | `Forensics:Read`, administrator or approval | Standard command audit |

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
