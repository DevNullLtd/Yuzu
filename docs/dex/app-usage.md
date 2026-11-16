# App usage: which executables ran on a device

DEX (Digital Employee Experience) app usage answers one question for one
device: which executables ran there recently, how often and for how long.

[Back to the hub](README.md) | [Surface map](surfaces.md)

App usage is **per device**. It is not a fleet rollup, and it is not
interactive-use or foreground time.

## What it is

For each executable on a device the projection holds:

- the first and last time it was seen, within the retention window of the
  device's Echo store (31 days by default);
- the number of runs and the total run seconds over the trailing 30 days.

An executable is named by its lowercase file name. There is never a full path,
process id, command line or user name.

## Why it is useful

- **Reclaim licences and attack surface.** Comparing what is installed with what
  ran shows software nobody uses.
- **Support questions.** "Has this application run on this laptop recently, and
  when last?" gets a direct answer.
- **A usage picture without surveillance.** The data is machine-scope run
  history. It never says who used something.

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
`run_count_30d` and `total_seconds_30d`. A device that reported no rows returns
`200` with an empty list. A degraded store returns `503`, never an empty `200`.

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
| REST route, MCP tool, dashboard panel | `Forensics:Read`, scoped to the device. Administrator and ForensicsAnalyst hold it by default. | `app_usage.agent.view`, written before any data is served. If the row cannot be stored the read fails closed, on REST (`503` with `Sec-Audit-Failed: true`) and on MCP. |
| `app_usage` plugin actions | `Forensics:Read`, administrator or approval | Standard command audit |

A service-scoped token is limited to its own devices.

## Limits and privacy

- This is behavioural data about what people run. That is why access is limited
  to the Forensics permission and every read is audited.
- No process id, command line or user name is collected. Users appear only as
  a count in the plugin's `summary`.
- It is wall-clock run time of the process, not interactive use.
- History starts when the usage fold started. There is no "since install" figure.
- The panel is built from the daily report, so figures are up to a day old.

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
