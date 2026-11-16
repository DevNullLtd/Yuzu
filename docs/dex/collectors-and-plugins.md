# Collectors and plugins: what feeds DEX

DEX (Digital Employee Experience) has no collection of its own on the server.
Everything it shows is gathered on each device by agent code and plugins, then
sent to the server. This page lists each piece, what it feeds, whether it is on
by default, how to switch it on or off, and what it needs.

[Back to the hub](README.md) | [Surface map](surfaces.md)

## At a glance

| Piece | Feeds | Default | Switch |
|---|---|---|---|
| [DEX observer](#the-dex-observer) | Signals, fleet health, apps, alerts | On | `--dex-disable` |
| [Heartbeat performance tags](#heartbeat-performance-and-network-tags) | Performance, fleet gauges | On | `--dex-disable` |
| [Heartbeat network tags](#heartbeat-performance-and-network-tags) | Network | On | `--dex-disable` |
| [Echo plugin](#the-echo-plugin) (`perf`, `procperf`, `netqual`, `usage`) | Per-device performance, app performance, per-connection network, app usage | On | Echo settings, per source |
| [app usage plugin](#the-app-usage-plugin) | App usage | On, read-only | Follows Echo's `usage_enabled` |
| [Plugins a DEX drill dispatches](#plugins-a-dex-drill-dispatches) | Get live info | On demand | Not applicable |

## What `--dex-disable` stops

`--dex-disable` (environment `YUZU_AGENT_DEX_DISABLE`) is a deploy-time setting
on the agent. It is not a server-side runtime toggle. When it is set, the agent:

- does not arm the DEX observer, so no signal observations are collected;
- does not send the observer health tags;
- does not send the heartbeat performance tags;
- does not send the heartbeat network-quality tags.

It does **not** stop the Echo sources. Echo is a separate subsystem with its own
per-source settings, and the Echo performance sampler, the per-application
sampler, the per-connection network sampler and the usage fold keep running
unless you switch each off. It also does not stop the daily sync of
per-application performance and app usage to the server. `--inventory-disable`
(environment `YUZU_AGENT_INVENTORY_DISABLE`) does that, and it stops the whole
daily sync, so the agent collects and sends none of its daily sources. To stop
DEX data leaving a device, set both flags. To stop collecting it on the device
as well, switch the Echo sources off.

Switching collection off does not recall what was already captured. The
per-application performance sync covers the last two completed days, so rows
captured before the switch can still arrive in the next syncs. Nothing already
on the server is deleted by any of these switches: it stays for as long as
[what is kept and for how long](#what-is-kept-and-for-how-long) says.

The agent's own `--help` text for the flag mentions only the crash recorder. The
checks for the flag in the agent's code show the wider scope given above.

## The DEX observer

**What it feeds.** Every DEX signal: the Catalogue, fleet health, application
stability, device history and alerts. See [signals](signals.md).

**Default state.** On, on Windows, Linux and macOS.

**Enable and disable.** On by default. Switch off with `--dex-disable`. There is
no per-category toggle and no server-side switch.

**How it works.** The observer reads operating-system event sources and turns
each event into a uniform observation (type, subject, reason, component, metric,
platform, time). It applies a per-type hourly cap so a storm cannot flood the
store. Observations are sent to the server over the agent's existing connection
and projected into the DEX read model.

**Health tags.** While enabled, each heartbeat carries two tags: whether the
observer is armed, and a running count of observations. The server turns the
first into the fleet total of devices whose observer is not armed. An armed
observer has started and has at least one source. It does not prove every crash
source on the device is readable.

**Platforms.**

| Platform | Sources | Notes |
|---|---|---|
| Windows | Event-log observer, plus a state poll for storage pressure, battery health and sustained performance breaches | Fullest coverage. Breach thresholds are fixed on the agent. |
| Linux | `/proc` performance poll, storage poll, CPU thermal-throttle poll, and a journal reader that classifies kernel and unit records | Workstation-only headings are not applicable on headless servers. Inside an unmodified container, `/proc` reflects the host. |
| macOS | An unprivileged collector reusing the same signal types | Deliberately limited. |

The signal-by-platform table is
[dex_obs_platforms.tsv](../capability-registries/dex_obs_platforms.tsv); the
collectors are described in [the signal catalogue](../dex-signal-catalog.md).

## Heartbeat performance and network tags

**What they feed.** The [Performance](performance.md) tab, the cohort views, the
[Network](network.md) tab and the fleet Prometheus gauges.

**How they work.** Each heartbeat carries a small set of device-aggregate
readings derived from kernel counters over the heartbeat interval. The server
aggregates the latest value from every reporting agent. A device that sends
nothing is left out of that metric, not counted as zero.

| Tags | Windows | Linux | macOS |
|---|---|---|---|
| Performance: CPU busy | Yes | Yes | No |
| Performance: memory commit | Yes | Yes, but omitted where `vm.overcommit_memory` is `1` | No |
| Performance: disk latency | Yes | No | No |
| Network: round-trip time | No | Yes | No |
| Network: interval retransmit rate | Yes | Yes | No |
| Network: device throughput | Yes | Yes | Yes |

**Enable and disable.** On by default. Both families stop with `--dex-disable`.

## The Echo plugin

Echo is the agent's local telemetry warehouse. Each capture source records
changes into hourly, daily and monthly tiers in a database on the device, and
the raw samples stay there until an operator asks. DEX uses four of its sources.

| Echo source | Feeds | Setting | Platforms |
|---|---|---|---|
| `perf` (device performance) | The per-device performance panel | `perf_enabled` | Windows, Linux |
| `procperf` (per-application top-N) | [App performance](app-performance.md), the daily sync, the device Top applications panel | `procperf_enabled` | Windows, Linux |
| `netqual` (per-connection TCP quality) | Per-connection network detail through Echo queries | `netqual_enabled` | Linux, Windows (elevated agent), macOS (root agent) |
| `usage` (derived run history) | [App usage](app-usage.md) | `usage_enabled` | Windows, Linux, macOS (constrained) |

**Default state.** All four are on by default, like every other Echo capture
source. The `perf` and `procperf` samplers share one interval,
`perf_interval_seconds` (default 30), read at agent startup.

**Enable and disable.** Use Echo's `configure` action to set `<source>_enabled`
to `true` or `false` on a device or across the fleet. The action is definition
`crossplatform.echo.configure`, needs `Infrastructure:Write`, and is gated to an
administrator or an approval. Disabling a source stops new captures at once;
rows already on the device age out on Echo's own tier windows, and the server's
copies follow [what is kept](#what-is-kept-and-for-how-long). See
[Echo configuration](../user-manual/echo.md#configuration) for every setting and
its range.

**Reading from DEX.** The device performance and Top applications panels run
Echo's `sql` action on the device with a fixed, read-only query. The `sql`
action itself is classified `Infrastructure:Read`, and the DEX panels additionally need
`GuaranteedState:Read` and `Execution:Execute` on the device. Each panel records
its own audit verb (see [performance](performance.md) and
[app performance](app-performance.md)). The `usage` tables cannot be read
through `echo.sql`; they are reachable only through the Forensics-gated
`app_usage` reads.

**Privacy.** On the device, per-application data records process names only,
never command lines, and the per-connection rows are joined to the name of the
owning process. Redaction patterns apply to the per-application names and to the
command lines the process source reads, not to process names in the process
source or to that owning-process name. A connection's destination is
stored only as a coarse class. What reaches the server is described in
[app performance](app-performance.md#what-feeds-it-and-how-to-enable-it) and
[app usage](app-usage.md#what-feeds-it-and-how-to-enable-it): per-device,
per-application figures keyed by application or executable name.

Reference: [Echo user manual](../user-manual/echo.md) and the
[plugin README](../../agents/plugins/echo/README.md).

## The app usage plugin

**What it feeds.** [App usage](app-usage.md).

**How it works.** The `app_usage` plugin opens Echo's usage store read-only on
each dispatch and reports from it. It never writes the Echo database, never
accepts a path from the caller, and never emits a process id, command line or
user name. Its `last_used` action is what the agent's daily sync calls to send
the projection to the server.

**Default state and switch.** The plugin is a read-only collector. It reports a
typed reason, not an empty result, when Echo's usage source is off. Switch the
data off with Echo's `usage_enabled`. The server keeps a device's last report
until the next one replaces it or the device is decommissioned, so switching the
source off does not remove what the server already holds.

**Actions.** `summary`, `last_used` and `foreground`, with their definition ids
and what each answers, are listed on
[app usage](app-usage.md#using-the-plugin-directly).

**Permission.** `Forensics:Read`, with an approval gate of administrator or
approval.

**Platforms.** Windows and Linux supported; macOS constrained.

Reference: [plugin README](../../agents/plugins/app_usage/README.md).

## Plugins a DEX drill dispatches

On the REST route, "Get live info" sends a read-only instruction through the
normal dispatch path and waits for the answer. The route supports the two kinds
below; the device page offers more, described in
[device management](../user-manual/device-management.md#get-live-info). DEX
keeps no copy of its own, but the device's reply is held in the response store
like any instruction result, for the server's `--response-retention-days` (90 days by default).
The device performance and Top applications panels dispatch an Echo query the
same way, so their replies are held there too.

| Kind | Plugin and action | Permission | Platforms |
|---|---|---|---|
| Uptime | `os_info`, `uptime` (definition `device.os_info.uptime`) | `Inventory:Read` | Windows, macOS, Linux |
| Running processes | `processes`, `list_hashed` | `Inventory:Read` | Windows, macOS, Linux |

Operators also need `Execution:Execute` and `GuaranteedState:Read` on the target
device to use the DEX live route; see [signals](signals.md).

Plugin READMEs: [os_info](../../agents/plugins/os_info/README.md) and
[processes](../../agents/plugins/processes/README.md). Other plugins, including
`power_health`, do not feed a DEX view.

## What is kept and for how long

This table covers the server. On the device, Echo prunes each of its tiers on
its own window and caps the whole database; see the
[maintenance cycle](../user-manual/echo.md#maintenance-cycle).

| Data | Kept on the server | Removed when the device is decommissioned | Switch off |
|---|---|---|---|
| Signal observations | 30 days by default, set by the server's `--guardian-event-retention-days` | No; they expire by that window | `--dex-disable` |
| Per-device application performance | 31 days | Yes | Echo `procperf_enabled`; `--inventory-disable` stops the sync |
| Fleet application trend, with no per-device rows | 180 days | Nothing to remove: it holds no device identity | As the row above |
| Per-device app usage | The last report, until the next one replaces it | Yes | Echo `usage_enabled`; `--inventory-disable` stops the sync |
| Replies to on-demand reads (live info, device performance, Top applications) | The server's `--response-retention-days`, 90 days by default | No; they expire by that window | Not applicable: a read runs only when someone asks |

## Related pages

- [Signals](signals.md), [Performance](performance.md),
  [App performance](app-performance.md), [Network](network.md) and
  [App usage](app-usage.md): what each collector appears as.
- [DEX in the user manual](../user-manual/dex.md#turning-it-off): the original
  note on turning collection off.
