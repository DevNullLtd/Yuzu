# App performance: CPU and memory per application over time

DEX (Digital Employee Experience) app performance keeps a retained history of
how much CPU and memory each application version uses, so you can see a
regression arrive with a release and check whether an upgrade helped.

[Back to the hub](README.md) | [Surface map](surfaces.md)

## What it is

The **App Performance** tab is a picker over every application with retained
history. Choosing an application opens its trend:

- one row per **version**, with average and 95th-percentile CPU, a CPU
  sparkline, average working set (memory in use) and the number of reporting
  devices;
- for the whole fleet, a second table of **crashes and hangs by version**, with
  exposed devices, failure rate and the rate against the previous version;
- a **version-devices drill** that lists the devices behind one version row;
- the same trend scoped to one **management group** or one **device model**
  (a device-tag value);
- a **before and after comparison** for an upgrade, for scripts and agentic
  workers.

The Performance tab is the live fleet-now view. App Performance is the retained
history. They are siblings, not duplicates.

## Why it is useful

- **Catch regressions early.** A new version that doubles CPU shows up as a
  step between adjacent version rows.
- **Prove an upgrade helped, or did not.** The comparison measures the shift
  machine by machine for the machines that ran both versions, which avoids
  comparing different populations.
- **See who is affected.** The version drill names the devices behind a number
  so you can start with them.
- **Honest rates.** Every failure rate sits beside the number of devices it came
  from, and an unknown exposure reads "unknown", never zero.

## What feeds it and how to enable it

The data comes from the **Echo per-application sampler** (`procperf`) on each
device, which records the heaviest processes by name only, never by command
line. Each day the agent rolls the on-device hourly data up into one summary
per application version per day and sends it to the server over the daily sync.
The server keeps two retained stores: a fleet trend kept for 180 days and
per-device daily summaries kept for 31 days.

- It is on by default. Switch it off per device with Echo's `procperf_enabled`
  setting, which is separate from `--dex-disable`.
- It samples on Windows and Linux. macOS has no per-application sampler.
- The Linux daily rollup leaves out kernel threads. Linux agents report an
  unknown version, so Linux applications appear under the "unknown version"
  bucket.

See [collectors and plugins](collectors-and-plugins.md#the-echo-plugin).

## Using it in the dashboard

1. Open **DEX**, then **App Performance**.
2. Find an application. **Search** filters by name, **Platform** (All, Windows,
   Linux) filters by a name-suffix guess (a name ending `.exe` is treated as
   Windows), and **Sort** orders by most recently seen, name or most versions.
3. Click the application. Read each version row, and the **Crashes and hangs by
   version** table beneath it on the whole-fleet scope.
4. To scope the trend, choose a **Scope** (management group) or a **Model**
   (device-tag value). They are mutually exclusive. Choosing a group or model
   scopes the performance table; the crashes-and-hangs table is shown for the
   whole fleet only.
5. To see the devices behind a version, click its **devices** link. The drill
   lists devices where that exact version was among the heaviest processes on
   that day, with last-seen day, CPU and working set.

The version-devices list is a top-N sample, not a census. For a complete list
of where a version is installed, use the [software inventory](../user-manual/inventory.md).
It also reads a shorter window than the trend, 31 days against 180, so a
version last seen over a month ago can legitimately show no devices.

### On a device

Open any device in DEX. The device drill-down has two application panels, each
behind its own click:

- **Application performance over time** reads the retained per-device summaries
  from the server. It runs no query on the device, so it needs no Execute
  permission. Each application is grouped with its versions and a CPU sparkline
  per version.
- **Top applications** runs a live, read-only Echo query on the device for the
  last day of per-application data, process names only. It needs the device
  online, `GuaranteedState:Read` and `Execution:Execute`.

## REST

- `GET /api/v1/dex/perf/apps` lists applications with retained fleet data.
- `GET /api/v1/dex/perf/app` returns the fleet trend for one application. Takes
  `app` (required) and `version`. One point per version and day over the
  retained window, plus a per-version join of crashes, hangs, exposure and
  failure rate.
- `GET /api/v1/dex/perf/app/devices` lists the devices behind one exact
  version. Takes `app` and `version`, both required. An empty `version` means
  the unknown-version bucket. A `truncated` flag means only the highest-CPU
  devices were returned.
- `GET /api/v1/dex/perf/group` returns the trend for one management group. Takes
  `group_id`, `app` and optional `version`.
- `GET /api/v1/dex/perf/tag` returns the trend for one device-tag value. Takes
  `key` (default `model`), `value`, `app` and optional `version`. Discover valid
  values with `GET /api/v1/dex/perf/cohorts`.
- `GET /api/v1/dex/devices/{id}/app-perf` returns one device's retained
  per-application history. Takes optional `app`.
- `GET /api/v1/dex/perf/compare` compares two versions. Takes `group`, `app`,
  `baseline` and `candidate` (the two must differ) and `window`, in days on each
  side (default 7). The answer is evidence only: the measured shift and how many
  machines went up, stayed flat or went down, with no verdict.

## MCP

| Tool | Does |
|---|---|
| `list_dex_perf_apps` | Applications with retained fleet data. |
| `get_dex_app_perf` | Fleet trend for one application. |
| `list_dex_app_perf_devices` | Devices behind one exact version. |
| `get_dex_group_app_perf` | Trend for one management group. |
| `get_dex_tag_app_perf` | Trend for one device-tag value. |
| `get_dex_device_app_perf` | One device's retained history. |
| `compare_app_perf_versions` | Before and after comparison of two versions. |

The per-device live Top applications panel is dashboard only.

## Permissions and audit

| Read | Permission | Audit |
|---|---|---|
| Picker, fleet trend | `GuaranteedState:Read` | Not audited. They are fleet aggregates. |
| Group and tag trends | `GuaranteedState:Read` | Not audited when they succeed. |
| Version-devices drill | `GuaranteedState:Read` through the fleet-read check, confined to the devices the caller can see | `dex.app_perf.devices.view`. REST refuses to answer if the row cannot be stored. |
| One device's retained history | `GuaranteedState:Read`, scoped to the device | `dex.device.app_perf.view` on REST, MCP and the dashboard panel |
| Live Top applications panel | `GuaranteedState:Read` and `Execution:Execute`, both scoped to the device | `dex.device.procperf.query`, kept separate because per-application data shows what people run |
| Version comparison | `GuaranteedState:Read` | `dex.app_perf.compare` |

A service-scoped token is refused on the picker, the fleet, group and tag
trends and the version comparison. The version-devices drill answers with only
the devices the token can see. The two per-device reads, one device's retained
history and the live Top applications panel, follow the per-device rule: they
accept such a token only for a device tagged with its own service, with RBAC
enforcement on. See [surfaces](surfaces.md#the-rest-api).

## Limits and privacy

- **Usage-class data.** Per-application data observes what people run, not only
  how a machine behaves. That is why the device-level reads have their own audit
  verbs, so that works councils can count them.
- **Names only.** The sampler records process names, never command lines, and
  operator redaction patterns apply at collection.
- **One-device floor.** Trends publish any version-day with at least one device.
  Only an empty point is reduced to a count. A group or model of one device is
  that device's figures, so read small cohorts as anecdotes.
- **Sampled, not census.** Only a device's heaviest applications are sampled
  each day, so exposed devices are a sample, and a version with no samples is
  not listed. A missing row is not the absence of failures.
- **Not a verdict.** Nothing on these pages is labelled good or bad.
- **Absence proves little.** A process that renames itself can ride another
  name's bucket for a tick, so the absence of a process from this trend is not,
  on its own, evidence that nothing was running.

## Platform coverage

| Platform | Per-application sampling | Versions |
|---|---|---|
| Windows | Yes | Reported |
| Linux | Yes | Unknown-version bucket only |
| macOS | No | Not applicable |

## Related pages

- [Performance](performance.md): live fleet-now figures.
- [Apps](apps.md): crashes and hangs for the same application.
- [App usage](app-usage.md): how often and how long an executable ran on one device.
- [Collectors and plugins](collectors-and-plugins.md): the Echo sampler.
- [DEX in the user manual](../user-manual/dex.md#drill-downs): detailed behaviour of each drill-down.
