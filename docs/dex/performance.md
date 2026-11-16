# Performance: how devices are running now

DEX (Digital Employee Experience) performance shows the levels of CPU, memory
and disk delay across the fleet right now, lets you benchmark groups of devices
against each other, and lets you look at a single device's performance on
demand.

[Back to the hub](README.md) | [Surface map](surfaces.md)

## What it is

Where [Trends](fleet-health.md) shows events, Performance shows levels. It is a
**now-view**: every number is computed when the page renders from the latest
heartbeat sample of each reporting device. It has no window selector.

- **Fleet now cards** for CPU utilisation, memory commit and disk I/O latency,
  each with average, median (p50), p90 and maximum, plus a **Reporting** card
  that states how many devices the figures are built from.
- **Cohort benchmarking**: the same percentiles per cohort, where a cohort is
  the set of devices sharing a value of a tag key (default `model`).
- **Cohort comparison**: one cohort set directly against another.
- **Device lists** behind every card and cohort: the worst devices by a metric,
  the devices not reporting, or the members of a cohort.
- **Per-device performance**: on a device's drill-down, CPU, memory and
  disk-latency sparklines built from that device's own hourly rollups, plus
  strips placing its current values against the fleet and its cohort.
- **A Prometheus rollup** of the fleet figures for dashboards you already run.

## Why it is useful

- **Spot pressure before it becomes a ticket.** A fleet whose p90 memory commit
  keeps rising is an early warning that no crash signal would give.
- **Compare like with like.** Cohorts let you compare a vanilla image against a
  layered one on identical hardware, or one device model against another.
  Tag the fleet with a key such as `image` and the comparison appears.
- **Never a false average.** Every figure sits beside its population. An average
  over twelve devices is never presented as fleet-wide truth.
- **Find the devices that do not report.** The Reporting card opens the devices
  that are online but sending no performance sample.

## What feeds it and how to enable it

- **Fleet now, cohorts and device lists** come from heartbeat tags that the
  agent attaches to each heartbeat: CPU busy percentage, commit-charge
  percentage and per-IO disk latency, derived over the heartbeat interval. Windows
  and Linux agents send them. macOS agents show as online but are absent from
  these figures, not counted as zero. These tags are stopped by the agent's
  `--dex-disable` switch.
- **Cohorts** come from device tags, not an inventory column. Tag your devices
  (see the [asset tagging guide](../asset-tagging-guide.md)) and pick the tag key
  on the page.
- **Per-device performance** reads the Echo performance sampler on the device.
  The sampler is on by default and is controlled by Echo's `perf_enabled`
  setting, separate from `--dex-disable`. See
  [collectors and plugins](collectors-and-plugins.md#the-echo-plugin).

## Using it in the dashboard

1. Open **DEX**, then **Performance**.
2. Read the three fleet cards and the Reporting card. The Reporting card reads
   "of N perf-capable online", where N counts online devices whose operating
   system has a performance collector (Windows and Linux), with macOS shown
   separately.
3. In **Cohort benchmarking**, choose a tag key. Each cohort row shows its
   percentiles and population. Devices without the key appear as an explicit
   **(untagged)** row.
4. Click any card to open the worst devices for that metric. Click a cohort row
   to open its members. Click a device to open its drill-down.

**On a device's drill-down**, the **device performance** panel is click to load.
When you load it, the server runs a live, read-only Echo query on that device,
so the raw samples stay on the device until someone asks. It needs the device
online and the Echo sampler enabled, and it needs the `Execution:Execute`
permission as well as `GuaranteedState:Read`; without Execute the panel shows a
note instead. The **vs fleet and cohort** strips beside it use current heartbeat
values and run no query.

A separate **Top applications** panel on the device, behind its own click,
reads per-application usage from the device. That is covered in
[app performance](app-performance.md#on-a-device).

## REST

- `GET /api/v1/dex/perf/fleet` returns the fleet-now figures: average, p50,
  p90, max and sample count per metric (null when nobody reported it), with the
  reporting and online populations.
- `GET /api/v1/dex/perf/cohorts` returns the cohort table, including
  suppression flags, the untagged residual and `available_keys` for pickers.
  Takes `key` (default `model`).
- `GET /api/v1/dex/perf/cohort-diff` compares two cohorts. Takes `key`, `a`
  and `b` (both cohort values required). It returns both cohort rows and
  `delta_pct`, with `b` as the baseline.
- `GET /api/v1/dex/perf/devices` returns the device list behind a drill. Takes
  `metric` (`cpu`, `commit` or `disk_lat`), `filter=not_reporting`,
  `cohort_key`, `cohort_value` and `limit`.

## MCP

| Tool | Does |
|---|---|
| `get_dex_perf_fleet` | Fleet-now figures. |
| `get_dex_perf_cohorts` | Cohort benchmarking table. |
| `get_dex_perf_cohort_diff` | Direct comparison of two cohorts. |
| `list_dex_perf_devices` | Devices behind a metric, a cohort or not reporting. |

The per-device live performance panel is a dashboard feature; it has no REST
route or MCP tool. The retained per-device history is covered in
[app performance](app-performance.md).

## Permissions and audit

| Read | Permission | Audit |
|---|---|---|
| Fleet, cohorts, cohort comparison | `GuaranteedState:Read` | Not audited. They are machine-health aggregates. |
| Device lists | `GuaranteedState:Read` | `dex.perf.device.view`. REST refuses to answer if the row cannot be stored. A service-scoped token is refused, because every row names a device fleet-wide. |
| Per-device performance panel | `GuaranteedState:Read` and `Execution:Execute` | `dex.device.perf.query` |

A grant scoped to one management group does not pass the aggregate reads.

## Limits and privacy

- **One-device floor.** A cohort is published when at least one device reported.
  A cohort keyed by a per-device tag value with one device is that device's own
  figures. Only an empty cohort is withheld. Treat a small cohort as an
  anecdote.
- **Names, not content.** The per-device panel reads machine-level performance,
  not per-application data, so it carries no application names.
- **Opt-in cohort export.** The Prometheus cohort export is off by default and
  is not behind the DEX read permission once enabled; see below.
- **Now-view.** Nothing on the fleet page is retained history. For history, use
  [app performance](app-performance.md).

### Prometheus rollup

The server aggregates the latest value from every reporting agent into fleet
gauges on `/metrics`, named `yuzu_fleet_perf_*`. When no agent reports a metric
the series goes absent, never a made-up zero. Values are validated on the server,
so one misbehaving agent cannot poison a percentile.

An administrator can set a **cohort export tag key** on the DEX **Alerts** tab.
That additionally publishes per-cohort gauges for that key, limited to the 50
largest cohorts, with a gauge that shows when cohorts were cut. The key is empty
by default. Per-device and per-application data are never exported. The full
list of series is in [the metrics reference](../user-manual/metrics.md#fleet-performance-gauges-dex).

## Platform coverage

| Platform | Fleet now and cohorts | Per-device performance |
|---|---|---|
| Windows | Yes | Yes, through the Echo sampler |
| Linux | Yes | Yes, through the Echo sampler |
| macOS | Online, but sends no performance tags | No sampler on macOS |

## Related pages

- [Fleet health](fleet-health.md): events rather than levels.
- [App performance](app-performance.md): CPU and memory per application over time.
- [Collectors and plugins](collectors-and-plugins.md): the heartbeat tags and Echo.
- [DEX in the user manual](../user-manual/dex.md#performance): full reference.
