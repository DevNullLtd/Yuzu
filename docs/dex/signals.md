# Signals: the catalogue, drill-downs and device history

DEX (Digital Employee Experience) signals are the raw material of everything
else in this guide. A signal is a small, uniform record of something that went
wrong, or changed, on a managed device: an application crashed, a service
failed, a boot was slow, a disk reported errors, a sign-in failed.

[Back to the hub](README.md) | [Surface map](surfaces.md)

## What it is

Each agent watches operating-system event sources and turns what it sees into
**observations** with a common shape: a signal type (`obs_type`, such as
`process.crashed`), a subject (the failing entity, such as an application
name), a reason, an optional component and metric, a platform and a time. The
server stores them in a read model and offers these views:

- the **Catalogue**: every signal type, grouped into families, with coverage
  and a score per family;
- the **signal rollup and scope**: counts per type, and which signals each
  operating system collects;
- **drill-downs** into one signal type, one device and one observation;
- **Get live info**: a read-only live uptime or process list from one device.

The signals are ruleless: no Guardian rule produced them, and no rule acts on
them. This is observation, not enforcement. The wire and read-model shape is in
[the signal catalogue](../dex-signal-catalog.md).

## Why it is useful

- **Coverage you can trust.** The Catalogue shows which signal types a platform
  collects, so "no events" is not mistaken for "not monitored". A type
  watched with nothing to report reads as "watched, nothing happened". A type no
  connected platform collects is shown dimmed as "not collected", never as
  healthy.
- **From fleet to device in three clicks.** Start at a family, open a signal
  type, see the most affected devices, open one device and read its timeline.
- **Answers for helpdesk and security.** One device's history puts every signal
  type on a single timeline with friendly labels, which shortens "what happened
  on this laptop last week".
- **Stable machine keys for automation.** `obs_type` values are stable keys an
  agentic worker can group and alert on.

## What feeds it and how to enable it

The agent's DEX observer feeds every signal. It is on by default, runs on
Windows, Linux and macOS, and is switched off per agent with `--dex-disable`
(environment `YUZU_AGENT_DEX_DISABLE`). The sources behind each platform, and
what the switch does and does not stop, are in
[collectors and plugins](collectors-and-plugins.md#the-dex-observer).

"Get live info" does not read stored signals. It dispatches the `os_info`
plugin (`uptime`) or the `processes` plugin (`list_hashed`) to the device; see
[collectors and plugins](collectors-and-plugins.md#plugins-a-dex-drill-dispatches).

## Using it in the dashboard

**Catalogue.** Open **DEX**, then the **Catalogue** tab.

1. Read the family cards. Each shows how many of its signal types are
   monitored and a score from 0 to 100. Under **All connected** the score is
   the family's share of the fleet composite. Under one operating-system chip
   the family is rescored against that platform's own devices and signals.
2. Pick an operating-system chip to narrow coverage. The choice stays as you
   open families and types.
3. Open a family to list every type with its coverage and, for types that
   fired, event and device counts.
4. Open a type for its top subjects, live operating-system split, most
   affected devices and an activity trend.

A signal that a newer agent emits but the catalogue does not yet list appears
under **Other**, so nothing the fleet reports is hidden.

**Device history.** Click a device anywhere in DEX. The drill-down shows its
signal history across every type, newest first. Click a row to open the event
detail panel: every captured field of that one event, including subject,
reason, symbolic name, component, metric, platform, exact time and event id.

The same history is available from the device page's DEX tab.

**Get live info.** On a device page, **Get live info** asks the device for its
uptime or its running processes. Viewing a device page never dispatches
anything on its own; the read happens only when you click. The REST route supports the two kinds named below, uptime and processes.

## REST

- `GET /api/v1/dex/catalogue` returns the family cards, fleet coverage and the
  list of uncatalogued types. Takes `window` and `os`.
- `GET /api/v1/dex/catalogue/group` returns one family's member signals. Takes
  `name`, `os` and `window`. An unknown family is a `404`.
- `GET /api/v1/dex/signals` returns the rollup for the window. Takes `window`
  and optional `os`.
- `GET /api/v1/dex/scope` returns per-operating-system signal coverage. Takes
  `window`.
- `GET /api/v1/dex/signals/{obs_type}` returns one signal in depth: subjects,
  operating-system split, most affected devices and a per-day trend. Takes
  `window`, `os` and `limit`. `obs_type` may contain letters, digits, dots,
  underscores and hyphens, up to 64 characters.
- `GET /api/v1/dex/devices/{id}` returns one device's score and signal summary.
  Takes `window`.
- `GET /api/v1/dex/devices/{id}/history` returns that device's raw signal
  history. Takes `window`.
- `GET /api/v1/dex/devices/{id}/observations/{event_id}` returns one
  observation. An unknown event id, or one that belongs to another device, is
  a `404`.
- `POST /api/v1/dex/devices/{id}/live` takes `kind=uptime` or `kind=processes`,
  dispatches a read-only instruction to the device and waits up to about 20
  seconds for the answer. It answers `429` when too many live queries are
  already running, and `502`, `503` or `504` when the device cannot answer in
  time. A device that is offline gets a `503`.

## MCP

| Tool | Does |
|---|---|
| `get_dex_catalogue` | Family cards, coverage and uncatalogued list. |
| `get_dex_catalogue_group` | One family's member signals. |
| `list_dex_signals` | The signal rollup for a window. |
| `get_dex_signal_scope` | Per-operating-system coverage. |
| `get_dex_signal_detail` | One signal type in depth. |
| `get_dex_device_score` | One device's score and signal summary. |
| `get_dex_device_history` | One device's signal history. |
| `get_dex_observation` | One observation in detail. |

There is no MCP tool for live info. Arguments match the REST parameters above.

## Permissions and audit

All reads need `GuaranteedState:Read`. The live-info route additionally needs
`Execution:Execute`; both are checked against the device you target.

| Read | Audit verb |
|---|---|
| Signal drill-down by type | `dex.signal.view` |
| Device score, device history | `dex.device.view` |
| One observation | `dex.observation.view` |
| Live uptime or processes | `device.live.uptime` or `device.live.processes`, written before the dispatch |
| Catalogue, rollup and scope | Not audited |

On REST, an audited read refuses to answer if its audit row cannot be stored
(`503` with `Sec-Audit-Failed: true`). The signal drill-down is refused to a
service-scoped token, because it lists devices fleet-wide. The per-device reads
accept such a token only for a device tagged with its own service.

## Limits and privacy

- **Device history is behavioural data.** A device's signal history shows which
  applications a person runs. That is why every device-level read is permission
  gated and audit logged.
- **Data minimisation at the edge.** Extractors drop user content on the
  device before anything is sent: queried DNS names, print document names and
  owners, profile user names and image paths. What is never sent cannot leak.
  See [the privacy and works-council contract](../dex-signal-catalog.md#privacy--works-council-contract).
- **Rate caps.** Each signal type has an hourly cap per device, so a failing
  disk or a flapping network cannot flood the store. See
  [rate caps](../dex-signal-catalog.md#rate-caps).
- **Names are shown as sent.** Application, device and group names that contain
  invisible direction or zero-width characters are printed with a visible
  marker, so two names that differ only by an invisible character never look
  the same.
- Signals need the Guardian event store to be healthy. If the projection is
  reset, it resumes forward only. See
  [recovery](../user-manual/dex.md#recovery--empty-or-stale-dex-projection).

## Platform coverage

Windows has the fullest collector. macOS and Linux collect a deliberately
narrower set; workstation-only headings such as battery, Wi-Fi and display are
not applicable on headless Linux servers. The per-signal, per-platform table is
[docs/capability-registries/dex_obs_platforms.tsv](../capability-registries/dex_obs_platforms.tsv),
and the platform sections of [the signal catalogue](../dex-signal-catalog.md)
describe each collector. Because each operating system carries its own signal
scope, compare rates within a platform, not across platforms.

## Related pages

- [Fleet health](fleet-health.md): the Overview, Health score and Trends.
- [Apps](apps.md): application crashes and hangs.
- [Alerts](alerts.md): route chosen signal types to notifications.
- [Collectors and plugins](collectors-and-plugins.md): how the data is gathered.
- [Guaranteed State](../user-manual/guaranteed-state.md#dex-signal-observations): the store the signals sit in.
