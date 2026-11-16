# DEX guide

DEX (Digital Employee Experience) is Yuzu's view of what the workforce actually
experiences on their machines: applications that crash or hang, devices that
boot slowly or run out of memory, networks that drop, services that fail. It is
a read-only lens. It measures and reports; it does not author or enforce
anything.

This guide is a set of short pages, one per area. Each page covers what the
capability is, why it is useful, which collectors and plugins feed it, and how
to use it from the dashboard, the REST API and MCP. The detailed reference for
each dashboard view is [DEX in the user manual](../user-manual/dex.md); this
guide links to it rather than copying it.

## Why DEX

- **Measured, not guessed.** Headline figures are real rates with their
  populations beside them, not invented scores.
- **Honest about gaps.** A device that cannot be heard from is unknown, not
  healthy. A platform with narrower collection reads as less observed.
- **Edge first.** Measurement happens on the device. Only thin, device-aggregate
  facts leave it, and user content is dropped before anything is sent.
- **Three surfaces, one model.** Almost everything a person sees on the
  dashboard is also available to scripts over REST and to agentic workers over
  MCP. The [surface map](surfaces.md#the-capability-map) lists the exceptions.

## How the data flows

1. Agents collect on each device: the DEX observer reads operating-system event
   sources, the heartbeat carries performance and network readings, and Echo
   keeps a local warehouse of detail.
2. Agents send signal observations, heartbeat tags and a once-a-day summary of
   per-application data to the server.
3. The server stores observations in a read model projected from the Guardian
   event store, aggregates the heartbeat tags each cycle, and keeps retained
   per-application history.
4. The dashboard, the REST API and the MCP server all read those same models, so
   they agree figure for figure.

[Collectors and plugins](collectors-and-plugins.md) describes step 1 in detail.

## Quick start

1. Make sure your account holds `GuaranteedState:Read`. Every DEX read needs it
   except per-device application usage, which needs `Forensics:Read`.
2. Open **DEX** in the sidebar, or go to `/dex`. Start at the Overview and click
   down.
3. For scripts, create an API token and call a route such as
   `GET /api/v1/dex/overview`. For an agentic worker, create an API token with an
   MCP tier and call a tool such as `get_dex_overview`. Worked examples are in
   [surfaces](surfaces.md).
4. Use the [surface map](surfaces.md#the-capability-map) to find the route and
   tool for any dashboard page.

## Turning collection off

Collection is controlled on each agent, at deploy time. The agent's `--dex-disable`
switch stops the DEX observer and the heartbeat performance and network tags on
that device. It does not stop Echo's sampling, which is switched off separately,
source by source, in Echo's settings. Do not read it as "all DEX collection off".
See [collectors and plugins](collectors-and-plugins.md) for exactly what each
switch stops and what keeps running.

## Pages

| Page | What it covers |
|---|---|
| [Surfaces](surfaces.md) | How the dashboard, REST and MCP work, and the map from every capability to its page, route, tool, collector and permission. |
| [Fleet health](fleet-health.md) | Overview, Health score and Trends. |
| [Signals](signals.md) | The signal catalogue, drill-downs, device history and live info. |
| [Apps](apps.md) | Application stability and the score policy. |
| [Performance](performance.md) | CPU, memory and disk now, cohorts and per-device performance. |
| [App performance](app-performance.md) | Per-application CPU and memory over time and version comparison. |
| [Network](network.md) | Network quality from the device. |
| [App usage](app-usage.md) | Which executables ran on a device. |
| [Alerts](alerts.md) | Fleet incident and routed signal alerts. |
| [Collectors and plugins](collectors-and-plugins.md) | What feeds DEX and how to switch each part. |
| [Contributing](contributing.md) | How to add or change a page in this guide. |

## Related documentation

- [DEX in the user manual](../user-manual/dex.md): the detailed reference.
- [The signal catalogue](../dex-signal-catalog.md): every signal, channel,
  extracted field and privacy rule.
- [REST reference](../user-manual/rest-api.md#dex-digital-employee-experience)
  and [MCP guide](../user-manual/mcp.md): full request and response shapes.
- [Guaranteed State](../user-manual/guaranteed-state.md): the Guardian event
  store DEX reads from.
