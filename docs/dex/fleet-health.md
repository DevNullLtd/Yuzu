# Fleet health: Overview, Health score and Trends

DEX (Digital Employee Experience) fleet health is the top of the guide: three
dashboard tabs that answer "how is the workforce doing on their machines right
now, and is it getting better or worse?"

[Back to the hub](README.md) | [Surface map](surfaces.md)

## What it is

- **Overview** is the landing page of `/dex`. It summarises the fleet in a few
  measured figures and links into every deeper page.
- **Health score** is a secondary composite from 0 to 100, with its full
  working shown.
- **Trends** compares operating systems side by side and shows how each
  signal family moves over time.

All three read the same store of signal observations that the agents report
(see [signals](signals.md)). They only read and aggregate; they never author
or enforce anything.

## Why it is useful

- **A number a leader can quote.** The headline is a measured rate, such as
  the share of devices with no application crash in the window. It is not a
  made-up score.
- **Honest about what it cannot see.** A device that is offline or silent is
  unknown, not healthy. If nothing is reporting, the tile shows a dash rather
  than a reassuring figure.
- **Fair across operating systems.** Each operating system carries the list of
  signals it actually collects, so a platform with narrower collection reads as
  less observed, never as healthier.
- **A starting point, not a dead end.** Every tile and row opens the
  application, signal or device behind it.

## What feeds it and how to enable it

The data comes from the agent's DEX observer, which reads operating-system
event sources on each device and reports uniform observations to the server.
It is on by default. See
[collectors and plugins](collectors-and-plugins.md#the-dex-observer) for the
observer, what it collects on each platform and how to switch it off.

The Overview's explore cards also carry live teaser figures from the deeper
pages (see [performance](performance.md)).

## Using it in the dashboard

Open **DEX** in the sidebar. The Overview opens first.

1. Pick a window (`24h`, `7d`, `30d` or `All`).
2. Read the four headline tiles:
   - **Crash-free devices** is the share of reporting Windows devices with no
     application crash in the window.
   - **Crashes per 1,000 device-days** normalises crash frequency by fleet size
     and window length.
   - **Devices impacted** is the number of distinct devices with a crash in
     the window.
   - **Agents reporting** is the count of agents reporting now. It stands in
     for "telemetry coverage", because a coverage percentage would need a fleet
     size the server does not know.
3. Scan the explore cards, the crashes-per-day chart, the top crashing
   applications beside the most affected devices, and the by-operating-system
   summary.
4. Click a card, an application or a device to go deeper.

The rates are computed over currently reporting Windows agents only, the
platform with the most complete collector. Offline agents are left out of the
denominator rather than counted as healthy.

**Health score.** Open the **Health score** tab. The score is 100 minus
weighted deductions, and the page lists each family's deduction and the
weighting preset in force: Default, Stability, Productivity or Security.
With no reporting agents the score is suppressed, never shown as 100.

**Trends.** Open the **Trends** tab for cross-operating-system comparison
cards (each with its live signal scope), per-family small-multiple sparklines
and a family-by-day activity heatmap.

## REST

- `GET /api/v1/dex/overview` returns the landing-page summary, including the
  top-devices list. Takes `window`.
- `GET /api/v1/dex/health` returns the composite score and its decomposition.
  Takes `window` and `weighting` (`default`, `stability`, `productivity` or
  `security`; default `default`).
- `GET /api/v1/dex/trends` returns the cross-OS comparison and per-family trend
  data. Takes `window`.

Full shapes: [REST reference](../user-manual/rest-api.md#dex-digital-employee-experience).

## MCP

- `get_dex_overview` mirrors the overview route.
- `get_dex_health` mirrors the health route.
- `get_dex_trends` mirrors the trends route.

## Permissions and audit

| Surface | Permission | Audit |
|---|---|---|
| Overview (REST, MCP) | `GuaranteedState:Read` | `dex.overview.view`. REST refuses to answer if the row cannot be stored. |
| Health score, Trends | `GuaranteedState:Read` | Not audited. They carry no device identity. |

The Overview is audited on REST and MCP because its top-devices list names
devices; the dashboard Overview opens without an audit row. A service-scoped
token is refused on all three reads. See
[surfaces](surfaces.md#the-rest-api).

## Limits and privacy

- The headline rates cover Windows agents that are reporting now. When no
  agent is reporting, the rate tiles show a dash.
- Health score and Trends are secondary to the measured rates. Read the
  decomposition before acting on a single number.
- Nothing here is mock data. Every figure is an aggregation or an explicit "no
  data" note.
- Signals are projected from the Guardian event store. The projection is
  forward-only, so history from before it was created is not rebuilt.

## Platform coverage

The headline rates use Windows agents. The signal scope shown on each
operating-system card says what that platform collects. Per-signal coverage is
in [signals](signals.md#platform-coverage).

## Related pages

- [Signals](signals.md): the catalogue and drill-downs behind these tiles.
- [Apps](apps.md): application stability, linked from the top-crashing list.
- [Performance](performance.md): live device performance.
- [DEX in the user manual](../user-manual/dex.md): the detailed reference.
