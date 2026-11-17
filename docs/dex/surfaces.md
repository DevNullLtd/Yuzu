# DEX surfaces: dashboard, REST API and MCP

DEX (Digital Employee Experience) is reachable three ways, and each shows the
same read models:

- the **dashboard** at `/dex`, for people;
- the **REST API** under `/api/v1/dex/`, for scripts and integrations;
- the **MCP (Model Context Protocol) server** at `/mcp/v1/`, for agentic workers.

This page explains how each surface behaves, shows one worked example of each,
and ends with the capability map: one row per capability, naming the dashboard
page, the REST route, the MCP tool, what feeds it and the permission it needs.
Every area page in this guide links back to the map.

[Back to the hub](README.md)

## The dashboard

Open **DEX** in the sidebar, or go to `/dex`. The page has a shared sub-navigation:
**Overview, Apps, Catalogue, Health score, Trends, Performance, App Performance,
Network, Scoring, Alerts**. Overview is the hub; the other tabs are the deep pages.

Conventions that apply to every tab:

- **Window selector.** `24h`, `7d`, `30d` or `All` rescopes the signal views.
  The default is `7d`. `All` is not a longer history than the store keeps:
  observations are kept for 30 days by default, so `30d` and `All` match unless
  that setting was raised. Drill-downs inherit the window you were viewing, so
  the numbers on a drill-down match the panel you came from. Performance and
  Network are now-views and have no window.
- **Operating-system filter.** The Catalogue has an All / Windows / Linux /
  macOS filter that rescopes coverage and scores. The Apps tab has its own
  platform chips.
- **Honest empties.** A view with no data says so. A rate with no population
  shows a dash, never a made-up number, and an offline device is left out of the
  rates. A connected device whose observer is switched off or not armed is still
  counted, as crash-free; see [fleet health](fleet-health.md#limits-and-privacy).
- **Everything drills.** Cards and rows open the next level down: an
  application, a signal type, a device, one observation.

Worked example: from a crash spike to the event behind it. On the Overview, read
the top crashing applications and click one name to open its blast-radius
drill-down. Click an affected device to open that device's signal history, then
click one row of the history to read the single observation. The window you
chose on the Overview stays selected all the way down.

The Scoring and Alerts tabs are configuration pages. Scoring edits the
[score policy](apps.md#the-score-policy); Alerts is for administrators and
configures [alert routing](alerts.md).

## The REST API

All routes live under `/api/v1/dex/`, plus the network routes and the
per-device app-usage route (see the map below). Conventions:

- **Authentication.** Send an API token as `Authorization: Bearer <token>`.
  See [Authentication](../user-manual/rest-api.md#authentication).
- **Permissions.** A permission named on these pages is enforced as written
  only while RBAC enforcement is on, and it is off by default. With it off, any
  signed-in user passes a read such as `GuaranteedState:Read`, while writes,
  `Execution:Execute` and `Forensics:Read` need the administrator role. See
  [RBAC](../user-manual/rbac.md#enabling-rbac).
- **Envelope.** Success is `{"data": ..., "meta": {...}}`. Errors use the
  standard error envelope with a `correlation_id`; see
  [JSON Envelope](../user-manual/rest-api.md#json-envelope).
- **Time windows.** The signal routes take `window` as `24h`, `7d`, `30d` or `all`.
  Leaving it out means `7d`. An empty or unknown value is a `400` error,
  not a silent fallback. The Apps list also takes `platform` as `all`,
  `windows`, `macos` or `linux`.
- **Read-only, except the score policy.** Every route is a read except
  `PUT` and `DELETE` on the score policy and `POST` on the live-info route
  (a `POST` only because it waits for the device to answer).
- **Failed store reads.** Some routes fail loudly and some do not. The device
  score, the catalogue, the Apps list, per-device application usage and the
  retained application-performance reads (the picker, the fleet, group and tag
  trends, the version-devices drill, the version comparison and one device's
  retained history) answer `503` with a `retry_after_ms` hint. The Overview,
  Health score, Trends, the signal rollup, scope and signal drill-down, the
  application drill-down, the catalogue family drill-down and a device's signal
  history do not: if their read fails they answer `200` with empty figures, the
  crash-free rate reads 100 percent and the health score carries no deductions,
  and a single observation reads as `404`. A clean answer from those is not
  proof of a quiet fleet. Every failed read is counted on
  `yuzu_server_guardian_read_degrade_total`, labelled by reason and source;
  check it before you trust a surprisingly empty answer.
- **Audit.** Routes that name individual devices write an audit row before
  they answer, and refuse to answer (`503` with `Sec-Audit-Failed: true`) if
  that row cannot be stored. Aggregates that carry no device identity are not
  audited. Each area page lists its verbs.
- **Service-scoped tokens.** A token scoped to one service is refused on
  every DEX route except these:
  - The per-device routes under `/api/v1/dex/devices/{id}` accept it only for a
    device tagged with its own service.
  - `GET /api/v1/dex/perf/app/devices` answers with only the devices the token
    can see.
  - Both kinds need RBAC enforcement to be on and the service owner role to hold
    the permission.
  - Every other route is refused, aggregates included, and so is the per-device
    app-usage route, because the service owner role does not hold
    `Forensics:Read`.
  - Every refusal on REST and MCP is audited. The overview, the signal and
    application drill-downs, the performance and network device lists, the group
    and tag trends and the version comparison record it under their own verb
    with the result `denied`. Every other refused route records the standard
    permission-denied row.
  - The dashboard's fragments make the same checks, and the version drill uses
    the same gate as its route, so a service-scoped token gets no fleet-wide
    data there either. The dashboard writes the same audit rows for the views
    that name devices, but a fragment still renders when a row cannot be
    stored, where REST refuses to answer.
  - The per-device panels (device history, one observation, live performance,
    Top applications and application history) follow the per-device rule. The
    Application usage panel shows a permission note instead of an error.
- **Management-group grants.** A grant scoped to a management group alone does
  not pass the aggregate reads, which need a global `GuaranteedState:Read`. It
  does pass the per-device reads for devices in the group.

Worked example: the signal rollup for Windows devices over the last seven days.

    curl -sS -H "Authorization: Bearer $YUZU_TOKEN" \
      "https://yuzu.example.com:8080/api/v1/dex/signals?window=7d&os=windows"

The answer is a list of `{obs_type, count, distinct_devices, last_seen}` rows.
Full request and response shapes are in the
[REST reference](../user-manual/rest-api.md#dex-digital-employee-experience)
and in the server's own `GET /api/v1/openapi.json`.

## The MCP server

An agentic worker reaches the same data through MCP tools. Conventions:

- **Endpoint and tokens.** `POST /mcp/v1/` with an API token minted with an
  `mcp_tier` (`readonly`, `operator` or `supervised`). A token without a tier
  is refused. See the [MCP guide](../user-manual/mcp.md).
- **Read tools work at every tier.** The DEX read tools need
  `GuaranteedState:Read` and are available to a `readonly` token. The
  per-device app-usage tool needs `Forensics:Read` instead, and is available at
  every tier too.
- **Same model, same numbers.** A tool answers from the same read model as the
  REST route it mirrors, so the two agree figure for figure. Tool arguments
  match the route's query parameters. The one difference is the device: the
  per-device tools take it as `agent_id`, where the REST routes carry it in the
  path as `{id}`.
- **Score-policy tools.** `get_dex_score_policy` reads at every tier.
  `set_dex_score_policy` and `reset_dex_score_policy` are write tools: a
  supervised-tier token is required, and `reset_dex_score_policy` also needs
  an approval ticket. See [Apps](apps.md#the-score-policy).
- **Audit.** A tool that names devices records the same audit verb as its REST
  twin, with one exception: `compare_app_perf_versions` records the generic
  `mcp.compare_app_perf_versions` row on success and uses `dex.app_perf.compare`
  only for a refusal. Most tools set-and-proceed on MCP, flagging
  `audit_persisted: false` if the row was lost; the per-device app-usage tool
  withholds data instead.
- **Service-scoped tokens.** A tool follows the same rule as the REST route
  it mirrors. A token scoped to one service is refused on every DEX tool
  except the per-device tools (`get_dex_device_score`,
  `get_dex_device_history`, `get_dex_observation` and
  `get_dex_device_app_perf`), which accept it only for a device tagged with its
  own service, and `list_dex_app_perf_devices`, which answers with only the
  devices the token can see. The other tools are refused, either before the
  handler runs or by the handler's own permission check.

Worked example: ask for the fleet's CPU, memory and disk figures.

    {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": { "name": "get_dex_perf_fleet", "arguments": {} }
    }

## The capability map

### How this map is kept current

This map is maintained by hand. When a route or tool is added, renamed or
removed, update its row in the same change. The authoritative lists are the
[REST reference](../user-manual/rest-api.md#dex-digital-employee-experience) and
the [MCP guide](../user-manual/mcp.md); where this table and those pages
disagree, they win. See [contributing](contributing.md) for the rule.

Every route listed here is under `/api/v1`. "Read" means
`GuaranteedState:Read` unless the row says otherwise. Audit statements describe
the REST route and its MCP twin, except that `compare_app_perf_versions`
records `mcp.compare_app_perf_versions` on success. The dashboard writes the
same verb when it opens the same view, with two exceptions: the Overview and
the application drill-down open without an audit row. Unless a row says
otherwise, a service-scoped token is refused on the route and on the tool in
the same row; see the service-scoped rule under
[the REST API](#the-rest-api). Network discovery (the
Discovered tab of the Network page) is an Estate feature, not DEX, and is not in
this map; see [network](network.md).

### Fleet health

| Capability | Dashboard | REST | MCP | Fed by | Permission and audit | Page |
|---|---|---|---|---|---|---|
| Executive summary and headline reliability | Overview | `GET /api/v1/dex/overview` | `get_dex_overview` | DEX observer | Read; audited `dex.overview.view` | [fleet health](fleet-health.md) |
| Composite health score and its deductions | Health score | `GET /api/v1/dex/health` | `get_dex_health` | DEX observer | Read; not audited | [fleet health](fleet-health.md) |
| Cross-OS comparison and trends | Trends | `GET /api/v1/dex/trends` | `get_dex_trends` | DEX observer | Read; not audited | [fleet health](fleet-health.md) |

### Signals

| Capability | Dashboard | REST | MCP | Fed by | Permission and audit | Page |
|---|---|---|---|---|---|---|
| Signal catalogue: families, coverage, health per family | Catalogue | `GET /api/v1/dex/catalogue`<br>`GET /api/v1/dex/catalogue/group` | `get_dex_catalogue`<br>`get_dex_catalogue_group` | DEX observer | Read; not audited | [signals](signals.md) |
| Signal rollup and per-OS coverage | Catalogue | `GET /api/v1/dex/signals`<br>`GET /api/v1/dex/scope` | `list_dex_signals`<br>`get_dex_signal_scope` | DEX observer | Read; not audited | [signals](signals.md) |
| One signal type in depth | Catalogue, signal drill | `GET /api/v1/dex/signals/{obs_type}` | `get_dex_signal_detail` | DEX observer | Read; audited `dex.signal.view` | [signals](signals.md) |
| One device: score and signal summary | Device drill | `GET /api/v1/dex/devices/{id}` | `get_dex_device_score` | DEX observer | Read, scoped to the device; a service-scoped token reaches only devices tagged with its own service; audited `dex.device.view` | [signals](signals.md) |
| One device: signal history | Device drill | `GET /api/v1/dex/devices/{id}/history` | `get_dex_device_history` | DEX observer | Read, scoped to the device; a service-scoped token reaches only devices tagged with its own service; audited `dex.device.view` | [signals](signals.md) |
| One observation in detail | Device drill, event panel | `GET /api/v1/dex/devices/{id}/observations/{event_id}` | `get_dex_observation` | DEX observer | Read, scoped to the device; a service-scoped token reaches only devices tagged with its own service; audited `dex.observation.view` | [signals](signals.md) |
| Live uptime or process list from a device (these two kinds on REST; the device page offers more) | Device page, Get live info | `POST /api/v1/dex/devices/{id}/live` | None | `os_info`, `processes` plugins | Read, `Execution:Execute` and `Inventory:Read` (checked at dispatch), scoped to the device; a service-scoped token reaches only devices tagged with its own service; audited `device.live.uptime` or `device.live.processes` before dispatch | [signals](signals.md) |

### Applications

| Capability | Dashboard | REST | MCP | Fed by | Permission and audit | Page |
|---|---|---|---|---|---|---|
| Application stability list | Apps | `GET /api/v1/dex/apps` | `list_dex_apps` | DEX observer | Read; not audited | [apps](apps.md) |
| One application's blast radius | Apps, app drill | `GET /api/v1/dex/app` | `get_dex_app` | DEX observer | Read; audited `dex.app.view` | [apps](apps.md) |
| Read the score policy | Scoring | `GET /api/v1/dex/score-policy` | `get_dex_score_policy` | Runtime config | Read; not audited | [apps](apps.md) |
| Replace the score policy | Scoring | `PUT /api/v1/dex/score-policy` | `set_dex_score_policy` | Runtime config | `Infrastructure:Write` (and Read for the tool); audited `dex.score_policy.update` or `dex.score_policy.validate`; supervised-tier token on MCP | [apps](apps.md) |
| Reset the score policy to defaults | Scoring | `DELETE /api/v1/dex/score-policy` | `reset_dex_score_policy` | Runtime config | `Infrastructure:Write` on REST; `Infrastructure:Delete` plus an approval ticket on MCP; audited `dex.score_policy.reset` | [apps](apps.md) |

### Device performance now

| Capability | Dashboard | REST | MCP | Fed by | Permission and audit | Page |
|---|---|---|---|---|---|---|
| Fleet CPU, memory and disk figures | Performance | `GET /api/v1/dex/perf/fleet` | `get_dex_perf_fleet` | Heartbeat performance tags | Read; not audited | [performance](performance.md) |
| Cohort benchmarking by tag value | Performance | `GET /api/v1/dex/perf/cohorts` | `get_dex_perf_cohorts` | Heartbeat performance tags, device tags | Read; not audited | [performance](performance.md) |
| Compare two cohorts | Performance | `GET /api/v1/dex/perf/cohort-diff` | `get_dex_perf_cohort_diff` | Heartbeat performance tags, device tags | Read; not audited | [performance](performance.md) |
| Devices behind a metric, a cohort or not reporting | Performance drill | `GET /api/v1/dex/perf/devices` | `list_dex_perf_devices` | Heartbeat performance tags | Read; audited `dex.perf.device.view` | [performance](performance.md) |
| One device's live performance (dashboard only) | Device drill, device performance panel | None | None | Echo `perf` | Read and `Execution:Execute`, both scoped to the device; audited `dex.device.perf.query` | [performance](performance.md) |

### Application performance over time

| Capability | Dashboard | REST | MCP | Fed by | Permission and audit | Page |
|---|---|---|---|---|---|---|
| Applications with retained history | App Performance | `GET /api/v1/dex/perf/apps` | `list_dex_perf_apps` | Echo `procperf`, daily sync | Read; not audited | [app performance](app-performance.md) |
| Fleet trend for one application | App Performance | `GET /api/v1/dex/perf/app` | `get_dex_app_perf` | Echo `procperf`, daily sync | Read; not audited | [app performance](app-performance.md) |
| Devices behind one application version | App Performance, version drill | `GET /api/v1/dex/perf/app/devices` | `list_dex_app_perf_devices` | Echo `procperf`, daily sync | Fleet read, confined to visible devices; a service-scoped token gets only the devices it can see; audited `dex.app_perf.devices.view` | [app performance](app-performance.md) |
| Trend for one management group | App Performance | `GET /api/v1/dex/perf/group` | `get_dex_group_app_perf` | Echo `procperf`, daily sync | Read; not audited on success | [app performance](app-performance.md) |
| Trend for one device-tag cohort | App Performance | `GET /api/v1/dex/perf/tag` | `get_dex_tag_app_perf` | Echo `procperf`, daily sync | Read; not audited on success | [app performance](app-performance.md) |
| One device's live top applications (dashboard only) | Device drill, Top applications panel | None | None | Echo `procperf` | Read and `Execution:Execute`, both scoped to the device; audited `dex.device.procperf.query` | [app performance](app-performance.md) |
| One device's retained per-application history | Device drill | `GET /api/v1/dex/devices/{id}/app-perf` | `get_dex_device_app_perf` | Echo `procperf`, daily sync | Read, scoped to the device; a service-scoped token reaches only devices tagged with its own service; audited `dex.device.app_perf.view` | [app performance](app-performance.md) |
| Before and after comparison of two versions | `/auto` Verify stage | `GET /api/v1/dex/perf/compare` | `compare_app_perf_versions` | Echo `procperf`, daily sync | Read; audited `dex.app_perf.compare` on REST and the Verify stage, `mcp.compare_app_perf_versions` on MCP success; the Verify stage's per-machine table is audited `dex.app_perf.compare.drill` | [app performance](app-performance.md) |

### Network quality

| Capability | Dashboard | REST | MCP | Fed by | Permission and audit | Page |
|---|---|---|---|---|---|---|
| Fleet network quality now | Network | `GET /api/v1/network/fleet` | `get_network_fleet` | Heartbeat network tags | Read; not audited | [network](network.md) |
| Worst devices by network metric | Network, Devices | `GET /api/v1/network/devices` | `list_network_devices` | Heartbeat network tags | Read; audited `network.device.view` | [network](network.md) |

### Application usage

| Capability | Dashboard | REST | MCP | Fed by | Permission and audit | Page |
|---|---|---|---|---|---|---|
| One device's per-executable usage | Device page, Application usage | `GET /api/v1/forensics/agents/{id}/app-usage` | `get_agent_app_usage` | Echo `usage`, `app_usage` plugin, daily sync | `Forensics:Read` scoped to the device; refused to service-scoped tokens, whose role does not hold `Forensics:Read`; audited `app_usage.agent.view`, fails closed | [app usage](app-usage.md) |

### Alerts

Alert routing and the fleet-incident thresholds are configured on the
dashboard's Alerts tab. There is no dedicated REST route and no MCP tool for
them; the generic configuration route accepts their keys but does not apply
them until the next Alerts-tab save or a restart. The events they raise reach
other systems through webhooks. See [alerts](alerts.md).
