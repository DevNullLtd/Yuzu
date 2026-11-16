# Alerts: fleet incidents and signal routing

DEX (Digital Employee Experience) alerts tell you when something is going wrong
across your fleet, so you do not have to be looking at the dashboard to notice.
There are two kinds: automatic **fleet incident** alerts, and **routed signal**
alerts that you choose.

[Back to the hub](README.md) | [Surface map](surfaces.md)

## What it is

- **Fleet incident (blast radius).** When several distinct devices report the
  same signal type and the same subject inside a short window, the server raises
  a fleet incident. An example is `process.crashed` for one application on five
  devices within fifteen minutes. It is always on.
- **Routed signals.** You tick the signal types you care about, and each routed
  observation raises an operator notification and a webhook event. Nothing is
  routed by default.
- **The Alerts tab.** The DEX **Alerts** tab holds the incident thresholds, the
  routing list and the Prometheus cohort export key (see
  [performance](performance.md#prometheus-rollup)).

## Why it is useful

- **One failure spreading is the expensive kind.** A bad update that crashes an
  application on many devices shows up as one incident, and your ticketing
  system can open it automatically.
- **No flood.** Both kinds are rate limited, so a flapping device or a
  correlated multi-application incident cannot bury you.
- **Tunable without a restart.** Thresholds and routing apply immediately.

## What feeds it and how to enable it

Both kinds are driven by the signals that agents report, so they depend on the
DEX observer (see [collectors and plugins](collectors-and-plugins.md#the-dex-observer)).
Detection runs where observations arrive on the server, so devices that connect
directly and devices that connect through a gateway both count. Time is server
receipt time, so an agent with a skewed clock cannot stretch the window.

Nothing needs enabling for fleet incidents. Routed signals start empty.

## Using it in the dashboard

Open **DEX**, then **Alerts**. The tab is for administrators; anyone else sees a
note naming the role.

1. **Fleet blast-radius thresholds.** Set the minimum number of distinct devices
   (2 to 100000), the sliding window in seconds (60 to 86400) and the cooldown
   after an incident fires. Defaults are 5 devices, a 15-minute window and a
   one-hour cooldown.
2. **Signal routing.** Tick the signal types to route, grouped by the same
   families as the Catalogue. Good candidates are low-volume, high-meaning
   types such as the sustained performance breaches, `os.bugcheck`,
   `disk.smart_failure` and `security.rtp_disabled`. Routing a chatty type such
   as `process.crashed` is safe for the server and noisy for you.
3. **Cohort export key.** Optionally set a tag key to export per-cohort
   performance gauges. It is empty by default.

Changes apply immediately.

## What you receive

**Operator notification.** Each fleet incident raises a notification in the
dashboard bell with severity `warn`, naming the signal, the subject and the
device count. Each routed observation raises one too.

**Webhook and offload events.** Subscribe to either event in
[webhooks](../user-manual/rest-api.md#webhooks).

| Event | Sent when | Fields |
|---|---|---|
| `dex.blast_radius` | A fleet incident fires. | `obs_type`, `subject`, `device_count`, `window_seconds` |
| `dex.signal` | A routed signal is reported. | `obs_type`, `subject`, `agent_id` |

**Rate limits.** A standing incident re-alerts at most once per cooldown, per
signal and subject pair. A routed signal fires at most once per device per hour
per type. A global per-minute cap sits underneath both. The memory and fan-out
bounds are not configurable, because they are protection rather than policy.

## REST

There is no REST route for alert configuration. The events leave through
webhooks and offload targets, which have their own routes in the
[REST reference](../user-manual/rest-api.md#webhooks).

## MCP

There is no MCP tool for alert configuration.

## Permissions and audit

| Action | Permission | Audit |
|---|---|---|
| View or change the Alerts tab | Administrator role | `settings.dex_alerts.blast`, `settings.dex_alerts.routing` and `settings.dex_alerts.cohort_export` on change |

The role test counts an active just-in-time elevation. Service-scoped and MCP
tokens never count.

## Limits and privacy

- Fleet incidents need at least two devices by design. Single-device alerting is
  what signal routing is for.
- The agent-side thresholds for sustained performance breaches (90 percent CPU
  for ten minutes, and so on) are fixed and are not set from this tab.
- Detector and router activity is exported as Prometheus counters and gauges
  with the prefixes `yuzu_server_dex_blast_radius_` and `yuzu_server_dex_alert_`.
  The series are listed in [DEX in the user manual](../user-manual/dex.md#routing-signals-to-alerts).
- Alerts name signal types, subjects and, for routed signals, a device id. Treat
  webhook receivers accordingly.

## Platform coverage

Alerts work on whatever the fleet reports. A signal type that a platform does not
collect cannot fire for it. See [signals](signals.md#platform-coverage).

## Related pages

- [Signals](signals.md): the types you can route.
- [Apps](apps.md): drill into the application behind an incident.
- [DEX in the user manual](../user-manual/dex.md#fleet-incident-alerts-blast-radius): full reference.
