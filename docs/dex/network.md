# Network quality: how connections feel from the device

DEX (Digital Employee Experience) network quality shows how healthy each
device's network link is, measured on the device from operating-system counters.
It needs no packet capture, no flow export and no network appliance.

[Back to the hub](README.md) | [Surface map](surfaces.md)

This page is a short guide. The full reference, including the privacy model, is
[the Network quality dashboard](../user-manual/network.md).

## What it is

The **Network** tab is a now-view like [Performance](performance.md). It shows
fleet-now cards for round-trip time, the interval retransmit rate and device
throughput, each with its own reporting population, and a **Devices** list of
the worst devices by a chosen metric. The page is also reachable at `/network`
and under **Fleet** in the sidebar.

Network discovery, the Discovered tab of the same page, is an Estate feature and
not part of DEX. It is described in
[Discovered hosts](../user-manual/network.md#discovered-hosts).

## Why it is useful

- **Tell a bad link from a bad device.** A weak Wi-Fi or congested uplink drives
  loss across every connection, so the device-wide retransmit rate flags it
  cleanly, and a device whose network is fine but whose CPU is struggling reads
  differently.
- **Evidence, not a verdict.** The page reports measured rates and does not
  classify devices as "degraded", because a trustworthy threshold needs a
  baseline from your own fleet.
- **Honest denominators.** Round-trip time has its own, smaller population, and a
  device that does not report a metric is left out of that metric, never counted
  as zero.

## What feeds it and how to enable it

- **Fleet cards and device list** come from heartbeat tags that the agent
  derives from kernel counters: median round-trip time, interval retransmit
  rate and device throughput. They are on by default and stopped by the agent's
  `--dex-disable` switch.
- **Per-connection detail** is a separate Echo source, `netqual`, kept on the
  device and reachable through Echo queries. It is on by default and controlled
  by Echo's `netqual_enabled` setting. Only a coarse destination class
  (loopback, private or public) is stored; remote addresses are dropped at the
  edge. Windows needs an elevated agent for it and macOS needs a root agent;
  without that, the source records nothing. To check a device, read
  `netqual_capture_method` in the output of Echo's `status` action: `none`
  means the agent is recording nothing.

See [collectors and plugins](collectors-and-plugins.md#the-echo-plugin).

## Using it in the dashboard

1. Open **DEX**, then **Network**.
2. Read the cards. Each is a fleet-wide median with p50, p90 and max, beside the
   number of devices behind it.
3. Open **Devices** to list worst devices by round-trip time, retransmit rate
   or throughput, or the devices that are not reporting. Each row opens the
   device drill-down.

Round-trip time is a coarse signal, a median across whatever connections are
open. Throughput is an upper bound, because stacked interfaces such as a bridge
and its virtual pairs count a packet at each layer. It says which device has a
poor link, not which destination or application is affected.

## REST

- `GET /api/v1/network/fleet` returns the fleet-now figures and their
  populations.
- `GET /api/v1/network/devices` returns the worst-devices list. Takes `metric`
  (`rtt`, `retrans` or `throughput`), `filter=not_reporting`, `key` and
  `cohort_value` for a tag cohort, `limit` and `cooc`. `cooc` (`device`, `app`,
  `network_only` or `degraded`) filters to a co-occurrence band. The bands list
  only devices flagged network-degraded, and agents do not send that flag, so
  they return no rows; see
  [the user manual](../user-manual/network.md#degraded-classification--co-occurrence--a-later-slice).

## MCP

- `get_network_fleet` mirrors the fleet route.
- `list_network_devices` mirrors the devices route.

## Permissions and audit

Both routes need `GuaranteedState:Read`. The fleet figures are not audited. The
device list names devices fleet-wide, so it is audited as
`network.device.view` (REST refuses to answer if the row cannot be stored). A
service-scoped token is refused on both routes. See
[surfaces](surfaces.md#the-rest-api).

## Limits and privacy

- Only device-aggregate facts leave the device on the heartbeat. No
  per-connection or per-destination data does.
- The Windows retransmit figure is system-wide and includes loopback, so it is
  caveated on the page and withheld from the Prometheus retransmit gauge, which
  covers Linux only.
- The `yuzu_fleet_net_*` gauges carry an `os` label. Do not alert on a cross-OS
  aggregate. See [the metrics reference](../user-manual/metrics.md).

## Platform coverage

| Platform | Round-trip time | Retransmit rate | Throughput |
|---|---|---|---|
| Linux | Yes | Yes | Yes |
| Windows | Per connection through Echo, not on the heartbeat | Yes | Yes |
| macOS | No | No | Yes |

## Related pages

- [Performance](performance.md): the sibling now-view for CPU, memory and disk.
- [Collectors and plugins](collectors-and-plugins.md): heartbeat tags and Echo.
- [Network quality dashboard](../user-manual/network.md): full reference.
