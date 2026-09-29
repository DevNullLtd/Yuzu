# Network Quality Dashboard

The `/network` dashboard is a continuous, fleet-wide view of TCP network
**quality**, measured on each agent endpoint from kernel counters. No packet
capture, no flow export, and no central network appliance is required — the
measurement happens at the edge and only thin, device-aggregate facts leave the
device.

It is deliberately *not* a network-appliance clone: because network quality is
measured on the same box as device performance and process/service activity, the
dashboard can show whether a network-degraded device *co-occurs* with a device
or app problem — something a network-only tool cannot do.

## Access

Network is a **sub-view of DEX**, not a standalone top-level nav item: open
**DEX** in the top navigation bar and choose the **Network** tab, or go to
`/network` directly. Permission required: **`GuaranteedState:Read`** (the same
permission that gates the Guardian and DEX read surfaces).

## Overview tab

Four fleet-now cards, updated each heartbeat cycle:

| Card | Metric |
|---|---|
| Round-trip time | Median smoothed RTT across active TCP connections (p50 / p90 / max) |
| TCP retransmission | Median device **interval** retransmit rate — ΔΣretransmits / ΔΣsegments smoothed over the last few heartbeats (loss in the recent window, **not** a lifetime average) |
| Throughput (device) | Median device rx+tx bytes/s, summed across non-loopback interfaces |
| Reporting | Devices whose latest heartbeat carried at least one network fact |

Every aggregate carries its reporting population. **RTT carries its own
(smaller) denominator** — devices that do not report smoothed RTT are excluded
from the RTT numbers, never counted as 0 ms.

> **RTT is a coarse signal.** It is a device-aggregate median across whatever TCP
> connections are open (loopback / LAN / internet blended together), so read it
> as a rough indicator, not per-flow truth. Actionable per-destination /
> per-app latency is a later (warehouse-tier) slice.

> **Throughput is a coarse upper bound.** It sums the byte counters of every
> non-loopback interface. On a host with stacked interfaces (a bridge plus its
> `veth` pairs, a VPN `tun` over a physical NIC, container bridges) a packet is
> counted on each layer it crosses, so the figure **over-counts** — treat it as
> an upper bound on device traffic, not a wire-accurate rate. Yuzu deliberately
> does not filter interfaces by name (that heuristic is fragile and would wrongly
> drop a VPN tunnel the operator cares about). Accurate per-interface / per-route
> throughput is a later warehouse-tier slice.

### Why this is device / local-link health, not localization

The interval retransmit rate is a **device-aggregate** signal: a bad *local*
link (Wi-Fi, congested uplink) drives loss across every connection, so the
device-wide rate flags it cleanly. It deliberately **cannot** say *which*
destination or app is affected — that localization ("is it the network, the
device, or the app?") is the deferred per-destination warehouse drill.

### Degraded classification & co-occurrence — a later slice

v1 is **measurement-first**: it surfaces the interval retransmit rate as
evidence but does **not** yet classify a device as *network-degraded*. A
trustworthy threshold needs a real-fleet baseline — healthy internet links
retransmit a little, so the cutoff cannot be guessed (a value tuned on a
loss-free link would cry wolf on every normal device). The earlier
absolute-lifetime-ratio degraded signal was empirically disproven (it is diluted
to noise) and has been retired.

The **co-occurrence headline** — "of the network-degraded devices, how many also
show device-perf pressure or app instability" — is gated on that classification,
so it lands in the same later slice. Until then the page is honest evidence, not
a verdict. The co-occurrence model (`NetCooccurrence`) and the
`yuzu_fleet_net_degraded` gauge stay wired but unfed: `recompute_metrics` clears
the gauge each cycle and re-emits it **only** when at least one agent reports the
`net_degraded` tag. Because no agent emits that fact today, the gauge is
**absent** (never emitted), not `0`. Treat absent as "not classified" — never
read a missing gauge as "0 degraded = healthy".

## Devices tab

Lists devices worst-by-metric (RTT, retransmit, or throughput), or filtered to a
co-occurrence band or to not-reporting devices, with the co-occurring
device/app facts flagged inline. Each row links to the device drill-down.

## Platform coverage (v1)

This table is the **device-level heartbeat** sampler (the fleet gauges). The
separate opt-in **per-connection `netqual` tier** below now has Windows RTT via
ESTATS — see its row.

| Platform | RTT (heartbeat) | Retransmit | Throughput |
|---|---|---|---|
| Linux | Full — netlink `INET_DIAG` per-connection `TCP_INFO` | Yes — per-connection sum | Yes (`/proc/net/dev`) |
| Windows | Heartbeat: not yet · **per-connection: yes via the opt-in `netqual` tier (ESTATS, elevated — ADR-0020)** | Yes — `GetTcpStatisticsEx` (system-wide; see caveat) | Yes (`GetIfTable2`) |
| macOS | Not yet (deferred) | Not yet (deferred) | Yes (`NET_RT_IFLIST2`) |

**Linux, Windows, and macOS agents all emit heartbeat network facts.** At the
**heartbeat** layer Windows reports device throughput (`GetIfTable2`) and an
interval retransmit rate (`GetTcpStatisticsEx`) but **not RTT** — the fleet
gauge has no per-connection ESTATS sweep. **Per-connection smoothed RTT IS
available on Windows** in the opt-in `netqual` TAR tier (below) via ESTATS
(`GetPerTcpConnectionEStats`: per-connection enable, **admin/elevated only**,
ms-resolution — ADR-0020); it is a distinct, on-device warehouse tier, not a
heartbeat gauge. **Two caveats on the Windows heartbeat retransmit rate:**
(1) the counter is **system-wide** — Windows exposes no per-interface TCP
retransmit MIB, so it
*includes loopback* and cannot be scoped to real interfaces; (2) it is
**measurement-first, unvalidated on Windows** — the interval-delta signal's
separation-under-loss was validated under `netem` on Linux only, and on a
loopback-dominated host (e.g. a single-box UAT rig) it dilutes toward ~0.
**macOS reports device throughput only**, via `NET_RT_IFLIST2` (a
routing-socket interface-list walk) — the same coarse, non-loopback aggregate
as the Linux/Windows paths. **Retransmit and RTT are deferred on macOS in v1.**
The originally-planned retransmit source — the global `net.inet.tcp.stats` OID
— is unusable: it returns an all-zero counter struct on current macOS (every
field reads 0, matching Apple's own `netstat -s -p tcp`), so it cannot back a
retransmit metric. A retransmit fact will follow from a per-flow source (a planned
NetworkStatistics/`nstat` client). Absent metrics are always
omitted from rollups; a device that does not report a metric is excluded from
that metric's denominator, never counted as zero.

## Collection & privacy

Only **device-aggregate** facts leave the endpoint on the heartbeat — median
RTT, the interval retransmit rate, and device throughput. **No per-connection or
per-destination data leaves the device on the heartbeat.** Network sampling
shares the agent's `--dex-disable` flag — disabling DEX disables the network
heartbeat facts.

### Per-connection tier (opt-in, off by default)

A separate **`netqual`** TAR capture source can record per-connection TCP
quality — smoothed RTT, jitter, and current-loss counters per ESTABLISHED
connection, joined to the owning process — into the agent's **local edge
warehouse** as `$NetQual_Live`. It is governed independently of the heartbeat:

- **Off by default.** Set the agent TAR config key **`netqual_enabled = true`**
  to enable it (mirrors `procperf_enabled`; per-connection telemetry is
  usage-class data under the works-council posture, so it is never on by
  default).
- **Bucket-only.** Only a coarse destination *class* — `loopback` / `private` /
  `public` — is stored. The raw remote address, port, and hostname are dropped
  at the collector edge and **never persisted**. The owning process is recorded
  as its image name only.
- **On-device.** These rows stay in the local warehouse (queryable via the
  Execute-gated TAR SQL surface as `$NetQual_Live`); they are not shipped to the
  server. A per-tick top-N cap and a row-count retention ceiling bound storage.
- **Linux, Windows, and macOS.** Linux reads netlink INET_DIAG; Windows reads
  TCP ESTATS (ADR-0020) and **requires an elevated agent** — non-elevated it
  records nothing and `tar.status` reports `netqual_capture_method|none`.
  Windows RTT is ms-resolution and `retrans`/`segs_out` count from first
  observation of the connection, not connection start (constraints listed in
  the compatibility matrix). **macOS reads per-socket `tcp_connection_info`
  via `nstat`**, the private `com.apple.network.statistics` kernel control
  (no framework, no entitlement) that also drives the macOS `tcp` source's
  event-driven lifecycle. It carries the same elevation caveat as
  Windows in spirit but a different mechanism: **system-wide flow visibility
  requires root**, so a non-root agent records nothing and reports
  `netqual_capture_method|none` rather than a silently partial capture. macOS
  RTT is already microsecond-resolution (no unit conversion); `lost` is a
  per-tick delta like Windows, since nstat exposes cumulative retransmit
  counters, not an instantaneous loss gauge. The struct layout is a private,
  version-unstable interface — a runtime self-check falls back to
  `capture_method=none` on a layout mismatch rather than emit wrong values,
  and the mechanism is pending validation on real hardware (see
  `docs/darwin-compat.md` and the compatibility matrix in
  [the TAR dashboard doc](tar.md)).
- **Retrospective companions (ADR-0020).** `$NetQual_Boot` records one row per
  boot from since-boot OS counters — a coarse "network quality before TAR was
  running this boot" baseline — and the separate opt-in **`netconn`** source
  (`$NetConn_Live`, `netconn_enabled`) backfills OS-retained connectivity
  transitions (connect/disconnect, internet-capability changes, Wi-Fi drops with
  reason codes) reaching days-to-weeks before TAR existed on the box, storing
  enum tokens and reason codes only.

This tier has no dashboard consumer yet — it is the foundation for the deferred
per-destination drill. See the [TAR dashboard](tar.md) for the query surface.

## Metrics

The fleet gauges (`yuzu_fleet_net_*`) are documented in
[Metrics — Fleet network gauges](metrics.md#fleet-network-gauges). They are fed
from the same heartbeat facts as this page, via the shared
`network_perf_rules.hpp` validators, so the gauges and the dashboard cannot
disagree. The agent emits the literal `yuzu.net_*` heartbeat keys, which must
match the server's `kNetTag*` constants — pinned by a `static_assert` in
`test_network_perf_model.cpp`, so drift fails the build.
