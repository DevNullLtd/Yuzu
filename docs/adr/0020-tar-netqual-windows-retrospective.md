# ADR-0020: Windows netqual via TCP ESTATS + retrospective network-quality layers

**Status:** Accepted
**Date:** 2026-07-03
**Authors:** Alex Young
**Relates to:** ADR-0015 (ARP/DNS capture sources), `docs/tar-implementer.md`,
`docs/user-manual/network.md` (netqual tier), ADR-0003 (telemetry capture model)

## Context

The `netqual` TAR source (per-connection TCP quality: smoothed RTT, jitter,
current loss, lifetime retrans/segs context, privacy-bucketed destination) has
shipped Linux-only (netlink INET_DIAG), with Windows registered `kPlanned`
("estats"). The goal of this slice is Windows support with an explicit extra
requirement: **assess network quality from before TAR was running** — ideally
before the agent existed on the box — wherever the OS retains the evidence.

## Decision

Three layers, all opt-in under the existing usage-class posture:

1. **Live per-connection collector via TCP ESTATS** (`Get/SetPerTcp[6]ConnectionEStats`,
   `TcpConnectionEstatsPath` + `TcpConnectionEstatsData`), filling the existing
   `collect_tcp_quality()` stub in `tar_network_collector.cpp`. Windows flips to
   `kSupportedConstrained`.
2. **Per-boot retrospective baseline** (`$NetQual_Boot`, a second `netqual`
   granularity): one row per boot at plugin init from cumulative-since-boot OS
   counters (`GetTcpStatisticsEx2` IPv4+IPv6, `GetIfTable2` non-loopback
   totals). Covers the window before TAR started this boot; zero provisioning,
   no elevation.
3. **`netconn`, a new small source** (`$NetConn_Live`): `EvtQuery` backfill +
   incremental reads of the OS-retained NetworkProfile / NCSI / WLAN-AutoConfig
   operational channels — connectivity transitions reaching days-to-weeks
   before TAR (or the agent) existed. High-water-mark state; the first read
   after opt-in recovers the retained history, so enabling late loses nothing.

### ESTATS mechanics (layer 1)

- Stats are **disabled per connection until enabled** (`EnableCollection=TRUE`
  via Set, admin-only) and the ROD blocks are documented-undefined until the Rw
  echo confirms collection is on — the collector verifies the echo on every
  read (known API flakiness otherwise).
- **Two-tick protocol**: first sight of an ESTABLISHED connection enables
  Path+Data and takes a baseline read (emits nothing); later ticks emit
  since-baseline deltas. Bounded: ≤128 enables/tick, ≤2048 tracked connections,
  pruned on close (`ERROR_NOT_FOUND`).
- **Never disable**: since Windows 10 1709 a disable can reset counters under
  other ESTATS consumers (and a foreign reset appears to us as a negative
  delta, clamped to 0 for one tick). Stats die with the TCB; no cleanup needed.
- **Elevation**: `SetPerTcpConnectionEStats` requires an elevated token. The
  first `ERROR_ACCESS_DENIED` latches the collector off for the process
  lifetime (one `spdlog::warn`; token elevation cannot change mid-process) and
  `tar.status` reports `netqual_capture_method|none` — "opted in but cannot
  collect" is always distinguishable from "off".

### Field mapping (Linux TCP_INFO → Windows ESTATS)

| NetQualRow | Linux | Windows |
|---|---|---|
| `rtt_us` / `rtt_var_us` | `tcpi_rtt`/`tcpi_rttvar` (µs) | `Path.SmoothedRtt`/`Path.RttVar` × 1000 (**ms-resolution**; sub-ms LAN RTT reads 0) |
| `lost` | `tcpi_lost` (instantaneous gauge) | **Δ`Path.PktsRetrans` this tick**, wrap-clamped ≥ 0 (closest moves-with-current-conditions analogue) |
| `retrans` / `segs_out` | lifetime cumulative | cumulative **since stats-enable** (first observation), not connection start |
| `ca_state` | `tcpi_ca_state` | **synthesized** from Path deltas, severity precedence: RTO live/completed → 4 Loss; any retransmission → 3 Recovery; ECN signals → 2 CWR; dup-ACKs → 1 Disorder; else 0 Open |

The derivation is pure (`nq_win_build_sample` / `nq_win_ca_state` in
`tar_netqual.hpp`) and unit-tested cross-platform; the Windows semantics are
documented in the header's SIGNAL DISCIPLINE block and in the registry
constraint notes.

### netconn privacy (layer 3)

The parser (`tar_netconn.hpp`) is an **allow-list**: the only event fields ever
extracted are `Category`, `Capability`, `CapabilityChangeReason` and
`ReasonCode` — numeric enums mapped to closed tokens. SSID, BSSID, profile
names, interface GUIDs/descriptions and MACs are structurally unreachable, raw
event XML never leaves the reader, and a fixture test pins that no sentinel
free-text survives into a row. This is deliberately stricter than the wifi
plugin (netconn rows are a fleet-queryable warehouse table). WLAN failure
events' RSSI is *not* captured (only failures carry it — a biased sample).

## Alternatives considered

- **`SIO_TCP_INFO`** — µs RTT, no elevation, but own-socket only: an agent
  cannot observe other processes' connections with it. Rejected for netqual;
  it remains the right tool for agent-owned probe sockets (netprobe).
- **Microsoft-Windows-TCPIP real-time ETW** — per-connection retransmit events
  exist (1186/1187/1077, `ut:TcpipDiagnosis` 0x80, level 4) but RTT rides
  per-ACK level-5 events; a session + TDH decode + the same elevation buys no
  additional schema column over ESTATS. Documented as the future
  sub-tick-fidelity option.
- **TCPIP boot AutoLogger** (mirror of `YuzuProcBoot`) for pre-agent-start
  per-connection data — **rejected**: the useful RTT events are a per-ACK
  firehose that wraps a 16–32 MB circular `.etl` in minutes under load,
  destroying the "since boot" promise; its unique coverage (boot → agent-start
  of the boot *after* provisioning) is small for an auto-start service and
  already summarized by layer 2 and timeline-covered by layer 3; and unlike
  process events, network quality has OS-retained counters and logs the other
  layers read for free (no installer changes, works on first install,
  non-elevated). A `ut:TcpipDiagnosis`-only (loss-scaled, low-volume)
  AutoLogger is the documented fallback if per-connection *forensic* depth in
  the pre-agent window is ever demanded.
- **Raising the event-log channel `maxSize`** to deepen future netconn lookback
  — declined (strict read-only posture; the agent does not mutate system
  logging config). Recorded here as a deliberate future decision for
  works-council review if deeper history is wanted.

## Privacy / lawfulness note (retroactive reach)

The retrospective layers read state the OS accumulated **before any monitoring
was disclosed on the device**: netconn's first read backfills up to
`netconn_lookback_seconds` (default 7 days) of connectivity/Wi-Fi transitions
from before TAR — or the agent — existed on the box, and `$NetQual_Boot`
summarizes the whole pre-TAR-this-boot window. On a person-assigned device the
*timing* of network/Wi-Fi connect/disconnect events is a proxy for presence and
working hours — behavioral/personal data under GDPR even with SSID/BSSID
stripped — so collecting a window that predates the monitoring notice is a
distinct lawfulness/transparency (GDPR Art. 13-14) and co-determination question
from forward-looking collection.

Mitigations shipped: (a) all three surfaces are **opt-in** (`default_enabled =
false`); (b) the retroactive reach is operator-configurable —
`netconn_lookback_seconds = 0` disables the pre-enablement read entirely, so a
works-council/DPO can permit `netconn` forward-only where retrospective
collection is not lawful; (c) only closed enum tokens + numeric reason codes are
stored, never SSID/BSSID/profile/GUID/MAC/addresses. **For EU/co-determination
workforces the retroactive reach should be raised with the works-council/DPO
before enablement** (mirroring the procperf co-determination trigger); the
data-classification and works-council register in
`docs/enterprise-readiness-soc2-first-customer.md` carries the per-source rows.

## Consequences

- Non-elevated Windows agents record **zero** netqual live rows (status shows
  `none`); the retrospective layers (boot baseline, netconn) still work
  non-elevated by design.
- `netconn` history depth is bounded by the OS channels' default ~1MB circular
  logs — days-to-weeks, event-rate-dependent; Server SKUs may lack the WLAN
  channel (per-channel skip).
- The boot baseline is host-wide context (one cumulative average over the
  pre-TAR window), deliberately never a current-loss verdict — the same signal
  discipline as the live tier.
- `GetTcpStatisticsEx2` is resolved dynamically (1709+; falls back to the
  32-bit `GetTcpStatisticsEx`) so `tar.dll` gains no hard import that could
  block loading on older Windows 10.
