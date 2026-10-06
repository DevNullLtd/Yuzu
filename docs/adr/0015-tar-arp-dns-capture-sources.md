# ADR-0015: Add ARP and DNS Capture Sources to the TAR Plugin

**Date:** 2026-06-19
**Status:** Accepted
**Component:** TAR (Telemetry, Acquisition, Response) — Capture Source Layer
**Authors:** Alex (Security Architecture)

> Supersedes the proposal that was mis-numbered "ADR-0010" (0010 is
> `secrets-at-rest-envelope-encryption`). This is the accepted record; it amends
> the original proposal per the decisions in "Amendments" below.

> **Amended by ADR-3006 (capability enablement).** The default state in Amendment 1
> ("opt-in, not default-on") is superseded for new installations: capture sources ship on
> and the customer switches them off. Existing installations keep their current state.
> Everything else here is unchanged.

## Context

TAR captures processes, TCP connections, services, user sessions, and device
performance. Forensic analysts investigating lateral movement and C2 have two
systemic gaps:

- **ARP tables** are not captured — no Layer-2 adjacency, no way to confirm an IP
  resolved to the expected MAC, no ARP-spoofing/poisoning signal at acquisition
  time.
- **DNS resolution state** is not captured — connection IPs cannot be attributed
  back to the domain the host resolved without out-of-band SIEM/NDR reconstruction.

Both are standard EDR collection targets. TAR's snapshot-and-diff model (finite,
read-only, low-frequency reads written to the local SQLite warehouse) fits both.

## Decision

Add two new TAR capture sources, `arp` and `dns`, following the **core
capture-source pattern** (identical in shape to network/service/user — types +
`enumerate_*()`/`compute_*_events()` in `tar_collectors.hpp`, one
`tar_<source>_collector.cpp` per source, diffs in `tar_diff.cpp`, row structs +
`insert_*_events` in `tar_db.{hpp,cpp}`, one `CaptureSourceDef` in
`tar_schema_registry.cpp`). See `docs/tar-implementer.md` → "Adding a capture
source".

### Source: `arp`
- Windows: `GetIpNetTable2(AF_UNSPEC)` (IP Helper) — ARP + IPv6 neighbour cache.
- Linux (`/proc/net/arp`) and macOS (`sysctl NET_RT_FLAGS`) are **kPlanned**.
- Snapshot-diff keyed on `(interface, ip_address, mac_address)` → `appeared` /
  `removed`; `entry_type` is a value field, not part of the key (a dynamic/static
  flap is not churn). Hard cap **2048** entries/cycle (warn + truncate).
- Tables: `$ARP_Live` (5000-row ring) + `$ARP_Hourly` (24 h). Columns:
  `ts, snapshot_id, action, interface, ip_address, mac_address, entry_type`.

### Source: `dns`
- Windows: `DnsGetCacheDataTable` (resolved dynamically — undocumented `dnsapi.dll`
  export) + `DnsQuery_W(..., DNS_QUERY_NO_WIRE_QUERY, ...)` to read each entry's
  data + TTL **from cache only** (the flag guarantees no wire query — no network
  amplification, no privacy leak from the collector).
- Linux (systemd-resolved / `/etc/hosts`) and macOS (`dscacheutil`) are **kPlanned**.
- **Device resolver-cache STATE — host-wide, no PID.** There is no per-process
  attribution. Snapshot-diff keyed on `(name, record_type, data)` → `appeared` /
  `removed`; `ttl_remaining_s` is a value field (decrements every tick, never
  keyed). Hard cap **4096** entries/cycle.
- Tables: `$DNS_Live` + `$DNS_Hourly`. Columns: `ts, snapshot_id, action, name,
  record_type, data, ttl_remaining_s, source` (`source` ∈ cache/hosts_file/unknown).

### Integration
`query`/`sql` (`type: "arp"`/`"dns"`, `$ARP_*`/`$DNS_*`), `status`,
`compatibility`, `configure`, `snapshot` all extend (the registry-driven actions
auto-cover; `do_query`/`do_export` get explicit branches). Both sources are
queryable empty until enabled.

### Operator surfaces
- **GUI — Capture sources frame** on `/tar`: per-source toggle table with a
  category filter and a **staged-then-push guardrail** (a toggle stages a change;
  nothing dispatches until **Push** — guards against accidental enablement).
- **GUI — device DNS-cache + ARP-table panels** embedded in the process-tree pane
  (device-level, **not** per-process).
- **MCP / REST** — `crossplatform.tar.configure` carries `arp_enabled` /
  `dns_enabled`; convenience canned queries `crossplatform.tar.recent_arp` /
  `recent_dns`. The same `tar configure` dispatch backs the GUI Push.

## Amendments (vs. the original proposal)

1. **Opt-in, not default-on.** Both `default_enabled = false`, matching every
   recent usage-class source (`module`/`procperf`/`netqual`) under the
   works-council posture. DNS cache is usage-class PII (reveals visited domains);
   enabling it is audited.
2. **Windows-first.** This slice ships Windows collectors only; Linux/macOS rows
   are `kPlanned` (the schema-invariant test requires a row per OS) and land as
   follow-ups.
3. **No Prometheus metrics.** The proposal's "emit `yuzu_agent_*` metrics" is
   dropped — TAR has no agent `/metrics` endpoint; the observable surface is the
   `status` action's per-source row counts (auto-covered). Truncation is a
   `spdlog::warn`, not an audit-event (TAR has no event bus).
4. **DNS is a device panel, not a process join.** Per-process DNS attribution
   (Microsoft-Windows-DNS-Client ETW provider, pid-tagged query events) was
   considered and **deferred**; `$DNS_Live` carries no pid.
5. **Audit verbs.** The GUI device panels audit `tar.dns.read` / `tar.arp.read`
   (DNS is PII → kept separately countable); the Capture-sources frame audits
   `tar.sources.read` (load) and `tar.sources.configure` (per-source push).

## Consequences

**Positive:** L2 visibility (ARP spoofing/MAC↔IP confirmation) and domain
attribution directly from TAR; closes a gap vs. commercial EDR; aligns to MITRE
ATT&CK DS0022/DS0029; no new operator concepts (existing actions extend).

**Negative / deferred:** Linux/macOS collectors deferred; per-process DNS deferred
(ETW); macOS DNS via `dscacheutil` will be a subprocess shell-out (flag for
security review when it lands); the 2048/4096 caps are estimates to validate on
VLAN-heavy / large-resolver-cache hosts. `DnsGetCacheDataTable` is undocumented —
resolved via `GetProcAddress` with graceful degradation if absent.

## References
- `docs/adr/0003-telemetry-capture-model.md` — TAR capture model
- `docs/user-manual/tar.md`, `docs/tar-implementer.md`, `docs/tar-dashboard.md`
- `content/definitions/tar.yaml`, `content/definitions/tar_warehouse.yaml`
- MITRE ATT&CK Data Sources: DS0022 (File/ARP), DS0029 (Network Traffic/DNS)
- Microsoft: `GetIpNetTable2`, `DnsGetCacheDataTable`, `DnsQuery_W`
