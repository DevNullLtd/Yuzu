---
status: proposed
date: 2026-10-03
owner: Nathan Dornbrook
deciders: Nathan Dornbrook (project owner) — grilling session 2026-10-02/03
depends-on: ADR-0067 (co-determination purview + Incident), ADR-1005 Decision 2 (connectors are core — appendix verdict 2026-10-03), ADR-0010 (SecretCodec), ADR-0012 (Postgres store author contract), ADR-2002 §3/§6 (fenced leader), ADR-0031 (engine principals)
related: ADR-0044 (DiscoveryStore), ADR-0016 (daily sync — `last_seen` is server receipt time), ADR-0033 §10 (Execution Plans — the reserved write path), ADR-1006 (service-scope default-deny), `docs/pki-architecture.md` (non-agent client certs deferred), roadmap Phase 9
scope: platform — first connector; network-element model; gNMI adapter via gnmic; Prometheus and MCP surfaces
---

# ADR-0068: Network elements as first-class estate members — a protocol-neutral model with gNMI (via gnmic) as the first adapter

## Context

Yuzu wants to draw service diagrams that include the network, and to hold a complete inventory
of everything attached to it — agent-managed devices and the switches, routers and firewalls
between them. That needs facts only the network elements hold: LLDP adjacency, interface state,
and the MAC (FDB) and ARP tables that say which host sits behind which port. Today nothing in the
tree reaches a device that does not run the agent daemon: the only non-agent row is the
`discovery` plugin's ARP/ping scan output (`discovered_devices`, ADR-0044), every inventory and
authorization store is keyed by `agent_id`, and `CONTEXT.md` "Reachability" declares fabric-level
knowledge out of scope with a seam left to consume it from an upstream source.

gNMI/OpenConfig is the modern, streaming, vendor-neutral management protocol — on data-centre and
service-provider gear (Arista EOS, Cisco IOS-XR/NX-OS/IOS-XE, Junos, Nokia, SONiC). It is thin or
absent on firewalls, load balancers, wireless controllers and older campus/branch switches, which
a bank estate has many of. No endpoint fleet-management platform speaks gNMI natively; the
incumbents (ServiceNow Discovery, Device42, Tanium Discover) use SNMP/SSH, and the network-only
platforms (CloudVision, Crosswork, Apstra) know nothing about endpoints. The join of the
endpoint's view and the network's own view is unoccupied ground, and the collector half of it is
a solved open-source problem (gnmic).

**Market check (web, 2026-10-03):** Datadog NDM remains SNMP/traps/syslog/API only; Zabbix has
no native gNMI (open feature request ZBXNEXT-9074, community workaround is gnmic → Prometheus);
LibreNMS declined gNMI as philosophically SNMP-bound; SuzieQ's transports are SSH/REST/JSON-RPC/
NETCONF, not gNMI (which is exactly why it is the candidate *second* adapter, not the first). The
closest thing to this ADR is **NetBox Discovery's gNMI backend** (NetBox Labs' Orb agent): it
subscribes `ON_CHANGE` with `SAMPLE`/`GET` fallback, auto-detects a vendor gNMI profile with
per-target override, and ingests devices, interfaces, modules, IPs and VRFs into NetBox — the same
vendor-profile shape as D11 — but it collects **no LLDP, FDB or ARP**, has no endpoint view, and
feeds a source-of-truth, not a fleet control plane. Batfish (the candidate for the fabric-level
reachability seam, outside this ADR) is actively released (pybatfish 2026.9).

Two existing decisions bound the design: ADR-1005 Decision 2 (estate-fact *collection* is core
mechanism; *interpretation* is engine territory) and the ADR-0032 split merge-gate, which is red,
so nothing engine-hosted can merge today.

## Decisions

### D1 — A protocol-neutral **network element** model, gNMI first

The unit of the design is the **network element** (`CONTEXT.md`): a piece of network
infrastructure Yuzu inventories and observes without an agent daemon, reached through a
**network collector** speaking a **protocol adapter**. Identity, authorization unit, inventory
home and surfaces are the same whichever adapter reaches the element. gNMI/OpenConfig is the
first adapter; SNMP/SSH is deferred and **not foreclosed** (SuzieQ is the candidate second
adapter, chosen for its cross-vendor normalisation). A gNMI-shaped model would fail the
completeness goal on the first firewall.

### D2 — Connectors are core (ADR-1005 Decision 2, verdict for the class)

Collection, normalisation and storage of network-element facts is core mechanism, exposed through
the versioned REST/MCP surface. The service diagram that *interprets* those facts is out of this
ADR; whichever surface draws it (the grandfathered dashboard viz now, the UCE later) composes the
facts through the public API like any consumer. The maintainer gave this verdict for the class
"collection of estate facts from an external source", recorded in ADR-1005's appendix, settling the
roadmap Phase 9 placement question.

### D3 — gnmic is the network collector; Yuzu is control plane and consumer

Yuzu does **not** write a gNMI client that dials devices. The data plane is
[gnmic](https://github.com/openconfig/gnmic) (openconfig, Apache-2.0), shipped as the compose
service `yuzu-netcollector` near the elements. It holds every device session and is the **only**
thing that ever connects to a network element. Yuzu:

- **owns** the element inventory, adapter/vendor profiles and credentials, and publishes the
  target list gnmic loads (D6);
- **consumes** element state through gnmic's single gNMI-server endpoint as its sole client
  (D7), and answers operator `Get` queries from gnmic's cache through the same endpoint (D10);
- **never carries counters**: interface counters flow gnmic → the customer's Prometheus directly
  (D8).

gnmic's gNMI server has no per-caller authorization; all element authorization lives in Yuzu's
REST/MCP layer, and the gnmic endpoint is reachable from core only, mTLS
(`gnmi-server.client-auth: require-verify`), `read-only: true` (gnmic's default — `Set` returns
`Unimplemented`), with its own REST API server disabled.

**gnmic features this ADR leans on, verified against its documentation on 2026-10-03:** the HTTP
target loader (`loader.type: http`, `interval` default 60s, basic or bearer auth, TLS with CA/cert/
key, a JSON map of target-name → per-target config including `address`, `username`, `password`,
`tls-ca`/`tls-cert`/`tls-key`, `skip-verify`, `subscriptions`, `event-tags`, `timeout`; `on-add`/
`on-delete` actions); the gNMI server (`Get` from cache, `Subscribe`, `Set` relay off by default,
`max-subscriptions`/`max-unary-rpc` caps, TLS client-auth modes); the Prometheus scrape output
(`listen`, `expiration`, `metric-prefix`, `append-subscription-name`, `export-timestamps`,
path-derived metric names, `source`/`subscription_name`/path-key labels, optional Consul service
registration, TLS); clustering via `consul`/`k8s`/`redis` lockers with leader-driven target
distribution and lock-expiry failover (deferred, D9). Not available and designed around: a live
device `Get` and `Capabilities` through gnmic (D10).

### D4 — Read-only now; `Set` reserved, not foreclosed

No surface in this ADR writes to a network element. A gNMI `Set` is an *effect*: it must cross core
as a plan-hash-bound Execution Plan with approval provenance (ADR-0033 §10, #1398 `ExecuteGate`)
before any element is ever written to, and it puts Yuzu inside the customer's network
change-control process. Port quarantine is the obvious future use; the ADR that adds it revisits
the credential-egress security of D6 first. Every tool here is `readOnlyHint: true`,
`destructiveHint: false`.

### D5 — Authorization: a dedicated global securable; purview takes the presence-data concern

- New securable **`NetworkElement`** with operations `Read`, `Write`, `Collect`. Seeded:
  `Read`+`Write` to Administrator and a new **`NetworkEngineer`** role; `Collect` to **no human
  role** (D6).
- Element inventory, interfaces, LLDP edges and cache `Get` are gated on **global**
  `NetworkElement:Read`, per-open audited (`network_element.state.view` for state reads). There is
  **no per-site confinement** of elements in this iteration; the ADR says so rather than faking a
  filter. Generalising management-group membership to non-agent members stays open as the path to
  site-confined network teams; the securable can gain a scoped variant later as `Forensics:Read`
  did, so nothing here forecloses it.
- The FDB/ARP/LLDP tables are **presence data** — the same device-CI tier of personal data as
  serial/UUID/MAC (ADR-0016) — and are routed through the single behavioural-read funnel
  `emit_behavioral_audit` (`rest_audit.hpp`). That funnel is where ADR-0067's **purview** gate
  lands: an in-purview element's tables are readable only under an open **Incident**; until
  ADR-0067 ships they are audited like `device_ci`. An element's purview is **derived** (in
  purview if its tables can reveal in-purview devices' presence), admin-overridable.
- Joins onto agent-managed devices ("this laptop hangs off port 12 of switch X") are filtered on
  the **agent** side by ordinary confinement (ADR-0017 admit-then-filter). A confined operator sees
  their own devices' uplinks, never a switch's whole table.
- Registering elements and credentials is `NetworkElement:Write`, REST with MCP twins — fleet
  operation, not server administration, so #520's REST-only rule does not apply.
- `ServiceScopeClass::denied` on every tool (ADR-1006).

### D6 — Credentials reach gnmic by pull, through Yuzu's first secret-egress route

- A new `network_element_credentials` table, enrolled in `SecretCodec` (ADR-0010) and KEK
  rotation, **write-only** through every REST/MCP surface except one route — the
  `PluginConfigStore` pattern (ADR-3005).
- gnmic's HTTP target loader polls **`GET /api/v1/network-elements/collector-targets`** over TLS,
  authenticating as a **collector principal**: an engine principal (ADR-0031) holding exactly
  `NetworkElement:Collect`. That route is the **only** code path that decrypts element
  credentials; it audits every fetch with principal id and target count; a caller that is not a
  collector principal is **denied**, not merely logged. gnmic holds credentials in memory only.
- Device-side mTLS client certificates are **customer-supplied** and mounted into gnmic. Yuzu's CA
  does not issue them: the non-agent client-cert namespace and EKU policy are deliberately
  deferred in `docs/pki-architecture.md`, and this ADR does not reopen that.
- Accepted residual risk, stated plainly: an attacker holding the collector principal's token and
  reaching core obtains every element credential in one call. Mitigations: single-purpose
  principal (the `validate_assignment` gate already forbids admin/wildcard), the fetch audit, and
  an alert on fetches from an unexpected source. Revisited before any write path (D4).
- A "reference mode" (Yuzu stores only a secret-manager reference; the customer provisions gnmic
  from Vault) is named as a later option and not built.

### D7 — Identity and inventory: core-minted id, a new Postgres store, joins computed at read time

- A network element's identity is a **core-minted opaque id** (`ne-<uuid>`) assigned at
  registration; it is gnmic's target name (loader JSON key) and an `event-tags` label. Management address,
  chassis serial, LLDP chassis-id and hostname are *attributes* and may change; the id does not —
  which also keeps `SecretCodec`'s row-PK-bound AAD stable across a re-address.
- **`NetworkElementStore`**, born on Postgres (ADR-0012): the element row (id, display name,
  vendor/model/OS as learned, management address, adapter, vendor profile + override, purview
  override, enabled, `last_seen`); **interfaces**; **LLDP neighbours as edges**; and the **FDB/ARP
  tables as observations** with `first_seen`/`last_seen`. Edges and observations are **separate
  tables**, so the service diagram can query adjacency without touching presence data (D5).
- `discovered_devices` (ADR-0044) stays separate and scan-shaped; registering an element for a
  discovered IP **links** the discovered row to the element id rather than converting it.
- The join to agent-managed devices is **by MAC and IP, computed at read time** against
  `device_ci`'s MACs and the `FleetTopologyStore` IP→agent map — never stored. A stored join
  duplicates fleet truth and is wrong between a port move and the next sync.
- Every timestamp is **server receipt time**, never the element's clock (ADR-0016's `last_seen`
  rule).

### D8 — Prometheus: per-element series live only on gnmic; the server exposes aggregates only

- Per-element, per-interface series are served by gnmic's Prometheus output and scraped by the
  customer's Prometheus. Yuzu ships the scrape job (`deploy/prometheus/*.yml`) and a
  `yuzu-network-elements` alert group (`docs/prometheus/yuzu-alerts.yml`) whose thresholds ship in
  their **own** change, tuned against real data (the OTA alert-group precedent).
- Labels: gnmic's `source` label is the **target name**, which the HTTP loader sets from the
  JSON key, so the key is the element id and `address` is a separate field; to make the labels
  independent of that detail, core also emits `event-tags` `element_id` and `element_name` per
  target. Hostnames and management addresses are never labels.
- gnmic-side metric names follow gnmic's path-derived names, **not** `yuzu_*` — they are
  OpenConfig facts, and community dashboards already understand them. A sentence in
  `docs/observability-conventions.md` records that this is deliberate for connector-sourced
  series.
- `yuzu-server`'s `/metrics` gains **aggregate families only**, table-driven, absent-not-zero:
  `yuzu_network_elements_by_{vendor,adapter,state}`,
  `yuzu_network_element_collector_last_fetch_seconds`,
  `yuzu_network_element_collector_stream_up` (0/1, pre-seeded), and the collector-principal
  fetch counter. **No `element_id` label ever appears on the server's `/metrics`.**
- No remote_write, Pushgateway or OTLP in this ADR.

### D9 — Ingest: core subscribes to gnmic, on the fenced leader

- Core opens **one gNMI `Subscribe`** to gnmic's gNMI server for the state paths (`ON_CHANGE`
  where the vendor supports it, else slow `SAMPLE`) across all targets. The subscriber is a
  background job classified **`FencedLeaderOnly`** via `background_jobs.hpp` (ADR-2002 §3/§6) —
  never a second "which loops are leader-only" list. `is_leader()` gates only the *attempt*; each
  observation-batch write carries the `epoch_fence_sql()` predicate, so a paused ex-leader cannot
  write stale state after a new leader takes over (the slice-3.3 outbox shape).
- Stream loss is **observable, never silent**: `..._stream_up` drops to 0 with an alert, and
  `last_seen` stops advancing rather than being fabricated.
- gnmic clustering (Consul-locked target sharding) is out of scope: one collector per deployment
  in this iteration.
- Cache `Get` (D10) is a per-request unary call to gnmic's gNMI server from whichever replica
  serves the request — not a leader concern. gnmic caps concurrent unary RPCs (`max-unary-rpc`,
  default 64) and subscriptions (`max-subscriptions`, default 64); core's client bounds its own
  concurrency below those.
- gnmic push outputs (Kafka/NATS into an inbound ingest route) were rejected: a broker is a new
  dependency, and an inbound route is a new surface to secure.

### D10 — MCP/REST surface: five read-only tools; `Get` is a **cache read** allowlisted by OpenConfig subtree, state only

**Verified 2026-10-03 against gnmic's docs:** gnmic's gNMI server serves `Get` **from its local
cache of subscribed notifications** (original timestamps preserved), relays `Set` only when
`read-only: false` (the default is read-only, which D4 keeps), and **does not implement
`Capabilities`**. Its REST API manages targets and subscriptions only; there is no on-demand
device RPC. So under D3 there is no *live* `Get` and no `Capabilities` at all, and the design is
the better for it:

- **`Get` reads gnmic's cache, never the device.** `get_network_element_state` returns the
  **last-known** state for an allowlisted subtree together with gnmic's cached notification
  timestamp, surfaced as `element_timestamp` and labelled as the **element's own clock** (D7's
  receipt-time rule governs stored rows, not this pass-through), and its description and output
  schema say so (A5 decision-grade). An agentic worker can never generate
  load on a switch, and the cache holds only what core subscribed (D9) — state paths — so a
  config-tree disclosure is structurally impossible, not merely filtered.
- **The allowlist is the subscription list.** One table, `type: STATE`, initial entries
  `/interfaces`, `/lldp`, `/system/state`, `/components`, `/network-instances/*/fdb`,
  `/network-instances/*/protocols/*/neighbors`, drives **both** the D9 subscriptions and the
  `Get` shape check (one copy for REST and MCP — the `dispatch_target_shape.hpp` rule). A path
  outside it is refused with an A4 error naming the allowed subtrees. **Widening the list is a
  security decision**, never inferred from one feature.
- **No `Capabilities` tool.** What a worker wanted from it — "which models does this vendor
  serve" — comes from the vendor profile (D11) and `/system/state` software version; a
  profile-less element reports `constrained: no_profile`.
- Tools (each with a REST twin, A1–A5, `ServiceScopeClass::denied`):
  `list_network_elements`, `get_network_element`, `list_network_element_neighbors`
  (`NetworkElement:Read`); `list_network_element_attachments` (the FDB/ARP join, agent-side
  confined, through `emit_behavioral_audit`); `get_network_element_state` (cache `Get`,
  `openWorldHint: false` — it reaches gnmic, not the open world — audited
  `network_element.state.view`).
- Registration/credential tools are in `kWriteTools` under `NetworkElement:Write`,
  `destructiveHint: false`, `idempotentHint: true`; no tool ever returns a credential.
- `retry_after_ms` on a `Get` that finds gnmic unreachable is derived from the D9 stream-health
  state (down → the reconnect backoff), not a constant (CI-gated by
  `scripts/ci/check-mcp-retry-hints.py`).
- A genuinely live device read, if ever wanted, is a new decision: it would need a second client
  path to the device, which D3 forbids today.

### D11 — Build, deploy, vendor normalisation; core only

- `gnmi.proto` and `gnmi_ext.proto` (Apache-2.0) are vendored under
  `proto/third_party/openconfig/` with their LICENSE and compiled into the existing `yuzu_proto`
  static library; `gen_proto.py` learns to flatten gnmi's import path. Same library as
  `agent.proto`, so the Windows #375/#572 linkage constraints are unchanged. They are the first
  third-party protos in the tree: `docs/build-guide.md` gains a "vendored third-party protos"
  section with the pin and update procedure.
- `yuzu-netcollector` is a compose service on a pinned `ghcr.io/openconfig/gnmic` image, with a
  healthcheck (the compose healthcheck invariant), added to `scripts/check-compose-versions.sh`'s
  `FILES` array where tracked, API server disabled, gNMI-server port reachable from core only.
- **Vendor profiles are content, not code**: build-time-embedded YAML under
  `content/network-profiles/` (Arista EOS, Cisco IOS-XR/NX-OS, Junos, Nokia SR Linux, SONiC to
  start) mapping the canonical facts to the paths/encodings each vendor family actually serves,
  with a per-element operator override. An element with no profile is registered but reports
  `constrained: no_profile` — never a fabricated empty table.
- **Nothing is added to the agent daemon or the plugin ABI.**
- The gnmic pin is a supply-chain dependency Yuzu does not build: the image digest is pinned, and
  a gnmic release bump is a reviewed change (its loader/gNMI-server contract is what D6 and D10
  stand on).
- gnmic's Prometheus output expires a series `expiration` (default 60s) after its last update, so
  an `ON_CHANGE` counter that stops changing disappears rather than flatlines — the scrape job
  and alert rules in D8 must assume absent-not-stale, which matches Yuzu's own absent-not-zero rule.

## Considered and rejected

- **Yuzu-written gNMI client (in core, or a "collector agent" — an agent daemon hosting the
  dialer).** The collector-agent shape is the incumbents' pattern (MID server, Datadog NDM, Zabbix
  proxy) and was the recommendation until gnmic was weighed: it needs gRPC in agent core
  (no plugin links gRPC; Windows linkage is fragile), the agent secret-delivery threat model
  ADR-3005 demands before `yuzu_ctx_get_secret` is wired, and the agent's first `/metrics`
  endpoint. gnmic gives the same data plane for a compose pin.
- **A new standalone Yuzu southbound binary** (`yuzu-netcollector` as our code): a new seam
  ADR-0031's inventory lacks, a new artifact, and a shape that resembles an engine while the merge
  gate is red.
- **Engine-hosted** (UCE): fails the Decision 2 test (collection is mechanism) and cannot merge.
- **gNMI-only model**: fails completeness on the first firewall.
- **Elements as management-group members** now: touches the catastrophic confinement chokepoint
  (`authorize_list_read`, `dispatch_confined_arms`) for a need the first iteration does not have.
- **A separate site/trust-zone confinement lattice for elements**: a second lattice is the drift
  the access-control rows exist to prevent.
- **Per-element series on `yuzu-server`'s `/metrics`**: breaks the aggregated, absent-not-zero
  label discipline and makes the server a telemetry bottleneck.
- **Yuzu writing gnmic's config file** (secrets on disk, co-located with the server) and
  **Yuzu holding no credentials at all** (two consoles; no rotation) — see D6.
- **Storing the element↔device join**: duplicates fleet truth and goes stale on a port move.
- **Reusing `discovered_devices`** as the element row: IP-keyed, which breaks on multi-homed or
  re-addressed management planes.

## Consequences

- `CONTEXT.md` gains **Network element**, **Network collector**, **Collector principal**,
  **Connector** (and, via ADR-0067, **Purview** and **Incident**). "Network device" keeps its
  existing meaning (an agent endpoint in the `/network` lens); "telemetry" stays ADR-0003's.
- The roadmap's Phase 9 placement question is settled (connectors are core); the 9.x sketches
  remain sketches.
- `docs/enterprise-readiness-soc2-first-customer.md` data inventory gains rows for
  `network_element_store` (edges: asset topology; observations: presence data, device-CI tier) and
  `network_element_credentials` (secret, `SecretCodec`), plus the collector-targets route in the
  "what can read a secret" and "individual behavioural read" inventories.
- Governance routing for the implementation PRs: `security-guardian` + `architect` (new securable,
  engine-principal grant, secret egress, `Get` allowlist, `emit_behavioral_audit` consumer),
  `cpp-safety` (long-lived gRPC stream, fenced-leader job), `sre` (new metric families, alert
  group), `build-ci` (vendored protos, `gen_proto.py`), `release-deploy` (compose service, version
  gate), `docs-writer`. A new routed-concern row for the `Get` allowlist and the collector-targets
  route lands with the first implementation slice, not with this ADR.
- The fabric-level reachability seam in `CONTEXT.md` "Reachability" is **not** filled by this ADR:
  LLDP/FDB give physical adjacency, not what ACLs/VLANs *permit*. Config-analysis (Batfish) is the
  candidate filler for that seam and is a separate decision.
- Open follow-ups: gnmic clustering / multi-collector sharding; SNMP/SSH adapter (SuzieQ); the
  `Set` write path with its Execution Plan and credential-egress hardening; site-confined
  elements via generalised group membership; reference-mode credentials; a Helm chart.

## Binding status

Binds prospectively on acceptance (merge to `dev`, `docs/agents/domain.md` convention). D4 (no
write path), D5 (global securable, no faked confinement), D6 (single decrypting route, collector
principal only), D8 (no per-element series on the server), D10 (state-only subtree allowlist, one
copy) are the clauses a future diff is most likely to erode silently and are the ones the
implementation's routed-concern row must restate.
