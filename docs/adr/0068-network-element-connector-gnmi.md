---
status: accepted
date: 2026-10-03
owner: Nathan Dornbrook
deciders: Nathan Dornbrook (project owner) — grilling session 2026-10-02/03; governance run PR #5367 (2026-10-04, two rounds, 76 + 33 findings folded)
amends: 0031-presentation-core-engine-decomposition.md Decision 8 (seam inventory: B8 core → network collector)
depends-on: ADR-0067 (co-determination purview + Incident — the purview clauses of D5/D7/D10 bind only once it is accepted), ADR-1005 Decision 2 (connectors are core — appendix verdict 2026-10-03), ADR-0010 (SecretCodec), ADR-0012 (Postgres store author contract), ADR-2002 §3/§6/§10 (fenced leader), `0031-engine-principal-store.md` (engine principals), `0031-presentation-core-engine-decomposition.md` Decision 8 (seam inventory — amended by this ADR, see Consequences)
related: ADR-0044 (DiscoveryStore), `0016-agent-daily-sync-framework.md` (`last_seen` is server receipt time), ADR-0033 §4/§10 (approval primitive; Execution Plans — the reserved write path), ADR-1006 (service-scope default-deny), ADR-0017 (confinement), ADR-3005 (`PluginConfigStore` write-only pattern), `docs/pki-architecture.md` (non-agent client certs deferred), `docs/clock-guarded-retention.md`, roadmap Phase 9
scope: platform — first connector; network-element model; gNMI adapter via gnmic; Prometheus and MCP surfaces
tracking: PR #5367 (acceptance = merge to `dev`, EXCEPT the purview clauses — see Binding status)
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

gNMI/OpenConfig is the modern, streaming, vendor-neutral management protocol on data-centre and
service-provider gear (Arista EOS, Cisco IOS-XR/NX-OS/IOS-XE, Junos, Nokia, SONiC). It is thin or
absent on firewalls, load balancers, wireless controllers and older campus/branch switches, which
a bank estate has many of. No endpoint fleet-management platform speaks gNMI natively; the
incumbents (ServiceNow Discovery, Device42, Tanium Discover) use SNMP/SSH, and the network-only
platforms (CloudVision, Crosswork, Apstra) know nothing about endpoints. The join of the
endpoint's view and the network's own view is unoccupied ground, and the collector half of it is
a solved open-source problem (gnmic).

**Market check (web, 2026-10-03; sources at the end of this section):** Datadog NDM remains
SNMP/traps/syslog/API only; Zabbix has no native gNMI (open feature request ZBXNEXT-9074; the
community workaround is gnmic → Prometheus); LibreNMS declined gNMI as philosophically SNMP-bound;
SuzieQ's transports are SSH/REST/JSON-RPC/NETCONF, not gNMI (which is exactly why it is the
candidate *second* adapter, not the first). The closest thing to this ADR is **NetBox Discovery's
gNMI backend** (NetBox Labs' Orb agent): it subscribes `ON_CHANGE` with `SAMPLE`/`GET` fallback,
auto-detects a vendor gNMI profile with per-target override, and ingests devices, interfaces,
modules, IPs and VRFs into NetBox — the same vendor-profile shape as D11 — but it collects **no
LLDP, FDB or ARP**, has no endpoint view, and feeds a source-of-truth, not a fleet control plane.
Batfish (the candidate for the fabric-level reachability seam, outside this ADR) is actively
released (pybatfish 2026.9).

Sources: gnmic docs — HTTP discovery (`gnmic.openconfig.net/user_guide/targets/target_discovery/http_discovery/`),
target options (`…/user_guide/targets/targets/`), gNMI server (`…/user_guide/gnmi_server/`), REST
API (`…/user_guide/api/api_intro/`, `…/api/targets/`), Prometheus output
(`…/user_guide/outputs/prometheus_output/`), HA (`…/user_guide/HA/`); loader source
`github.com/openconfig/gnmic/pkg/loaders/http_loader/http_loader.go`; NetBox Discovery gNMI
backend (`netboxlabs.com/docs/discovery/agent/backends/gnmi_discovery/`); Datadog NDM integrations
(`docs.datadoghq.com/network_monitoring/devices/integrations/`); Zabbix ZBXNEXT-9074; LibreNMS
community thread 2329; SuzieQ docs (`suzieq.readthedocs.io`); pybatfish on PyPI.

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
"collection of **estate** facts from an external source", recorded in ADR-1005's appendix,
settling the roadmap Phase 9 placement question. An *estate fact* is a fact about the customer's
own estate; external **domain** data (vulnerability feeds, threat intelligence, CVE/threat
catalogues) is not one and stays engine territory under ADR-1005's existing tiebreaker — the verdict
does not move it.

### D3 — gnmic is the network collector; Yuzu is control plane and consumer

Yuzu does **not** write a gNMI client that dials devices. The data plane is
[gnmic](https://github.com/openconfig/gnmic) (openconfig, Apache-2.0), shipped as the **opt-in**
compose service `yuzu-netcollector` (D11) near the elements. It holds every device session and is
the **only** thing that ever connects to a network element. Yuzu:

- **owns** the element inventory, adapter/vendor profiles and credentials, and publishes the
  target list gnmic loads (D6);
- **consumes** element state through gnmic's single gNMI-server endpoint as its sole client
  (D9), and answers operator `Get` queries from gnmic's cache through the same endpoint (D10);
- **never carries counters**: interface counters flow gnmic → the customer's Prometheus directly
  (D8).

gnmic's gNMI server has no per-caller authorization; all element authorization lives in Yuzu's
REST/MCP layer, and the gnmic endpoint is reachable from core only, mTLS
(`gnmi-server.client-auth: require-verify`), `read-only: true` (gnmic's default — `Set` returns
`Unimplemented`), with its own REST API server disabled.

**This is a new seam.** Core → network collector is a southbound seam that
`0031-presentation-core-engine-decomposition.md` Decision 8's normative inventory (B1–B7) does not
cover; this ADR amends that inventory with **B8 core → network collector** (contract: the pinned
gnmic image digest, the D10 fact table that drives subscriptions and `Get`, and `read-only: true`).
The gnmic → core target-loader pull is **B4-shaped** (a public, versioned API consumed by an
engine-class principal) and needs no new row. The flows, for a firewall request:

| # | Source zone → destination zone | Port / protocol | Auth | Initiated by | Required |
|---|---|---|---|---|---|
| F1 | collector (management) → core (server) | core **HTTPS** listener (`--https-port`, default **8443**) `GET /api/v1/network-elements/collector-targets` | collector-principal bearer over TLS (core's server cert); the route **refuses the plaintext `--web-port` listener** and fails closed | gnmic, every loader interval (default 60s) | mandatory |
| F2 | core (server) → collector (management) | gnmic gNMI-server port (`gnmi-server.address`, default 57400) | mTLS, core client cert, `require-verify` | **every** core replica (`Get`); the leader (`Subscribe`) — rule scope is the set of replica addresses | mandatory |
| F3 | collector (management) → element (management) | vendor-variable gNMI port (57400 / 6030 / 9339 …) | per-element credentials (D6) + customer-supplied client cert | gnmic | mandatory |
| F4 | monitoring → collector (management) | gnmic Prometheus output (`:9804/metrics`) | TLS optional (gnmic output config) | the customer's Prometheus | optional (metrics only) |

All four are stateful TCP flows initiated as shown; no reverse rule is needed. Core **never
initiates a connection to an element**; F3 is the only flow that leaves the collector toward
devices, and F1 is the only inbound hole into the server zone. A customer may place the collector
in the server zone instead and route F3 outward. Full firewall guidance ships in
`docs/user-manual/server-admin.md` with slice 1.

**gnmic features this ADR leans on, verified against its documentation and loader source on
2026-10-03/04:** the HTTP target loader (`loader.type: http`, `interval` default 60s, basic or
bearer auth, TLS with CA/cert/key, a JSON map of target-name → per-target config including
`address`, `username`, `password`, `tls-ca`/`tls-cert`/`tls-key`, `tls-reload`, `skip-verify`,
`subscriptions`, `event-tags`, `timeout`; `on-add`/`on-delete` actions; **on a fetch error it logs
and keeps the last list unchanged — no delete is emitted; on a SUCCESSFUL response that omits a
known target it emits a delete and runs `on-delete`**; no retry/backoff beyond the fixed
interval); the gNMI server (`Get` from cache, `Subscribe`, `Set` relay off by default,
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
the credential-egress security of D6 first, and is itself subject to the ADR-0032 interlock if it
touches the Execution-Plan machinery. Every **read** tool here is `readOnlyHint: true`,
`destructiveHint: false`; the write tools (registration, update, credential, delete) carry the
annotations D10 states — they write Yuzu's own store, never an element.

### D5 — Authorization: a dedicated global securable; the whole table is deliberate; purview takes the presence-data concern

- New securable **`NetworkElement`** with operations `Read`, `Write`, `Delete`, `Collect`.
  Seeded: `Read`/`Write`/`Delete` to Administrator (it **joins the Administrator CRUD loop** in
  `rbac_store.cpp` — which also seeds `Execute`/`Approve` on every type it iterates; both are
  unconsumed here, the Decommission precedent) and to a new **`NetworkEngineer`** role; `Collect`
  is **excluded from `crud_ops` and from the Administrator loop** (the `Push`/`Attest`/`Rotate`
  precedent) and seeded only to a new **non-assignable `NetworkCollector` role** (engine principals
  are granted roles, `validate_assignment`), which no human role list offers (D6). Every closed list
  the securable and operation must join is a slice-1
  consequence, enumerated under Consequences.
- **The whole table is deliberate (owner decision, 2026-10-04).** Global `NetworkElement:Read`
  grants an element's complete FDB, ARP and LLDP tables. A complete inventory of everything
  attached to the network — agent-managed or not — is the point of the connector, so the table is
  not narrowed by confinement. The controls on it are **per-open audit** and **purview**
  (ADR-0067), not confinement. There is **no per-site confinement** of elements in this
  iteration; generalising management-group membership to non-agent members stays open as the path
  to site-confined network teams, and the securable can later gain a scoped variant as
  `Forensics:Read` did, so nothing here forecloses it.
- **RBAC-off audience, stated plainly.** RBAC ships off. In that default, `require_permission`'s
  legacy branch admits every `Read` to any authenticated session, so "seeded to Administrator +
  NetworkEngineer" bites only once RBAC is enabled. The raw-table reads are **not** floored to
  admin under RBAC-off: they are the same **control posture** as `device_ci` today (the audit
  funnel, the RBAC-off legacy rule) with a **higher data class** (see the next bullet), and purview
  is the control that matters for the EU case.
  Flooring only this surface would make a switch's table harder to read than the device's own CI
  panel. (If a floor is ever wanted it is applied to both, via `authz_topology_floor.hpp`, never a
  second list.)
- **Audit verbs, separately countable** (works-council rule): `network_element.view` (inventory
  list/get — not behavioural), `network_element.state.view` (interfaces, LLDP, system — asset
  topology, not behavioural), **`network_element.presence.view`** (FDB/ARP/neighbour subtrees of
  `Get` — presence data, through the behavioural-read gate), **`network_element.attachment.view`**
  (the attachments join — presence data, through the behavioural-read gate),
  `network_element.register`,
  `network_element.update`, `network_element.delete` (its cascade purges that element's edges and
  observations), `network_element.credential.set` (a rotation is a second `set`),
  `network_element.observations.erase` (the DSAR/decommission erasure, with a row count),
  `network_element.purview.override` (this is ADR-0067's `purview.override` — one verb, one name),
  `network_element.profile.override`, and `network_element.collector.fetch` (D6, with
  `result=success|denied|degraded` and, on `degraded`, the offending element id — an id is not a
  secret). The two presence verbs are the ones ADR-0067's gate set is derived from.
- **Presence data classification** (compliance finding co-1, folded): FDB/ARP observations are
  **not** device-CI tier. `device_ci` is current-state, one row per agent, replaced on sync; the
  observations table is a **presence-over-time log of every device on every switch — agent,
  non-agent, visitor** — behavioural-adjacent and works-council-relevant by the SOC 2 doc's own
  reasoning for `netconn`, and personal data under GDPR where MAC → person is resolvable. LLDP
  edges are asset topology, not personal. The two presence verbs above route through ADR-0067's
  pre-read behavioural gate; until ADR-0067 ships they are audited like `device_ci`. An element's
  purview is **derived at read time** (in purview if its tables can reveal in-purview devices'
  presence, evaluated against current group membership, never cached) and admin-overridable.
  **In an EU co-determination deployment the works-council agreement precedes the first
  `network_element.register` and the first `NetworkCollector` grant** — those two audit rows are
  the evidence of that decision — **and the collector is not enabled before ADR-0067's
  deployment-wide default flip ships** (ADR-0067 D5; restated in `upgrading.md`).
- Joins onto agent-managed devices ("this laptop hangs off port 12 of switch X") on a device page
  are filtered on the **agent** side by ordinary confinement (ADR-0017 admit-then-filter). That is
  a different question from the table read, not a narrowing of it.
- Registering elements and credentials is `NetworkElement:Write` — fleet operation, not server
  administration, so #520's REST-only rule does not apply; REST with MCP twins (D10).
- `ServiceScopeClass::denied` on every tool (ADR-1006).

### D6 — Credentials reach gnmic by pull, through Yuzu's first secret-egress route

- A new `network_element_credentials` table, enrolled in `SecretCodec` (ADR-0010) and KEK
  rotation, **write-only** through every REST/MCP surface except one route. ADR-3005's
  `PluginConfigStore` is the write-only precedent; it has **no** read-back, so this route is a
  first, not an instance of that pattern.
- gnmic's HTTP target loader polls **`GET /api/v1/network-elements/collector-targets`** over TLS,
  authenticating as a **collector principal**: an engine principal
  (`0031-engine-principal-store.md`)
  holding exactly `NetworkElement:Collect`. **Admission is a dedicated predicate, never
  `require_permission`'s generic path** (the `rbac_admin_predicate.hpp` "instead of perm_fn"
  shape): the route admits a session iff `principal_kind == "engine"`, `is_elevated` is false,
  `token_scope_service` and `mcp_tier` are empty, AND a **direct** `RbacStore::check_permission`
  (503 on store degrade) resolves `NetworkElement:Collect` — so an elevated human session (which
  `require_permission` short-circuits) and an RBAC-off Administrator (which the legacy branch
  admits for non-`Read` operations) are **denied explicitly**, not merely logged. The route also
  refuses a request that arrived on the plaintext listener. Because engine
  principals resolve RBAC-only, **the connector requires RBAC enabled**; with RBAC off the route
  403s every caller and the collector cannot start. That precondition is stated in the user manual
  and the compose file.
- The route is the **only** code path that decrypts element credentials. It is **all-or-503**: a
  store-not-open, pool-acquire timeout, query error, audit-persist failure, or **any single
  element's decrypt failure** returns 503 with a retry hint and **never an empty or partial 200**
  (the app-usage "503-on-degrade never empty-200" rule). gnmic keeps its last list on a 5xx
  (verified), so a degraded core never deletes a target; a 200 that omitted a row **would** (gnmic
  `on-delete`), which is why partial success is forbidden. A KEK rotation mid-poll therefore yields
  the old-complete or the new-complete list, never a mix. Every fetch is audited
  (`network_element.collector.fetch`, principal id, target count, `result`); the audit is
  fail-closed. The response body never reaches any log. gnmic's loader sends no conditional
  request and treats any non-200 as a failed fetch (verified in its source), so there is **no
  `ETag`/304 path**: every poll decrypts the full list and writes one audit row; the supported
  scale and the loader-interval floor are stated in the runbook. A `degraded` fetch names the
  offending element id in its audit row, `get_network_element` exposes a non-secret
  `credential_status: ok|unreadable`, and the runbook says to re-enter or delete each unreadable
  element — otherwise one undecryptable row stalls the whole list until it is fixed.
- **Collector-principal integrity check**: `validate_assignment` rejects only the literal admin
  role names; a custom all-permission role is auditor-detected, not prevented. So core verifies at
  **every fetch, from the effective permission set, never from a cached verdict**, that the
  calling collector principal holds **exactly** `NetworkElement:Collect`; the route fails closed
  (403, audited `denied`) for a principal that holds anything else. One collector principal per
  collector instance. A second source address on one principal within an interval is a
  **signal** — it is audited and counted (`result=success`, the address in the audit row, never a
  label) and surfaced to the operator, but it does not deny: NAT hides a stolen token behind the
  collector's own address and a rescheduled collector legitimately changes address.
- Bearer lifetime and rotation use the existing `engine_principal.credential.rotate`/`.reveal`
  verbs and procedure; the user manual states the rotation steps and that a rotated device
  password reaches gnmic on its next poll (≤ 60s) and applies on that target's next reconnect.
- Device-side mTLS client certificates are **customer-supplied** and mounted into gnmic
  (`tls-reload: true` so a rotated file is picked up without restart — verify in the slice-1
  contract test). Yuzu's CA does not issue them: the non-agent client-cert namespace and EKU policy
  are deliberately deferred in `docs/pki-architecture.md`, and this ADR does not reopen that. The
  core ↔ gnmic mTLS pair (F2) is issued by Yuzu's CA under the existing server-leaf policy for
  core's client cert and a customer-supplied or Yuzu-issued server cert for gnmic (decided in slice
  1; stated in the runbook).
- **Risk-register entry** (SOC 2 doc, risk-register precedent): *collector-token theft discloses
  every element credential in one call.* Owner: the Security Lead (the SOC 2 doc's register
  owner). Likelihood: low (single-purpose bearer, mounted secret, RBAC-on only). Impact: high
  (every registered element's management credential). Mitigations: single-purpose principal + the
  per-fetch integrity check; fail-closed fetch audit; the `result=denied` alert and the
  source-change signal; bearer lifetime bounded by the engine-principal credential policy and
  rotated via the existing verbs; RBAC-enabled precondition. Review cadence: quarterly with the
  register, with every ADR that touches D6, and before any write path (D4). The entry is
  forward-declared here and lands in the register with slice 1. This is a register entry, not an
  "accepted residual" — the controls above are the controls.
- A "reference mode" (Yuzu stores only a secret-manager reference; the customer provisions gnmic
  from Vault) is named as a later option and not built — tracked as a follow-up issue filed with
  this ADR (its number is recorded in the PR before merge).
- `skip-verify` on an element target is **refused** by core's target publication: an element
  either presents a certificate the customer-supplied CA bundle verifies or is not dialled, so
  "TLS to devices with the customer's own PKI" is true as written and never silently downgraded.

### D7 — Identity and inventory: core-minted id, a new Postgres store, joins computed at read time

- A network element's identity is a **core-minted opaque id** (`ne-<uuid>`) assigned at
  registration; it is gnmic's target name (loader JSON key) and an `event-tags` label. The
  **natural key** is `(management address, adapter)`, unique: registration is an **upsert by
  natural key** that returns the existing id, so a retried `register_network_element` is
  genuinely idempotent (`idempotentHint: true` is truthful) and never mints a second element,
  credential or gnmic target. A **re-address is `update_network_element` with a new
  `management_address`** (uniqueness-checked), never a second registration; the id keeps
  `SecretCodec`'s row-PK-bound AAD stable across it. Learned chassis serial and LLDP chassis-id
  form a **second uniqueness key**: a registration whose learned identity already belongs to
  another element is audited `duplicate_identity` and refused (or linked, operator's choice), so
  one physical device can never be dialled under two ids. A **change in chassis serial or
  chassis-id under the same id is an audited `identity_change`**: edges and observations before it
  are retired, and the operator chooses relabel (keep the id) or new element (the old row is
  re-keyed to `address:<retired>` so the natural key is free, then disabled).
- **`NetworkElementStore`**, born on Postgres (ADR-0012): the element row (id, display name,
  learned vendor/model/OS, management address, adapter, vendor-profile family + override, purview
  override, enabled, `state`, `last_seen`); **interfaces**; **LLDP neighbours as edges**
  (`first_seen`, `last_seen`, `retired_at`); and the **FDB/ARP tables as observations**
  (`first_seen`/`last_seen`). Edges and observations are **separate tables**, so the service
  diagram can query adjacency without touching presence data (D5). `state` is a closed enum:
  `registered` (no data yet) · `no_profile` · `reachable` · `unreachable` · `disabled`.
  `last_seen` advances **only** on the per-target liveness signal (D9), never on stream health.
- **Edge retirement**: a gNMI delete notification retires the edge (`last_seen` frozen,
  `retired_at` set); an element's disable retires its edges; the leader's initial sync after a
  (re)subscribe is a full snapshot that retires edges absent from it — **but only for targets whose
  liveness is fresh and whose cache is not `no_data_yet`**, so a cold or evicted gnmic cache can
  never retire a live link. The `lldp` subscription in the shipped reference config is `SAMPLE`
  (or `ON_CHANGE` plus a periodic `SAMPLE`) at an interval below the gNMI-server cache expiration
  (a different cache from the Prometheus output's, D8). Retired edges are returned flagged, never
  silently as current.
- **Disable, re-enable, delete**: disable omits the target from the published list (gnmic
  `on-delete` tears the session down), retires edges, and makes `Get` answer `constrained:
  disabled`; re-enable republishes and the next initial sync re-establishes state. Delete
  cascades to the element's interfaces, edges, observations and credential
  (`network_element.delete`), clears the discovered-device link, and the next poll removes the
  target.
- **Observations retention and erasure**: observations keep a retention window **independent of
  any Incident** (closure neither purges nor extends; rows tied to an exported Incident are held
  only until the export's own retention expires), distinct from the edges window, implemented as a
  clock-guarded pass adopting `docs/clock-guarded-retention.md`'s apparatus in its PG shared-row
  variant and registered in that doc's adoption register. The store is a **DSAR erasure source**:
  `network_element.observations.erase` deletes the observation rows for a set of MACs and audits
  the row count, and the `AgentDecommission` cascade calls it with the agent's MACs **resolved from
  `device_ci` before that row is deleted** (ordering is load-bearing). Erasure for a MAC that
  resolves to no agent — a visitor's device — has no subject-resolution path today and stays
  **open** (ADR-0067's DSAR row), stated rather than implied. The
  default window, the lawful basis for non-employee MACs (legitimate interest + notice), and the
  SOC 2 inventory rows are decided before slice 1 ships. Collection is **opt-in by construction**:
  no element is observed until an operator registers it and stands up the opt-in collector (the
  SOC 2 doc's "opt-in artifact as the collection off-switch" precedent).
- `discovered_devices` (ADR-0044) stays separate and scan-shaped; registering an element for a
  discovered IP **links** the discovered row to the element id as a **soft id reference** (no
  cross-schema FK; cleared on element delete) via a v2 migration of `discovery_store` under the
  ADR-0012 runner — ADR-0044 is not amended.
- The join to agent-managed devices is **by MAC and IP, computed at read time** — never stored (a
  stored join duplicates fleet truth and is wrong between a port move and the next sync). Neither
  query surface exists today: `FleetTopologyStore` exposes agent → IP only (in-memory,
  per-replica, TAR-pushing agents only) and `device_ci` holds MACs as comma-joined text. ADR-0012
  §3 forbids a cross-schema method on `NetworkElementStore`, so the join has a **dedicated query
  owner** (an attachments query module in `server/core`), a by-value MAC index/normalised table on
  the device-CI side lands with slice 1, and the IP half is **best-effort** (the live TAR map). A
  MAC that resolves to no device is reported `unresolved`, never "no attachment".
- **Attachments result shape** (one copy for REST and MCP): `matches[]`, each with `element_id`,
  `interface`, `role` (`access` | `trunk` | `unknown`), `first_seen`/`last_seen`, and
  `ambiguous: true` when more than one access-port match exists in overlapping windows — **never
  a single pick**; `ambiguous` is computed over the **full candidate set before purview omission**,
  so an omitted competitor still marks the visible match ambiguous. The edge-port rule: an interface
  is `access` if it carries no LLDP neighbour
  edge to another element and ≤ `kAccessPortMacCap` MACs; otherwise `trunk`. A MAC seen on access,
  distribution and core switches returns the access-port match as the attachment and the others
  as `trunk`. An in-purview element the caller may not read without an Incident is **omitted per
  row with the omission declared** (`omitted: {element_id, reason: purview}`), never silently; an
  unresolvable purview denies that subject only (ADR-0067 D7), never the whole call.
- Every stored timestamp is **server receipt time**, never the element's clock (ADR-0016's
  `last_seen` rule).

### D8 — Prometheus: per-element series live only on gnmic; the server exposes aggregates only

- Per-element, per-interface series are served by gnmic's Prometheus output and scraped by the
  customer's Prometheus. Yuzu ships the scrape job in **all four** `deploy/prometheus/` files
  (`prometheus`, `-docker`, `-uat`, `-full-uat`) and a `yuzu-network-elements` alert group in
  `docs/prometheus/yuzu-alerts.yml`. **The alert names and signals are the contract and are fixed
  here; only thresholds ship in their own change, tuned against real data** (the OTA precedent):
  `NetworkCollectorStreamDown` (`…_stream_up == 0` on the leader), `NetworkCollectorFetchStale`
  (`time() - max(…_last_fetch_timestamp_seconds)` beyond N intervals — the only signal that
  distinguishes "stale forever" from healthy), `NetworkCollectorFetchRejected`
  (`…_fetch_total{result="denied"}` increments), `NetworkCollectorTargetDown` (gnmic's own
  per-target state via `up{job="gnmic"}` and gnmic's target metrics), `NetworkElementUnreachable`
  (**per element**, on gnmic's per-target state series carrying the `event-tags` `element_id`
  label — verified in the slice-1 contract test; if gnmic's internal metrics turn out not to carry
  `event-tags`, the alert is re-keyed on `source` — the server never carries it). gnmic's output
  `expiration` must exceed the scrape interval by a
  stated margin or a quiet `ON_CHANGE` series flaps.
- Labels: gnmic's `source` label is the **target name**, which the HTTP loader sets from the JSON
  key, so the key is the element id and `address` is a separate field; core also emits
  `event-tags` `element_id` and `element_name` per target so the labels do not depend on that
  detail. Whether gnmic's own `gnmic_*` target-health metrics carry `event-tags` is verified in the
  slice-1 contract test; the user manual documents resolving `ne-<uuid>` via `get_network_element`
  either way. Hostnames and management addresses are never labels.
- gnmic-side metric names follow gnmic's path-derived names, **not** `yuzu_*` — they are
  OpenConfig facts, and community dashboards already understand them. A sentence in
  `docs/observability-conventions.md` records that this is deliberate for connector-sourced
  series. gnmic's `expiration` means a stopped `ON_CHANGE` counter goes **absent**, which the
  alert rules assume (absent-not-stale, consistent with Yuzu's absent-not-zero rule).
- `yuzu-server`'s `/metrics` gains **aggregate families only**, named per
  `docs/observability-conventions.md` (`yuzu_server_*`), table-driven:
  `yuzu_server_network_elements_by_{vendor,adapter,state}` (absent-not-zero rollups; `vendor` is
  the **vendor-profile family — a closed set from `content/network-profiles/` plus `unknown`**,
  never the learned string; `adapter` and `state` are closed enums; label sets come from a
  `constexpr` list), `yuzu_server_network_collector_fetch_total{result}` (pre-seeded counter,
  per replica, summed), `yuzu_server_network_collector_last_fetch_timestamp_seconds` (epoch of
  the last **200** — never a 503 — per replica, alert on the max; **emitted as 0 as soon as a
  collector endpoint is configured**, so a collector that never fetches — wrong bearer, a 401
  before the route — is stale from boot rather than invisible),
  `yuzu_server_network_collector_stream_up` (0/1 — **emitted
  only by the replica that holds leadership and only while a collector endpoint is configured;
  absent on every other replica and on a deployment without the feature**, so it can never read
  0 on a non-leader or a non-user),
  `yuzu_server_network_collector_batches_total{result=ok|fenced_out|failed}` and
  `yuzu_server_network_element_store_degrade_total` (pre-seeded). Every pre-seed is gated on a
  configured collector endpoint (consistent with D9's "no job, no gauge" when dormant). **No
  `element_id` label ever appears on the server's `/metrics`.**
- No remote_write, Pushgateway or OTLP in this ADR.

### D9 — Ingest: core subscribes to gnmic, on the fenced leader

- Core opens **one gNMI `Subscribe`** to gnmic's gNMI server for the fact table's state paths
  (`ON_CHANGE` where the vendor supports it, else slow `SAMPLE`) across all targets. The
  subscriber is a background job classified **`FencedLeaderOnly`** via `background_jobs.hpp`
  (ADR-2002 §3/§6) — never a second "which loops are leader-only" list. `leader_gate.hpp` is a
  per-tick attempt gate and a stream has no tick, so the job **subscribes only while leading and
  tears the stream down on leadership loss** (otherwise two live subscriptions count against
  gnmic's `max-subscriptions` and the ex-leader's fenced-out batches are dropped silently).
- **Writes**: one transaction per notification batch, **chunked to a bounded row count**, the
  first data statement carrying the `epoch_fence_sql()` predicate under the isolation contract in
  `leader_elector.hpp`; a fenced-out batch is dropped whole and counted
  (`…_batches_total{result="fenced_out"}`); the new leader's initial sync is a full snapshot and the
  recovery. The writer has a **bounded lease-hold budget separate from request traffic** so a core
  switch's 50k-row FDB can neither hold a lease past `statement_timeout` nor starve heartbeat
  ingest or `is_revoked()` (ADR-1005's "a hot engine must not starve heartbeats" applies to this
  internal writer). A batch that fails is counted (`result="failed"`), never retried unbounded; a
  periodic full resync (`SAMPLE` or resubscribe at a stated cadence) bounds divergence when gnmic's
  subscription buffer drops updates behind a slow consumer.
- **Per-target liveness** (what `last_seen` means): a `SAMPLE` heartbeat path per target
  (`/system/state/current-datetime` at a stated interval) or gnmic's per-target state metric —
  decided in slice 1, stated in the runbook — drives `state` and `last_seen`; the liveness bound
  for an element that has **never** reported is measured from its registration or re-enable time,
  so a wrong credential at registration becomes `unreachable` within the bound rather than staying
  `registered` forever (a test-connection action is explicitly deferred). `…_stream_up`
  qualifies the **core ↔ gnmic hop only**; a dead switch behind a healthy gnmic is reported by
  `NetworkElementUnreachable` within the liveness bound, never left looking like a quiet one.
- Stream loss on the core ↔ gnmic hop is **observable, never silent**: `…_stream_up` drops to 0
  with an alert, `last_seen` stops advancing rather than being fabricated. Reconnect uses jittered
  exponential backoff with a stated cap; D10's `retry_after_ms` is derived from it.
- **Readiness**: the gnmic endpoint, stream state and fetch state are **never `/readyz` inputs**
  (ADR-1005 D7's rule, stated here because gnmic is not an "engine" by name).
  `NetworkElementStore` construction is fail-closed per ADR-0012 but it does **not** join the
  `stores_ok` conjunction: it is not on the agent control-plane path (the ADR-0049 precedent); a
  store degrade is counted (`…_store_degrade_total`), its routes return 503, the replica stays in
  rotation, and — so the degrade is never invisible — `/readyz`'s body carries a non-gating
  `notices` row (`degraded: ["network_element_store"]`) while a collector endpoint is configured.
  The SOC 2 doc's "every PostgreSQL store is gated into `/readyz`" sentence names this store as
  the exception. The feature is structurally dormant (no job, no gauge) when no collector endpoint
  is configured.
- gnmic clustering (Consul-locked target sharding) is out of scope: one collector per deployment
  in this iteration.
- Cache `Get` (D10) is a per-request unary call to gnmic's gNMI server from whichever replica
  serves the request — not a leader concern. gnmic caps concurrent unary RPCs (`max-unary-rpc`,
  default 64) and subscriptions (`max-subscriptions`, default 64); core's client bounds its own
  concurrency below those.
- gnmic push outputs (Kafka/NATS into an inbound ingest route) were rejected: a broker is a new
  dependency, and an inbound route is a new surface to secure.

### D10 — MCP/REST surface: five read-only tools; `Get` is a **cache read** keyed by canonical fact

**Verified 2026-10-03 against gnmic's docs:** gnmic's gNMI server serves `Get` **from its local
cache of subscribed notifications** (original timestamps preserved), relays `Set` only when
`read-only: false`, and **does not implement `Capabilities`**. Its REST API manages targets and
subscriptions only; there is no on-demand device RPC. So under D3 there is no *live* `Get` and no
`Capabilities` at all.

- **The fact table is the single source of truth for what is subscribed and what may be read.**
  One table in `server/core` (one copy for REST and MCP — the `dispatch_target_shape.hpp` rule)
  lists the **canonical facts**: `interfaces`, `lldp`, `system`, `platform`, `fdb`, `arp_nd`.
  Each vendor profile (D11) expands a fact to that vendor's `state`-container paths — OpenConfig
  by default (`/interfaces/interface/state`, `/lldp/…/state`, `/system/state`,
  `/components/…/state`, `/network-instances/…/fdb/…/state`,
  `/network-instances/…/neighbors/…/state`), vendor-native where a profile must — at **both**
  the subscription publish and the `Get` shape check. gnmic's loader takes per-target
  `subscriptions` as **names** that reference subscription definitions in gnmic's config file, so
  the paths live in the **Yuzu-shipped reference config, which defines exactly one named
  subscription per (profile family, fact)**, and core publishes per target the names its profile
  selects; the slice-1 contract test fails if the shipped config defines any other subscription or
  any `config` container. A per-element profile override selects a **named profile**, never a raw
  path.
- **Config-tree disclosure is filtered, not "impossible"**: subscriptions are `state` containers
  only, a `Get` is accepted **by fact name** (a raw path, OpenConfig or native, is refused with an
  A4 error naming the facts), and the response path **drops any `config` container** as
  defence-in-depth before the body is returned. **Widening the fact table is a security decision**,
  never inferred from one feature.
- **`Get` reads gnmic's cache, never the device.** `get_network_element_state` returns the
  **last-known** state for a fact, with gnmic's cached notification timestamp surfaced as
  `element_timestamp` and labelled as the **element's own clock** (D7's receipt-time rule governs
  stored rows, not this pass-through). **Absent is never empty**: a cold cache (gnmic restarted,
  nothing since subscribe) returns `constrained: no_data_yet`; an evicted/stale entry returns
  `constrained: stale`; neither is ever an empty table (gnmic's gNMI-server cache expiration is
  set explicitly and verified in the contract test). An agentic worker can never load a switch.
- **Output schema is honest**: a typed **envelope** (`element_id`, `fact`, `element_timestamp`,
  `constrained`, `observed_at`) around an **open JSON body** of vendor-variable OpenConfig shape.
  If the body is accepted as a typed-schema waiver under A5 it is registered in the A5 exception
  ledger (`docs/agentic-first-principle.md` §A5) with issue and revisit date at implementation.
- **No `Capabilities` tool.** What a worker wanted from it — "which models does this vendor
  serve" — comes from the vendor profile (D11) and the `system` fact's software version; a
  profile-less element reports `constrained: no_profile`.
- Read tools (each with a REST twin, A1–A5, `ServiceScopeClass::denied`, `openWorldHint: false`
  per the house rule that the managed estate is a closed world):
  `list_network_elements`, `get_network_element` (`NetworkElement:Read`, audited
  `network_element.view`); `list_network_element_neighbors` (edges, flagged when retired;
  `network_element.state.view`); `list_network_element_attachments` (D7 shape; agent-side
  confined; `network_element.attachment.view` through the behavioural-read gate);
  `get_network_element_state` (cache `Get` by fact; `network_element.state.view` for
  `interfaces`/`lldp`/`system`/`platform`, `network_element.presence.view` for `fdb`/`arp_nd`).
- Write surfaces (`NetworkElement:Write`/`Delete`, in `kWriteTools`, `destructiveHint: false`
  except delete, `idempotentHint: true` by the D7 upsert): `register_network_element`
  (`POST /api/v1/network-elements`), `update_network_element` (`PATCH …/{id}` — display name,
  enabled, purview override, profile override), `delete_network_element` (`DELETE …/{id}`,
  `destructiveHint: true`), `set_network_element_credential` (`PUT …/{id}/credential` —
  write-only; no tool ever returns a credential). `GET /api/v1/network-elements/collector-targets`
  is **REST-only by design** (gnmic is the caller) and is recorded as a dated entry in ADR-1005's
  D1 exception ledger with this ADR.
- `retry_after_ms` on a `Get` that finds gnmic unreachable is derived from the D9 backoff state,
  not a constant (CI-gated by `scripts/ci/check-mcp-retry-hints.py`).
- A genuinely live device read, if ever wanted, is a new decision: it would need a second client
  path to the device, which D3 forbids today.

### D11 — Build, deploy, vendor normalisation; core only

- `gnmi.proto` and `gnmi_ext.proto` (Apache-2.0) are vendored at their **canonical import path**
  under `proto/third_party/github.com/openconfig/gnmi/…` with their LICENSE, and compiled into a
  **separate `yuzu_gnmi_proto` static library linked by `server/core` only** — not into
  `yuzu_proto`: `buf lint`'s `PACKAGE_DIRECTORY_MATCH` and `buf breaking --against origin/main`
  (Tier-1 CI) would otherwise police upstream gnmi on every pin bump, and `gen_proto.py`'s
  flattening is deliberately limited to `yuzu/` includes. `proto/buf.yaml` gains `lint.ignore`/
  `breaking.ignore` for `third_party/`. Server unit tests that link it inherit the #572
  single-descriptor-pool shape via the headers dependency; nothing is added to the agent daemon or
  the plugin ABI by structure, not by dead-object elision. `docs/build-guide.md` gains a "vendored
  third-party protos" section with the pin (gnmi release tag) and the update procedure.
- **`yuzu-netcollector` is an opt-in compose profile/overlay, absent from the default `up`**;
  default behaviour is unchanged on upgrade, and making it default later would be a
  `**Breaking —**` fragment. Image `ghcr.io/openconfig/gnmic` pinned by **tag + sha256 digest**
  (the Prometheus/Grafana precedent; dependabot's docker ecosystem on `/deploy/docker` proposes
  bumps; a bump is a reviewed change). The image is **outside both Yuzu gates** — the compose
  healthcheck invariant covers the Yuzu images + postgres, and `check-compose-versions.sh` matches
  only `yuzu-{server,gateway,agent}` — so: its healthcheck is a TCP/HTTP probe against gnmic's
  Prometheus listener using a tool **verified present in the pinned digest — a slice-1 exit
  criterion, not a present fact** (a TCP probe proves the process is up, not that targets are
  healthy); `yuzu-server`'s `depends_on` never waits on the collector; the service appears in the
  `-uat`/`-full-uat` composes and the reference `docker-compose.yml` behind the profile; and its
  digest pin is guarded by the **slice-1 contract test against the pinned image** (loader JSON
  shape, cache
  `Get`, label names, `tls-reload`, `expiration`), which also guards `source`-label and loader
  semantics across bumps. gnmic is a **separate process** (Apache-2.0, nothing linked). The
  digest is content-addressed and survives a by-digest registry mirror; a tag-only mirror must
  re-pin; customers scan it as a third-party image (Yuzu's release SBOM/cosign covers Yuzu images
  only). gnmic's REST API server is disabled; its gNMI server is reachable from core only.
- **Bootstrap order** (slice-1 deliverable, runbook in `server-admin.md`): core up with RBAC
  enabled → an admin creates the collector engine principal and grants `NetworkElement:Collect` →
  the bearer is minted and mounted as a secret → gnmic starts with the Yuzu-shipped reference
  config; on a 401/503 or an empty list at first boot gnmic simply has no targets and polls again.
  Core learns the gnmic endpoint and its client mTLS material from `--netcollector-endpoint` /
  `--netcollector-client-cert`/`-key`/`-ca` (names final in slice 1). A non-compose install path
  (Podman/systemd/VM) and a Helm chart are deferred and named as follow-ups.
- **Vendor profiles are content, not code**: build-time-embedded YAML under
  `content/network-profiles/` mapping each canonical fact (D10) to the `state`-container paths and
  encodings a vendor family serves. **Profiles land incrementally and each carries a status**:
  `contract-tested` (exercised by the containerlab rig — slice 1 ships **Nokia SR Linux** and
  **Arista cEOS**, the two the rig can run), `field-reported` (a design-partner lab device), or
  `unverified`. **Cisco IOS-XE, IOS-XR, NX-OS, Junos and SONiC are planned**, not committed to
  slice 1, and each profile records which of the D10 facts it serves (IOS-XE's OpenConfig FDB/ARP/
  LLDP coverage is the thinnest, so it is the likeliest to serve a subset). A per-element operator
  override selects a named profile. Each profile records its device-side prerequisites (gNMI
  enablement, minimum OS
  version, a read-only AAA/TACACS+ account, the change request a network team expects). An
  element with no profile is registered, reports `state = no_profile` and `constrained:
  no_profile`, and is never served a fabricated empty table.
- **Nothing is added to the agent daemon or the plugin ABI.**

## Considered and rejected

- **Yuzu-written gNMI client (in core, or a "collector agent" — an agent daemon hosting the
  dialer).** The collector-agent shape is the incumbents' pattern (MID server, Datadog NDM, Zabbix
  proxy) and was the recommendation until gnmic was weighed. Both shapes need the **same** new
  southbound seam this ADR registers as B8, so the seam is not the discriminator; the
  discriminators are: a Yuzu-written dialer is code Yuzu must own and harden against every vendor's
  gNMI quirks; the agent-hosted variant needs gRPC in agent core (no plugin links gRPC; Windows
  linkage is fragile), the agent secret-delivery threat model ADR-3005 demands before
  `yuzu_ctx_get_secret` is wired, and the agent's first `/metrics` endpoint. gnmic gives the same
  data plane for a compose pin.
- **A new standalone Yuzu southbound binary** (`yuzu-netcollector` as our code): all of the above,
  plus a new artifact that resembles an engine while the merge gate is red.
- **Engine-hosted** (UCE): fails the Decision 2 test (collection is mechanism) and cannot merge.
- **gNMI-only model**: fails completeness on the first firewall.
- **Elements as management-group members** now: touches the catastrophic confinement chokepoint
  (`authorize_list_read`, `dispatch_confined_arms`) for a need the first iteration does not have.
- **A separate site/trust-zone confinement lattice for elements**: a second lattice is the drift
  the access-control rows exist to prevent.
- **Narrowing the table read by confinement**: rejected by owner decision — the whole table is the
  feature; purview and audit are the controls.
- **Per-element series on `yuzu-server`'s `/metrics`**: breaks the aggregated, absent-not-zero
  label discipline and makes the server a telemetry bottleneck.
- **Yuzu writing gnmic's config file** (secrets on disk, co-located with the server) and
  **Yuzu holding no credentials at all** (two consoles; no rotation) — see D6.
- **Storing the element↔device join**: duplicates fleet truth and goes stale on a port move.
- **Reusing `discovered_devices`** as the element row: IP-keyed, which breaks on multi-homed or
  re-addressed management planes.
- **Vendoring gnmi protos into `yuzu_proto`**: fails `buf lint`/`breaking` and the flatten step
  (D11).

## Consequences

- **ADR-0031 Decision 8 seam inventory amended**: B8 core → network collector (D3). The
  amendment lands in `0031-presentation-core-engine-decomposition.md` with this ADR's merge.
- **ADR-1005**: Decision 2 appendix row (connectors are core, for the class; estate fact ≠ domain
  data); D1 exception-ledger entry for the REST-only collector-targets route.
- `CONTEXT.md` gains **Network element**, **Network collector**, **Collector principal**,
  **Connector** (and, via ADR-0067, **Purview** and **Incident**). "Network device" keeps its
  existing meaning (an agent endpoint in the `/network` lens); "telemetry" stays ADR-0003's.
- The roadmap's Phase 9 placement question is settled (connectors are core: control plane in core;
  the data plane may be an external, non-Yuzu process); the 9.x sketches remain sketches.
- **Closed lists that gain entries in slice 1** (each a build/test failure if missed):
  `rbac_store.cpp` securable `types[]` and `ops[]` (+ the Administrator loop for
  Read/Write/Delete, `Collect` excluded), `kRbacSecurables`/`kRbacOps` in `mcp_server.cpp`,
  `kSeededSecurableTypes`/`kSeededOperations` in `test_capability_catalogue.cpp`, the
  `test_rbac_store.cpp` binding test, `kRbacAssignableRoles` (`rbac_assignable_roles.hpp`) and its
  MCP schema enum for `NetworkEngineer` (and **not** for `NetworkCollector`, which is seeded but
  never human-assignable), the "securable types" counts in
  `docs/user-manual/rbac.md` and `docs/auth-architecture.md`, `/api/v1/discover/permissions` (store-
  derived, automatic), and the audit-verb table in `docs/user-manual/audit-log.md` (D5's verbs).
- **SOC 2** (`docs/enterprise-readiness-soc2-first-customer.md`): the "Postgres Data Inventory"
  table gains
  `network_element_store` (edges: asset topology; observations: **presence-over-time, new
  category, behavioural-adjacent**, DSAR erasure source, decommission-cascade member, retention per
  D7) and `network_element_credentials` (secret, `SecretCodec`); the "Behavioral telemetry (DEX)"
  section's channel list gains `network_element.presence.view` and
  `network_element.attachment.view`; the collector-targets route is listed as the secret-egress
  channel; the Workstream A risk register gains D6's entry; the shared-responsibility matrix
  records Yuzu = control plane, customer = gnmic hosting, device certs, device-side AAA.
  **Questionnaire answers — true once slice 1 ships, not before**: device credentials are stored in
  Postgres under `SecretCodec` envelope encryption; they are readable in the clear only by
  collector-class engine principals holding exactly `NetworkElement:Collect`, through one audited
  route, and they then live in the collector process's memory and transit the F1 response body
  over TLS; rotation is a credential `set` that reaches the collector on its next poll; a
  customer-hosted secrets manager (reference mode) is a tracked roadmap item (issue number in the
  PR); device-side TLS verifies against the customer's CA bundle with customer-issued client
  certificates where the device requires them, and `skip-verify` is refused.
- **Documentation deliverables (slice 1)**: `docs/user-manual/network-elements.md` (collector
  install and bootstrap, register an element, profiles and `no_profile`, credentials and rotation,
  the D3 flow table, troubleshooting `stream_up`/`last_seen`/`state`); `rbac.md` (securable, role);
  `rest-api.md` + `mcp.md` (tools, twins, write routes, the REST-only route); `audit-log.md`
  (verbs); `metrics.md` (families, alert names); `upgrading.md` (additive — no behaviour changes
  for a deployment that never registers an element: the securable seed is additive, the job and
  gauge are dormant, the compose service is opt-in); `server-admin.md` (recovery runbook: **core is
  authoritative and gnmic converges** — gnmic holds no durable state and rebuilds from the next
  poll; restoring an older Postgres snapshot removes later-registered elements from collection and
  they must be re-registered — which mints a new `ne-` id, so their series and `event-tags`
  change; KEK loss makes `network_element_credentials` unrecoverable (ADR-0010) and credentials
  are re-entered, and a single unreadable row stalls the whole target list until it is re-entered
  or deleted (D6); the KEK files under `--ca-dir` are backed up **paired** with the Postgres dump
  per `server-admin.md`'s existing pairing rule, with old KEK versions retained; backup scope
  includes the `network_element` schema). The
  works-council export runbook depends on ADR-0067's mechanism.
- Governance routing for the implementation PRs: `security-guardian` + `architect` (new securable,
  engine-principal grant, secret egress, fact table, behavioural-gate consumers), `cpp-safety`
  (long-lived gRPC stream, fenced-leader job, bounded writer), `sre` (metric families, alert
  group, readiness statement), `compliance-officer` (presence-data classification, retention,
  erasure), `build-ci` (vendored protos, `buf.yaml`), `release-deploy` (compose profile, pin
  guard), `docs-writer`. A new routed-concern row for the fact table, the collector-targets route
  and the presence verbs lands with the first implementation slice, not with this ADR.
- The fabric-level reachability seam in `CONTEXT.md` "Reachability" is **not** filled by this ADR:
  LLDP/FDB give physical adjacency, not what ACLs/VLANs *permit*. Config-analysis (Batfish) is the
  candidate filler for that seam and is a separate decision.
- Follow-ups filed with this ADR: the containerlab + pinned-gnmic contract rig (shared by every
  chaos scenario); gnmic clustering / multi-collector sharding; SNMP/SSH adapter (SuzieQ); the
  `Set` write path with its Execution Plan and credential-egress hardening; site-confined elements
  via generalised group membership; reference-mode credentials; non-compose install path and Helm
  chart; the numeric constants (liveness bound, batch chunk, lease budget, backoff cap, retention
  default, `kAccessPortMacCap`).

## Binding status

`status: accepted` on merge to `dev` (`docs/agents/domain.md` convention — the merged file
carries the status) **except** the purview clauses — D5's behavioural-read gate on the two presence
verbs,
D7's purview-derivation and per-row omission, D10's gate routing — which bind when **ADR-0067 is
accepted**; until then those reads are audited at the `device_ci` tier. This is the additional
acceptance gate the convention lets an ADR name. D4 (no write path), D5 (global securable, whole
table deliberate, no faked confinement, split verbs), D6 (single decrypting route, dedicated
predicate, all-or-503), D8 (no per-element series on the server; leader-only `stream_up`), D10
(fact table as single source, `state` containers only, absent-not-empty) are the clauses a future
diff is most likely to erode silently and are the ones the implementation's routed-concern row
must restate.
