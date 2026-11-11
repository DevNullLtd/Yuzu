# ADR-0016: Agent→Server Daily Sync Framework (hash-skip conditional push)

**Date:** 2026-06-24
**Status:** Accepted (v1 sliced — installed software is source #1)
**Component:** Agent core (sync scheduler) · Server (inventory ingest + Postgres store) · Gateway (proxy)
**Authors:** Dave Rae

> **Amendment pending: ADR-3006 (plugin management, proposed 2026-10-06).** ADR-3006 sets
> the direction that `--inventory-disable` stops being the collection toggle: it becomes a
> one-time starting-state input that the server adopts as a visible off-rule, and each daily-sync
> source becomes a unit that can be switched off on its own. Nothing has changed in the product
> yet: until the work that follows ADR-3006 lands, this ADR describes what ships.

## Context

We are beginning to write endpoint-reported data to the server's **PostgreSQL**
substrate (ADR-0006/0008). The first concrete need: every endpoint reports its
**installed-software inventory daily** into central Postgres, queryable
fleet-wide for software asset management (SAM), vulnerability relevance, and
(future) software-entitlement reclamation ("software not used in ≥ X days").

This is the first instance of a broader, recurring need: the agent should push
**different *flavours* of data on *different cadences*** to the server. We want
one mechanism for that, not a bespoke path per data type.

Two existing constraints shape the design:

- **Be kind to the network at fleet scale.** A full installed-software list is
  ~100–300 entries/host; shipping it from every endpoint every cycle is exactly
  the traffic we want to avoid.
- **Thin central (ADR-0004).** Most device data stays on the per-agent edge
  warehouse; central Postgres holds only what fleet-wide queries need.

### Why not "Echo first"

The initial instinct was to land this in the agent's local **Echo** edge
warehouse and pull it centrally. Rejected: Echo is **pull-only by design** and
**event-shaped** (it records *change events*, e.g. PR #1620's `$Software`
source records install/uninstall/upgrade deltas). Echo answers *"what changed,
when"* on the edge. Our goal is *"what is installed now, daily, in central
Postgres."* Routing a full daily snapshot through Echo would require building a
new push/export transport that contradicts Echo's no-push philosophy, and Echo's
delta shape does not match a full-snapshot need. The two are **complementary,
not substitutes**: this framework owns *current state, central*; Echo owns
*change history, edge*. PR #1620 is out of scope here and lives or dies on its
own merits.

## Decision

Build a **generic, agent-driven, per-source daily sync framework** that pushes
data to the server over the existing (dormant) `ReportInventory` RPC, with a
**hash-skip conditional protocol** to keep the network quiet. Installed software
is **source #1**; the seam is built right so further sources (and a future
`last_used` usage source for SAM/entitlement) are drop-ins.

### 1. Vehicle — direct push over `ReportInventory`
Reuse the dormant `AgentService.ReportInventory(InventoryReport) → InventoryAck`
RPC. `InventoryReport.plugin_data` is already a generic `map<string,bytes>`
envelope (key = data-type, value = opaque blob). No Echo involvement.

### 2. Generic per-source framework (agent)
A small, source-agnostic seam:
- `SyncSource { name, interval, collect_fn, hash_fn }`.
- `SyncScheduler` owns the per-source loop, the spread/startup policy, the
  hash-skip protocol, and the weekly full-floor.
- Sources register installed_software for v1. No speculative knobs.

### 3. Trigger — agent-internal, per-source cadence, no fleet lockstep
- The **agent owns the clock**; each source has its **own cadence** (software =
  24 h).
- Spread across the fleet by a **stable per-agent phase offset**:
  `offset = hash(agent_id + source) % interval`. Deterministic → a reboot does
  not re-cluster the fleet or trigger a spurious sync.
- Persist `last_sync_ts` + `last_hash` per source in the agent **`KvStore`**
  (`agents/core/src/kv_store.cpp`, `kv_store.db`), namespace `__sync__` — the
  same agent-core state store Guardian uses (namespace `__guardian__`).
  Explicitly **not** Echo: Echo is a *plugin-owned, append-only* capture
  warehouse; this is *mutable agent-core* KV state, and core must not depend on
  a plugin's DB being loaded/healthy.
- **Startup policy:** first-run or overdue (gone past one interval while
  offline) → one catch-up sync after a *short random startup delay* (so a
  mass-deploy or a site's Monday-morning power-on does not herd); otherwise wait
  for the next phase fire. *(Amended by the Update of 2026-11-04 below: "overdue"
  means a `next_fire` more than 15 minutes late, not a full interval, and the
  catch-up is spread over 30 minutes; the 10 minute startup delay stays for a first
  run.)*

> **Update (2026-10-04, #5327):** a source whose collect yields nothing records
> `skip_streak` / `last_skip` in the same `__sync__` KV. A source that opts in
> (`skip_backoff`; today installed_software only — device_ci dispatches many
> actions per attempt and software_licensing's single `license_scan.list` is a
> full scan of every detection surface, so neither retry is cheap) retries after
> the earlier of the next phase slot and 1 h · 2^(streak-1) while the streak is
> at most 5, then once per daily slot; the others keep one full interval. The operator-facing schedule is stated once, in
> `docs/user-manual/inventory.md`. The skip reason reaches the server only as a
> heartbeat tag, never a report. KV writes are ordered skip fields first
> (`save_state`), so an interrupted save never advances `next_fire` with the skip
> unrecorded.

### 4. Hash-skip conditional protocol
- The agent **always** sends a per-source `content_hash`; it **omits the full
  blob when the hash is unchanged** since the last successful sync.
- The server is **authoritative**: on stored-hash mismatch *or no record* it
  replies `need_full` for that source, and the agent re-pushes the full list
  (conditional-request / HTTP-304 pattern); the resend is jittered so a
  server-side cold cache doesn't trigger a synchronized full-resend herd.
  This covers all cold-cache cases: DB wiped, new/migrated server,
  reassigned agent.
- A **weekly full-floor** (send full regardless) is the defense-in-depth
  backstop.
- **Hash trust:** the server **recomputes the canonical hash server-side from
  the received rows** on a full payload and stores *that* — it never trusts the
  agent's claimed hash as the stored value. Skip decisions compare the agent's
  claimed hash against the server-recomputed stored hash. A buggy agent that
  wrongly believes "unchanged" is bounded by the weekly full-floor (accepted
  staleness bound).

Proto additions (wire-compatible, additive):
- `InventoryReport.content_hashes : map<string,string> = 4`
- `InventoryAck.need_full : repeated string = 2`

### 5. Two server entry points → one shared ingest seam
A gateway-connected agent does **not** reach `AgentServiceImpl::ReportInventory`;
it reaches `GatewayUpstreamServiceImpl::ProxyInventory` (the gateway re-encodes
and calls the server's `ProxyInventory`, exactly like Register/ProxyRegister).
Both entry points route the typed sources through **one** shared
`ingest_inventory_report(...)` seam (mirroring `HeartbeatIngestion`) so direct
and gateway paths persist `installed_software` **identically** into the typed
`SoftwareInventoryStore`. The gateway additionally keeps its pre-existing
generic `InventoryStore::upsert` for any **other** `plugin_data` key (the
sync-framework baseline), skipping `installed_software` there to avoid double
storage. Closing the direct/gateway gap is load-bearing, since the gateway
topology is the one we do **not** internet-expose direct.

The report is **untrusted external input**: size caps on `plugin_data`, row
caps, UTF-8 validation at the seam (security-guardian gate).

### 6. Gateway field survival
`ReportInventory` is already proxied, but the gateway **decodes then re-encodes**
via gpb (`gateway_pb:encode_msg`). New proto fields are silently dropped at the
gateway hop unless the gateway's `agent_pb.erl` + `gateway_pb.erl` are
regenerated (the documented "csr_pem trap"). Regen is in scope — without it,
through-gateway agents lose both the hash-skip and the `need_full` nack, so
their data never lands.

### 7. Server store — coexistence: generic baseline + typed Postgres projection
**Correction (recon error):** the existing `InventoryStore` is **not** a dead
stub — it is the generic per-source blob store (`agent_id, plugin, data_json`)
that **backs a documented, tested scope-walking source** (`kInventoryQuery` /
`from-inventory-query` in `scope-walking-design.md`) **and** the inventory eval
engine (`evaluate_inventory`, `/api/v1/inventory/evaluate`). It is unfed today
(no agent calls `ReportInventory`), but it is wired + tested + documented.
Crucially, its per-*source* shape is the **same shape** as the daily-sync
envelope, so it is the natural **baseline store for the whole sync framework**
(many data types will sync — not just software).

Therefore we **coexist, not replace**:
- Keep the generic `InventoryStore` (SQLite today) **untouched** — the
  sync-framework baseline + the scope/eval surface. (Porting it to Postgres
  under the sync framework is a follow-on, aligned with ADR-0006.)
- Add a **new born-on-Postgres `SoftwareInventoryStore`** (schema
  `software_inventory_store`) — the **typed, read-optimized projection** for
  sources that need fleet-wide queries. `installed_software` is the first;
  future high-query sources get their own typed table in this store. Built per
  the `OfflineEndpointStore` template + ADR-0012 + the postgres-store-playbook:
  - **Current-state only** (replace on change) for the inventory rows. One
    exception, recorded in the 2026-11-04 Update (schema v11): a per-device
    install history (`software_changes`, 400 days, clock-guarded prune) is kept
    in central PG; any wider change-history is an edge/Echo concern (ADR-0004
    boundary).
  - **Normalized relational rows**, **no JSONB/GIN** — honors the
    "migrate off Postgres easily" constraint. Generic parent
    `inventory_state(agent_id, source, content_hash, first_seen, last_seen)` +
    one **typed child per source** (`installed_software(agent_id, name, version,
    publisher, install_date)`). Replace an agent's child rows in one transaction.
- **Failure posture:** authoritative for reads (surface errors, never
  silent-empty); ingest tolerates a transient PG outage (next sync + weekly
  floor self-heal).
- App-identity key kept **stable + normalizable** so a future `last_used` usage
  source can join (`installed ⨝ last_used → unused ≥ X days`).

### 8. Scope, identity, and access
- **No end-user profiles** for v1. We invoke `installed_apps` `list` (Windows:
  `HKLM` + the *agent service account's own* `HKCU`; Linux: the system package
  DBs dpkg/rpm/pacman; macOS: a `system_profiler SPApplicationsDataType`
  application-**bundle scan** of machine-wide locations + the calling account's
  user-domain context — NOT a package DB) — **not** `list_per_user`, which
  enumerates every user profile + carries usernames. So no end-user PII and no
  works-council co-determination trigger. The Windows `HKCU` and the macOS
  user-domain context are benign **by run identity**: the agent runs as a service
  account or root, never the console user, so neither crawls a logged-in user's
  hive / `~/Applications`. (On Windows the account is **LocalSystem** today, not
  the intended virtual `NT SERVICE\YuzuAgent` — tracked as #1442. That deviation
  does not weaken this argument: LocalSystem's own profile is no more an end
  user's than the virtual account's. Linux/macOS are `_yuzu` / root as stated.) (If macOS ever moves
  to a console-scoped account, re-evaluate.) Per-user enumeration is a later,
  gated, pseudonymized addition if needed.
- Reuse the existing `installed_apps` plugin (already 3-OS) **in-process via
  `LocalDispatcher`** — no new collector.
- New **`Inventory` securable type**; reads gated on `Inventory:Read` (no
  inventory securable exists today; `Response` is semantically wrong for a
  dedicated store; `Inventory` future-proofs the framework).
- Read surfaces: **shipped in v1** — direct SQL (free) + an **MCP query tool**
  (`query_installed_software`, `Inventory:Read`, management-group scoped).
  **Planned follow-ons** (NOT in v1): a **REST** endpoint, an installed-software
  section on the existing `/device` drill-down, and a dedicated fleet-wide
  software dashboard.

> **Update (2026-06-26):** the REST read surface shipped as
> `GET /api/v1/inventory/software` (`Inventory:Read`, management-group scoped,
> degrade→503-never-empty per §7, set-and-proceed audit per §8) — the REST sibling
> of `query_installed_software`, mirrored 1:1. See `docs/user-manual/inventory.md`
> §REST and `docs/user-manual/rest-api.md`. Remaining follow-ons: the `/device`
> drill-down section and the fleet-wide software dashboard.

> **Update (2026-06-28):** the "management-group scoped" qualifier on the read
> surfaces above (`query_installed_software` and `GET /api/v1/inventory/software`)
> is **superseded — not yet effective.** Both gate on the *global* `Inventory:Read`
> permission, under which the per-agent drop filter does not narrow results (a
> management-group-confined operator is denied at the global gate; a global operator's
> filter is a no-op). Read these as "global `Inventory:Read`; per-device confinement
> only" until the admit-then-filter list gate lands. See **ADR-0017** (the decision +
> gate design), **#1716** (doc-honesty), and **#1713/#1676** (the inventory
> effective-vs-inert UAT).

> **Update (2026-08-20, #3290):** the effective-vs-inert gap above is closed for both
> read surfaces. `query_installed_software` and `GET /api/v1/inventory/software`
> migrated onto `AuthRoutes::require_fleet_read` (ADR-0017's admit-then-filter
> primitive, composed with service-scope confinement) as their sole authorization
> gate — a management-group-confined operator now gets a genuinely filtered result
> instead of a 403, and a service-scoped token gets a filtered result instead of a
> blanket deny. This closes ADR-0017's PR-D backlog item for these two surfaces; the
> `/inventory` dashboard Find tab is unmigrated and stays global-gate-only for now
> (that tab's routes were since removed; the equivalent read is the `/software` page's
> devices expansion, still global-gate-only).
> See `docs/security-reviews/service-scope-phase2-migrations-2026-08.md`.

## Consequences

**Positive**
- One mechanism for all future agent→server periodic data; new sources are
  drop-ins.
- Network cost tracks *change*, not cadence: steady-state is a per-source hash,
  not a list.
- Portable store (plain relational rows) — re-homing off Postgres is swapping
  the substrate layer, not rewriting the data model.
- Direct + gateway parity via a single ingest seam.

**Negative / costs**
- Proto + gateway gpb regen required (multi-module: `agent_pb`, `gateway_pb`).
- A new born-on-PG store + RBAC securable + MCP/REST/dashboard surfaces.
- Server-side hash recompute on full payloads (cheap; bounded by hash-skip
  rarity).

**Risks**
- A buggy agent under-reporting "unchanged" → bounded by the weekly full-floor.
- Forgetting the gateway regen → silent field drop for through-gateway agents
  (explicitly called out; covered by a gateway wire test).

## Alternatives considered

- **Echo-first + central pull** — rejected (pull-only, event-shaped; see Context).
- **JSONB blob + GIN index** — rejected (Postgres lock-in; clunky range
  filters; conflicts with the migrate-off-PG constraint).
- **Always send the full list** — rejected (abandons network-kindness).
- **Server-dispatched daily schedule** — rejected (daily fleet fan-out; the
  agent-push model matches the RPC's purpose and self-staggers).
- **Full version history in central PG** — rejected for v1 (fattest; contradicts
  thin-central; history is Echo's edge concern).

## Relationship to other ADRs
- **ADR-0004** (edge warehouses / thin central) — this framework's
  current-state-central / history-on-edge boundary is a direct application.
- **ADR-0006/0008** (Postgres substrate) — `InventoryStore` is born-on-PG.
- **ADR-0012** (server Postgres store contract) — `InventoryStore` follows it;
  recorded as a prioritized net-new store in `docs/postgres-migration-ladder.md`.
- **PR #1620 / `$Software` Echo source** — complementary edge change-history,
  not a substitute for this framework.

## Updates

### 2026-06-27 — freshness keys off server receipt time, not agent `collected_at` (#1685)

**Decision.** `inventory_state.last_seen` (and `first_seen`) is stamped with the
**server receipt time**, not the agent-supplied `collected_at`. The
`yuzu_inventory_stale_agents` freshness gauge therefore measures *contact
freshness* (when the server last heard from the agent for this source), not
*content-collection time*.

**Why.** The gauge (`count_stale_agents`, surfaced from the metrics sweep)
flags `last_seen < server_now − 2d`. With `last_seen` written from
`collected_at`, that comparison straddled **two clocks** — a server-side
threshold versus an agent-supplied timestamp. A future-skewed or hostile agent
could pin `last_seen` ahead of `now`, so it never counted as stale and a *dark
endpoint stayed hidden* (the worst case); a >2d past-skewed agent counted as
stale while actively syncing (false positive). Server-stamping puts both sides
of the comparison on one clock, immune to agent skew in either direction. This
supersedes the implicit "trust `collected_at` for freshness" of §4/§7.

**Implementation.** No schema change and no new column were needed — `last_seen`
has no display/REST consumer, only the gauge, so the existing column is reused
with corrected write semantics. `collected_at` remains on the wire
(proto-carried) and in the ingest signature for a possible future *content-age*
signal, but drives no persisted timestamp. The write fix is forward-only (a dark
agent cannot re-stamp itself), so **migration v3** clamps any pre-fix row whose
`last_seen` was written into the future down to `now`, re-entering it into the
staleness window. Options weighed and rejected: a `min(collected_at, now)`
*clamp* (kills only future-skew, not past-skew) and a *separate server-stamped
column* (correct but an unnecessary migration given the absent display consumer).

### 2026-06-30 — source #3 `device_ci` (device hardware/OS identity, CMDB CI record)

A third sync source, **`device_ci`**, collects the machine's stable
hardware/OS identity by invoking the existing `hardware`, `device_identity`,
`os_info`, and `network_config` plugins in-process (`LocalDispatcher`) and
rendering them into a canonical CI record: manufacturer, model, **serial
number**, **system UUID**, BIOS vendor/version/date, CPU model/cores/threads,
RAM bytes, a disks summary, **primary MAC** + a MAC summary + NIC count, OS
name/version/build, and architecture. A new `hardware` plugin `system` action
collects serial + UUID (Windows WMI, Linux `/sys/class/dmi/id` via
`cap_dac_read_search`, macOS `ioreg`). **Volatile telemetry — disk free space,
uptime, IP addresses — is deliberately excluded** so the content hash is stable
and hash-skip suppresses steady-state traffic (an IP that churns on DHCP renewal
would flap the hash and force a daily full resend).

**No proto change and no gateway gpb regen.** A new source is a new KEY in the
existing `plugin_data`/`content_hashes` maps, not a new proto FIELD — §6's regen
requirement is about new fields (`content_hashes`/`need_full` themselves), which
already shipped. `app_perf` (source #2) established this precedent; `device_ci`
confirms it. The Erlang gateway decodes/re-encodes only the existing map fields
and never inspects opaque map values, so a new key survives the hop unchanged.

**Store.** Born-on-PG `DeviceInventoryStore` (schema `device_inventory_store`,
table `device_ci`) — **1:1 per agent** (one identity per machine, the
`OfflineEndpointStore` shape), not the 1:N parent+child of §7 (that is for the
N-row `installed_software`). Ingest via the shared `device_ci_ingestion.*` seam
on **both** `ReportInventory` and gateway `ProxyInventory` (§5 parity). Failure
posture per §7: ingest fail-soft, reads authoritative (`std::expected` /
`std::nullopt`, never silent-empty). `last_seen`/`first_seen` are the server
receipt time from day one (#1685).

**Data classification + co-determination (supersedes the borrowed §8 citation).**
§8's "no PII / no co-determination trigger" argument was constructed for
`installed_software` (HKLM app names) and does **not** transfer unchanged:
`serial`, `system_uuid`, and `primary_mac` are **stable device-persistent
identifiers**, which are personal data under GDPR when a device is
person-assigned, and the *capability* to track a device (and by association its
user) over time triggers EU works-council co-determination review regardless of
per-user data. The collection is still **machine-scope** (no username/SID/user
path). The existing **`--inventory-disable`** flag is the collection toggle and
covers `device_ci` at the same gate as the other sources (it gates the whole
daily-sync thread).

**DPIA status update (gov Gate 6 compliance-officer, PR2).** The line above
originally scoped the DPIA/Workstream-E entry as a "pre-correlation-PR assurance
item" — written when this data was store-only (central Postgres, no operator
surface). That framing is now stale: the `/inventory` Devices tab CI columns +
per-device CI panel (PR2 of this ladder; now the Hardware CI list/record — the
`/inventory` Devices-tab fragments were removed) make serial/system_uuid/primary_mac
**operator-visible** for the first time, which is a co-determination trigger
point distinct from mere central storage (works-council review is about
monitoring *capability becoming exercised*, not just data existing in a DB).
The interim posture — already-permissioned operators, management-group scoped,
audited via the behavioural-PII tier (`emit_behavioral_audit`) — is a
defensible control pending the DPIA, not a reason to withhold the read surface.
But the DPIA / Workstream-E data-inventory entry for centralizing
serial/UUID/MAC is now an **outstanding item that applies to a live,
operator-visible surface**, not a future-tense placeholder — track it as a
dated, owned issue (see the SOC2 Workstream E data-inventory doc) rather than
leaving it as prose here.

**Binding requirement for a future CMDB-correlation PR (unscheduled) — do NOT
correlate on `"unknown"`.** (Note: the ladder's actual "PR2" — the `/inventory`
Devices tab CI columns + per-device CI panel, now the Hardware CI list/record — is
dashboard-**read**-only; it joins purely on `agent_id` and does not implement CMDB correlation/merge, so this
requirement does not apply to it and remains open for whichever future PR adds
cross-device correlation.) When the platform identity subsystem is unavailable, or
a host genuinely has no SMBIOS serial (many VMs; Linux without the capability),
`serial`/`system_uuid` are the literal `"unknown"`. The PR1 collect skips a cycle
only when manufacturer AND model are both `"unknown"` (a wholesale WMI/DMI outage —
`core_identity_unavailable`), which prevents a transient blip from overwriting a
good row and flapping the hash; but a serial-less VM with real manufacturer/model
is persisted with `serial="unknown"` by design. **A future CMDB correlation/merge
feature MUST treat `serial=="unknown"` / `system_uuid=="unknown"` as ABSENT and
never merge distinct devices on it** (otherwise every WMI-down or serial-less host
collapses into one CI). The store keys on `agent_id`, so there is no PR1
collision — this is purely a future correlation-feature concern. Also note
**macOS `IOPlatformUUID` ≠ the SMBIOS UUID** reported on Windows/Linux, so
cross-OS correlation by UUID will miss.

**Known inherited property (forward).** The content hash covers the field *set*,
so a mixed-version rollout (an agent that adds/removes a field vs an older server)
round-trips to a different hash → continuous `need_full` until both sides match.
This is identical to `installed_software` and is a **framework-wide** trait;
hashing the raw received blob bytes instead of the re-serialized record would
neutralize it (and the multi-copy scrub/clamp drift surface) but must be done for
**all** sources together, not `device_ci` alone — tracked as a follow-up. The
agent↔server scrub/clamp byte-equality is locked by a clean **and dirty** cross-pin
test today. A 1-byte blob format-version prefix is the other future-proofing option.

The `yuzu_inventory_stale_agents` freshness gauge is **not** yet extended to
`device_ci` (it reads `SoftwareInventoryStore::count_stale_agents` only); the
#1685 server-stamped `last_seen` is in place but its gauge consumer is a deferred
follow-up (same as `app_perf`).

### 2026-07-02 — blob contract v2: package-manager fields on `installed_software`

The `installed_software` wire blob grows from 4 to **12 fields** per record, in
this exact order (append-only; 0x1F between fields, 0x1E terminating a record):

```
name, version, publisher, install_date,
kind, ecosystem, epoch, release, arch, signature_status, distro_id, distro_version
```

Motivation: the server-authoritative vulnerability-matching direction (ADR-0018)
needs full EVR (`epoch:version-release`) + `arch` + the host's distro release for
Lane-1 OVAL matching, and an honest `kind=app` discriminator for the Lane-3
OS-native tail. The population contract is **honest-empty**: a field the
ecosystem does not store is `''`, never synthesised, except `publisher`, which carries a
vendor or a `via:` label (the section "2026-11-04 — `installed_software`: a publisher on every
row, and the `via:` origin label" below states the rule). Per source: rpm = full NEVRA + VENDOR, else
PACKAGER, + stored-tag signature status; deb = NEVRA + Maintainer + arch, installed AND
held; apk = name/version/pkgrel; pacman = name/EVR; Windows/macOS = `kind=app`
with name/version/publisher only; `distro_id`/`distro_version` from
`/etc/os-release` stamped on every Linux row; `homebrew` is a reserved
ecosystem value, not collected. `version` is the upstream version with the
release/revision split into its own field, and rpm `publisher` is the `VENDOR` tag,
else the `PACKAGER` tag.

> **Update (2026-10-04, #5328):** `homebrew` was never emitted as an ecosystem
> value and is retired. Homebrew (ecosystem `brew`; kind `pkg` for formulae, `app`
> for casks) and Windows optional features (ecosystem `optional_feature`, kind
> `feat`) are collected since #5335.

> **Update (2026-10-14):** `pkg_inventory.store_packages` is collected as
> ecosystems `snap` (kind `app` or `pkg`; version from the mounted revision's
> `snap.yaml`; release = the revision) and `flatpak` (kind `app` or `pkg`;
> version empty, a branch being a ref; release = the commit), active rows only;
> snap/flatpak rows carry no distro fields.

> **Update (2026-10-17):** `msi_packages.list_inventory` is collected as
> ecosystem `msi`, kind `pkg`, with `package_id` set to the MSI product code
> exactly as registered (Windows machine install context only; per-user products
> are never listed by this source). Name, version and publisher come from
> `InstalledProductName`/`VersionString`/`Publisher`. The product code travels in
> the blob's extended-tail `package_id` field (the tail appended after the twelve
> v2 fields); the tail's first two slots, `install_location` and
> `uninstall_string`, stay reserved and empty (#5186). A `constrained`
> enumeration, or a product-property read that fails for any reason other than
> the product not having the property, fails the action and skips the whole
> cycle, like `pkg_inventory.packages`. The same product also appears as an
> `installed_apps` `app`/`windows` row; the two are not de-duplicated.

> **Update (2026-10-29):** `middleware.ibm_mq` is collected as ecosystem `ibm_mq`,
> kind `app`. Name, publisher and kind come from the `middleware` plugin's product
> table, never from the row; `version` is VRM (version.release.modification), the
> fix-pack level not being visible in the installer metadata the agent reads.
> The collector row sets `ConstrainedPolicy::drop_source`, a per-row policy and the
> exception to the norm above that a source which cannot answer skips the cycle: a
> `constrained` answer contributes zero rows and the cycle continues with every
> other source. Because the cycle's aggregate replaces the agent's stored
> inventory, that source's stored rows are removed server-side by the replace until
> it answers again, and the server sees no signal (`skip_reason` stays empty; the
> agent logs one warn line). The policy exists for a steady-state constraint that
> is a permission fact, where skipping the cycle would freeze every other source
> for ever.

> **Update (2026-11-04):** the `pkg_inventory` Windows legs are collected as three
> ecosystems, all machine scope: `appx` (kind `app`; the packages registered for
> all users in the `AppxAllUserStore` `Applications` and `InboxApplications`
> registry keys; name is the package name, version and arch come from the package
> full name, release empty; a package in the `Deprovisioned` key is read but never
> collected), `chocolatey` (kind `pkg`; one row per `lib\<id>` directory holding a
> loose nuspec, version from its `<version>`, empty if unreadable) and `winget`
> (kind `app`; a presence row from the `managers` action, present when the App
> Installer package is registered, version from that package). Chocolatey's own
> presence row has an empty version. No process is spawned and nothing is hashed;
> the `ConstrainedPolicy` of the three actions is unchanged, so a constrained
> `packages` or `store_packages` answer still skips the cycle, which is why a
> per-item shortfall (an unreadable nuspec, an unparsable package name) degrades its
> own row to an empty version instead of constraining the action. The three values
> are appended at the tail of the published ecosystem enumeration. The tail
> `install_location` slot stays reserved and empty.

Mechanics:

- The fields ride **inside** the `plugin_data["installed_software"]` blob — no
  proto change, no gateway pb regen (§6 applies only to outer-envelope fields).
- Collection is a new `installed_apps` action **`list_inventory`** (13-token
  `inv|` rows); the operator-facing `list`/`query`/`list_per_user` output is a
  stable contract whose fields this ADR left byte-unchanged (rpm `list` keeps
  VENDOR). On Windows, `get_installed_apps_windows()` feeds `list` and `query`, and
  the hashed `inv|` rows come from the registry walk
  (`reg_walk::collect_uninstall_apps`), so a change to either must be checked
  against the hashed rows. *Amended 2026-10-06:* the hashed rows moved off
  `get_installed_apps_windows()` onto the registry walk. *Amended 2026-09-21:* `list` gained two trailing columns
  (`install_location`, `bundle_id`) under ADR-0028's binding condition. Its
  `app` tag, `name`, `version`, `publisher` and `install_date` keep their
  position and value for every real value; every `list` field is now
  escape-aware (`\`→`/`, `|`→`\|`, CR/LF→space, 4 KiB cut) — `list` rows are
  never hashed. On macOS, the collector `list`/`query`/`list_per_user` share now
  sorts same-named apps by (name, `install_location`) instead of an arbitrary
  order; their row shape is otherwise unchanged. The `inv|` rows are unchanged
  for real Location values (a relative or control-byte Location, which only a
  hostile bundle produces, is now ignored rather than feeding the #2273
  enrichment): the Windows name+version dedupe (`dedupe_uninstall_records`)
  keeps the same survivor as before and sets that survivor's `install_location`
  to the lexicographically smallest populated location in its run. Data
  classification: `install_location` is
  operator-tier — an ordinary stored Response (90-day default retention, no
  per-subject erasure, not covered by `--inventory-disable`), never in this
  v2 blob — and can name an account's home directory
  (`/Users/<account>/...`, `C:/Users/<name>/...`). §8's finding — that the
  sync neither crawls a logged-in user's hive nor `~/Applications` — is about
  the sync and the Windows `HKCU` path specifically; it does not extend to
  `list`: on macOS the shared `system_profiler` scan `list`/`list_inventory`
  both run CAN list entries under `/Users/<account>/Applications` (4 of the
  323 rows in the committed macOS sample), so `list` may name a home
  directory. §8's classification was re-opened for the server store of blob v3
  (the 2026-11-04 Update, "Slot 13 is stored on v3 only"); the change that
  starts SENDING slot 13 (ADR-0028) must honour its outcome before an agent
  emits it. `list`/`list_inventory` keep their
  `Inventory:Read`/`ExecuteGate::None` tier; `list_per_user`'s AdminOrApproval
  gate exists for profile enumeration, which `list` does not do (CC6.3
  decision recorded here).
- Store: migration v5 adds the 8 columns as `TEXT NOT NULL DEFAULT ''`
  (metadata-only on PG11+). REST/MCP rows carry all 12 fields.
- Caps: unchanged (`kMaxEntries` 20k, `kMaxFieldLen` 1024, `kMaxBlobBytes`
  3 MiB — a 20k-row v2 blob is ~2.8 MB, still under the 4 MiB gRPC ceiling).
  The sync source passes a per-call **3.5 MiB** capture cap to
  `LocalDispatcher` (the shared 2 MiB default would silently truncate — and
  therefore cycle-skip — hosts above ~14k packages).
- **One-time rekey herd (expected):** the hash reformats even when every new
  field is empty, so each upgraded agent's first v2 report mismatches its stored
  v1 hash → one `need_full` full resend per agent, phase-spread over the ~24 h
  window, self-healing. Mixed-version windows settle into the bounded
  ~2-RPC/day loop described in the "Known inherited property" paragraph above —
  this change deliberately does NOT add a one-source compat hash; the raw-blob
  hash / 1-byte format-version prefix remain the framework-wide follow-up.
- The v1→v2 parse compatibility (a 4-field record reads with fields 5–12 empty)
  is pinned by tests on both sides, as is the identical 12-field cross-pin hash.
- **Deploy order: server before agents.** The server accepts both v1 and v2
  wire blobs from the moment it's deployed, so a new agent against an old
  server is possible but not the intended path — it degrades gracefully (the
  old server's 4-field parser drops fields 5-12, same bounded loop as any
  other mixed-version window). Deploying the server first means every agent
  upgrade lands against a server that already understands v2.
- **PII scope note.** §8's "no end-user PII, no works-council trigger" finding
  is about the *monitored device's* end user — it is unaffected by v2. It does
  NOT extend to third-party package-maintainer metadata: the deb `Maintainer`
  tag (unchanged from v1) and the rpm `PACKAGER`/`VENDOR` tags can, per upstream
  packaging convention, carry an individual maintainer's real name + email
  (common on community/COPR-built packages) — that is third-party data-subject
  data, not the monitored end-user's, and is out of scope for the
  co-determination analysis above. `distro_id`/`distro_version` add no new

### 2026-09-17 — source `app_usage` (machine-scope usage evidence) CATASTROPHIC clauses

A new sync source, **`app_usage`**, ships the agent-side `app_usage` plugin's
`last_used` projection to the server once a day. Its own plugin README and the
header banner in `agents/plugins/app_usage/src/app_usage_parsers.hpp` are the
per-file contracts; this entry is the routed-concerns.md pointer's full text
(kept here, not duplicated inline in that file, to stay under its per-file
character budget — see `docs/instruction-file-standard.md`'s placement
ladder). The plugin reads Echo's `usage` fold read-only (`PRAGMA query_only`,
`SQLITE_OPEN_READONLY`) — it never writes `echo.db`. Four clauses, all
CATASTROPHIC-IF-VIOLATED:

1. **No pid, command line or user name is ever emitted.** `usage_daily_user`
   contributes only a distinct-user COUNT, never a name. A negative test greps
   the plugin source for the raw process-event table name and `cmdline` and
   must find zero hits.
2. **`exe_key` pipe-escaping is a byte-for-byte contract.** Every emitted row
   pipe-escapes `exe_key` via `yuzu::util::safe_output_field`, and this
   source's `split_pipe` parser only splits on UNESCAPED pipes and unescapes
   the producer's backslash-pipe escape sequence — changing one side without
   the other silently corrupts or drops rows whose executable name contains a
   delimiter character.
3. **An `echo_config` read failure must map to `Errored`, never `Enabled`.**
   `source_state_from_config`'s tri-state (Enabled/Disabled/Errored) mirrors
   Echo's own `canonical_source_enabled` #560 fix; defaulting a read failure to
   `Enabled` is the opposite of fail-closed.
4. **Never send an empty blob for a constrained capture.** Skip the sync cycle
   instead — an empty blob reads server-side as "genuinely zero usage" on a
   host that is actually constrained or disabled, which is a false negative a
   downstream consumer cannot distinguish from real data.
  exposure (already derivable from the existing `os_info` source).

### 2026-10-29 — `device_ci` blob v2 (store and ingest)

The server now accepts and stores a versioned `device_ci` blob. This entry is the
binding wire contract for the agent-side writer change and records the store-side
rules. **Server-first rollout:** a v1 server cannot read a v2 blob (it would
store `\x02` + the manufacturer and nack every cycle), so every serving replica upgrades
before any agent emits v2; the agent-side change may additionally gate emission on an
ack-advertised capability. No proto change.

**Layout.** `blob := 0x02 scalar_record list_record*`; every record is 0x1F-separated
and 0x1E-terminated. A blob whose first byte is not `0x02` parses exactly as before (v1).

| Part | Contents |
|---|---|
| `scalar_record` | positions 0-21 = the frozen v1 fields (unchanged order); positions 22-32 appended: `chassis_type`, `chassis_serial`, `chassis_asset_tag`, `chassis_source`, `board_vendor`, `board_product`, `board_serial`, `board_source`, `machine_id_hash`, `machine_id_algorithm`, `machine_id_source`. Missing trailing positions stay blank; extras are ignored. |
| status record | `status` 1F `<section>` 1F `<level>` 1F `<reason>` — one per registered section, including the three status-only ones (`chassis`, `baseboard`, `machine_id`, whose values are the appended scalars). Last wins. An unregistered section is ignored. |
| list row | `<kind>` 1F `<c1>` ... `<cn>` — columns per kind below. A short row is padded blank, extra fields are ignored, an unknown kind is ignored. Each blob's ignored tokens (unknown kinds and sections, the scalar record, status records or kinds that carried extra fields) are named in one debug log line, so version skew is diagnosable. |
| blob ceiling | 96 KiB (98,304 bytes) total, on the server and, equal by contract, on the agent (`kDeviceCiMaxBlobBytes` in `device_ci_kinds.hpp` and in `sync_source_device_ci.hpp`; the two binaries share no header, so each side's test pins its own constant to the literal 98304). The v1 agent's cap moves from 64 KiB to 96 KiB with it; that is behaviour-neutral, as its record is about 1 KiB. Derived from the section registry below, not from a transport limit: a p99 large host is about 25 KiB, and every kind at its row cap with a p99.9-wide row sums to about 75 KiB (table below). A conforming sender never reaches the ceiling (see "A host over the caps"). Every field is clamped to 1,024 bytes. |

Section registry (one declaration, `server/core/src/device_ci_kinds.hpp`, shared by the
parser and the store; the agent-side v2 writer MUST apply the same caps). The row budget is the
declared p99.9 row width in wire bytes (kind token, separators and the record terminator
included): a budget, not a bound. The 1,024-byte field clamp bounds each field and the
ceiling bounds the blob.

| Section / row kind | Columns | Row cap | Row budget (B) | Cap x budget (B) |
|---|---|---|---|---|
| `chassis`, `baseboard`, `machine_id` | status only | n/a | n/a | n/a |
| `cpu` | idx, model, cores, threads, clock_mhz, socket_designation, stepping | 32 | 96 | 3,072 |
| `dimm` | slot, size_mb, type, speed_mhz, manufacturer, part_number, serial | 64 | 96 | 6,144 |
| `disk` | idx, model, size_gb, media_type, interface | 128 | 64 | 8,192 |
| `swap` | device, total_mb, source | 16 | 56 | 896 |
| `volume` | volume, mount_points, device, fstype, total_bytes, detail | 128 | 144 | 18,432 |
| `partition` | disk, partition, size_bytes, type, mount_points, detail | 192 | 120 | 23,040 |
| `topology` | topo_kind, name, uuid, members, detail | 96 | 144 | 13,824 |
| rows subtotal | | | | 73,600 |
| scalar record + status records | declared budget | | | 3,072 |
| registry-derived total | 74.9 KiB, 78.0% of the 98,304-byte ceiling | | | 76,672 |

A `static_assert` in `device_ci_kinds.hpp` holds that total to at most 80% of the ceiling, so
changing a cap or a budget fails the build until the ceiling is reconsidered on both the server
and the agent. A second `static_assert` keeps every row budget between the shortest possible row
and the clamp-bound row, and at or above the measured width recorded beside it (`row_floor`), so
a budget cannot be cut below a width actually observed to dodge the 80% line.

The `partition` and `topology` budgets are assumed widths: no Linux or macOS captures exist yet
(a Windows `partition` capture does: 76 to 85 wire bytes against the 95 floor, 2026-11-04), so they
are re-measured when the storage legs land (`swap` has no capture either, its legs being planned, and
its floor is its shortest possible row). `topology`'s cap is 96, not the 192 starting target,
because 192 x 144 B would put the registry-derived total past the 80% line.

**A host over the caps (sender contract).** The agent v2 writer implements this contract (see
the 2026-11-01 entry below). The sender keeps the first N rows of each kind (N = the kind's row
cap) in a fixed sorted order, so the blob and its hash are stable day to day, and marks the
section `constrained` with kept-of-total counts in its reason (a token distinct from the
server's own `server_cap:<cap>`). If the blob would still exceed the ceiling it trims whole
sections' tail rows, least valuable first: `topology`, `partition`, `volume`, `dimm`, `disk`,
`cpu`, `swap` (swap last; see the 2026-11-01 entry), each trimmed section staying `constrained`
with its kept-of-total. The scalar record and
the per-section status records are never trimmed (together about 2-3 KiB, budgeted at 3 KiB), so
a record always fits and the base fields always land. Trimmed rows are not stored: the daily
record is a bounded summary, the live actions return the full data, and the daily record keeps
no history. Any later report or search over these tables must present a `constrained` host as
incomplete, not as one with fewer rows. The server drops and nacks `need_full` a blob over the
ceiling as a backstop for a non-conforming sender only (its base fields then never land); each
such drop writes one warn log line (`device_ci: oversized blob from agent=...`) and counts
`yuzu_inventory_ingest_total{source="device_ci",outcome="dropped"}`.

**Plugin-action to section mapping (agent-side writer obligation).** The section identifier on
the wire is always the row-kind token, never the plugin action name: `chassis`->`chassis`,
`baseboard`->`baseboard`, `machine_id`->`machine_id`, `swap`->`swap`, `volumes`->`volume`,
`partitions`->`partition`, `topology`->`topology`. `partitions`->`partition` is the one
rename. Fibre Channel and iSCSI tables are deferred: no column contract exists yet, so
they land as an additive store migration with their own PR.

**`swap.used_mb` is excluded** from the daily row — it is volatile telemetry that changes
every cycle, the same hash-stability rule as the 2026-06-30 entry. The on-demand action
still reports it.

**Truncation is disclosed, not silent.** Rows past a kind's cap are dropped and the
section is persisted with level `constrained` and reason `server_cap:<cap>` (appended with
`;` after a non-empty incoming reason), so a hash-only acknowledgement of an unchanged blob
never presents a bounded projection as complete.

**The machine ID ships only as a hash.** `machine_id_hash` must be lower-case hex (any
length — the algorithm is open) or `-` when absent. Any other value, such as a raw
GUID or `IOPlatformUUID`, is blanked and the `machine_id` section is persisted `constrained`
with reason `server:machine_id_shape` (appended with `;` after a non-empty incoming reason),
through the same disclosure path as the row caps. The limit is stated plainly: this rejects
UUID/GUID shapes but cannot detect a raw hex id such as `/etc/machine-id`.

**Hash, per version.** v1 keeps the positional 22-field join byte-for-byte (the v1
cross-pin constants are untouched), so an old agent never loops on `need_full`. v2's
canonical hash is the sha256 of the received blob bytes, set by the parser: the agent's
canonical bytes are the blob, so the server carries no re-serialisation to drift (a
cap or clamp mismatch would otherwise store the server's bounded view and storm
`need_full`). The "raw-byte hashing must be done for all sources together" note above
concerns changing v1 semantics and does not apply to a new format. A digest failure yields
a v2 record with an empty hash; the store refuses it (`kError`, nack `need_full`) rather
than store under a placeholder. A v1 agent whose manufacturer begins with byte `0x02` is
read as v2. Its blob is its canonical bytes, so the server's sha256 of the received bytes
equals the hash the agent claims and there is no `need_full` loop. The record is stored as v2
with no sections and blank appended scalars, and the manufacturer loses that leading byte (it
was taken for the version byte). The next cycle's hash-only report matches and is touched, so
the record does not self-heal until the value changes or the agent emits v2. This is not a
real DMI/WMI value.

**Store.** Migration 2 is additive: `blob_version` plus the 11 scalars on `device_ci`, a
`device_ci_section` status table and one typed table per list kind, each referencing
`device_ci` with `ON DELETE CASCADE` (so decommission stays one `DELETE`). A full payload
of either version replaces the parent row and every child row in ONE transaction under a
per-agent advisory lock (key prefixed `device_ci:` so it never collides with the software
store's per-agent lock); any failure rolls back with the previous set intact and nacks
`need_full`. A v1 full replaces the child set with the empty set. The sections read runs in
one REPEATABLE READ transaction so a replacement committing mid-read cannot mix generations.

**Rollback.** Do not run an older server after migration 2. An older server keeps working
on the migrated database (the new columns default blank and the child tables cascade), but its
v1 full neither rewrites the v2 columns nor deletes the child rows. If you must, expect stale
chassis, board and machine-id values and stale child rows to be served as current until each
agent's next full report on the upgraded server.

**Personal data.** `chassis_serial`, `board_serial` and the DIMM `serial` column join the
serial/UUID/MAC behavioural-PII tier. The `volume` and `partition` mount-point column can name an
account or a personal label as the OS reports it, so the agent redacts such entries before sending
(2026-11-01 entry, "Mount points (personal data)"). As of the 2026-11-04 entry at the end of this
file (H.7), the sections are served on REST and MCP behind the audited `inventory.device.ci` read.

### 2026-11-01 — `device_ci` blob v2 (agent writer)

The agent now emits the v2 record defined in the 2026-10-29 entry. This entry records
what the writer does and the order in which a fresh deployment brings its components up.

**v2 is emitted unconditionally.** There is no capability negotiation and no agent-side
fallback flag; this supersedes the 2026-10-29 sentence that the agent change "may
additionally gate emission on an ack-advertised capability". The class "a host that cannot
produce v2" is empty by construction: an older hardware plugin (`unknown action`, rc 1), a
missing `disk_actions` plugin and every planned leg each become a typed section status, so the
22 base fields always land. The v1 writer is unchanged and stays byte-pinned; the v2 scalar
record is the same clamp-join over 33 fields, and its first 22 fields equal the v1 blob.

**Independent optional sections.** The 15 original actions keep abort-on-failure (a failed
required action skips the cycle). The seven added with v2 (`chassis`, `baseboard`, `swap`,
`machine_id`, and `disk_actions` `volumes`, `partitions`, `topology`) never abort it. All ten
section-bearing actions, including the three that already existed (`processors`, `memory`,
`disks`), map to a section status from the ABI4 typed result:

| Source | Level | Reason |
|---|---|---|
| typed OK or undeclared | `ok` | typed provenance, else the plugin's own status-row token (`-` is empty), else empty |
| typed CONSTRAINED | `constrained` | same |
| typed UNAVAILABLE | `unavailable` | same (a planned leg reads `<os>:planned`) |
| typed PERMISSION_DENIED | `permission_denied` | same |
| rc != 0 | `unavailable` | `agent:action_absent` when the output starts `unknown action`, else `agent:rc=<n>` |
| capture truncated | `unavailable` | `agent:truncated` |
| `disk_actions` not loaded | `unavailable` | `agent:plugin_not_loaded` |
| Windows `volumes` | `unavailable` | `agent:windows_volumes_unbounded` (the action is not run; see below) |
| a mount point was redacted | `constrained` | `agent:mount_points_redacted`, placed before any plugin reason |

**No rows from a failed section.** A section whose level is `unavailable` or
`permission_denied` carries its status record and no rows, and its appended scalar positions
stay blank. Nothing from a failed, truncated, absent or refused capture is projected, and the
cap token below can never promote such a section to `constrained`.

**Mount points (personal data).** The `volume` and `partition` mount-point column is forwarded as
the OS reports it, so a volume folder-mounted under a user profile (`C:\Users\<name>\...`,
`/Users/<name>/...`) or an APFS volume mounted at `/Volumes/<label>` would put an account name or
a personal label into a record stored centrally on every cycle. The statement "machine-scope (no
username/SID/user path)" in the data-classification paragraph above therefore holds for this column
only because the writer minimises it: before the blob is built, every entry that lies under
`/Users`, `/home`, `/Documents and Settings` or `/Volumes` is replaced with `[redacted]`. The match
ignores case, reads `\` as `/`, ignores a leading drive letter and looks through a
`/System/Volumes/Data` prefix, which macOS can use to spell the firmlinked user tree. The boot volume's label is user-chosen, so every
`/Volumes` entry goes. A piece that is not a path (the tail of a label that held a comma) is
replaced with it. A section in which any entry was replaced is `constrained` with
`agent:mount_points_redacted`, placed before any plugin reason so the reason clamp cannot drop it.
Drive letters, `/`, the `/System/Volumes/*` volumes themselves and any other folder mount pass
through as the OS reported them, so the column can still name a folder an administrator chose; it is
minimised, not proven free of names. Not covered by this paragraph: those other folder mounts; the
user-chosen roots the Linux legs will report once they emit mount points (`/media/<user>`,
`/run/media/<user>`), which the leg that adds them must add to the roots table and to this paragraph;
free text in the other columns once a leg fills them with user-chosen labels; and the v1 `hostname`,
`domain` and `ou` fields, which name a machine and are frozen. Redaction removes one route to a personal
name. It does not change the stable-identifier capability (serial, UUID, MAC, chassis, board) that makes
works-council review applicable, and it is not a consent mechanism: `--inventory-disable` remains the only
control over the collection. The serial, board-serial and DIMM-serial columns of the 2026-10-29 "Personal data" paragraph
are unchanged.

**Windows `volumes` is not run.** The Windows `volumes` leg issues synchronous `DeviceIoControl`
calls on handles opened without a deadline (`disk_actions_win.cpp`, "BOUNDING"). The daily sync runs
on the thread the agent joins on reconnect and on shutdown, so one wedged drive would leave the
endpoint unable to reconnect or to stop cleanly. Until those calls have a bound, the Windows writer
does not run the action: the `volume` section is `unavailable` with `agent:windows_volumes_unbounded`
and carries no rows. The operator-triggered `volumes` action is unchanged. The Windows
`partitions` leg reads `Win32_DiskPartition` and `Win32_LogicalDiskToPartition`, and cross-checks the
drive letters against `Win32_LogicalDisk`, through the bounded WMI helper (`agents/shared/wmi_bounded.hpp`, per-call deadlines), so it runs on the sync thread; only
Windows `topology` is status-only (`windows:planned`). No other section is affected. The Windows volume rows return when the platform gap named in `disk_actions_win.cpp` (plugin OS
calls have no deadline, #3925) is closed. The reason is expected on every Windows host and needs no
operator action; the operator-triggered `volumes` action still works there.

**Pipes inside a field.** The plugins write a literal `|` as `\|` and fold a literal `\` to `/`
(`safe_output_field`). The writer splits the list rows and the three scalar groups on an unescaped
pipe and unescapes before the clamp, so a pipe in a label or a firmware string stays in its field and
moves no later column. The 22 v1 positions keep the raw split: their bytes are frozen.

**Caps and the reserved reason slot.** Rows are projected to the wire columns, sorted
lexicographically on the wire row (so the blob and its hash do not depend on the plugin's
emission order), and the first N are kept (N = the kind's row cap, equal to the server's). A
section over its cap is `constrained` with ONE token, `agent_cap:<kept>/<total>`, appended to the
reason after `;` when a reason exists. The base reason is clamped to the field clamp minus the
token's maximum width, so the composed reason always fits the 1,024-byte field contract and the
server's clamp cannot cut the disclosure. A later ceiling trim replaces the token; a record never
carries two. The token is distinct from the server's own `server_cap:<n>`. `swap` drops
`used_mb` (volatile); the hardware disk sentinel row and the `disk_actions` volume
placeholder (volume name `-`) are not rows.

**Ceiling trim.** If the blob still exceeds the 96 KiB ceiling, tail rows are popped kind by
kind in the order `topology`, `partition`, `volume`, `dimm`, `disk`, `cpu`, `swap`, each trimmed
kind `constrained` with its final kept-of-total. This clarifies the six-kind order recorded
above: `swap` is appended last so the sender's termination proof holds for every registered
row-bearing kind (the scalar record and status records are never trimmed, and their clamp-bound
worst case is `static_assert`ed under the ceiling on both sides). In practice the earlier kinds
absorb any realistic overflow first, so `swap` is a defensive tail.

**Component order in a fresh deployment.** The server of this build is brought up before agents of
the same build enroll, and every replica is on that build. The deployment contract (a fresh
database, every writer on this build; `docs/user-manual/upgrading.md`, "Deployment contract (hard
cutover)") excludes an earlier server, so this entry states no behaviour of an agent against one.

### 2026-11-04 — `installed_software` blob v3 (sections) and schema v10: store and ingest

This entry records the server half: the v3 wire grammar the ingest seam accepts, the store
columns and tables it fills, and the rules the agent writer (a later change) must reproduce
byte for byte. The v2 path is unchanged and still owns every blob that does not start with the
v3 header. No shipped agent sends v3 yet.

**Wire (same `plugin_data` and `content_hashes` key, `installed_software`).** Record 0 is the
header `0x1F "v3" 0x1E`: an empty first field, which the v2 parser drops (it ignores a record
with an empty name), so no v2 record can collide with it. A blob that does not start with exactly
those four bytes is v2, including a v2 blob whose first product is named `v3`. After the header
every record is `0x1E`-terminated with `0x1F`-separated fields, and the first field is the record
kind:

| Record | Fields after the kind | Meaning |
|---|---|---|
| `S` | `facet`, `status`, `base`, `token`, `duration_ms`, `bytes_read`, `expect` | opens a section; `expect` is the section hash after the agent applies it (64 lowercase hex, mandatory on `delta`, see the SAM-14 entry below) |
| `+` | `name`, `version`, `publisher`, `install_date`, `kind`, `ecosystem`, `epoch`, `release`, `arch`, `signature_status`, `distro_id`, `distro_version`, `install_location`, *slot 14 (reserved, empty)*, `package_id`, `source` | an install row |
| `-` | `row_hash` | a deletion by row hash (64 lowercase hex); applied by the SAM-14 delta apply below |
| `comp` | `kind`, `name`, `version`, `version_source`, `path`, `size`, `mtime`, `anchor_app` | a component row; `version_source` is one of `filename`, `pom`, `manifest`, `metadata`, `package_json`, `pe`, `elf`, `macho`, `unreadable`; stored by the SAM-14 component store below |

`facet` is a `kSoftwareSources` value (the collector source) or `component_inventory`, 1 to 64
characters of `[a-z0-9_.]`. `status` is `full`, `delta`, `constrained`, `timeout`, `oversize`,
`not_collected` or `disabled`; only `full` and `delta` sections carry records. `duration_ms` and
`bytes_read` are agent-reported diagnostics: anything that is not plain digits reads as 0. Every
field passes the v2 field step: scrub to valid UTF-8 first (U+FFFD for each invalid byte), then
clamp to 1,024 bytes on a codepoint boundary. A `+` row's `source` must equal its section's
`facet`. Caps bound the retained records per call: 3 MiB of blob (unchanged), 32 sections, 20,000 `+` rows, 20,000 `-`
records, 20,000 `comp` records. A refused section gives its records back, so a call can parse more than
20,000 in total; the 3 MiB and 32-section caps still bound the work, and refused rows never reach Postgres.

**Every record is terminated, the last one too.** A blob whose final record lacks its `0x1E` was
cut off: a truncated row refuses the section it sits in (`unterminated`; the complete rows
before it in that section are not applied alone), and a truncated `S` record or one before any
section cannot be attributed to a facet, so it fails the whole blob. The agent writer terminates
every record.

**No NUL byte in any record.** A record that holds a `0x00` byte refuses the section it is in
(`nul_byte`). NUL is valid UTF-8, so the field scrub would keep it, and both hashes (the section
hash and `instance_key`) would be taken over it; but the text bound to Postgres cannot carry a
NUL, so the stored row would read without it while its keys were computed with it. Two rows
(`AB` and `A\0B`) would then be stored identically under different keys, and the stored section
hash could not be reproduced from the stored rows. The refusal is a v3 grammar rule, and the
writer contract: **the agent writer must never emit a NUL byte in any field of any record.** The
v2 parser is unchanged.

**Containment.** A grammar violation inside a section refuses that section only: a `+`, `-` or
`comp` record in a status-only section; a `-` record in a `full` section; a `+` source other
than the facet; `+` in `component_inventory` or `comp` anywhere else; an unknown status, facet or
record kind; a malformed row hash; an unknown `version_source`; a repeated facet; a row over the
per-call cap; a record holding a NUL byte; a final record with no terminator. The rest of a refused section is skipped to the next `S`, and the other sections
still apply. A defect that cannot be attributed to a facet fails the whole blob (a record before
any section, a header with no section after it, an `S` record whose facet is empty or outside
the charset, more than 32 sections, over 3 MiB): the ingest seam answers the whole-source `installed_software` nack and counts
`dropped`, like an over-cap v2 blob.

**Nack form.** `InventoryAck.need_full` is a `repeated string`, so the per-section nack is
`installed_software:<facet>` with no proto change. The whole-source `installed_software` stays
the nack for a hash-only claim the server cannot match and for an unattributable v3 blob.

**Section hash.** `canonical_section_hash(rows)` is the SHA-256 hex of the section's rows,
sorted and de-duplicated, each written as all 16 wire slots (slot 14 empty, and no conditional
tail: unlike the v2 hash, `package_id` and `source` are always written), `0x1F`-joined and
`0x1E`-terminated. The sort walks the stored fields in wire order: `name`, `version`,
`publisher`, `install_date`, `kind`, `ecosystem`, `epoch`, `release`, `arch`,
`signature_status`, `distro_id`, `distro_version`, `install_location`, `package_id`, `source`,
byte-wise. An honest-empty `full` section hashes the empty string. The hash is over the
**stored form** of each row: the field step above (scrub to UTF-8, then clamp) has already run,
and the rows are sorted and de-duplicated, so an agent that mirrors it hashes the scrubbed and
clamped fields, never the raw bytes it collected. The pinned vectors are the test cases
`canonical_section_hash is order and duplicate independent, 16 slots always, pinned` and
`v3_report_hash sorts by facet in byte order, carries the v3: prefix, pinned` in
`tests/unit/server/test_software_inventory_store.cpp`; a writer is correct when it reproduces
them.

**Report hash.** The value stored in `inventory_state.content_hash` for a v3 agent, and the value
a v3 agent claims in a hash-only report, is `v3:` followed by the SHA-256 hex of
`facet 0x1F section_hash 0x1E` for every facet the server holds, sorted by facet in byte order.
A facet is held when its `software_facet_state` row has status `full` or `delta` and a
non-empty section hash. It is recomputed from that table after every v3 call, never from the
call's own sections, so a first contact split over several calls converges to the hash a single
call produces. A facet reporting a status-only status (`constrained`, `timeout`, `oversize`,
`not_collected`, `disabled`) is not in the hash until a `full` section confirms it again, though
its rows are kept. The `v3:` prefix means a v2 hash-only claim (plain hex) can never match a v3
state, and the other way round; each side asks for a full report.

**Apply rules** (`apply_installed_software_v3`, one transaction under the same per-agent
advisory lock as the v2 replace):

- *First v3 contact.* If the stored report hash does not start with `v3:` (or there is none),
  every `installed_software` row and every facet state row of the agent is deleted first, so no
  v2 leftover survives. A call that applies nothing (every section refused, or only `delta`
  sections) does not do this.
- *`full`.* Deletes the agent's rows of that facet, inserts the section's rows with their
  derived keys, and upserts the facet state (status, token, recomputed section hash,
  `last_confirmed_at`, duration, bytes). An honest-empty section deletes the facet's rows.
- *Status-only.* Upserts status, token, duration, bytes and `enabled` (false only for
  `disabled`). Rows, the stored section hash and `last_confirmed_at` are left alone.
- *`delta`.* Applied by the SAM-14 rules in the entry below (row-hash `-` / `+` against the held
  rows, verified against the agent's `expect`).
- *`component_inventory`.* Applied by the SAM-14 rules in the entry below: the rows live in
  `software_components`, the section hash is real and joins the report hash.
- *Refused sections.* A refused section is skipped before any write, so its previously held
  rows, facet state and section hash stay as they were, and the report hash still includes that
  held section hash. A facet the agent refuses permanently therefore keeps its old rows and is
  nacked `need_full` on every cycle until the agent is fixed (`YuzuInventorySectionIngestRefused`
  alerts on it); this is by design, not a stuck state to repair on the server.
- *Report state.* `inventory_state` (the report hash and `last_seen`) is written only by a call
  that applied at least one section: a `full`, a status-only, a `component_inventory` or a `delta`
  that verified. A call made up only of refused, need-full and mismatched sections is a nack, not
  a received report: it leaves the hash and `last_seen` alone, and the section the agent sends on
  the resend is what advances them.
- *Failure.* A SQL failure rolls the whole call back and every section in it that was not
  refused is answered `error` and nacked. A v2 full report additionally deletes the agent's
  `software_facet_state` rows, and `delete_agent` deletes them too.

**Slot 13 is stored on v3 only.** `install_location` (wire slot 13) is stored from the v3 `+`
record. The v2 path still parses and discards it, so a v2 row's location is always empty and the
v2 canonical hash is unchanged. Slot 14 (`uninstall_string`) stays reserved on both paths, so
#5186 is closed for slot 13 only.

*§8 outcome for slot 13 (this change re-opens §8 for the server store).* `install_location` is
operator-tier: machine-scope roots only (ADR-0028), but a root can still name an account's home
directory, so it is classified like the `list` column above. It is erased on decommission
(`delete_agent` deletes the rows), and nothing in this change reads it back (no route, tool, page
or log line carries it; the first read-back is the 2026-11-09 lookup surface below, which
re-opens §8 again). The server stores it as sent after the field step, without minimisation,
so **the agent writer must not send per-user paths**: that precondition is owned by the change
that starts sending slot 13, which must also test that no profile path is emitted.
The change ledger (the 2026-11-04 Update, schema v11) keeps a copy for its retention window:
`software_changes.identity_key` carries the lower-cased location as its last segment for 400
days, past the hard delete of the `installed_software` row (`delete_agent` removes the ledger
rows with the device). That is accepted on the writer's requirement not to send per-user paths
(the precondition above), which the server does not enforce, so the copy is expected to name
machine-scope roots only; the writer's no-profile-path test covers the ledger copy as well, and
nothing reads the ledger back.

**`install_type` and `install_scope`.** Both are derived by the server at insert time and are
never on the wire or in either hash. `install_type` is one of `msi`, `installer`, `store`,
`package_manager`, `optional_feature`, `runtime`, `middleware`, `component`, `driver`, or `''`
for a row not yet derived. The source decides it: `installed_apps.list_inventory` → `installer`,
except that a row of ecosystem `deb`, `rpm`, `apk` or `pacman` (the same collector lists the Linux
packages) is `package_manager`, so the same package reads the same with or without a source;
`pkg_inventory.managers` and `pkg_inventory.packages` → `package_manager`;
`pkg_inventory.store_packages` → `store`; `windows_optional_features.list` →
`optional_feature`; `msi_packages.list_inventory` → `msi`; `runtimes.python` → `runtime`;
`middleware.ibm_mq` → `middleware`. A row with an empty source (a pre-tail agent) falls back by
ecosystem: `msi` → `msi`, `optional_feature` → `optional_feature`, `python` → `runtime`,
`ibm_mq` → `middleware`, `snap` and
`flatpak` → `store`, `brew`, `rpm`, `deb`, `apk`, `pacman` → `package_manager`, `windows`, `macos`,
`macos_pkgutil` → `installer`, anything else `''`. `component` and `driver` are reserved for the
component and drivers facets; no source maps to them yet. The table has a compile-time
totality check over `kSoftwareSources`, so a new collector cannot ship without an install type.
The `pkg_inventory.managers` presence row is stored in `installed_software` today, so it is typed
`package_manager` like the packages it manages; it is not exempted by name. `install_scope` is
`machine` or `user`; collection is machine-scope only, so the server writes `machine`.

**`purl`.** A Package URL per row, composed by the server (`purl_compose.hpp`, `compose_purl`)
from fields already on the `+` record and stored in `installed_software.purl`. It is not on the
wire and in neither hash, so the agent and the v2 path are untouched. Only the v3 apply path
sets it: a row from a v2 report carries an empty `purl` until its device's first v3 report (the
`install_location` coexistence rule). It is built to the Package-URL specification (ECMA-427,
Clause 5 and the `alpm`, `apk`, `brew`, `deb`, `rpm` type definitions of the purl-spec
repository) and is `''` wherever the specification registers no type for the ecosystem: a type
is never invented. `purl_type_for` (the title normalisation pack's ecosystem table) is the one
source of the type. Rules common to all types: UTF-8 bytes percent-encoded except
`A-Z a-z 0-9 . - _ ~ :`; qualifier keys sorted, empty values dropped; `''` when the name or the
version is empty, when a required namespace has no source, and when the result would exceed 2048
bytes (never truncated).

| Ecosystem | Result | Notes |
|---|---|---|
| `deb` | `pkg:deb/<distro_id>/<name>@[<epoch>:]<version>[-<revision>]?arch=&distro=` | name lowercased |
| `rpm` | `pkg:rpm/<distro_id>/<name>@<version>[-<release>]?arch=&distro=&epoch=` | name keeps its case; epoch is a qualifier |
| `apk` | `pkg:apk/<distro_id>/<name>@<version>[-r<pkgrel>]?arch=&distro=` | the agent stores pkgrel without apk's `r` |
| `pacman` | `pkg:alpm/<distro_id>/<name>@[<epoch>:]<pkgver>[-<pkgrel>]?arch=` | rolling: no distro qualifier |
| `brew` formula | `pkg:brew/<name>@<version>` | default tap; `@` in a name is `%40` |
| `brew` cask | `pkg:brew/homebrew/cask/<name>@<version>` | the Homebrew presence row gets no purl |
| `windows`, `macos`, `macos_pkgutil`, `msi`, `snap`, `flatpak`, `optional_feature`, `python`, `ibm_mq` | `''` | no registered type; `python` rows are interpreter installs, not PyPI distributions |

The namespace is the lower-cased `/etc/os-release` ID (`distro_id`). `distro` is
`<distro_id>-<distro_version>` and only when both are known. `arch` is the stored architecture
when non-empty, except for `brew`, whose type defines no `arch` qualifier. An index (`installed_software_purl_idx`, a partial btree `WHERE purl <> ''`) and
`SoftwareInventoryStore::find_by_purl` serve exact lookups; no route, tool or page reads the
column yet.

**Keys, and why the uniqueness is not the identity.** Two keys are derived in one place (the
store's `derive_install_keys`) on both insert paths:

- `instance_key` is the SHA-256 hex of the row's single canonical record (the section-hash
  serialisation of that one row). Rows are sorted and de-duplicated before insert, so it is
  unique per agent by construction. It is the value a `-` record names. A partial unique index on
  `(agent_id, instance_key) WHERE instance_key <> ''` enforces it.
- `identity_key` is `norm_key(name, publisher)` (an origin label `via:<ecosystem>` in `publisher` reads
  as no vendor), `0x1F`, `version`, `0x1F`, `arch`, `0x1F`, the
  install location lower-cased with trailing path separators stripped (empty on v2 rows). It is
  stored and **not** unique and not indexed; it is the key a later consolidation step will use.

This deviates from the spec row, which asked for a `UNIQUE (agent_id, identity_key, removed_at)`.
The Update of 2026-10-17 above records that one MSI product is listed by both
`msi_packages.list_inventory` and `installed_apps.list_inventory` and that the two rows are not
de-duplicated. They share an identity, so an identity-keyed unique constraint would reject the
first v10 ingest of every Windows host that has an MSI product. `removed_at` belongs to the
deletion-tracking change and is not added here.

**Migration v10** (`docs/postgres-migration-ladder.md`, `SoftwareInventoryStore` row): six
columns on `installed_software` (`install_type`, `install_scope` default `machine`,
`install_location`, `identity_key`, `instance_key`, `purl`; constant defaults, no rewrite); two CHECK
constraints (`install_type` in the vocabulary above or `''`, `install_scope` in `machine`,
`user`) added `NOT VALID` (`''` is the "not derived" value of `install_type`); the partial unique index
above and the partial btree `installed_software_purl_idx` on `(purl) WHERE purl <> ''`; and the new `software_facet_state (agent_id, facet, status, token, section_hash, enabled,
last_confirmed_at, duration_ms, bytes_read, updated_at)` table, primary key `(agent_id, facet)`.
The index builds are not online: they hold `ACCESS EXCLUSIVE` for their duration, under the same
fresh-database hard-cutover ruling of 2026-10-24 (not v7's basis; see the ladder and the playbook's
recorded-exception register). In a fresh deployment the table is empty, so the
build returns at once; the ladder row keeps the measured build time over a populated table as a
hazard note only.

**Partitioning decision: `installed_software` stays a plain table.** No measurement exists (the
partitioning spike was skipped). Hash-partitioning by `agent_id` needs the non-transactional
migration kind that is not built (`app_perf_daily_store.hpp`, the ladder), would rewrite the
table under `ACCESS EXCLUSIVE` at a size past the v7 ceiling of 2-4M rows, and would turn the one
measured query, the `installed_software_name_idx` seek, into a scan of every partition. The
decision is reversible and is revisited when a measurement exists.

**Observability.** Each section bumps `yuzu_inventory_section_ingest_total{facet,outcome}`
(`outcome`: `stored`, `status_only`, `need_full`, `mismatch`, `rejected`, `error`; `facet`
is a collector source, `component_inventory`, or `unknown`, never the agent's raw string). The
apply is timed under `yuzu_inventory_ingest_duration_seconds{source="installed_software",phase="v3"}`,
and the source-level
`yuzu_inventory_ingest_total` outcome is `stored`, `need_full`, `error` or `dropped`. The
agent-reported per-section duration and bytes live in the facet state row, not in Prometheus
labels.

**Hand-off to the delta apply and the agent writer.** Two facts the next changes must carry.
`instance_key` hashes the row's whole 16-slot record, so adding a slot to that record re-keys
every stored row once, so the agent writer and the server move together on it. The
delta apply and the component store are described in the SAM-14 entry below; the agent writer's golden-vector parity
test must reproduce the section hash, the report hash and the hash membership rule above
byte for byte, including that a facet whose status moves from `full` to a status-only status
(for example `disabled`) leaves the report hash while its rows are kept.

Three further facts belong to the agent change that sends v3. (1) The shipped
`SyncScheduler::apply_ack` (`agents/core/src/sync_scheduler.cpp`) matches `need_full` by the
exact source name, so the per-section token `installed_software:<facet>` reads as a clean sync:
the scheduler must treat any `installed_software:*` token as a nack of the source, or a
refused or delta section is never resent. (2) Sequencing is same-build only: every server
replica of the build is up before the agents of that build enroll, and this ADR records no
behaviour of the record against an earlier server. (3) `ConstrainedPolicy::drop_source` (the 2026-10-29 Update) removes the source's
rows on a constrained read under v2, because the full replace omits them; under v3 the same
read is a status-only section and the rows are kept, so the writer must send `full` (honest
empty) to retire a facet's rows and not a status. The first v3 call of a device that applies a section also deletes
all its v2 rows first, so it should carry `full` for every facet it holds.

**Not in this change.** The agent writer; any read surface returning the new columns (the existing reads select the old columns
only; `find_by_purl` is a store method with no caller).

### 2026-11-04 — sync-now parameters, the installed-software window, and overdue catch-up

This amends the trigger text of section 3 and the `__sync__.now` reserved-command contract. No
proto field is added: both new inputs are entries in the command's existing string `parameters`
map, and the wire, the KV keys and the heartbeat tags are unchanged.

- **`__sync__.now` parameters.** `source` accepts `all`, one name, or a comma-separated list. The
  list is all-or-nothing: any unknown name fails the command (exit 2, naming the valid set) and
  arms nothing. `delay_max_s` is an integer from 0 to 86400; absent or 0 is the immediate path.
  When it is above 0 the agent still forces a full report, but fires it at a stable per-agent
  offset in `[0, delay_max_s)` from the request instead of at once; a source already armed to
  fire sooner keeps the sooner time, so a repeated request never delays it. A malformed or
  out-of-range value fails the command (exit 2); a present but empty value is malformed. The
  existing `stagger_seconds` field stays ignored for `__sync__`. The server sends neither
  `delay_max_s` nor a source list yet, so an operator's sync-now is immediate today.
- **The sender's audit row.** The change that adds the server-side sender records `delay_max_s`
  and the target source list in the dispatch's audit row. The sender and the agent are the same
  build, so it needs no version or capability gate.
- **Installed-software window.** `installed_software` is scheduled inside a nightly window of
  01:00 to 05:00 in the machine's local time, at a stable per-agent moment
  (`fnv1a(agent:window:source)` over the window length, to the second); a source without a window
  fires at a phase offset of its interval. The skip backoff of #5327 is capped at that moment rather than at
  the next phase slot. It governs the regular daily sync only: the first sync after enrolment,
  skip-ladder and `need_full` retries, catch-up and an operator's sync-now can fall outside it.
  The window is a compile-time default carried by the source; there is no channel to change it
  per fleet yet, and a settings push is deferred. "Local" is the machine's own clock and time
  zone: an agent with no zone configured (a container, a VDI image, a service with `TZ` unset)
  runs on UTC and gets 01:00 to 05:00 UTC, which can be working hours where its users are. A
  local time that does not exist (a spring-forward gap) resolves forward, an ambiguous one
  (fall-back) resolves to whichever instant the C library chooses. A machine that is off or
  asleep through its window syncs at its next wake (see catch-up) and then returns to the next
  window. A source's full resend floor (7 days) is checked at its fire time, so across a
  spring-forward change the seventh day's fire is an hour short of it and the full send lands on
  the eighth: the floor is 7 to 8 days. Sources without a window keep the interval and phase-slot cadence.
- **Capacity.** A window concentrates the day's reports. A fleet in one time zone reports
  within four hours rather than across twenty-four: about 70 `ReportInventory` calls a second per
  million agents at the peak, against about 12 for the uniform spread (six times), and zones
  overlap less than a uniform spread would. Hash-skip is unchanged, so most of those calls carry
  a hash only; the blob goes out for a changed source, at the 7 to 8 day floor and for an
  operator-forced sync. The handler takes a per-agent lock and no fleet-wide one, and nothing
  rate-limits it; these figures are arithmetic from the window length, not measurements, and
  pool sizing against them has not been measured.
- **Catch-up.** A persisted `next_fire` more than `kMaxTickSeconds` (15 minutes) in the past,
  which a live agent never has, or more than two days ahead (a clock stepped back, a restored
  VM, a corrupt value: no interval plus window reaches two days), is re-armed to now plus a
  stable offset in `[0, 30 min)`. It is checked on every batch pass, so it covers both a restart
  and a tick that runs long after the previous one (sleep and resume). It changes the schedule
  only: `last_hash` and `force_full` are untouched, so a catch-up sync is hash-only unless the
  source changed. An overdue source is spread rather than fired at once, which is the startup policy section 3
  describes. First-run jitter (10 minutes) is unchanged. After a mass reboot or
  a server outage every overdue agent reports within 30 minutes: about 550 calls a second per
  million agents (eight times the in-window peak). The 30 minute spread is a constant and does
  not scale with the fleet.
- **Forced syncs and outages.** An operator-forced sync is outside catch-up only while its pass
  is current. If the forced pass finds nothing to send or its send fails, `next_fire` stays at
  the request time and the batch pass retries every 30 seconds, but only for 15
  minutes; catch-up then re-arms it to a stable offset in `[0, 30 min)` and the 30 second retries
  resume from there, with `force_full` kept so the sync is still full. The same applies to any
  source whose send keeps failing: during a long outage an agent retries in 15 minute bursts
  separated by a pause of up to 30 minutes.
  A server that comes back is reached within about 30 seconds if the agent is mid-burst and
  otherwise within 30 minutes; a sync-now that failed on first send can arrive up to about
  45 minutes after it was requested (15 minutes to notice, up to 30 of spread).
- **Staleness.** A windowed source's consecutive daily syncs are 24 hours apart, 23 or 25 across
  a clock change, because the moment is fixed in local time; a machine that missed its window
  reports at its next wake. With the 45 minutes above, both stay inside the 48 hour "two missed
  daily cycles" staleness threshold of `docs/user-manual/inventory.md`, and the freshness gauge
  keys on server receipt time, so no freshness expectation is weakened.

### 2026-11-04 — `installed_software` blob v3: delta apply, change ledger, component store, retention (schema v11)

The server applies a verified delta section, records what every applied section changed, stores
the component section, and prunes the ledger, so an agent can be delta-only. Schema v11 adds three
empty tables; nothing existing is rewritten.

**The `expect` field (a contract revision).** The `S` record has a seventh field after
`bytes_read`: `expect`, the section hash the agent holds AFTER applying the section (64 lowercase
hex). A `delta` section without a valid `expect` is refused `bad_record`; a `full` or status-only
section ignores it (the server recomputes a full section's hash from its rows). The field is
mandatory for `delta`, and the agent writer of the same build emits it. Like every other record
field it follows the parse rules above: a record holding a NUL byte refuses its section (`nul_byte`,
which covers the `S` record and so `expect`), and an `S` record cut off before its terminator fails
the whole blob. It is the only per-section check the server has that its apply produced the
agent's row set.

**Delta apply.** Each full or delta section runs inside its own `SAVEPOINT`; a section that does
not verify is rolled back alone and the others of the call still apply.

- The facet must be held with status `full` or `delta` and a section hash equal to the delta's
  `base`; anything else is `need_full` and writes nothing (a facet last reported status-only is
  not a valid base).
- The `-` set is ONE statement: `DELETE ... WHERE agent_id AND source AND instance_key =
  ANY(...) RETURNING ...`. The rows returned must equal the UNIQUE `-` count (an agent may repeat a
  hash); fewer means the agent's base is not what the server holds.
- The `+` rows are inserted with the same batched statement as a full section. A collision on
  `installed_software_instance_idx` is a producer defect, not a fault.
- The facet's rows are re-read and their section hash must equal `expect`.
- Any of these failing is `mismatch`: the savepoint is rolled back, the facet keeps its held rows and hash, and it is
  nacked so the agent resends it in full. A genuine SQL fault still rolls the whole call back.
- A facet that would hold more than the per-call cap (20,000 rows or components) after the apply is
  `mismatch` too: the cap bounds the records one call carries, and this check bounds what deltas
  can accumulate.
- On success the facet state is `delta` with `expect` as its section hash and the report hash is
  recomputed.

**Change ledger (`software_changes`).** Every applied installed-software section (a component
section writes none) writes one row per install, remove
or upgrade, in the same transaction (one `unnest()` statement per section). `observed_at` is the
replica's own server clock in whole seconds (not the database clock) and, with `agent_id`, groups
the rows of one apply call: calls for an agent are serialised by its advisory lock, but two calls
inside the same second share an `observed_at`, so rows are ordered by `change_id` within a group.
A row's identity is its `instance_key`, stored on the ledger row. The rows come from a pure
diff: removed = held-not-new, added = new-not-held, keyed by `instance_key`. A row's version is
the (`epoch`, `version`, `release`) tuple, so a release-only or epoch-only change (a distribution
backport, a Flatpak commit) is an update. Within one identity stem (`identity_key` with its
version segment blanked) both sides are sorted by (tuple, `instance_key`): a removed and an added
row with an EQUAL tuple pair first and write no row (install_date, signature, a location
spelling that normalises equal, or a publisher that normalises equal, which includes one origin
label for another); the rest pair k-th to k-th in tuple order as one
`upgrade(from, to)` each; leftovers are `remove` and `install`. `from_version` and `to_version`
hold `[epoch:]version[-release]`, non-empty parts only (the `:` follows a non-empty epoch, the
`-` joins a release to a non-empty version, so a Flatpak row reads as its commit), in the
existing text columns. A version is compared as written, so a row whose version could not be read
(an empty version, which the collector reports when a Chocolatey package's nuspec cannot be read,
for example when the `lib` directory is a junction) moves to or from a real version as an
`upgrade` with an empty side, provided the row has no epoch or release either. The writer must
also keep the spelling of `arch`, the install location and the vendor stable from one sync to the
next: a row whose `arch`, or whose location beyond ASCII case and trailing separators, or whose
vendor beyond what the vendor normaliser reads as equal, changes is a removal and an install, not
an update. An origin label (`via:<ecosystem>`) reads as no vendor, so one label for another is no
event, while a source that starts or stops declaring a vendor changes the vendor.
**There are no tombstones on `installed_software`**: a removal is a hard
delete plus a `remove` row carrying name, publisher and that version text, so no read needs a
`removed_at` filter.

**Baseline rule.** A `full` section is a BASELINE (rows written, no ledger rows) unless the
server HOLDS the facet's rows. A facet is held when its state has a non-empty section hash, its
status is not `disabled`, and the stored rows hash to that section hash. A baseline is therefore a
device's first contact for the facet (including the first v3 call that applies a section, which
deletes the device's v2 rows), a facet that has received only status-only sections (that creates a
facet state with no hash), a facet switched off and then on (a status-only section over a
`disabled` facet clears its stored hash, so a timeout following the switch-off does not turn the next
full into a diff), and a facet whose stored rows do not hash to its section hash (an out-of-band
delete or a partial-table restore; no product path produces one), which is baselined with a
warning so a missing row is never recorded as a phantom `install`. The warning is the only signal
of that last case: no counter or alert counts it, because no product path produces it. Changes made
while a facet is disabled are never recorded, by design. A held facet's rows are in the table (a
status-only section leaves them in place), so its full section is diffed against them: a timeout
followed by a full carrying an upgrade writes one `upgrade`, and an honest-empty full followed by
a populated one writes the installs.

**Components (`software_components`).** The component table lives in this store's schema, owned
by `SoftwareInventoryStore`, because a component section is applied in the same transaction as
`software_facet_state` and the report hash and ADR-0012 §3 forbids a second store writing across
the schema. Primary key `(agent_id, kind, path_hash)`, `path_hash` = SHA-256 of
the exact path bytes. A component canonical record is `kind US name US version US version_source
US path US size US mtime US anchor_app RS`; a row hash is the SHA-256 of one record (the value a
`-` names); the section hash is the SHA-256 of the records sorted by those fields (size and mtime
numerically) and de-duplicated. A full section deletes the agent's components then inserts
(`first_seen` = the time the row was written); a delta deletes by
`row_hash`, inserts, and verifies `expect`, and does not touch the rows it does not name; every `-`
must name a held row, else the section is a mismatch and rolls back. Freshness
of a delta-maintained facet is `software_facet_state.last_confirmed_at`, not a per-row column.
An honest-empty full
deletes the rows. A repeated `(kind, path)` inside one section is a producer defect: `mismatch`.
That includes two components of one kind with an empty path, and it holds for a `full` section
too: the resend repeats the pair, so the facet is answered `mismatch` on every cycle and none of
it is stored until the writer sends each path once. It does not repair itself.

The component writer is held to the same precondition as slot 13: `path` and `anchor_app` are
stored as sent, the server does not enforce it, so the writer must not send per-user paths.

The facet now carries a real section hash and enters the report hash. A row a delta removes is
hard-deleted with no history row: component change history is out of scope. Components are
current-state, bounded to the per-call cap per device by the post-apply check above, and die with
the device, so they have no prune.

**Retention.** `run_retention_prune_changes` prunes `software_changes` through the shared
clock-guarded helper (all seven parts, `docs/clock-guarded-retention.md` register): 400-day window
in epoch seconds, a missing anchor declines, 50,000 rows per pass, ticked hourly beside the
deployment prune. The rows are stamped by the replica's clock while the cutoff reads Postgres
`now()`: the two clock domains are split, which the 400-day window absorbs (the register records
why). `decommission` (`delete_agent`) removes an agent's ledger and component rows.

**Observability.** `yuzu_software_changes_total{kind}` counts ledger rows by kind (a baseline
counts none); its closed `kind` set (`install`, `remove`, `upgrade`) is created at 0 at boot beside
the section counter's series. `YuzuInventorySectionDeltaMismatch` (warning, `for: 1h`) watches
`outcome="mismatch"`. A device reports about once a day, so a `rate()` over a short window
never holds for an hour; the rule reads `increase(...[1d])` and needs both at least 5 `mismatch`
sections for a facet and more than 5% of that facet's sections. An isolated mismatch (an agent
restored from a snapshot, a report racing a decommission) is expected and does not fire it; the
agent resends the facet in full, which repairs a delta that went out of step; a component section
that repeats a `(kind, path)` does not repair itself (above).

**Not in this change.** The agent writer (it must emit `expect` and mirror the component hashes);
any read surface for the ledger or the components.

### 2026-11-04 — `device_ci` read surface on REST and MCP (H.7)

`GET /api/v1/hardware/{id}` and the MCP tool
`get_hardware_ci` serve the expanded record behind the fail-closed `inventory.device.ci` audit.
The chassis, board and DIMM serials and the machine-id hash (with its algorithm and source) are
served. Section rows are served only for the `ok` and `constrained` levels, except a section withheld
for an integrity mismatch (below); a section at any other level shows its reason and no rows. The record and its sections are read in one REPEATABLE READ
snapshot (`get_device_ci_with_sections`), so the scalars and the rows are the same replace
generation. A failed read of the sections is a `503` on REST and a retryable error on MCP
(`retry_after_ms` 5000), with the record withheld and the audit detail `state=sections
unreadable`; it is never a `200` with an empty sections list.

Each table-backed section's status row also records `row_count` (migration v3, additive and
nullable): the number of child rows the full replace actually inserted for it, taken from the insert in
the same transaction and never from the agent. The read side compares it with the rows it reads in the
same snapshot; if they differ (child rows lost outside the product, for example a partial single-table
restore or a manual `DELETE`) an `ok` section is served `constrained` and `complete: false` with reason
`server:row_count_mismatch` (appended after any existing reason, so `server_cap:<n>` is kept), and its
rows are withheld (`rows: []`; #7165, owner ruling 2026-11-09).

The status row also records `content_digest` (the same migration v3, additive and nullable): the
SHA-256 of a canonical, length-prefixed serialization of the section's rows (section kind, column
count, row count, then each row's position and cells, with any NUL byte in a cell skipped because the
store cannot keep one), computed by the server from the rows it inserts in the same transaction,
never taken from the agent. It is stored as `v1:<64 hex>`: the prefix names the preimage layout, and a
stored digest that is a well-formed digest of a different layout version (`v<n>:` with a non-empty
remainder, n one to six digits, not 1, no leading zero) is treated as unverified, never as a mismatch; every other
non-NULL value that is not the current form (empty, whitespace, `V1:`, bare hex, a malformed version,
`v2:` with nothing after it) IS a mismatch, because treating a damaged column as unverified would let a
same-count edit read as complete. A later layout change or a registry column change (see the warning in
`device_ci_kinds.hpp`) can therefore be rolled out under a new prefix without raising a false integrity
alarm on every stored row. (A column change also needs its own ALTER migration; the registry is not the schema, see
`docs/postgres-store-playbook.md` "Registry-backed tables".) One pure function
(`device_ci_section_digest.hpp`) serves the writer and the read mapping, so the two cannot drift. The
read side recomputes it from the rows it reads in the same snapshot; a difference with an unchanged
row count (rows edited, or swapped for another sync's, out of band) serves the section `constrained`
and `complete: false` with reason `server:content_digest_mismatch`, appended after any existing
reason. Its rows are withheld (`rows: []`; #7165), because they are not the values the agent reported. A
lost row is reported by the count token alone, since it changes the digest too. This is an integrity
check against accident and non-malicious drift, not tamper resistance: anyone able to write the child
tables can also rewrite the digest column, and the digest covers the rows only, not the section's
level or reason. It closes the same-count content drift that the count alone could not see (finding
`up2r-up-3`). A status-only section (chassis, baseboard, machine_id) and a section written before v3
store NULL for both, are not verified, and read exactly as before.
Only a full replace records the count and repairs a mismatched section: a device whose hash is
unchanged sends only a hash, which leaves the rows alone, so this happens on a hardware change, an
operator Sync now of the device record (`POST /api/v1/hardware/{id}/sync`; the fleet-wide route and the
MCP `sync_hardware_software` tool re-send installed software only and do not repair a section), or the
weekly full floor (at most 7 days); the pre-v3 fleet is therefore unverified
for up to a week after upgrade. The wire format and the agent are unchanged. Migration 3 is a single
additive `ALTER TABLE device_ci_section ADD COLUMN IF NOT EXISTS row_count INTEGER NULL, ADD COLUMN IF
NOT EXISTS content_digest TEXT NULL` (the digest column is folded into v3 because v3 had not shipped;
the runner is gated on the recorded version only, so a development database that already recorded the
earlier row-count-only v3 must be reset with `UPDATE public.schema_meta SET version = 2 WHERE store =
'device_inventory_store';` and a server restart, or recreated). The rollback note above
holds after migrations 2 and 3: an older server that runs against the migrated database writes NULL
there, so the sections it writes are unverified until a v3 server next does a full replace for that
device.

> **Update (2026-11-03):** `runtimes.dotnet` and `runtimes.jvm` are collected as ecosystems `dotnet` and `jvm` (kind `app`; name `.NET Runtime`/`.NET SDK`/`.NET Framework` or `Java JDK`/`Java JRE`; version from the plugin row; publisher Microsoft or the JVM vendor), on Windows, macOS and Linux, under the `keep_rows_if_present_seen` constrained policy (a constrained answer that lists at least one install keeps its rows; one that lists none skips the device's whole installed-software report for the cycle, retried daily on backoff, and the stored rows stay), not the `drop_source` policy of `runtimes.python`. `hardware.drivers_inventory` is an on-demand action and is not a daily-sync source.

### 2026-11-04 — `installed_software`: a publisher on every row, and the `via:` origin label

Every row of every `installed_software` source carries a non-empty `publisher`, so slot 3 of the
row (hashed on both the v2 and the v3 path) is always populated. The wire layout has no extra
slot and the parser gains no rule for it: the server parses and hashes slot 3 on both paths, so the
mechanism is a value rule on the agent, one recognition rule in the server normaliser, and golden
vectors on both sides.

**The value rule.** A row's publisher is the vendor its source declares; when the source
declares none it is the origin label `via:<ecosystem>`, where the ecosystem is the row's own
`ecosystem` value (`via:unknown` when that is empty, never the bare `via:`). The fallback is applied in exactly one place, the collector loop in
`make_installed_software_source` (`vendor_or_origin`, after each adapter has run and the row's
`source` is stamped), not inside `installed_software_canonical_blob`. The blob builder hashes the
publisher as given (a fixture entry with an empty publisher hashes an empty slot), so the fixture
cross-pins (`kCrossPinHash` and the extended, tail-order and mixed-blob pins) are independent of
the fallback.

| Source (`source`) | Publisher | Fallback |
|---|---|---|
| `installed_apps.list_inventory`, rpm | package `VENDOR` tag, else `PACKAGER` (a person or a build-system address; kept only when no vendor is set) | `via:rpm` |
| same, deb | `Maintainer` | `via:deb` |
| same, pacman, apk | none: `pacman -Q` and `apk info -v` list no vendor and a second subprocess per package is not worth it | `via:pacman`, `via:apk` |
| same, Windows | the Uninstall key's `Publisher` | `via:windows` |
| same, macOS apps | the signing certificate's leaf common name | `via:macos` |
| same, macOS installer receipts | none: a reverse-domain id is an identifier, not a vendor, and no heuristic turns one into the other | `via:macos_pkgutil` |
| `pkg_inventory.packages` (Homebrew, Chocolatey), `pkg_inventory.store_packages` (snap, flatpak, Appx) | none: `pkg_inventory` starts no process by design | `via:brew`, `via:chocolatey`, `via:snap`, `via:flatpak`, `via:appx` |
| `pkg_inventory.managers` (Homebrew presence row) | the constant `Homebrew` | n/a |
| `pkg_inventory.managers` (Chocolatey and winget presence rows) | none: no constant vendor is declared for them | `via:chocolatey`, `via:winget` |
| `windows_optional_features.list` | the constant `Microsoft` (DISM features are Windows components; the middleware table's `IBM` is the precedent) | n/a |
| `msi_packages.list_inventory` | the product's `Publisher` | `via:msi` |
| `runtimes.python`, Windows | the row's vendor column (the `PythonCore` registry tag), unescaped | `via:python` when the column is `-` |
| `runtimes.python`, Linux | none: the Linux producer always emits `-` in the vendor column | `via:python` |
| `runtimes.python`, macOS | none: the column is a `CFBundleIdentifier` reverse-domain id (`org.python.python`), an identifier and not a vendor, and no heuristic turns one into the other; the adapter ignores the column on macOS | `via:python` |
| `middleware.ibm_mq` | `IBM`, from the product table | n/a |
| `runtimes.dotnet` | the constant `Microsoft` (.NET is a Microsoft product; the adapter drops the row's vendor column, which is `-` on Linux and on the native macOS root) | n/a |
| `runtimes.jvm` | the row's vendor column: the `release` file's self-reported `IMPLEMENTOR`, or on macOS, for a bundle with an openable `Contents` and no `release` file under `Contents/Home`, its `Info.plist` `JVMVendor` | `via:jvm` when the column is `-` (the home reports no vendor, or it is a Windows home known only by its registry tag) |

The rpm `list_inventory` query format has ten columns, `%{VENDOR}` the last; the pinned argv
literal in `docs/agent-spawn-sink-manifest.md` carries the same format, and `parse_rpm_inv_line`
takes ten tokens. The `list` action has its own columns.

**The server rule.** `normalize_vendor` returns the empty vendor when the RAW value starts with
`kOriginLabelPrefix` (`via:`), as its first statement, before lower-casing or tokenising. The test
is case-sensitive and exact: the agent writes the prefix in lower case, so a Windows publisher of
`VIA:Acme` is a vendor and normalises as one, and a vendor that merely contains `via:` is not a
label. A labelled title therefore keys like a vendorless one.
The catalogue treats a label as no vendor in two more places: `total_publishers` excludes
`publisher LIKE 'via:%'`, and the representative publisher of a title (the rollup statement and
the single-device catalogue read) prefers a non-label value and falls back to the plain maximum
only when every row of the group is labelled.

**Keys of `title_dimension` and `curation_queue`.** Both are keyed on the raw
`(raw_name, raw_publisher, ecosystem)` triple, so a title with no declared vendor is keyed under
its `via:` label, not under an empty publisher, and a `via:<ecosystem>` triple has its own
`title_dimension` row. A label normalises to no vendor, so a pack or curated alias with an empty
raw publisher covers it (the shipped aliases all have one, and such a title resolves `pack` and is
not queued); a title no alias covers is `unnormalized` and queued as an open item.

**Hash.** The publisher is part of each row's hash. The agent's collector characterisation
digests over the real capture samples include it, and the agent and the server pin the same
labelled row to the same digests.

### 2026-11-05 — per-management-group collection settings (server side)

The server stores a collection settings document per management group
(`SoftwareCollectionSettingsStore`, schema `software_collection_settings_store`, tables `settings` and
`settings_history`) and resolves the document that applies to a device. The agent behaviour is a hard
requirement on the settings push, below. Wire reference: `docs/user-manual/rest-api.md`, "Software
collection settings". Settings are managed by fleet administrators: a write needs the global
`ManagementGroup:Write` grant (the administrator role while RBAC enforcement is off), and reads take
the standard `ManagementGroup:Read` gate; group-scoped delegation is not part of this build. This
build sends no settings to agents.

- **Document.** `interval_s` 3600 to 604800, an optional window in minutes past local midnight, a zone
  (empty = the machine's own, else an IANA name checked against `pg_timezone_names` in the write
  transaction; names under `posix/`, `right/` or `SystemV/` and the placeholder `Factory` are refused,
  as an agent cannot resolve them), a boolean per collector (`installed_apps`, `middleware`, `msi_packages`,
  `pkg_inventory`, `runtimes`, `windows_optional_features`) and a priority 0 to 1000. A window needs a
  whole-day interval: the agent fires a window once per local day, so a 25 hour interval with a window
  has no meaning. `installed_apps` cannot be turned off by a document. The roadmap's `evidence`
  collector has no plugin in the tree, so it has no key.
- **Resolution** (pure, `collection_settings_resolve.hpp`). The root group's document is the fleet
  default layer and never a competing candidate: every device is a member of the root group and groups
  created without a parent sit beside it at depth 0, so a competing root document would win every
  creation-time tie against a top-level group. A branch is a group the device belongs to, not a
  document: a membership group that is an ancestor of another membership group is dropped, so a
  device in a group and in its descendant resolves through the descendant whatever the priorities.
  Each remaining branch's winner is the nearest group (itself, then its ancestors, excluding root)
  with a document; an ancestor's document therefore competes for a sibling branch that has none of
  its own (a device in G1 and G2, both children of X, with a document on X and on G2, compares X
  against G2). The branch winners are chosen between by priority (higher wins), depth (deeper
  wins), group creation time (older wins), group id (smaller wins). The kill-switch snapshot is applied last and
  always wins; the host route reads the all-OS layer only, and a degraded kill-switch read is a `503`,
  never a document with collectors off. The per-OS withheld set belongs to the settings push, which
  knows the target OS.
- **Versions.** `document_version` is the SHA-256 of a fixed-order canonical text including priority
  (so `expected_version` catches a concurrent priority-only edit); `effective_version` hashes the
  resolved fields only (interval, window, zone, sorted switches with the overlay applied), with no priority,
  source group or timestamps. Golden vectors are pinned in `test_collection_settings_resolve.cpp`.
- **Read rule.** A stored row whose `plugins_json` does not parse, holds a non-boolean or an unknown key,
  whose `version` is not 64 lowercase hex, or whose scalar fields fail the validator is `Corrupt` (a
  `503` with no retry hint), never a default document. A
  missing known collector key reads as that collector's fleet default (on), and the stored `version`
  is returned as written.
- **Writes.** Create is `INSERT ... ON CONFLICT DO NOTHING RETURNING`; replace is `SELECT ... FOR
  UPDATE`, a version compare, then `UPDATE ... WHERE version = $n RETURNING`. A stale version is a
  conflict (`409`), never last-writer-wins. A create is refused once 20,000 documents exist, the cap
  the list read enforces. History keeps the newest 200 rows per group, trimmed by count in the write
  transaction.
- **Hard requirement on the settings push.** The agent must honour an interval of 1 hour to 7 days, run
  a window only at a whole-day interval of 24 hours or more in whole days, apply the IANA zone, honour
  the per-collector switch, and reject any setting it cannot honour, then report the effective version
  it applied. Until the push lands the settings have no effect on any agent.

### 2026-11-09 — the lookup read surface: v3 columns, components, and totals (SAM-17, schema v12)

**Decision.** The first read surface that returns the v3 columns. `GET /api/v1/inventory/software`
rows gain `hostname`, `last_seen`, `status`, `last_confirmed_at`, `install_type`, `install_scope`,
`install_location` and `instance_key`, and a new `GET /api/v1/inventory/software/components`
reads the component store (`software_components`, schema v11) the same way. One call answers
the lookup question for an application or a component: how many installs, on which devices,
polled when, in what state.

- **Row status.** `status` is derived from the row's own collection facet (`software_facet_state`
  for the row's `source`; `component_inventory` for a component) by ONE rule: `disabled` when the
  facet is switched off, `current` when it last reported a `full` or `delta` section, `unconfirmed`
  otherwise, including a device with no facet record. The rule is one SQL fragment
  (`kRowStatusCaseSql`) used by the reads, the status filter, the rollup and the live totals, and
  its C++ twin is pinned equal to it by a test over every (status, enabled) pair. An unconfirmed
  row may be stale or missing and is never proof of absence; it is returned by default.
- **Totals.** `totals` is `{installs, devices, as_of}` (components: `{instances, devices,
  devices_unconfirmed, as_of}`). `installs` and `instances` count install ROWS everywhere (a
  device with two architectures counts twice), `devices` distinct devices, so a rollup-served and a
  live figure agree on one definition. Application totals come from the hourly catalogue rollup
  (the name-only grain, which gains a `row_count` column) unless a version filter is present, in
  which case they are ONE live aggregate over the version set (never a sum of per-version distinct
  counts). Component totals come from a new hourly `component_rollup` (one row per kind and name,
  refreshed by the existing rollup thread with its own advisory lock and keep-last-good), or are
  live for a version filter or no kind. Totals are served only to an unfiltered caller for an
  exact name; ADR-0017 records why a confined caller gets rows and `totals_omitted: "scope"`.
- **Version range.** `version_min` / `version_max` resolve against the title's distinct versions
  within the caller's scope (the gate's `VisibleSet` pushed into the read; an unfiltered caller
  reads the fleet) under the catalogue comparator into a version set, for every caller; a title
  at the 2000-version read cap in that scope is refused. The set is a predicate only. The distinct
  versions are read LIVE (`installed_software` for a title, `software_components` for a component,
  5 s bounded, the name indexes), never from the hourly rollups: a rollup lacks a version first
  reported since its last refresh, which would drop that version from the set and serve a live,
  exact-looking zero for software that is installed. The scope is pushed into this read for the
  same reason the totals are withheld (ADR-0017): a fleet-wide cut would make the refusal a fact
  about devices the caller cannot see, so a confined caller is answered for a title with 2000
  versions outside its scope exactly as for an unknown title.
- **Schema v12.** `catalog_rollup.row_count` (constant default, metadata-only; the migration also
  sets the catalogue stamp back to `building` so no reader sees a zero row count beside a non-zero
  device count), the two component rollup tables, and `software_components_name_idx`. The index is a plain `CREATE INDEX` in the ladder transaction:
  `software_components` is empty in every deployment until an agent emits component rows (the
  server apply path is live, the producer ships later), so the build holds its lock for no
  measurable time.
- **Component rollup ceiling (recorded, not fixed here).** `refresh_component_rollup` is one
  `GROUP BY kind, name` with a `count(DISTINCT agent_id)` over `software_components`: measured at
  44-47 s for 8.8M component rows (en_US collation, 4 MB and 64 MB `work_mem` alike), so it meets
  the flat 60 s statement limit near 11M rows (about 1M devices with 10 components each); past
  that the first refresh never completes and the kind-and-name totals stay `building`
  (keep-last-good; rows and live totals are unaffected). Latent today: the table is empty until
  the component producer ships (SAM-40). A per-(kind, name, agent) pre-aggregate ran the same
  refresh in 8.2 s and is the recorded upgrade path.
- **Recorded limits of the lookup surface (recorded, not fixed here).** (1) The live
  version-set totals and the version-range reads (`installed_software_version_set_totals`,
  `installed_software_distinct_versions`, `component_versions`) run under the 5 s statement
  bound with no in-flight bound of their own (`/crypto` has one): about 3 requests per second
  of 5-second reads can pin a 16-connection pool, which audit and revocation share; the figure
  is 5 s divided by 16 leases, not measured. On a title above about 5M rows the live read times
  out every time, so that `503` is deterministic and retrying does not clear it (the rows are
  still served by paging or export). (2) The range read pushes the caller's whole scope as one
  array with no `kScopePushdownMaxIds` cut (a cut distinct set cannot be post-filtered without
  re-leaking the fleet property), so a confined caller with 100k or more devices sends a
  multi-MB parameter per range request and the same 5 s bound caps it; cost at 100k and 500k
  ids is unmeasured. (3) Rollup alerting shares the catalogue rollup's pattern: a peer holding
  the advisory lock makes a replica's refresh a skip that counts as success and stamps the
  liveness gauge, so replicas whose tick offsets alternate the lock winner, each timing out,
  keep both `YuzuInventoryComponentRollup*` rules quiet while the totals age; a worker that
  never started exports no series at all, and a throw in the catalogue leg (none expected, the
  store returns bool) skips the components leg with no `error` increment. (4) The wide-scope
  cursor's `skip` reaches `OFFSET` on the unbounded installs page read and a forged value can
  hold a pool lease to the 30 s statement timeout; this is the pre-existing `read_devices_page`
  behaviour moved verbatim into `read_scoped_page` (base `software_catalogue_model.cpp:865` and
  `software_inventory_store.cpp:2268`), not introduced here. (5) A maximum-width CSV export
  (1024-byte fields in 22 columns, 10,000 rows) can reach about 200 MB per request by cap
  arithmetic; the measured exports used typical rows. Each is a candidate issue; none changes a
  served figure.
- **§8 re-opened for the first read-back of slot 13 and the component path.** `install_location`
  (and a component's `path` and `anchor_app`) is served by both routes and their CSV exports to
  every caller the gate admits with `Inventory:Read`; a confined caller sees only the paths of its
  own rows, and a service-scoped token only those of its service's devices. Classification is
  unchanged (operator-tier, a machine-scope path that can still name an account's directory, the
  `list` column's class); retention is unchanged (erased with the device by `delete_agent`, kept
  lower-cased in `software_changes.identity_key` for 400 days). The server cannot minimise the
  value at read or store time without breaking the v3 hash agreement, so the control for
  `install_location` is the agent writer's allowlist: the agent-side blob-v3 writer
  (`installed_software_v3.cpp`, delivered by the sibling SAM-15 change, which lands before this
  surface is read) keeps a location only under a machine root (`kMachineRoots`) and blanks every
  other path, fail closed, and tests that no profile path is emitted. A component's `path` and
  `anchor_app` carry NO allowlist yet: the component writer only clamps them
  (`component_normal_form`), and the SAM-40 producer must apply the same machine-root allowlist
  with a no-profile-path test before it populates them. This read surface therefore depends on
  the SAM-15 writer shipping alongside it; until it does, no agent sends slot 13 or component
  rows and both fields are empty. An agent that does not apply the allowlist (older, forked or
  hostile) can place a per-user path here; the row is still served as sent, which the manual
  states beside the field.
- **Not changed.** The MCP `query_installed_software` rows keep their 14 fields; the twin is a
  later change (recorded in `docs/api-parity-ledger.md` and as the 2026-11-09 entry of the
  ADR-1005 exception ledger, revisit by 2026-12-31).
