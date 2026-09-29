# ADR-0016: Agent→Server Daily Sync Framework (hash-skip conditional push)

**Date:** 2026-06-24
**Status:** Accepted (v1 sliced — installed software is source #1)
**Component:** Agent core (sync scheduler) · Server (inventory ingest + Postgres store) · Gateway (proxy)
**Authors:** Dave Rae

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

### Why not "TAR first"

The initial instinct was to land this in the agent's local **TAR** edge
warehouse and pull it centrally. Rejected: TAR is **pull-only by design** and
**event-shaped** (it records *change events*, e.g. PR #1620's `$Software`
source records install/uninstall/upgrade deltas). TAR answers *"what changed,
when"* on the edge. Our goal is *"what is installed now, daily, in central
Postgres."* Routing a full daily snapshot through TAR would require building a
new push/export transport that contradicts TAR's no-push philosophy, and TAR's
delta shape does not match a full-snapshot need. The two are **complementary,
not substitutes**: this framework owns *current state, central*; TAR owns
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
envelope (key = data-type, value = opaque blob). No TAR involvement.

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
  Explicitly **not** TAR: TAR is a *plugin-owned, append-only* capture
  warehouse; this is *mutable agent-core* KV state, and core must not depend on
  a plugin's DB being loaded/healthy.
- **Startup policy:** first-run or overdue (gone past one interval while
  offline) → one catch-up sync after a *short random startup delay* (so a
  mass-deploy or a site's Monday-morning power-on does not herd); otherwise wait
  for the next phase fire.

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
  - **Current-state only** (replace on change). No history in central PG —
    change-history stays an edge/TAR concern (ADR-0004 boundary).
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
> `/inventory` dashboard Find tab is unmigrated and stays global-gate-only for now.
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

- **TAR-first + central pull** — rejected (pull-only, event-shaped; see Context).
- **JSONB blob + GIN index** — rejected (Postgres lock-in; clunky range
  filters; conflicts with the migrate-off-PG constraint).
- **Always send the full list** — rejected (abandons network-kindness).
- **Server-dispatched daily schedule** — rejected (daily fleet fan-out; the
  agent-push model matches the RPC's purpose and self-staggers).
- **Full version history in central PG** — rejected for v1 (fattest; contradicts
  thin-central; history is TAR's edge concern).

## Relationship to other ADRs
- **ADR-0004** (edge warehouses / thin central) — this framework's
  current-state-central / history-on-edge boundary is a direct application.
- **ADR-0006/0008** (Postgres substrate) — `InventoryStore` is born-on-PG.
- **ADR-0012** (server Postgres store contract) — `InventoryStore` follows it;
  recorded as a prioritized net-new store in `docs/postgres-migration-ladder.md`.
- **PR #1620 / `$Software` TAR source** — complementary edge change-history,
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
per-device CI panel (PR2 of this ladder) make serial/system_uuid/primary_mac
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
Devices tab CI columns + per-device CI panel — is dashboard-**read**-only; it joins
purely on `agent_id` and does not implement CMDB correlation/merge, so this
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
ecosystem does not store is `''`, never synthesised (rpm = full NEVRA + PACKAGER
+ stored-tag signature status; deb = NEVRA + Maintainer + arch, installed AND
held; apk = name/version/pkgrel; pacman = name/EVR; Windows/macOS = `kind=app`
with name/version/publisher only; `distro_id`/`distro_version` from
`/etc/os-release` stamped on every Linux row; `homebrew` is a reserved
ecosystem value, not collected). `version` is now the upstream version with the
release/revision split into its own field, and rpm `publisher` switches
VENDOR→PACKAGER — both operator-visible data shifts on Linux fleets.

Mechanics:

- The fields ride **inside** the `plugin_data["installed_software"]` blob — no
  proto change, no gateway pb regen (§6 applies only to outer-envelope fields).
- Collection is a new `installed_apps` action **`list_inventory`** (13-token
  `inv|` rows); the operator-facing `list`/`query`/`list_per_user` output is a
  stable contract whose fields this ADR left byte-unchanged (rpm `list` keeps
  VENDOR). On Windows, `get_installed_apps_windows()` feeds `list`, `query` AND
  the hashed `inv|` rows, so any change to it must be checked against the
  hashed rows. *Amended 2026-09-21:* `list` gained two trailing columns
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
  blob — and can name an account's home directory
  (`/Users/<account>/...`, `C:/Users/<name>/...`). §8's finding — that the
  sync neither crawls a logged-in user's hive nor `~/Applications` — is about
  the sync and the Windows `HKCU` path specifically; it does not extend to
  `list`: on macOS the shared `system_profiler` scan `list`/`list_inventory`
  both run CAN list entries under `/Users/<account>/Applications` (4 of the
  323 rows in the committed macOS sample), so `list` may name a home
  directory. Any change that puts `install_location` into a hashed or synced
  blob (the component-inventory collection's blob v3, ADR-0028) must re-open
  §8's classification first. `list`/`list_inventory` keep their
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
ladder). The plugin reads TAR's `usage` fold read-only (`PRAGMA query_only`,
`SQLITE_OPEN_READONLY`) — it never writes `tar.db`. Four clauses, all
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
3. **A `tar_config` read failure must map to `Errored`, never `Enabled`.**
   `source_state_from_config`'s tri-state (Enabled/Disabled/Errored) mirrors
   TAR's own `canonical_source_enabled` #560 fix; defaulting a read failure to
   `Enabled` is the opposite of fail-closed.
4. **Never send an empty blob for a constrained capture.** Skip the sync cycle
   instead — an empty blob reads server-side as "genuinely zero usage" on a
   host that is actually constrained or disabled, which is a false negative a
   downstream consumer cannot distinguish from real data.
  exposure (already derivable from the existing `os_info` source).
