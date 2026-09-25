# Installed-software inventory

Yuzu collects each endpoint's **installed-software inventory** and syncs it to the
central server's PostgreSQL database on a **daily** cadence, so you can answer
fleet-wide questions like "which devices have package X at version < Y" for asset
management and vulnerability relevance. This is the first source of the agent's
**daily-sync framework** (ADR-0016); more data types will follow on their own
cadences.

## What is collected

- **Machine-wide installed software** (blob contract v2): name, version,
  publisher, install date, plus the package-manager fields below. Collected by
  the `installed_apps` plugin via its `list_inventory` action (Windows: `HKLM` +
  the agent service account's own `HKCU`; Linux: `dpkg`/`rpm`/`pacman`/`apk`;
  macOS: `system_profiler`). The operator-facing `list` action keeps its
  original four columns (`name`, `version`, `publisher`, `install_date`) in
  the same order and appends two trailing columns, `install_location` and
  `bundle_id` (ADR-0028). A response's raw `output` holds many rows joined by
  newlines: split `output` on newlines first, then each row is seven
  escape-aware tokens: split on `|` not preceded by `\`, decode `\|` to `|`;
  every field is escaped the same way (`\`
  folds to `/`, CR/LF to a space, a field over 4 KiB is cut), so a literal `|` in
  a name never shifts a column on an agent running plugin 1.2.0 or later.
  Agents older than 1.2.0 emit five tokens and do not escape `|`, so a row from
  one of them can split into any count: accept a row only when it has exactly 5
  or exactly 7 tokens under the escape-aware split, reject any other count, and
  read the sixth/seventh columns only for agents known to be on plugin >= 1.2.0.
  The dashboard results table renders `installed_apps` rows
  as key/value (`app` plus one remainder cell — a pre-existing server-side limit
  shared by the four original columns), so the new columns are not separately
  sortable or filterable there; read them from the raw `output` on
  `GET /api/v1/responses/{id}` or MCP `query_responses`. A macOS `list` payload
  is about three times larger than before (14 KB to 42 KB for 323 applications);
  `bundle_id` is `-` past the 5000-application / 120 s enrichment cap, which the
  agent logs but does not report as degraded.
  On Linux/macOS, a
  degraded acquisition (timeout, kill, spawn failure, truncation, or a
  nonzero exit) now emits a single `error|installed_apps: acquisition
  degraded (...)` row and a nonzero result instead of an empty or partial
  `app|` list — see "Degraded collections are skipped, not published" below.
  Automation that only parses `app|` rows and ignores `error|` is
  unaffected; automation that assumed `list` always succeeds needs an
  update. See `docs/user-manual/agent-plugins.md`'s `installed_apps`/
  `msi_packages` entries for the exact per-action wording.
- **The honest-empty contract:** a field the ecosystem does not store is the
  empty string, **never synthesised** (no `-` placeholders, no guessed `0`
  epoch). Per-ecosystem availability:

  | Field | rpm | deb | apk | pacman | Windows | macOS apps | macOS pkgutil |
  |---|---|---|---|---|---|---|---|
  | `kind` | `package` | `package` | `package` | `package` | `app` | `app` | `pkg` |
  | `ecosystem` | `rpm` | `deb` | `apk` | `pacman` | `windows` | `macos` | `macos_pkgutil` |
  | `name` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (receipt id) |
  | `version` (upstream, release stripped) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
  | `epoch` | ✓ (empty if none) | ✓ (empty if none) | — | ✓ (empty if none) | — | — | — |
  | `release` | ✓ | ✓ (empty for native pkgs) | ✓ (pkgrel) | ✓ | — | — | — |
  | `arch` | ✓ | ✓ | — | — | — | — | — |
  | `publisher` | PACKAGER | Maintainer | — | — | Publisher | signing leaf CN | — |
  | `install_date` | ✓ | — | — | — | ✓ | Last Modified | epoch seconds |
  | `signature_status` | `signed`/`unsigned` (stored header tags) | — | — | — | — | `signed`/`unsigned`; empty = not read | — |
  | `distro_id` / `distro_version` | ✓ | ✓ | ✓ | ✓ | — | — | — |

  Notes: rpm `signature_status` reflects the **stored** signature header tags in
  the rpmdb (is a signature recorded), never a live `rpm -K` cryptographic
  verification. `distro_id`/`distro_version` are host-level (`/etc/os-release`
  `ID`/`VERSION_ID`), stamped on every Linux row. deb rows include **held**
  packages (they are installed). `homebrew` is a reserved `ecosystem` value —
  not collected yet (brew is per-user; the sync is machine-scope).

  **macOS `app` rows** carry `publisher` and `signature_status` read natively
  through CoreFoundation + Security.framework (`CFBundleCreate`,
  `SecStaticCodeCreateWithPath`, `SecCodeCopySigningInformation`) — no
  `codesign` subprocess, and no deep `SecStaticCodeCheckValidity` verify. Like
  rpm's, the field records that a signature is **present**, not that it is
  valid. `signed` means signing metadata was found; it does **not** mean the
  signature verifies. An ad-hoc or self-signed bundle reads `signed`, and so
  does a bundle whose signature has since been **broken** — deleting a bundle's
  `_CodeSignature` directory or modifying its executable leaves the recorded
  identifier and certificates in place, so such a bundle still reads `signed`
  and still reports the original vendor's Common Name as `publisher`. Treat
  `publisher` as unverified attribution, never proof of origin, and do **not**
  use `signature_status` as tamper detection or as a Gatekeeper/notarization
  result. (Deep verification — `SecStaticCodeCheckValidity` — is not performed;
  adding it would turn this into a validity verdict and need a third state, an
  open contract decision.) `publisher` is empty for ad-hoc-signed and unsigned
  apps. Enrichment covers up to 5000 located apps per collection; that guard is
  a runaway bound rather than a routine limit, and reaching it makes the agent
  report the collection degraded (see below) instead of publishing rows whose
  signature fields silently went blank.

  **macOS `pkg` rows** are `pkgutil` receipts — system installer packages
  (Command Line Tools, XProtect payloads, vendor `.pkg` installs) that never
  appear in `system_profiler`'s GUI-app enumeration. `name` is the receipt's
  reverse-domain identifier (`com.apple.pkg.CLTools_Executables`), not a
  display name. `install_date` is the receipt's raw **UNIX epoch seconds**,
  the only form `pkgutil --pkg-info` reports — deliberately carried through
  verbatim under the honest-empty contract rather than reformatted into a
  precision the receipt never recorded. Bounded at 5000 receipts per collection,
  again a runaway guard rather than a routine limit.

  **On Linux and macOS, degraded collections are skipped, not published.** If
  any acquisition step does not complete on its own terms — a timeout, a spawn
  failure, a killed child, a capture truncation, a nonzero exit from a
  top-level enumerator, exhaustion of the 120-second whole-collection budget
  mid-enrichment or mid-receipt-walk, either runaway guard above, or (macOS
  only) `system_profiler` or `pkgutil` running successfully and reporting
  nothing at all — the agent reports the whole collection as degraded and the
  daily sync SKIPS that cycle. The previous inventory is retained. This is
  deliberate: an incomplete snapshot is indistinguishable from a complete one
  once it reaches the server, so the omissions would be read as uninstalls. A
  stale inventory is recoverable; a confidently wrong one is not. Degraded
  cycles are logged as warnings, and a host that degrades every day will stop
  updating — treat repeated warnings as actionable.

  The "ran but reported nothing" trigger is macOS-only by design: every Mac has
  GUI applications and installer receipts, so zero means the tool failed. On
  Linux an empty result is often honest — a host may legitimately have `rpm`
  installed and no rpm packages — so that check is not applied there.

  **Windows has no degraded signal today.** Its inventory is collected natively
  from the registry rather than through the subprocess runner, so none of the
  above applies: a partial registry walk publishes as complete. Tracked as a
  known gap, not closed by this release.
- **Changes for rpm fleets vs the v1 (4-field) contract:** `publisher` is now
  the rpm **PACKAGER** tag (was VENDOR), and `version` is the upstream version
  only — the release moved to its own `release` column (was fused
  `VERSION-RELEASE`). Fleet-wide version rollups on Linux change shape
  accordingly on the first post-upgrade sync.
- **No end-user profiles / personal data in the daily sync.** We do **not** use
  the plugin's per-user enumeration (`list_per_user`), so no logged-in-user
  profiles and no usernames are collected by the sync — no end-user PII. The
  operator `list` action is different: its `install_location` can name an
  account's home directory (`/Users/<account>/...` on macOS,
  `C:/Users/<name>/...` on Windows) and is stored as an ordinary Response (90-day
  default retention, no per-subject erasure), outside this sync and outside
  `--inventory-disable`. (The only `HKCU` read is the agent's
  own service-account hive, which is benign: the agent runs outside any
  interactive login session, so `HKCU` is that service account's profile. Note
  the account is **LocalSystem** today, not the intended `NT SERVICE\YuzuAgent`
  — a tracked deviation, #1442. The conclusion is unaffected; LocalSystem's
  profile is no more an end user's than the virtual account's would be.) It carries **lower behavioral
  sensitivity** than the process/performance tiers (no run-time, no resource
  attribution). **Note for works-council jurisdictions:** the data is still
  device-attributable, and on personally-assigned devices installed-software
  enumeration may be co-determination-relevant under national law (e.g. BetrVG
  §87(1)(6)) — co-determination is triggered by the *capability to monitor*, not
  by username presence. Use the opt-out below where an agreement requires it.
- **Disabling it.** Pass **`--inventory-disable`** (or set
  `YUZU_AGENT_INVENTORY_DISABLE`) on the agent to collect and push **no**
  installed-software inventory. Deploy-time opt-out; not a server-side runtime
  toggle. It does not gate the operator `list`/`query`/`list_per_user` actions.

## How the sync behaves (and why it's quiet on the network)

- **Daily, per source.** Installed software syncs every ~24 h.
- **Spread, not lockstep.** Each endpoint picks a stable, per-agent time offset,
  so a fleet does not all report at once. A freshly enrolled (or long-offline)
  agent does its first sync shortly after connecting, jittered to avoid a
  mass-enrollment thundering herd.
- **Hash-skip.** If a device's installed software hasn't changed since its last
  successful sync, the agent sends only a small **content hash** instead of the
  full list. The server replies asking for the full list only when it can't match
  the hash (e.g. a fresh/restored server). A full list is also sent at least once
  a week regardless, as a safety net.
- **Resilient.** Sync state is kept on the agent and survives reconnects and
  reboots; a failed sync simply retries on the next cycle.

## Reading the inventory

The data lands in the Postgres schema **`software_inventory_store`**:

- `installed_software(agent_id, name, version, publisher, install_date, kind,
  ecosystem, epoch, release, arch, signature_status, distro_id, distro_version)`
  — one row per installed package per device. Every column except `agent_id`
  and `name` may be empty (`''`) per the honest-empty contract above; rows
  synced by a pre-v2 agent carry `''` in all eight v2 columns until that
  agent's next full resend.
- `inventory_state(agent_id, source, content_hash, first_seen, last_seen)` — per
  device sync bookkeeping. `first_seen`/`last_seen` are **server receipt times**
  (epoch seconds, stamped when the report is ingested), **not** the agent-supplied
  `collected_at` — so the recency filters and freshness gauge below are immune to
  agent clock skew (#1685).

Today it is queried with **direct SQL**, e.g.:

```sql
-- Which devices have Google Chrome, and what version?
SELECT agent_id, version
FROM software_inventory_store.installed_software
WHERE name = 'Google Chrome'
ORDER BY version;

-- Everything installed on one device
SELECT name, version, publisher, install_date
FROM software_inventory_store.installed_software
WHERE agent_id = '<agent-id>'
ORDER BY name;

-- Full EVR + provenance for one package across the fleet (rpm/deb hosts)
SELECT agent_id, ecosystem, epoch, version, release, arch,
       signature_status, distro_id, distro_version
FROM software_inventory_store.installed_software
WHERE name = 'openssl'
ORDER BY agent_id;

-- Unsigned rpm packages anywhere in the fleet
SELECT agent_id, name, version, release
FROM software_inventory_store.installed_software
WHERE ecosystem = 'rpm' AND signature_status = 'unsigned'
ORDER BY agent_id, name;
```

**Counting the *active* fleet (excluding decommissioned devices).** A device's
rows persist after it stops reporting — Yuzu keeps last-known state rather than
silently dropping a host (the same posture as the offline-endpoint view). So for
software-asset-management counts ("how many devices run X *right now*"), scope to
recently-seen devices via `inventory_state.last_seen` rather than counting raw
rows, which would include long-gone hosts:

```sql
-- Devices that ran Google Chrome AND reported within the last 30 days
SELECT s.agent_id, s.version
FROM software_inventory_store.installed_software s
JOIN software_inventory_store.inventory_state st
  ON st.agent_id = s.agent_id AND st.source = 'installed_software'
WHERE s.name = 'Google Chrome'
  AND st.last_seen > EXTRACT(EPOCH FROM now()) - 30 * 86400
ORDER BY s.version;
```

(A platform-wide decommission/retention purge across all per-device stores is a
tracked follow-on; until then, `last_seen` is the canonical "is this device still
active" filter.)

### MCP (for agentic workers)

The **`query_installed_software`** MCP tool exposes the same data to agentic
workers, gated SOLELY by `AuthRoutes::require_fleet_read` (#3290 Phase 2):

- Filter by software `name` and/or `agent_id`; omit both for a fleet-wide scan.
- Returns up to `limit` rows (max 1000). When `result_truncated_by_cap` is
  `true`, more rows exist past the cap (keyset pagination is a follow-up).
- **A per-agent scope drop filter is applied** — out-of-scope devices are
  dropped (and the omission audited), with the count returned as
  `devices_omitted` (absent when zero). This confinement is **effective**: the
  gate composes management-group visibility with the caller's service-scope tag
  (`meet(management-group, service-scope)`), so a management-group-confined
  operator and a correctly-confined service-scoped API token both get a real
  filtered result — a service-scoped token is no longer denied outright as it
  was before #3290. When present, a positive `devices_omitted` means matching
  software exists outside your scope — an empty or short result does
  **not** mean the software is absent fleet-wide. This is distinct from the generic
  `query_inventory` / `get_agent_inventory` tools, which read a *separate*
  generic blob store on `Infrastructure:Read` and do **not** surface this typed
  software data.
- **On store degradation (authoritative reads, ADR-0016 §7):** if the Postgres
  store cannot be read (pool-acquire timeout or query error), the tool returns a
  JSON-RPC error (`kInternalError`) rather than an empty result. Treat any error
  response as "unknown — do **not** proceed as if nothing is installed". A
  genuinely empty result (no error, zero rows) means the query succeeded and
  matched nothing in your scope.

### REST (for automation / scripts)

The same data is exposed over REST at **`GET /api/v1/inventory/software`**, gated
SOLELY by `AuthRoutes::require_fleet_read` (#3290 Phase 2) — the agentic-first
sibling of the MCP tool:

```bash
# Which devices run Google Chrome (fleet-wide, within your scope)?
curl -H "Authorization: Bearer $TOKEN" \
  "$SERVER/api/v1/inventory/software?name=Google%20Chrome"

# Everything on one device
curl -H "Authorization: Bearer $TOKEN" \
  "$SERVER/api/v1/inventory/software?agent_id=<agent-id>"
```

- Query params: `name` (exact), `agent_id` (exact), `limit` (max 1000). Omit both
  `name` and `agent_id` for a fleet-wide scan.
- Success body: `{"data": {"software": [...], "count": N, "devices_omitted": M, ...},
  "meta": {"api_version": "v1"}}`. Each row is
  `{agent_id, name, version, publisher, install_date, kind, ecosystem, epoch,
  release, arch, signature_status, distro_id, distro_version}` — the v2 fields
  are `""` where the ecosystem does not store them (see the availability matrix
  above). The MCP tool's rows carry the identical field set.
- **Carries the same per-agent scope drop filter as the MCP tool**
  (out-of-scope devices dropped, omission audited, `devices_omitted` reports the
  count) — the SAME `require_fleet_read` gate, so REST and MCP cannot observe a
  different admit/filter decision for the same caller (see the MCP note above).
  When present, a positive `devices_omitted` means matching software exists
  outside your scope — an empty or short result does **not** mean the software
  is absent fleet-wide.
- `result_truncated_by_cap: true` (present only when set) means more rows exist past
  `limit` (keyset pagination is a follow-up, #1634).
- **On store degradation** the endpoint returns **`503`** (an A4 error envelope with a
  `correlation_id`), **never** an empty `200` — so a vulnerability query cannot read a
  transient Postgres outage as "installed nowhere" (ADR-0016 §7 authoritative reads).
  Distinct from a genuinely empty result (`200` with `count: 0`), which means the query
  succeeded and matched nothing in your scope. An unexpected `503` here for a
  management-group-scoped-only caller (no global grant) correlates with the
  `YuzuMgmtGroupReadDegraded` Prometheus alert firing — a management-group store
  degrade, not an authorization problem; retry once it clears (sre, governance run
  2026-08-20).

**Narrow scope on a large fleet (applies to *both* the MCP tool and the REST
endpoint).** The 1000-row cap is applied by the store *before* the management-group
scope filter runs. So a narrow-scope operator querying a popular title across a large
fleet can see `result_truncated_by_cap: true` together with few — or **zero** — of
their own rows, because the cap was consumed by out-of-scope devices that sort ahead
of yours. **That is "incomplete", not "absent in your scope."** Until keyset
pagination lands (#1634), narrow the query: pass `agent_id` (`?agent_id=<id>` on REST,
the `agent_id` arg on MCP) to read a specific device, or a more selective `name`
filter, so your in-scope rows fit under the cap.

### Dashboard (`/inventory` → `/hardware` / `/software`)

The old three-tab **Inventory** dashboard is gone. `/inventory` itself still exists as a
route, but it now just **302-redirects to `/hardware`** (auth still gates first, so an
unauthenticated visitor lands on `/login`, never in a redirect loop through an
authed-only destination) — old bookmarks and links keep working, nothing to change on
your end beyond expecting a redirect. The top nav carries two separate links in its
place, **Hardware** and **Software**, each its own page:

- **`/hardware`** — a ServiceNow-style Configuration-Item list and record; the successor
  to the old **Devices** tab, extended with a generic action runner. The list shows
  hostname, **IP** (new — read live from the TAR fleet-snapshot cache, so it is honestly
  blank once a device goes offline rather than a stale last-known address), OS,
  online/offline/**stale** status, per-page **DEX score**, agent version, last-seen,
  **Tags** (new — click a chip to filter by that exact `key` or `key=value`, or type
  `tag=<key>[=<value>]` directly), and the device-CI columns from before (manufacturer,
  model, serial, CPU model + cores/threads, RAM, OS version). All columns except DEX are
  sortable; a server-side search box (hostname/serial/model/CPU), OS/status filter
  chips, a filter breadcrumb, and pagination narrow a large fleet. A new checkbox column
  plus a sticky bulk-tag bar let you apply or remove one tag across every selected
  device in one action — under the hood it loops the existing single-device tag routes,
  so each device still runs its own `Tag:Write` gate and its own `tag.set`/`tag.delete`
  audit row; nothing is bulk-authorized. The KPI strip (Total CIs / Online / Offline /
  Stale / CI coverage) is computed over the same rows the table shows. **The list is
  gated on the global `Inventory:Read`, but — unlike the old Devices tab, whose
  management-group confinement this doc used to flag as "designed for, not yet verified
  effective" — it is wired as a live caller of the real ADR-0017 admit-then-filter
  chokepoint (`require_fleet_read`)**: a management-group-scoped operator's visible
  rows, and the KPI counts drawn from them, genuinely narrow to their scope, the same
  confinement class the REST/MCP software-query surfaces use (see above). The roster
  read is audited as `inventory.devices` (unchanged verb, still the behavioural-PII
  tier). A store-wide CI or Tags read failure shows its own explicit **"CI columns
  unavailable"** / **"Tags unavailable"** banner (never silently "no CI"/"no tags") —
  distinct from a single device that simply hasn't synced yet, which still shows a plain
  `—` placeholder in just that cell.

  **Click a device** (or visit `/hardware/ci?id=`) for its record — a seven-tab CI
  record, gated per device on `Inventory:Read` for the device's management group
  (`scoped_perm_fn`, the same per-device chokepoint the old drill used):
  - **Overview** — the CI identity block carried over from the old per-device CI panel:
    manufacturer, model, serial, system UUID, domain/OU, BIOS, CPU, memory, primary/all
    MAC addresses (each now its own wrapping chip, not one comma-joined line that used
    to run off the page), NIC count, OS name/version/build, architecture, and
    first/last-synced times. Audited `inventory.device.ci` (behavioural-PII tier). A
    **Sync now** button (new) requests an immediate out-of-cycle daily sync — a source
    picker (or "all") — instead of waiting for the ~24h cadence; the panel then polls
    until the CI store's freshness stamp passes the request time, with an honest note if
    the device is offline, its agent predates 0.13.1, or you lack `Execution:Execute`
    for it (see `inventory.sync.request` in [Audit log](audit-log.md)).
  - **Installed software** — the same per-device software list as before (audited
    `inventory.device.software`), now with its own filter box and, for the first time,
    rendered **Signature** and **Ecosystem** columns. Carries the same **Sync now**
    affordance, scoped to the `installed_software` source.
  - **Tags** — inline add/remove via the existing tag routes, shown only when a
    `Tag:Write` probe passes for the device.
  - **DEX**, **Guardian**, **Live** — not reimplemented: these mount the *same*
    `/fragments/device/*` fragments the (now-redirected) device page used, each gated on
    scoped `GuaranteedState:Read` as before. **Live** additionally carries the ten
    physical-hardware cards (Disks, Memory, Processors, Drivers, Battery, Thermal, Disk
    health (SMART), Volumes, Network adapters, Wi-Fi) — see
    [Device management](device-management.md) for their per-OS availability and audit
    verbs (`device.live.hw_*` and friends).
  - **Actions** (new) — the generic action-runner catalogue: every action a connected
    agent's loaded plugins report, classified by capability (read-only / mutating /
    destructive, irreversible, approval-gated) from the compile-time capability
    catalogue, each with a generated parameter form (filled in from the plugin's own
    documented parameter hints where available) and a dispatch-result panel with
    free-text/regex search, a hit counter, CSV export, and Copy. Dispatch is **not** a
    new endpoint — the form posts to the existing `POST /api/command` route, so
    classification, authorization, the destructive gate, and audit all apply exactly as
    they do for every other caller of that route. Viewing the catalogue needs
    `Inventory:Read`; without `Execution:Execute` for the device you see an honest note
    instead of a form that would only fail on submit. Audited as `hardware.actions.view`
    (the catalogue was viewed) and `hardware.action.result` (a dispatched action's
    result reached a terminal state — rendered, empty, failed, or timed out; the verb
    records that the *result view* was shown to the operator, not whether the
    underlying action itself succeeded) — see [Audit log](audit-log.md).

- **`/software`** — the fleet software catalogue, unchanged in its rollup mechanics: a
  background thread still precomputes the per-title/per-version counts hourly, the KPI
  strip still shows Titles / Devices reporting / Stale / an "updated N ago" (or
  "building") stamp for the catalogue, and the counts are still **fleet-wide, not
  management-group scoped** — the same ADR-0017 gap the REST/MCP section above
  describes. Two things changed:
  - The search box is now a **real server round-trip matching title OR publisher**
    (was client-side and title-only), using the same debounced/narrow-swap-target
    pattern as the Hardware list's search box.
  - Each row grows a **"devices ›"** control that expands inline — independent of the
    row's own click-to-drill-into-**installs-per-version** action — to list every device
    running that title: hostname (linking to its Hardware CI record), version,
    publisher, install date, signature status, ecosystem, and architecture, with its own
    client-side filter for a popular title with many installs. This inline expansion is
    server-scoped the same way the old Find results were (per-row management-group
    drop, 1000-row cap, `inventory.software.query` audit verb) — a short/zero result
    under a narrow scope is *incomplete*, not *absent*.

  The expansion replaces the standalone **Find software** tab, which is gone from the
  sub-nav. Its routes, `/fragments/inventory/find` and `/fragments/inventory/find/results`,
  are still registered for old bookmarks and deep links, but nothing in the UI links to
  them any more — treat them as a legacy escape hatch, not a supported feature.

**On store degradation** the **`/software`** catalogue, its **devices ›** expansion, and
the CI record's **Installed software** lens — the *authoritative* reads — show an
explicit **"unavailable"** banner rather than an empty table, because an empty table
would read as "installed nowhere", the fail-open the authoritative-read contract
(ADR-0016 §7) forbids. The **Hardware list** itself (hostname/OS/status/last-seen/IP/
DEX/version) is sourced from the deliberately *fail-soft* endpoint-state store, with the
CI and Tags columns layered on top from a best-effort `DeviceInventoryStore`/tag-store
read — a *whole-store* degrade there is now its own explicit "CI columns unavailable" /
"Tags unavailable" banner (an improvement on the old Devices tab, where a
`DeviceInventoryStore` degrade during the list render was indistinguishable from "not
yet synced"); the roster read itself being wholly unavailable shows a dedicated "roster
unavailable" banner rather than an empty table. The **per-device CI record's Overview
lens**, by contrast, has always been an authoritative three-state read: found /
genuinely-not-yet-synced ("no CI record synced yet") / degraded (an explicit "CI record
unavailable" banner) are never conflated.

## Access control

Inventory reads are governed by the **`Inventory`** RBAC securable
(`Inventory:Read`), granted by default to the Administrator, ITServiceOwner,
PlatformEngineer, Viewer, and Operator roles. (The gate applies to the
inventory REST/MCP surfaces; direct database access is governed by your Postgres
credentials.)

## Troubleshooting

**The `installed_software` table is empty after upgrading agents.** Most likely
the `installed_apps` plugin isn't loaded — the sync source then idles silently
(it logs `sync: installed_apps plugin not loaded` only at **debug**). Verify the
agent was built with `-Dbuild_agent=true` (the default for released binaries)
and that `installed_apps` is present in the agent's `--plugin-dir`. The sync also
only runs once per ~24 h per agent (spread across the fleet), so a freshly
enrolled agent populates within minutes (jittered first sync), not instantly.

**Non-ASCII app names show as `?` after upgrading from a pre-#1662 build.** The
initial `installed_apps` plugin read the Windows registry with the ANSI `Reg*A`
APIs, which return the system code page (cp1252 on Western installs), so any
non-ASCII character in an app or publisher name was stored as `?` (e.g. `Café` →
`Caf?`). This is fixed in the release containing #1662 (the plugin now reads via
`Reg*W` + UTF-8). After upgrading an agent, the corrected names land on that
agent's **next daily sync** — typically within hours, not the weekly full-floor,
because the changed bytes change the content hash and force a full re-send (it is
*not* gated behind the weekly floor). Until then, an exact-match query
(`WHERE name = 'Café'`) returns zero rows for that device. To force the refresh
immediately on a device, **restart the Yuzu agent** there — the first sync after
restart sends a full list. Note that app *counts* can rise slightly after the
fix: names that previously collapsed to the same `?`-mangled string (e.g. two
different non-ASCII apps) now separate into distinct rows.

**A generic (non-typed) inventory source never appears, with no error visible
to the reporting agent.** Reachable only via gateway-proxied agents
(`GatewayUpstreamServiceImpl::ProxyInventory`); the direct
`AgentServiceImpl::ReportInventory` path never writes generic sources to
`InventoryStore` at all, by design, regardless of depth, so a direct-connect
agent cannot hit this case. For a gateway-proxied agent: the agent's own
report is still acknowledged even when the server silently rejects one
over-depth source blob (nesting past `kMcpMaxJsonDepth`, json-dump-depth-guard
fix) - unlike a store/pool degrade, this is not surfaced back to the agent. Because ADR-0016's hash-skip only
resends a source when its content changes, an agent whose plugin keeps
reporting the SAME malformed shape never resends it, so the source stays
permanently, silently absent from `InventoryStore` until the plugin itself
stops emitting the over-depth shape. **Restarting the agent alone does not
help** - unlike the non-ASCII-names case above, there is no cached mismatch
for a restart to force-resend against. Diagnose via
`yuzu_inventory_ingest_total{source="__generic__",outcome="rejected_depth"}`
(non-zero means at least one agent has hit this) and the accompanying
`spdlog::warn` log line, which names the real agent/plugin identifiers.
This is a WRITE-TIME rejection (the source blob never reaches `InventoryStore`
at all); the distinct READ-TIME signal for a record that already made it into
the store but is excluded when a later query evaluates it (over-nested or
malformed `data_json`, #4496 + follow-up) is documented under
[REST API → `POST /api/v1/inventory/evaluate`](rest-api.md#post-apiv1inventoryevaluate).
The two share a root cause only for the over-depth shape: the write-time guard
above checks nesting depth on the raw wire bytes and never attempts a JSON
parse, so a syntactically malformed but shallow blob passes it untouched, is
stored, and is caught only at read time as `parse_error_excluded` - there is
no write-time signal for that shape.

**A `need_full` spike right after deploying the blob-v2 release is expected.**
The v2 contract reformats the canonical content hash (12 fields instead of 4),
so every agent's first post-upgrade report mismatches its stored v1 hash and the
server nacks `need_full` — one full resend per agent, phase-spread across the
~24 h sync window, then hash-skip resumes. Watch
`yuzu_inventory_ingest_total{outcome="need_full"}` fall back to baseline within
a day. During a mixed-version window the loop is bounded, not broken: an **old
agent against a new server** (or a new agent against an old server) settles into
roughly one hash-only nack plus one full resend per day — data stays correct,
and it ends when the lagging side upgrades. Deploy **server first, then agents**
(the platform's normal order).

**Observability.** The server emits `yuzu_inventory_ingest_total{source,outcome}`
(outcome ∈ `stored` / `touched` / `need_full` / `error` / `dropped` / `rejected` /
`rejected_depth`: `rejected` is a whole report rejected at the source-map cap,
`rejected_depth` is a single generic (non-typed) source blob rejected for
nesting past `kMcpMaxJsonDepth`, kept as its own outcome specifically so it
does not page the `YuzuInventoryReportRejected` alert's source-map-cap
runbook - its `source` label is always the fixed sentinel `__generic__`,
never the reporting plugin's actual name, so a query for a specific
plugin's `source` label will not find it there) - watch the `need_full`
and `error` rates to spot a fleet whose hash-skip is degrading or whose
ingest is failing. Four further series sharpen the picture:

- `yuzu_inventory_ingest_duration_seconds{source,phase}` (histogram) — how long
  applying one source's report holds a pooled Postgres connection (advisory lock +
  the atomic replace, whose inserts are now batched into a single `unnest()`
  statement). `phase=full` is the full-payload replace; `phase=hash_only` is the
  cheap hash-skip compare + `last_seen` bump — split so the steady-state
  hash_only majority doesn't bury the `full` tail, the pool-pressure signal under
  a cold-cache `need_full` herd.
- `yuzu_inventory_read_degrade_total{reason, source}` (counter, reason ∈ `store_not_open` /
  `pool_acquire_timeout` / `query_error`; source ∈ `installed_software` / `device_ci` /
  `software_licensing` / `product_registry` / `app_usage` / `generic`) — an
  **authoritative read** that returned
  a degrade (no data) rather than a silent empty. `/readyz` stays green under pure
  pool saturation, so without this counter a degraded fleet software query is
  otherwise invisible. The per-degrade WARN is sampled per site — the leading edge
  of each outage *episode* (a degrade arriving after a quiet gap), then every 100th
  within it — so a fan-out outage can't flood the log while a second, later outage
  still logs its onset rather than staying silent; the counter is the continuous
  signal.
- `yuzu_inventory_stale_agents{source}` (gauge) — agents that have not synced this
  source within the staleness window (two missed daily cycles), a freshness /
  liveness signal sampled on the metrics sweep. Staleness keys on the **server
  receipt time** (`inventory_state.last_seen`), not the agent's `collected_at`, so a
  future-skewed or hostile agent cannot pin itself "fresh" and hide a dark endpoint
  (#1685). On a degrade the gauge **holds its
  prior value** (it is never set to a false `0`), so pair it with the counter below
  to know whether a low reading is current.
- `yuzu_inventory_stale_count_unavailable_total` (counter) — the freshness count
  could not be computed (pool saturation / query timeout) and the gauge above was
  held at its prior value. A non-zero rate means `yuzu_inventory_stale_agents` may
  be **frozen, not genuinely low** — the freeze-detector that travels with the
  gauge (the freshness count uses a tighter 250 ms budget than the read paths, so
  it can stall while `yuzu_inventory_read_degrade_total` stays quiet).
- `yuzu_inventory_ingest_dropped_total{reason}` (counter, reason ∈ `store_not_open` /
  `pool_acquire_timeout` / `query_error` / `invalid_key` / `stale`) — generic-store
  (ADR-0037) upsert calls that did not persist. Ingest is fail-soft (the next
  changed/full report re-sends the blob, bounded by the weekly full floor), so alert on a
  **sustained rate**, never on presence;
  `reason="stale"` in particular spikes benignly for the duration of a server clock
  step-back and self-heals (the stale-overwrite guard compares receipt-clamped
  timestamps).
  `YuzuGenericInventoryPersistenceDropped` warns only after a non-`stale` reason's rate
  remains non-zero for 15 minutes, avoiding alerts for a single self-healing report or
  expected clock-step stale suppression.
- `yuzu_inventory_query_truncated_total` (counter) — generic-store reads that hit their
  row cap or 8 MiB aggregate payload cap. A non-zero rate on the result-set
  producer path pairs with 503s from
  `POST /api/v1/result-sets/from-inventory-query` (see #2633); on
  `/inventory/evaluate` it pairs with `result_truncated_by_cap: true` responses.


The **catalogue rollup** (the `/software` page's precomputed counts, refreshed
hourly by the background `SoftwareCatalogRollup` thread) emits three further series:

- `yuzu_inventory_catalog_rollup_total{outcome}` (counter, outcome ∈ `success` / `error`)
  — one per recompute attempt. A rising `error` count with a frozen
  `…_last_success_timestamp` means recomputes are failing (PG outage / the 60s budget
  exceeded at scale) and the catalogue is going stale; keep-last-good serves the prior
  rollup meanwhile.
- `yuzu_inventory_catalog_rollup_duration_seconds` (gauge) — the last recompute's
  wall-clock. A rising value approaching the 60s budget is the leading indicator to raise
  the budget (or shard the rollup) before recomputes start timing out. (A gauge, not a
  histogram: at one sample/hour percentiles add nothing.)
- `yuzu_inventory_catalog_rollup_last_success_timestamp` (gauge, epoch seconds) — the
  primary liveness signal; it is the source of the Software tab's "updated N ago" stamp.
  **Seeded to `0` at startup** so the series always exists (a never-succeeded server is
  still alertable). Alert on `time() - this > 7200` **guarded by `and this > 0`** — the
  `> 0` guard skips the cold-boot "building" window (epoch 0); the never-succeeded /
  ongoing-failure case is caught by `…_rollup_total{outcome="error"}` instead.

Shipped alert rules live in the `yuzu-inventory` group of
`docs/prometheus/yuzu-alerts.yml`: `YuzuInventorySustainedIngestErrors` (a non-zero
`error` rate held for 15m), `YuzuInventoryHighNeedFullRatio` (>20% of ingests are
`need_full` for 15m — hash-skip is not taking, so agents keep re-sending full
payloads), `YuzuInventoryDroppedBlobs` (an over-cap blob dropped + nacked),
`YuzuInventoryReportRejected` (a whole report rejected at the source-map cap),
`YuzuInventoryGenericBlobRejectedDepth` (a generic source blob rejected for
nesting past `kMcpMaxJsonDepth`, json-dump-depth-guard fix),
`YuzuInventoryReadDegraded` (a read returned a degrade, by reason),
`YuzuInventoryIngestSlow` (full-payload ingests holding a connection >10s — a
leading pool-saturation indicator), and `YuzuInventoryStaleCountUnavailable` (the
freshness gauge may be frozen).

A **recording rule**, `yuzu:inventory_ingest_duration_seconds:p99{source,phase}`,
ships in the same group: it precomputes the 99th-percentile ingest duration per
`(source, phase)` over a 10m window (matching `YuzuInventoryIngestSlow`) so
dashboards and any future tighter latency alert read a cheap single series rather
than a fan-out `histogram_quantile` at query time — meaningful only because the
extended 10-60s buckets resolve the tail. Reference it directly in Grafana panels
or custom alert expressions; it returns no data unless the shipped rules file is
loaded.

`YuzuInventoryStaleAgents` ships **disabled** (commented out) in the same group:
the `yuzu_inventory_stale_agents` gauge has no fleet-size-independent absolute
threshold (`>50` is day-one noise on a 100-device pilot and 0.1% ambient churn on a
50k fleet), and a fleet-relative ratio against `yuzu_fleet_agents_healthy` needs
explicit `on()/group_left()` matching with a denominator caveat. **Enable it** once
you have observed your fleet's normal stale-count baseline and set the threshold to
~5–10% of your expected active fleet; correlate with `yuzu_fleet_agents_healthy` to
separate "agents offline" from "sync source broken / disabled".

**`install_location` is `-` for many Windows applications and every Linux application.** `-` means the OS
reported no location, not that collection failed. Windows reads each Uninstall key's `InstallLocation`, which many
MSI-registered products, SDK and runtime component packages and some system components never populate (182 of
241 rows on one developer workstation); Linux is always `-` by design, since a package installs to many prefixes.
`-` also results from a Windows value longer than 511 characters or stored with a non-string registry type, and
for per-user installs, which the machine-scope `list` does not read. `bundle_id` is `-` on Windows
and Linux, and on macOS for a non-bundle location or beyond the 5000-application / 120 s enrichment cap.

**The results table shows column headers with nothing under them.** The dashboard splits `installed_apps` rows at
the first `|` (`app` plus one merged cell) while the headers come from the definition. Nothing is lost: read the
seven tokens from `GET /api/v1/responses/{id}`, its `/export` or MCP `query_responses`, or search the merged cell
with the results search box.

## Device-identity inventory (`device_ci`)

A second daily-sync source, **`device_ci`** (ADR-0016 source #3), is live on the
agent and server. It collects the machine's stable hardware/OS identity — a
ServiceNow-CMDB-style configuration item — and persists one row per device in the
Postgres schema **`device_inventory_store`** (table `device_ci`): manufacturer,
model, **serial number**, **system UUID**, BIOS vendor/version/date, CPU
model/cores/threads, RAM, a disk summary, **primary MAC** + MAC summary + NIC
count, OS name/version/build, and architecture. Serial number and system UUID are
the CMDB correlation key.

It is collected via the existing `hardware` (incl. a new `system` action for
serial + UUID), `device_identity`, `os_info`, and `network_config` plugins. It
**excludes volatile telemetry** — free disk space, uptime, IP addresses —
deliberately: those change between cycles and would flip the content hash every
sync, defeating the hash-skip protocol.

- **Scope / privacy.** Machine-scope only (no per-user data), but serial/UUID/MAC
  are device-persistent identifiers — treat as potentially personal data where a
  device is person-assigned. The same **`--inventory-disable`** flag suppresses
  `device_ci` along with the other sources (it gates the whole daily-sync thread).
- **Observability.** Ingest shares
  `yuzu_inventory_ingest_total{source="device_ci"}` +
  `yuzu_inventory_ingest_duration_seconds{source="device_ci"}`; read degrades use
  `yuzu_inventory_read_degrade_total{source="device_ci"}`. The store joins
  `/readyz` + `/healthz`.
- **VMs / serial-less hosts.** A device with no SMBIOS serial (many VMs) reports
  `serial`/`system_uuid` as the literal `"unknown"` — use `manufacturer`/`model`
  (e.g. "VMware, Inc."/"VMware7,1") to recognise it.

The operator-facing read surface — the **Hardware** list's CI columns and the CI
record's **Overview** lens — is live; see the **`/hardware`** bullet above for its
columns, fields, and audit/degrade posture.

## App usage inventory (`app_usage`)

A further daily-sync source, **`app_usage`**, is live on the agent and server. It
derives machine-scope executable usage evidence read-only from TAR's `usage` fold
(`usage_daily`/`usage_daily_user`/`usage_live` inside `tar.db`) and persists it in
the typed Postgres schema **`app_usage_store`**: per-executable run counts, total
seconds, first/last-seen, and a distinct-user count over a 30-day sliding window.

- **Scope / privacy.** No pid, command line, or user name is ever emitted —
  `distinct_users` is a `COUNT(DISTINCT user)` only. Even so, executable names and
  run times are a working-hours/presence proxy: a host whose interactive tools
  cluster their usage in a narrow daily window says something about when its
  operator is active, regardless of who that operator is — treat this source as
  behaviorally sensitive. The same **`--inventory-disable`** flag suppresses
  `app_usage` along with the other sources (it gates the whole daily-sync thread).
- **Observability.** Ingest shares `yuzu_inventory_ingest_total{source="app_usage"}`
  + `yuzu_inventory_ingest_duration_seconds{source="app_usage"}`; read degrades use
  `yuzu_inventory_read_degrade_total{source="app_usage"}`. The store joins
  `/readyz` + `/healthz`.
- **Read surface.** Unlike the sources above, `app_usage` is NOT exposed through
  the generic inventory read endpoints — it is gated behind the **`Forensics`**
  securable (`GET /api/v1/forensics/agents/{id}/app-usage` + MCP
  `get_agent_app_usage`), scoped to the device and floored to Administrator under
  RBAC-off. See `docs/authz-model.md` §4 and the `execution_artifacts`/`app_usage`
  rows in `.claude/routed-concerns.md`.
- **Per-host executable cap.** The agent-side `last_used` action is capped at 5000
  distinct executables in the retained window; a host past the cap still reports
  5000 of them (lexicographically first by `exe_key`, not by recency or any usage
  metric) plus a trailing truncation marker (never a silent drop). Known
  limitation, tracked in
  [#4489](https://github.com/Tr3kkR/Yuzu/issues/4489): a host that stays
  *continuously* over the cap has its whole daily-sync cycle skipped rather than
  syncing a partial result — build servers, CI runners and dev workstations with
  heavy toolchain churn are the plausible case. There is currently no
  operator-facing alert for this state.

## See also

- `docs/adr/0016-agent-daily-sync-framework.md` — the design and rationale.
- `docs/os-capability-matrix.md` — per-OS collection coverage.
